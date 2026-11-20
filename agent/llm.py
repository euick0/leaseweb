"""Structured model calls with one retry, a provider fallback chain, and a per-key answer cache.

The providers themselves (Ollama, OpenAI-compatible APIs, Anthropic) are in
agent/providers.py.

The cache is the stage safety net: every valid live answer is written to
agent/cache/<kind>/<key>.json, and when the model is slow, down, or returns
invalid JSON twice, the cached answer is used instead (and labelled as such).
Hand-written seed answers (model "seed") let the demo run before the model is
pulled; they are labelled "seed" and replaced by the first live answer.

A content-keyed question (`content_keyed=True`) is cached under a hash of the
full prompt, so a cached answer is only ever reused for the identical question.
Seed answers are still found under the plain key; callers must not treat a
"seed" answer as a real review. In live mode such a question is not asked
again once it has a real answer: it is the identical prompt, so a slow model
cannot stall a run that was already reviewed.

Sovereignty: a provider outside our own infrastructure is only called when the
fleet policy says `allow_hosted_llm: true`; its prompts are redacted first
(agent/redact.py) and every call is counted in `egress`.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Optional, Type, TypeVar

from pydantic import BaseModel, ValidationError

from . import config, policy, providers
from .redact import redact
from .providers import LLMUnavailable  # noqa: F401  (re-exported)

T = TypeVar("T", bound=BaseModel)

# model calls since the agent started; `hosted` ones left our own infrastructure
egress = {"local_calls": 0, "hosted_calls": 0, "redactions": 0}


def _cache_path(kind: str, key: str):
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", key)
    return config.CACHE_DIR / kind / f"{safe}.json"


def cache_get(kind: str, key: str, schema: Type[T]) -> Optional[tuple[T, str]]:
    """(answer, source) where source is "cache", or "seed" for a hand-written answer."""
    path = _cache_path(kind, key)
    if not path.exists():
        return None
    doc = json.loads(path.read_text())
    return schema.model_validate(doc["answer"]), "seed" if doc.get("model") == "seed" else "cache"


def cache_put(kind: str, key: str, answer: BaseModel, model: str) -> None:
    path = _cache_path(kind, key)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"model": model, "saved": time.time(),
                                "answer": answer.model_dump()}, indent=2) + "\n")


def describe() -> str:
    """The provider chain as shown to operators, e.g. "ollama:qwen2.5:14b → deepseek:deepseek-chat"."""
    return " → ".join(f"{p.name}:{p.model}" for p in providers.chain())


def check_sovereignty() -> None:
    """Called at startup: a hosted provider in the chain while the policy forbids it is a
    configuration error, not something to skip quietly."""
    outside = [p.name for p in providers.chain() if providers.hosted(p)]
    if outside and not policy.fleet()["allow_hosted_llm"]:
        raise RuntimeError(f"LLM_PROVIDER includes hosted provider(s) {', '.join(outside)}, but the fleet policy "
                           f"says allow_hosted_llm: false. Remove them or change the policy.")


def status() -> dict:
    """For the dashboard: the chain, and whether anything can or did leave our infrastructure."""
    outside = [p.name for p in providers.chain() if providers.hosted(p)]
    return {"providers": describe(), "mode": config.LLM_MODE, "hosted_providers": outside,
            "sovereign": not outside and egress["hosted_calls"] == 0, **egress}


def complete(system: str, user: str, schema: Type[T], timeout: Optional[float] = None) -> tuple[T, str]:
    """One structured call, trying each configured provider in order until one answers.
    Returns (answer, "provider:model"). Raises LLMUnavailable or ValidationError."""
    errors = []
    allow_hosted = policy.fleet()["allow_hosted_llm"]
    for p in providers.chain():
        sys_, user_ = system, user
        if providers.hosted(p):
            if not allow_hosted:
                errors.append(f"{p.name}: hosted provider refused (allow_hosted_llm is false in the fleet policy)")
                continue
            (sys_, n1), (user_, n2) = redact(system), redact(user)
            egress["redactions"] += n1 + n2
            egress["hosted_calls"] += 1
            print(f"[llm] prompt leaves this infrastructure: {p.name}:{p.model}, {n1 + n2} redaction(s)", flush=True)
        else:
            egress["local_calls"] += 1
        try:
            return p.chat(sys_, user_, schema, timeout or config.LLM_TIMEOUT), f"{p.name}:{p.model}"
        except LLMUnavailable as exc:
            errors.append(f"{p.name}: {exc}")
    raise LLMUnavailable("; ".join(errors) or "no LLM provider configured (LLM_PROVIDER)")


def chat(system: str, user: str, schema: Type[T], timeout: Optional[float] = None) -> T:
    """One structured call to the configured model. Raises LLMUnavailable or ValidationError."""
    return complete(system, user, schema, timeout)[0]


def ask(kind: str, key: str, system: str, user: str, schema: Type[T],
        timeout: Optional[float] = None, content_keyed: bool = False) -> tuple[T, str]:
    """Ask the model; returns (answer, source) where source is 'live', 'cache' or 'seed'.

    live mode: try, retry once on invalid output, then fall back to the cache.
    cache mode: cache only.
    """
    errors: list[str] = []
    plain_key = key
    if content_keyed:
        key = f"{key}-{hashlib.sha256((system + chr(0) + user).encode()).hexdigest()[:12]}"
    if config.LLM_MODE == "live":
        known = cache_get(kind, key, schema) if content_keyed else None
        if known is not None:             # the identical question already has a real answer
            return known
        for attempt in range(2):
            try:
                answer, model = complete(system, user, schema, timeout)
                cache_put(kind, key, answer, model)
                return answer, "live"
            except ValidationError as exc:
                errors.append(f"attempt {attempt + 1}: invalid output ({exc.error_count()} errors)")
            except LLMUnavailable as exc:
                errors.append(f"model unavailable: {exc}")
                break
    cached = cache_get(kind, key, schema)
    if cached is None and content_keyed:
        seed = cache_get(kind, plain_key, schema)
        cached = seed if seed and seed[1] == "seed" else None
    if cached is not None:
        return cached
    raise LLMUnavailable("; ".join(errors) or f"no cached answer for {kind}/{key}")
