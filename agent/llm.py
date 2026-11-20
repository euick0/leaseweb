"""Structured model calls with one retry, a provider fallback chain, and a per-key answer cache.

The providers themselves (Ollama, OpenAI-compatible APIs, Anthropic) are in
agent/providers.py.

The cache is the stage safety net: every valid live answer is written to
agent/cache/<kind>/<key>.json, and when the model is slow, down, or returns
invalid JSON twice, the cached answer is used instead (and labelled as such).
Hand-written seed answers (model "seed") let the demo run before the model is
pulled; they are labelled "seed" and replaced by the first live answer.
"""
from __future__ import annotations

import json
import re
import time
from typing import Optional, Type, TypeVar

from pydantic import BaseModel, ValidationError

from . import config, providers
from .providers import LLMUnavailable  # noqa: F401  (re-exported)

T = TypeVar("T", bound=BaseModel)




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


def complete(system: str, user: str, schema: Type[T], timeout: Optional[float] = None) -> tuple[T, str]:
    """One structured call, trying each configured provider in order until one answers.
    Returns (answer, "provider:model"). Raises LLMUnavailable or ValidationError."""
    errors = []
    for p in providers.chain():
        try:
            return p.chat(system, user, schema, timeout or config.LLM_TIMEOUT), f"{p.name}:{p.model}"
        except LLMUnavailable as exc:
            errors.append(f"{p.name}: {exc}")
    raise LLMUnavailable("; ".join(errors) or "no LLM provider configured (LLM_PROVIDER)")


def chat(system: str, user: str, schema: Type[T], timeout: Optional[float] = None) -> T:
    """One structured call to the configured model. Raises LLMUnavailable or ValidationError."""
    return complete(system, user, schema, timeout)[0]


def ask(kind: str, key: str, system: str, user: str, schema: Type[T],
        timeout: Optional[float] = None) -> tuple[T, str]:
    """Ask the model; returns (answer, source) where source is 'live', 'cache' or 'seed'.

    live mode: try, retry once on invalid output, then fall back to the cache.
    cache mode: cache only.
    """
    errors: list[str] = []
    if config.LLM_MODE == "live":
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
    if cached is not None:
        return cached
    raise LLMUnavailable("; ".join(errors) or f"no cached answer for {kind}/{key}")
