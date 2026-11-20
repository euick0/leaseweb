"""Ollama client with structured output, one retry, and a per-key answer cache.

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

import requests
from pydantic import BaseModel, ValidationError

from . import config

T = TypeVar("T", bound=BaseModel)


class LLMUnavailable(RuntimeError):
    pass


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


def chat(system: str, user: str, schema: Type[T], timeout: Optional[float] = None) -> T:
    """One structured call to Ollama. Raises LLMUnavailable or ValidationError."""
    body = {
        "model": config.OLLAMA_MODEL,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "format": schema.model_json_schema(),
        "stream": False,
        "options": {"temperature": 0, "num_ctx": 16384},
    }
    try:
        resp = requests.post(f"{config.OLLAMA_URL}/api/chat", json=body,
                             timeout=timeout or config.LLM_TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise LLMUnavailable(str(exc)) from exc
    content = resp.json().get("message", {}).get("content", "")
    return schema.model_validate_json(content)


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
                answer = chat(system, user, schema, timeout)
                cache_put(kind, key, answer, config.OLLAMA_MODEL)
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
