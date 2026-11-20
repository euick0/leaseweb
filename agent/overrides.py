"""Settings changed from the dashboard (agent/static/settings.html), kept in
state/ui-settings.json and layered over the files:

  llm     {providers: [...], mode: live|cache, models: {provider: model}}
          over LLM_PROVIDER / LLM_MODE / <NAME>_MODEL and patchpilot.yaml
  policy  a partial policy, validated like policy.yaml, over policy.yaml
  scope   {targets: [...], workloads: [...], ecosystems: [...], packages: [...]}
          what PatchPilot leaves alone: excluded from runs, probes and the OSV feed

A section that is not set falls back to the files; "reset" in the dashboard
deletes the section. Secrets (API keys, tokens) are never stored here: they
stay in .env. Every change is written to the audit log by the API.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Optional

from . import config

SECTIONS = ("llm", "policy", "scope")
SCOPE_KEYS = ("targets", "workloads", "ecosystems", "packages")

_lock = threading.Lock()
_cache: tuple[Optional[Path], float, dict] = (None, 0.0, {})


def path() -> Path:
    return config.STATE_DIR / "ui-settings.json"


def get() -> dict:
    global _cache
    p = path()
    try:
        mtime = p.stat().st_mtime
    except FileNotFoundError:
        return {}
    if _cache[0] != p or _cache[1] != mtime:
        try:
            _cache = (p, mtime, json.loads(p.read_text()) or {})
        except (OSError, ValueError) as exc:
            print(f"[settings] {p} ignored: {exc}", flush=True)
            _cache = (p, mtime, {})
    return _cache[2]


def section(name: str) -> dict:
    return dict(get().get(name) or {})


def put(name: str, value: Optional[dict]) -> None:
    """Replace one section; None removes it (back to the files)."""
    if name not in SECTIONS:
        raise KeyError(name)
    with _lock:
        doc = {k: v for k, v in get().items() if k in SECTIONS}
        if value is None:
            doc.pop(name, None)
        else:
            doc[name] = value
        p = path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, indent=2) + "\n")
        os.replace(tmp, p)


# ------------------------------------------------------------------ readers

def llm_providers() -> list[str]:
    names = section("llm").get("providers") or config.LLM_PROVIDER.split(",")
    return [n.strip() for n in names if n.strip()]


def llm_mode() -> str:
    return section("llm").get("mode") or config.LLM_MODE


def model(provider: str) -> Optional[str]:
    return (section("llm").get("models") or {}).get(provider) or None


def scope() -> dict[str, list[str]]:
    s = section("scope")
    return {k: list(s.get(k) or []) for k in SCOPE_KEYS}


def in_scope(wl: Any) -> bool:
    s = scope()
    return wl.target not in s["targets"] and wl.id not in s["workloads"]


def package_in_scope(component: Any) -> bool:
    s = scope()
    return component.ecosystem not in s["ecosystems"] and not (
        {component.name, component.coordinate} & set(s["packages"]))
