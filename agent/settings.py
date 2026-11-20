"""Company settings: the puzzle board.

PatchPilot is built from pieces. Each slot below has built-in pieces, and a
company fills in only what is specific to it in `patchpilot.yaml` (secrets
go in `.env`, referenced as ${NAME}):

  auth      who may use the dashboard and API        none | token | proxy
  forge     where fixes are proposed                 local | github | gitlab
  feed      where advisories come from               files | osv
  notify    who hears about decisions                slack | teams | webhook | email
  llm       which model triages and reviews          see agent/providers.py
  sources, targets, ecosystems                       fleet.yaml

Any slot also takes a custom piece by dotted path, `kind: "my_module:MyClass"`,
loaded from the workspace or `plugins/`. Without a patchpilot.yaml every slot
falls back to the self-contained demo behaviour.

`python -m agent.doctor` shows which pieces are in place and which are missing.
"""
from __future__ import annotations

import importlib
import os
import re
import sys
from typing import Any, Optional

import yaml

from . import config
from .config import load_dotenv  # noqa: F401  (re-exported)

_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
_settings: Optional[dict] = None


def expand(value: Any) -> Any:
    """${NAME} and ${NAME:-default} from the environment, recursively. A missing
    variable becomes "" so `doctor` can point at it instead of crashing."""
    if isinstance(value, str):
        return _VAR.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)
    if isinstance(value, list):
        return [expand(v) for v in value]
    if isinstance(value, dict):
        return {k: expand(v) for k, v in value.items()}
    return value


def missing_vars(value: Any) -> list[str]:
    """Names of ${VARS} in a raw (unexpanded) setting that are not set."""
    text = yaml.safe_dump(value) if not isinstance(value, str) else value
    return sorted({m.group(1) for m in _VAR.finditer(text) if not os.environ.get(m.group(1)) and m.group(2) is None})


def raw() -> dict:
    path = config.SETTINGS_FILE
    return (yaml.safe_load(path.read_text(encoding="utf-8")) or {}) if path.exists() else {}


def get() -> dict:
    global _settings
    if _settings is None:
        _settings = expand(raw())
        _apply_core(_settings)
    return _settings


def set_settings(value: Optional[dict]) -> None:
    """Tests and alternative entry points inject their own settings."""
    global _settings
    _settings = None if value is None else expand(value)
    if _settings is not None:
        _apply_core(_settings)


def section(name: str, default: Any = None) -> Any:
    value = get().get(name, default)
    return default if value is None else value


def _apply_core(s: dict) -> None:
    """Settings that live in agent/config.py; environment variables still win."""
    llm = s.get("llm") or {}
    if llm.get("providers") and "LLM_PROVIDER" not in os.environ:
        config.LLM_PROVIDER = ",".join(llm["providers"]) if isinstance(llm["providers"], list) else llm["providers"]
    if llm.get("mode") and "LLM_MODE" not in os.environ:
        config.LLM_MODE = llm["mode"]


def public_url() -> str:
    return str(section("public_url", "http://localhost:8000")).rstrip("/")


# ------------------------------------------------------------------ pieces

def load_class(kind: str, builtins: dict[str, Any], slot: str):
    """A built-in piece by name, or a custom one by "module:Class"."""
    if kind in builtins:
        return builtins[kind]
    if ":" not in kind:
        raise ValueError(f"unknown {slot} piece {kind!r}; built-in: {', '.join(builtins)}, "
                         f"or a custom piece as 'module:Class'")
    for extra in (config.WORKSPACE, config.WORKSPACE / "plugins"):
        if str(extra) not in sys.path:
            sys.path.append(str(extra))
    module, _, name = kind.partition(":")
    return getattr(importlib.import_module(module), name)
