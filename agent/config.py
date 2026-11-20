"""Runtime configuration. Paths and knobs come from environment variables;
what the fleet looks like (sources, targets) comes from fleet.yaml."""
from __future__ import annotations

import os
from pathlib import Path

WORKSPACE = Path(os.environ.get("PP_WORKSPACE", Path(__file__).resolve().parent.parent))

ARTIFACTS = WORKSPACE / "artifacts"
FEED_DIR = WORKSPACE / "feed"
SCENARIOS_DIR = WORKSPACE / "scenarios"
FLEET_FILE = Path(os.environ.get("PP_FLEET", WORKSPACE / "fleet.yaml"))
POLICY_FILE = Path(os.environ.get("PP_POLICY", WORKSPACE / "policy.yaml"))
STATE_DIR = Path(os.environ.get("PP_STATE", WORKSPACE / "state"))
REPOS_DIR = STATE_DIR / "repos"
CACHE_DIR = Path(os.environ.get("PP_CACHE_DIR", Path(__file__).resolve().parent / "cache"))
DB_PATH = Path(os.environ.get("PP_DB", STATE_DIR / "decisions.sqlite"))

# LLM
# One provider, or a comma-separated fallback chain tried in order, e.g.
# "ollama,deepseek". Known: ollama (open-weight model on our own hardware, the
# hackathon setup), openai, anthropic, gemini, deepseek, kimi, mistral,
# openai-compatible. Per-provider settings are in agent/providers.py.
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "ollama")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:14b")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-opus-5-5")
ANTHROPIC_EFFORT = os.environ.get("ANTHROPIC_EFFORT", "medium")
# live  = ask the model, fall back to the cache on failure
# cache = only use cached answers (stage safety net)
LLM_MODE = os.environ.get("LLM_MODE", "live")
LLM_TIMEOUT = float(os.environ.get("LLM_TIMEOUT", "120"))
VET_BUDGET_SECONDS = float(os.environ.get("VET_BUDGET_SECONDS", "60"))

# Canary and rollout
HEALTH_TIMEOUT = float(os.environ.get("PP_HEALTH_TIMEOUT", "60"))
ROLLOUT_TIMEOUT = float(os.environ.get("PP_ROLLOUT_TIMEOUT", "120"))

FEED_POLL_SECONDS = float(os.environ.get("FEED_POLL_SECONDS", "2"))
