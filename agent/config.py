"""Runtime configuration. Paths and knobs come from environment variables
(and `.env`); what the fleet looks like (sources, targets) comes from
fleet.yaml; the company's pieces (auth, forge, feed, notify) from
patchpilot.yaml, see agent/settings.py."""
from __future__ import annotations

import os
import re
from pathlib import Path

WORKSPACE = Path(os.environ.get("PP_WORKSPACE", Path(__file__).resolve().parent.parent))


def load_dotenv(path: Path) -> None:
    """KEY=value lines from .env into the environment; real variables win."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$", line)
        if m and not line.lstrip().startswith("#") and m.group(1) not in os.environ:
            value = m.group(2)
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            os.environ[m.group(1)] = value


load_dotenv(Path(os.environ.get("PP_ENV_FILE", WORKSPACE / ".env")))
SETTINGS_FILE = Path(os.environ.get("PP_CONFIG", WORKSPACE / "patchpilot.yaml"))

ARTIFACTS = WORKSPACE / "artifacts"
# Recorded when an artifact first enters the store, and kept outside it: whoever can
# swap a file in artifacts/ cannot fix up its checksum in the same place.
CHECKSUMS = Path(os.environ.get("PP_CHECKSUMS", WORKSPACE / "checksums.lock"))
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
# An update that changes at most this many files is reviewed in full; a larger
# one must have its flagged files, new files and the advisory's focus files reviewed.
VET_REVIEW_ALL_UP_TO = int(os.environ.get("VET_REVIEW_ALL_UP_TO", "20"))

# Canary and rollout
HEALTH_TIMEOUT = float(os.environ.get("PP_HEALTH_TIMEOUT", "60"))
ROLLOUT_TIMEOUT = float(os.environ.get("PP_ROLLOUT_TIMEOUT", "120"))

# Demo controls (publish a scenario, wipe the decision log) exist only with PP_DEMO=1.
DEMO = os.environ.get("PP_DEMO", "") == "1"

FEED_POLL_SECONDS = float(os.environ.get("FEED_POLL_SECONDS", "2"))
