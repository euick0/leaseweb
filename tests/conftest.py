import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent import config, db, llm  # noqa: E402
from agent.schemas import ChunkReview  # noqa: E402


@pytest.fixture
def state(tmp_path, monkeypatch):
    """Isolated decision log, feed and repositories; cached model answers only."""
    monkeypatch.setattr(config, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(config, "REPOS_DIR", tmp_path / "state" / "repos")
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "state" / "decisions.sqlite")
    monkeypatch.setattr(config, "FEED_DIR", tmp_path / "feed")
    monkeypatch.setattr(config, "LLM_MODE", "cache")
    monkeypatch.setattr(config, "HEALTH_TIMEOUT", 15.0)
    monkeypatch.setattr(config, "DEMO", True)
    monkeypatch.setattr(llm, "egress", {"local_calls": 0, "hosted_calls": 0, "redactions": 0})
    monkeypatch.setenv("PP_API_TOKENS", "eric:tok-eric,maria:tok-maria")
    monkeypatch.delenv("PP_API_TOKEN", raising=False)
    (tmp_path / "feed").mkdir()
    db.reset_connection()
    yield tmp_path
    db.reset_connection()


@pytest.fixture
def model(state, monkeypatch):
    """A live stand-in model for diff reviews: it calls the trojan's load-time report
    exfiltration and everything else consistent with the fix. Triage still comes from the
    cached answers. Works on a copy of the cache, so tests never write to agent/cache."""
    shutil.copytree(config.CACHE_DIR, state / "cache")
    monkeypatch.setattr(config, "CACHE_DIR", state / "cache")
    monkeypatch.setattr(config, "LLM_MODE", "live")
    seen: list[str] = []

    def complete(system, user, schema, timeout=None):
        if schema is not ChunkReview:
            raise llm.LLMUnavailable("the test model only reviews diffs")
        seen.append(user)
        bad = "+_report(_snapshot())" in user
        return ChunkReview(suspicious=bad, confidence="high" if bad else "low",
                           category="data_exfiltration" if bad else "security_fix",
                           evidence_lines=["_report(_snapshot())", "not in the diff"] if bad else [],
                           explanation="test model"), "test:model"

    monkeypatch.setattr(llm, "complete", complete)
    return seen


@pytest.fixture
def fleet_policy(tmp_path, monkeypatch):
    """Write the fleet policy file for this test: fleet_policy("allow_hosted_llm: true")."""
    def write(text: str) -> None:
        (tmp_path / "policy.yaml").write_text(text)
        monkeypatch.setattr(config, "POLICY_FILE", tmp_path / "policy.yaml")
    return write


def scenario(name: str) -> dict:
    return json.loads((ROOT / "scenarios" / f"{name}.json").read_text())
