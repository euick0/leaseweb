import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent import config, db  # noqa: E402


@pytest.fixture
def state(tmp_path, monkeypatch):
    """Isolated decision log, feed and repositories; cached model answers only."""
    monkeypatch.setattr(config, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(config, "REPOS_DIR", tmp_path / "state" / "repos")
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "state" / "decisions.sqlite")
    monkeypatch.setattr(config, "FEED_DIR", tmp_path / "feed")
    monkeypatch.setattr(config, "LLM_MODE", "cache")
    monkeypatch.setattr(config, "HEALTH_TIMEOUT", 15.0)
    (tmp_path / "feed").mkdir()
    db.reset_connection()
    yield tmp_path
    db.reset_connection()


def scenario(name: str) -> dict:
    return json.loads((ROOT / "scenarios" / f"{name}.json").read_text())
