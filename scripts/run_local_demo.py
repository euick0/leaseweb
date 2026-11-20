#!/usr/bin/env python3
"""Run PatchPilot on a laptop with no Docker, Kubernetes or model: the fleet is
the local fake from tests/fakes.py (billing-py really runs, the Java services
are simulated) and the model answers come from the cache.

  uv run scripts/run_local_demo.py          # then open http://localhost:8000

For dashboard and pipeline work away from the server. State goes to
state/local-demo/ and is wiped on every start.
"""
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
os.environ.setdefault("LLM_MODE", "cache")
os.environ.setdefault("PP_DEMO", "1")

from agent import config  # noqa: E402

work = ROOT / "state" / "local-demo"
shutil.rmtree(work, ignore_errors=True)
config.STATE_DIR = work
config.REPOS_DIR = work / "repos"
config.DB_PATH = work / "decisions.sqlite"
config.FEED_DIR = work / "feed"
config.LLM_MODE = os.environ["LLM_MODE"]

import uvicorn  # noqa: E402

from agent import fleet  # noqa: E402
from fakes import LocalBuilder, LocalTarget  # noqa: E402

sys.path.insert(0, str(ROOT / "scripts"))
import init_repos  # noqa: E402

init_repos.DEST = config.REPOS_DIR
names = ("orders-java", "reports-java", "billing-py")
for n in names:
    init_repos.init(n)

fl = fleet.Fleet({"sources": [{"name": n, "url": f"https://git.acme.example/shop/{n}", "path": str(config.REPOS_DIR / n)}
                              for n in names],
                  "targets": [{"name": "hyperscaler", "kind": "local", "label": "Hyperscaler (stand-in)",
                               "provider": "local fake"},
                              {"name": "eu", "kind": "local", "label": "EU sovereign cloud", "provider": "local fake"}]})
builder = LocalBuilder(work)
fl.builder = builder
v1 = {n: builder.build(str(config.REPOS_DIR / n), n, "", "v1", False) for n in names}
fl.targets = {
    "hyperscaler": LocalTarget("hyperscaler", builder, {"orders-java": {"image": v1["orders-java"], "exposed": True}}),
    "eu": LocalTarget("eu", builder, {"billing-py": {"image": v1["billing-py"], "exposed": True},
                                      "reports-java": {"image": v1["reports-java"], "exposed": False}}),
}
fleet.set_fleet(fl)

from agent.main import app  # noqa: E402

try:
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", "8000")))
finally:
    for t in fl.targets.values():
        t.close()
