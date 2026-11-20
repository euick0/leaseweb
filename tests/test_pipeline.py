"""End to end through the real pipeline, policy, vetter, git source and
ecosystem drivers, against the local fakes in tests/fakes.py. Uses the seeded
model answers (LLM_MODE=cache)."""
import importlib.util
import json
import shutil
import subprocess
import time

import pytest

from agent import config, db, fleet, pipeline
from conftest import ROOT, scenario
from fakes import LocalBuilder, LocalTarget

pytestmark = pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv to build service virtualenvs")


@pytest.fixture
def demo(state):
    spec = importlib.util.spec_from_file_location("init_repos", ROOT / "scripts/init_repos.py")
    init_repos = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(init_repos)
    init_repos.DEST = config.REPOS_DIR
    for name in ("orders-java", "reports-java", "billing-py"):
        init_repos.init(name)

    fl = fleet.Fleet({"sources": [{"name": n, "url": f"https://git.acme.example/shop/{n}",
                                   "path": str(config.REPOS_DIR / n)}
                                  for n in ("orders-java", "reports-java", "billing-py")],
                      "targets": [{"name": "hyperscaler", "kind": "local"}, {"name": "eu", "kind": "local"}]})
    builder = LocalBuilder(state)
    fl.builder = builder
    v1 = {n: builder.build(str(config.REPOS_DIR / n), n, "", "v1", False)
          for n in ("orders-java", "reports-java", "billing-py")}
    fl.targets = {
        "hyperscaler": LocalTarget("hyperscaler", builder, {"orders-java": {"image": v1["orders-java"], "exposed": True}}),
        "eu": LocalTarget("eu", builder, {"billing-py": {"image": v1["billing-py"], "exposed": True},
                                          "reports-java": {"image": v1["reports-java"], "exposed": False}}),
    }
    fleet.set_fleet(fl)
    pipeline.forget_sboms()
    yield fl
    for t in fl.targets.values():
        t.close()
    fleet.set_fleet(None)


def publish(name: str) -> int:
    adv = scenario(name)
    (config.FEED_DIR / f"{name}.json").write_text(json.dumps(adv))
    return pipeline.run_advisory(adv)


def items_by_workload(run_id: int) -> dict:
    return {i["workload"]["name"]: i for i in db.items(run_id)}


def wait_settled(item_id: int, timeout: float = 60) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        item = db.get_item(item_id)
        if item["status"] != "running":
            return item
        time.sleep(0.2)
    raise AssertionError("item still running")


def titles(run_id: int, item_id: int) -> list[str]:
    return [e["title"] for e in db.events(run_id) if e["item_id"] == item_id]


def git(repo: str, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=config.REPOS_DIR / repo, capture_output=True, text=True).stdout


def test_log4shell_same_cve_two_verdicts(demo):
    run_id = publish("log4shell")
    items = items_by_workload(run_id)
    assert set(items) == {"orders-java", "reports-java"}            # billing-py does not carry log4j

    orders = items["orders-java"]
    assert orders["rank"] == 1 and orders["status"] == "done", orders["outcome"]
    assert (orders["proof"]["before"]["result"], orders["proof"]["after"]["result"]) == ("VULNERABLE", "SAFE")
    assert orders["proof"]["after"]["via"] == "public"
    assert sorted(p.name for p in (config.REPOS_DIR / "orders-java/lib").glob("*.jar")) == \
        ["log4j-api-2.17.1.jar", "log4j-core-2.17.1.jar"]
    assert "2.17.1" in git("orders-java", "show", "HEAD:vendor.txt")
    assert "Bump org.apache.logging.log4j:log4j-core" in git("orders-java", "log", "-1", "--format=%s")

    reports = items["reports-java"]
    assert reports["rank"] == 2 and reports["status"] == "queued"
    assert "not internet-exposed" in reports["outcome"]
    assert any("cached verdict reused" in t for t in titles(run_id, reports["id"]))

    pipeline.approve(reports["id"])                                  # operator: "act now"
    reports = wait_settled(reports["id"])
    assert reports["status"] == "done", reports["outcome"]
    assert (reports["proof"]["before"]["result"], reports["proof"]["after"]["result"]) == ("VULNERABLE", "SAFE")
    assert reports["proof"]["after"]["via"] == "internal"


def test_propose_only_opens_a_pull_request_and_leaves_production_to_ci(demo, monkeypatch, tmp_path):
    """forge: github, deploy: false. The fix is verified on a canary, pushed to the
    company's remote and proposed as a pull request; production is not touched."""
    from agent.drivers import forge
    repo = config.REPOS_DIR / "orders-java"
    bare = tmp_path / "orders-java.git"
    subprocess.run(["git", "clone", "-q", "--bare", str(repo), str(bare)], check=True)
    subprocess.run(["git", "remote", "add", "origin", str(bare)], cwd=repo, check=True)
    calls = []

    def fake_api(method, url, **kw):
        calls.append((method, url, kw.get("json")))
        body = {"number": 12, "html_url": "https://github.com/acme/orders-java/pull/12"}
        return type("R", (), {"status_code": 201, "text": "", "json": lambda self: body})()

    monkeypatch.setattr(forge.requests, "request", fake_api)
    demo.sources["orders-java"] = forge.GitHubSource("orders-java", str(bare), repo, token="t",
                                                      repo="acme/orders-java", deploy=False)
    image_before = demo.target("hyperscaler").list_workloads()[0].image

    orders = items_by_workload(publish("log4shell"))["orders-java"]
    assert orders["status"] == "proposed", orders["outcome"]
    assert (orders["proof"]["before"]["result"], orders["proof"]["after"]["result"]) == ("VULNERABLE", "SAFE")
    assert orders["proof"]["after"]["via"] == "canary"
    assert "pull/12" in orders["outcome"]
    pr = calls[0][2]
    assert pr["head"].startswith("patchpilot/") and "VULNERABLE → SAFE" in pr["body"]
    assert "2.17.1" in subprocess.run(["git", "show", f"{pr['head']}:vendor.txt"], cwd=bare,
                                      capture_output=True, text=True).stdout
    assert "2.14.1" in git("orders-java", "show", "main:vendor.txt")          # nothing merged
    assert demo.target("hyperscaler").list_workloads()[0].image == image_before  # CI/CD deploys, not us


def test_trojan_fix_blocked_then_virtual_patch(demo):
    images_before = len(demo.builder.images)
    run_id = publish("trojan")
    billing = items_by_workload(run_id)["billing-py"]
    assert billing["status"] == "awaiting_approval"
    assert billing["decision"]["action"] == "mitigate" and "malicious" in billing["decision"]["reason"]
    assert len(demo.builder.images) == images_before                # the poisoned fix was never built
    assert git("billing-py", "branch", "--list").strip() == "* main"

    pipeline.approve(billing["id"])
    billing = wait_settled(billing["id"])
    assert billing["status"] == "done", billing["outcome"]
    assert (billing["proof"]["before"]["result"], billing["proof"]["after"]["result"]) == ("VULNERABLE", "BLOCKED")
    assert "Service still healthy behind the rule" in titles(run_id, billing["id"])


def test_zeroday_needs_approval_and_blocks(demo):
    run_id = publish("zeroday")
    billing = items_by_workload(run_id)["billing-py"]
    assert billing["fixed_version"] is None and billing["status"] == "awaiting_approval"
    pipeline.approve(billing["id"])
    assert wait_settled(billing["id"])["proof"]["after"]["result"] == "BLOCKED"


def test_badupdate_canary_fails_and_production_keeps_serving(demo):
    run_id = publish("badupdate")
    billing = items_by_workload(run_id)["billing-py"]
    assert billing["status"] == "rolled_back", billing["outcome"]
    assert "/health" in billing["outcome"] and "TEXTFMT_STYLE" in billing["outcome"]
    assert "Production still serving the previous version" in titles(run_id, billing["id"])
    assert "acme-textfmt==1.0.0" in (config.REPOS_DIR / "billing-py/requirements.txt").read_text()
    assert git("billing-py", "rev-parse", "--abbrev-ref", "HEAD").strip() == "main"
    assert demo.targets["eu"].canary == {}


def test_unaffected_advisory_touches_nothing(demo):
    adv = scenario("trojan")
    adv["id"] = "PPSA-TEST-NONE"
    adv["affected"][0]["package"]["name"] = "some-other-lib"
    (config.FEED_DIR / "none.json").write_text(json.dumps(adv))
    run_id = pipeline.run_advisory(adv)
    assert db.get_run(run_id)["outcome"] == "no workload affected" and db.items(run_id) == []


def test_api_and_dashboard(demo):
    from fastapi.testclient import TestClient
    from agent.main import app

    with TestClient(app) as client:
        assert "PatchPilot" in client.get("/").text
        fleet_view = client.get("/api/fleet").json()
        assert {w["name"] for w in fleet_view["workloads"]} == {"orders-java", "reports-java", "billing-py"}
        probed = client.post("/api/probe").json()
        assert {(p["workload"], p["probe"], p["result"]) for p in probed} == {
            ("hyperscaler/shop/orders-java", "log4shell", "VULNERABLE"),
            ("eu/shop/reports-java", "log4shell", "VULNERABLE"),
            ("eu/shop/billing-py", "keyid-traversal", "VULNERABLE")}
        shown = {w["name"]: [p["result"] for p in w["probes"]] for w in client.get("/api/fleet").json()["workloads"]}
        assert shown["billing-py"] == ["VULNERABLE"]
        assert client.post("/api/scenarios/zeroday").status_code == 200
        deadline = time.time() + 30
        while time.time() < deadline and not client.get("/api/runs").json():
            time.sleep(0.2)
        run_id = client.get("/api/runs").json()[0]["id"]
        item = {"status": None}
        deadline = time.time() + 30
        while time.time() < deadline and item["status"] != "awaiting_approval":
            time.sleep(0.2)
            items = client.get(f"/api/runs/{run_id}").json()["items"]   # a run exists before its items
            item = items[0] if items else item
        assert client.post(f"/api/items/{item['id']}/approve").status_code == 200
        assert client.post(f"/api/items/{item['id']}/approve").status_code == 409
        assert wait_settled(item["id"])["status"] == "done"
        assert client.post("/api/reset").json() == {"ok": True}
        assert client.get("/api/runs").json() == []
