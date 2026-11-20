"""End to end through the real pipeline, policy, vetter, git source and
ecosystem drivers, against the local fakes in tests/fakes.py. Triage uses the
cached model answers; diff reviews come from the stand-in model in conftest."""
import importlib.util
import json
import shutil
import subprocess
import time

import pytest

from agent import config, db, fleet, llm, pipeline
from conftest import ROOT, scenario
from fakes import LocalBuilder, LocalTarget

pytestmark = pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv to build service virtualenvs")


@pytest.fixture
def demo(state, model):
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
    assert pr["head"].startswith("lighthouse/") and "VULNERABLE → SAFE" in pr["body"]
    assert "2.17.1" in subprocess.run(["git", "show", f"{pr['head']}:vendor.txt"], cwd=bare,
                                      capture_output=True, text=True).stdout
    assert "2.14.1" in git("orders-java", "show", "main:vendor.txt")          # nothing merged
    assert demo.target("hyperscaler").list_workloads()[0].image == image_before  # CI/CD deploys, not us


def test_model_down_never_patches_without_a_human(demo, monkeypatch):
    def down(*a, **kw):
        raise llm.LLMUnavailable("connection refused")
    monkeypatch.setattr(llm, "complete", down)
    images_before = len(demo.builder.images)
    run_id = publish("log4shell")
    items = items_by_workload(run_id)
    orders, reports = items["orders-java"], items["reports-java"]

    assert orders["status"] == "awaiting_approval" and reports["status"] == "awaiting_approval"
    assert "not fully reviewed" in orders["decision"]["reason"]
    assert len(demo.builder.images) == images_before                # nothing was built
    assert all(db.vet_cache_get(k)["verdict"] == "unreviewed" for k in orders["vet_key"].split(","))
    # the incomplete verdict is not reused for the second workload: it is vetted again
    assert not any("cached verdict reused" in t for t in titles(run_id, reports["id"]))

    pipeline.approve(orders["id"])                                   # a human can still take the decision
    orders = wait_settled(orders["id"])
    assert orders["status"] == "done", orders["outcome"]
    assert (orders["proof"]["before"]["result"], orders["proof"]["after"]["result"]) == ("VULNERABLE", "SAFE")


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


def test_trojan_then_zeroday_is_not_a_fake_before_and_after(demo):
    """The zero-day hits the same header the trojan run already blocks: say so, do not claim the block."""
    first = items_by_workload(publish("trojan"))["billing-py"]
    pipeline.approve(first["id"])
    assert wait_settled(first["id"])["status"] == "done"

    run_id = publish("zeroday")
    billing = items_by_workload(run_id)["billing-py"]
    pipeline.approve(billing["id"], "maria")
    billing = wait_settled(billing["id"])
    assert billing["status"] == "done" and "already blocked by an earlier virtual patch" in billing["outcome"]
    assert billing["proof"] == {"level": "already blocked before this action"}
    assert set(demo.targets["eu"].rules["billing-py"]) == {"pp-ppsa-2026-0007", "pp-ppsa-2026-0011"}
    assert billing["decided_by"] == "maria"


def test_mitigation_that_breaks_the_service_is_removed(demo):
    run_id = publish("zeroday")
    billing = items_by_workload(run_id)["billing-py"]
    # a rule that does stop the exploit request, and every other request with it (the health check too)
    db.update_item(billing["id"], triage={**billing["triage"], "mitigation_pattern": "e"})
    pipeline.approve(billing["id"])
    billing = wait_settled(billing["id"])
    assert billing["status"] == "rolled_back" and "broke the health check" in billing["outcome"]
    assert demo.targets["eu"].rules["billing-py"] == {}
    assert any(t.startswith("Virtual patch removed") for t in titles(run_id, billing["id"]))
    wl = next(w for w in demo.discover(max_age=0) if w.name == "billing-py")
    assert demo.targets["eu"].http(wl, "/health").status == 200


def test_log4shell_block_must_cover_the_url_path(demo):
    from agent import mitigation, probes
    target = demo.targets["hyperscaler"]
    wl = next(w for w in demo.discover(max_age=0) if w.name == "orders-java")
    header_only = "\n".join(l for l in mitigation.render("x", "${", ["header:X-Api-Version"]).splitlines()
                            if "$request_uri" not in l)
    target.apply_mitigation(wl, "old-style", header_only)
    assert probes.log4shell(target, wl, "public", wait=1).result == "VULNERABLE"      # /${jndi:...} gets through
    target.apply_mitigation(wl, "old-style", mitigation.render("x", "${", ["header:X-Api-Version"]))
    assert probes.log4shell(target, wl, "public", wait=1).result == "BLOCKED"


def test_two_approvals_at_once_run_the_action_once(demo):
    import threading
    run_id = publish("zeroday")
    item = items_by_workload(run_id)["billing-py"]
    results, start = [], threading.Barrier(8)

    def decide(i):
        start.wait()
        try:
            (pipeline.approve if i % 2 else pipeline.reject)(item["id"], f"op{i}")
            results.append(i)
        except ValueError:
            pass
    threads = [threading.Thread(target=decide, args=(i,)) for i in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(results) == 1
    final = wait_settled(item["id"])
    assert final["decided_by"] == f"op{results[0]}"
    assert sum("Approved by" in t or "Rejected by" in t for t in titles(run_id, item["id"])) == 1


def test_api_needs_a_token_and_demo_controls_need_the_flag(demo, monkeypatch):
    from fastapi.testclient import TestClient
    from agent.main import app

    with TestClient(app) as client:
        assert "LightHouse" in client.get("/").text                  # the page itself carries no data
        for method, path in (("get", "/api/fleet"), ("get", "/api/runs"), ("post", "/api/probe"),
                             ("post", "/api/reset"), ("post", "/api/scenarios/zeroday"), ("post", "/api/items/1/approve")):
            assert getattr(client, method)(path).status_code == 401, path
            assert getattr(client, method)(path, headers={"Authorization": "Bearer nope"}).status_code == 401, path
        eric = {"Authorization": "Bearer tok-eric"}
        assert client.get("/api/fleet", headers=eric).json()["llm"]["sovereign"] is True

        monkeypatch.setattr(config, "DEMO", False)                   # production: no scenario buttons, no wipe
        assert client.post("/api/reset", headers=eric).status_code == 404
        assert client.post("/api/scenarios/zeroday", headers=eric).status_code == 404
        assert client.get("/api/scenarios", headers=eric).json() == []
        assert list(config.FEED_DIR.glob("*.json")) == []


def test_api_and_dashboard(demo):
    from fastapi.testclient import TestClient
    from agent.main import app

    with TestClient(app, headers={"Authorization": "Bearer tok-maria"}) as client:
        assert "LightHouse" in client.get("/").text
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
        done = wait_settled(item["id"])
        assert done["status"] == "done" and done["decided_by"] == "maria"
        assert "Approved by maria: mitigate" in titles(run_id, item["id"])
        assert client.post("/api/reset").json() == {"ok": True}
        assert client.get("/api/runs").json() == []


def test_out_of_scope_workloads_are_left_alone(demo):
    from agent import overrides
    overrides.put("scope", {"workloads": ["hyperscaler/shop/orders-java"]})
    items = items_by_workload(publish("log4shell"))
    assert set(items) == {"reports-java"}                       # orders-java carries log4j too, but is excluded
    assert pipeline.probes_for(demo, demo.workload("hyperscaler/shop/orders-java"), [scenario("log4shell")]) == []
