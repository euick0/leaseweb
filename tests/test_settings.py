"""The settings page: model choice, AI permissions, scope and the server view.
Changes go to state/ui-settings.json over the files and are audited."""
import pytest
from fastapi.testclient import TestClient

from agent import auth, config, db, fleet, overrides, policy, providers, settings
from agent.main import app
from agent.schemas import Component, Workload

ADMIN = {"Authorization": "Bearer tok-alice"}
VIEWER = {"Authorization": "Bearer tok-bob"}


@pytest.fixture
def client(state, monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.setattr(config, "LLM_PROVIDER", "ollama")
    settings.set_settings({"auth": {"kind": "token", "tokens": {"alice": "tok-alice", "bob": "tok-bob"},
                                    "approvers": ["alice", "bob"], "admins": ["alice"]}})
    auth.reset()
    providers.reset()
    fleet.set_fleet(fleet.Fleet({"sources": [], "targets": []}))
    yield TestClient(app)                                    # no lifespan: no background threads
    settings.set_settings(None)
    auth.reset()
    providers.reset()
    fleet.set_fleet(None)


def test_settings_are_readable_by_everyone_and_changed_only_by_admins(client):
    s = client.get("/api/settings", headers=VIEWER).json()
    assert s["me"] == {"user": "bob", "may_admin": False}
    assert [p["name"] for p in s["llm"]["chain"]] == ["ollama"]
    assert set(s["policy"]["presets"]) == {"observe", "balanced", "autonomous"}
    body = {"providers": ["ollama"], "mode": "cache", "models": {"ollama": "llama3.1:8b"}}
    assert client.put("/api/settings/llm", json=body, headers=VIEWER).status_code == 403
    assert client.put("/api/settings/scope", json={"targets": ["eu"]}, headers=VIEWER).status_code == 403
    assert client.get("/api/me", headers=VIEWER).json()["may_act"] is True        # bob still approves


def test_model_choice_overrides_the_environment(client):
    r = client.put("/api/settings/llm", headers=ADMIN,
                   json={"providers": ["ollama"], "mode": "cache", "models": {"ollama": "llama3.1:8b"}})
    assert r.status_code == 200, r.text
    assert [(p.name, p.model) for p in providers.chain()] == [("ollama", "llama3.1:8b")]
    assert overrides.llm_mode() == "cache"
    assert client.put("/api/settings/llm", headers=ADMIN, json={"providers": ["pigeon"]}).status_code == 422
    assert client.delete("/api/settings/llm", headers=ADMIN).status_code == 200
    assert overrides.llm_mode() == config.LLM_MODE and providers.chain()[0].model == config.OLLAMA_MODEL
    log = db.audit_log()
    assert [(e["actor"], e["action"], e["target"]) for e in log][:2] == [("alice", "settings", "llm")] * 2


def test_hosted_models_need_the_policy_to_allow_them(client):
    hosted = {"providers": ["ollama", "deepseek"], "mode": "live"}
    r = client.put("/api/settings/llm", headers=ADMIN, json=hosted)
    assert r.status_code == 409 and "allow_hosted_llm" in r.json()["detail"]
    assert [p.name for p in providers.chain()] == ["ollama"]                    # nothing was saved
    assert client.put("/api/settings/policy", headers=ADMIN, json={"allow_hosted_llm": True}).status_code == 200
    assert client.put("/api/settings/llm", headers=ADMIN, json=hosted).status_code == 200
    # forbidding hosted models again while one is chosen would break the next question
    assert client.put("/api/settings/policy", headers=ADMIN, json={"allow_hosted_llm": False}).status_code == 409
    assert client.delete("/api/settings/policy", headers=ADMIN).status_code == 409
    assert client.put("/api/settings/policy", headers=ADMIN, json={"preset": "observe"}).status_code == 200
    assert policy.fleet()["allow_hosted_llm"] is True                           # a preset never changes sovereignty


def test_permission_levels_are_validated_and_layered_over_policy_yaml(client):
    assert client.put("/api/settings/policy", headers=ADMIN, json={"patch": {"malicious": "auto"}}).status_code == 422
    assert client.put("/api/settings/policy", headers=ADMIN, json={"mitigate": "sometimes"}).status_code == 422
    r = client.put("/api/settings/policy", headers=ADMIN, json={"preset": "autonomous"})
    assert r.status_code == 200
    eff = policy.fleet()
    assert eff["patch"]["clean"] == "auto" and eff["mitigate"] == "auto" and eff["act_now_when"] == "always"
    assert eff["patch"]["suspicious"] == "needs_approval" and eff["patch"]["malicious"] == "block"
    stored = overrides.section("policy")
    assert "malicious" not in stored.get("patch", {})                          # only what differs from the file
    client.put("/api/settings/policy", headers=ADMIN, json={"preset": "balanced"})
    assert overrides.section("policy") == {} and policy.fleet() == policy.file_policy()


def test_scope_leaves_workloads_and_packages_alone(client):
    wl = Workload(id="eu/shop/billing", name="billing", target="eu", target_kind="k", provider="p", image="i",
                  internet_exposed=True, exposure="")
    log4j = Component(ecosystem="maven", group="org.apache.logging.log4j", name="log4j-core", version="2.14.1")
    assert overrides.in_scope(wl) and overrides.package_in_scope(log4j)
    r = client.put("/api/settings/scope", headers=ADMIN,
                   json={"workloads": ["eu/shop/billing"], "packages": ["org.apache.logging.log4j:log4j-core"]})
    assert r.status_code == 200
    assert not overrides.in_scope(wl) and not overrides.package_in_scope(log4j)
    client.put("/api/settings/scope", headers=ADMIN, json={"targets": ["eu"], "ecosystems": ["pypi"]})
    assert not overrides.in_scope(wl)
    assert not overrides.package_in_scope(Component(ecosystem="pypi", name="x", version="1"))
    client.delete("/api/settings/scope", headers=ADMIN)
    assert overrides.in_scope(wl)


def test_system_view(client):
    s = client.get("/api/system", headers=VIEWER).json()
    assert s["host"]["cpus"] and s["host"]["disk"]["total"] > 0
    assert s["agent"]["auth"] == "token" and "items" in s["agent"]
    assert "reachable" in s["ollama"] and isinstance(s["tools"], dict)
    assert client.get("/settings").status_code == 200
