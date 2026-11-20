"""The company puzzle pieces: settings, auth, forge, feed, notify, doctor.
No network: forge and OSV APIs are faked, git remotes are local bare repos."""
import json
import subprocess
import time

import pytest

from agent import auth, config, db, doctor, feeds, fleet, notify, settings
from agent.drivers import forge
from agent.schemas import Component, Workload


@pytest.fixture(autouse=True)
def clean_pieces():
    yield
    settings.set_settings(None)
    for piece in (auth, notify, feeds):
        piece.reset()
    fleet.set_fleet(None)


def use(cfg: dict) -> None:
    settings.set_settings(cfg)
    for piece in (auth, notify, feeds):
        piece.reset()


# ------------------------------------------------------------------ settings

def test_secrets_come_from_the_environment(monkeypatch, tmp_path):
    env = tmp_path / ".env"
    env.write_text("# comment\nPP_T1='from-dotenv'\nexport PP_T2=two\nPP_T3=ignored\n")
    monkeypatch.setenv("PP_T3", "real-env-wins")
    for k in ("PP_T1", "PP_T2"):
        monkeypatch.delenv(k, raising=False)
    settings.load_dotenv(env)
    raw = {"a": "${PP_T1}", "b": ["x-${PP_T2}"], "c": "${PP_T3}", "d": "${PP_NOPE:-fallback}", "e": "${PP_NOPE}"}
    assert settings.expand(raw) == {"a": "from-dotenv", "b": ["x-two"], "c": "real-env-wins", "d": "fallback", "e": ""}
    assert settings.missing_vars(raw) == ["PP_NOPE"]           # the one with a default is not missing
    monkeypatch.delenv("PP_T1")
    monkeypatch.delenv("PP_T2")


def test_pieces_load_by_name_or_dotted_path():
    assert settings.load_class("slack", notify.BUILTIN, "notify") is notify.Slack
    assert settings.load_class("example_jira:JiraIssue", notify.BUILTIN, "notify").kind == "jira"   # plugins/
    with pytest.raises(ValueError, match="built-in: slack"):
        settings.load_class("pigeon", notify.BUILTIN, "notify")


def test_llm_settings_fill_in_config(monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.setattr(config, "LLM_PROVIDER", "ollama")
    use({"llm": {"providers": ["ollama", "mistral"]}})
    assert config.LLM_PROVIDER == "ollama,mistral"


# ---------------------------------------------------------------------- auth

def test_token_auth_and_approvers():
    use({"auth": {"kind": "token", "tokens": {"alice": "a" * 32, "bob": "b" * 32, "nobody": ""},
                  "approvers": ["alice"]}})
    a = auth.get()
    assert a.identify({"authorization": "Bearer " + "a" * 32}) == "alice"
    assert a.identify({"authorization": "Bearer wrong"}) is None and a.identify({}) is None
    assert a.may_act("alice") and not a.may_act("bob")
    use({"auth": {"kind": "proxy", "header": "X-Auth-Email"}})
    assert auth.get().identify({"x-auth-email": "carol@example.com"}) == "carol@example.com"
    assert auth.get().may_act("carol@example.com")              # no approvers list: everyone may act
    use({"auth": {"kind": "none"}})
    assert auth.get().identify({}) == "anonymous"
    use({})                                                     # the default stays closed: a token is required
    assert auth.get().piece.kind == "token" and auth.get().identify({}) is None


def test_api_requires_login_and_records_who(state):
    from fastapi.testclient import TestClient

    from agent.main import app
    use({"auth": {"kind": "token", "tokens": {"alice": "tok-alice", "bob": "tok-bob"}, "approvers": ["alice"]}})
    client = TestClient(app)                                     # no lifespan: no background threads
    assert client.get("/api/me").status_code == 401
    assert client.get("/").status_code == 200                   # the page itself is public; the data is not
    bob = {"Authorization": "Bearer tok-bob"}
    alice = {"Authorization": "Bearer tok-alice"}
    assert client.get("/api/me", headers=bob).json() == {"user": "bob", "may_act": False, "may_admin": False, "auth": "token"}
    assert client.post("/api/scenarios/log4shell", headers=bob).status_code == 403
    assert client.post("/api/scenarios/log4shell", headers=alice).status_code == 200
    assert client.post("/api/items/999/approve", headers=alice).status_code == 409
    log = client.get("/api/audit", headers=bob).json()
    assert [(e["actor"], e["action"], e["target"]) for e in log] == [("alice", "trigger", "log4shell")]


# --------------------------------------------------------------------- forge

def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=cwd,
                          capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def remote(tmp_path):
    """A bare 'origin' with one commit on main."""
    bare, work = tmp_path / "origin.git", tmp_path / "seed"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(bare)], check=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(work)], check=True)
    (work / "requirements.txt").write_text("acme-textfmt==1.0.0\n")
    git(work, "add", "-A")
    git(work, "commit", "-q", "-m", "init")
    git(work, "push", "-q", str(bare), "main")
    return bare


class FakeAPI:
    def __init__(self, replies):
        self.calls, self.replies = [], list(replies)

    def __call__(self, method, url, **kw):
        self.calls.append((method, url, kw.get("json"), kw.get("params"), kw.get("headers")))
        status, body = self.replies.pop(0)
        return type("R", (), {"status_code": status, "text": json.dumps(body), "json": lambda self: body})()


def test_repo_path_from_clone_urls():
    assert forge.repo_path("https://github.com/acme/shop.git") == "acme/shop"
    assert forge.repo_path("git@gitlab.example.com:group/sub/shop.git") == "group/sub/shop"
    assert forge.repo_path("ssh://git@host/acme/shop") == "acme/shop"


def test_github_source_clones_pushes_and_opens_a_pull_request(remote, tmp_path, monkeypatch):
    api = FakeAPI([(201, {"number": 7, "html_url": "https://github.com/acme/shop/pull/7"}), (200, [])])
    monkeypatch.setattr(forge.requests, "request", api)
    src = fleet.make_source({"name": "shop", "url": str(remote), "repo": "acme/shop", "path": str(tmp_path / "clone")},
                            {"kind": "github", "token": "ghp_secret", "labels": ["security"]})
    assert isinstance(src, forge.GitHubSource) and src.check()[0][0]
    src.ensure()                                                 # cloned on first use
    assert (tmp_path / "clone" / "requirements.txt").exists()

    src.start_change("lighthouse/x")
    (src.path / "requirements.txt").write_text("acme-textfmt==1.0.1\n")
    src.commit("Bump acme-textfmt")
    url = src.accept_change("lighthouse/x", "Bump acme-textfmt", "evidence")
    assert url == "https://github.com/acme/shop/pull/7"
    method, endpoint, body, _, headers = api.calls[0]
    assert (method, endpoint) == ("POST", "https://api.github.com/repos/acme/shop/pulls")
    assert body == {"title": "Bump acme-textfmt", "head": "lighthouse/x", "base": "main", "body": "evidence"}
    assert headers["Authorization"] == "Bearer ghp_secret"
    assert api.calls[1][2] == {"labels": ["security"]}
    # pushed to origin, not merged into main anywhere
    assert "acme-textfmt==1.0.1" in git(remote, "show", "lighthouse/x:requirements.txt")
    assert "1.0.0" in git(remote, "show", "main:requirements.txt")
    assert "1.0.0" in (src.path / "requirements.txt").read_text()


def test_existing_review_is_reused_and_tokens_stay_out_of_git_args(monkeypatch):
    api = FakeAPI([(409, {}), (200, [{"web_url": "https://gitlab.com/g/s/-/merge_requests/3"}])])
    monkeypatch.setattr(forge.requests, "request", api)
    src = forge.GitLabSource("s", "https://gitlab.com/g/s.git", config.WORKSPACE / "nowhere", token="glpat-x")
    assert src.open_review("b", "t", "d") == "https://gitlab.com/g/s/-/merge_requests/3"
    assert api.calls[0][1] == "https://gitlab.com/api/v4/projects/g%2Fs/merge_requests"
    env = src._env()
    assert env["GIT_CONFIG_KEY_0"] == "http.extraHeader" and "glpat-x" not in env["GIT_CONFIG_VALUE_0"]


def test_review_body_carries_the_evidence():
    from agent import pipeline
    wl = Workload(id="eu/shop/orders", name="orders", target="eu", target_kind="kubernetes", provider="Leaseweb",
                  image="i", internet_exposed=True, exposure="lb")
    comp = Component(ecosystem="maven", group="org.apache.logging.log4j", name="log4j-core", version="2.14.1")
    proof = {"before": {"result": "VULNERABLE"}, "after": {"result": "SAFE", "via": "canary"}}
    body = pipeline._review_body({"id": "GHSA-1", "aliases": ["CVE-2021-44228"], "summary": "Log4Shell"},
                                 wl, comp, "2.17.1", [(comp, "2.17.1")], proof, False, "https://pp/#run=1&item=2")
    assert "CVE-2021-44228" in body and "VULNERABLE → SAFE" in body and "CI/CD" in body and "#run=1&item=2" in body


# ---------------------------------------------------------------------- feed

def test_osv_feed_queries_the_fleet_and_filters_by_severity(state, monkeypatch):
    piece = feeds.OsvFeed({"min_severity": "high"})
    monkeypatch.setattr(piece, "packages", lambda: [("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")])
    records = {"GHSA-crit": {"id": "GHSA-crit", "affected": [], "database_specific": {"severity": "CRITICAL"}},
               "GHSA-low": {"id": "GHSA-low", "affected": [], "database_specific": {"severity": "LOW"}}}
    posted = []

    def post(url, json, timeout):
        posted.append(json)
        return type("R", (), {"raise_for_status": lambda s: None,
                              "json": lambda s: {"results": [{"vulns": [{"id": "GHSA-crit"}, {"id": "GHSA-low"}]}]}})()

    def get(url, timeout):
        return type("R", (), {"raise_for_status": lambda s: None, "json": lambda s: records[url.rsplit("/", 1)[1]]})()

    monkeypatch.setattr(feeds.requests, "post", post)
    monkeypatch.setattr(feeds.requests, "get", get)
    found = piece.poll()
    assert [a["id"] for a in found] == ["GHSA-crit"]
    assert posted[0]["queries"][0]["package"] == {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"}
    assert feeds.publish(found) == 1 and feeds.publish(found) == 0
    assert (config.FEED_DIR / "GHSA-crit.json").exists()


def test_a_cve_is_resolved_to_the_record_that_names_packages(monkeypatch):
    cve = {"id": "CVE-2021-44228", "aliases": ["GHSA-jfh8-c2jp-5v3q"], "affected": []}
    ghsa = {"id": "GHSA-jfh8-c2jp-5v3q", "affected": [
        {"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"}, "ranges": []}]}

    def get(url, timeout):
        rec = {"CVE-2021-44228": cve, "GHSA-jfh8-c2jp-5v3q": ghsa}.get(url.rsplit("/", 1)[1])
        return type("R", (), {"status_code": 200 if rec else 404, "raise_for_status": lambda s: None,
                              "json": lambda s: rec})()

    monkeypatch.setattr(feeds.requests, "get", get)
    assert feeds.fetch_osv("CVE-2021-44228")["id"] == "GHSA-jfh8-c2jp-5v3q"
    with pytest.raises(LookupError):
        feeds.fetch_osv("CVE-0000-0000")


# -------------------------------------------------------------------- notify

class Recorder:
    kind = "recorder"
    sent: list = []

    def __init__(self, cfg):
        pass

    def send(self, message):
        Recorder.sent.append(message)


def test_status_changes_reach_the_right_channels(state, monkeypatch):
    use({"public_url": "https://pp.example.com", "notify": [{"kind": "test_pieces:Recorder", "on": ["awaiting_approval"]}]})
    Recorder.sent = []
    monkeypatch.setattr(db, "STATUS_HOOKS", [notify.on_status])
    wl = Workload(id="eu/shop/billing", name="billing", target="eu", target_kind="kubernetes", provider="p",
                  image="i", internet_exposed=True, exposure="lb")
    run = db.create_run("GHSA-x", "CVE-2026-1", "summary")
    item = db.create_item(run, wl, Component(ecosystem="pypi", name="acme-authutils", version="1.0.0"), "1.0.1")
    db.update_item(item, status="running")                       # not subscribed
    db.update_item(item, status="awaiting_approval", decision={"action": "patch", "decision": "needs_approval",
                                                               "reason": "fix vetted suspicious"})
    deadline = time.time() + 5
    while not Recorder.sent and time.time() < deadline:
        time.sleep(0.05)
    assert len(Recorder.sent) == 1
    m = Recorder.sent[0]
    assert m["title"] == "CVE-2026-1 on billing: needs your approval"
    assert m["package"] == "acme-authutils 1.0.0" and m["reason"] == "fix vetted suspicious"
    assert m["url"] == f"https://pp.example.com/#run={run}&item={item}"


def test_a_broken_channel_never_breaks_the_pipeline(state, monkeypatch):
    def boom(item):
        raise RuntimeError("webhook down")
    monkeypatch.setattr(db, "STATUS_HOOKS", [boom])
    wl = Workload(id="a/b/c", name="c", target="a", target_kind="k", provider="p", image="i",
                  internet_exposed=False, exposure="x")
    item = db.create_item(db.create_run("A", "A", ""), wl, Component(ecosystem="pypi", name="n", version="1"), None)
    db.update_item(item, status="failed")
    assert db.get_item(item)["status"] == "failed"


# -------------------------------------------------------------------- doctor

def test_doctor_names_the_missing_pieces(state, monkeypatch, capsys, tmp_path):
    fleet_file = tmp_path / "fleet.yaml"
    fleet_file.write_text("sources:\n  - {name: shop, url: 'https://github.com/acme/shop.git'}\ntargets: []\n")
    monkeypatch.setattr(config, "FLEET_FILE", fleet_file)
    monkeypatch.setattr(config, "LLM_PROVIDER", "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("PP_TOKEN_NOBODY", raising=False)
    settings_raw = {"auth": {"kind": "token", "tokens": {"alice": "${PP_TOKEN_NOBODY}"}},
                    "forge": {"kind": "github", "token": "${PP_TOKEN_NOBODY}"},
                    "notify": [{"kind": "slack", "webhook": ""}]}
    monkeypatch.setattr(settings, "raw", lambda: settings_raw)
    use(settings_raw)
    assert doctor.main() == 1
    out = capsys.readouterr().out
    for expected in ("fill in (in .env or the environment): PP_TOKEN_NOBODY", "auth.tokens is empty",
                     "shop: fill in the github token", "fill in the Slack webhook URL", "openai: fill in OPENAI_API_KEY",
                     "no targets"):
        assert expected in out, expected
