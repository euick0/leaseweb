"""Repository audit (agent/repo_audit.py): repo-only sources, OSV matching,
govulncheck reachability, local fix proposals and the API. No network: OSV is
mocked from tests/fixtures/golib-osv.json, and `go` / `govulncheck` are small
stand-in scripts, so the real toolchain is never asked to download anything."""
import json
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from agent import auth, db, fleet, repo_audit, settings
from agent.schemas import Component

FIXTURES = Path(__file__).resolve().parent / "fixtures"
OSV = json.loads((FIXTURES / "golib-osv.json").read_text())

FAKE_GO = """
import re, sys, os
args = sys.argv[1:]
if args[:1] == ["get"]:
    mod, ver = args[1].split("@")
    text = open("go.mod").read()
    open("go.mod", "w").write(re.sub(re.escape(mod) + r" v\\S+", mod + " " + ver, text))
    with open("go.sum", "a") as f:
        f.write(f"{mod} {ver} h1:TESTFIXTUREnotarealhash=\\n{mod} {ver}/go.mod h1:TESTFIXTUREnotarealhash=\\n")
elif args[:1] == ["build"]:
    print("built")
elif args[:1] == ["test"]:
    if os.environ.get("LH_FAKE_TEST_FAIL") and "v0.17.0" not in open("go.mod").read():
        print("--- FAIL: TestParse"); sys.exit(1)
    print("ok  \\texample.com/lhfixture\\t0.01s")
"""

FAKE_GOVULNCHECK = """
import json, sys
mod = open("go.mod").read()
out = [{"config": {"protocol_version": "v1.0.0", "scanner_name": "govulncheck"}}]
if "golang.org/x/net v0.17.0" in mod:
    out.append({"osv": {"id": "GO-2024-2687", "aliases": ["CVE-2023-45288", "GHSA-4v7x-pqxf-cx7m"],
                        "summary": "HTTP/2 CONTINUATION flood"}})
    out.append({"finding": {"osv": "GO-2024-2687", "fixed_version": "v0.23.0",
                            "trace": [{"module": "golang.org/x/net", "version": "v0.17.0"}]}})
    out.append({"finding": {"osv": "GO-2024-2687", "fixed_version": "v0.23.0",
                            "trace": [{"module": "golang.org/x/net", "version": "v0.17.0",
                                       "package": "golang.org/x/net/html", "function": "Parse"},
                                      {"module": "example.com/lhfixture", "package": "example.com/lhfixture",
                                       "function": "Parse"}]}})
if "golang.org/x/text v0.13.0" in mod:
    out.append({"osv": {"id": "GO-2099-0001", "aliases": ["GHSA-0000-lhtx-0001"], "summary": "made-up"}})
    out.append({"finding": {"osv": "GO-2099-0001", "fixed_version": "v0.14.0",
                            "trace": [{"module": "golang.org/x/text", "version": "v0.13.0"}]}})
out.append({"osv": {"id": "GO-2025-0001", "aliases": ["CVE-2025-0001"], "summary": "made-up stdlib bug"}})
out.append({"finding": {"osv": "GO-2025-0001", "fixed_version": "v1.21.9",
                        "trace": [{"module": "stdlib", "version": "v1.21.0", "package": "net/http",
                                   "function": "ListenAndServe"}]}})
for m in out:
    print(json.dumps(m, indent=2))
"""


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=cwd,
                          capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def golib(state, monkeypatch):
    """The fixture module as a git repository, registered as a repo-only source; OSV mocked."""
    repo = state / "golib"
    shutil.copytree(FIXTURES / "golib", repo)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "fixture")
    fl = fleet.Fleet({"sources": [{"name": "golib", "path": str(repo), "audit": "repo"},
                                  {"name": "svc", "url": "https://git.example/svc", "path": str(state / "svc")}],
                      "targets": []})
    fleet.set_fleet(fl)

    queried = []

    def osv_query(comps):
        queried.extend(comps)
        return [OSV["query"].get(f"{c.coordinate}@{c.version}", []) for c in comps]

    monkeypatch.setattr(repo_audit, "osv_query", osv_query)
    monkeypatch.setattr(repo_audit, "osv_vuln", lambda vid: OSV["vulns"][vid])
    yield repo, queried
    fleet.set_fleet(None)


@pytest.fixture
def no_govulncheck(monkeypatch):
    real = shutil.which
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: None if name in ("govulncheck", "go") else real(name, *a, **k))


@pytest.fixture
def fake_tools(state, monkeypatch):
    """Stand-in `go` and `govulncheck` first on PATH."""
    bin_dir = state / "fakebin"
    bin_dir.mkdir()
    for name, body in (("go", FAKE_GO), ("govulncheck", FAKE_GOVULNCHECK)):
        path = bin_dir / name
        path.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
        path.chmod(0o755)
    import os
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return bin_dir


def test_repo_only_sources_are_kept_apart_from_deployed_ones(golib):
    fl = fleet.get()
    assert set(fl.repos) == {"golib"} and set(fl.sources) == {"svc"}     # never linked to a workload
    assert fl.repos["golib"].kind == "local" and fl.repos["golib"].deploy is False
    assert fleet.repo_only({"audit": "Repo"}) and not fleet.repo_only({"name": "x"})


def test_scan_without_govulncheck_says_so_and_ranks_by_severity(golib, no_govulncheck):
    repo, queried = golib
    result = repo_audit.scan("golib", "eric")
    assert {(c.name, c.version) for c in queried} == {("golang.org/x/net", "0.17.0"), ("golang.org/x/text", "0.13.0")}
    assert result["govulncheck"]["available"] is False and "not installed" in result["govulncheck"]["note"]
    by_pkg = {p["name"]: p for p in result["packages"]}
    assert by_pkg["golang.org/x/text"]["indirect"] and not by_pkg["golang.org/x/net"]["indirect"]
    # GO-2024-2687 and its GHSA alias are one finding, rated by the GHSA record; the 0.1.x one is rejected
    assert [(f["package"], f["severity"], f["reachability"]) for f in result["findings"]] == [
        ("golang.org/x/text", "high", None), ("golang.org/x/net", "medium", None)]
    net = result["findings"][1]
    assert net["advisory"] == "GHSA-4v7x-pqxf-cx7m" and "GO-2024-2687" in net["ids"] and net["fixed_version"] == "0.23.0"
    assert result["rejected"] == [{"package": "golang.org/x/net", "version": "0.17.0", "advisory": "GHSA-0000-lhrj-0001"}]
    assert repo_audit.load("golib")["status"] == "ok"


def test_govulncheck_ranks_reachable_findings_first(golib, fake_tools):
    result = repo_audit.scan("golib")
    assert result["govulncheck"]["ran"] is True
    assert [(f["package"], f["reachability"]) for f in result["findings"]] == [
        ("golang.org/x/net", "called"),         # medium, but its vulnerable code is called
        ("stdlib", "called"),                   # only govulncheck knows the stdlib; no go.mod bump fixes it
        ("golang.org/x/text", "required")]      # high, but never imported: lower priority
    assert result["findings"][0]["symbols"] == ["golang.org/x/net/html.Parse"]
    assert result["findings"][1]["not_fixable"] and result["reachable"] == 2


def test_propose_fix_makes_a_local_branch_with_evidence(golib, fake_tools):
    repo, _ = golib
    repo_audit.scan("golib")
    prop = repo_audit.propose("golib", "GO-2024-2687", "eric")
    assert prop["status"] == "proposed", prop
    ev = prop["evidence"]
    assert ev["changed_files"] == ["go.mod", "go.sum"] and ev["pinned_after"] == "0.23.0"
    assert ev["govulncheck"]["before"]["reachability"] == "called"
    assert ev["govulncheck"]["after"]["reachability"] == "not_reported"
    assert [s["kind"] for s in ev["checks"]["steps"]] == ["build", "test"] and ev["checks"]["ok"]
    # the main branch is untouched and checked out again; the fix lives on its own local branch
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert "golang.org/x/net v0.17.0" in (repo / "go.mod").read_text()
    assert "golang.org/x/net v0.23.0" in git(repo, "show", f"{prop['branch']}:go.mod")
    message = git(repo, "log", "-1", "--format=%B", prop["branch"])
    assert "govulncheck after: not reported by govulncheck" in message and "not pushed" in message
    assert git(repo, "remote") == ""                            # nothing to push to, nothing pushed
    assert Path(prop["patch"]).read_text().startswith("From ")
    assert repo_audit.load("golib")["proposals"][0]["status"] == "proposed"


def test_failing_tests_are_recorded_against_the_main_branch(golib, fake_tools, monkeypatch):
    monkeypatch.setenv("LH_FAKE_TEST_FAIL", "1")                 # tests fail only after the bump
    repo_audit.scan("golib")
    prop = repo_audit.propose("golib", "GO-2024-2687")
    assert prop["status"] == "proposed_with_failures"
    checks = prop["evidence"]["checks"]
    assert not checks["ok"] and checks["before"]["ok"]           # the bump broke it, not the repository
    assert git(golib[0], "worktree", "list").count("\n") == 0    # the throwaway worktree is gone


def test_proposals_refuse_what_cannot_be_fixed(golib, fake_tools):
    with pytest.raises(ValueError, match="not been scanned"):
        repo_audit.propose("golib", "GO-2024-2687")
    repo_audit.scan("golib")
    with pytest.raises(ValueError, match="Go toolchain"):
        repo_audit.start_proposal("golib", "GO-2025-0001")
    with pytest.raises(KeyError):
        repo_audit.start_proposal("golib", "GHSA-nope")


def test_api_lists_scans_and_proposes(golib, fake_tools):
    from fastapi.testclient import TestClient

    from agent.main import app
    settings.set_settings({"auth": {"kind": "token", "tokens": {"alice": "tok-alice", "bob": "tok-bob"},
                                    "approvers": ["alice"]}})
    auth.reset()
    try:
        client = TestClient(app)                                 # no lifespan: no background threads
        alice, bob = {"Authorization": "Bearer tok-alice"}, {"Authorization": "Bearer tok-bob"}
        assert client.get("/api/repos").status_code == 401
        listed = client.get("/api/repos", headers=bob).json()["repos"]
        assert [(r["name"], r["status"]) for r in listed] == [("golib", "never")]
        assert client.post("/api/repos/golib/scan", headers=bob).status_code == 403
        assert client.post("/api/repos/nope/scan", headers=alice).status_code == 404
        assert client.post("/api/repos/golib/scan?wait=true", headers=alice).json()["findings"] == 3
        repo = client.get("/api/repos", headers=bob).json()["repos"][0]
        assert repo["scan"]["findings"][0]["reachability"] == "called" and repo["scan"]["head"]
        assert client.post("/api/repos/golib/propose?wait=true", json={"finding": "GO-2025-0001"},
                           headers=alice).status_code == 409
        out = client.post("/api/repos/golib/propose?wait=true", json={"finding": "CVE-2023-45288"}, headers=alice).json()
        assert out["status"] == "proposed" and out["branch"].startswith("lighthouse/")
        patch = client.get(f"/api/repos/golib/proposals/{out['id']}/patch", headers=bob)
        assert patch.status_code == 200 and "golang.org/x/net v0.23.0" in patch.text
        log = [(e["actor"], e["action"], e["target"]) for e in db.audit_log()]
        assert ("alice", "repo-scan", "golib") in log and ("alice", "propose-fix", "golib: CVE-2023-45288") in log
        assert not any(e[0] == "bob" for e in log)
    finally:
        settings.set_settings(None)
        auth.reset()


def test_json_stream_and_reachability_helpers():
    assert repo_audit._json_stream('{\n "a": 1\n}\n{"b": [2]}\n') == [{"a": 1}, {"b": [2]}]
    vc = {"ran": True, "levels": {"GO-1": "imported"}, "aliases": {"GO-1": ["CVE-1"]}}
    assert repo_audit.reach_for(["CVE-1"], vc) == "imported"
    assert repo_audit.reach_for(["CVE-2"], vc) == "not_reported"
    assert repo_audit.reach_for(["CVE-1"], {"ran": False}) is None
    comp = Component(ecosystem="go", name="m", version="1.0.0")
    assert comp.coordinate == "m"
