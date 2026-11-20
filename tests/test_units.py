"""Unit tests for the deterministic parts: matching, vetting, mitigation
rendering, policy, and Kubernetes discovery from plain API objects."""
import json
import re
import shutil
import zipfile

import pytest

from agent import config, matcher, mitigation, policy, vetter
from agent.drivers import kubernetes as k8s
from agent.drivers.maven import MavenEcosystem
from agent.drivers.pypi import PypiEcosystem
from agent.schemas import Component, TriageResult, VetResult, Workload
from agent.versions import compare
from conftest import scenario

NOLOG = lambda *a: None  # noqa: E731


# ------------------------------------------------------------------ matching

def test_version_order():
    assert compare("2.0-beta9", "2.0-rc1") < 0 < compare("2.17.1", "2.14.1")
    assert compare("1.0", "1.0.0") == 0


def test_match_is_fleet_wide_and_ecosystem_aware():
    core = lambda v: Component(ecosystem="maven", group="org.apache.logging.log4j", name="log4j-core", version=v)
    inv = {"a": [core("2.14.1")], "b": [core("2.17.1")], "c": [core("2.14.1")],
           "d": [Component(ecosystem="pypi", name="log4j-core", version="2.14.1")]}
    found = matcher.match(scenario("log4shell"), inv)
    assert sorted(m.workload_id for m in found) == ["a", "c"]
    assert all(m.fixed_version == "2.17.1" and m.patch_available for m in found)


def test_pypi_names_are_normalised_and_unfixed_advisories_match():
    comp = Component(ecosystem="pypi", name="Acme_AuthUtils", version="1.0.0")
    assert matcher.match(scenario("trojan"), {"w": [comp]})[0].fixed_version == "1.0.1"
    m = matcher.match(scenario("zeroday"), {"w": [comp]})[0]
    assert m.fixed_version is None and not m.patch_available


# ------------------------------------------------------------------- vetting

def test_trojan_is_malicious_without_the_model():
    r = vetter.vet({"id": "x"}, PypiEcosystem(), "acme-authutils", "1.0.0", "1.0.1", NOLOG, review=False)
    assert r.verdict == "malicious"
    hard = [f for f in r.flags if f.severity == "hard"]
    assert [f.check for f in hard] == ["exfiltration-pattern"]
    assert hard[0].file == "acme_authutils/_metrics.py"
    assert "_report(_snapshot())" in hard[0].lines


def test_trojan_review_uses_seeded_answers(state):
    r = vetter.vet(scenario("trojan"), PypiEcosystem(), "acme-authutils", "1.0.0", "1.0.1", NOLOG)
    reviewed = {x.file: x for x in r.reviews}
    assert reviewed["acme_authutils/_metrics.py"].review.category == "data_exfiltration"
    assert reviewed["acme_authutils/_metrics.py"].source == "seed"
    # evidence lines are kept only if they really are added lines
    assert "_report(_snapshot())" in reviewed["acme_authutils/_metrics.py"].review.evidence_lines


def test_honest_updates_are_clean():
    assert vetter.vet({"id": "x"}, PypiEcosystem(), "acme-textfmt", "1.0.0", "1.0.1", NOLOG,
                      review=False).verdict == "clean"
    assert vetter.vet({"id": "x"}, MavenEcosystem(), "log4j-core", "2.14.1", "2.17.1", NOLOG,
                      review=False).verdict == "clean"


@pytest.fixture
def artifacts(tmp_path, monkeypatch):
    dst = tmp_path / "artifacts"
    shutil.copytree(config.ARTIFACTS / "pypi", dst / "pypi")
    shutil.copy(config.ARTIFACTS / "checksums.json", dst)
    monkeypatch.setattr(config, "ARTIFACTS", dst)
    return dst


def _rewrite_wheel(path, name, data):
    tmp = path.with_suffix(".tmp")
    with zipfile.ZipFile(path) as src, zipfile.ZipFile(tmp, "w") as out:
        for item in src.infolist():
            out.writestr(item, data if item.filename == name else src.read(item.filename))
    tmp.replace(path)


def test_code_only_in_the_wheel_is_malicious(artifacts):
    """The xz pattern: the shipped artifact differs from its source release."""
    wheel = artifacts / "pypi/acme-textfmt/1.0.1/acme_textfmt-1.0.1-py3-none-any.whl"
    with zipfile.ZipFile(wheel) as zf:
        code = zf.read("acme_textfmt/__init__.py") + b"\nimport os as _o\n_o.system('true')\n"
    _rewrite_wheel(wheel, "acme_textfmt/__init__.py", code)
    sums = json.loads((artifacts / "checksums.json").read_text())
    sums[str(wheel.relative_to(artifacts))] = vetter.sha256(wheel)      # attacker controls the checksum too
    (artifacts / "checksums.json").write_text(json.dumps(sums))
    r = vetter.vet({"id": "x"}, PypiEcosystem(), "acme-textfmt", "1.0.0", "1.0.1", NOLOG, review=False)
    assert r.verdict == "malicious"
    assert any(f.check == "shipped-without-source" and "differs from the sdist" in f.file for f in r.flags)


def test_swapped_artifact_fails_the_checksum(artifacts):
    wheel = artifacts / "pypi/acme-textfmt/1.0.1/acme_textfmt-1.0.1-py3-none-any.whl"
    _rewrite_wheel(wheel, "acme_textfmt-1.0.1.dist-info/WHEEL", b"Wheel-Version: 1.0\n")
    r = vetter.vet({"id": "x"}, PypiEcosystem(), "acme-textfmt", "1.0.0", "1.0.1", NOLOG, review=False)
    assert r.verdict == "malicious" and any(f.check == "checksum" for f in r.flags)


def test_acme_builds_are_reproducible(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("build_acme", config.WORKSPACE / "scripts/build_acme.py")
    build = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(build)
    import tomllib
    src = config.WORKSPACE / "acme-libs/acme-authutils/1.0.1"
    project = tomllib.loads((src / "pyproject.toml").read_text())["project"]
    build.build_wheel(src, project, "acme_authutils", tmp_path / "w.whl")
    build.build_sdist(src, project, "acme_authutils", tmp_path / "s.tar.gz")
    shipped, source = PypiEcosystem().artifacts("acme-authutils", "1.0.1")
    assert vetter.sha256(tmp_path / "w.whl") == vetter.sha256(shipped)
    assert vetter.sha256(tmp_path / "s.tar.gz") == vetter.sha256(source)


# ---------------------------------------------------------------- mitigation

def _as_python(rule_regex: str) -> re.Pattern:
    """Undo nginx string escaping, then compile like PCRE would (case-insensitive)."""
    return re.compile(rule_regex.replace('\\"', '"').replace("\\\\", "\\"), re.I)


@pytest.mark.parametrize("pattern,hits,misses", [
    ("${", ["${jndi:ldap://x}", "%24%7bjndi", "$%7B", "%24{"], ["$x", "{}", "jndi"]),
    ("..", ["../../etc/passwd", "%2e%2e/x", ".%2E/"], ["a.b", "default"]),
])
def test_mitigation_regex_catches_encodings(pattern, hits, misses):
    rx = _as_python(mitigation.regex(pattern))
    assert all(rx.search(h) for h in hits)
    assert not any(rx.search(m) for m in misses)


def test_mitigation_render_whitelists_fields():
    rule = mitigation.render("PPSA-1", "..", ["header:X-Key-Id", "query"])
    assert 'if ($http_x_key_id ~* "' in rule and 'if ($args ~* "' in rule and rule.count("return 403") == 2
    for bad in (["header:X-Key-Id; return 200"], ["cookie"], []):
        with pytest.raises(mitigation.InvalidMitigation):
            mitigation.render("x", "..", bad)
    with pytest.raises(mitigation.InvalidMitigation):
        mitigation.render("x", "a" * 65, ["query"])


# -------------------------------------------------------------------- policy

def _wl(exposed: bool) -> Workload:
    return Workload(id="t/ns/w", name="w", target="t", target_kind="kubernetes", provider="p", image="i",
                    internet_exposed=exposed, exposure="x", gateway="w-gateway" if exposed else None)


def _triage(**kw) -> TriageResult:
    base = dict(affected=True, reachable=True, severity_for_this_workload="high", recommended_action="patch",
                mitigation_pattern="..", mitigation_fields=["header:X-Key-Id"], explanation="e")
    return TriageResult(**{**base, **kw})


def _vet(verdict: str) -> VetResult:
    return VetResult(ecosystem="pypi", artifact="a", from_version="1", to_version="2", verdict=verdict,
                     reasons=[], flags=[], reviews=[], files_changed=1, files_reviewed=1)


def test_policy_decisions():
    p = policy.load()
    assert policy.decide(p, _wl(True), _triage(), True, _vet("clean"), True).decision == "auto"
    assert policy.decide(p, _wl(False), _triage(), True, _vet("clean"), False).decision == "queue"
    assert policy.decide(p, _wl(True), _triage(), True, _vet("suspicious"), True).decision == "needs_approval"
    blocked = policy.decide(p, _wl(True), _triage(), True, _vet("malicious"), True)
    assert (blocked.action, blocked.decision) == ("mitigate", "needs_approval")
    assert policy.decide(p, _wl(False), _triage(), True, _vet("malicious"), False).decision == "block"
    assert policy.decide(p, _wl(True), _triage(reachable=False), True, None, True).decision == "ignore"
    zero = policy.decide(p, _wl(True), _triage(recommended_action="mitigate"), False, None, True)
    assert (zero.action, zero.decision) == ("mitigate", "needs_approval")
    always = policy.load({"act_now_when": "always"})
    assert policy.decide(always, _wl(False), _triage(), True, _vet("clean"), False).decision == "auto"


# ------------------------------------------------------------------ priority

def test_most_critical_is_fixed_first():
    from agent import pipeline

    def row(name, exposed, sev, reachable=True):
        wl = _wl(exposed).model_copy(update={"id": f"t/ns/{name}", "name": name})
        return wl, _triage(severity_for_this_workload=sev, reachable=reachable)

    rows = [row("low-exposed", True, "low"), row("critical-internal", False, "critical"),
            row("high-exposed", True, "high"), row("high-internal", False, "high"),
            row("high-unreachable", True, "high", reachable=False), row("medium", True, "medium")]
    rows.sort(key=lambda r: pipeline.priority(*r))
    assert [wl.name for wl, _ in rows] == ["critical-internal", "high-exposed", "high-internal",
                                           "high-unreachable", "medium", "low-exposed"]


def test_most_critical_advisory_runs_first():
    from agent import feed
    advs = [{"id": i, "database_specific": {"severity": s}} if s else {"id": i}
            for i, s in [("a", "LOW"), ("b", None), ("c", "CRITICAL"), ("d", "moderate"), ("e", "HIGH")]]
    assert [a["id"] for a in feed.by_severity(advs)] == ["c", "e", "d", "a", "b"]


# ------------------------------------------------------- kubernetes discovery

def _dep(name, labels, annotations=None, role=None):
    meta = {"name": name, "labels": {"patchpilot.io/role": role} if role else {}, "annotations": annotations or {}}
    return {"metadata": meta, "spec": {"template": {"metadata": {"labels": labels}, "spec": {"containers": [
        {"name": "app", "image": f"reg/{name}:v1", "readinessProbe": {"httpGet": {"path": "/healthz"}}}]}}}}


def _svc(name, selector, kind="ClusterIP"):
    return {"metadata": {"name": name}, "spec": {"type": kind, "selector": selector, "ports": [{"port": 80}]}}


def test_discover_exposure_provider_and_gateways():
    deps = [_dep("orders", {"app": "orders", "track": "stable"}),
            _dep("orders-gateway", {"app": "orders-gateway"}, {"patchpilot.io/gateway-for": "orders"}, "gateway"),
            _dep("reports", {"app": "reports"}),
            _dep("web", {"app": "web"}),
            _dep("orders-canary", {"patchpilot.io/canary-of": "orders"}, role="canary")]
    svcs = [_svc("orders", {"app": "orders", "track": "stable"}), _svc("orders-gateway", {"app": "orders-gateway"}, "LoadBalancer"),
            _svc("reports", {"app": "reports"}), _svc("web", {"app": "web"})]
    ing = [{"metadata": {"name": "main"}, "spec": {"rules": [{"host": "shop.example", "http": {"paths": [
        {"path": "/", "backend": {"service": {"name": "web", "port": {"number": 80}}}}]}}]}}]
    nodes = [{"spec": {"providerID": "aws:///eu-central-1a/i-0abc"},
              "metadata": {"labels": {"topology.kubernetes.io/region": "eu-central-1"}}}]
    wls = {w.name: w for w in k8s.discover("prod", deps, svcs, ing, nodes, "shop")}
    assert sorted(wls) == ["orders", "reports", "web"]
    assert wls["orders"].internet_exposed and wls["orders"].gateway == "orders-gateway"
    assert "LoadBalancer Service orders-gateway → gateway orders-gateway" == wls["orders"].exposure
    assert not wls["reports"].internet_exposed
    assert wls["web"].internet_exposed and wls["web"].exposure.startswith("Ingress main (shop.example/)")
    assert (wls["orders"].provider, wls["orders"].region) == ("AWS", "eu-central-1")
    assert wls["orders"].health_path == "/healthz" and wls["orders"].id == "prod/shop/orders"


@pytest.mark.parametrize("pid,name", [("gce://p/europe-west4-a/n", "Google Cloud"), ("scaleway://instance/fr-par-1/x", "Scaleway"),
                                      ("hcloud://123", "Hetzner Cloud"), ("openstack:///abc", "OpenStack"),
                                      ("k3s://node", "k3s"), ("", "Kubernetes")])
def test_provider_from_provider_id(pid, name):
    assert k8s.provider_of([{"spec": {"providerID": pid}, "metadata": {}}])[0] == name
