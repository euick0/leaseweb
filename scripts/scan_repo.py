#!/usr/bin/env python3
"""Read-only LightHouse scan of a real repository (no build, no deploy).

  python scripts/scan_repo.py <repo> [--triage N] [--internal] [--name NAME]

1. inventory  - Maven: every pom.xml, with ${properties} and dependencyManagement
                resolved. Python: every requirements*.txt, through LightHouse's
                own PyPI pin parser (name==version; unpinned lines are counted).
                Go: every go.mod (direct and // indirect requires), through
                LightHouse's Go driver
2. advisories - real OSV records for those packages (api.osv.dev)
3. match      - LightHouse's own matcher decides which advisories apply
                (and is cross-checked against OSV's answer)
   reachable  - Go: with govulncheck installed, whether the vulnerable code is
                called, only imported, or only in the module graph (ranked in
                that order); without it the report says so
4. triage     - optional: LightHouse's AI triage for the N worst runtime
                matches, with import sites found in the repository as evidence

Writes <repo>-lighthouse-report.md next to the repository. Model answers are
cached in state/external/cache, not in agent/cache.
"""
from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent import config, feed, matcher, repo_audit, triage  # noqa: E402  (config loads .env)
from agent.drivers.golang import GoEcosystem, gomods, parse_requires  # noqa: E402
from agent.drivers.pypi import _PIN  # noqa: E402
from agent.schemas import Component, Workload  # noqa: E402

NS = {"m": "http://maven.apache.org/POM/4.0.0"}
OSV = "https://api.osv.dev/v1"
OSV_ECOSYSTEM = {"maven": "Maven", "pypi": "PyPI", "go": "Go"}
SKIP_DIRS = {"target", "node_modules", ".venv", "venv", ".git", "build", "dist", "site-packages"}
_PROP = re.compile(r"\$\{([^}]+)\}")


def _skipped(path: Path, repo: Path) -> bool:
    return bool(SKIP_DIRS & set(path.relative_to(repo).parts))


# ------------------------------------------------------------- maven inventory

def _text(node, path: str):
    el = node.find(path, NS)
    return el.text.strip() if el is not None and el.text else None


def _properties(root) -> dict[str, str]:
    return {el.tag.split("}", 1)[1]: (el.text or "").strip() for el in root.findall("m:properties/*", NS)}


def _resolve(value, props: dict[str, str]):
    for _ in range(10):
        if not value or "${" not in value:
            return value
        value = _PROP.sub(lambda m: props.get(m.group(1), m.group(0)), value)
    return value


def maven_inventory(repo: Path):
    poms = sorted(p for p in repo.rglob("pom.xml") if not _skipped(p, repo))
    if not (repo / "pom.xml").exists():
        return [], len(poms), set()
    root_pom = ET.parse(repo / "pom.xml").getroot()
    own_group = _text(root_pom, "m:groupId") or _text(root_pom, "m:parent/m:groupId") or ""
    version = _text(root_pom, "m:version") or _text(root_pom, "m:parent/m:version")
    root_props = {**_properties(root_pom), "project.version": version, "project.parent.version": version,
                  "project.groupId": own_group}

    managed = {}
    for el in root_pom.findall(".//m:dependencyManagement//m:dependency", NS):
        g, a, v = _text(el, "m:groupId"), _text(el, "m:artifactId"), _text(el, "m:version")
        if g and a and v:
            managed[(_resolve(g, root_props), a)] = _resolve(v, root_props)

    found = defaultdict(lambda: {"files": set(), "scopes": set()})
    unresolved = set()
    for pom in poms:
        try:
            node = ET.parse(pom).getroot()
        except ET.ParseError:
            continue
        props = {**root_props, **_properties(node)}
        for el in node.findall(".//m:dependency", NS):
            g, a = _resolve(_text(el, "m:groupId"), props), _text(el, "m:artifactId")
            if not g or not a or (own_group and g.startswith(own_group)):
                continue
            v = _resolve(_text(el, "m:version"), props) or managed.get((g, a))
            if not v or "${" in v:
                unresolved.add(f"{g}:{a}")
                continue
            entry = found[(g, a, v)]
            entry["files"].add(pom.relative_to(repo).as_posix())
            entry["scopes"].add(_text(el, "m:scope") or "compile")
    comps = [(Component(ecosystem="maven", group=g, name=a, version=v, purl=f"pkg:maven/{g}/{a}@{v}",
                        path=sorted(info["files"])[0]), info) for (g, a, v), info in sorted(found.items())]
    return comps, len(poms), unresolved


# ------------------------------------------------------------ python inventory

def pypi_inventory(repo: Path):
    files = sorted(p for p in repo.rglob("requirements*.txt") if not _skipped(p, repo))
    found = defaultdict(lambda: {"files": set(), "scopes": set()})
    unpinned = set()
    for req in files:
        scope = "test" if re.search(r"(test|dev|doc|lint)", req.name, re.I) else "runtime"
        for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            m = _PIN.match(line)
            if not m:
                unpinned.add(re.split(r"[\s<>=!~;\[]", line, maxsplit=1)[0])
                continue
            entry = found[(feed.normalise("pypi", m.group(1)), m.group(2))]
            entry["files"].add(req.relative_to(repo).as_posix())
            entry["scopes"].add(scope)
    comps = [(Component(ecosystem="pypi", name=n, version=v, purl=f"pkg:pypi/{n}@{v}",
                        path=sorted(info["files"])[0]), info) for (n, v), info in sorted(found.items())]
    return comps, len(files), unpinned


# ---------------------------------------------------------------- go inventory

def go_inventory(repo: Path):
    """Every require of every go.mod; scope is "direct" or "indirect" (both ship)."""
    mods = [m for m in gomods(repo) if not _skipped(m, repo)]
    indirect = {(m, v) for mod in mods for m, v, ind in parse_requires(mod.read_text(encoding="utf-8")) if ind}
    found = defaultdict(lambda: {"files": set(), "scopes": set()})
    for comp in GoEcosystem().components(repo):
        if _skipped(repo / comp.path, repo):
            continue
        entry = found[(comp.name, comp.version)]
        entry["files"].add(comp.path)
        entry["scopes"].add("indirect" if (comp.name, comp.version) in indirect else "direct")
    comps = [(Component(ecosystem="go", name=n, version=v, purl=f"pkg:golang/{n}@v{v}", path=sorted(info["files"])[0]),
              info) for (n, v), info in sorted(found.items())]
    return comps, len(mods)


# ----------------------------------------------------------------- advisories

def osv_ids(comps) -> dict[int, list[str]]:
    out = {}
    for start in range(0, len(comps), 500):
        chunk = comps[start:start + 500]
        body = {"queries": [{"package": {"ecosystem": OSV_ECOSYSTEM[c.ecosystem], "name": c.coordinate},
                             "version": c.version} for c, _ in chunk]}
        res = requests.post(f"{OSV}/querybatch", json=body, timeout=60)
        res.raise_for_status()
        for i, r in enumerate(res.json()["results"]):
            out[start + i] = [v["id"] for v in r.get("vulns", [])]
    return out


def osv_record(vid: str) -> dict:
    res = requests.get(f"{OSV}/vulns/{vid}", timeout=60)
    res.raise_for_status()
    return res.json()


def severity(adv: dict) -> str:
    """critical..low from the database rating or the CVSS vector (agent/feed.py)."""
    return (feed.advisory_severity(adv) or "unknown").upper()


SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}


# --------------------------------------------------------------------- evidence

# Maven coordinate -> Java packages, where the group id is not the package
JAVA_PACKAGES = {
    "com.google.code.gson:gson": ["com.google.gson"],
    "com.google.guava:guava": ["com.google.common"],
    "com.fasterxml.jackson.core:jackson-core": ["com.fasterxml.jackson.core"],
    "com.fasterxml.jackson.core:jackson-databind": ["com.fasterxml.jackson.databind"],
    "org.springframework:spring-web": ["org.springframework.web", "org.springframework.remoting"],
    "org.springframework:spring-webmvc": ["org.springframework.web.servlet"],
    "com.rabbitmq:amqp-client": ["com.rabbitmq.client"],
    "com.mysql:mysql-connector-j": ["com.mysql"],
    "mysql:mysql-connector-java": ["com.mysql"],
    "org.eclipse.jetty:jetty-server": ["org.eclipse.jetty.server"],
    "org.apache.tomcat.embed:tomcat-embed-core": ["org.apache.catalina", "org.apache.tomcat"],
    "org.apache.logging.log4j:log4j-core": ["org.apache.logging.log4j"],
    "commons-collections:commons-collections": ["org.apache.commons.collections"],
    "org.apache.commons:commons-collections4": ["org.apache.commons.collections4"],
    "org.apache.struts:struts2-core": ["org.apache.struts2", "com.opensymphony.xwork2"],
    "org.yaml:snakeyaml": ["org.yaml.snakeyaml"],
}
# PyPI distribution -> import names, where they differ
PY_MODULES = {
    "pyyaml": ["yaml"], "pillow": ["PIL"], "beautifulsoup4": ["bs4"], "python-dateutil": ["dateutil"],
    "pycryptodome": ["Crypto"], "pycrypto": ["Crypto"], "psycopg2-binary": ["psycopg2"],
    "scikit-learn": ["sklearn"], "opencv-python": ["cv2"], "pyjwt": ["jwt"], "python-jose": ["jose"],
    "djangorestframework": ["rest_framework"], "flask-sqlalchemy": ["flask_sqlalchemy"],
    "aiohttp-jinja2": ["aiohttp_jinja2"], "aiohttp-session": ["aiohttp_session"], "pymysql": ["pymysql"],
}


def grep(repo: Path, comp) -> list[str]:
    """Import sites of the package: the evidence triage reasons from."""
    if comp.ecosystem == "go":
        pattern = re.compile(r'^\s*(import\s+)?([\w.]+\s+)?"' + re.escape(comp.name) + r'(/[^"]*)?"')
        files = repo.rglob("*.go")
    elif comp.ecosystem == "maven":
        prefixes = JAVA_PACKAGES.get(comp.coordinate) or (
            [comp.group] if "." in comp.group else [f"org.apache.{comp.group.replace('-', '.')}"])
        pattern = re.compile(r"^import\s+(static\s+)?(" + "|".join(map(re.escape, prefixes)) + r")\.")
        files = repo.rglob("*.java")
    else:
        mods = PY_MODULES.get(comp.name) or [comp.name.replace("-", "_")]
        pattern = re.compile(r"^\s*(from|import)\s+(" + "|".join(map(re.escape, mods)) + r")\b", re.I)
        files = repo.rglob("*.py")
    hits = []
    for src in files:
        if _skipped(src, repo) or "test" in src.relative_to(repo).as_posix().lower() or "vendor" in src.relative_to(repo).parts:
            continue
        try:
            for n, line in enumerate(src.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if pattern.match(line):
                    hits.append(f"{src.relative_to(repo).as_posix()}:{n}: {line.strip()}")
                    break
        except OSError:
            continue
        if len(hits) >= 25:
            break
    return hits


# ------------------------------------------------------------------------ main

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("repo", type=Path)
    ap.add_argument("--triage", type=int, default=0, help="run AI triage on the N worst runtime matches")
    ap.add_argument("--internal", action="store_true", help="treat the service as not internet-exposed")
    ap.add_argument("--name", help="service name for the report (default: the folder name)")
    args = ap.parse_args()
    repo = args.repo.resolve()
    name = args.name or repo.name
    config.CACHE_DIR = ROOT / "state" / "external" / "cache"

    mvn, n_poms, unresolved = maven_inventory(repo)
    py, n_reqs, unpinned = pypi_inventory(repo)
    go, n_gomods = go_inventory(repo)
    comps = mvn + py + go
    print(f"[inventory] {name}: {n_poms} pom.xml -> {len(mvn)} Maven packages ({len(unresolved)} unresolved); "
          f"{n_reqs} requirements files -> {len(py)} pinned PyPI packages ({len(unpinned)} unpinned); "
          f"{n_gomods} go.mod -> {len(go)} Go modules")

    ids = osv_ids(comps) if comps else {}
    unique = sorted({v for vs in ids.values() for v in vs})
    with ThreadPoolExecutor(8) as pool:
        records = dict(zip(unique, pool.map(lambda v: repo_audit.rated(osv_record(v)), unique)))
    print(f"[advisories] {len(unique)} OSV advisories for {sum(1 for v in ids.values() if v)} packages")

    exposure = ("ASSUMED internal service; not verified, this is a source scan" if args.internal else
                "ASSUMED internet-facing web application; not verified, this is a source scan")
    wl = Workload(id=f"scan/{name}", name=name, target="scan", target_kind="source", provider="source scan only",
                  image="(not built)", repo=name, internet_exposed=not args.internal, exposure=exposure)

    vc = repo_audit.govulncheck(repo) if go else {"ran": False, "note": "no Go modules"}
    if go:
        print(f"[reachable] {vc['note']}")

    matches, disagreements = [], []
    for i, (comp, info) in enumerate(comps):
        known: set[str] = set()                  # GO-… and GHSA-… records of one vulnerability: report it once
        for vid in sorted(ids.get(i, []), key=lambda v: (v.startswith("GO-"), v)):
            adv = records[vid]
            if {adv["id"], *adv.get("aliases", [])} & known:
                continue
            ours = matcher.match(adv, {wl.id: [comp]})
            if not ours:
                disagreements.append((comp, adv))
                continue
            known |= {adv["id"], *adv.get("aliases", [])}
            runtime = bool(info["scopes"] - {"test", "provided"})
            matches.append((comp, info, adv, ours[0], runtime))
    matches.sort(key=lambda m: (not m[4], repo_audit.REACH.get(reach(m, vc), 9), SEV_ORDER.get(severity(m[2]), 9),
                                m[0].coordinate))
    print(f"[match] LightHouse's matcher confirms {len(matches)} matches; {len(disagreements)} OSV matches rejected")

    triaged = {}
    if args.triage:
        print(f"[triage] providers={config.LLM_PROVIDER} mode={config.LLM_MODE}")
        seen = set()
        for comp, info, adv, m, runtime in matches:
            if len(triaged) >= args.triage:
                break
            if not runtime or severity(adv) not in ("CRITICAL", "HIGH") or comp.coordinate in seen:
                continue
            seen.add(comp.coordinate)
            hits = grep(repo, comp)
            t, source = triage.triage(adv, wl, m, hits, None)
            triaged[(comp.coordinate, comp.version, adv["id"])] = (t, source, len(hits), feed.title(adv))
            print(f"[triage] {comp.coordinate} {comp.version} / {feed.title(adv)}: "
                  f"{t.severity_for_this_workload} -> {t.recommended_action} ({source}, {len(hits)} import sites)")

    report = repo.parent / f"{repo.name}-lighthouse-report.md"
    report.write_text(render(name, n_poms, n_reqs, comps, unresolved, unpinned, matches, disagreements,
                             triaged, exposure, n_gomods, vc), encoding="utf-8")
    print(f"[report] {report}")


def reach(match, vc) -> str | None:
    """govulncheck's level for a Go match (called / imported / required / not_reported), else None."""
    comp, _, adv, _, _ = match
    return repo_audit.reach_for([adv["id"], *adv.get("aliases", [])], vc) if comp.ecosystem == "go" else None


def render(name, n_poms, n_reqs, comps, unresolved, unpinned, matches, disagreements, triaged, exposure,
           n_gomods=0, vc=None) -> str:
    vc = vc or {"ran": False, "note": "no Go modules"}
    by_sev = defaultdict(int)
    for _, _, adv, _, runtime in matches:
        if runtime:
            by_sev[severity(adv)] += 1
    affected = {(m[0].coordinate, m[0].version) for m in matches if m[4]}
    lines = [f"# LightHouse read-only scan: {name}", "",
             f"- Inventory: {n_poms} pom.xml, {n_reqs} requirements files, {n_gomods} go.mod,"
             f" {len(comps)} pinned third-party packages"
             f" ({len(unresolved)} Maven without a resolvable version, {len(unpinned)} Python unpinned: skipped)",
             f"- {len(affected)} runtime packages with known advisories: "
             + (", ".join(f"{n} {s.lower()}" for s, n in sorted(by_sev.items(), key=lambda x: SEV_ORDER.get(x[0], 9)))
                or "none"),
             f"- OSV listed {len(disagreements)} more matches that LightHouse's version matcher rejected",
             f"- Exposure: {exposure}",
             f"- Go reachability: {vc['note']}", ""]
    if triaged:
        lines += ["## AI triage (worst runtime matches)", ""]
        for (coord, ver, vid), (t, source, nhits, title) in triaged.items():
            lines += [f"### {coord} {ver}: {title} ({vid})",
                      f"- **{t.severity_for_this_workload}**, reachable={t.reachable}, action **{t.recommended_action}**"
                      f" (source: {source}, {nhits} import sites found)",
                      f"- {t.explanation}", ""]
    lines += ["## Matches", "", "| Package | Version | Advisory | Severity | Fixed in | Scope | Reachable |",
              "|---|---|---|---|---|---|---|"]
    for match in matches:
        comp, info, adv, m, runtime = match
        r = reach(match, vc)
        lines.append(f"| {comp.coordinate} | {comp.version} | {feed.title(adv)} ({adv['id']}) | "
                     f"{severity(adv)} | {m.fixed_version or 'none'} | {', '.join(sorted(info['scopes']))} | "
                     f"{repo_audit.REACH_TEXT.get(r, r) if comp.ecosystem == 'go' else 'n/a'} |")
    if disagreements:
        lines += ["", "## OSV matches LightHouse's matcher rejected", "",
                  "Either OSV data LightHouse ignores (e.g. GIT-only ranges) or a gap in `agent/versions.py`.", "",
                  "| Package | Version | Advisory |", "|---|---|---|"]
        lines += [f"| {c.coordinate} | {c.version} | {a['id']} |" for c, a in disagreements]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
