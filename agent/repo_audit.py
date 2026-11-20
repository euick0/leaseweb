"""Repository audit: libraries and tools that have no deployment to discover.

A source in fleet.yaml marked `audit: repo` is never linked to a workload. It is
cloned (or synced) read-only, its pins are read with the same ecosystem drivers
the pipeline uses (Go, Maven, Python), and every package is matched against OSV
with LightHouse's own matcher, like scripts/scan_repo.py does.

  sources:
    - name: terraform-provider-leaseweb
      url: https://github.com/LeaseWeb/terraform-provider-leaseweb
      audit: repo

Go repositories get a reachability check when `govulncheck` is installed: an
advisory whose vulnerable symbol is called from the repository's code is
`called`; one whose package is only imported, or whose module is only in the
module graph, ranks lower. Without govulncheck the result says so.

A fix proposal bumps one package with its ecosystem driver (for Go: go.mod and
go.sum through `go get`), runs `go build ./...` and `go test ./...` when the
toolchain is there, re-runs govulncheck, and commits the change with that
evidence on a local branch, plus a patch file. Nothing is ever pushed: the
change stays in the local clone for a human to take upstream.
"""
from __future__ import annotations

import functools
import json
import os
import tempfile
import re
import shutil
import subprocess
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Optional

import requests

from . import config, feed, fleet, matcher, overrides, settings
from .drivers.base import DriverError
from .drivers.golang import gomods, parse_requires
from .schemas import Component
from .versions import compare

OSV_ECOSYSTEM = {"maven": "Maven", "pypi": "PyPI", "go": "Go"}
# govulncheck levels, most to least reachable; None = govulncheck did not run
REACH = {"called": 0, None: 1, "imported": 2, "required": 3, "not_reported": 3}
REACH_TEXT = {"called": "vulnerable code is called", "imported": "package imported, vulnerable code not called",
              "required": "only in the module graph, not imported", "not_reported": "not reported by govulncheck",
              None: "reachability not checked"}
BUILD_TIMEOUT = float(os.environ.get("PP_REPO_BUILD_TIMEOUT", "1200"))
TEST_TIMEOUT = float(os.environ.get("PP_REPO_TEST_TIMEOUT", "1800"))
VULNCHECK_TIMEOUT = float(os.environ.get("PP_GOVULNCHECK_TIMEOUT", "1200"))

_locks: dict[str, threading.Lock] = {}      # one scan or proposal per repository at a time
_state_lock = threading.RLock()
_osv_cache: dict[str, dict] = {}


def _lock(name: str) -> threading.Lock:
    with _state_lock:
        return _locks.setdefault(name, threading.Lock())


def state_dir() -> Path:
    return config.STATE_DIR / "repo-audit"


def _state_file(name: str) -> Path:
    return state_dir() / f"{name}.json"


def load(name: str) -> dict:
    with _state_lock:
        path = _state_file(name)
        if path.exists():
            try:
                return json.loads(path.read_text())
            except json.JSONDecodeError:
                pass
        return {"scan": None, "status": "never", "proposals": []}


def _save(name: str, data: dict) -> None:
    with _state_lock:
        state_dir().mkdir(parents=True, exist_ok=True)
        tmp = _state_file(name).with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1, default=str))
        tmp.replace(_state_file(name))


def _update(name: str, fn: Callable[[dict], None]) -> dict:
    with _state_lock:
        data = load(name)
        fn(data)
        _save(name, data)
        return data


# ------------------------------------------------------------------------ OSV

def _api() -> str:
    cfg = settings.section("feed", {}) or {}
    return (cfg.get("api_url") or "https://api.osv.dev/v1").rstrip("/")


def osv_query(comps: list[Component]) -> list[list[str]]:
    """Advisory ids per component, in order (api.osv.dev querybatch)."""
    out: list[list[str]] = []
    for start in range(0, len(comps), 500):
        chunk = comps[start:start + 500]
        r = requests.post(f"{_api()}/querybatch", timeout=60, json={"queries": [
            {"package": {"ecosystem": OSV_ECOSYSTEM[c.ecosystem], "name": c.coordinate}, "version": c.version}
            for c in chunk]})
        r.raise_for_status()
        out += [[v["id"] for v in res.get("vulns", [])] for res in r.json().get("results", [])]
    return out


def osv_vuln(vid: str) -> dict:
    if vid not in _osv_cache:
        r = requests.get(f"{_api()}/vulns/{vid}", timeout=60)
        r.raise_for_status()
        _osv_cache[vid] = r.json()
    return _osv_cache[vid]


def rated(adv: dict) -> dict:
    """Go's own records (GO-…) carry no severity; the GitHub record they alias does.
    Returns the advisory with that rating filled in, or unchanged."""
    if feed.advisory_severity(adv):
        return adv
    for alias in adv.get("aliases", []):
        if not alias.startswith("GHSA-"):
            continue
        try:
            level = feed.advisory_severity(osv_vuln(alias))
        except Exception:                       # a missing alias record only costs the rating
            continue
        if level:
            return {**adv, "database_specific": {**(adv.get("database_specific") or {}), "severity": level,
                                                 "severity_from": alias}}
    return adv


# ----------------------------------------------------------------- inventory

def inventory(repo: Path) -> list[dict]:
    """Every pinned package of the repository, through the ecosystem drivers."""
    out, seen = [], set()
    for eco in fleet.ECOSYSTEMS.values():
        try:
            if not eco.detect(repo):
                continue
            comps = eco.components(repo)
        except Exception as exc:                 # one unreadable manifest must not hide the rest
            print(f"[repo-audit] {eco.name} inventory of {repo.name}: {exc}", flush=True)
            continue
        indirect = _go_indirect(repo) if eco.name == "go" else set()
        for c in comps:
            key = (c.ecosystem, c.group, c.name, c.version)
            if key in seen or c.ecosystem not in OSV_ECOSYSTEM or not overrides.package_in_scope(c):
                continue
            seen.add(key)
            out.append({"component": c, "indirect": (c.name, c.version) in indirect})
    return out


def _go_indirect(repo: Path) -> set[tuple[str, str]]:
    return {(m, v) for mod in gomods(repo) for m, v, ind in parse_requires(mod.read_text(encoding="utf-8")) if ind}


# ---------------------------------------------------------------- govulncheck

def govulncheck_available() -> Optional[str]:
    """None when govulncheck can run, else why not."""
    if not shutil.which("govulncheck"):
        return "govulncheck is not installed (go install golang.org/x/vuln/cmd/govulncheck@latest)"
    if not shutil.which("go"):
        return "the Go toolchain is not installed, govulncheck needs it"
    return None


def _json_stream(text: str) -> list[dict]:
    """govulncheck -format json writes a stream of (indented) JSON objects."""
    dec, out, i = json.JSONDecoder(), [], 0
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            return out
        obj, i = dec.raw_decode(text, i)
        out.append(obj)


def _level(frame: dict) -> str:
    return "called" if frame.get("function") else "imported" if frame.get("package") else "required"


def govulncheck(repo: Path) -> dict:
    """Run govulncheck in every Go module of the repository.

    {available, ran, note, levels: {GO-id: level}, aliases: {GO-id: [ids]},
     found: {GO-id: {module, version, fixed_version, summary, symbols}}}"""
    why = govulncheck_available()
    if why:
        return {"available": False, "ran": False, "note": why, "levels": {}, "aliases": {}, "found": {}}
    levels: dict[str, str] = {}
    aliases: dict[str, list[str]] = {}
    found: dict[str, dict] = {}               # GO-id -> {module, version, fixed_version, summary}
    errors = []
    env = {**os.environ, "GOFLAGS": "-mod=mod", "GOTOOLCHAIN": os.environ.get("GOTOOLCHAIN", "auto")}
    mods = gomods(repo)
    for mod in mods:
        try:
            proc = subprocess.run(["govulncheck", "-format", "json", "./..."], cwd=mod.parent, capture_output=True,
                                  text=True, env=env, timeout=VULNCHECK_TIMEOUT)
            messages = _json_stream(proc.stdout)
        except (subprocess.SubprocessError, OSError, json.JSONDecodeError) as exc:
            errors.append(f"{mod.relative_to(repo).as_posix()}: {type(exc).__name__}: {exc}"[:300])
            continue
        if not messages and proc.returncode != 0:
            errors.append(f"{mod.relative_to(repo).as_posix()}: {proc.stderr.strip()[-300:]}")
            continue
        for msg in messages:
            if "osv" in msg:
                o = msg["osv"]
                aliases[o["id"]] = list(o.get("aliases") or [])
                found.setdefault(o["id"], {})["summary"] = o.get("summary") or ""
            elif "finding" in msg:
                f = msg["finding"]
                trace = f.get("trace") or [{}]
                level = _level(trace[0])
                vid = f.get("osv", "")
                if vid not in levels or REACH[level] < REACH[levels[vid]]:
                    levels[vid] = level
                info = found.setdefault(vid, {})
                info.update({"module": trace[-1].get("module", ""), "version": trace[-1].get("version", ""),
                             "fixed_version": f.get("fixed_version", "")})
                if level == "called" and trace[0].get("function"):
                    info.setdefault("symbols", [])
                    sym = ".".join(x for x in (trace[0].get("package"), trace[0].get("receiver"),
                                               trace[0].get("function")) if x)
                    if sym not in info["symbols"] and len(info["symbols"]) < 10:
                        info["symbols"].append(sym)
    ran = len(errors) < len(mods)
    note = (f"govulncheck checked {len(mods) - len(errors)} of {len(mods)} Go modules" if ran
            else "govulncheck failed: " + "; ".join(errors)[:600])
    if errors and ran:
        note += "; failed: " + "; ".join(errors)[:400]
    return {"available": True, "ran": ran, "note": note, "levels": levels, "aliases": aliases, "found": found}


def reach_for(ids: list[str], vc: dict) -> Optional[str]:
    """The govulncheck level for an advisory known under any of these ids."""
    if not vc.get("ran"):
        return None
    wanted = set(ids)
    best = None
    for go_id, level in vc["levels"].items():
        if go_id in wanted or wanted & set(vc["aliases"].get(go_id, [])):
            if REACH.get(level, 9) < REACH.get(best, 9) or best is None:
                best = level
    return best or "not_reported"


# ----------------------------------------------------------------------- scan

def _norm_version(v: str) -> str:
    return v[1:] if v and v[0] == "v" and v[1:2].isdigit() else v


def _group(advs: list[dict]) -> list[list[dict]]:
    """Advisories naming the same vulnerability (GO-… and GHSA-… aliases) together."""
    groups: list[tuple[set[str], list[dict]]] = []
    for adv in advs:
        ids = {adv["id"], *adv.get("aliases", [])}
        for known, members in groups:
            if known & ids:
                known |= ids
                members.append(adv)
                break
        else:
            groups.append((ids, [adv]))
    return [m for _, m in groups]


def _finding(comp: Component, indirect: bool, group: list[dict], vc: dict) -> dict:
    sevs = [feed.advisory_severity(a) for a in group]
    sev = min((s for s in sevs if s), key=feed.SEVERITY.get, default=None)
    # the record with a rating (GitHub's) is the one shown; every id stays listed
    main = next((a for a in group if feed.advisory_severity(a)), group[0])
    # a GO- record borrows its rating from a GHSA alias; credit that GHSA id as canonical
    advisory_id = (main.get("database_specific") or {}).get("severity_from") or main["id"]
    ids = sorted({x for a in group for x in [a["id"], *a.get("aliases", [])]})
    fixes = [f for a in group for f in [feed.target_version(a, comp.ecosystem, comp.coordinate)] if f]
    fixed = max(fixes, key=functools.cmp_to_key(compare)) if fixes else None
    reach = reach_for(ids, vc) if comp.ecosystem == "go" else None
    go_id = next((i for i in ids if i.startswith("GO-")), None)
    symbols = (vc.get("found", {}).get(go_id) or {}).get("symbols", []) if go_id else []
    return {"key": f"{comp.coordinate}@{comp.version}#{advisory_id}", "advisory": advisory_id, "ids": ids,
            "title": feed.title(main), "summary": main.get("summary") or next(
                (a.get("summary") for a in group if a.get("summary")), "") or "",
            "severity": sev, "ecosystem": comp.ecosystem, "package": comp.coordinate, "version": comp.version,
            "path": comp.path, "indirect": indirect, "fixed_version": fixed, "patch_available": fixed is not None,
            "reachability": reach, "reachability_text": REACH_TEXT.get(reach, reach), "symbols": symbols,
            "source": "osv"}


def rank(findings: list[dict]) -> list[dict]:
    """Reachable first, then by severity, then direct before indirect."""
    return sorted(findings, key=lambda f: (REACH.get(f["reachability"], 9), feed.SEVERITY.get(f["severity"] or "none", 5),
                                           f["indirect"], f["package"], f["advisory"]))


def scan_path(name: str, repo: Path, run_govulncheck: bool = True) -> dict:
    """Inventory, OSV match and reachability for one checked-out repository."""
    started = time.time()
    inv = inventory(repo)
    comps = [x["component"] for x in inv]
    ids = osv_query(comps) if comps else []
    unique = sorted({v for vs in ids for v in vs})
    with ThreadPoolExecutor(8) as pool:
        records = dict(zip(unique, pool.map(lambda v: rated(osv_vuln(v)), unique)))
    has_go = any(c.ecosystem == "go" for c in comps)
    if has_go and run_govulncheck:
        vc = govulncheck(repo)
    elif has_go:
        vc = {"available": govulncheck_available() is None, "ran": False, "note": "govulncheck skipped",
              "levels": {}, "aliases": {}, "found": {}}
    else:
        vc = {"available": govulncheck_available() is None, "ran": False, "note": "no Go modules in this repository",
              "levels": {}, "aliases": {}, "found": {}}

    findings, rejected, packages = [], [], []
    wl = f"repo/{name}"
    for item, vids in zip(inv, ids + [[]] * (len(inv) - len(ids))):
        comp = item["component"]
        confirmed = []
        for vid in vids:
            adv = records[vid]
            if matcher.match(adv, {wl: [comp]}):
                confirmed.append(adv)
            else:
                rejected.append({"package": comp.coordinate, "version": comp.version, "advisory": vid})
        groups = _group(confirmed)
        for group in groups:
            findings.append(_finding(comp, item["indirect"], group, vc))
        packages.append({"ecosystem": comp.ecosystem, "name": comp.coordinate, "version": comp.version,
                         "path": comp.path, "indirect": item["indirect"], "advisories": len(groups)})

    # standard-library findings come only from govulncheck (go.mod pins no stdlib version)
    for go_id, info in (vc.get("found") or {}).items():
        if info.get("module") == "stdlib" and vc["levels"].get(go_id) == "called":
            findings.append({"key": f"stdlib#{go_id}", "advisory": go_id, "ids": sorted({go_id, *vc["aliases"].get(go_id, [])}),
                             "title": next((a for a in vc["aliases"].get(go_id, []) if a.startswith("CVE-")), go_id),
                             "summary": info.get("summary", ""), "severity": None, "ecosystem": "go", "package": "stdlib",
                             "version": _norm_version(info.get("version", "")), "path": None, "indirect": False,
                             "fixed_version": _norm_version(info.get("fixed_version", "")) or None,
                             "patch_available": False, "reachability": "called",
                             "reachability_text": REACH_TEXT["called"], "symbols": info.get("symbols", []),
                             "source": "govulncheck", "not_fixable": "upgrade the Go toolchain that builds this repository"})

    findings = rank(findings)
    return {"name": name, "scanned": time.time(), "seconds": round(time.time() - started, 1),
            "packages": sorted(packages, key=lambda p: (p["ecosystem"], p["name"])),
            "ecosystems": sorted({c.ecosystem for c in comps}), "findings": findings, "rejected": rejected,
            "govulncheck": {k: vc[k] for k in ("available", "ran", "note")},
            "counts": {s: sum(1 for f in findings if f["severity"] == s) for s in feed.SEVERITY},
            "reachable": sum(1 for f in findings if f["reachability"] == "called")}


# ------------------------------------------------------------------- sources

def sources() -> dict:
    return getattr(fleet.get(), "repos", {}) or {}


def source(name: str):
    src = sources().get(name)
    if src is None:
        raise KeyError(name)
    return src


def _checkout(src) -> str:
    """Clone or sync the repository read-only; returns a note when syncing failed."""
    src.ensure()
    if not src.path.exists():
        raise DriverError(f"{src.name}: no repository at {src.path} and nothing to clone it from (set `url`)")
    note = ""
    if src.has_remote():
        try:
            src.sync()
        except DriverError as exc:
            note = f"sync failed, scanned the local copy: {exc}"
    return note


def scan(name: str, actor: Optional[str] = None) -> dict:
    """Clone or sync one repo-only source and audit it. Records the result."""
    src = source(name)
    with _lock(name):
        _update(name, lambda d: d.update(status="scanning", error=None, started=time.time(), by=actor))
        try:
            note = _checkout(src)
            result = scan_path(name, src.path)
            result.update(head=src.head(), branch=src.main, sync_note=note or None, by=actor)
            _update(name, lambda d: d.update(status="ok", scan=result, error=None))
            return result
        except Exception as exc:
            msg = f"{type(exc).__name__}: {exc}"[:500]
            _update(name, lambda d: d.update(status="error", error=msg))
            raise


def start_scan(name: str, actor: Optional[str] = None) -> None:
    source(name)

    def run():
        try:
            scan(name, actor)
        except Exception as exc:
            print(f"[repo-audit] scan of {name}: {exc}", flush=True)
    _update(name, lambda d: d.update(status="scanning", error=None, started=time.time(), by=actor))
    threading.Thread(target=run, daemon=True, name=f"pp-repo-scan-{name}").start()


def overview() -> list[dict]:
    out = []
    for name, src in sources().items():
        data = load(name)
        out.append({"name": name, "url": src.url, "path": str(src.path), "branch": src.main,
                    "cloned": src.path.exists(), "status": data.get("status", "never"), "error": data.get("error"),
                    "started": data.get("started"), "scan": data.get("scan"),
                    "proposals": data.get("proposals", [])[:20],
                    "govulncheck": govulncheck_available() or "installed"})
    return out


# -------------------------------------------------------------- fix proposals

def _run(cmd: list[str], cwd: Path, timeout: float) -> dict:
    env = {**os.environ, "GOFLAGS": "-mod=mod", "GOTOOLCHAIN": os.environ.get("GOTOOLCHAIN", "auto")}
    started = time.time()
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env, timeout=timeout)
        out = (proc.stdout + proc.stderr).strip()
        return {"cmd": " ".join(cmd), "ok": proc.returncode == 0, "exit": proc.returncode,
                "seconds": round(time.time() - started, 1), "tail": out[-2000:]}
    except subprocess.TimeoutExpired:
        return {"cmd": " ".join(cmd), "ok": False, "exit": None, "seconds": round(time.time() - started, 1),
                "tail": f"timed out after {timeout:.0f}s"}
    except OSError as exc:
        return {"cmd": " ".join(cmd), "ok": False, "exit": None, "seconds": 0, "tail": str(exc)}


def _checks(repo: Path, dirs: list[Path]) -> dict:
    """go build ./... and go test ./... in every changed module, when Go is installed."""
    if not shutil.which("go"):
        return {"ran": False, "note": "the Go toolchain is not installed: build and tests not run", "steps": []}
    steps = []
    for d in dirs:
        rel = d.relative_to(repo).as_posix() or "."
        b = _run(["go", "build", "./..."], d, BUILD_TIMEOUT)
        steps.append({**b, "module": rel, "kind": "build"})
        t = _run(["go", "test", "./..."], d, TEST_TIMEOUT) if b["ok"] else \
            {"cmd": "go test ./...", "ok": False, "exit": None, "seconds": 0, "tail": "skipped: build failed"}
        steps.append({**t, "module": rel, "kind": "test"})
    return {"ran": True, "ok": all(s["ok"] for s in steps), "steps": steps}


def _finding_by(scan_result: dict, key: str) -> dict:
    for f in scan_result.get("findings", []):
        if key in (f["key"], f["advisory"]) or key in f["ids"]:
            return f
    raise KeyError(key)


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-")[:80]


def _proposable(name: str, key: str):
    src = source(name)
    data = load(name)
    if not data.get("scan"):
        raise ValueError(f"{name} has not been scanned yet")
    finding = _finding_by(data["scan"], key)
    if finding.get("not_fixable"):
        raise ValueError(f"{finding['package']}: {finding['not_fixable']}")
    if not finding.get("fixed_version"):
        raise ValueError(f"{finding['package']} {finding['version']}: no fixed version released for {finding['advisory']}")
    return src, finding


def _base_checks(src, dirs: list[Path]) -> dict:
    """The same build and tests on the main branch, in a throwaway worktree."""
    with tempfile.TemporaryDirectory() as tmp:
        wt = Path(tmp) / "base"
        src._git("worktree", "add", "-q", "--detach", str(wt), src.main)
        try:
            base = _checks(wt, [wt / d.relative_to(src.path) for d in dirs])
        finally:
            src._git("worktree", "remove", "--force", str(wt))
    return {"ok": base.get("ok", False),
            "steps": [{k: s[k] for k in ("cmd", "module", "kind", "ok", "exit")} for s in base.get("steps", [])]}


def propose(name: str, key: str, actor: Optional[str] = None, proposal_id: Optional[str] = None) -> dict:
    """Bump the package of one finding on a local branch, with build/test/govulncheck evidence.
    Never pushes, never merges into the main branch."""
    src, finding = _proposable(name, key)
    eco = fleet.ECOSYSTEMS[finding["ecosystem"]]
    pid = proposal_id or f"{int(time.time() * 1000)}"
    branch = f"lighthouse/{_slug(finding['package'].split('/')[-1])}-{finding['fixed_version']}-{_slug(finding['advisory'])}"
    prop = {"id": pid, "key": finding["key"], "advisory": finding["advisory"], "title": finding["title"],
            "package": finding["package"], "from": finding["version"], "to": finding["fixed_version"],
            "branch": branch, "status": "running", "by": actor, "started": time.time(), "steps": []}

    def record(**fields):
        prop.update(fields)

        def put(d):
            props = [p for p in d.setdefault("proposals", []) if p["id"] != pid]
            d["proposals"] = [dict(prop)] + props
        _update(name, put)

    def step(title: str, status: str, detail: str = ""):
        prop["steps"].append({"ts": time.time(), "title": title, "status": status, "detail": detail[:2000]})
        record()

    record()
    with _lock(name):
        started_change = False
        try:
            note = _checkout(src)
            if note:
                step("Sync", "warn", note)
            repo = src.path
            comp = next((x["component"] for x in inventory(repo)
                         if x["component"].coordinate == finding["package"] and x["component"].version == finding["version"]), None)
            if comp is None:
                raise DriverError(f"{finding['package']} {finding['version']} is no longer pinned on {src.main}; scan again")
            go = finding["ecosystem"] == "go"
            before_vc = govulncheck(repo) if go else None
            if before_vc is not None:
                step("govulncheck before", "ok" if before_vc["ran"] else "info",
                     f"{REACH_TEXT.get(reach_for(finding['ids'], before_vc))}. {before_vc['note']}")
            src.start_change(branch)
            started_change = True
            moved = []
            if hasattr(eco, "lockstep"):
                moved = eco.lockstep(repo, comp, finding["fixed_version"])
            changed = eco.bump(repo, comp, finding["fixed_version"])
            step("Bump", "ok", f"{comp.coordinate} {comp.version} -> {finding['fixed_version']}; changed "
                 + ", ".join(changed) + (f"; also moves {', '.join(f'{m} {v}' for m, v in moved)}" if moved else ""))
            after_inv = {(x["component"].coordinate): x["component"].version for x in inventory(repo)}
            if go:
                dirs = sorted({(repo / c).parent for c in changed if c.endswith("go.mod")}) or [repo]
                checks = _checks(repo, dirs)
                if checks["ran"] and not checks["ok"]:
                    # was it already broken before the bump? the same checks on the main branch
                    checks["before"] = _base_checks(src, dirs)
                for s in checks["steps"]:
                    step(f"go {s['kind']} ({s['module']})", "ok" if s["ok"] else "fail", s["tail"][-800:])
                if not checks["ran"]:
                    step("Build and tests", "info", checks["note"])
                after_vc = govulncheck(repo)
                left = reach_for(finding["ids"], after_vc)
                step("govulncheck after", "ok" if after_vc["ran"] and left in ("not_reported", None) else
                     "fail" if after_vc["ran"] else "info",
                     f"{REACH_TEXT.get(left) if after_vc['ran'] else after_vc['note']}")
            else:
                checks, after_vc, left = {"ran": False, "note": f"no build check for {finding['ecosystem']}", "steps": []}, None, None
                step("Build and tests", "info", checks["note"])

            evidence = {
                "advisory": finding["advisory"], "ids": finding["ids"], "package": comp.coordinate,
                "from": comp.version, "to": finding["fixed_version"], "changed_files": changed,
                "also_moved": [{"module": m, "version": v} for m, v in moved],
                "pinned_after": after_inv.get(comp.coordinate),
                "checks": checks,
                "govulncheck": None if before_vc is None else {
                    "before": {"ran": before_vc["ran"], "note": before_vc["note"],
                               "reachability": reach_for(finding["ids"], before_vc)},
                    "after": {"ran": after_vc["ran"], "note": after_vc["note"], "reachability": left}},
            }
            message = _commit_message(finding, evidence)
            commit = src.commit(message)
            patch = src._git("format-patch", "-1", "--stdout", "HEAD")
            patch_path = state_dir() / name / f"{_slug(branch)}.patch"
            patch_path.parent.mkdir(parents=True, exist_ok=True)
            patch_path.write_text(patch + "\n", encoding="utf-8")
            src._git("checkout", "-q", src.main)        # leave the branch for a human; never merge, never push
            started_change = False
            ok = (not checks.get("ran") or checks.get("ok")) and (after_vc is None or not after_vc["ran"]
                                                                   or left in ("not_reported",))
            step("Proposed", "ok" if ok else "warn",
                 f"commit {commit} on local branch {branch} in {repo}; patch {patch_path}. Not pushed.")
            record(status="proposed" if ok else "proposed_with_failures", commit=commit, evidence=evidence,
                   patch=str(patch_path), diff=patch[:20000], finished=time.time())
            return prop
        except Exception as exc:
            if started_change:
                try:
                    src.abandon_change(branch)
                except DriverError:
                    pass
            step("Failed", "fail", f"{type(exc).__name__}: {exc}")
            record(status="failed", error=f"{type(exc).__name__}: {exc}"[:500], finished=time.time())
            if not isinstance(exc, (DriverError, ValueError, KeyError)):
                traceback.print_exc()
            return prop


def start_proposal(name: str, key: str, actor: Optional[str] = None) -> dict:
    """Validate, then run the proposal in the background; returns its id."""
    src, finding = _proposable(name, key)
    pid = f"{int(time.time() * 1000)}"

    def run():
        propose(src.name, finding["key"], actor, pid)
    threading.Thread(target=run, daemon=True, name=f"pp-repo-fix-{name}").start()
    return {"id": pid, "key": finding["key"]}


def _commit_message(f: dict, ev: dict) -> str:
    lines = [f"LightHouse: {f['package']} {f['version']} -> {f['fixed_version']} ({f['title']})", "",
             f"Advisory: {', '.join(f['ids'])}", f"Severity: {f['severity'] or 'unknown'}", ""]
    if f.get("summary"):
        lines += [f["summary"], ""]
    lines.append(f"Changed: {', '.join(ev['changed_files'])}")
    if ev["also_moved"]:
        lines.append("Also moved by minimal version selection: "
                     + ", ".join(f"{m['module']} {m['version']}" for m in ev["also_moved"]))
    c = ev["checks"]
    if c.get("ran"):
        for s in c["steps"]:
            lines.append(f"{s['cmd']} ({s['module']}): {'ok' if s['ok'] else 'FAILED'}")
        if "before" in c:
            lines.append(f"Same checks before the bump: {'ok' if c['before']['ok'] else 'also failing'}")
    else:
        lines.append(c.get("note", ""))
    g = ev.get("govulncheck")
    if g:
        lines.append(f"govulncheck before: {REACH_TEXT.get(g['before']['reachability']) if g['before']['ran'] else g['before']['note']}")
        lines.append(f"govulncheck after: {REACH_TEXT.get(g['after']['reachability']) if g['after']['ran'] else g['after']['note']}")
    lines += ["", "Proposed by LightHouse on a local branch; not pushed."]
    return "\n".join(lines)
