"""The pipeline: one advisory in, one decision per affected workload out.

  discover → inventory → match → triage (per workload) → rank → vet (once per
  package version) → policy (per workload) → act (per workload, in rank order)

Every step is logged to the decision log. Actions are bracketed by a probe on
the live path: the result before, the result after.
"""
from __future__ import annotations

import threading
import traceback
from typing import Optional

from . import config, db, feed, fleet, inventory, matcher, mitigation, policy, probes, triage, vetter
from .builder import BuildError
from .drivers.base import DriverError
from .schemas import Component, Match, TriageResult, VetResult, Workload

SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
_action_lock = threading.Lock()        # one rollout at a time: builds, canaries and probes share resources


class Log:
    def __init__(self, run_id: int, item_id: Optional[int] = None):
        self.run_id, self.item_id = run_id, item_id

    def __call__(self, step: str, status: str, title: str, detail: Optional[str] = None, data=None) -> None:
        db.log(self.run_id, step, status, title, detail, data, self.item_id)


# ------------------------------------------------------------- helpers

_sboms: dict[str, tuple[list[Component], str]] = {}     # image -> (components, how); images are immutable


def sbom(fl: fleet.Fleet, wl: Workload) -> tuple[list[Component], str]:
    if wl.image not in _sboms:
        src = fl.source(wl)
        refs = [f"docker:{wl.image}"] if wl.target_kind == "compose" else [fl.builder.push_name(wl.image)]
        _sboms[wl.image] = inventory.scan(refs, src.path if src else None, list(fleet.ECOSYSTEMS.values()))
    return _sboms[wl.image]


def forget_sboms() -> None:
    _sboms.clear()


def probes_for(fl: fleet.Fleet, wl: Workload, advisories: list[dict]) -> list[str]:
    """Probes of the advisories whose package this workload carries, in any version."""
    names = []
    comps = sbom(fl, wl)[0]
    for adv in advisories:
        probe = feed.hints(adv).get("probe")
        if probe and probe not in names and any(
                eco == c.ecosystem and pkg in (feed.normalise(eco, c.name), c.coordinate)
                for eco, pkg, _ in feed.affected_packages(adv) for c in comps):
            names.append(probe)
    return names

def _probe(fl: fleet.Fleet, adv: dict, wl: Workload, via: str, log: Log, label: str) -> Optional[dict]:
    name = feed.hints(adv).get("probe")
    if not name or name not in probes.PROBES:
        return None
    r = probes.run(name, fl.target(wl.target), wl, via)
    if via != "canary":
        db.record_probe(wl.id, r.probe, r.via, r.result, r.detail)
    status = {"VULNERABLE": "fail", "SAFE": "ok", "BLOCKED": "ok"}.get(r.result, "warn")
    log("probe", status, f"{label}: {r.result} ({r.via})", r.detail, r.as_dict())
    return r.as_dict()


def vet_key(eco: str, name: str, old: str, new: str) -> str:
    shipped, _ = fleet.ECOSYSTEMS[eco].artifacts(name, new)
    sha = vetter.sha256(shipped)[:16] if shipped.exists() else "missing"
    return f"{eco}:{name}:{old}->{new}@{sha}"


def vet_once(adv: dict, comp: Component, new: str, log: Log) -> tuple[VetResult, str]:
    """Vet comp -> new once per artifact; later workloads reuse the verdict."""
    key = vet_key(comp.ecosystem, comp.name, comp.version, new)
    cached = db.vet_cache_get(key)
    if cached:
        result = VetResult.model_validate(cached).model_copy(update={"cached": True})
        log("vet", "ok" if result.verdict == "clean" else "warn",
            f"{comp.name} {comp.version} → {new}: {result.verdict.upper()} (cached verdict reused)",
            "; ".join(result.reasons), result.model_dump())
        return result, key
    log("vet", "info", f"Vetting {comp.name} {comp.version} → {new} before anything is built")
    result = vetter.vet(adv, fleet.ECOSYSTEMS[comp.ecosystem], comp.name, comp.version, new,
                        lambda status, title, detail, data: log("vet", status, title, detail, data))
    db.vet_cache_put(key, result)
    log("vet", {"clean": "ok", "suspicious": "warn", "malicious": "fail"}[result.verdict],
        f"{comp.name} {new}: {result.verdict.upper()}", "; ".join(result.reasons), result.model_dump())
    return result, key


def _bump_set(fl: fleet.Fleet, adv: dict, wl: Workload, comp: Component, version: str) -> list[Component]:
    """The fixed package plus packages released in lockstep with it (log4j-api with log4j-core)."""
    out = [comp]
    src = fl.source(wl)
    together = set(feed.hints(adv).get("bump_together", []))
    if src and together:
        eco = fl.ecosystem(comp.ecosystem)
        for c in eco.components(src.path):
            if c.coordinate in together and c.version != version:
                out.append(c)
    return out


def priority(wl: Workload, t: TriageResult) -> tuple:
    """Sort key: most critical first; within a severity, exposed and reachable,
    then reachable, then the rest."""
    return (SEVERITY[t.severity_for_this_workload],
            not (wl.internet_exposed and t.reachable), not t.reachable, wl.id)


def _mitigation_ok(wl: Workload, t: TriageResult) -> bool:
    if not (wl.gateway and t.mitigation_pattern and t.mitigation_fields):
        return False
    try:
        mitigation.render("check", t.mitigation_pattern, t.mitigation_fields)
        return True
    except mitigation.InvalidMitigation:
        return False


# ------------------------------------------------------------- the run

def run_advisory(adv: dict) -> int:
    run_id = db.create_run(adv["id"], feed.title(adv), adv.get("summary", ""))
    log = Log(run_id)
    try:
        _run(adv, run_id, log)
    except Exception as exc:
        log("error", "fail", f"Pipeline error: {type(exc).__name__}", traceback.format_exc()[-1500:])
        db.update_run(run_id, "failed", f"pipeline error: {exc}")
    return run_id


def _run(adv: dict, run_id: int, log: Log) -> None:
    fl = fleet.get()
    log("watch", "info", f"New advisory {feed.title(adv)}", adv.get("summary"), {"id": adv["id"]})

    # 1. discover
    workloads = fl.discover(max_age=0)
    envs = sorted({w.target for w in workloads})
    log("discover", "ok" if workloads else "warn",
        f"{len(workloads)} workloads across {len(envs)} environments",
        "; ".join(f"{n}: {e}" for n, e in fl.target_errors.items()) or None,
        [w.model_dump() for w in workloads])

    # 2. inventory, one SBOM per distinct image
    inv = {wl.id: sbom(fl, wl)[0] for wl in workloads}
    images = {wl.image for wl in workloads}
    log("inventory", "ok", f"SBOMs for {len(images)} images, {sum(len(_sboms[i][0]) for i in images)} packages",
        "; ".join(sorted({_sboms[i][1] for i in images})))

    # 3. match
    matches = matcher.match(adv, inv)
    if not matches:
        log("match", "ok", "No workload carries an affected version")
        db.update_run(run_id, "done", "no workload affected")
        return
    by_id = {w.id: w for w in workloads}
    log("match", "warn", f"{len(matches)} workload(s) affected",
        "\n".join(f"{m.component.coordinate} {m.component.version} in {m.workload_id}" for m in matches))

    # 4. triage, per workload
    rows: list[tuple[int, Workload, Match, TriageResult]] = []
    for m in matches:
        wl = by_id[m.workload_id]
        item_id = db.create_item(run_id, wl, m.component, m.fixed_version)
        ilog = Log(run_id, item_id)
        src = fl.source(wl)
        eco = fl.ecosystem(m.component.ecosystem)
        terms = feed.hints(adv).get("grep") or eco.grep_terms(m.component)
        hits = src.grep(terms) if src else []
        try:
            gateway = fl.target(wl.target).gateway_config(wl)
        except Exception:
            gateway = None
        t, source = triage.triage(adv, wl, m, hits, gateway)
        db.update_item(item_id, triage=t, triage_source=source)
        ilog("triage", "ai" if source != "fallback" else "warn",
             f"{wl.name}: {t.severity_for_this_workload.upper()}, "
             f"{'reachable' if t.reachable else 'not reachable'}, "
             f"{'internet-exposed' if wl.internet_exposed else 'internal'} → {t.recommended_action}",
             t.explanation, {"source": source, "grep_hits": hits, **t.model_dump()})
        rows.append((item_id, wl, m, t))

    # 5. rank
    rows.sort(key=lambda r: priority(r[1], r[3]))
    for rank, (item_id, wl, _, t) in enumerate(rows, 1):
        db.update_item(item_id, rank=rank)
    log("rank", "info", "Priority (most critical first): " + " > ".join(
        f"{r[1].name}@{r[1].target} ({r[3].severity_for_this_workload})" for r in rows))

    # 6. vet, once per package version, for every workload that may need the fix
    vets: dict[int, Optional[VetResult]] = {}
    for item_id, wl, m, t in rows:
        if not (m.patch_available and t.affected and t.recommended_action in ("patch", "investigate")):
            vets[item_id] = None
            continue
        worst, keys = None, []
        for comp in _bump_set(fl, adv, wl, m.component, m.fixed_version):
            result, key = vet_once(adv, comp, m.fixed_version, Log(run_id, item_id))
            keys.append(key)
            if worst is None or ["clean", "suspicious", "malicious"].index(result.verdict) > \
                    ["clean", "suspicious", "malicious"].index(worst.verdict):
                worst = result
        vets[item_id] = worst
        db.update_item(item_id, vet_key=",".join(keys))

    # 7. policy and 8. act, in rank order
    for item_id, wl, m, t in rows:
        src = fl.source(wl)
        pol = policy.load((src.config() if src else {}).get("policy"))
        d = policy.decide(pol, wl, t, m.patch_available, vets[item_id], _mitigation_ok(wl, t))
        ilog = Log(run_id, item_id)
        db.update_item(item_id, decision=d.__dict__)
        ilog("policy", {"auto": "ok", "needs_approval": "pending", "block": "fail", "queue": "info",
                        "ignore": "info", "escalate": "warn"}[d.decision],
             f"{wl.name}: {d.action} → {d.decision.replace('_', ' ')}", d.reason, d.__dict__)
        status = {"auto": "running", "needs_approval": "awaiting_approval", "queue": "queued",
                  "block": "blocked", "ignore": "ignored", "escalate": "escalated"}[d.decision]
        db.update_item(item_id, status=status, outcome=d.reason)
        if d.decision == "auto":
            execute(item_id)
    finish_run(run_id)


# ------------------------------------------------------------- actions

def finish_run(run_id: int) -> None:
    its = db.items(run_id)
    states = [i["status"] for i in its]
    if any(s == "running" for s in states):
        status = "running"
    elif any(s == "awaiting_approval" for s in states):
        status = "awaiting_approval"
    else:
        status = "done"
    counts = {s: states.count(s) for s in dict.fromkeys(states)}
    db.update_run(run_id, status, ", ".join(f"{n} {s.replace('_', ' ')}" for s, n in counts.items()))


def approve(item_id: int) -> None:
    item = db.get_item(item_id)
    if not item or item["status"] not in ("awaiting_approval", "queued"):
        raise ValueError("item is not waiting for a decision")
    db.update_item(item_id, status="running")
    db.update_run(item["run_id"], "running")
    Log(item["run_id"], item_id)("policy", "ok", f"Approved by operator: {item['decision']['action']}")
    threading.Thread(target=lambda: (execute(item_id), finish_run(item["run_id"])), daemon=True).start()


def reject(item_id: int) -> None:
    item = db.get_item(item_id)
    if not item or item["status"] not in ("awaiting_approval", "queued"):
        raise ValueError("item is not waiting for a decision")
    db.update_item(item_id, status="blocked", outcome="rejected by operator")
    Log(item["run_id"], item_id)("policy", "warn", "Rejected by operator")
    finish_run(item["run_id"])


def execute(item_id: int) -> None:
    item = db.get_item(item_id)
    log = Log(item["run_id"], item_id)
    adv = next((a for a in feed.list_feed() if a["id"] == db.get_run(item["run_id"])["advisory_id"]), None)
    try:
        if adv is None:
            raise DriverError("advisory is no longer in the feed")
        with _action_lock:
            action = item["decision"]["action"]
            if action == "patch":
                _patch(item, adv, log)
            elif action == "mitigate":
                _mitigate(item, adv, log)
            else:
                db.update_item(item_id, status="escalated", outcome="nothing to execute")
    except Exception as exc:
        log("error", "fail", f"Action failed: {type(exc).__name__}", f"{exc}\n{traceback.format_exc()[-1200:]}")
        db.update_item(item_id, status="failed", outcome=str(exc)[:300])


def _patch(item: dict, adv: dict, log: Log) -> None:
    fl = fleet.get()
    wl = Workload.model_validate(item["workload"])
    comp = Component.model_validate(item["component"])
    version = item["fixed_version"]
    target = fl.target(wl.target)
    src = fl.source(wl)
    if not src:
        raise DriverError(f"{wl.name} is not linked to a source repository")
    eco = fl.ecosystem(comp.ecosystem)

    # every artifact must be the exact one that was vetted
    bump = _bump_set(fl, adv, wl, comp, version)
    for c in bump:
        key = vet_key(c.ecosystem, c.name, c.version, version)
        cached = db.vet_cache_get(key)
        if not cached:
            raise DriverError(f"{c.name} {version} has no vet verdict for this exact artifact ({key})")
        if cached["verdict"] == "malicious":
            raise DriverError(f"{c.name} {version} is vetted malicious")

    before = _probe(fl, adv, wl, probes.default_via(wl), log, "Before")

    branch = f"patchpilot/{adv['id']}-{comp.name}-{version}".lower()
    src.start_change(branch)
    changed = []
    for c in bump:
        changed += eco.bump(src.path, c, version)
    sha = src.commit(f"Bump {comp.coordinate} {comp.version} -> {version} ({feed.title(adv)})\n\n"
                     f"{adv.get('summary', '')}\n\nVetted by PatchPilot: "
                     + ", ".join(f"{c.name} {version}" for c in bump) + "\n")
    log("change", "ok", f"Commit {sha} on {src.name}:{branch}", "\n".join(changed), {"files": changed})

    try:
        image = fl.builder.build(str(src.path), src.name, src.url, f"pp-{sha}", push=wl.target_kind == "kubernetes")
    except BuildError as exc:
        src.abandon_change(branch)
        log("build", "fail", "Build failed; nothing deployed", str(exc))
        db.update_item(item["id"], status="failed", outcome="build failed, production untouched")
        return
    log("build", "ok", f"Built {image}")

    def fail(step: str, why: str) -> None:
        target.remove_canary(wl)
        src.abandon_change(branch)
        log(step, "fail", f"Canary rejected: {why}", "Canary removed; production untouched; branch left unmerged")
        ok, detail = probes.health(target, wl, probes.default_via(wl), 10)
        log("rollback", "ok" if ok else "fail",
            "Production still serving the previous version" if ok else "Production health check failing", detail)
        db.update_item(item["id"], status="rolled_back", outcome=f"canary failed: {why}"[:300])

    try:
        target.deploy_canary(wl, image)
    except DriverError as exc:
        return fail("canary", str(exc))
    log("canary", "info", f"Canary {wl.name}-canary running {image}")
    ok, detail = probes.health(target, wl, "canary", config.HEALTH_TIMEOUT)
    if not ok:
        return fail("canary", f"{wl.health_path} {detail}")
    log("canary", "ok", f"Canary healthy: {wl.health_path}", detail)
    canary = _probe(fl, adv, wl, "canary", log, "Canary")
    if canary and canary["result"] == "VULNERABLE":
        return fail("canary", "exploit still works on the canary")

    try:
        previous = target.promote(wl, image)
    except DriverError as exc:
        return fail("promote", f"rollout failed and was rolled back: {exc}")
    log("promote", "ok", f"Promoted {image}", f"previous image {previous}")
    target.remove_canary(wl)

    after = _probe(fl, adv, wl, probes.default_via(wl), log, "After")
    if after and after["result"] == "VULNERABLE":
        target.rollback(wl, previous)
        src.abandon_change(branch)
        log("rollback", "fail", "Still vulnerable after promote: rolled back", after["detail"])
        db.update_item(item["id"], status="rolled_back", outcome="still vulnerable after promote")
        return
    src.accept_change(branch)

    if after:
        proof = {"level": "exploit probe", "before": before, "after": after}
    else:
        comps, how = inventory.scan([fl.builder.push_name(image)], src.path, [eco])
        now = next((c.version for c in comps if c.name == comp.name), "unknown")
        ok, detail = probes.health(target, wl, probes.default_via(wl), 10)
        proof = {"level": "re-scan + health", "rescan": f"{comp.name} {now} ({how})", "health": ok}
    db.update_item(item["id"], status="done", proof=proof,
                   outcome=f"patched to {comp.name} {version}" + (f": {before['result']} → {after['result']}"
                                                                  if before and after else ""))


def _mitigate(item: dict, adv: dict, log: Log) -> None:
    fl = fleet.get()
    wl = Workload.model_validate(item["workload"])
    t = TriageResult.model_validate(item["triage"])
    target = fl.target(wl.target)
    rule = mitigation.render(adv["id"], t.mitigation_pattern, t.mitigation_fields)

    before = _probe(fl, adv, wl, probes.default_via(wl), log, "Before")
    try:
        target.apply_mitigation(wl, mitigation.key(adv["id"]), rule)
    except DriverError as exc:
        log("mitigate", "fail", "Virtual patch rejected by the gateway; previous config kept", str(exc))
        db.update_item(item["id"], status="failed", outcome="virtual patch rejected by nginx")
        return
    log("mitigate", "ok", f"Virtual patch active on gateway {wl.gateway}", rule, {"rule": rule})
    after = _probe(fl, adv, wl, probes.default_via(wl), log, "After")
    if after and after["result"] == "VULNERABLE":
        db.update_item(item["id"], status="failed", proof={"level": "exploit probe", "before": before, "after": after},
                       outcome="virtual patch applied but the probe still gets through")
        return
    ok, detail = probes.health(target, wl, probes.default_via(wl), 10)
    log("mitigate", "ok" if ok else "warn", "Service still healthy behind the rule" if ok else "Health check failing",
        detail)
    db.update_item(item["id"], status="done",
                   proof={"level": "exploit probe", "before": before, "after": after} if after else None,
                   outcome="virtual patch on the gateway" + (f": {before['result']} → {after['result']}"
                                                            if before and after else ""))
