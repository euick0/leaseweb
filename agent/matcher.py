"""Match every workload's SBOM against an advisory by package name and version
range. `patch_available` and `fixed_version` come from the advisory, never
from the model. The result is fleet-wide: one Match per affected workload."""
from __future__ import annotations

from . import feed
from .schemas import Component, Match
from .versions import in_osv_range


def _names(comp: Component) -> set[str]:
    names = {feed.normalise(comp.ecosystem, comp.name)}
    if comp.group:
        names.add(f"{comp.group}:{comp.name}")
    return names


def affected(adv: dict, comp: Component) -> bool:
    for eco, pkg, aff in feed.affected_packages(adv):
        if eco != comp.ecosystem or pkg not in _names(comp):
            continue
        if comp.version in aff.get("versions", []):
            return True
        if any(in_osv_range(comp.version, r.get("events", []))
               for r in aff.get("ranges", []) if r.get("type") in ("ECOSYSTEM", "SEMVER")):
            return True
    return False


def match(adv: dict, inventory: dict[str, list[Component]]) -> list[Match]:
    """inventory: workload id -> components found in its image."""
    out = []
    for workload_id, comps in inventory.items():
        for comp in comps:
            if affected(adv, comp):
                fixed = feed.target_version(adv, comp.ecosystem, comp.coordinate)
                out.append(Match(advisory_id=adv["id"], workload_id=workload_id, component=comp,
                                 fixed_version=fixed, patch_available=fixed is not None))
    return out
