"""Safe exploit probes: the before/after signal for every action. A probe only
sends requests through a Target driver, so the same probe works on any platform.

A probe is a callable ``fn(target, workload, via) -> ProbeResult`` registered in
the ``PROBES`` registry under a short name. ``via`` says which path was probed:
public (what the internet sees), internal (the workload's own service) or canary.

Attaching a check to an advisory
--------------------------------
Two things can point the pipeline at a check for a given advisory:

- the advisory's own ``database_specific.<db>.probe`` hint (read by agent/feed.py),
  which travels with the OSV record; and
- the advisory registry here (``attach``), which maps an advisory id or a CVE /
  GHSA alias to a registered check name. This lets a check be attached to a real
  OSV advisory that was added through the dashboard's "Add advisory" box, which
  carries no hint of its own.

``for_advisory`` resolves both, preferring an explicit hint. Register a check
with ``register`` and attach it to advisories with ``attach``; both start empty,
so a deployment only runs the checks it has deliberately installed.
"""
from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass
from typing import Callable, Optional

from .drivers.base import Target
from .schemas import Workload

_lock = threading.Lock()     # a probe that shares a listener can serialise on this


@dataclass
class ProbeResult:
    probe: str
    workload: str
    via: str
    result: str          # VULNERABLE | SAFE | BLOCKED | ERROR
    detail: str

    def as_dict(self) -> dict:
        return asdict(self)


# ------------------------------------------------------------- the registries

Probe = Callable[[Target, Workload, str], ProbeResult]

PROBES: dict[str, Probe] = {}            # check name -> callable
_ADVISORY_PROBES: dict[str, str] = {}    # advisory id / CVE / GHSA (upper-case) -> check name


def register(name: str, fn: Probe) -> None:
    """Add a check to the registry under `name`."""
    PROBES[name] = fn


def attach(advisory_or_alias: str, check_name: str) -> None:
    """Attach a registered check to an advisory id or one of its CVE/GHSA aliases."""
    _ADVISORY_PROBES[advisory_or_alias.strip().upper()] = check_name


def for_advisory(adv: dict, hint: Optional[str] = None) -> Optional[str]:
    """The registered check attached to this advisory, or None.

    An explicit `hint` (from the advisory's own database_specific block) wins; a
    check attached to the advisory's id or any of its CVE/GHSA aliases comes next.
    Only names that are actually registered are returned, so an advisory can be
    added before its check is installed without the pipeline trying to run it."""
    if hint and hint in PROBES:
        return hint
    for key in [adv.get("id"), *(adv.get("aliases") or []), *(adv.get("related") or [])]:
        name = _ADVISORY_PROBES.get((key or "").strip().upper())
        if name in PROBES:
            return name
    return None


# ------------------------------------------------------------- running a probe

def run(name: str, target: Target, wl: Workload, via: str) -> ProbeResult:
    try:
        return PROBES[name](target, wl, via)
    except Exception as exc:                       # a probe must never take the pipeline down
        return ProbeResult(name, wl.id, via, "ERROR", f"{type(exc).__name__}: {exc}"[:300])


def default_via(wl: Workload) -> str:
    return "public" if wl.internet_exposed else "internal"


def health(target: Target, wl: Workload, via: str, timeout: float) -> tuple[bool, str]:
    """Poll the health path until it answers 200, the app answers 5xx, or time runs out."""
    deadline = time.time() + timeout
    last = "no answer"
    while time.time() < deadline:
        r = target.http(wl, wl.health_path, via=via, timeout=3)
        if r.status == 200:
            return True, r.body.strip()[:200]
        if r.status >= 500:
            return False, f"HTTP {r.status}: {r.body.strip()[:200]}"    # the app is up and failing
        last = f"HTTP {r.status}: {r.body.strip()[:200]}" if r.status else r.body[:200]
        time.sleep(0.5)
    return False, last
