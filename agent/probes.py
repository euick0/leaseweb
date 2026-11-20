"""Safe exploit probes: the before/after signal for every action. A probe only
sends requests through a Target driver, so the same probe works on any platform.

log4shell  sends `${jndi:ldap://callback:1389/<token>}` in X-Api-Version and
           asks the target's callback listener whether the token arrived. A
           connection means the lookup ran: VULNERABLE. No payload is ever
           served, so nothing executes.
keyid-traversal
           asks billing for the key `../../../../srv/pp-probe/marker.txt`. The
           marker is a harmless file placed in the image for this purpose; its
           fingerprint in the response means the path escaped the key
           directory: VULNERABLE.
A 403 from the gateway means the request never reached the app: BLOCKED.

`via` says which path was probed: public (what the internet sees), internal
(the workload's own service) or canary.
"""
from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import asdict, dataclass

from .drivers.base import DriverError, Target
from .schemas import Workload

_lock = threading.Lock()     # probes share the callback listener: run one at a time

MARKER = b"patchpilot probe marker: if you can read this, the key id escaped the key directory\n"


@dataclass
class ProbeResult:
    probe: str
    workload: str
    via: str
    result: str          # VULNERABLE | SAFE | BLOCKED | ERROR
    detail: str

    def as_dict(self) -> dict:
        return asdict(self)


def log4shell(target: Target, wl: Workload, via: str, wait: float = 5.0) -> ProbeResult:
    def res(result: str, detail: str) -> ProbeResult:
        return ProbeResult("log4shell", wl.id, via, result, detail)

    with _lock:
        token = "pp" + secrets.token_hex(6)
        since = time.time() - 1
        r = target.http(wl, "/", {"X-Api-Version": f"${{jndi:ldap://callback:1389/{token}}}"}, via=via)
        if r.status == 0:
            return res("ERROR", r.body[:200])
        if r.status == 403:
            return res("BLOCKED", "gateway rejected the payload with 403")
        deadline = time.time() + wait
        while time.time() < deadline:
            try:
                hits = target.callback_hits(wl, since)
            except (DriverError, ValueError) as exc:
                return res("ERROR", f"callback listener unreachable: {exc}")
            tagged = [h for h in hits if token in h.get("data", "")]
            if tagged:
                return res("VULNERABLE", f"the app opened a JNDI/LDAP connection to the callback listener "
                                         f"from {tagged[0]['peer']} carrying the probe token")
            time.sleep(0.25)
        return res("SAFE", f"HTTP {r.status}, no callback within {wait:.0f}s: the lookup did not run")


def keyid_traversal(target: Target, wl: Workload, via: str) -> ProbeResult:
    def res(result: str, detail: str) -> ProbeResult:
        return ProbeResult("keyid-traversal", wl.id, via, result, detail)

    fp = hashlib.sha256(MARKER).hexdigest()[:16]
    r = target.http(wl, "/invoice", {"X-Key-Id": "../../../../srv/pp-probe/marker.txt"}, via=via)
    if r.status == 0:
        return res("ERROR", r.body[:200])
    if r.status == 403:
        return res("BLOCKED", "gateway rejected the key id with 403")
    if fp in r.body:
        return res("VULNERABLE", f"HTTP {r.status}: the response carries the marker file's fingerprint {fp}")
    return res("SAFE", f"HTTP {r.status}: the key id did not leave the key directory")


PROBES = {"log4shell": log4shell, "keyid-traversal": keyid_traversal}


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
