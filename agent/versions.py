"""Small Maven-style version comparison, enough for OSV ECOSYSTEM ranges.

2.0-beta9 < 2.0-rc1 < 2.0 < 2.0.1 < 2.14.1 < 2.17.1
"""
from __future__ import annotations

import re

_QUALIFIERS = {"alpha": -5, "a": -5, "beta": -4, "b": -4, "milestone": -3, "m": -3,
               "rc": -2, "cr": -2, "snapshot": -1, "": 0, "ga": 0, "final": 0, "release": 0}


def _tokens(version: str) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for part in re.split(r"[.\-_]", version.lower()):
        for num, word in re.findall(r"(\d+)|([a-z]+)", part):
            if num:
                out.append((1, int(num)))
            else:
                # qualifiers sort before any release number; unknown words after
                out.append((0, _QUALIFIERS.get(word, 1)))
    while out and out[-1] == (1, 0):
        out.pop()
    return out


def compare(a: str, b: str) -> int:
    ta, tb = _tokens(a), _tokens(b)
    for i in range(max(len(ta), len(tb))):
        x = ta[i] if i < len(ta) else (1, 0)
        y = tb[i] if i < len(tb) else (1, 0)
        if x != y:
            return -1 if x < y else 1
    return 0


def in_osv_range(version: str, events: list[dict]) -> bool:
    """Evaluate one OSV range: events are processed in order of version."""
    def key(e: dict) -> str:
        return next(iter(e.values()))

    affected = False
    for event in sorted(events, key=lambda e: _tokens("0" if key(e) == "0" else key(e))):
        if "introduced" in event:
            if event["introduced"] == "0" or compare(version, event["introduced"]) >= 0:
                affected = True
        elif "fixed" in event:
            if compare(version, event["fixed"]) >= 0:
                affected = False
        elif "last_affected" in event:
            if compare(version, event["last_affected"]) > 0:
                affected = False
    return affected
