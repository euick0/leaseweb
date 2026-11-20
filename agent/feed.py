"""Mock advisory feed. Files in feed/*.json are OSV records, so a live OSV
query can replace this later without touching the parser.

PatchPilot-specific hints live in `database_specific.patchpilot`, which OSV
reserves for the publishing database:
  grep            - strings to search for in a repository's source (triage input)
  probe           - name of the safe exploit probe that proves the result
  bump_together   - packages released in lockstep that must move with the fix
  target_version  - version to deploy when the advisory lists several fixes
  review_focus    - files the diff review should look at first
"""
from __future__ import annotations

import functools
import json
import math
import re
from pathlib import Path
from typing import Optional

from . import config
from .versions import compare

# OSV ecosystem name -> PatchPilot ecosystem driver
ECOSYSTEMS = {"Maven": "maven", "PyPI": "pypi", "Go": "go"}


def normalise(ecosystem: str, name: str) -> str:
    """Package names as the ecosystem compares them (PEP 503 for PyPI)."""
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


def load(path: Path) -> dict:
    adv = json.loads(path.read_text())
    if "id" not in adv or "affected" not in adv:
        raise ValueError(f"{path.name} is not an OSV record")
    return adv


def list_feed() -> list[dict]:
    out = []
    for path in sorted(config.FEED_DIR.glob("*.json")):
        try:
            out.append(load(path))
        except (ValueError, json.JSONDecodeError):
            continue
    return out


def _database_specific(adv: dict) -> dict:
    return adv.get("database_specific") or {}


def hints(adv: dict) -> dict:
    return _database_specific(adv).get("patchpilot") or {}


def affected_packages(adv: dict) -> list[tuple[str, str, dict]]:
    """(ecosystem driver, normalised name, affected entry) for each supported package."""
    out = []
    for aff in adv["affected"]:
        eco = ECOSYSTEMS.get(aff["package"].get("ecosystem", ""))
        if eco:
            out.append((eco, normalise(eco, aff["package"]["name"]), aff))
    return out


def fixed_versions(adv: dict, ecosystem: str, name: str) -> list[str]:
    out = []
    for eco, pkg, aff in affected_packages(adv):
        if eco != ecosystem or pkg != normalise(ecosystem, name):
            continue
        for rng in aff.get("ranges", []):
            out += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return out


def target_version(adv: dict, ecosystem: str, name: str) -> Optional[str]:
    """The version to deploy: the advisory's explicit target, else the highest fix."""
    explicit = hints(adv).get("target_version")
    if explicit:
        return explicit
    fixes = fixed_versions(adv, ecosystem, name)
    return max(fixes, key=functools.cmp_to_key(compare)) if fixes else None


# the one severity scale, for advisories and for workloads (TriageResult)
SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
_ALIASES = {"moderate": "medium", "important": "high", "negligible": "low"}

_CVSS3 = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
          "UI": {"N": 0.85, "R": 0.62}, "CIA": {"H": 0.56, "L": 0.22, "N": 0.0}}


def _roundup(x: float) -> float:
    """CVSS 3.1 Roundup: the smallest one-decimal number >= x."""
    i = round(x * 100000)
    return i / 100000 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10


def cvss3_score(vector: str) -> Optional[float]:
    """Base score of a CVSS:3.x vector, or None if it is not one."""
    parts = vector.split("/")
    if not parts[0].startswith("CVSS:3"):
        return None
    m = dict(p.split(":", 1) for p in parts[1:] if ":" in p)
    try:
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - math.prod(1 - _CVSS3["CIA"][m[k]] for k in ("C", "I", "A"))
        expl = 8.22 * _CVSS3["AV"][m["AV"]] * _CVSS3["AC"][m["AC"]] * pr * _CVSS3["UI"][m["UI"]]
    except KeyError:
        return None
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    return _roundup(min((1.08 if changed else 1) * (impact + expl), 10))


def _rating(score: float) -> str:
    return ("none" if score == 0 else "low" if score < 4 else "medium" if score < 7
            else "high" if score < 9 else "critical")


def _level(text) -> Optional[str]:
    level = _ALIASES.get(str(text).strip().lower(), str(text).strip().lower())
    return level if level in SEVERITY else None


def advisory_severity(adv: dict) -> Optional[str]:
    """critical | high | medium | low | none, or None if the advisory gives none.
    The database's own rating (GitHub style) wins; otherwise the worst of the
    OSV `severity` entries (CVSS 3 vectors, or a plain rating such as Ubuntu's)."""
    explicit = _level(_database_specific(adv).get("severity", ""))
    if explicit:
        return explicit
    levels = []
    for entry in adv.get("severity") or []:
        score = str((entry or {}).get("score", ""))
        cvss = cvss3_score(score)
        level = _rating(cvss) if cvss is not None else _level(score)
        if level:
            levels.append(level)
    return min(levels, key=SEVERITY.get) if levels else None


def severity_rank(adv: dict) -> int:
    """0 for critical up to 4 for none; advisories without a severity go last."""
    return SEVERITY[advisory_severity(adv) or "none"]


def by_severity(advisories: list[dict]) -> list[dict]:
    """Most critical first; ties keep their feed order."""
    return sorted(advisories, key=severity_rank)


def title(adv: dict) -> str:
    aliases = [a for a in adv.get("aliases", []) if a.startswith("CVE-")]
    return aliases[0] if aliases else adv["id"]


def summary(adv: dict) -> str:
    return f"{title(adv)}: {adv.get('summary', '')}"
