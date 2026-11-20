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
import re
from pathlib import Path
from typing import Optional

from . import config
from .versions import compare

# OSV ecosystem name -> PatchPilot ecosystem driver
ECOSYSTEMS = {"Maven": "maven", "PyPI": "pypi"}


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


def hints(adv: dict) -> dict:
    return adv.get("database_specific", {}).get("patchpilot", {})


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


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3}


def severity_rank(adv: dict) -> int:
    """0 for critical up to 3 for low; advisories without a severity go last."""
    return SEVERITY_ORDER.get(str(adv.get("database_specific", {}).get("severity", "")).upper(), 4)


def by_severity(advisories: list[dict]) -> list[dict]:
    """Most critical first; ties keep their feed order."""
    return sorted(advisories, key=severity_rank)


def title(adv: dict) -> str:
    aliases = [a for a in adv.get("aliases", []) if a.startswith("CVE-")]
    return aliases[0] if aliases else adv["id"]


def summary(adv: dict) -> str:
    return f"{title(adv)}: {adv.get('summary', '')}"
