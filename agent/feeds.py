"""Feed piece: where advisories come from. Every piece writes OSV records into
feed/, which the watcher in agent/main.py already runs the pipeline on, so a
new source of advisories never touches the pipeline.

  feed:
    kind: files                  # only what is dropped into feed/ (the default; demo scenarios)

  feed:
    kind: osv                    # ask api.osv.dev about every package the fleet runs
    every_minutes: 60
    min_severity: medium         # skip advisories rated below this (none | low | medium | high | critical)
    api_url: https://api.osv.dev/v1   # or a company mirror

A custom piece is a class with `poll() -> list[dict]` returning OSV records.
"""
from __future__ import annotations

import json
import threading
from typing import Optional

import requests

from . import config, feed, fleet, overrides, settings

ECOSYSTEM_NAMES = {"maven": "Maven", "pypi": "PyPI", "go": "Go"}


class FilesFeed:
    kind = "files"

    def __init__(self, cfg: dict):
        self.every = 0

    def poll(self) -> list[dict]:
        return []

    def check(self) -> list[tuple[bool, str]]:
        return [(True, f"advisories are read from {config.FEED_DIR} (drop OSV JSON files there)")]


class OsvFeed:
    kind = "osv"

    def __init__(self, cfg: dict):
        self.api = (cfg.get("api_url") or "https://api.osv.dev/v1").rstrip("/")
        self.every = float(cfg.get("every_minutes", 60)) * 60
        self.min_severity = feed.SEVERITY.get(str(cfg.get("min_severity", "none")).lower(), 4)

    def packages(self) -> list[tuple[str, str, str]]:
        """(OSV ecosystem, package name, version) for everything the fleet runs."""
        from .pipeline import sbom
        fl = fleet.get()
        out = set()
        for wl in fl.discover(max_age=0):
            if not overrides.in_scope(wl):
                continue
            for c in sbom(fl, wl)[0]:
                if c.ecosystem in ECOSYSTEM_NAMES and overrides.package_in_scope(c):
                    out.add((ECOSYSTEM_NAMES[c.ecosystem], c.coordinate, c.version))
        return sorted(out)

    def poll(self) -> list[dict]:
        pkgs = self.packages()
        ids: set[str] = set()
        for start in range(0, len(pkgs), 500):
            chunk = pkgs[start:start + 500]
            r = requests.post(f"{self.api}/querybatch", timeout=60, json={"queries": [
                {"package": {"ecosystem": eco, "name": name}, "version": ver} for eco, name, ver in chunk]})
            r.raise_for_status()
            for res in r.json().get("results", []):
                ids.update(v["id"] for v in res.get("vulns", []))
        out = []
        for vid in sorted(ids):
            if (config.FEED_DIR / f"{vid}.json").exists():
                continue
            r = requests.get(f"{self.api}/vulns/{vid}", timeout=60)
            r.raise_for_status()
            adv = r.json()
            if feed.severity_rank(adv) <= self.min_severity:
                out.append(adv)
        return out

    def check(self) -> list[tuple[bool, str]]:
        return [(True, f"OSV checked every {self.every / 60:g} min at {self.api}")]


BUILTIN = {"files": FilesFeed, "osv": OsvFeed}

_piece = None


def get():
    global _piece
    if _piece is None:
        cfg = settings.section("feed", {}) or {}
        _piece = settings.load_class(cfg.get("kind", "files"), BUILTIN, "feed")(cfg)
    return _piece


def reset() -> None:
    global _piece
    _piece = None


def fetch_osv(advisory_id: str, api: str = "https://api.osv.dev/v1") -> dict:
    """One OSV record by its id or any alias (CVE-..., GHSA-...)."""
    cfg = settings.section("feed", {}) or {}
    api = (cfg.get("api_url") or api).rstrip("/")

    def get(vid: str) -> Optional[dict]:
        r = requests.get(f"{api}/vulns/{vid}", timeout=30)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    adv = get(advisory_id)
    if adv is None:
        raise LookupError(f"{advisory_id} is not in OSV")
    if feed.affected_packages(adv):
        return adv
    # a CVE record names no packages; the GitHub/PyPA record it aliases does
    for alias in adv.get("aliases", []) + adv.get("related", []):
        if alias.startswith(("GHSA-", "PYSEC-")):
            other = get(alias)
            if other and feed.affected_packages(other):
                return other
    raise LookupError(f"{advisory_id} names no Maven or PyPI package PatchPilot can match")


def publish(advisories: list[dict]) -> int:
    """Write new advisories into feed/; the watcher picks them up."""
    config.FEED_DIR.mkdir(parents=True, exist_ok=True)
    n = 0
    for adv in advisories:
        path = config.FEED_DIR / f"{adv['id']}.json"
        if not path.exists():
            path.write_text(json.dumps(adv, indent=1))
            n += 1
    return n


def run_poller(stop: threading.Event, piece: Optional[object] = None) -> None:
    piece = piece or get()
    every = float(getattr(piece, "every", 0) or 0)
    if every <= 0:
        return
    while not stop.is_set():
        try:
            n = publish(piece.poll())
            if n:
                print(f"[feed] {piece.kind}: {n} new advisories", flush=True)
        except Exception as exc:                          # keep polling whatever happens
            print(f"[feed] {getattr(piece, 'kind', piece)}: {type(exc).__name__}: {exc}", flush=True)
        stop.wait(every)
