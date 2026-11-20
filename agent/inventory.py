"""Inventory: the SBOM of what is actually running. Syft reads the image (one
tool for every ecosystem). If Syft or the image is unavailable, the ecosystem
drivers read the pins of the workload's repository, whose main branch always
mirrors what is deployed."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from .drivers.base import Ecosystem
from .feed import normalise
from .schemas import Component

SYFT_TYPES = {"java-archive": "maven", "jenkins-plugin": "maven", "python": "pypi", "go-module": "go"}


def parse_syft(doc: dict) -> list[Component]:
    comps = []
    for art in doc.get("artifacts", []):
        eco = SYFT_TYPES.get(art.get("type"))
        if not eco:
            continue
        purl = art.get("purl") or ""
        group = None
        if purl.startswith("pkg:maven/"):
            group = purl[len("pkg:maven/"):].split("/")[0]
        version = art.get("version") or ""
        if eco == "go":
            if not version.startswith("v") or art["name"] == "stdlib":
                continue                      # the main module "(devel)" and the Go toolchain itself
            version = version[1:]             # OSV writes Go versions without the "v"
        locs = art.get("locations") or [{}]
        comps.append(Component(ecosystem=eco, group=group, name=normalise(eco, art["name"]),
                               version=version, purl=purl or None, path=locs[0].get("path")))
    return _dedupe(comps)


def _syft(ref: str) -> list[Component]:
    out = subprocess.run(["syft", ref, "-o", "json", "-q"], capture_output=True,
                         text=True, timeout=300, check=True).stdout
    return parse_syft(json.loads(out))


def scan(image_refs: list[str], repo: Optional[Path], ecosystems: list[Ecosystem]) -> tuple[list[Component], str]:
    """Returns (components, how) where `how` names the SBOM source."""
    if shutil.which("syft"):
        for ref in image_refs:
            try:
                comps = _syft(ref)
                if comps:
                    return comps, f"syft {ref}"
            except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
                continue
    if repo and repo.exists():
        comps = [c for eco in ecosystems if eco.detect(repo) for c in eco.components(repo)]
        return _dedupe(comps), f"pins in {repo.name} (syft unavailable)"
    return [], "no SBOM source available"


def _dedupe(comps: list[Component]) -> list[Component]:
    seen, out = set(), []
    for c in comps:
        key = (c.ecosystem, c.group, c.name, c.version)
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out
