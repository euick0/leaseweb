"""Fetch real releases into the artifact store, verified against what the
registry publishes, before anything is vetted or built.

  Maven  {maven_url}/g/r/o/u/p/artifact/version/artifact-version(.jar|-sources.jar)
         verified with the .sha256 (or .sha1) file next to it
  PyPI   {pypi_url}/pypi/name/version/json -> a wheel (what ships) and the sdist
         (the source), verified with the sha256 digests in that JSON
  Go     {go_proxy}/module/@v/version.zip, verified with the h1: hash from the
         checksum database (sum.golang.org), the same check `go` itself does

A verified download is recorded in checksums.lock, so the vetter's
fail-closed checksum check covers it from then on, and a later download that
differs is caught. Mirrors (Nexus, Artifactory, devpi, Athens) are set in
lighthouse.yaml:

  registries:
    maven: https://nexus.example.com/repository/maven-public
    pypi: https://pypi.org
    go_proxy: https://proxy.golang.org
    go_sumdb: https://sum.golang.org
    headers: {Authorization: "Bearer ${REGISTRY_TOKEN}"}     # optional, sent to all of them
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import threading
import zipfile
from pathlib import Path
from typing import Optional

import requests

from . import config, settings
from .feed import normalise
from .schemas import Component

DEFAULTS = {"maven": "https://repo1.maven.org/maven2", "pypi": "https://pypi.org",
            "go_proxy": "https://proxy.golang.org", "go_sumdb": "https://sum.golang.org"}
_lock = threading.Lock()


class FetchError(RuntimeError):
    pass


def _cfg() -> dict:
    return {**DEFAULTS, **(settings.section("registries", {}) or {})}


def _get(url: str) -> requests.Response:
    try:
        r = requests.get(url, headers=_cfg().get("headers") or {}, timeout=120)
    except requests.RequestException as exc:
        raise FetchError(f"{url}: {exc}") from exc
    return r


def _download(url: str) -> bytes:
    r = _get(url)
    if r.status_code != 200:
        raise FetchError(f"{url}: HTTP {r.status_code}")
    return r.content


def _record(paths_and_data: list[tuple[Path, bytes]]) -> None:
    """Write verified files and add their SHA-256 to checksums.lock."""
    with _lock:
        sums = json.loads(config.CHECKSUMS.read_text()) if config.CHECKSUMS.exists() else {}
        for path, data in paths_and_data:
            key = path.relative_to(config.ARTIFACTS).as_posix()
            digest = hashlib.sha256(data).hexdigest()
            if key in sums and sums[key] != digest:
                raise FetchError(f"{key}: the registry now serves different bytes than when first recorded")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            sums[key] = digest
        config.CHECKSUMS.write_text(json.dumps(dict(sorted(sums.items())), indent=2) + "\n")


def fetch(comp: Component, version: str) -> list[str]:
    """Make sure `comp` at `version` is in the artifact store; returns what was downloaded."""
    if comp.ecosystem == "maven":
        return _maven(comp, version)
    if comp.ecosystem == "pypi":
        return _pypi(comp.name, version)
    if comp.ecosystem == "go":
        return _go(comp.name, version)
    return []


# ------------------------------------------------------------------- maven

def _maven(comp: Component, version: str) -> list[str]:
    from .drivers.maven import MavenEcosystem
    jar, src = MavenEcosystem().artifacts(comp.name, version)
    if jar.exists() and src.exists():
        return []
    if not comp.group:
        raise FetchError(f"{comp.name}: no groupId, cannot locate it in a Maven repository")
    base = f"{_cfg()['maven'].rstrip('/')}/{comp.group.replace('.', '/')}/{comp.name}/{version}"
    out = []
    for path, name in ((jar, f"{comp.name}-{version}.jar"), (src, f"{comp.name}-{version}-sources.jar")):
        if path.exists():
            continue
        data = _download(f"{base}/{name}")
        for algo in ("sha256", "sha1"):
            r = _get(f"{base}/{name}.{algo}")
            if r.status_code == 200:
                want = r.text.strip().split()[0].lower()
                got = hashlib.new(algo, data).hexdigest()
                if got != want:
                    raise FetchError(f"{name}: {algo} {got} does not match the published {want}")
                break
        else:
            raise FetchError(f"{name}: the repository publishes no checksum")
        out.append((path, data))
    _record(out)
    return [p.name for p, _ in out]


# -------------------------------------------------------------------- pypi

def _pick_wheel(files: list[dict]) -> Optional[dict]:
    wheels = [f for f in files if f.get("packagetype") == "bdist_wheel" and not f.get("yanked")]

    def rank(f):
        n = f["filename"]
        if n.endswith("-none-any.whl"):
            return 0
        if "manylinux" in n and "x86_64" in n:
            return 1
        return 2
    return min(wheels, key=rank) if wheels else None


def _pypi(name: str, version: str) -> list[str]:
    from .drivers.pypi import PypiEcosystem
    wheel, sdist = PypiEcosystem().artifacts(name, version)
    if wheel.exists() and sdist.exists():
        return []
    r = _get(f"{_cfg()['pypi'].rstrip('/')}/pypi/{name}/{version}/json")
    if r.status_code != 200:
        raise FetchError(f"{name} {version} is not on the package index (HTTP {r.status_code})")
    files = r.json().get("urls") or []
    chosen = [_pick_wheel(files), next((f for f in files if f.get("packagetype") == "sdist"), None)]
    if not chosen[1]:
        raise FetchError(f"{name} {version} publishes no source distribution: its wheel cannot be checked "
                         f"against its source")
    out = []
    base = wheel.parent
    for f in chosen:
        if f is None or (base / f["filename"]).exists():
            continue
        data = _download(f["url"])
        want = (f.get("digests") or {}).get("sha256")
        if not want or hashlib.sha256(data).hexdigest() != want:
            raise FetchError(f"{f['filename']}: SHA-256 does not match the index")
        out.append((base / f["filename"], data))
    _record(out)
    return [p.name for p, _ in out]


# ---------------------------------------------------------------------- go

def go_escape(module: str) -> str:
    """Module path as the proxy and checksum database spell it (uppercase -> !lower)."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), module)


def go_h1(files: dict[str, bytes]) -> str:
    """dirhash.Hash1, the h1: hash in go.sum: SHA-256 over the sorted list of
    "<sha256 hex>  <name>" lines of every file."""
    summary = "".join(f"{hashlib.sha256(files[n]).hexdigest()}  {n}\n" for n in sorted(files))
    return "h1:" + base64.b64encode(hashlib.sha256(summary.encode()).digest()).decode()


def go_zip_h1(data: bytes) -> str:
    import io
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return go_h1({n: zf.read(n) for n in zf.namelist() if not n.endswith("/")})


def go_sums(module: str, version: str) -> tuple[str, str]:
    """(h1 of the module zip, h1 of its go.mod) from the checksum database."""
    v = version if version.startswith("v") else f"v{version}"
    r = _get(f"{_cfg()['go_sumdb'].rstrip('/')}/lookup/{go_escape(module)}@{v}")
    if r.status_code != 200:
        raise FetchError(f"{module}@{v} is not in the checksum database (HTTP {r.status_code})")
    zip_h1 = mod_h1 = None
    for line in r.text.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == module and parts[1] == v:
            zip_h1 = parts[2]
        elif len(parts) == 3 and parts[0] == module and parts[1] == f"{v}/go.mod":
            mod_h1 = parts[2]
    if not zip_h1 or not mod_h1:
        raise FetchError(f"{module}@{v}: the checksum database answer has no h1 lines")
    return zip_h1, mod_h1


def _go(module: str, version: str) -> list[str]:
    from .drivers.golang import GoEcosystem
    path, _ = GoEcosystem().artifacts(module, version)
    if path.exists():
        return []
    v = version if version.startswith("v") else f"v{version}"
    data = _download(f"{_cfg()['go_proxy'].rstrip('/')}/{go_escape(module)}/@v/{v}.zip")
    want, _ = go_sums(module, v)
    got = go_zip_h1(data)
    if got != want:
        raise FetchError(f"{module}@{v}: zip hash {got} does not match the checksum database ({want})")
    _record([(path, data)])
    return [path.name]
