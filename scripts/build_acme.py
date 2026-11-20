#!/usr/bin/env python3
"""Build every acme demo library version into artifacts/pypi/ as a wheel (what
ships) and an sdist (the source), then record checksums.

Pure standard library and byte-for-byte reproducible (fixed timestamps), so the
recorded checksums survive a rebuild and no build backend or network is needed.
"""
import base64
import gzip
import hashlib
import io
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIBS = ROOT / "acme-libs"
OUT = ROOT / "artifacts" / "pypi"
ZIP_DATE = (2026, 1, 1, 0, 0, 0)
TAR_MTIME = 1767225600            # 2026-01-01T00:00:00Z


def metadata(project: dict) -> str:
    lines = ["Metadata-Version: 2.1", f"Name: {project['name']}", f"Version: {project['version']}",
             f"Summary: {project.get('description', '')}"]
    if "requires-python" in project:
        lines.append(f"Requires-Python: {project['requires-python']}")
    lines += [f"Requires-Dist: {d}" for d in project.get("dependencies", [])]
    return "\n".join(lines) + "\n"


def record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def build_wheel(src: Path, project: dict, dist: str, out: Path) -> None:
    files: dict[str, bytes] = {}
    for f in sorted((src / "src").rglob("*.py")):
        files[f.relative_to(src / "src").as_posix()] = f.read_bytes()
    info = f"{dist}-{project['version']}.dist-info"
    files[f"{info}/METADATA"] = metadata(project).encode()
    files[f"{info}/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: patchpilot-build-acme\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    top = sorted({n.split("/")[0] for n in files if not n.startswith(info)})
    files[f"{info}/top_level.txt"] = ("\n".join(top) + "\n").encode()
    record = "".join(f"{n},{record_hash(d)},{len(d)}\n" for n, d in files.items()) + f"{info}/RECORD,,\n"
    files[f"{info}/RECORD"] = record.encode()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zi = zipfile.ZipInfo(name, ZIP_DATE)
            zi.external_attr = 0o644 << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zi, data)


def build_sdist(src: Path, project: dict, dist: str, out: Path) -> None:
    root = f"{dist}-{project['version']}"
    files = {f"{root}/PKG-INFO": metadata(project).encode(),
             f"{root}/pyproject.toml": (src / "pyproject.toml").read_bytes()}
    for f in sorted((src / "src").rglob("*.py")):
        files[f"{root}/src/{f.relative_to(src / 'src').as_posix()}"] = f.read_bytes()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode = len(data), TAR_MTIME, 0o644
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            tf.addfile(ti, io.BytesIO(data))
    with open(out, "wb") as fh, gzip.GzipFile(fileobj=fh, mode="wb", mtime=TAR_MTIME, filename="") as gz:
        gz.write(raw.getvalue())


def main() -> None:
    for pyproject in sorted(LIBS.glob("*/*/pyproject.toml")):
        src = pyproject.parent
        project = tomllib.loads(pyproject.read_text())["project"]
        dist = project["name"].replace("-", "_")
        out = OUT / project["name"] / project["version"]
        wheel = out / f"{dist}-{project['version']}-py3-none-any.whl"
        sdist = out / f"{dist}-{project['version']}.tar.gz"
        if wheel.exists() and sdist.exists():
            continue
        out.mkdir(parents=True, exist_ok=True)
        build_wheel(src, project, dist, wheel)
        build_sdist(src, project, dist, sdist)
        print(f"  built {project['name']} {project['version']}")
    subprocess.run([sys.executable, str(ROOT / "scripts" / "record_checksums.py")], check=True)


if __name__ == "__main__":
    main()
