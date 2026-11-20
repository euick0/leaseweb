"""Python / PyPI ecosystem driver.

What a repository pins, in order of precision:
  lock files   poetry.lock, uv.lock, Pipfile.lock: every installed package, transitive too
  requirements requirements*.txt (test/dev/doc/lint files skipped): `name==version`
  pyproject    [project] dependencies pinned with ==

A fix pins `name==version` where the package is declared (requirements, then
pyproject); a transitive package is pinned in requirements.txt. A lock file is
refreshed with its own tool (uv / poetry) when that tool is installed.

Vendored layout (the offline demo): requirements.txt plus the wheels in
`wheels/`, installed with `pip install --no-index --find-links wheels`.

Releases are vetted from artifacts/pypi/<name>/<version>/ (wheel = what ships,
sdist = the source), filled from PyPI or a mirror by agent/registry.py.
"""
from __future__ import annotations

import ast
import email.parser
import json
import re
import shutil
import subprocess
import tarfile
import tomllib
import zipfile
from pathlib import Path

from .. import config
from ..feed import normalise
from ..schemas import Component
from .base import DriverError, Sensitive

_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([^\s;#]+)")
_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(?:[<>=!~]=?[^;#]*)?")
_SOURCE_FILES = (".py", "pyproject.toml", "setup.cfg")
_SKIP_REQ = re.compile(r"(test|dev|doc|lint|ci)", re.I)


def requirement_files(repo: Path) -> list[Path]:
    """requirements*.txt at the root and in requirements/, runtime ones only."""
    files = list(repo.glob("requirements*.txt")) + list((repo / "requirements").glob("*.txt"))
    return sorted(p for p in files if not _SKIP_REQ.search(p.name))


class PypiEcosystem:
    name = "pypi"
    language = "Python"
    sensitive = [
        Sensitive("subprocess", r"\bsubprocess\b|\bos\s*\.\s*(system|popen|exec\w*|spawn\w*)\s*\(", "soft", "exec"),
        Sensitive("eval/exec", r"(?<![\w.])(eval|exec|compile)\s*\(|\b(marshal|pickle)\s*\.\s*loads?\s*\(", "soft", "load"),
        Sensitive("socket", r"\bsocket\s*\.\s*(socket|create_connection)\b|^\s*import\s+socket\b", "info", "network"),
        Sensitive("http client", r"\burllib\b|\bhttp\.client\b|\brequests\s*\.\s*(get|post|put)\b|\burlopen\s*\(", "info", "network"),
        Sensitive("os.environ", r"\bos\s*\.\s*(environ|getenv)\b", "info", "env"),
        Sensitive("dynamic import", r"\b__import__\s*\(|\bimportlib\b", "info", "load"),
    ]

    # ------------------------------------------------------------ repository

    def detect(self, repo: Path) -> bool:
        return bool(requirement_files(repo)) or any((repo / f).exists() for f in (
            "pyproject.toml", "poetry.lock", "uv.lock", "Pipfile.lock"))

    def components(self, repo: Path) -> list[Component]:
        """Lock file if there is one (it has the transitive packages too), else the pins."""
        locked = _lock_components(repo)
        if locked:
            return locked
        out, seen = [], set()

        def add(name: str, version: str, where: str):
            name = normalise("pypi", name)
            if (name, version) not in seen:
                seen.add((name, version))
                out.append(Component(ecosystem="pypi", name=name, version=version,
                                     purl=f"pkg:pypi/{name}@{version}", path=where))

        for req in requirement_files(repo):
            for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
                m = _PIN.match(line)
                if m:
                    add(m.group(1), m.group(2), req.relative_to(repo).as_posix())
        for dep in _pyproject_deps(repo):
            m = _PIN.match(dep)
            if m:
                add(m.group(1), m.group(2), "pyproject.toml")
        return out

    def bump(self, repo: Path, comp: Component, version: str) -> list[str]:
        """Pin the vetted version where the package is declared. Vendored: also swap the wheel."""
        if not (repo / "wheels").is_dir():
            return _pin(repo, comp.name, version)
        wheel, _ = self.artifacts(comp.name, version)
        wheels = repo / "wheels"
        wheels.mkdir(exist_ok=True)
        changed = []
        for old in wheels.glob("*.whl"):
            if normalise("pypi", old.name.split("-")[0]) == normalise("pypi", comp.name):
                old.unlink()
                changed.append(f"wheels/{old.name}")
        shutil.copy2(wheel, wheels / wheel.name)
        changed.append(f"wheels/{wheel.name}")
        req = repo / "requirements.txt"
        lines = []
        for line in req.read_text().splitlines():
            m = _PIN.match(line)
            if m and normalise("pypi", m.group(1)) == normalise("pypi", comp.name):
                line = f"{m.group(1)}=={version}"
            lines.append(line)
        req.write_text("\n".join(lines) + "\n")
        changed.append("requirements.txt")
        return changed

    def grep_terms(self, comp: Component) -> list[str]:
        return [comp.name.replace("-", "_")]

    # -------------------------------------------------------------- artifacts

    def artifacts(self, name: str, version: str) -> tuple[Path, Path]:
        """(wheel, sdist) in the store. Real releases keep their published file names;
        a pure-Python wheel is preferred over a platform one."""
        base = config.ARTIFACTS / "pypi" / normalise("pypi", name) / version
        stem = f"{normalise('pypi', name).replace('-', '_')}-{version}"
        wheel, sdist = base / f"{stem}-py3-none-any.whl", base / f"{stem}.tar.gz"
        if base.is_dir():
            if not wheel.exists():
                wheels = sorted(base.glob("*.whl"), key=lambda p: (not p.name.endswith("-none-any.whl"), p.name))
                wheel = wheels[0] if wheels else wheel
            if not sdist.exists():
                sdist = next(iter(sorted(base.glob("*.tar.gz"))), sdist)
        return wheel, sdist

    def sources(self, source_artifact: Path) -> dict[str, list[str]]:
        """Source files of an sdist, keyed by their path inside the installed package."""
        out = {}
        with tarfile.open(source_artifact) as tf:
            for member in tf.getmembers():
                if not member.isfile() or not member.name.endswith(_SOURCE_FILES):
                    continue
                rel = member.name.split("/", 1)[1] if "/" in member.name else member.name
                rel = rel.removeprefix("src/")
                data = tf.extractfile(member).read()          # read into memory, never to disk
                out[rel] = data.decode("utf-8", "replace").splitlines()
        return out

    def shipped_without_source(self, shipped: Path, sources: dict[str, list[str]]) -> list[str]:
        """Code in the wheel that is not in the sdist, or differs from it, plus .pth
        files (which run on every interpreter start)."""
        out = []
        with zipfile.ZipFile(shipped) as zf:
            for n in zf.namelist():
                if n.endswith(".pth"):
                    out.append(f"{n} (.pth file: runs at interpreter start)")
                elif n.endswith(".py"):
                    if n not in sources:
                        out.append(n)
                    elif zf.read(n).decode("utf-8", "replace").splitlines() != sources[n]:
                        out.append(f"{n} (differs from the sdist)")
        return sorted(out)

    def load_time_lines(self, path: str, added: list[str], new_lines: list[str]) -> list[str]:
        """Added lines of module-level code that runs on import (not def/class/import)."""
        if not path.endswith(".py"):
            return []
        try:
            tree = ast.parse("\n".join(new_lines))
        except SyntaxError:
            return []
        added_set = {a.strip() for a in added}
        out = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom)):
                continue
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                continue                                     # docstring
            if isinstance(node, ast.If) and "__main__" in ast.unparse(node.test):
                continue
            if not any(isinstance(n, ast.Call) for n in ast.walk(node)):
                continue                                     # plain constants
            for line in new_lines[node.lineno - 1:node.end_lineno]:
                if line.strip() and line.strip() in added_set:
                    out.append(line.strip())
        return out

    def new_dependencies(self, old_shipped: Path, new_shipped: Path) -> list[str]:
        return [f"dependency {d}" for d in sorted(_requires(new_shipped) - _requires(old_shipped))]


def _pyproject_deps(repo: Path) -> list[str]:
    path = repo / "pyproject.toml"
    if not path.exists():
        return []
    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError:
        return []
    return list((doc.get("project") or {}).get("dependencies") or [])


def _lock_components(repo: Path) -> list[Component]:
    """Every package a lock file installs (main/default groups only for Pipfile.lock)."""
    pkgs: list[tuple[str, str, str]] = []
    for name in ("poetry.lock", "uv.lock"):
        path = repo / name
        if path.exists():
            try:
                doc = tomllib.loads(path.read_text(encoding="utf-8"))
            except tomllib.TOMLDecodeError:
                continue
            for p in doc.get("package") or []:
                src = p.get("source") or {}
                if p.get("name") and p.get("version") and not (src.get("editable") or src.get("virtual")):
                    pkgs.append((p["name"], p["version"], name))
            break
    else:
        path = repo / "Pipfile.lock"
        if path.exists():
            for n, info in (json.loads(path.read_text(encoding="utf-8")).get("default") or {}).items():
                v = str(info.get("version", "")).removeprefix("==")
                if v:
                    pkgs.append((n, v, "Pipfile.lock"))
    out, seen = [], set()
    for n, v, where in pkgs:
        n = normalise("pypi", n)
        if (n, v) not in seen:
            seen.add((n, v))
            out.append(Component(ecosystem="pypi", name=n, version=v, purl=f"pkg:pypi/{n}@{v}", path=where))
    return out


def _pin(repo: Path, name: str, version: str) -> list[str]:
    """`name==version` wherever name is declared; a transitive package is added to
    requirements.txt. Lock files are refreshed with their own tool."""
    key = normalise("pypi", name)
    changed: list[str] = []
    for req in requirement_files(repo):
        lines, hit = [], False
        for line in req.read_text(encoding="utf-8").splitlines():
            code, hash_, comment = line.partition("#")
            m = _REQ.match(code)
            if m and code.strip() and not code.lstrip().startswith("-") and normalise("pypi", m.group(1)) == key:
                marker = code[code.index(";"):].rstrip() if ";" in code else ""     # environment marker
                line = f"{m.group(1)}{m.group(2) or ''}=={version}{marker}" + (f"  #{comment}" if hash_ else "")
                hit = True
            lines.append(line)
        if hit:
            req.write_text("\n".join(lines) + "\n", encoding="utf-8")
            changed.append(req.relative_to(repo).as_posix())

    pyproject = repo / "pyproject.toml"
    if pyproject.exists():
        text = pyproject.read_text(encoding="utf-8")
        deps = _pyproject_deps(repo)
        new = text
        for dep in deps:
            m = _REQ.match(dep)
            if m and normalise("pypi", m.group(1)) == key:
                marker = dep[dep.index(";"):] if ";" in dep else ""
                new = new.replace(f'"{dep}"', f'"{m.group(1)}{m.group(2) or ""}=={version}{marker}"')
        if new != text:
            pyproject.write_text(new, encoding="utf-8")
            changed.append("pyproject.toml")

    if not changed:
        req = repo / "requirements.txt"
        if req.exists():
            text = req.read_text(encoding="utf-8")
            req.write_text(text.rstrip("\n") + f"\n{name}=={version}  # LightHouse: pinned to the vetted fix\n",
                           encoding="utf-8")
            changed.append("requirements.txt")
        elif not (repo / "uv.lock").exists() and not (repo / "poetry.lock").exists():
            raise DriverError(f"{name} is not declared anywhere LightHouse can pin it (no requirements.txt)")

    changed += _relock(repo, name, version)
    return changed


def _relock(repo: Path, name: str, version: str) -> list[str]:
    """Bring a lock file to the pinned version with the project's own tool."""
    if (repo / "uv.lock").exists():
        cmd = ["uv", "lock", "--upgrade-package", f"{name}=={version}"]
        lock = "uv.lock"
    elif (repo / "poetry.lock").exists():
        cmd = ["poetry", "update", "--lock", name]
        lock = "poetry.lock"
    else:
        return []
    if not shutil.which(cmd[0]):
        raise DriverError(f"{lock} must be refreshed with {cmd[0]}, which is not installed here")
    proc = subprocess.run(cmd, cwd=repo, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        raise DriverError(f"{' '.join(cmd)} failed: {proc.stderr.strip()[-400:]}")
    return [lock]


def _requires(wheel: Path) -> set[str]:
    with zipfile.ZipFile(wheel) as zf:
        for n in zf.namelist():
            if n.endswith(".dist-info/METADATA"):
                meta = email.parser.Parser().parsestr(zf.read(n).decode("utf-8", "replace"))
                return {re.split(r"[\s;<>=!~(\[]", r, maxsplit=1)[0] for r in meta.get_all("Requires-Dist") or []}
    return set()
