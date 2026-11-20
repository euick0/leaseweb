"""Python / PyPI ecosystem driver.

A Python repository pins `name==version` in requirements.txt and vendors the
matching wheels in `wheels/`; the Dockerfile installs with
`pip install --no-index --find-links wheels`. The upstream is
artifacts/pypi/<name>/<version>/ (wheel = what ships, sdist = the source).
"""
from __future__ import annotations

import ast
import email.parser
import re
import shutil
import tarfile
import zipfile
from pathlib import Path

from .. import config
from ..feed import normalise
from ..schemas import Component
from .base import Sensitive

_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([^\s;#]+)")
_SOURCE_FILES = (".py", "pyproject.toml", "setup.cfg")


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
        return (repo / "requirements.txt").exists()

    def components(self, repo: Path) -> list[Component]:
        out = []
        for line in (repo / "requirements.txt").read_text().splitlines():
            m = _PIN.match(line)
            if m:
                name, version = normalise("pypi", m.group(1)), m.group(2)
                out.append(Component(ecosystem="pypi", name=name, version=version,
                                     purl=f"pkg:pypi/{name}@{version}", path="requirements.txt"))
        return out

    def bump(self, repo: Path, comp: Component, version: str) -> list[str]:
        """Swap the vendored wheel for the vetted one and update the pin."""
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
        base = config.ARTIFACTS / "pypi" / normalise("pypi", name) / version
        stem = f"{normalise('pypi', name).replace('-', '_')}-{version}"
        return base / f"{stem}-py3-none-any.whl", base / f"{stem}.tar.gz"

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


def _requires(wheel: Path) -> set[str]:
    with zipfile.ZipFile(wheel) as zf:
        for n in zf.namelist():
            if n.endswith(".dist-info/METADATA"):
                meta = email.parser.Parser().parsestr(zf.read(n).decode("utf-8", "replace"))
                return {re.split(r"[\s;<>=!~(\[]", r, maxsplit=1)[0] for r in meta.get_all("Requires-Dist") or []}
    return set()
