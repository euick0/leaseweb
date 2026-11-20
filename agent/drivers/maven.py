"""Java / Maven ecosystem driver. Two repository layouts:

  pom.xml   a normal Maven build (single or multi-module). Dependencies are read
            from the poms; a fix edits the version where it is defined (see pom.py)
            and the Dockerfile's `mvn package` fetches the vetted release.
  vendored  `vendor.txt` pins `group:artifact version` and `lib/` holds the jars,
            compiled with plain javac (offline, pre-vendored services).

Releases are vetted from artifacts/maven/<artifact>/<version>/ (binary +
sources jar), filled from Maven Central or a mirror by agent/registry.py.
"""
from __future__ import annotations

import re
import shutil
import zipfile
from pathlib import Path

from .. import config
from ..schemas import Component
from . import pom
from .base import Sensitive


class MavenEcosystem:
    name = "maven"
    language = "Java"
    sensitive = [
        Sensitive("Runtime.exec", r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\b|\.exec\s*\(", "soft", "exec"),
        Sensitive("ProcessBuilder", r"\bProcessBuilder\b", "soft", "exec"),
        Sensitive("defineClass", r"\bdefineClass\s*\(", "soft", "load"),
        Sensitive("Socket", r"\bnew\s+(Server)?Socket\s*\(|\bSocketChannel\b", "info", "network"),
        Sensitive("URLConnection", r"\b(Http)?URLConnection\b|\.openConnection\s*\(|\.openStream\s*\(", "info", "network"),
        Sensitive("URLClassLoader", r"\bURLClassLoader\b", "info", "load"),
        Sensitive("System.getenv", r"\bSystem\s*\.\s*getenv\b", "info", "env"),
        Sensitive("file read", r"\bnew\s+FileInputStream\s*\(|\bFiles\s*\.\s*(readAllBytes|readString|newInputStream)\b", "info", ""),
    ]
    _STATIC_INIT = re.compile(r"^\s*static\s*\{")

    # ------------------------------------------------------------ repository

    def detect(self, repo: Path) -> bool:
        return self._vendored(repo) or (repo / "pom.xml").exists()

    @staticmethod
    def _vendored(repo: Path) -> bool:
        return (repo / "vendor.txt").exists() or any((repo / "lib").glob("*.jar"))

    def components(self, repo: Path) -> list[Component]:
        if self._vendored(repo):
            return [read_jar(j) for j in sorted((repo / "lib").glob("*.jar"))]
        return pom.components(repo)

    def bump(self, repo: Path, comp: Component, version: str) -> list[str]:
        """pom.xml: change the version where it is defined. Vendored: swap the jar and the pin."""
        if not self._vendored(repo):
            if not comp.group:
                raise ValueError(f"{comp.name}: no groupId, cannot find it in pom.xml")
            return pom.bump(repo, comp.group, comp.name, version, current=comp.version)
        new_jar, _ = self.artifacts(comp.name, version)
        lib = repo / "lib"
        changed = []
        for old in lib.glob(f"{comp.name}-*.jar"):
            if read_jar(old).name == comp.name:
                old.unlink()
                changed.append(f"lib/{old.name}")
        shutil.copy2(new_jar, lib / new_jar.name)
        changed.append(f"lib/{new_jar.name}")
        pins = repo / "vendor.txt"
        if pins.exists():
            lines = pins.read_text().splitlines()
            coord = comp.coordinate
            lines = [f"{coord} {version}" if l.split()[:1] == [coord] else l for l in lines]
            pins.write_text("\n".join(lines) + "\n")
            changed.append("vendor.txt")
        return changed

    def lockstep(self, repo: Path, comp: Component, version: str) -> list[tuple[str, str]]:
        """(coordinate, version) of the artifacts released together with comp: they share
        its version property, so they move to the same version and are vetted too."""
        if self._vendored(repo) or not comp.group:
            return []
        return sorted((f"{g}:{a}", version) for g, a in pom.lockstep(repo, comp.group, comp.name))

    def grep_terms(self, comp: Component) -> list[str]:
        return [comp.group] if comp.group else [comp.name]

    # -------------------------------------------------------------- artifacts

    def artifacts(self, name: str, version: str) -> tuple[Path, Path]:
        base = config.ARTIFACTS / "maven" / name / version
        return base / f"{name}-{version}.jar", base / f"{name}-{version}-sources.jar"

    def sources(self, source_artifact: Path) -> dict[str, list[str]]:
        with zipfile.ZipFile(source_artifact) as zf:
            return {n: zf.read(n).decode("utf-8", "replace").splitlines()
                    for n in zf.namelist() if n.endswith(".java")}

    def shipped_without_source(self, shipped: Path, sources: dict[str, list[str]]) -> list[str]:
        """Classes in the binary jar with no matching source file (how the xz backdoor hid)."""
        with zipfile.ZipFile(shipped) as zf:
            classes = [n for n in zf.namelist() if n.endswith(".class")]
        return sorted(c for c in classes
                      if not c.endswith("module-info.class") and _source_for(c) not in sources)

    def load_time_lines(self, path: str, added: list[str], new_lines: list[str]) -> list[str]:
        """Added lines that open a static initialiser: code that runs when the class loads."""
        return [l.strip() for l in added if self._STATIC_INIT.match(_strip_comment(l))]

    def new_dependencies(self, old_shipped: Path, new_shipped: Path) -> list[str]:
        out = [f"bundled jar {j}" for j in sorted(_nested_jars(new_shipped) - _nested_jars(old_shipped))]
        out += [f"dependency {d}" for d in sorted(_pom_deps(new_shipped) - _pom_deps(old_shipped))]
        return out


def read_jar(jar: Path) -> Component:
    """Identify a jar from its embedded pom.properties, falling back to the filename."""
    with zipfile.ZipFile(jar) as zf:
        for name in zf.namelist():
            if name.startswith("META-INF/maven/") and name.endswith("/pom.properties"):
                props = dict(line.split("=", 1) for line in zf.read(name).decode().splitlines()
                             if "=" in line and not line.startswith("#"))
                g, a, v = props.get("groupId"), props.get("artifactId"), props.get("version")
                if a and v:
                    return Component(ecosystem="maven", group=g, name=a, version=v,
                                     purl=f"pkg:maven/{g}/{a}@{v}", path=str(jar))
    name, _, version = jar.stem.rpartition("-")
    return Component(ecosystem="maven", name=name or jar.stem, version=version or "unknown", path=str(jar))


def _source_for(cls: str) -> str:
    """org/x/Foo$Inner.class (or META-INF/versions/9/org/x/Foo.class) -> org/x/Foo.java"""
    path = re.sub(r"^META-INF/versions/\d+/", "", cls)
    return path.removesuffix(".class").split("$")[0] + ".java"


def _strip_comment(line: str) -> str:
    return "" if line.strip().startswith(("//", "*", "/*")) else line


def _nested_jars(jar: Path) -> set[str]:
    with zipfile.ZipFile(jar) as zf:
        return {n for n in zf.namelist() if n.endswith(".jar")}


def _pom_deps(jar: Path) -> set[str]:
    with zipfile.ZipFile(jar) as zf:
        for n in zf.namelist():
            if n.startswith("META-INF/maven/") and n.endswith("/pom.xml"):
                pom = zf.read(n).decode("utf-8", "replace")
                pom = re.sub(r"<dependencyManagement>.*?</dependencyManagement>", "", pom, flags=re.S)
                out = set()
                for block in re.findall(r"<dependency>(.*?)</dependency>", pom, flags=re.S):
                    if re.search(r"<scope>\s*(test|provided)\s*</scope>", block):
                        continue
                    g = re.search(r"<groupId>([^<]+)</groupId>", block)
                    a = re.search(r"<artifactId>([^<]+)</artifactId>", block)
                    if g and a:
                        out.add(f"{g.group(1).strip()}:{a.group(1).strip()}")
                return out
    return set()
