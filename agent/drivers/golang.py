"""Go modules ecosystem driver.

Dependencies come from go.mod (direct and `// indirect`; with Syft, from the
binary's embedded build info instead). A fix runs `go get module@version`
when the Go toolchain is installed, which updates go.mod and go.sum exactly as
a developer would; without it, the require line is edited and go.sum gets the
two h1: lines from the checksum database (a build then fails closed if the new
release needs newer transitive modules).

Go has no separate binary: the module zip from the proxy IS the source, so the
"shipped without source" check is moot and the whole diff can be reviewed.
Releases are vetted from artifacts/go/<module>/<version>/source.zip, fetched
from the module proxy and verified against the checksum database by
agent/registry.py.

Versions are kept without the leading "v" (OSV's notation) and written back with it.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

from .. import config
from ..schemas import Component
from .base import DriverError, Sensitive

_REQUIRE_LINE = re.compile(r"^\s*(?:require\s+)?([^\s()]+)\s+(v[^\s]+)(\s*//.*)?$")


def _v(version: str) -> str:
    return version if version.startswith("v") else f"v{version}"


def gomods(repo: Path) -> list[Path]:
    return sorted(p for p in repo.rglob("go.mod")
                  if not ({"vendor", "testdata", ".git"} & set(p.relative_to(repo).parts)))


def parse_requires(text: str) -> list[tuple[str, str, bool]]:
    """(module, version without v, indirect) for every require in a go.mod."""
    out, block = [], False
    for raw in text.splitlines():
        line = raw.split("//")[0].rstrip() if "// indirect" not in raw else raw.rstrip()
        stripped = line.strip()
        if stripped.startswith("require ("):
            block = True
            continue
        if block and stripped == ")":
            block = False
            continue
        if block or stripped.startswith("require "):
            m = _REQUIRE_LINE.match(stripped if block else stripped)
            if m:
                out.append((m.group(1), m.group(2)[1:], "indirect" in (m.group(3) or "")))
    return out


class GoEcosystem:
    name = "go"
    language = "Go"
    # Plain `syscall` / `unsafe` imports are routine in systems and networking code:
    # shown, not escalated. Running programs and loading code are escalated.
    sensitive = [
        Sensitive("os/exec", r'"os/exec"|\bexec\s*\.\s*Command(Context)?\s*\(', "soft", "exec"),
        Sensitive("plugin loading", r'"plugin"|\bplugin\s*\.\s*Open\s*\(', "soft", "load"),
        Sensitive("process exec", r'\bsyscall\s*\.\s*(Exec|ForkExec|StartProcess)\b', "soft", "exec"),
        Sensitive("syscall/unsafe", r'"syscall"|"unsafe"', "info", ""),
        Sensitive("net dial", r'\bnet\s*\.\s*Dial(Timeout|TCP|UDP)?\s*\(|\bnet\s*\.\s*Listen\s*\(', "info", "network"),
        Sensitive("http client", r'\bhttp\s*\.\s*(Get|Post|PostForm|Head)\s*\(|\bhttp\.Client\b', "info", "network"),
        Sensitive("environment", r'\bos\s*\.\s*(Getenv|LookupEnv|Environ)\s*\(', "info", "env"),
    ]
    _INIT = re.compile(r"^\s*func\s+init\s*\(\s*\)")

    # ------------------------------------------------------------ repository

    def detect(self, repo: Path) -> bool:
        return bool(gomods(repo))

    def components(self, repo: Path) -> list[Component]:
        out, seen = [], set()
        for mod in gomods(repo):
            for module, version, _ in parse_requires(mod.read_text(encoding="utf-8")):
                if (module, version) in seen:
                    continue
                seen.add((module, version))
                out.append(Component(ecosystem="go", name=module, version=version,
                                     purl=f"pkg:golang/{module}@{_v(version)}", path=mod.relative_to(repo).as_posix()))
        return out

    def bump(self, repo: Path, comp: Component, version: str) -> list[str]:
        changed, done = [], False
        for mod in gomods(repo):
            have = {m: v for m, v, _ in parse_requires(mod.read_text(encoding="utf-8"))}
            if have.get(comp.name) == comp.version:
                changed += self._bump_one(repo, mod, comp.name, version)
                done = True
            elif have.get(comp.name) == version.removeprefix("v"):
                done = True                       # already raised by an earlier `go get` of this fix
        if not done:
            raise DriverError(f"{comp.name} {comp.version} is not required by any go.mod in {repo.name}")
        return sorted(set(changed))

    def lockstep(self, repo: Path, comp: Component, version: str) -> list[tuple[str, str]]:
        """What `go get module@version` will also move (minimal version selection),
        found by running it on a throwaway copy of go.mod and go.sum. Without the Go
        toolchain only the module itself moves (go.mod/go.sum are edited directly)."""
        if not shutil.which("go"):
            return []
        import tempfile
        moved: dict[str, str] = {}
        for mod in gomods(repo):
            before = {m: v for m, v, _ in parse_requires(mod.read_text(encoding="utf-8"))}
            if before.get(comp.name) != comp.version:
                continue
            with tempfile.TemporaryDirectory() as tmp:
                shutil.copy(mod, Path(tmp) / "go.mod")
                if (mod.parent / "go.sum").exists():
                    shutil.copy(mod.parent / "go.sum", Path(tmp) / "go.sum")
                env = {**os.environ, "GOFLAGS": "-mod=mod", "GOTOOLCHAIN": os.environ.get("GOTOOLCHAIN", "auto")}
                proc = subprocess.run(["go", "get", f"{comp.name}@{_v(version)}"], cwd=tmp, capture_output=True,
                                      text=True, env=env, timeout=900)
                if proc.returncode != 0:
                    raise DriverError(f"go get {comp.name}@{_v(version)} (dry run): {proc.stderr.strip()[-300:]}")
                after = parse_requires((Path(tmp) / "go.mod").read_text(encoding="utf-8"))
            for m, v, _ in after:
                if m != comp.name and before.get(m) != v:
                    moved[m] = v
        return sorted(moved.items())

    def _bump_one(self, repo: Path, mod: Path, module: str, version: str) -> list[str]:
        here = mod.parent
        rel = lambda name: (here / name).relative_to(repo).as_posix()  # noqa: E731
        if shutil.which("go"):
            env = {**os.environ, "GOFLAGS": "-mod=mod", "GOTOOLCHAIN": os.environ.get("GOTOOLCHAIN", "auto")}
            proc = subprocess.run(["go", "get", f"{module}@{_v(version)}"], cwd=here, capture_output=True,
                                  text=True, env=env, timeout=900)
            if proc.returncode != 0:
                raise DriverError(f"go get {module}@{_v(version)} failed: {proc.stderr.strip()[-400:]}")
            return [rel("go.mod"), rel("go.sum")]
        from ..registry import go_sums
        text = mod.read_text(encoding="utf-8")
        new = re.sub(rf"(^|\s){re.escape(module)}\s+v[^\s]+", lambda m: f"{m.group(1)}{module} {_v(version)}",
                     text, flags=re.M)
        mod.write_text(new, encoding="utf-8")
        zip_h1, mod_h1 = go_sums(module, version)
        gosum = here / "go.sum"
        lines = gosum.read_text(encoding="utf-8").splitlines() if gosum.exists() else []
        for entry in (f"{module} {_v(version)} {zip_h1}", f"{module} {_v(version)}/go.mod {mod_h1}"):
            if entry not in lines:
                lines.append(entry)
        gosum.write_text("\n".join(sorted(lines)) + "\n", encoding="utf-8")
        return [rel("go.mod"), rel("go.sum")]

    def grep_terms(self, comp: Component) -> list[str]:
        return [comp.name]

    # -------------------------------------------------------------- artifacts

    def artifacts(self, name: str, version: str) -> tuple[Path, Path]:
        """The module zip is both what ships and the source."""
        path = config.ARTIFACTS / "go" / name.replace("/", "_") / _v(version) / "source.zip"
        return path, path

    def sources(self, source_artifact: Path) -> dict[str, list[str]]:
        """Files keyed by their path in the module ("module@version/" prefix removed)."""
        out = {}
        with zipfile.ZipFile(source_artifact) as zf:
            for n in zf.namelist():
                rel = _in_module(n)
                # tests and testdata are never compiled into a program: nothing to vet there
                if (rel and (rel.endswith(".go") or rel.endswith("go.mod")) and "testdata/" not in rel
                        and not rel.endswith("_test.go")):
                    out[rel] = zf.read(n).decode("utf-8", "replace").splitlines()
        return out

    def shipped_without_source(self, shipped: Path, sources: dict[str, list[str]]) -> list[str]:
        return []

    def load_time_lines(self, path: str, added: list[str], new_lines: list[str]) -> list[str]:
        """Added `func init()` declarations: code that runs when the package is imported."""
        return [line.strip() for line in added if self._INIT.match(line)] if path.endswith(".go") else []

    def new_dependencies(self, old_shipped: Path, new_shipped: Path) -> list[str]:
        def requires(p: Path) -> set[str]:
            with zipfile.ZipFile(p) as zf:
                mod = next((n for n in zf.namelist() if _in_module(n) == "go.mod"), None)
                return {m for m, _, _ in parse_requires(zf.read(mod).decode("utf-8", "replace"))} if mod else set()
        return [f"dependency {d}" for d in sorted(requires(new_shipped) - requires(old_shipped))]


def _in_module(zip_name: str) -> str:
    """"golang.org/x/net@v0.60.0/http2/server.go" -> "http2/server.go" """
    if "@" not in zip_name:
        return ""
    rest = zip_name[zip_name.index("@"):]
    return rest.split("/", 1)[1] if "/" in rest else ""
