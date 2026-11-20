"""The fleet: sources, targets and ecosystems from fleet.yaml, and discovery of
every workload across all targets. No per-repository setup is needed to be
discovered: an image's OCI source label (or its app name) links it to a source.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Optional

import yaml

from . import config, settings
from .builder import SOURCE_LABEL, Builder
from .drivers import forge
from .drivers.base import Ecosystem, Source, Target
from .drivers.golang import GoEcosystem
from .drivers.maven import MavenEcosystem
from .drivers.pypi import PypiEcosystem
from .schemas import Workload

ECOSYSTEMS: dict[str, Ecosystem] = {"maven": MavenEcosystem(), "pypi": PypiEcosystem(), "go": GoEcosystem()}


def register_ecosystems(specs: list) -> None:
    """Custom ecosystem pieces from fleet.yaml: `ecosystems: ["my_module:GoModules"]`."""
    for spec in specs or []:
        eco = settings.load_class(spec, {}, "ecosystem")()
        ECOSYSTEMS[eco.name] = eco


def make_source(s: dict, defaults: dict) -> Source:
    """A source from fleet.yaml, on the company's forge unless it says otherwise."""
    cfg = {**(defaults or {}), **{k: v for k, v in s.items() if k != "forge"}}
    if isinstance(s.get("forge"), dict):
        cfg.update(s["forge"])
    elif s.get("forge"):
        cfg["kind"] = s["forge"]
    kind = cfg.get("kind", "local")
    path = Path(s.get("path") or config.REPOS_DIR / s["name"])
    if not path.is_absolute():
        path = config.WORKSPACE / path
    author = (cfg["author_name"], cfg["author_email"]) if cfg.get("author_name") and cfg.get("author_email") else None
    cls = settings.load_class(kind, forge.BUILTIN, "forge")
    if cls is forge.GitSource:
        return cls(s["name"], s.get("url", ""), path, s.get("branch", "main"), clone=bool(cfg.get("clone", False)),
                   deploy=bool(cfg.get("deploy", True)), author=author)
    return cls(s["name"], s.get("url", ""), path, s.get("branch", "main"), token=cfg.get("token"),
               api_url=cfg.get("api_url"), repo=s.get("repo"), labels=cfg.get("labels"),
               deploy=bool(cfg.get("deploy", True)), clone=bool(cfg.get("clone", True)), author=author)


class Fleet:
    def __init__(self, spec: dict):
        self.spec = spec
        reg = spec.get("registry") or {}
        self.builder = Builder(reg.get("push"), reg.get("pull"))
        register_ecosystems(spec.get("ecosystems"))
        forge_defaults = settings.section("forge", {})
        self.sources: dict[str, Source] = {s["name"]: make_source(s, forge_defaults) for s in spec.get("sources", [])}
        self.targets: dict[str, Target] = {}
        self.target_errors: dict[str, str] = {}
        self.target_specs = {t["name"]: t for t in spec.get("targets", [])}
        self._workloads: list[Workload] = []
        self._discovered = 0.0
        self._lock = threading.Lock()

    # ------------------------------------------------------------- lookups

    def repo_for(self, image: str, meta: dict) -> Optional[str]:
        """Image -> source name, by OCI source label, then by app name."""
        url = self.builder.labels(image).get(SOURCE_LABEL)
        for s in self.sources.values():
            if url and url.rstrip("/").removesuffix(".git") == s.url.rstrip("/").removesuffix(".git"):
                return s.name
        if "metadata" in meta:                    # a Kubernetes object
            pod = meta.get("spec", {}).get("template", {}).get("metadata", {})
            labels = {**(meta["metadata"].get("labels") or {}), **(pod.get("labels") or {})}
        else:                                     # container labels
            labels = meta
        for key in ("app.kubernetes.io/name", "app", "com.docker.compose.service"):
            if labels.get(key) in self.sources:
                return labels[key]
        return None

    def target(self, name: str) -> Target:
        if name not in self.targets:
            self.targets[name] = self._make_target(self.target_specs[name])
        return self.targets[name]

    def _make_target(self, t: dict) -> Target:
        if t["kind"] == "kubernetes":
            from .drivers.kubernetes import KubernetesTarget
            return KubernetesTarget(t["name"], t.get("context"), t.get("namespace", "default"),
                                    t.get("provider"), t.get("endpoints"), self.repo_for)
        if t["kind"] == "compose":
            from .drivers.compose import ComposeTarget
            return ComposeTarget(t["name"], t.get("project", t["name"]), t.get("provider", "Docker host"),
                                 t.get("region"), t.get("endpoints"), self.repo_for)
        if ":" in t["kind"]:
            # custom target piece: constructed with its fleet.yaml entry and the repo linker
            return settings.load_class(t["kind"], {}, "target")(t, self.repo_for)
        raise ValueError(f"unknown target kind {t['kind']!r}; built-in: kubernetes, compose, "
                         f"or a custom piece as 'module:Class'")

    def source(self, wl: Workload) -> Optional[Source]:
        src = self.sources.get(wl.repo) if wl.repo else None
        if src is not None and hasattr(src, "ensure"):
            try:
                src.ensure()
            except Exception as exc:              # a clone failure must not hide the workload
                print(f"[fleet] {src.name}: {exc}", flush=True)
        return src

    def ecosystem(self, name: str) -> Ecosystem:
        return ECOSYSTEMS[name]

    # ----------------------------------------------------------- discovery

    def discover(self, max_age: float = 5.0) -> list[Workload]:
        with self._lock:
            if time.time() - self._discovered < max_age:
                return list(self._workloads)
            out = []
            for name in self.target_specs:
                try:
                    out += self.target(name).list_workloads()
                    self.target_errors.pop(name, None)
                except Exception as exc:          # one unreachable environment must not hide the rest
                    self.target_errors[name] = f"{type(exc).__name__}: {exc}"[:300]
                    self.targets.pop(name, None)
            self._workloads, self._discovered = out, time.time()
            return list(out)

    def workload(self, workload_id: str) -> Optional[Workload]:
        return next((w for w in self.discover() if w.id == workload_id), None)

    def environments(self) -> list[dict]:
        return [{"name": n, "kind": t["kind"], "provider": t.get("provider"), "label": t.get("label", n),
                 "error": self.target_errors.get(n)} for n, t in self.target_specs.items()]


_fleet: Optional[Fleet] = None


def get() -> Fleet:
    global _fleet
    if _fleet is None:
        _fleet = Fleet(yaml.safe_load(config.FLEET_FILE.read_text()) or {})
    return _fleet


def set_fleet(f: Fleet) -> None:
    """Tests and alternative entry points inject their own fleet."""
    global _fleet
    _fleet = f
