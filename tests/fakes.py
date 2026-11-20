"""A Target and a Builder that run on a laptop without Docker or Kubernetes,
for end-to-end tests of the pipeline.

Python services really run: the "image" is a copy of the repository with a
virtualenv built from its vendored wheels, and each deployment is a process on
a free port. So the path-traversal probe, the broken update and the gateway
rule are exercised for real. Java services are simulated: the JNDI callback
fires when the deployed image vendors log4j-core 2.14.1.
"""
from __future__ import annotations

import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from agent.drivers.base import DriverError, HttpResult
from agent.drivers.http import get
from agent.schemas import Workload

RULE = re.compile(r'^if \((\$\w+) ~\* "(.*)"\) \{ return 403; \}$')


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LocalBuilder:
    push_prefix = None

    def __init__(self, workdir: Path):
        self.workdir = workdir
        self.images: dict[str, Path] = {}

    def push_name(self, image: str) -> str:
        return image

    def labels(self, image: str) -> dict:
        return {}

    def build(self, path: str, repo: str, url: str, tag: str, push: bool) -> str:
        dest = self.workdir / "images" / f"{repo}-{tag}"
        shutil.copytree(path, dest, ignore=shutil.ignore_patterns(".git"))
        if (dest / "requirements.txt").exists():
            subprocess.run(["uv", "venv", "-q", "--python", sys.executable, str(dest / ".venv")], check=True)
            subprocess.run(["uv", "pip", "install", "-q", "--python", str(dest / ".venv/bin/python"), "--no-index",
                            "--find-links", str(dest / "wheels"), "-r", str(dest / "requirements.txt")], check=True)
            # same layout as the container: /app/keys and /srv/pp-probe four levels apart
            root = dest / "root"
            shutil.copytree(dest / "keys", root / "a/b/c/keys")
            (root / "srv/pp-probe").mkdir(parents=True)
            shutil.copy(dest / "pp-probe/marker.txt", root / "srv/pp-probe/marker.txt")
        image = f"{repo}:{tag}"
        self.images[image] = dest
        return image


class Instance:
    def __init__(self, image: str, path: Path):
        self.image, self.path, self.proc, self.port = image, path, None, None
        if (path / "app.py").exists():
            self.port = _free_port()
            env = {"PORT": str(self.port), "ACME_KEY_DIR": str(path / "root/a/b/c/keys"), "PATH": "/usr/bin:/bin"}
            self.proc = subprocess.Popen([str(path / ".venv/bin/python"), "app.py"], cwd=path, env=env,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.time() + 10
            while time.time() < deadline and get(f"http://127.0.0.1:{self.port}/", timeout=1).status == 0:
                time.sleep(0.1)

    @property
    def log4shell_vulnerable(self) -> bool:
        return (self.path / "lib/log4j-core-2.14.1.jar").exists()

    def stop(self) -> None:
        if self.proc:
            self.proc.terminate()
            self.proc.wait(5)


class LocalTarget:
    kind = "local"

    def __init__(self, name: str, builder: LocalBuilder, apps: dict[str, dict]):
        """apps: name -> {"image": str, "exposed": bool}"""
        self.name, self.builder, self.apps = name, builder, apps
        self.stable = {a: Instance(spec["image"], builder.images[spec["image"]]) for a, spec in apps.items()}
        self.canary: dict[str, Instance] = {}
        self.rules: dict[str, dict[str, list]] = {a: {} for a in apps}
        self.hits: list[dict] = []

    def close(self) -> None:
        for inst in [*self.stable.values(), *self.canary.values()]:
            inst.stop()

    def list_workloads(self) -> list[Workload]:
        return [Workload(id=f"{self.name}/shop/{a}", name=a, target=self.name, target_kind="local",
                         provider="laptop", image=self.stable[a].image, repo=a, internet_exposed=s["exposed"],
                         exposure="test gateway" if s["exposed"] else "internal",
                         gateway=f"{a}-gateway" if s["exposed"] else None)
                for a, s in self.apps.items()]

    def _blocked(self, app: str, path: str, headers: dict) -> bool:
        query = path.split("?", 1)[1] if "?" in path else ""
        for var, rx in (r for rules in self.rules[app].values() for r in rules):
            value = query if var == "$args" else next(
                (v for k, v in headers.items() if "$http_" + k.lower().replace("-", "_") == var), "")
            if rx.search(value):
                return True
        return False

    def http(self, wl: Workload, path: str, headers: Optional[dict] = None, via: str = "public",
             timeout: float = 8) -> HttpResult:
        headers = headers or {}
        if via == "public" and wl.gateway and self._blocked(wl.name, path, headers):
            return HttpResult(403, "blocked by gateway")
        inst = self.canary.get(wl.name) if via == "canary" else self.stable[wl.name]
        if inst is None:
            return HttpResult(0, "no canary")
        if inst.port:
            return get(f"http://127.0.0.1:{inst.port}{path}", headers, timeout)
        payload = headers.get("X-Api-Version", "")
        if "${jndi:" in payload and inst.log4shell_vulnerable:
            self.hits.append({"ts": time.time(), "peer": wl.name, "data": payload})
        return HttpResult(200, "ok\n")

    def callback_hits(self, wl: Workload, since: float) -> list[dict]:
        return [h for h in self.hits if h["ts"] >= since]

    def gateway_config(self, wl: Workload) -> Optional[str]:
        return "test gateway" if wl.gateway else None

    def deploy_canary(self, wl: Workload, image: str) -> None:
        self.remove_canary(wl)
        self.canary[wl.name] = Instance(image, self.builder.images[image])

    def remove_canary(self, wl: Workload) -> None:
        inst = self.canary.pop(wl.name, None)
        if inst:
            inst.stop()

    def promote(self, wl: Workload, image: str) -> str:
        old = self.stable[wl.name]
        self.stable[wl.name] = Instance(image, self.builder.images[image])
        old.stop()
        return old.image

    def rollback(self, wl: Workload, previous_image: str) -> None:
        self.promote(wl, previous_image)

    def apply_mitigation(self, wl: Workload, key: str, rule: str) -> None:
        if not wl.gateway:
            raise DriverError("no gateway")
        parsed = []
        for line in rule.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            m = RULE.match(line)
            if not m:
                raise DriverError(f"nginx -t would fail: {line}")
            nginx_unquoted = m.group(2).replace('\\"', '"').replace("\\\\", "\\")
            parsed.append((m.group(1), re.compile(nginx_unquoted, re.I)))
        self.rules[wl.name][key] = parsed

    def clear_mitigations(self, wl: Workload) -> None:
        self.rules[wl.name] = {}
