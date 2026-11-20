"""Docker Compose Target driver: one Compose project per environment, for VMs
and bare metal without Kubernetes (and the plan's fallback if the clusters are
not ready by hour 3). Talks to the Docker API only.

Facts come from the containers:
  workloads    containers of the project, by com.docker.compose.service
  exposure     published ports bound to a non-loopback address, directly or
               through a gateway container labelled patchpilot.io/gateway-for
  provider     from fleet.yaml (a Docker host has no provider metadata)

Promote starts the new container with the service name as network alias and
removes the old one; gateways resolve the alias through Docker DNS on every
request (`resolver 127.0.0.11`), so traffic moves without a reload. Virtual
patches are files in the gateway's bind-mounted /etc/nginx/pp/mitigations,
checked with `nginx -t` inside the gateway before the reload.

Reaching containers by IP needs a Linux host (the hackathon server).
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, Optional

from .. import config
from ..schemas import Workload
from .base import DriverError, HttpResult
from .http import get

PROJECT = "com.docker.compose.project"
SERVICE = "com.docker.compose.service"
ROLE = "patchpilot.io/role"
GATEWAY_FOR = "patchpilot.io/gateway-for"
PORT = "patchpilot.io/port"
CANARY_OF = "patchpilot.io/canary-of"
MITIGATIONS = "/etc/nginx/pp/mitigations"


class ComposeTarget:
    kind = "compose"

    def __init__(self, name: str, project: str, provider: str = "Docker host", region: Optional[str] = None,
                 endpoints: Optional[dict] = None,
                 repo_for: Callable[[str, dict], Optional[str]] = lambda image, labels: None):
        import docker

        self.name, self.project, self.provider, self.region = name, project, provider, region
        self.endpoints = endpoints or {}
        self._repo_for = repo_for
        self.docker = docker.from_env()
        self.network = f"{project}_default"

    # -------------------------------------------------------------- helpers

    def _containers(self) -> list:
        return self.docker.containers.list(filters={"label": f"{PROJECT}={self.project}"})

    def _service(self, svc: str):
        for c in self._containers():
            if c.labels.get(SERVICE) == svc and not c.labels.get(CANARY_OF):
                return c
        raise DriverError(f"no running container for service {svc} in {self.project}")

    def _canary(self, svc: str):
        found = self.docker.containers.list(all=True, filters={"label": f"{CANARY_OF}={self.project}/{svc}"})
        return found[0] if found else None

    def _ip(self, c) -> str:
        c.reload()
        nets = c.attrs["NetworkSettings"]["Networks"]
        net = nets.get(self.network) or next(iter(nets.values()), {})
        if not net.get("IPAddress"):
            raise DriverError(f"container {c.name} has no IP address")
        return net["IPAddress"]

    @staticmethod
    def _published(c) -> Optional[str]:
        for port, binds in (c.attrs["NetworkSettings"].get("Ports") or {}).items():
            for b in binds or []:
                if b.get("HostIp") not in ("127.0.0.1", "::1"):
                    return f"published port {b.get('HostIp') or '0.0.0.0'}:{b['HostPort']} → {port}"
        return None

    @staticmethod
    def _host_port(c) -> Optional[str]:
        for binds in (c.attrs["NetworkSettings"].get("Ports") or {}).values():
            for b in binds or []:
                return b["HostPort"]
        return None

    def _port(self, c) -> int:
        return int(c.labels.get(PORT, "8080"))

    def _run(self, template, image: str, name: str, labels: dict, aliases: Optional[list] = None):
        try:
            self.docker.containers.get(name).remove(force=True)
        except Exception:
            pass
        c = self.docker.containers.create(image, name=name, environment=template.attrs["Config"]["Env"],
                                          labels=labels, detach=True)
        self.docker.networks.get(self.network).connect(c, aliases=aliases or [])
        c.start()
        deadline = time.time() + config.HEALTH_TIMEOUT
        while time.time() < deadline:
            c.reload()
            if c.status == "running":
                return c
            if c.status in ("exited", "dead"):
                logs = c.logs(tail=5).decode("utf-8", "replace")
                raise DriverError(f"container {name} exited: {logs[-300:]}")
            time.sleep(0.5)
        raise DriverError(f"container {name} not running within {config.HEALTH_TIMEOUT:.0f}s")

    def _wait_healthy(self, c, path: str) -> None:
        deadline = time.time() + config.HEALTH_TIMEOUT
        last = "no answer"
        while time.time() < deadline:
            r = get(f"http://{self._ip(c)}:{self._port(c)}{path}", timeout=3)
            if r.status == 200:
                return
            last = r.body[:200]
            time.sleep(0.5)
        raise DriverError(f"{c.name} not healthy: {last}")

    def _gateway(self, wl: Workload):
        if not wl.gateway:
            raise DriverError(f"{wl.name} has no gateway to carry a virtual patch")
        return self._service(wl.gateway)

    def _mitigation_dir(self, gw) -> Path:
        for m in gw.attrs.get("Mounts", []):
            if m.get("Destination") == MITIGATIONS:
                return Path(m["Source"])
        raise DriverError(f"gateway {gw.name} has no bind mount at {MITIGATIONS}")

    def _reload(self, gw) -> None:
        code, out = gw.exec_run(["nginx", "-t"])
        if code != 0:
            raise DriverError(f"nginx -t failed in {gw.name}: {out.decode('utf-8', 'replace')[-400:]}")
        code, out = gw.exec_run(["nginx", "-s", "reload"])
        if code != 0:
            raise DriverError(f"nginx reload failed in {gw.name}: {out.decode('utf-8', 'replace')[-400:]}")

    # ----------------------------------------------------------- interface

    def list_workloads(self) -> list[Workload]:
        containers = [c for c in self._containers() if not c.labels.get(CANARY_OF)]
        gateways = {c.labels[GATEWAY_FOR]: c for c in containers if c.labels.get(GATEWAY_FOR)}
        out = []
        for c in containers:
            if c.labels.get(ROLE) or c.labels.get(GATEWAY_FOR):
                continue
            svc = c.labels.get(SERVICE, c.name)
            how = self._published(c)
            gw = gateways.get(svc)
            if not how and gw and self._published(gw):
                how = f"{self._published(gw)} → gateway {gw.labels.get(SERVICE)}"
            image = c.image.tags[0] if c.image.tags else c.attrs["Config"]["Image"]
            out.append(Workload(
                id=f"{self.name}/{self.project}/{svc}", name=svc, target=self.name, target_kind="compose",
                provider=self.provider, region=self.region, image=image, repo=self._repo_for(image, c.labels),
                internet_exposed=how is not None,
                exposure=how or "no published port: reachable only on the project network",
                gateway=gw.labels.get(SERVICE) if gw else None,
                health_path=c.labels.get("patchpilot.io/health", "/health")))
        return out

    def http(self, wl: Workload, path: str, headers: Optional[dict] = None,
             via: str = "public", timeout: float = 8) -> HttpResult:
        if via == "public" and wl.name in self.endpoints:
            return get(self.endpoints[wl.name] + path, headers, timeout)
        if via == "canary":
            c = self._canary(wl.name)
            if not c:
                return HttpResult(0, "no canary container")
            return get(f"http://{self._ip(c)}:{self._port(c)}{path}", headers, timeout)
        if via == "public" and wl.internet_exposed and wl.gateway:
            gw = self._service(wl.gateway)
            port = self._host_port(gw)
            if port:
                return get(f"http://127.0.0.1:{port}{path}", headers, timeout)
        c = self._service(wl.name)
        return get(f"http://{self._ip(c)}:{self._port(c)}{path}", headers, timeout)

    def callback_hits(self, wl: Workload, since: float) -> list[dict]:
        import json

        r = get(f"http://{self._ip(self._service('callback'))}:8000/hits?since={since}", timeout=3)
        if r.status != 200:
            raise DriverError(f"callback listener: {r.body[:120]}")
        return json.loads(r.body)

    def gateway_config(self, wl: Workload) -> Optional[str]:
        if not wl.gateway:
            return None
        gw = self._service(wl.gateway)
        _, out = gw.exec_run(["sh", "-c", f"cat /etc/nginx/nginx.conf {MITIGATIONS}/*.conf 2>/dev/null"])
        return out.decode("utf-8", "replace")

    def deploy_canary(self, wl: Workload, image: str) -> None:
        current = self._service(wl.name)
        labels = {CANARY_OF: f"{self.project}/{wl.name}", ROLE: "canary", PORT: str(self._port(current))}
        self._run(current, image, f"{self.project}-{wl.name}-canary", labels)

    def remove_canary(self, wl: Workload) -> None:
        c = self._canary(wl.name)
        if c:
            c.remove(force=True)

    def promote(self, wl: Workload, image: str) -> str:
        old = self._service(wl.name)
        previous = old.image.tags[0] if old.image.tags else old.attrs["Config"]["Image"]
        name = f"{self.project}-{wl.name}-{int(time.time())}"
        new = self._run(old, image, name, dict(old.labels), aliases=[wl.name])
        try:
            self._wait_healthy(new, wl.health_path)
        except DriverError:
            new.remove(force=True)
            raise
        old.remove(force=True)
        return previous

    def rollback(self, wl: Workload, previous_image: str) -> None:
        self.promote(wl, previous_image)

    def apply_mitigation(self, wl: Workload, key: str, rule: str) -> None:
        gw = self._gateway(wl)
        path = self._mitigation_dir(gw) / f"{key}.conf"
        path.write_text(rule)
        try:
            self._reload(gw)
        except DriverError:
            path.unlink()
            raise

    def clear_mitigations(self, wl: Workload) -> None:
        if not wl.gateway:
            return
        gw = self._gateway(wl)
        removed = False
        for f in self._mitigation_dir(gw).glob("*.conf"):
            f.unlink()
            removed = True
        if removed:
            self._reload(gw)
