"""Kubernetes Target driver. Uses only the standard Kubernetes API, so the same
code serves k3s on Leaseweb, EKS, GKE, AKS and the managed Kubernetes of
OVHcloud, Scaleway, Hetzner, IONOS, STACKIT, Open Telekom Cloud or Exoscale.

Facts come from standard fields:
  provider, region   node.spec.providerID scheme, topology.kubernetes.io/region
  exposure           Services of type LoadBalancer/NodePort and Ingress backends
  health path        the container's readiness probe

Two Lighthouse conventions, both plain labels/annotations:
  lighthouse.io/gateway-for: <deployment>   on an nginx gateway Deployment in
      front of a workload; virtual patches go into its ConfigMap
      `<gateway>-mitigations`, mounted at /etc/nginx/pp/mitigations
  lighthouse.io/role: gateway | canary | infra   keeps helpers out of the workload list

All HTTP to workloads (health, probes, canary checks) goes through the API
server's service and pod proxy, so Lighthouse needs nothing but a kubeconfig.
"""
from __future__ import annotations

import copy
import hashlib
import json
import time
from typing import Callable, Optional

from .. import config
from ..schemas import Workload
from .base import DriverError, HttpResult

GATEWAY_FOR = "lighthouse.io/gateway-for"
ROLE = "lighthouse.io/role"
CANARY_OF = "lighthouse.io/canary-of"
# API server proxy errors that mean "the app did not answer", not "the app said 5xx"
PROXY_UNREACHABLE = ("error trying to reach", "connection refused", "dial tcp", "no endpoints available")

PROVIDERS = {
    "aws": "AWS", "gce": "Google Cloud", "azure": "Azure", "openstack": "OpenStack",
    "ovhcloud": "OVHcloud", "scaleway": "Scaleway", "hcloud": "Hetzner Cloud", "ionos": "IONOS",
    "exoscale": "Exoscale", "stackit": "STACKIT", "digitalocean": "DigitalOcean",
    "linode": "Akamai/Linode", "k3s": "k3s", "kind": "kind",
}


# ------------------------------------------------------------ pure discovery

def _labels(obj: dict) -> dict:
    return obj.get("metadata", {}).get("labels") or {}


def _annotations(obj: dict) -> dict:
    return obj.get("metadata", {}).get("annotations") or {}


def _pod_labels(dep: dict) -> dict:
    return dep.get("spec", {}).get("template", {}).get("metadata", {}).get("labels") or {}


def selects(svc: dict, dep: dict) -> bool:
    selector = svc.get("spec", {}).get("selector") or {}
    pod = _pod_labels(dep)
    return bool(selector) and all(pod.get(k) == v for k, v in selector.items())


def provider_of(nodes: list[dict]) -> tuple[str, Optional[str]]:
    for node in nodes:
        pid = node.get("spec", {}).get("providerID") or ""
        scheme = pid.split("://", 1)[0] if "://" in pid else ""
        region = _labels(node).get("topology.kubernetes.io/region")
        if scheme:
            return PROVIDERS.get(scheme, scheme), region
        if region:
            return "Kubernetes", region
    return "Kubernetes", None


def _direct_exposure(dep: dict, services: list[dict], ingresses: list[dict]) -> Optional[str]:
    for svc in services:
        kind = svc.get("spec", {}).get("type", "ClusterIP")
        if kind in ("LoadBalancer", "NodePort") and selects(svc, dep):
            return f"{kind} Service {svc['metadata']['name']}"
    by_name = {s["metadata"]["name"]: s for s in services}
    for ing in ingresses:
        for rule in ing.get("spec", {}).get("rules") or []:
            for p in (rule.get("http") or {}).get("paths") or []:
                backend = (p.get("backend") or {}).get("service") or {}
                svc = by_name.get(backend.get("name"))
                if svc and selects(svc, dep):
                    host = rule.get("host") or "*"
                    return f"Ingress {ing['metadata']['name']} ({host}{p.get('path', '/')}) → Service {svc['metadata']['name']}"
        default = ((ing.get("spec", {}).get("defaultBackend") or {}).get("service") or {}).get("name")
        if default in by_name and selects(by_name[default], dep):
            return f"Ingress {ing['metadata']['name']} (default backend) → Service {default}"
    return None


def health_path(dep: dict) -> str:
    for c in dep.get("spec", {}).get("template", {}).get("spec", {}).get("containers") or []:
        probe = c.get("readinessProbe") or c.get("livenessProbe") or {}
        path = (probe.get("httpGet") or {}).get("path")
        if path:
            return path
    return "/health"


def discover(target: str, deployments: list[dict], services: list[dict], ingresses: list[dict],
             nodes: list[dict], namespace: str, provider: Optional[str] = None,
             repo_for: Callable[[str, dict], Optional[str]] = lambda image, dep: None) -> list[Workload]:
    detected, region = provider_of(nodes)
    gateways = {_annotations(d).get(GATEWAY_FOR): d for d in deployments if _annotations(d).get(GATEWAY_FOR)}
    out = []
    for dep in deployments:
        if _labels(dep).get(ROLE) or _annotations(dep).get(GATEWAY_FOR):
            continue
        name = dep["metadata"]["name"]
        containers = dep["spec"]["template"]["spec"]["containers"]
        image = containers[0]["image"]
        how = _direct_exposure(dep, services, ingresses)
        gw = gateways.get(name)
        gw_name = gw["metadata"]["name"] if gw else None
        if not how and gw:
            via = _direct_exposure(gw, services, ingresses)
            if via:
                how = f"{via} → gateway {gw_name}"
        out.append(Workload(
            id=f"{target}/{namespace}/{name}", name=name, target=target, target_kind="kubernetes",
            provider=provider or detected, region=region, image=image, repo=repo_for(image, dep),
            internet_exposed=how is not None,
            exposure=how or "ClusterIP only: no LoadBalancer, NodePort or Ingress route reaches it",
            gateway=gw_name, health_path=health_path(dep)))
    return out


# ------------------------------------------------------------------ driver

class KubernetesTarget:
    kind = "kubernetes"

    def __init__(self, name: str, context: Optional[str], namespace: str, provider: Optional[str] = None,
                 endpoints: Optional[dict] = None,
                 repo_for: Callable[[str, dict], Optional[str]] = lambda image, dep: None):
        from kubernetes import client, config as kconfig

        self.name, self.namespace, self.provider = name, namespace, provider
        self.endpoints = endpoints or {}
        self._repo_for = repo_for
        self.api_client = kconfig.new_client_from_config(context=context)
        self.core = client.CoreV1Api(self.api_client)
        self.apps = client.AppsV1Api(self.api_client)
        self.net = client.NetworkingV1Api(self.api_client)
        self._client = client

    # -------------------------------------------------------------- helpers

    def _dict(self, obj) -> dict:
        return self.api_client.sanitize_for_serialization(obj)

    def _deployments(self) -> list[dict]:
        return [self._dict(d) for d in self.apps.list_namespaced_deployment(self.namespace).items]

    def _deployment(self, name: str) -> dict:
        return self._dict(self.apps.read_namespaced_deployment(name, self.namespace))

    def _services(self) -> list[dict]:
        return [self._dict(s) for s in self.core.list_namespaced_service(self.namespace).items]

    def _service_for(self, dep_name: str) -> tuple[str, int]:
        dep = self._deployment(dep_name)
        for svc in self._services():
            if selects(svc, dep) and not svc["metadata"]["name"].endswith("-canary"):
                return svc["metadata"]["name"], svc["spec"]["ports"][0]["port"]
        raise DriverError(f"no Service selects {dep_name}")

    def _raw(self, path: str, method: str = "GET", headers: Optional[dict] = None,
             timeout: float = 8) -> HttpResult:
        """A request through the API server (service or pod proxy), with any status code."""
        from kubernetes.client.rest import ApiException

        try:
            if hasattr(self.api_client, "param_serialize"):          # client >= 35: never raises on status
                method, url, hdrs, _, _ = self.api_client.param_serialize(
                    method, path, header_params=dict(headers or {}), auth_settings=["BearerToken"])
                resp = self.api_client.call_api(method, url, header_params=hdrs, _request_timeout=timeout)
                status, data = resp.status, resp.read()
            else:                                                     # older clients raise on non-2xx
                resp = self.api_client.call_api(
                    path, method, header_params=dict(headers or {}), auth_settings=["BearerToken"],
                    _preload_content=False, _return_http_data_only=True, _request_timeout=timeout)
                status, data = resp.status, resp.data
        except ApiException as exc:
            status, data = exc.status or 0, exc.body or b""
        except Exception as exc:                                      # urllib3 timeouts, connection errors
            return HttpResult(0, f"not reachable: {exc}")
        body = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
        if status in (502, 503) and any(s in body for s in PROXY_UNREACHABLE):
            return HttpResult(0, f"not reachable: {body[:200]}")      # the proxy, not the app, answered
        return HttpResult(status, body if status else f"not reachable: {body[:200]}")

    def _canary_pod(self, wl: Workload) -> Optional[str]:
        pods = self.core.list_namespaced_pod(self.namespace, label_selector=f"{CANARY_OF}={wl.name}").items
        running = [p for p in pods if p.status.phase == "Running" and not p.metadata.deletion_timestamp]
        return running[0].metadata.name if running else None

    def _container_port(self, dep: dict) -> int:
        c = dep["spec"]["template"]["spec"]["containers"][0]
        ports = c.get("ports") or [{"containerPort": 8080}]
        return ports[0]["containerPort"]

    def _wait_rollout(self, name: str, timeout: float) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            d = self.apps.read_namespaced_deployment(name, self.namespace)
            s, want = d.status, d.spec.replicas or 1
            if ((s.observed_generation or 0) >= d.metadata.generation and (s.updated_replicas or 0) == want
                    and (s.available_replicas or 0) == want and (s.replicas or 0) == want):
                return
            time.sleep(1)
        raise DriverError(f"rollout of {name} did not finish within {timeout:.0f}s")

    def _set_image(self, name: str, image: str) -> str:
        dep = self._deployment(name)
        containers = dep["spec"]["template"]["spec"]["containers"]
        previous = containers[0]["image"]
        patch = {"spec": {"template": {"spec": {"containers": [{"name": containers[0]["name"], "image": image}]}}}}
        self.apps.patch_namespaced_deployment(name, self.namespace, patch)
        return previous

    # ----------------------------------------------------------- interface

    def list_workloads(self) -> list[Workload]:
        nodes = [self._dict(n) for n in self.core.list_node().items]
        ingresses = [self._dict(i) for i in self.net.list_namespaced_ingress(self.namespace).items]
        return discover(self.name, self._deployments(), self._services(), ingresses, nodes,
                        self.namespace, self.provider, self._repo_for)

    def http(self, wl: Workload, path: str, headers: Optional[dict] = None,
             via: str = "public", timeout: float = 8) -> HttpResult:
        if via == "public" and wl.name in self.endpoints:
            from .http import get
            return get(self.endpoints[wl.name] + path, headers, timeout)
        if via == "canary":
            pod = self._canary_pod(wl)
            if not pod:
                return HttpResult(0, "no running canary pod")
            port = self._container_port(self._deployment(f"{wl.name}-canary"))
            return self._raw(f"/api/v1/namespaces/{self.namespace}/pods/{pod}:{port}/proxy{path}",
                             headers=headers, timeout=timeout)
        name = wl.gateway if via == "public" and wl.gateway and wl.internet_exposed else wl.name
        svc, port = self._service_for(name)
        return self._raw(f"/api/v1/namespaces/{self.namespace}/services/{svc}:{port}/proxy{path}",
                         headers=headers, timeout=timeout)

    def callback_hits(self, wl: Workload, since: float) -> list[dict]:
        r = self._raw(f"/api/v1/namespaces/{self.namespace}/services/callback:8000/proxy/hits?since={since}",
                      timeout=3)
        if r.status != 200:
            raise DriverError(f"callback listener: HTTP {r.status} {r.body[:120]}")
        return json.loads(r.body)

    def gateway_config(self, wl: Workload) -> Optional[str]:
        if not wl.gateway:
            return None
        parts = []
        for cm_name in (f"{wl.gateway}-conf", f"{wl.gateway}-mitigations"):
            try:
                cm = self.core.read_namespaced_config_map(cm_name, self.namespace)
            except self._client.exceptions.ApiException:
                continue
            for key, value in (cm.data or {}).items():
                parts.append(f"# {cm_name}/{key}\n{value}")
        return "\n".join(parts) or None

    def deploy_canary(self, wl: Workload, image: str) -> None:
        """One-replica copy of the workload with the new image, outside the live Service."""
        self.remove_canary(wl, wait=True)
        dep = self._deployment(wl.name)
        name = f"{wl.name}-canary"
        spec = copy.deepcopy(dep["spec"])
        spec["replicas"] = 1
        spec["selector"] = {"matchLabels": {CANARY_OF: wl.name}}
        labels = {k: v for k, v in _pod_labels(dep).items() if k not in ("app", "app.kubernetes.io/name", "track")}
        labels.update({CANARY_OF: wl.name, ROLE: "canary"})
        spec["template"]["metadata"]["labels"] = labels
        spec["template"]["spec"]["containers"][0]["image"] = image
        for c in spec["template"]["spec"]["containers"]:
            c.pop("readinessProbe", None)        # Lighthouse checks health itself, through the pod proxy
        spec.pop("strategy", None)
        body = {"apiVersion": "apps/v1", "kind": "Deployment",
                "metadata": {"name": name, "labels": {ROLE: "canary", CANARY_OF: wl.name}}, "spec": spec}
        self.apps.create_namespaced_deployment(self.namespace, body)

        deadline = time.time() + config.HEALTH_TIMEOUT
        while time.time() < deadline:
            pods = self.core.list_namespaced_pod(self.namespace, label_selector=f"{CANARY_OF}={wl.name}").items
            for p in pods:
                for cs in p.status.container_statuses or []:
                    waiting = cs.state.waiting
                    if waiting and waiting.reason in ("ErrImagePull", "ImagePullBackOff", "CrashLoopBackOff",
                                                      "CreateContainerConfigError", "InvalidImageName"):
                        raise DriverError(f"canary pod {p.metadata.name}: {waiting.reason} "
                                          f"{(waiting.message or '')[:200]}")
                    if cs.state.running:
                        return
            time.sleep(1)
        raise DriverError(f"canary pod not running within {config.HEALTH_TIMEOUT:.0f}s")

    def remove_canary(self, wl: Workload, wait: bool = False) -> None:
        try:
            self.apps.delete_namespaced_deployment(f"{wl.name}-canary", self.namespace,
                                                   propagation_policy="Foreground")
        except self._client.exceptions.ApiException as exc:
            if exc.status != 404:
                raise
            return
        deadline = time.time() + 60
        while wait and time.time() < deadline:
            if not self.core.list_namespaced_pod(self.namespace, label_selector=f"{CANARY_OF}={wl.name}").items:
                return
            time.sleep(1)

    def promote(self, wl: Workload, image: str) -> str:
        previous = self._set_image(wl.name, image)
        try:
            self._wait_rollout(wl.name, config.ROLLOUT_TIMEOUT)
        except DriverError:
            self.rollback(wl, previous)
            raise
        return previous

    def rollback(self, wl: Workload, previous_image: str) -> None:
        self._set_image(wl.name, previous_image)
        self._wait_rollout(wl.name, config.ROLLOUT_TIMEOUT)

    def _restart_gateway(self, gateway: str, data: dict) -> None:
        digest = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:12]
        patch = {"spec": {"template": {"metadata": {"annotations": {"lighthouse.io/mitigations": digest}}}}}
        self.apps.patch_namespaced_deployment(gateway, self.namespace, patch)
        self._wait_rollout(gateway, config.ROLLOUT_TIMEOUT)

    def _mitigations(self, gateway: str) -> dict:
        try:
            cm = self.core.read_namespaced_config_map(f"{gateway}-mitigations", self.namespace)
            return dict(cm.data or {})
        except self._client.exceptions.ApiException as exc:
            if exc.status != 404:
                raise
            return {}

    def _write_mitigations(self, gateway: str, data: dict) -> None:
        name = f"{gateway}-mitigations"
        body = {"metadata": {"name": name, "labels": {ROLE: "gateway"}}, "data": data}
        try:
            self.core.replace_namespaced_config_map(name, self.namespace, body)
        except self._client.exceptions.ApiException as exc:
            if exc.status != 404:
                raise
            self.core.create_namespaced_config_map(self.namespace, body)

    def apply_mitigation(self, wl: Workload, key: str, rule: str) -> None:
        if not wl.gateway:
            raise DriverError(f"{wl.name} has no gateway to carry a virtual patch")
        before = self._mitigations(wl.gateway)
        after = {**before, f"{key}.conf": rule}
        self._write_mitigations(wl.gateway, after)
        try:
            self._restart_gateway(wl.gateway, after)
        except DriverError:
            self._write_mitigations(wl.gateway, before)       # bad rule: gateway pods never became ready
            self._restart_gateway(wl.gateway, before)
            raise

    def remove_mitigation(self, wl: Workload, key: str) -> None:
        if not wl.gateway:
            return
        rules = self._mitigations(wl.gateway)
        if rules.pop(f"{key}.conf", None) is not None:
            self._write_mitigations(wl.gateway, rules)
            self._restart_gateway(wl.gateway, rules)

    def clear_mitigations(self, wl: Workload) -> None:
        if wl.gateway and self._mitigations(wl.gateway):
            self._write_mitigations(wl.gateway, {})
            self._restart_gateway(wl.gateway, {})
