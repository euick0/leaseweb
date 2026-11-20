"""The settings page's API (agent/static/settings.html): the AI model, the AI's
permissions (the policy), the scope PatchPilot works on, and what is running
on this server.

Everyone who can log in may read; changing anything takes `auth.admin`, is
validated like the files it overrides, and is written to the audit log.
Changes are kept in state/ui-settings.json (agent/overrides.py); resetting a
section goes back to the files.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
import threading
import time
from typing import Optional

import requests
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pydantic import BaseModel

from . import auth, config, db, fleet, llm, overrides, pipeline, policy, providers

router = APIRouter()
STARTED = time.time()
MODES = ("live", "cache")


def known_providers() -> list[str]:
    return ["ollama", "anthropic", *providers.PRESETS]


def _key_set(name: str) -> Optional[bool]:
    """Whether the provider's API key is in the environment; None when it needs none."""
    if name == "ollama":
        return None
    if name == "anthropic":
        return bool(os.environ.get("ANTHROPIC_API_KEY"))
    if name == "openai-compatible":
        return bool(os.environ.get("OPENAI_COMPATIBLE_API_KEY")) or None
    return any(os.environ.get(k) for k in providers.PRESETS[name].key_envs)


def _describe(name: str) -> dict:
    p = providers.get(name)
    return {"name": name, "model": p.model, "hosted": providers.hosted(p), "key_set": _key_set(name),
            "endpoint": getattr(p, "url", None) or getattr(p, "base_url", None) or "Anthropic API"}


def _audit(actor: str, what: str, before, after) -> None:
    db.audit(actor, "settings", what, json.dumps({"before": before, "after": after}, sort_keys=True)[:2000])


def _hosted_in(names: list[str]) -> list[str]:
    return [n for n in names if providers.hosted(providers.get(n))]


# ------------------------------------------------------------------- read

@router.get("/settings")
def get_settings(request: Request, scan: bool = False):
    """`scan=true` takes an SBOM of every workload not scanned yet, so every package can be listed."""
    user = request.state.user
    fl = fleet.get()
    workloads = fl.discover(max_age=10)
    scope = overrides.scope()
    comps = {w.id: pipeline.sbom(fl, w)[0] if scan else pipeline.cached_sbom(w) for w in workloads}
    seen_ecos = sorted({c.ecosystem for cs in comps.values() for c in cs} | set(fleet.ECOSYSTEMS))
    return {
        "me": {"user": user, "may_admin": auth.get().may_admin(user)},
        "llm": {
            "chain": [_describe(n) for n in overrides.llm_providers()],
            "mode": overrides.llm_mode(),
            "modes": MODES,
            "available": [_describe(n) for n in known_providers()],
            "changed": bool(overrides.section("llm")),
            "status": llm.status(),
        },
        "policy": {
            "effective": policy.fleet(),
            "file": policy.file_policy(),
            "changed": overrides.section("policy"),
            "allowed": {**{k: list(v) for k, v in policy.ALLOWED.items()},
                        "patch": {k: list(v) for k, v in policy.ALLOWED_PATCH.items()}},
            "presets": policy.PRESETS,
        },
        "scope": {
            "changed": bool(overrides.section("scope")),
            "excluded": scope,
            "targets": [{**e, "workloads": sum(1 for w in workloads if w.target == e["name"])}
                        for e in fl.environments()],
            "workloads": [{"id": w.id, "name": w.name, "target": w.target, "image": w.image,
                           "internet_exposed": w.internet_exposed, "repo": w.repo,
                           "packages": len(comps[w.id]) if comps[w.id] or scan else None} for w in workloads],
            "ecosystems": seen_ecos,
            "packages": sorted({c.coordinate for cs in comps.values() for c in cs}),
        },
    }


# -------------------------------------------------------------------- llm

class LlmSettings(BaseModel):
    providers: list[str]
    mode: str = "live"
    models: dict[str, str] = {}


@router.put("/settings/llm")
def put_llm(body: LlmSettings, actor: str = Depends(auth.admin)):
    names = [providers.ALIASES.get(n.strip().lower(), n.strip().lower()) for n in body.providers if n.strip()]
    unknown = [n for n in names if n not in known_providers()]
    if not names or unknown:
        raise HTTPException(422, f"unknown provider(s): {', '.join(unknown)}" if unknown else "choose at least one provider")
    if body.mode not in MODES:
        raise HTTPException(422, f"mode must be one of {', '.join(MODES)}")
    models = {k: v.strip() for k, v in body.models.items() if k in known_providers() and v and v.strip()}
    before = overrides.section("llm")
    after = {"providers": list(dict.fromkeys(names)), "mode": body.mode, "models": models}
    outside = _hosted_in(after["providers"])
    if outside and not policy.fleet()["allow_hosted_llm"]:
        raise HTTPException(409, f"{', '.join(outside)} would send prompts outside our infrastructure, and the "
                                 f"policy says allow_hosted_llm: false. Allow hosted models under Permissions first.")
    overrides.put("llm", after)
    providers.reset()
    _audit(actor, "llm", before, after)
    return {"ok": True, "chain": [_describe(n) for n in overrides.llm_providers()]}


@router.delete("/settings/llm")
def reset_llm(actor: str = Depends(auth.admin)):
    before = overrides.section("llm")
    overrides.put("llm", None)
    providers.reset()
    outside = _hosted_in(overrides.llm_providers())
    if outside and not policy.fleet()["allow_hosted_llm"]:
        overrides.put("llm", before or None)
        providers.reset()
        raise HTTPException(409, f"the configured chain includes hosted {', '.join(outside)}, which the policy forbids")
    _audit(actor, "llm", before, None)
    return {"ok": True}


@router.get("/settings/llm/models")
def list_models(provider: str):
    """The models a provider offers, to choose from; an empty list with the reason when it cannot say."""
    if provider not in known_providers():
        raise HTTPException(404, "unknown provider")
    p = providers.get(provider)
    try:
        if provider == "ollama":
            r = requests.get(f"{p.url}/api/tags", timeout=5)
            r.raise_for_status()
            return {"models": sorted(m["name"] for m in r.json().get("models", []))}
        if provider == "anthropic":
            key = os.environ.get("ANTHROPIC_API_KEY")
            if not key:
                return {"models": [], "error": "ANTHROPIC_API_KEY is not set"}
            r = requests.get("https://api.anthropic.com/v1/models", timeout=10,
                             headers={"x-api-key": key, "anthropic-version": "2023-06-01"})
            r.raise_for_status()
            return {"models": [m["id"] for m in r.json().get("data", [])]}
        if not p.base_url:
            return {"models": [], "error": "no base URL configured"}
        headers = {"Authorization": f"Bearer {p.api_key}"} if p.api_key else {}
        r = requests.get(f"{p.base_url}/models", headers=headers, timeout=10)
        r.raise_for_status()
        return {"models": sorted(m["id"].removeprefix("models/") for m in r.json().get("data", []))}
    except (requests.RequestException, ValueError, KeyError) as exc:
        return {"models": [], "error": f"{type(exc).__name__}: {str(exc)[:200]}"}


class Ping(BaseModel):
    ok: bool


@router.post("/settings/llm/test")
def test_llm(actor: str = Depends(auth.admin)):
    """One tiny structured call to every provider in the chain."""
    allow_hosted = policy.fleet()["allow_hosted_llm"]
    out = []
    for p in providers.chain():
        hosted = providers.hosted(p)
        if hosted and not allow_hosted:
            out.append({"name": p.name, "model": p.model, "ok": False, "detail": "skipped: hosted models not allowed"})
            continue
        llm.egress["hosted_calls" if hosted else "local_calls"] += 1
        t0 = time.time()
        try:
            answer = p.chat("You are a health check. Answer ok=true.", "ping", Ping, 60)
            out.append({"name": p.name, "model": p.model, "ok": answer.ok, "seconds": round(time.time() - t0, 1)})
        except Exception as exc:
            out.append({"name": p.name, "model": p.model, "ok": False, "detail": f"{type(exc).__name__}: {exc}"[:300]})
    db.audit(actor, "settings", "llm test", ", ".join(f"{r['name']}: {'ok' if r['ok'] else 'failed'}" for r in out))
    return out


# ----------------------------------------------------------------- policy

def _diff(full: dict, base: dict) -> dict:
    """Only what differs from policy.yaml, so a later change to the file still shows through."""
    out = {k: v for k, v in full.items() if k != "patch" and base.get(k) != v}
    patch = {k: v for k, v in (full.get("patch") or {}).items() if base["patch"].get(k) != v}
    if patch:
        out["patch"] = patch
    return out


@router.put("/settings/policy")
def put_policy(body: dict = Body(...), actor: str = Depends(auth.admin)):
    """A full or partial policy, or {"preset": name}."""
    if "preset" in body:
        if body["preset"] not in policy.PRESETS:
            raise HTTPException(422, "unknown preset")
        wanted = {**policy.PRESETS[body["preset"]]["policy"],
                  "allow_hosted_llm": policy.fleet()["allow_hosted_llm"]}     # a preset never changes sovereignty
    else:
        wanted = body
    try:
        policy.validate(wanted)
    except policy.PolicyError as exc:
        raise HTTPException(422, str(exc))
    base = policy.file_policy()
    merged = {**policy.fleet(), **{k: v for k, v in wanted.items() if k != "patch"}}
    merged["patch"] = {**policy.fleet()["patch"], **(wanted.get("patch") or {})}
    outside = _hosted_in(overrides.llm_providers())
    if outside and not merged["allow_hosted_llm"]:
        raise HTTPException(409, f"the model chain includes hosted {', '.join(outside)}: choose a local model "
                                 f"first, then forbid hosted models")
    before = overrides.section("policy")
    after = _diff(merged, base)
    overrides.put("policy", after or None)
    _audit(actor, "policy", before, after)
    return {"ok": True, "effective": policy.fleet()}


@router.delete("/settings/policy")
def reset_policy(actor: str = Depends(auth.admin)):
    outside = _hosted_in(overrides.llm_providers())
    if outside and not policy.file_policy()["allow_hosted_llm"]:
        raise HTTPException(409, f"policy.yaml forbids hosted models and the chain includes {', '.join(outside)}: "
                                 f"choose a local model first")
    before = overrides.section("policy")
    overrides.put("policy", None)
    _audit(actor, "policy", before, None)
    return {"ok": True, "effective": policy.fleet()}


# ------------------------------------------------------------------ scope

class Scope(BaseModel):
    targets: list[str] = []
    workloads: list[str] = []
    ecosystems: list[str] = []
    packages: list[str] = []


@router.put("/settings/scope")
def put_scope(body: Scope, actor: str = Depends(auth.admin)):
    before = overrides.section("scope")
    after = {k: sorted({v.strip() for v in getattr(body, k) if v.strip()}) for k in overrides.SCOPE_KEYS}
    after = {k: v for k, v in after.items() if v}
    overrides.put("scope", after or None)
    _audit(actor, "scope", before, after)
    return {"ok": True, "excluded": overrides.scope()}


@router.delete("/settings/scope")
def reset_scope(actor: str = Depends(auth.admin)):
    before = overrides.section("scope")
    overrides.put("scope", None)
    _audit(actor, "scope", before, None)
    return {"ok": True}


# ----------------------------------------------------------------- server

def _run(cmd: list[str], timeout: float = 5) -> Optional[str]:
    if not shutil.which(cmd[0]):
        return None
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None
    return proc.stdout if proc.returncode == 0 else None


def _memory() -> Optional[dict]:
    try:
        info = dict(line.split(":", 1) for line in open("/proc/meminfo").read().splitlines() if ":" in line)
        kib = lambda k: int(info[k].split()[0]) * 1024        # noqa: E731
        return {"total": kib("MemTotal"), "available": kib("MemAvailable")}
    except (OSError, KeyError, ValueError):
        total = _run(["sysctl", "-n", "hw.memsize"])           # macOS: total only
        return {"total": int(total), "available": None} if total and total.strip().isdigit() else None


def _host_uptime() -> Optional[float]:
    try:
        return float(open("/proc/uptime").read().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def _ollama() -> dict:
    url = config.OLLAMA_URL
    try:
        tags = requests.get(f"{url}/api/tags", timeout=2).json().get("models", [])
        loaded = requests.get(f"{url}/api/ps", timeout=2).json().get("models", [])
    except (requests.RequestException, ValueError) as exc:
        return {"url": url, "reachable": False, "detail": f"{type(exc).__name__}"}
    return {"url": url, "reachable": True, "installed": len(tags),
            "loaded": [{"name": m.get("name"), "size": m.get("size"), "vram": m.get("size_vram"),
                        "until": m.get("expires_at")} for m in loaded]}


def _containers() -> Optional[list[dict]]:
    out = _run(["docker", "ps", "--format", "{{json .}}"])
    if out is None:
        return None
    rows = []
    for line in out.splitlines():
        try:
            c = json.loads(line)
        except ValueError:
            continue
        rows.append({"name": c.get("Names"), "image": c.get("Image"), "status": c.get("Status"),
                     "ports": c.get("Ports")})
    return rows


@router.get("/system")
def system():
    """What runs on this server: the host, the agent and its workers, the model server,
    containers, and the fleet as discovered."""
    disk = shutil.disk_usage(config.WORKSPACE)
    counts = db.item_counts()
    fl = fleet.get()
    workloads = fl.discover(max_age=10)
    try:
        load = os.getloadavg()
    except (OSError, AttributeError):          # no load average on Windows
        load = None
    return {
        "host": {"hostname": socket.gethostname(), "os": platform.platform(terse=True),
                 "python": platform.python_version(), "cpus": os.cpu_count(), "load": load,
                 "memory": _memory(), "disk": {"total": disk.total, "free": disk.free},
                 "uptime": _host_uptime()},
        "agent": {"pid": os.getpid(), "uptime": time.time() - STARTED, "demo": config.DEMO,
                  "auth": auth.get().piece.kind, "llm": llm.status(),
                  "workers": sorted({t.name for t in threading.enumerate() if t.name.startswith("pp-")}),
                  "rollout_in_progress": pipeline._action_lock.locked(),
                  "runs_in_progress": sum(1 for r in db.list_runs() if r["status"] == "running"),
                  "items": counts},
        "ollama": _ollama(),
        "containers": _containers(),
        "environments": [{**e, "workloads": [{"id": w.id, "name": w.name, "image": w.image,
                                              "in_scope": overrides.in_scope(w)}
                                             for w in workloads if w.target == e["name"]]}
                         for e in fl.environments()],
        "tools": {t: bool(shutil.which(t)) for t in ("git", "docker", "kubectl", "syft", "uv")},
    }
