"""Which puzzle pieces are in place, and which are missing.

  uv run python -m agent.doctor          # exit code 1 if a required piece is missing

Reads lighthouse.yaml, fleet.yaml, policy.yaml and the environment (.env); does
not change anything. Target environments are contacted read-only to list
workloads.
"""
from __future__ import annotations

import shutil
import sys

import requests

from . import auth, config, feeds, notify, overrides, providers, settings

OK, MISSING, OPTIONAL = "[ok]      ", "[missing] ", "[optional]"


class Report:
    def __init__(self):
        self.missing = 0

    def slot(self, title: str) -> None:
        print(f"\n== {title}")

    def line(self, ok: bool, text: str, required: bool = True) -> None:
        if not ok and required:
            self.missing += 1
        print(f"  {OK if ok else (MISSING if required else OPTIONAL)} {text}")

    def checks(self, piece, required: bool = True) -> None:
        for ok, text in getattr(piece, "check", lambda: [(True, f"custom piece {type(piece).__name__}")])():
            self.line(ok, text, required)


def _llm(r: Report) -> None:
    r.slot(f"llm: {','.join(overrides.llm_providers())} (mode {overrides.llm_mode()})")
    if overrides.llm_mode() == "cache":
        r.line(True, "cache mode: only cached answers are used, no model is called")
    for p in providers.chain():
        if p.name == "ollama":
            try:
                requests.get(f"{p.url}/api/tags", timeout=3).raise_for_status()
                r.line(True, f"ollama reachable at {p.url} (model {p.model})")
            except requests.RequestException:
                r.line(False, f"ollama not reachable at {p.url}: start it or set OLLAMA_URL")
        elif p.name == "anthropic":
            import os
            r.line(bool(os.environ.get("ANTHROPIC_API_KEY")), "ANTHROPIC_API_KEY set" if os.environ.get(
                "ANTHROPIC_API_KEY") else "fill in ANTHROPIC_API_KEY (and uv sync --extra anthropic)")
        else:
            key = getattr(p, "api_key", None)
            needs_key = p.name != "openai-compatible"
            ok = bool(key) or not needs_key
            r.line(ok and bool(getattr(p, "base_url", "")), f"{p.name}: model {p.model or '?'}" if ok
                   else f"{p.name}: fill in {providers.PRESETS[p.name].key_envs[0]}")


def _fleet(r: Report) -> None:
    from . import fleet
    r.slot(f"fleet: {config.FLEET_FILE}")
    if not config.FLEET_FILE.exists():
        r.line(False, f"no fleet file at {config.FLEET_FILE}: list your sources and targets (see fleet.yaml)")
        return
    try:
        fl = fleet.get()
    except Exception as exc:
        r.line(False, f"fleet.yaml does not load: {exc}")
        return
    r.line(bool(fl.sources), f"{len(fl.sources)} source repositories" if fl.sources
           else "no sources: add the repositories your services are built from")
    for src in fl.sources.values():
        r.checks(src)
    r.line(bool(fl.target_specs), f"{len(fl.target_specs)} target environments" if fl.target_specs
           else "no targets: add the clusters / Docker hosts your services run on")
    try:
        workloads = fl.discover(max_age=0)
    except Exception as exc:
        workloads = []
        r.line(False, f"discovery failed: {exc}")
    for name in fl.target_specs:
        err = fl.target_errors.get(name)
        n = sum(1 for w in workloads if w.target == name)
        r.line(not err, f"{name}: {n} workloads" if not err else f"{name}: {err}")
    unlinked = [w.name for w in workloads if not w.repo]
    if unlinked:
        r.line(False, "not linked to a source (set the OCI source label or name the app after the source): "
               + ", ".join(sorted(set(unlinked))), required=False)


def _tools(r: Report) -> None:
    r.slot("tools on this machine")
    r.line(bool(shutil.which("git")), "git" if shutil.which("git") else "install git")
    r.line(bool(shutil.which("docker")), "docker (builds and canaries)" if shutil.which("docker")
           else "docker not found: needed to build and canary fixes", required=False)
    r.line(bool(shutil.which("syft")), "syft (SBOM of running images)" if shutil.which("syft")
           else "syft not found: inventory falls back to the repositories' pins", required=False)
    for tool, why in (("go", "Go fixes run `go get` (without it go.mod/go.sum are edited directly)"),
                      ("uv", "refreshes uv.lock after a Python fix"), ("poetry", "refreshes poetry.lock after a Python fix")):
        r.line(bool(shutil.which(tool)), f"{tool} ({why})" if shutil.which(tool) else f"{tool} not found: {why}",
               required=False)


def main() -> int:
    r = Report()
    raw = settings.raw()
    r.slot(f"settings: {config.SETTINGS_FILE}")
    if config.SETTINGS_FILE.exists():
        r.line(True, "company settings loaded")
    else:
        r.line(True, "no lighthouse.yaml: demo defaults (copy lighthouse.example.yaml to start)")
    gaps = settings.missing_vars(raw)
    r.line(not gaps, "every ${SECRET} is set" if not gaps else "fill in (in .env or the environment): " + ", ".join(gaps))

    a = auth.get()
    r.slot(f"auth: {a.piece.kind}" + (f" (approvers: {', '.join(sorted(a.approvers))})" if a.approvers else ""))
    r.checks(a.piece)

    f = settings.section("forge", {}) or {}
    r.slot(f"forge: {f.get('kind', 'local')}" + ("" if f.get("deploy", True) else " (propose only, CI/CD deploys)"))
    if f.get("kind", "local") == "local":
        r.line(True, "fixes are merged into the local clones (set forge.kind to github or gitlab for pull requests)",
               required=False)

    piece = feeds.get()
    r.slot(f"feed: {piece.kind}")
    r.checks(piece)

    chans = notify.channels()
    r.slot(f"notify: {', '.join(c.piece.kind for c in chans) or 'none'}")
    if not chans:
        r.line(False, "nobody is told when an approval is waiting (add slack, teams, webhook or email)", required=False)
    for c in chans:
        r.checks(c.piece)

    _llm(r)
    r.slot(f"policy: {config.POLICY_FILE}")
    r.line(config.POLICY_FILE.exists(), "policy loaded" if config.POLICY_FILE.exists()
           else "no policy.yaml: built-in defaults apply", required=False)
    _fleet(r)
    _tools(r)

    print(f"\n{'All required pieces are in place.' if not r.missing else f'{r.missing} required piece(s) missing.'}")
    return 1 if r.missing else 0


if __name__ == "__main__":
    sys.exit(main())
