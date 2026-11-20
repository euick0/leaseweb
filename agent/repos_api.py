"""Repository audit API (agent/repo_audit.py), mounted under /api by main.py.

  GET  /api/repos                          every `audit: repo` source, its packages and ranked findings
  POST /api/repos/{name}/scan              clone or sync and scan again (approvers; audited)
  POST /api/repos/{name}/propose           bump one finding's package on a local branch (approvers; audited)
  GET  /api/repos/{name}/proposals/{id}/patch   the proposal as a git patch

Scans and proposals run in the background; `?wait=true` runs them inline.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from . import auth, db, repo_audit

router = APIRouter()


class ProposeBody(BaseModel):
    finding: str            # the finding's key, or an advisory id (GO-…, GHSA-…, CVE-…)


def _known(name: str) -> None:
    if name not in repo_audit.sources():
        raise HTTPException(404, f"no repo-only source named {name!r} (mark it `audit: repo` in fleet.yaml)")


@router.get("/repos")
def repos():
    return {"repos": repo_audit.overview(), "govulncheck": repo_audit.govulncheck_available() or "installed"}


@router.post("/repos/{name}/scan")
def scan(name: str, wait: bool = False, actor: str = Depends(auth.act)):
    _known(name)
    db.audit(actor, "repo-scan", name)
    if not wait:
        repo_audit.start_scan(name, actor)
        return {"ok": True, "status": "scanning"}
    try:
        result = repo_audit.scan(name, actor)
    except Exception as exc:
        raise HTTPException(502, f"scan of {name} failed: {type(exc).__name__}: {exc}"[:500])
    return {"ok": True, "status": "ok", "findings": len(result["findings"])}


@router.post("/repos/{name}/propose")
def propose(name: str, body: ProposeBody, wait: bool = False, actor: str = Depends(auth.act)):
    _known(name)
    try:
        if wait:
            prop = repo_audit.propose(name, body.finding, actor)
            out = {"ok": prop["status"] != "failed", "id": prop["id"], "status": prop["status"],
                   "branch": prop["branch"], "error": prop.get("error")}
        else:
            started = repo_audit.start_proposal(name, body.finding, actor)
            out = {"ok": True, "id": started["id"], "status": "running"}
    except KeyError:
        raise HTTPException(404, f"no finding {body.finding!r} in the last scan of {name}")
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    db.audit(actor, "propose-fix", f"{name}: {body.finding}", "local branch only, never pushed")
    return out


@router.get("/repos/{name}/proposals/{proposal_id}/patch", response_class=PlainTextResponse)
def patch(name: str, proposal_id: str):
    _known(name)
    prop = next((p for p in repo_audit.load(name).get("proposals", []) if p["id"] == proposal_id), None)
    if not prop or not prop.get("patch") or not Path(prop["patch"]).exists():
        raise HTTPException(404, "no patch for this proposal")
    return PlainTextResponse(Path(prop["patch"]).read_text(encoding="utf-8"), media_type="text/x-patch")
