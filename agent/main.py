"""PatchPilot API and dashboard.

  uv run uvicorn agent.main:app --host 0.0.0.0 --port 8000

A background thread watches feed/ and runs the pipeline for every advisory it
has not seen; another one runs the feed piece (agent/feeds.py) that fills it.
The dashboard (agent/static) only reads the decision log and posts approvals.

Every /api call goes through the auth piece (agent/auth.py); actions that
change something are recorded in the audit log with who did them.
"""
from __future__ import annotations

import json
import shutil
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import auth, config, db, feed, feeds, fleet, llm, notify, pipeline, probes

STATIC = Path(__file__).resolve().parent / "static"
_run_lock = threading.Lock()

if notify.on_status not in db.STATUS_HOOKS:
    db.STATUS_HOOKS.append(notify.on_status)


def _watch_feed(stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            # one advisory per pass, the most critical unseen one, then read the
            # feed again: a critical advisory that arrives mid-run goes next
            unseen = [adv for adv in feed.list_feed() if not db.advisory_seen(adv["id"])]
            if unseen:
                with _run_lock:
                    pipeline.run_advisory(feed.by_severity(unseen)[0])
                continue
        except Exception as exc:                      # keep watching whatever happens
            print(f"[feed] {type(exc).__name__}: {exc}", flush=True)
        stop.wait(config.FEED_POLL_SECONDS)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    config.FEED_DIR.mkdir(parents=True, exist_ok=True)
    stop = threading.Event()
    watcher = threading.Thread(target=_watch_feed, args=(stop,), daemon=True)
    watcher.start()
    threading.Thread(target=feeds.run_poller, args=(stop,), daemon=True).start()
    yield
    stop.set()
    watcher.join(timeout=30)


app = FastAPI(title="PatchPilot", lifespan=lifespan)


@app.middleware("http")
async def authenticate(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        user = auth.get().identify(request.headers)
        if not user:
            return JSONResponse({"detail": "login required"}, status_code=401)
        request.state.user = user
    return await call_next(request)


def actor(request: Request) -> str:
    """The logged-in user, if they may change things."""
    user = request.state.user
    if not auth.get().may_act(user):
        raise HTTPException(403, f"{user} may view but not act (not in auth.approvers)")
    return user


@app.get("/api/me")
def me(request: Request):
    return {"user": request.state.user, "may_act": auth.get().may_act(request.state.user),
            "auth": auth.get().piece.kind}


@app.get("/api/audit")
def audit_log(limit: int = 200):
    return db.audit_log(limit)


# ------------------------------------------------------------------- fleet

@app.get("/api/fleet")
def get_fleet(refresh: bool = False):
    fl = fleet.get()
    workloads = fl.discover(max_age=0 if refresh else 10)
    latest = {}
    for p in db.latest_probes():
        latest.setdefault(p["workload_id"], []).append(p)
    return {"llm": {"providers": llm.describe(), "mode": config.LLM_MODE},
            "environments": fl.environments(),
            "workloads": [{**w.model_dump(), "probes": latest.get(w.id, [])} for w in workloads]}


@app.post("/api/probe")
def probe_all(request: Request):
    """Run every relevant probe on every workload's live path."""
    db.audit(actor(request), "probe", "fleet")
    fl = fleet.get()
    advisories = _scenarios() + feed.list_feed()
    out = []
    for wl in fl.discover(max_age=0):
        for name in pipeline.probes_for(fl, wl, advisories):
            r = probes.run(name, fl.target(wl.target), wl, probes.default_via(wl))
            db.record_probe(wl.id, r.probe, r.via, r.result, r.detail)
            out.append(r.as_dict())
    return out


# -------------------------------------------------------------------- runs

@app.get("/api/runs")
def runs():
    severity = {a["id"]: feed.advisory_severity(a) for a in _scenarios() + feed.list_feed()}
    out = []
    for r in db.list_runs():
        its = db.items(r["id"])
        out.append({**r, "severity": severity.get(r["advisory_id"]),
                    "items": [{k: i[k] for k in ("id", "workload_id", "status", "rank")} for i in its]})
    return out


@app.get("/api/runs/{run_id}")
def run(run_id: int, after: int = 0):
    r = db.get_run(run_id)
    if not r:
        raise HTTPException(404, "no such run")
    return {"run": r, "items": db.items(run_id), "events": db.events(run_id, after)}


@app.post("/api/items/{item_id}/approve")
def approve(item_id: int, request: Request):
    try:
        pipeline.approve(item_id, actor(request))
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return {"ok": True}


@app.post("/api/items/{item_id}/reject")
def reject(item_id: int, request: Request):
    try:
        pipeline.reject(item_id, actor(request))
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return {"ok": True}


@app.post("/api/advisories/{advisory_id}")
def add_advisory(advisory_id: str, request: Request):
    """Fetch one advisory from OSV by id or CVE (e.g. CVE-2021-44228) and run it."""
    who = actor(request)
    try:
        adv = feeds.fetch_osv(advisory_id.strip())
    except LookupError as exc:
        raise HTTPException(404, str(exc))
    feeds.publish([adv])
    db.audit(who, "trigger", adv["id"], f"added {advisory_id} from OSV")
    return {"ok": True, "advisory": adv["id"]}


# --------------------------------------------------------------- scenarios

def _scenarios() -> list[dict]:
    return [feed.load(p) for p in sorted(config.SCENARIOS_DIR.glob("*.json"))]


@app.get("/api/scenarios")
def scenarios():
    seen = {r["advisory_id"] for r in db.list_runs()}
    return [{"name": p.stem, "id": json.loads(p.read_text())["id"],
             "title": feed.title(json.loads(p.read_text())), "summary": json.loads(p.read_text()).get("summary"),
             "triggered": json.loads(p.read_text())["id"] in seen}
            for p in sorted(config.SCENARIOS_DIR.glob("*.json"))]


@app.post("/api/scenarios/{name}")
def trigger(name: str, request: Request):
    """Publish a scenario's advisory into the feed, as if it had just arrived."""
    who = actor(request)
    src = config.SCENARIOS_DIR / f"{name}.json"
    if not src.exists() or "/" in name:
        raise HTTPException(404, "no such scenario")
    shutil.copy(src, config.FEED_DIR / src.name)
    db.audit(who, "trigger", name, "demo scenario")
    return {"ok": True, "advisory": json.loads(src.read_text())["id"]}


@app.post("/api/reset")
def reset(request: Request):
    """Forget every run, probe and vet verdict (called by scripts/reset_demo.sh
    after it has restored the fleet). The LLM answer cache and the audit log are kept."""
    db.audit(actor(request), "reset", "decision log")
    with _run_lock:
        for f in config.FEED_DIR.glob("*.json"):
            f.unlink()
        db.clear()
        pipeline.forget_sboms()
        fleet.get().discover(max_age=0)
    return {"ok": True}


# --------------------------------------------------------------- dashboard

@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
