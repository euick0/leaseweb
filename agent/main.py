"""LightHouse API and dashboard.

  uv run uvicorn agent.main:app --host 127.0.0.1 --port 8000

A background thread watches feed/ and runs the pipeline for every advisory it
has not seen; another one runs the feed piece (agent/feeds.py) that fills it.
The dashboard (agent/static) only reads the decision log and posts approvals.

Every /api route goes through the auth piece (agent/auth.py, bearer tokens by
default); the user is recorded on every approval, and actions that change
something go to the audit log.
"""
from __future__ import annotations

import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import auth, config, db, feed, feeds, fleet, llm, notify, pipeline, policy, probes, repos_api, settings_api

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
    policy.fleet()                        # a bad policy file stops the agent here, not mid-run
    llm.check_sovereignty()
    if auth.generated():
        print(f"[auth] no API tokens configured; token for this run: {auth.generated()}\n"
              f"[auth] dashboard: http://localhost:8000/#token={auth.generated()}", flush=True)
    config.FEED_DIR.mkdir(parents=True, exist_ok=True)
    stop = threading.Event()
    watcher = threading.Thread(target=_watch_feed, args=(stop,), daemon=True, name="pp-feed-watcher")
    watcher.start()
    threading.Thread(target=feeds.run_poller, args=(stop,), daemon=True, name="pp-feed-poller").start()
    yield
    stop.set()
    watcher.join(timeout=30)


app = FastAPI(title="LightHouse", lifespan=lifespan)
api = APIRouter(prefix="/api", dependencies=[Depends(auth.require)])


@api.get("/me")
def me(request: Request):
    user = request.state.user
    return {"user": user, "may_act": auth.get().may_act(user), "may_admin": auth.get().may_admin(user),
            "auth": auth.get().piece.kind}


@api.get("/audit")
def audit_log(limit: int = 200):
    return db.audit_log(limit)


# ------------------------------------------------------------------- fleet

@api.get("/fleet")
def get_fleet(refresh: bool = False):
    fl = fleet.get()
    workloads = fl.discover(max_age=0 if refresh else 10)
    latest = {}
    for p in db.latest_probes():
        latest.setdefault(p["workload_id"], []).append(p)
    return {"llm": llm.status(),
            "environments": fl.environments(),
            "workloads": [{**w.model_dump(), "probes": latest.get(w.id, [])} for w in workloads]}


@api.post("/probe")
def probe_all(actor: str = Depends(auth.act)):
    """Run every relevant probe on every workload's live path."""
    db.audit(actor, "probe", "fleet")
    fl = fleet.get()
    advisories = feed.list_feed()
    out = []
    for wl in fl.discover(max_age=0):
        for name in pipeline.probes_for(fl, wl, advisories):
            r = probes.run(name, fl.target(wl.target), wl, probes.default_via(wl))
            db.record_probe(wl.id, r.probe, r.via, r.result, r.detail)
            out.append(r.as_dict())
    return out


# -------------------------------------------------------------------- runs

@api.get("/runs")
def runs():
    severity = {a["id"]: feed.advisory_severity(a) for a in feed.list_feed()}
    out = []
    for r in db.list_runs():
        its = db.items(r["id"])
        out.append({**r, "severity": severity.get(r["advisory_id"]),
                    "items": [{k: i[k] for k in ("id", "workload_id", "status", "rank")} for i in its]})
    return out


@api.get("/runs/{run_id}")
def run(run_id: int, after: int = 0):
    r = db.get_run(run_id)
    if not r:
        raise HTTPException(404, "no such run")
    return {"run": r, "items": db.items(run_id), "events": db.events(run_id, after)}


@api.post("/items/{item_id}/approve")
def approve(item_id: int, actor: str = Depends(auth.act)):
    try:
        pipeline.approve(item_id, actor)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return {"ok": True}


@api.post("/items/{item_id}/reject")
def reject(item_id: int, actor: str = Depends(auth.act)):
    try:
        pipeline.reject(item_id, actor)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return {"ok": True}


@api.post("/advisories/{advisory_id}")
def add_advisory(advisory_id: str, actor: str = Depends(auth.act)):
    """Fetch one advisory from OSV by id or CVE (e.g. CVE-2021-44228) and run it."""
    try:
        adv = feeds.fetch_osv(advisory_id.strip())
    except LookupError as exc:
        raise HTTPException(404, str(exc))
    feeds.publish([adv])
    db.audit(actor, "trigger", adv["id"], f"added {advisory_id} from OSV")
    return {"ok": True, "advisory": adv["id"]}


# --------------------------------------------------------------- dashboard

api.include_router(settings_api.router)
api.include_router(repos_api.router)
app.include_router(api)


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/settings")
def settings_page():
    return FileResponse(STATIC / "settings.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
