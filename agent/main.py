"""PatchPilot API and dashboard.

  uv run uvicorn agent.main:app --host 0.0.0.0 --port 8000

A background thread watches feed/ and runs the pipeline for every advisory it
has not seen. The dashboard (agent/static) only reads the decision log and
posts approvals.
"""
from __future__ import annotations

import json
import shutil
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import config, db, feed, fleet, llm, pipeline, probes

STATIC = Path(__file__).resolve().parent / "static"
_run_lock = threading.Lock()


def _watch_feed(stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            # several new advisories at once: the most critical runs first
            for adv in feed.by_severity(feed.list_feed()):
                if not db.advisory_seen(adv["id"]):
                    with _run_lock:
                        pipeline.run_advisory(adv)
        except Exception as exc:                      # keep watching whatever happens
            print(f"[feed] {type(exc).__name__}: {exc}", flush=True)
        stop.wait(config.FEED_POLL_SECONDS)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    config.FEED_DIR.mkdir(parents=True, exist_ok=True)
    stop = threading.Event()
    watcher = threading.Thread(target=_watch_feed, args=(stop,), daemon=True)
    watcher.start()
    yield
    stop.set()
    watcher.join(timeout=30)


app = FastAPI(title="PatchPilot", lifespan=lifespan)


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
def probe_all():
    """Run every relevant probe on every workload's live path."""
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
    out = []
    for r in db.list_runs():
        its = db.items(r["id"])
        out.append({**r, "items": [{k: i[k] for k in ("id", "workload_id", "status", "rank")} for i in its]})
    return out


@app.get("/api/runs/{run_id}")
def run(run_id: int, after: int = 0):
    r = db.get_run(run_id)
    if not r:
        raise HTTPException(404, "no such run")
    return {"run": r, "items": db.items(run_id), "events": db.events(run_id, after)}


@app.post("/api/items/{item_id}/approve")
def approve(item_id: int):
    try:
        pipeline.approve(item_id)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return {"ok": True}


@app.post("/api/items/{item_id}/reject")
def reject(item_id: int):
    try:
        pipeline.reject(item_id)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return {"ok": True}


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
def trigger(name: str):
    """Publish a scenario's advisory into the feed, as if it had just arrived."""
    src = config.SCENARIOS_DIR / f"{name}.json"
    if not src.exists() or "/" in name:
        raise HTTPException(404, "no such scenario")
    shutil.copy(src, config.FEED_DIR / src.name)
    return {"ok": True, "advisory": json.loads(src.read_text())["id"]}


@app.post("/api/reset")
def reset():
    """Forget every run, probe and vet verdict (called by scripts/reset_demo.sh
    after it has restored the fleet). The LLM answer cache is kept."""
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
