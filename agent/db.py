"""Decision log. A run is one advisory across the fleet; an item is that
advisory on one workload; every pipeline step is one row in `events`. The
dashboard polls these tables and never talks to the pipeline directly."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any, Callable, Optional

from . import config

_lock = threading.RLock()
_conn: Optional[sqlite3.Connection] = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id TEXT NOT NULL,
    title       TEXT,
    summary     TEXT,
    status      TEXT NOT NULL,          -- running | awaiting_approval | done | failed
    outcome     TEXT,
    started     REAL NOT NULL,
    finished    REAL
);
CREATE TABLE IF NOT EXISTS items (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER NOT NULL,
    workload_id   TEXT NOT NULL,
    workload      TEXT NOT NULL,        -- JSON Workload at match time
    component     TEXT NOT NULL,        -- JSON Component
    fixed_version TEXT,
    rank          INTEGER,
    triage        TEXT,                 -- JSON TriageResult
    triage_source TEXT,                 -- live | cache | fallback
    vet_key       TEXT,
    decision      TEXT,                 -- JSON {action, decision, reason}
    status        TEXT NOT NULL,        -- matched | queued | awaiting_approval | running | done | blocked
                                        -- | failed | ignored | rolled_back | escalated
    outcome       TEXT,
    pending       TEXT,                 -- JSON action awaiting approval
    proof         TEXT,                 -- JSON {level, before, after}
    decided_by    TEXT,                 -- who approved or rejected it (from the API token)
    updated       REAL
);
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id  INTEGER,
    item_id INTEGER,
    ts      REAL NOT NULL,
    step    TEXT NOT NULL,              -- discover | inventory | match | triage | rank | vet | policy | change
                                        -- | build | canary | promote | rollback | mitigate | probe
    status  TEXT NOT NULL,              -- info | ok | warn | fail | ai | pending
    title   TEXT NOT NULL,
    detail  TEXT,
    data    TEXT
);
CREATE TABLE IF NOT EXISTS probes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    workload_id TEXT NOT NULL,
    probe       TEXT NOT NULL,
    via         TEXT NOT NULL,
    result      TEXT NOT NULL,          -- VULNERABLE | SAFE | BLOCKED | ERROR
    detail      TEXT
);
CREATE TABLE IF NOT EXISTS vet_cache (
    key     TEXT PRIMARY KEY,           -- ecosystem:name:from->to@sha256
    result  TEXT NOT NULL,
    ts      REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (      -- who did what; never cleared by a demo reset
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      REAL NOT NULL,
    actor   TEXT NOT NULL,
    action  TEXT NOT NULL,              -- approve | reject | trigger | probe | reset
    target  TEXT,
    detail  TEXT
);
"""

_JSON = ("workload", "component", "triage", "decision", "pending", "proof", "data")


def conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.executescript(SCHEMA)
        if "decided_by" not in {r["name"] for r in _conn.execute("PRAGMA table_info(items)")}:
            _conn.execute("ALTER TABLE items ADD COLUMN decided_by TEXT")      # log from before the column
    return _conn


def reset_connection() -> None:
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
        _conn = None


def clear() -> None:
    """Empty every table (reset_demo.sh). The schema stays."""
    with _lock:
        for table in ("runs", "items", "events", "probes", "vet_cache"):
            conn().execute(f"DELETE FROM {table}")
        conn().commit()


def _exec(sql: str, args: tuple = ()) -> sqlite3.Cursor:
    with _lock:
        cur = conn().execute(sql, args)
        conn().commit()
        return cur


def _query(sql: str, args: tuple = ()) -> list[dict]:
    with _lock:
        rows = [dict(r) for r in conn().execute(sql, args).fetchall()]
    for r in rows:
        for k in _JSON:
            if k in r and isinstance(r[k], str):
                r[k] = json.loads(r[k])
    return rows


def _dump(v: Any) -> Optional[str]:
    if v is None:
        return None
    if hasattr(v, "model_dump"):
        v = v.model_dump()
    return json.dumps(v, default=str)


# ------------------------------------------------------------------- runs

def create_run(advisory_id: str, title: str, summary: str) -> int:
    return _exec("INSERT INTO runs (advisory_id, title, summary, status, started) VALUES (?, ?, ?, 'running', ?)",
                 (advisory_id, title, summary, time.time())).lastrowid


def update_run(run_id: int, status: str, outcome: Optional[str] = None) -> None:
    finished = None if status in ("running", "awaiting_approval") else time.time()
    _exec("UPDATE runs SET status = ?, outcome = COALESCE(?, outcome), finished = ? WHERE id = ?",
          (status, outcome, finished, run_id))


def get_run(run_id: int) -> Optional[dict]:
    rows = _query("SELECT * FROM runs WHERE id = ?", (run_id,))
    return rows[0] if rows else None


def list_runs() -> list[dict]:
    return _query("SELECT * FROM runs ORDER BY id DESC LIMIT 50")


def advisory_seen(advisory_id: str) -> bool:
    return bool(_query("SELECT 1 FROM runs WHERE advisory_id = ? LIMIT 1", (advisory_id,)))


# ------------------------------------------------------------------ items

def create_item(run_id: int, workload, component, fixed_version: Optional[str]) -> int:
    return _exec("INSERT INTO items (run_id, workload_id, workload, component, fixed_version, status, updated) "
                 "VALUES (?, ?, ?, ?, ?, 'matched', ?)",
                 (run_id, workload.id, _dump(workload), _dump(component), fixed_version, time.time())).lastrowid


# called with the item after every status change (notifications subscribe here)
STATUS_HOOKS: list[Callable[[dict], None]] = []


def update_item(item_id: int, **fields) -> None:
    if not fields:
        return
    cols = ", ".join(f"{k} = ?" for k in fields)
    vals = tuple(_dump(v) if k in _JSON else v for k, v in fields.items())
    _exec(f"UPDATE items SET {cols}, updated = ? WHERE id = ?", (*vals, time.time(), item_id))
    if "status" in fields:
        _status_changed(item_id)


def _status_changed(item_id: int) -> None:
    if not STATUS_HOOKS:
        return
    item = get_item(item_id)
    for hook in STATUS_HOOKS:
        try:
            hook(item)
        except Exception as exc:                  # a broken notifier must never stop a rollout
            print(f"[db] status hook {hook}: {type(exc).__name__}: {exc}", flush=True)


def claim_item(item_id: int, from_statuses: tuple[str, ...], status: str, **fields) -> bool:
    """Move an item to `status` only if it is still in one of `from_statuses`, in one
    statement: of two decisions arriving together, exactly one wins."""
    cols = "".join(f", {k} = ?" for k in fields)
    marks = ", ".join("?" for _ in from_statuses)
    cur = _exec(f"UPDATE items SET status = ?{cols}, updated = ? WHERE id = ? AND status IN ({marks})",
                (status, *fields.values(), time.time(), item_id, *from_statuses))
    if cur.rowcount != 1:
        return False
    _status_changed(item_id)
    return True


def item_counts() -> dict[str, int]:
    """Items per status, over every run."""
    return {r["status"]: r["n"] for r in _query("SELECT status, COUNT(*) AS n FROM items GROUP BY status")}


def get_item(item_id: int) -> Optional[dict]:
    rows = _query("SELECT * FROM items WHERE id = ?", (item_id,))
    return rows[0] if rows else None


def items(run_id: int) -> list[dict]:
    return _query("SELECT * FROM items WHERE run_id = ? ORDER BY COALESCE(rank, 999), id", (run_id,))


# ----------------------------------------------------------------- events

def log(run_id: Optional[int], step: str, status: str, title: str, detail: Optional[str] = None,
        data: Any = None, item_id: Optional[int] = None) -> None:
    _exec("INSERT INTO events (run_id, item_id, ts, step, status, title, detail, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
          (run_id, item_id, time.time(), step, status, title, detail, _dump(data)))


def events(run_id: int, after_id: int = 0) -> list[dict]:
    return _query("SELECT * FROM events WHERE run_id = ? AND id > ? ORDER BY id", (run_id, after_id))


# ----------------------------------------------------------------- probes

def record_probe(workload_id: str, probe: str, via: str, result: str, detail: str) -> None:
    _exec("INSERT INTO probes (ts, workload_id, probe, via, result, detail) VALUES (?, ?, ?, ?, ?, ?)",
          (time.time(), workload_id, probe, via, result, detail))


def latest_probes() -> list[dict]:
    """Latest result per (workload, probe) on the live path (canary probes excluded)."""
    return _query("""SELECT p.* FROM probes p
                     JOIN (SELECT workload_id, probe, MAX(id) AS id FROM probes
                           WHERE via != 'canary' GROUP BY workload_id, probe) l ON p.id = l.id""")


# ------------------------------------------------------------------ audit

def audit(actor: str, action: str, target: Optional[str] = None, detail: Optional[str] = None) -> None:
    _exec("INSERT INTO audit (ts, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
          (time.time(), actor, action, target, detail))


def audit_log(limit: int = 200) -> list[dict]:
    return _query("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))


# -------------------------------------------------------------- vet cache

def vet_cache_get(key: str) -> Optional[dict]:
    rows = _query("SELECT result FROM vet_cache WHERE key = ?", (key,))
    return json.loads(rows[0]["result"]) if rows else None


def vet_cache_put(key: str, result) -> None:
    _exec("INSERT OR REPLACE INTO vet_cache (key, result, ts) VALUES (?, ?, ?)", (key, _dump(result), time.time()))
