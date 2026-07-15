"""Persistence layer: sessions, events, health history, audit log.

Works with SQLite (default, zero-ops pilot) and PostgreSQL (production) via
TROUBLESHOOTER_DB, e.g.:
    sqlite:////opt/ai-troubleshooter/data/troubleshooter.db      (default-style)
    postgresql+psycopg://aitrouble_app:***@dbhost/aitroubleshooter

All functions here are synchronous; async callers wrap them in
asyncio.to_thread so the event loop never blocks on the database.
"""

import json
import os
import time
from pathlib import Path

from sqlalchemy import (
    Column,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    delete,
    event as sa_event,
    select,
    update,
)

from .inventory import BASE_DIR

DB_URL = os.environ.get(
    "TROUBLESHOOTER_DB",
    f"sqlite:///{BASE_DIR / 'data' / 'troubleshooter.db'}",
)

metadata = MetaData()

sessions_t = Table(
    "sessions", metadata,
    Column("id", String(32), primary_key=True),
    Column("server", String(100), index=True),
    Column("mode", String(20)),
    Column("problem", Text),
    Column("depth", String(20)),
    Column("layers", Text),          # JSON list
    Column("incident_time", String(64), nullable=True),
    Column("status", String(20), index=True),
    Column("phase", String(30), nullable=True),
    Column("created_at", Float, index=True),
    Column("finished_at", Float, nullable=True),
    Column("duration_ms", Integer, nullable=True),
    Column("cost_usd", Float, nullable=True),
    Column("num_turns", Integer, nullable=True),
    Column("confidence", String(20), nullable=True),
    Column("root_cause_layer", String(40), nullable=True),
    Column("error", Text, nullable=True),
    Column("report", Text, nullable=True),   # JSON
)

events_t = Table(
    "session_events", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("session_id", String(32), index=True),
    Column("ts", Float),
    Column("type", String(30)),
    Column("data", Text),            # JSON (event minus type/ts)
)

health_t = Table(
    "health_snapshots", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("session_id", String(32), index=True),
    Column("server", String(100), index=True),
    Column("ts", Float, index=True),
    Column("aspect", String(30)),
    Column("status", String(20)),
    Column("value", Text),
    Column("note", Text),
)

audit_t = Table(
    "audit_log", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ts", Float, index=True),
    Column("actor", String(120)),
    Column("action", String(60), index=True),
    Column("detail", Text),          # JSON
)

_engine = None


def engine():
    global _engine
    if _engine is None:
        kwargs = {"pool_pre_ping": True}
        if DB_URL.startswith("sqlite"):
            Path(DB_URL.split("///", 1)[-1]).parent.mkdir(parents=True, exist_ok=True)
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
        _engine = create_engine(DB_URL, **kwargs)
        if DB_URL.startswith("sqlite"):
            @sa_event.listens_for(_engine, "connect")
            def _set_wal(dbapi_conn, _record):  # noqa: ANN001
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA busy_timeout=30000")
                cur.close()
    return _engine


def init_db() -> None:
    metadata.create_all(engine())
    # sessions left 'running' by a crash/restart can never finish
    with engine().begin() as conn:
        conn.execute(
            update(sessions_t)
            .where(sessions_t.c.status == "running")
            .values(status="failed", error="Service restarted while the session was running")
        )


# ---------- sessions ----------

def session_started(s: dict) -> None:
    with engine().begin() as conn:
        conn.execute(sessions_t.insert().values(
            id=s["id"], server=s["server"], mode=s["mode"], problem=s["problem"],
            depth=s["depth"], layers=json.dumps(s["layers"]),
            incident_time=s["incident_time"], status="running",
            created_at=s["created_at"],
        ))


def session_phase(session_id: str, phase: str) -> None:
    with engine().begin() as conn:
        conn.execute(update(sessions_t).where(sessions_t.c.id == session_id).values(phase=phase))


def session_finished(s: dict) -> None:
    with engine().begin() as conn:
        conn.execute(update(sessions_t).where(sessions_t.c.id == s["id"]).values(
            status=s["status"], phase=s["phase"], finished_at=time.time(),
            duration_ms=s["duration_ms"], cost_usd=s["cost_usd"], num_turns=s["num_turns"],
            confidence=(s.get("report") or {}).get("confidence"),
            root_cause_layer=(s.get("report") or {}).get("root_cause_layer"),
            error=s["error"], report=json.dumps(s.get("report")) if s.get("report") else None,
        ))


def add_event(session_id: str, ev: dict) -> None:
    data = {k: v for k, v in ev.items() if k not in ("type", "ts")}
    with engine().begin() as conn:
        conn.execute(events_t.insert().values(
            session_id=session_id, ts=ev.get("ts", time.time()),
            type=ev.get("type", ""), data=json.dumps(data, default=str),
        ))


def add_health_snapshot(session_id: str, server: str, checks: dict) -> None:
    ts = time.time()
    rows = [
        {"session_id": session_id, "server": server, "ts": ts, "aspect": aspect,
         "status": (c or {}).get("status", "unknown"),
         "value": (c or {}).get("value", ""), "note": (c or {}).get("note", "")}
        for aspect, c in checks.items()
    ]
    if rows:
        with engine().begin() as conn:
            conn.execute(health_t.insert(), rows)


def _row_to_session(row) -> dict:
    d = dict(row._mapping)
    d["layers"] = json.loads(d.get("layers") or "[]")
    d["report"] = json.loads(d["report"]) if d.get("report") else None
    return d


def list_sessions(limit: int = 200, server: str | None = None) -> list[dict]:
    q = select(sessions_t).order_by(sessions_t.c.created_at.desc()).limit(limit)
    if server:
        q = q.where(sessions_t.c.server == server)
    with engine().connect() as conn:
        return [_row_to_session(r) for r in conn.execute(q)]


def get_session(session_id: str) -> dict | None:
    with engine().connect() as conn:
        row = conn.execute(select(sessions_t).where(sessions_t.c.id == session_id)).first()
        if row is None:
            return None
        session = _row_to_session(row)
        session["events"] = [
            {"type": r.type, "ts": r.ts, **json.loads(r.data or "{}")}
            for r in conn.execute(
                select(events_t).where(events_t.c.session_id == session_id).order_by(events_t.c.id)
            )
        ]
        return session


def health_history(server: str, limit_snapshots: int = 30) -> list[dict]:
    """Recent per-session health snapshots for one server, oldest first."""
    with engine().connect() as conn:
        rows = conn.execute(
            select(health_t).where(health_t.c.server == server)
            .order_by(health_t.c.ts.desc()).limit(limit_snapshots * 12)
        ).fetchall()
    snaps: dict[float, dict] = {}
    for r in rows:
        snaps.setdefault(r.ts, {"ts": r.ts, "session_id": r.session_id, "checks": {}})
        snaps[r.ts]["checks"][r.aspect] = {"status": r.status, "value": r.value}
    return sorted(snaps.values(), key=lambda s: s["ts"])[-limit_snapshots:]


# ---------- audit ----------

def audit(actor: str, action: str, detail: dict | None = None) -> None:
    with engine().begin() as conn:
        conn.execute(audit_t.insert().values(
            ts=time.time(), actor=actor or "anonymous", action=action,
            detail=json.dumps(detail or {}, default=str),
        ))


def list_audit(limit: int = 200) -> list[dict]:
    with engine().connect() as conn:
        return [
            {"ts": r.ts, "actor": r.actor, "action": r.action,
             "detail": json.loads(r.detail or "{}")}
            for r in conn.execute(select(audit_t).order_by(audit_t.c.id.desc()).limit(limit))
        ]


# ---------- retention ----------

def purge_older_than(days: int) -> dict:
    """Delete DB rows AND session directories older than the cutoff."""
    from .orchestrator import SESSIONS_DIR

    cutoff = time.time() - days * 86400
    with engine().connect() as conn:
        old_ids = [r.id for r in conn.execute(
            select(sessions_t.c.id).where(sessions_t.c.created_at < cutoff)
        )]
    removed_dirs = 0
    if old_ids:
        with engine().begin() as conn:
            conn.execute(delete(events_t).where(events_t.c.session_id.in_(old_ids)))
            conn.execute(delete(health_t).where(health_t.c.session_id.in_(old_ids)))
            conn.execute(delete(sessions_t).where(sessions_t.c.id.in_(old_ids)))
        import shutil

        for sid in old_ids:
            target = SESSIONS_DIR / sid
            if target.is_dir():
                shutil.rmtree(target, ignore_errors=True)
                removed_dirs += 1
    return {"sessions_purged": len(old_ids), "dirs_removed": removed_dirs}
