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
    Column("incident_id", String(64), nullable=True, index=True),
    Column("status", String(20), index=True),
    Column("phase", String(30), nullable=True),
    Column("created_at", Float, index=True),
    Column("finished_at", Float, nullable=True),
    Column("duration_ms", Integer, nullable=True),
    Column("cost_usd", Float, nullable=True),
    Column("num_turns", Integer, nullable=True),
    Column("input_tokens", Integer, nullable=True),
    Column("output_tokens", Integer, nullable=True),
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

feedback_t = Table(
    "rca_feedback", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("session_id", String(32), index=True),
    Column("ts", Float),
    Column("actor", String(120)),
    Column("verdict", String(20)),   # confirmed | rejected
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

# ---- knowledge base (RAG) ----
kb_docs_t = Table(
    "kb_docs", metadata,
    Column("id", String(32), primary_key=True),
    Column("title", Text),
    Column("source_type", String(20)),            # upload | text | chat
    Column("filename", Text, nullable=True),
    Column("server", String(100), index=True),    # '' = general / fleet-wide
    Column("os", String(40)),                      # linux | windows | ''
    Column("category", String(40), index=True),    # network|application|process|kb_article|config|design|manual|general
    Column("summary", Text),
    Column("keywords", Text),                      # JSON list
    Column("body", Text),                          # full extracted text
    Column("created_at", Float, index=True),
    Column("actor", String(120), nullable=True),
    Column("tokens_in", Integer, nullable=True),
    Column("tokens_out", Integer, nullable=True),
    Column("content_hash", String(64), index=True, nullable=True),
)

kb_chunks_t = Table(
    "kb_chunks", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("doc_id", String(32), index=True),
    Column("ordinal", Integer),
    Column("server", String(100), index=True),
    Column("os", String(40)),
    Column("category", String(40)),
    Column("text", Text),
    Column("keywords", Text),                      # space-joined lowercase tokens for lexical scoring
)

kb_usage_t = Table(
    "kb_usage", metadata,
    Column("id", Integer, primary_key=True),       # single accumulating row, id=1
    Column("input_tokens", Integer),
    Column("output_tokens", Integer),
    Column("cache_read_tokens", Integer),
    Column("cache_write_tokens", Integer),
    Column("calls", Integer),
    Column("model", String(80)),
)

_engine = None
_fts_ok = False   # SQLite FTS5 full-text index available? (set in init)


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
    # lightweight in-place migration: columns added after the first release.
    # create_all never ALTERs, so add them best-effort (no-op once present).
    import contextlib as _ctx
    from sqlalchemy import text as _text

    for ddl in (
        "ALTER TABLE sessions ADD COLUMN input_tokens INTEGER",
        "ALTER TABLE sessions ADD COLUMN output_tokens INTEGER",
        "ALTER TABLE sessions ADD COLUMN incident_id VARCHAR(64)",
        "ALTER TABLE kb_docs ADD COLUMN content_hash VARCHAR(64)",
    ):
        with _ctx.suppress(Exception), engine().begin() as conn:
            conn.execute(_text(ddl))
    _kb_fts_init()
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
            incident_time=s["incident_time"], incident_id=s.get("incident_id"),
            status="running", created_at=s["created_at"],
        ))


def session_phase(session_id: str, phase: str) -> None:
    with engine().begin() as conn:
        conn.execute(update(sessions_t).where(sessions_t.c.id == session_id).values(phase=phase))


def session_finished(s: dict) -> None:
    with engine().begin() as conn:
        conn.execute(update(sessions_t).where(sessions_t.c.id == s["id"]).values(
            status=s["status"], phase=s["phase"], finished_at=time.time(),
            duration_ms=s["duration_ms"], cost_usd=s["cost_usd"], num_turns=s["num_turns"],
            input_tokens=s.get("input_tokens"), output_tokens=s.get("output_tokens"),
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
            # 40 rows per snapshot leaves headroom over the 20 tracked aspects
            .order_by(health_t.c.ts.desc()).limit(limit_snapshots * 40)
        ).fetchall()
    snaps: dict[float, dict] = {}
    for r in rows:
        snaps.setdefault(r.ts, {"ts": r.ts, "session_id": r.session_id, "checks": {}})
        snaps[r.ts]["checks"][r.aspect] = {"status": r.status, "value": r.value}
    return sorted(snaps.values(), key=lambda s: s["ts"])[-limit_snapshots:]


def add_feedback(session_id: str, actor: str, verdict: str, note: str = "") -> None:
    with engine().begin() as conn:
        conn.execute(feedback_t.insert().values(
            session_id=session_id, ts=time.time(), actor=actor or "anonymous",
            verdict=verdict, note=note[:2000],
        ))


def get_feedback(session_id: str) -> dict | None:
    with engine().connect() as conn:
        row = conn.execute(
            select(feedback_t).where(feedback_t.c.session_id == session_id)
            .order_by(feedback_t.c.id.desc()).limit(1)
        ).first()
    if row is None:
        return None
    return {"verdict": row.verdict, "note": row.note, "ts": row.ts, "actor": row.actor}


def past_incidents(server: str, exclude_id: str, limit: int = 3) -> list[dict]:
    """Recent completed investigations on this server, for agent context."""
    with engine().connect() as conn:
        rows = conn.execute(
            select(sessions_t)
            .where(sessions_t.c.server == server)
            .where(sessions_t.c.mode == "investigate")
            .where(sessions_t.c.status == "completed")
            .where(sessions_t.c.id != exclude_id)
            .where(sessions_t.c.report.is_not(None))
            .order_by(sessions_t.c.created_at.desc())
            .limit(limit)
        ).fetchall()
    out = []
    for r in rows:
        report = json.loads(r.report) if r.report else {}
        cause = report.get("probable_root_cause")
        if not cause:
            continue
        fb = get_feedback(r.id)
        verdict_note = ""
        if fb and fb["verdict"] == "confirmed":
            verdict_note = " [OPERATOR-CONFIRMED correct]"
        elif fb and fb["verdict"] == "rejected":
            verdict_note = " [operator marked this conclusion INCORRECT — do not repeat it without new evidence]"
        out.append({
            "created_at": r.created_at,
            "problem": (r.problem or "")[:120],
            "confidence": r.confidence or report.get("confidence", "-"),
            "cause": str(cause)[:300] + verdict_note,
        })
    return out


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


# ---------- knowledge base (RAG) ----------

def _kb_fts_init() -> None:
    """Create the SQLite FTS5 index (fast, scan-free retrieval) and backfill it.
    No-op on non-SQLite or when FTS5 is unavailable — retrieval falls back to a
    linear scan then."""
    global _fts_ok
    _fts_ok = False
    if not DB_URL.startswith("sqlite"):
        return
    from sqlalchemy import text as _text
    try:
        with engine().begin() as conn:
            conn.execute(_text(
                "CREATE VIRTUAL TABLE IF NOT EXISTS kb_fts USING fts5("
                "text, keywords, doc_id UNINDEXED, server UNINDEXED, "
                "os UNINDEXED, category UNINDEXED, tokenize='unicode61')"))
            cnt = conn.execute(_text("SELECT count(*) FROM kb_fts")).scalar() or 0
            have = conn.execute(select(kb_chunks_t.c.id).limit(1)).first()
            if not cnt and have:                       # backfill existing chunks
                for r in conn.execute(select(kb_chunks_t)):
                    conn.execute(_text(
                        "INSERT INTO kb_fts(text,keywords,doc_id,server,os,category) "
                        "VALUES(:t,:k,:d,:s,:o,:c)"),
                        {"t": r.text or "", "k": r.keywords or "", "d": r.doc_id,
                         "s": r.server or "", "o": r.os or "", "c": r.category or ""})
        _fts_ok = True
    except Exception:  # noqa: BLE001 - FTS5 not compiled in; use the scan fallback
        _fts_ok = False


def kb_add_doc(doc: dict) -> None:
    with engine().begin() as conn:
        conn.execute(kb_docs_t.insert().values(
            id=doc["id"], title=doc.get("title", ""),
            source_type=doc.get("source_type", "text"), filename=doc.get("filename"),
            server=doc.get("server", ""), os=doc.get("os", ""),
            category=doc.get("category", "general"), summary=doc.get("summary", ""),
            keywords=json.dumps(doc.get("keywords", [])), body=doc.get("body", ""),
            created_at=doc.get("created_at") or time.time(), actor=doc.get("actor"),
            tokens_in=doc.get("tokens_in"), tokens_out=doc.get("tokens_out"),
            content_hash=doc.get("content_hash"),
        ))


def kb_find_by_hash(content_hash: str) -> dict | None:
    if not content_hash:
        return None
    with engine().connect() as conn:
        r = conn.execute(select(kb_docs_t).where(
            kb_docs_t.c.content_hash == content_hash)).first()
        return _kb_doc_row(r) if r else None


def kb_add_chunks(rows: list[dict]) -> None:
    if not rows:
        return
    with engine().begin() as conn:
        conn.execute(kb_chunks_t.insert(), rows)
    if _fts_ok:
        from sqlalchemy import text as _text
        with engine().begin() as conn:
            for r in rows:
                conn.execute(_text(
                    "INSERT INTO kb_fts(text,keywords,doc_id,server,os,category) "
                    "VALUES(:t,:k,:d,:s,:o,:c)"),
                    {"t": r.get("text", ""), "k": r.get("keywords", ""),
                     "d": r.get("doc_id"), "s": r.get("server", ""),
                     "o": r.get("os", ""), "c": r.get("category", "")})


def kb_fts_search(terms: list[str], server: str, limit: int) -> list[dict] | None:
    """FTS5 ranked search. Returns None when FTS is unavailable (caller then
    falls back to the linear scan); returns [] when there are simply no hits."""
    if not _fts_ok:
        return None
    from sqlalchemy import text as _text
    safe = [t for t in ('"%s"' % t.replace('"', '') for t in terms) if len(t) > 2]
    if not safe:
        return []
    match = " OR ".join(safe)
    sql = ("SELECT text, doc_id, server, os, category, bm25(kb_fts) AS rank "
           "FROM kb_fts WHERE kb_fts MATCH :q")
    params = {"q": match, "k": int(limit)}
    if server:
        sql += " AND (server = :s OR server = '')"
        params["s"] = server
    sql += " ORDER BY rank LIMIT :k"
    try:
        with engine().connect() as conn:
            return [{"text": r.text, "doc_id": r.doc_id, "server": r.server or "",
                     "os": r.os or "", "category": r.category or "", "rank": r.rank}
                    for r in conn.execute(_text(sql), params)]
    except Exception:  # noqa: BLE001 - malformed MATCH etc.
        return None


def _kb_doc_row(r) -> dict:
    return {"id": r.id, "title": r.title, "source_type": r.source_type,
            "filename": r.filename, "server": r.server or "", "os": r.os or "",
            "category": r.category or "general", "summary": r.summary or "",
            "keywords": json.loads(r.keywords or "[]"), "created_at": r.created_at,
            "actor": r.actor, "tokens_in": r.tokens_in, "tokens_out": r.tokens_out}


def kb_list_docs() -> list[dict]:
    with engine().connect() as conn:
        return [_kb_doc_row(r) for r in conn.execute(
            select(kb_docs_t).order_by(kb_docs_t.c.created_at.desc()))]


def kb_get_doc(doc_id: str) -> dict | None:
    with engine().connect() as conn:
        r = conn.execute(select(kb_docs_t).where(kb_docs_t.c.id == doc_id)).first()
        if not r:
            return None
        d = _kb_doc_row(r)
        d["body"] = r.body or ""
        return d


def kb_delete_doc(doc_id: str) -> None:
    with engine().begin() as conn:
        conn.execute(delete(kb_chunks_t).where(kb_chunks_t.c.doc_id == doc_id))
        conn.execute(delete(kb_docs_t).where(kb_docs_t.c.id == doc_id))
    if _fts_ok:
        from sqlalchemy import text as _text
        try:
            with engine().begin() as conn:
                conn.execute(_text("DELETE FROM kb_fts WHERE doc_id = :d"), {"d": doc_id})
        except Exception:  # noqa: BLE001
            pass


def kb_candidate_chunks(server: str = "") -> list[dict]:
    """Chunks for lexical scoring. When a server is given, return that server's
    chunks plus general (unscoped) knowledge; otherwise return everything."""
    with engine().connect() as conn:
        q = select(kb_chunks_t)
        if server:
            q = q.where((kb_chunks_t.c.server == server) | (kb_chunks_t.c.server == "")
                        | (kb_chunks_t.c.server.is_(None)))
        return [{"id": r.id, "doc_id": r.doc_id, "ordinal": r.ordinal,
                 "server": r.server or "", "os": r.os or "", "category": r.category or "",
                 "text": r.text or "", "keywords": r.keywords or ""}
                for r in conn.execute(q)]


def kb_stats() -> dict:
    from sqlalchemy import func
    with engine().connect() as conn:
        docs = conn.execute(select(func.count()).select_from(kb_docs_t)).scalar() or 0
        chunks = conn.execute(select(func.count()).select_from(kb_chunks_t)).scalar() or 0
        servers = conn.execute(
            select(func.count(func.distinct(kb_docs_t.c.server)))
            .where(kb_docs_t.c.server != "")).scalar() or 0
    return {"docs": int(docs), "chunks": int(chunks), "servers": int(servers)}


def kb_usage_get() -> dict:
    with engine().connect() as conn:
        r = conn.execute(select(kb_usage_t).where(kb_usage_t.c.id == 1)).first()
    if not r:
        return {"input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0,
                "cache_write_tokens": 0, "calls": 0, "model": None}
    return {"input_tokens": r.input_tokens or 0, "output_tokens": r.output_tokens or 0,
            "cache_read_tokens": r.cache_read_tokens or 0,
            "cache_write_tokens": r.cache_write_tokens or 0,
            "calls": r.calls or 0, "model": r.model}


def kb_usage_add(u: dict) -> None:
    cur = kb_usage_get()
    vals = {
        "input_tokens": cur["input_tokens"] + int(u.get("input_tokens") or 0),
        "output_tokens": cur["output_tokens"] + int(u.get("output_tokens") or 0),
        "cache_read_tokens": cur["cache_read_tokens"] + int(u.get("cache_read_tokens") or 0),
        "cache_write_tokens": cur["cache_write_tokens"] + int(u.get("cache_write_tokens") or 0),
        "calls": cur["calls"] + 1,
        "model": u.get("model") or cur["model"],
    }
    with engine().begin() as conn:
        if conn.execute(select(kb_usage_t.c.id).where(kb_usage_t.c.id == 1)).first():
            conn.execute(kb_usage_t.update().where(kb_usage_t.c.id == 1).values(**vals))
        else:
            conn.execute(kb_usage_t.insert().values(id=1, **vals))
