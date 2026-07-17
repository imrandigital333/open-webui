"""FastAPI app for the AI Troubleshooter UI.

Run with:  uvicorn app.main:app --host 0.0.0.0 --port 8090
"""

import asyncio
import contextlib
import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import cmdreview, db, healthprobe, itsm, orchestrator
from .datasources import load_datasources, missing_env_vars, to_public_dict
from .inventory import (
    load_inventory,
    load_raw_inventory,
    save_inventory,
    writable_inventory_path,
)
from .scriptlib import SCRIPTLIB_DIR, list_scripts

APP_VERSION = "2.29.2"

app = FastAPI(title="AI Troubleshooter", version=APP_VERSION)

STATIC_DIR = Path(__file__).resolve().parent / "static"


def _git_commit() -> str:
    try:
        import subprocess

        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=Path(__file__).resolve().parent,
            capture_output=True, text=True, timeout=5,
        ).stdout.strip() or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


GIT_COMMIT = _git_commit()

RETENTION_DAYS = int(os.environ.get("TROUBLESHOOTER_RETENTION_DAYS", "90"))


def _actor(request: Request) -> str:
    """Operator identity from the SSO/reverse proxy, if one is in front."""
    return (
        request.headers.get("X-Remote-User")
        or request.headers.get("X-Forwarded-User")
        or (request.client.host if request.client else "anonymous")
    )


@app.on_event("startup")
async def _startup():
    await asyncio.to_thread(db.init_db)

    async def retention_loop():
        while True:
            if RETENTION_DAYS > 0:
                with contextlib.suppress(Exception):
                    result = await asyncio.to_thread(db.purge_older_than, RETENTION_DAYS)
                    if result["sessions_purged"]:
                        await asyncio.to_thread(db.audit, "system", "retention_purge", result)
            await asyncio.sleep(24 * 3600)

    asyncio.get_running_loop().create_task(retention_loop())


class SessionRequest(BaseModel):
    server: str = Field(..., description="Server name from the inventory")
    # investigate = full incident RCA; healthcheck = fast proactive sweep
    mode: str = Field("investigate", pattern="^(investigate|healthcheck)$")
    problem: str = Field("", max_length=4000, description="Problem statement")
    # Evidence layers (datasource names) to investigate; empty = server only
    layers: list[str] = Field(default_factory=list)
    depth: str = Field("standard", pattern="^(quick|standard|deep)$")
    # Approximate time the problem started, as reported by the operator
    # (free-form; e.g. "2026-07-15T14:30" from the UI's datetime picker)
    incident_time: str | None = Field(None, max_length=64)
    # optional ITSM incident this session was launched from (e.g. "INC-100482")
    incident_id: str | None = Field(None, max_length=64)


@app.get("/")
async def index():
    # no-store: a stale cached UI silently reintroduces old behavior
    return FileResponse(
        STATIC_DIR / "index.html",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/api/version")
async def version():
    return {"version": APP_VERSION, "commit": GIT_COMMIT}


@app.get("/api/selfcheck")
async def selfcheck():
    """Verify the Claude Code pipeline end-to-end with a minimal 1-turn run.

    Use when sessions hang at 'Investigating': if this fails or times out,
    the problem is Claude Code auth / network on this machine, not the app.
    """
    import asyncio

    try:
        from claude_agent_sdk import ClaudeAgentOptions, query
        from claude_agent_sdk.types import ResultMessage
    except ImportError as exc:
        return {"ok": False, "error": f"claude-agent-sdk not installed: {exc}"}
    try:
        options = ClaudeAgentOptions(max_turns=1, allowed_tools=[])
        outcome: dict | None = None
        async with asyncio.timeout(90):
            async for message in query(prompt="Reply with the single word: ok", options=options):
                if isinstance(message, ResultMessage):
                    outcome = {
                        "ok": not message.is_error,
                        "result": (message.result or "")[:200],
                        "error": message.subtype if message.is_error else None,
                    }
        return outcome or {"ok": False, "error": "Claude Code produced no result message"}
    except TimeoutError:
        return {
            "ok": False,
            "error": (
                "Claude Code did not respond within 90s — check that the "
                "service account is logged in (run: claude -p 'say ok') and "
                "that this machine can reach the Claude API."
            ),
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@app.get("/api/inventory")
async def get_inventory():
    servers = load_inventory()
    return {"servers": [s.to_public_dict() for s in servers.values()]}


@app.get("/api/datasources")
async def get_datasources():
    sources = load_datasources()
    out = []
    for ds in sources.values():
        pub = to_public_dict(ds)
        missing = missing_env_vars(ds)
        pub["ready"] = not missing
        pub["missing_env"] = missing
        out.append(pub)
    return {"datasources": out}


@app.post("/api/sessions")
async def create_session(req: SessionRequest, request: Request):
    servers = load_inventory()
    server = servers.get(req.server)
    if server is None:
        raise HTTPException(status_code=404, detail=f"Server '{req.server}' not in inventory")
    if req.mode == "investigate" and len(req.problem.strip()) < 10:
        raise HTTPException(status_code=400, detail="Please describe the problem (at least a sentence)")
    sources = load_datasources()
    unknown = [name for name in req.layers if name not in sources]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown datasources: {', '.join(unknown)}")
    layer_sources = [sources[name] for name in req.layers] if req.mode == "investigate" else []
    state = orchestrator.start_session(
        server,
        req.problem.strip() or "Proactive health check (no reported incident).",
        layer_sources=layer_sources,
        depth=req.depth,
        incident_time=(req.incident_time or "").strip() or None,
        mode=req.mode,
        incident_id=(req.incident_id or "").strip() or None,
    )
    await asyncio.to_thread(
        db.audit, _actor(request), "session_started",
        {"session": state.id, "server": req.server, "mode": req.mode,
         "incident_id": (req.incident_id or "").strip() or None},
    )
    return state.to_dict()


@app.get("/api/itsm/status")
async def itsm_status():
    return itsm.status()


class ItsmConfigRequest(BaseModel):
    api_style: str = Field("summit_wcf", pattern="^(summit_wcf|rest)$")
    base_url: str = Field("", max_length=500)
    token: str = Field("", max_length=1000)          # empty = keep the stored key
    verify_tls: bool = True
    # summit_wcf style
    org_id: int = Field(1, ge=0, le=10_000)
    proxy_id: int = Field(0, ge=0, le=10_000)
    incidents_service: str = Field("IM_FetchIncidents", max_length=100)
    incident_detail_service: str = Field("IM_GetIncidentDetails", max_length=100)
    changes_service: str = Field("CM_FetchChanges", max_length=100)
    incidents_params: str = Field("", max_length=2000)
    # rest style
    auth_header: str = Field("Authorization", max_length=100)
    auth_prefix: str = Field("Bearer ", max_length=50)
    incidents_path: str = Field("/incidents", max_length=200)
    changes_path: str = Field("/changes", max_length=200)


@app.get("/api/admin/itsm")
async def get_itsm_config():
    return itsm.public_config()


@app.put("/api/admin/itsm")
async def save_itsm_config(req: ItsmConfigRequest, request: Request):
    cfg = req.model_dump()
    if not cfg["token"]:
        cfg["token"] = itsm.load_config()["token"]   # keep the stored secret
    await asyncio.to_thread(itsm.save_config, cfg)
    await asyncio.to_thread(db.audit, _actor(request), "itsm_config_saved",
                            {"base_url": cfg["base_url"],
                             "token_changed": bool(req.token)})
    return itsm.public_config()


@app.post("/api/admin/itsm/test")
async def test_itsm_config(req: ItsmConfigRequest, request: Request):
    """Probe the API with the (possibly unsaved) form values."""
    result = await asyncio.to_thread(itsm.test_config, req.model_dump())
    await asyncio.to_thread(db.audit, _actor(request), "itsm_config_tested",
                            {"base_url": req.base_url, "ok": result.get("ok")})
    return result


@app.get("/api/incidents")
async def incidents():
    """Active P1/P2 incidents from SummitAI (demo data until configured)."""
    try:
        rows = await asyncio.to_thread(itsm.list_incidents)
        return {"incidents": rows, **itsm.status()}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"SummitAI unavailable: {exc}")


@app.get("/api/incidents/{incident_id}")
async def incident_detail(incident_id: str):
    try:
        inc = await asyncio.to_thread(itsm.get_incident, incident_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"SummitAI unavailable: {exc}")
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@app.get("/api/changes")
async def changes():
    """Approved changes from SummitAI (dummy view for now)."""
    try:
        return {"changes": await asyncio.to_thread(itsm.list_changes), **itsm.status()}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"SummitAI unavailable: {exc}")


@app.get("/api/fleet")
async def fleet():
    data = orchestrator.scan_fleet()
    servers = load_inventory()
    sources = load_datasources()
    out = []
    for s in servers.values():
        last = data["latest"].get(s.name)
        last_checks = data["latest_checks"].get(s.name)
        overall = None
        counts = None
        # judge overall health from the freshest checks available for the
        # server, even when the newest session (e.g. an investigation) has none
        checks = (last or {}).get("checks") or (last_checks or {}).get("checks")
        if checks:
            counts = {"ok": 0, "warning": 0, "critical": 0, "unknown": 0}
            for v in checks.values():
                st = (v.get("status") or "unknown").lower()
                counts[st if st in counts else "unknown"] += 1
            overall = ("critical" if counts["critical"] else
                       "warning" if counts["warning"] else
                       "ok" if counts["ok"] else "unknown")
        out.append({**s.to_public_dict(), "last": last, "last_checks": last_checks,
                    "overall": overall, "counts": counts})
    stats = data["stats"]
    stats["servers"] = len(out)
    stats["datasources_ready"] = sum(1 for d in sources.values() if not missing_env_vars(d))
    return {"servers": out, "stats": stats}


@app.get("/api/sessions")
async def list_sessions(server: str | None = None, limit: int = 200):
    rows = await asyncio.to_thread(db.list_sessions, min(limit, 500), server)
    # overlay live in-memory state (fresher status/phase for running sessions)
    live = {s.id: s.to_dict() for s in orchestrator.SESSIONS.values()}
    merged = [live.pop(r["id"], r) for r in rows]
    merged.extend(live.values())  # sessions not yet visible in the DB
    merged.sort(key=lambda s: s["created_at"], reverse=True)
    return {"sessions": merged}


@app.get("/api/sessions/{session_id}")
async def get_session(session_id: str):
    state = orchestrator.SESSIONS.get(session_id)
    out = state.to_dict(include_events=True) if state is not None else \
        await asyncio.to_thread(db.get_session, session_id)
    if out is None:
        raise HTTPException(status_code=404, detail="Session not found")
    out["feedback"] = await asyncio.to_thread(db.get_feedback, session_id)
    return out


class FeedbackRequest(BaseModel):
    verdict: str = Field(..., pattern="^(confirmed|rejected)$")
    note: str = Field("", max_length=2000)


@app.post("/api/sessions/{session_id}/feedback")
async def post_feedback(session_id: str, req: FeedbackRequest, request: Request):
    if orchestrator.SESSIONS.get(session_id) is None \
            and await asyncio.to_thread(db.get_session, session_id) is None:
        raise HTTPException(status_code=404, detail="Session not found")
    actor = _actor(request)
    await asyncio.to_thread(db.add_feedback, session_id, actor, req.verdict, req.note)
    await asyncio.to_thread(db.audit, actor, "rca_feedback",
                            {"session": session_id, "verdict": req.verdict})
    return {"ok": True}


class ReinvestigateRequest(BaseModel):
    context: str = Field(..., min_length=5, max_length=4000,
                         description="New details: symptoms, exact log paths, what was tried")


@app.post("/api/sessions/{session_id}/reinvestigate")
async def reinvestigate(session_id: str, req: ReinvestigateRequest, request: Request):
    parent = await _load_any_session(session_id)
    if parent.get("mode") != "investigate":
        raise HTTPException(status_code=400, detail="Only investigations can be re-investigated")
    server = load_inventory().get(parent["server"])
    if server is None:
        raise HTTPException(status_code=404, detail=f"Server '{parent['server']}' no longer in inventory")
    prev = parent.get("report") or {}
    problem = (
        f"{parent['problem']}\n\n"
        f"REINVESTIGATION — a previous investigation (session {session_id}) concluded: "
        f"\"{str(prev.get('probable_root_cause', 'no conclusion'))[:400]}\" "
        f"({prev.get('confidence', '?')} confidence). The operator says this did NOT "
        f"resolve or explain the issue. Do not simply repeat that conclusion — "
        f"re-verify it and actively pursue alternatives.\n\n"
        f"ADDITIONAL CONTEXT FROM THE OPERATOR:\n{req.context.strip()}"
    )
    actor = _actor(request)
    # a reinvestigation implies the previous conclusion didn't hold
    await asyncio.to_thread(db.add_feedback, session_id, actor, "rejected",
                            f"reinvestigated with new context: {req.context.strip()[:200]}")
    sources = load_datasources()
    layer_sources = [sources[n] for n in parent.get("layers", []) if n in sources]
    state = orchestrator.start_session(
        server, problem, layer_sources=layer_sources, depth="deep",
        incident_time=parent.get("incident_time"), mode="investigate",
    )
    await asyncio.to_thread(db.audit, actor, "reinvestigation_started",
                            {"session": state.id, "parent": session_id})
    return state.to_dict()


@app.post("/api/sessions/{session_id}/remediate")
async def remediate(session_id: str, request: Request):
    parent = await _load_any_session(session_id)
    report = parent.get("report") or {}
    plan = report.get("remediation_plan") or []
    if not plan:
        raise HTTPException(status_code=400, detail="This session's report has no remediation plan")
    server = load_inventory().get(parent["server"])
    if server is None:
        raise HTTPException(status_code=404, detail=f"Server '{parent['server']}' no longer in inventory")
    actor = _actor(request)
    state = orchestrator.start_session(
        server,
        f"Execute approved remediation for: {parent['problem'][:200]}",
        mode="remediate",
        remediation={
            "plan": plan,
            "problem": parent["problem"][:400],
            "root_cause": str(report.get("probable_root_cause", ""))[:400],
            "parent_id": session_id,
        },
    )
    await asyncio.to_thread(db.audit, actor, "remediation_started",
                            {"session": state.id, "parent": session_id,
                             "steps": len(plan)})
    return state.to_dict()


class RunStepRequest(BaseModel):
    order: int = Field(..., ge=0, le=999)


class RunCmdRequest(BaseModel):
    command: str = Field(..., min_length=1, max_length=2000)


async def _ssh_exec(server, command: str) -> dict:
    """Run one command on the target over SSH, no agent involved."""
    cmd = server.ssh_command().split() + [command]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=90)
    except asyncio.TimeoutError:
        proc.kill()
        return {"ok": False, "exit_code": -1, "output": "Timed out after 90s"}
    except OSError as exc:
        return {"ok": False, "exit_code": -1, "output": str(exc)}
    return {"ok": proc.returncode == 0, "exit_code": proc.returncode,
            "output": out.decode(errors="replace")[-4000:]}


@app.post("/api/sessions/{session_id}/run-step")
async def run_step(session_id: str, req: RunStepRequest, request: Request):
    """Execute ONE approved remediation command over SSH and return its output.

    No agent involved — direct execution of the exact command the operator
    clicked, fully audited. Powers the per-command Run buttons in the UI.
    """
    parent = await _load_any_session(session_id)
    plan = (parent.get("report") or {}).get("remediation_plan") or []
    step = next((s for s in plan if s.get("order") == req.order), None)
    if step is None:
        raise HTTPException(status_code=404, detail="No such step in the remediation plan")
    server = load_inventory().get(parent["server"])
    if server is None:
        raise HTTPException(status_code=404, detail=f"Server '{parent['server']}' no longer in inventory")
    actor = _actor(request)
    await asyncio.to_thread(db.audit, actor, "remediation_step_run",
                            {"session": session_id, "order": req.order,
                             "command": step.get("command", "")[:300]})
    return await _ssh_exec(server, step.get("command", ""))


@app.post("/api/sessions/{session_id}/review-cmd")
async def review_cmd(session_id: str, req: RunCmdRequest, request: Request):
    """Assess an operator-typed command BEFORE execution: policy classification
    (readonly/modifies/dangerous/blocked) plus an AI impact summary, suggested
    backup command and worst-case damage. Blocked verdicts cannot be overridden."""
    parent = await _load_any_session(session_id)
    server = load_inventory().get(parent["server"])
    if server is None:
        raise HTTPException(status_code=404, detail=f"Server '{parent['server']}' no longer in inventory")
    result = await cmdreview.review(req.command, server)
    await asyncio.to_thread(db.audit, _actor(request), "command_reviewed",
                            {"session": session_id, "command": req.command[:300],
                             "verdict": result["verdict"]})
    return result


@app.post("/api/sessions/{session_id}/run-cmd")
async def run_cmd(session_id: str, req: RunCmdRequest, request: Request):
    """Execute ONE operator-typed command on the session's server over SSH.

    Powers the chat's ad-hoc `!command` input — the operator explicitly types
    and confirms the exact command; every run is audited with its full text.
    Policy-blocked commands are refused here too, independent of the UI.
    """
    parent = await _load_any_session(session_id)
    server = load_inventory().get(parent["server"])
    if server is None:
        raise HTTPException(status_code=404, detail=f"Server '{parent['server']}' no longer in inventory")
    verdict, why = cmdreview.classify(req.command)
    actor = _actor(request)
    if verdict == "blocked":
        await asyncio.to_thread(db.audit, actor, "adhoc_command_blocked",
                                {"session": session_id, "command": req.command[:500], "reason": why})
        raise HTTPException(status_code=403, detail=f"Blocked by policy: this command {why}")
    await asyncio.to_thread(db.audit, actor, "adhoc_command_run",
                            {"session": session_id, "command": req.command[:500],
                             "verdict": verdict})
    return await _ssh_exec(server, req.command)


async def _load_any_session(session_id: str) -> dict:
    state = orchestrator.SESSIONS.get(session_id)
    if state is not None:
        return state.to_dict()
    row = await asyncio.to_thread(db.get_session, session_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return row


@app.post("/api/sessions/{session_id}/cancel")
async def cancel_session(session_id: str, request: Request):
    state = _get_state(session_id)
    if not state.cancel():
        raise HTTPException(status_code=409, detail="Session is not running")
    await asyncio.to_thread(db.audit, _actor(request), "session_cancelled", {"session": session_id})
    return {"ok": True}


@app.get("/api/sessions/{session_id}/events")
async def stream_events(session_id: str):
    state = _get_state(session_id)

    async def generate():
        async for event in state.follow():
            yield f"data: {json.dumps(event, default=str)}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _session_workdir(session_id: str) -> Path:
    """Session working directory — valid for live AND historical sessions."""
    state = orchestrator.SESSIONS.get(session_id)
    if state is not None:
        return state.workdir
    if not session_id.isalnum() or len(session_id) > 32:
        raise HTTPException(status_code=404, detail="Session not found")
    workdir = orchestrator.SESSIONS_DIR / session_id
    if not workdir.is_dir():
        raise HTTPException(status_code=404, detail="Session files not found (purged?)")
    return workdir


@app.get("/api/sessions/{session_id}/health")
async def get_health(session_id: str):
    path = _session_workdir(session_id) / "health.json"
    if not path.exists():
        return {"health": None}
    try:
        return {"health": json.loads(path.read_text())}
    except (OSError, json.JSONDecodeError):
        return {"health": None}


@app.get("/api/sessions/{session_id}/files")
async def list_files(session_id: str):
    workdir = _session_workdir(session_id).resolve()
    files = []
    if workdir.exists():
        for path in sorted(workdir.rglob("*")):
            if path.is_file():
                rel = path.relative_to(workdir).as_posix()
                if rel.startswith(("remote", ".")):  # skip wrapper scripts
                    continue
                files.append({"path": rel, "size": path.stat().st_size})
    return {"files": files}


@app.get("/api/sessions/{session_id}/files/{file_path:path}")
async def get_file(session_id: str, file_path: str):
    workdir = _session_workdir(session_id).resolve()
    target = (workdir / file_path).resolve()
    if not target.is_relative_to(workdir) or target.name.startswith("remote"):
        raise HTTPException(status_code=403, detail="Forbidden path")
    if not target.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    if target.stat().st_size > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large to view; read it on the server")
    return PlainTextResponse(target.read_text(errors="replace"))


@app.get("/api/sessions/{session_id}/report.md")
async def download_report(session_id: str):
    path = _session_workdir(session_id) / "report.md"
    if not path.exists():
        raise HTTPException(status_code=404, detail="No report.md for this session")
    return FileResponse(
        path,
        media_type="text/markdown",
        filename=f"incident-report-{session_id}.md",
    )


class ServerEntry(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, pattern=r"^[\w.\-]+$")
    host: str = Field(..., min_length=1, max_length=255)
    user: str = Field(..., min_length=1, max_length=64)
    port: int = Field(22, ge=1, le=65535)
    ssh_key: str | None = Field(None, max_length=512)
    description: str = Field("", max_length=500)
    os: str = Field("", max_length=100)
    tags: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    log_hints: list[str] = Field(default_factory=list)

    def to_yaml_dict(self) -> dict:
        out = {"name": self.name, "host": self.host, "port": self.port, "user": self.user}
        if self.ssh_key:
            out["ssh_key"] = self.ssh_key
        for key in ("description", "os"):
            if getattr(self, key):
                out[key] = getattr(self, key)
        for key in ("tags", "services", "log_hints"):
            if getattr(self, key):
                out[key] = getattr(self, key)
        return out


@app.get("/api/admin/inventory")
async def admin_inventory():
    return {"servers": load_raw_inventory(), "path": str(writable_inventory_path())}


@app.put("/api/admin/inventory/{name}")
async def upsert_server(name: str, entry: ServerEntry, request: Request):
    servers = load_raw_inventory()
    # remove the entry being edited (by its original name) and any entry that
    # collides with the (possibly renamed) new name
    servers = [s for s in servers if s.get("name") not in (name, entry.name)]
    servers.append(entry.to_yaml_dict())
    save_inventory(servers)
    await asyncio.to_thread(
        db.audit, _actor(request), "inventory_upsert",
        {"name": entry.name, "renamed_from": name if name != entry.name else None,
         "host": entry.host},
    )
    return {"ok": True, "servers": servers}


@app.delete("/api/admin/inventory/{name}")
async def delete_server(name: str, request: Request):
    servers = load_raw_inventory()
    remaining = [s for s in servers if s.get("name") != name]
    if len(remaining) == len(servers):
        raise HTTPException(status_code=404, detail=f"Server '{name}' not found")
    save_inventory(remaining)
    await asyncio.to_thread(db.audit, _actor(request), "inventory_delete", {"name": name})
    return {"ok": True}


@app.post("/api/admin/inventory/{name}/test")
async def test_server(name: str):
    """SSH reachability test for one inventory server (10s timeout)."""
    import asyncio

    servers = load_inventory()
    server = servers.get(name)
    if server is None:
        raise HTTPException(status_code=404, detail=f"Server '{name}' not found")
    cmd = server.ssh_command().split() + ["echo CONNECTION_OK && uname -a"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=15)
    except asyncio.TimeoutError:
        proc.kill()
        return {"ok": False, "detail": "Timed out after 15s"}
    except OSError as exc:
        return {"ok": False, "detail": str(exc)}
    if proc.returncode == 0 and b"CONNECTION_OK" in out:
        return {"ok": True, "detail": out.decode(errors="replace").strip()}
    return {"ok": False, "detail": (err.decode(errors="replace") or out.decode(errors="replace")).strip()[:500]}


@app.get("/api/scripts")
async def get_scripts():
    return {"scripts": list_scripts(), "path": str(SCRIPTLIB_DIR)}


@app.get("/api/scripts/{filename}")
async def get_script(filename: str):
    target = (SCRIPTLIB_DIR / filename).resolve()
    if not target.is_relative_to(SCRIPTLIB_DIR.resolve()) or not filename.endswith(".sh"):
        raise HTTPException(status_code=403, detail="Forbidden")
    if not target.is_file():
        raise HTTPException(status_code=404, detail="Script not found")
    return PlainTextResponse(target.read_text(errors="replace"))


@app.delete("/api/scripts/{filename}")
async def delete_script(filename: str, request: Request):
    target = (SCRIPTLIB_DIR / filename).resolve()
    if not target.is_relative_to(SCRIPTLIB_DIR.resolve()) or not filename.endswith(".sh"):
        raise HTTPException(status_code=403, detail="Forbidden")
    if not target.is_file():
        raise HTTPException(status_code=404, detail="Script not found")
    target.unlink()
    await asyncio.to_thread(db.audit, _actor(request), "script_deleted", {"file": filename})
    return {"ok": True}


@app.get("/api/audit")
async def get_audit(limit: int = 200):
    return {"audit": await asyncio.to_thread(db.list_audit, min(limit, 1000))}


@app.post("/api/servers/{name}/probe")
async def start_probe(name: str, force: bool = False):
    """Kick an agentless live health probe (six SSH command groups, scored
    deterministically — no agent, no tokens). Returns the current state;
    poll GET to watch it fill group by group. force=1 bypasses the
    freshness cache for an on-demand re-probe."""
    server = load_inventory().get(name)
    if server is None:
        raise HTTPException(status_code=404, detail=f"Server '{name}' not in inventory")
    asyncio.get_running_loop().create_task(healthprobe.run_probe(server, force=force))
    return healthprobe.state(name)


@app.get("/api/servers/{name}/probe")
async def get_probe(name: str):
    return healthprobe.state(name)


@app.get("/api/servers/{name}/health-history")
async def get_health_history(name: str, limit: int = 30):
    return {"history": await asyncio.to_thread(db.health_history, name, min(limit, 100))}


def _get_state(session_id: str) -> orchestrator.SessionState:
    state = orchestrator.SESSIONS.get(session_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return state
