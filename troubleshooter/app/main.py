"""FastAPI app for the AI Troubleshooter UI.

Run with:  uvicorn app.main:app --host 0.0.0.0 --port 8090
"""

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import orchestrator
from .datasources import load_datasources, missing_env_vars, to_public_dict
from .inventory import (
    load_inventory,
    load_raw_inventory,
    save_inventory,
    writable_inventory_path,
)
from .scriptlib import SCRIPTLIB_DIR, list_scripts

APP_VERSION = "2.8.0"

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
async def create_session(req: SessionRequest):
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
    )
    return state.to_dict()


@app.get("/api/fleet")
async def fleet():
    data = orchestrator.scan_fleet()
    servers = load_inventory()
    sources = load_datasources()
    out = []
    for s in servers.values():
        last = data["latest"].get(s.name)
        overall = None
        counts = None
        if last and last.get("checks"):
            counts = {"ok": 0, "warning": 0, "critical": 0, "unknown": 0}
            for v in last["checks"].values():
                st = (v.get("status") or "unknown").lower()
                counts[st if st in counts else "unknown"] += 1
            overall = ("critical" if counts["critical"] else
                       "warning" if counts["warning"] else
                       "ok" if counts["ok"] else "unknown")
        out.append({**s.to_public_dict(), "last": last, "overall": overall, "counts": counts})
    stats = data["stats"]
    stats["servers"] = len(out)
    stats["datasources_ready"] = sum(1 for d in sources.values() if not missing_env_vars(d))
    return {"servers": out, "stats": stats}


@app.get("/api/sessions")
async def list_sessions():
    sessions = sorted(orchestrator.SESSIONS.values(), key=lambda s: s.created_at, reverse=True)
    return {"sessions": [s.to_dict() for s in sessions]}


@app.get("/api/sessions/{session_id}")
async def get_session(session_id: str):
    state = _get_state(session_id)
    return state.to_dict(include_events=True)


@app.post("/api/sessions/{session_id}/cancel")
async def cancel_session(session_id: str):
    state = _get_state(session_id)
    if not state.cancel():
        raise HTTPException(status_code=409, detail="Session is not running")
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


@app.get("/api/sessions/{session_id}/health")
async def get_health(session_id: str):
    state = _get_state(session_id)
    path = state.workdir / "health.json"
    if not path.exists():
        return {"health": None}
    try:
        return {"health": json.loads(path.read_text())}
    except (OSError, json.JSONDecodeError):
        return {"health": None}


@app.get("/api/sessions/{session_id}/files")
async def list_files(session_id: str):
    state = _get_state(session_id)
    workdir = state.workdir.resolve()
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
    state = _get_state(session_id)
    workdir = state.workdir.resolve()
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
    state = _get_state(session_id)
    path = state.workdir / "report.md"
    if not path.exists():
        raise HTTPException(status_code=404, detail="No report.md for this session")
    return FileResponse(
        path,
        media_type="text/markdown",
        filename=f"incident-report-{state.server}-{session_id}.md",
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
async def upsert_server(name: str, entry: ServerEntry):
    servers = load_raw_inventory()
    # remove the entry being edited (by its original name) and any entry that
    # collides with the (possibly renamed) new name
    servers = [s for s in servers if s.get("name") not in (name, entry.name)]
    servers.append(entry.to_yaml_dict())
    save_inventory(servers)
    return {"ok": True, "servers": servers}


@app.delete("/api/admin/inventory/{name}")
async def delete_server(name: str):
    servers = load_raw_inventory()
    remaining = [s for s in servers if s.get("name") != name]
    if len(remaining) == len(servers):
        raise HTTPException(status_code=404, detail=f"Server '{name}' not found")
    save_inventory(remaining)
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
async def delete_script(filename: str):
    target = (SCRIPTLIB_DIR / filename).resolve()
    if not target.is_relative_to(SCRIPTLIB_DIR.resolve()) or not filename.endswith(".sh"):
        raise HTTPException(status_code=403, detail="Forbidden")
    if not target.is_file():
        raise HTTPException(status_code=404, detail="Script not found")
    target.unlink()
    return {"ok": True}


def _get_state(session_id: str) -> orchestrator.SessionState:
    state = orchestrator.SESSIONS.get(session_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return state
