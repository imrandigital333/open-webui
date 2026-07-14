"""FastAPI app for the AI Troubleshooter UI.

Run with:  uvicorn app.main:app --host 0.0.0.0 --port 8090
"""

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import orchestrator
from .inventory import load_inventory

app = FastAPI(title="AI Troubleshooter", version="1.0.0")

STATIC_DIR = Path(__file__).resolve().parent / "static"


class SessionRequest(BaseModel):
    server: str = Field(..., description="Server name from the inventory")
    problem: str = Field(..., min_length=10, description="Problem statement")
    # Optional sudo password for the remote SSH user. Held in memory for this
    # one investigation only — never stored, logged, or shown to the AI model.
    sudo_password: str | None = Field(None, repr=False)


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/inventory")
async def get_inventory():
    servers = load_inventory()
    return {"servers": [s.to_public_dict() for s in servers.values()]}


@app.post("/api/sessions")
async def create_session(req: SessionRequest):
    servers = load_inventory()
    server = servers.get(req.server)
    if server is None:
        raise HTTPException(status_code=404, detail=f"Server '{req.server}' not in inventory")
    state = orchestrator.start_session(
        server, req.problem.strip(), sudo_password=req.sudo_password or None
    )
    return state.to_dict()


@app.get("/api/sessions")
async def list_sessions():
    sessions = sorted(orchestrator.SESSIONS.values(), key=lambda s: s.created_at, reverse=True)
    return {"sessions": [s.to_dict() for s in sessions]}


@app.get("/api/sessions/{session_id}")
async def get_session(session_id: str):
    state = orchestrator.SESSIONS.get(session_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return state.to_dict(include_events=True)


@app.get("/api/sessions/{session_id}/events")
async def stream_events(session_id: str):
    state = orchestrator.SESSIONS.get(session_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Session not found")

    async def generate():
        async for event in state.follow():
            yield f"data: {json.dumps(event, default=str)}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
