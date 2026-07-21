"""FastAPI app for the AI Troubleshooter UI.

Run with:  uvicorn app.main:app --host 0.0.0.0 --port 8090
"""

import asyncio
import contextlib
import json
import os
import time
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import changeplan, cmdreview, db, discovery, healthprobe, itsm, orchestrator, winexec
from .datasources import load_datasources, missing_env_vars, to_public_dict
from .inventory import (
    load_inventory,
    load_raw_inventory,
    save_inventory,
    writable_inventory_path,
)
from .scriptlib import SCRIPTLIB_DIR, list_scripts

APP_VERSION = "2.64.0"

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


@app.get("/api/ai/health")
async def ai_health():
    """Probe the Claude Agent SDK with a trivial one-shot call so operators can
    see whether (and why) AI features like plan generation are working."""
    data, err = await changeplan._one_shot_json(
        'Reply with ONLY this JSON: {"ok": true}', timeout_s=60)
    return {"ok": bool(data), "error": err,
            "detail": ("AI is reachable — plan generation and validation will work."
                       if data else
                       "AI is NOT reachable from the service. Plan generation/validation "
                       "will fall back. Ensure the service account is logged in to Claude "
                       "Code (the same login the troubleshooting agent uses) and the "
                       "`claude` CLI is on its PATH.")}


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
    use_proxy: bool = False
    # summit_wcf style
    wcf_operation: str = Field("RESTService/CommonWS_JsonObjCall", max_length=200)
    org_id: int = Field(1, ge=0, le=10_000)
    proxy_id: int = Field(0, ge=0, le=10_000)
    incidents_service: str = Field("IM_GetIncidentList", max_length=100)
    incident_detail_service: str = Field("IM_GetIncidentDetailsAndChangeHistory", max_length=100)
    update_service: str = Field("IM_LogOrUpdateIncident", max_length=100)
    changes_service: str = Field("CM_FetchChanges", max_length=100)
    change_detail_service: str = Field("CM_GetCR_Details", max_length=100)
    change_update_service: str = Field("CM_LogOrUpdateCR", max_length=100)
    change_token: str = Field("", max_length=1000)   # empty = keep stored change key
    change_statuses: str = Field("", max_length=300)
    change_list_filter_key: str = Field("objChangeCommonFilter", max_length=60)
    change_lookback_days: int = Field(30, ge=1, le=365)
    change_support_function: str = Field("IT", max_length=60)
    change_support_function_name: str = Field("BIAL Services", max_length=120)
    change_create_status: str = Field("Initial Authorization", max_length=60)
    change_default_workgroup: str = Field("Windows Server Support", max_length=120)
    change_workgroups: str = Field("Windows Server Support,Unix Server Support", max_length=500)
    change_owner_workgroup_id: str = Field("12", max_length=20)
    change_category_name: str = Field("Minor", max_length=60)
    change_category_id: int = Field(132, ge=0, le=10_000_000)
    change_executive_id: str = Field("2", max_length=20)
    change_classification: str = Field("Normal", max_length=60)
    caller_email: str = Field("", max_length=200)
    instance: str = Field("IT", max_length=50)
    incident_statuses: str = Field("New,In-Progress,Assigned,Pending,Resolved,Closed",
                                   max_length=300)
    lookback_days: int = Field(30, ge=1, le=365)
    page_size: int = Field(100, ge=1, le=1000)
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
    stored = itsm.load_config()
    if not cfg["token"]:
        cfg["token"] = stored["token"]                 # keep the stored secret
    if not cfg.get("change_token"):
        cfg["change_token"] = stored["change_token"]   # keep the stored change key
    await asyncio.to_thread(itsm.save_config, cfg)
    await asyncio.to_thread(db.audit, _actor(request), "itsm_config_saved",
                            {"base_url": cfg["base_url"],
                             "token_changed": bool(req.token),
                             "change_token_changed": bool(req.change_token)})
    return itsm.public_config()


@app.post("/api/admin/itsm/test")
async def test_itsm_config(req: ItsmConfigRequest, request: Request):
    """Probe the API with the (possibly unsaved) form values."""
    result = await asyncio.to_thread(itsm.test_config, req.model_dump())
    await asyncio.to_thread(db.audit, _actor(request), "itsm_config_tested",
                            {"base_url": req.base_url, "ok": result.get("ok")})
    return result


class ItsmChangeTestRequest(ItsmConfigRequest):
    cr_id: str = Field("", max_length=64)   # known CR → test the detail service


@app.post("/api/admin/itsm/test-change")
async def test_itsm_change_config(req: ItsmChangeTestRequest, request: Request):
    """Probe the CHANGE integration (its own API key) with form values."""
    result = await asyncio.to_thread(itsm.test_change_config, req.model_dump(), req.cr_id)
    await asyncio.to_thread(db.audit, _actor(request), "itsm_change_tested",
                            {"base_url": req.base_url, "ok": result.get("ok"),
                             "mode": result.get("mode")})
    return result


@app.post("/api/admin/itsm/discover-changes")
async def discover_itsm_change_services(req: ItsmConfigRequest, request: Request):
    """Read-only sweep of common SummitAI change-list ServiceNames."""
    result = await asyncio.to_thread(itsm.discover_change_services, req.model_dump())
    await asyncio.to_thread(db.audit, _actor(request), "itsm_change_services_probed",
                            {"base_url": req.base_url,
                             "hits": sum(1 for r in result.get("results", []) if r.get("ok"))})
    return result


class ItsmDiscoverRequest(ItsmConfigRequest):
    ticket_no: str = Field("", max_length=64)   # known ticket → also probe detail services


@app.post("/api/admin/itsm/discover")
async def discover_itsm_services(req: ItsmDiscoverRequest, request: Request):
    """Read-only sweep of common SummitAI ServiceNames with the form values."""
    result = await asyncio.to_thread(itsm.discover_services, req.model_dump(), req.ticket_no)
    await asyncio.to_thread(db.audit, _actor(request), "itsm_services_probed",
                            {"base_url": req.base_url,
                             "hits": sum(1 for r in result.get("results", []) if r.get("ok"))})
    return result


@app.get("/api/incidents")
async def incidents():
    """All incidents from SummitAI's configured window (demo data until
    configured) — priority/status slicing happens client-side."""
    try:
        rows = await asyncio.to_thread(itsm.list_incidents, None, True)
        return {"incidents": rows, **itsm.status()}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"SummitAI unavailable: {exc}")


@app.get("/api/admin/itsm/incident-fields")
async def incident_fields(n: int = 1):
    """Diagnostic: the raw field names the incident list returns and what the
    normaliser mapped (id/title/status) — to verify field mapping per instance."""
    try:
        return await asyncio.to_thread(itsm.incident_field_sample, n)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"SummitAI unavailable: {exc}")


class IncidentTrackRequest(BaseModel):
    id: str = Field(..., min_length=1, max_length=64)


@app.post("/api/incidents/track")
async def track_incident(req: IncidentTrackRequest, request: Request):
    """Pin an incident number to the dashboard (merged in via its detail) —
    used to surface app-created or otherwise-unlisted tickets."""
    await asyncio.to_thread(itsm.record_created_incident, req.id)
    await asyncio.to_thread(db.audit, _actor(request), "incident_tracked", {"id": req.id})
    return {"ok": True}


@app.get("/api/incidents/{incident_id}")
async def incident_detail(incident_id: str):
    try:
        inc = await asyncio.to_thread(itsm.get_incident, incident_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"SummitAI unavailable: {exc}")
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


class IncidentCreateRequest(BaseModel):
    description: str = Field(..., min_length=5, max_length=4000)
    caller_email: str = Field("", max_length=200)   # empty = configured default
    priority: str = Field("", max_length=40)
    urgency: str = Field("", max_length=40)
    impact: str = Field("", max_length=40)
    category: str = Field("", max_length=100)
    classification: str = Field("", max_length=100)
    workgroup: str = Field("", max_length=100)
    ci: str = Field("", max_length=100)


@app.post("/api/incidents/create")
async def create_incident_ticket(req: IncidentCreateRequest, request: Request):
    """Raise a new SummitAI ticket — operator-driven via the incident
    assistant; every creation is audited."""
    result = await asyncio.to_thread(itsm.create_incident, req.model_dump())
    await asyncio.to_thread(db.audit, _actor(request), "itsm_ticket_created",
                            {"ok": result.get("ok"),
                             "ticket": result.get("ticket") or "(unknown)",
                             "priority": req.priority or "(unset)",
                             "ci": req.ci or "(unset)"})
    return result


class TicketUpdateRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=8000)
    status: str = Field("", max_length=40)       # empty = leave the status alone
    solution: str = Field("", max_length=4000)


@app.post("/api/incidents/{incident_id}/update")
async def update_incident_ticket(incident_id: str, req: TicketUpdateRequest, request: Request):
    """Post a work-log entry (optionally with a status change) to the SummitAI
    ticket via IM_LogOrUpdateIncident. Always operator-initiated and reviewed."""
    result = await asyncio.to_thread(
        itsm.update_incident, incident_id, req.message, req.status, req.solution)
    await asyncio.to_thread(db.audit, _actor(request), "itsm_ticket_updated",
                            {"ticket": incident_id, "ok": result.get("ok"),
                             "status": req.status or "(unchanged)",
                             "chars": len(req.message)})
    return result


@app.get("/api/changes")
async def changes():
    """Changes from SummitAI (demo data until a list ServiceName is wired)."""
    try:
        rows = await asyncio.to_thread(itsm.list_changes)
        for c in rows:   # flag which changes carry a local machine-readable plan
            c["has_plan"] = changeplan.load_plan(c["id"]) is not None
        return {"changes": rows, **itsm.status()}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"SummitAI unavailable: {exc}")


@app.get("/api/changes/{change_id}")
async def change_detail(change_id: str):
    """CR detail from Summit merged with the locally stored structured plan."""
    try:
        change = await asyncio.to_thread(itsm.get_change, change_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"SummitAI unavailable: {exc}")
    plan = changeplan.load_plan(change_id)
    if change is None and plan is None:
        raise HTTPException(status_code=404, detail="Change not found")
    return {"change": change, "plan": plan}


class ChangeBatchRequest(BaseModel):
    ids: list[str] = Field(default_factory=list)


@app.post("/api/changes/batch")
async def changes_batch(req: ChangeBatchRequest):
    """Fetch several CRs by number via the detail service — powers the
    'add CRs to the board' change list when no list ServiceName is wired."""
    out, errors = [], {}
    seen = set()
    for cid in req.ids[:50]:
        cid = str(cid).strip()
        if not cid or cid in seen:
            continue
        seen.add(cid)
        try:
            c = await asyncio.to_thread(itsm.get_change, cid)
        except Exception as exc:  # noqa: BLE001
            errors[cid] = str(exc)[:150]
            continue
        if c:
            c["has_plan"] = changeplan.load_plan(c["id"]) is not None
            out.append(c)
        else:
            errors[cid] = "not found"
    return {"changes": out, "errors": errors}


class RefinePlanRequest(BaseModel):
    plan_text: str = Field(..., min_length=20, max_length=20000)
    platform: str = Field("linux", pattern=r"^(linux|windows)$")


@app.post("/api/changes/refine-plan")
async def refine_change_plan(req: RefinePlanRequest, request: Request):
    """AI pass over a pasted implementation-plan document: structured steps,
    validation/corrections, downtime verification, risk + success-rate,
    inferred CR fields, and still-missing mandatory fields."""
    result = await changeplan.refine_plan(req.plan_text, req.platform)
    await asyncio.to_thread(db.audit, _actor(request), "change_plan_refined",
                            {"chars": len(req.plan_text), "steps": len(result.get("steps", [])),
                             "refined_by": result.get("refined_by")})
    return result


class ReRefineRequest(BaseModel):
    plan: dict = Field(...)                       # the current refined plan
    answers: str = Field(..., min_length=1, max_length=6000)
    platform: str = Field("linux", pattern=r"^(linux|windows)$")


@app.post("/api/changes/re-refine")
async def re_refine_plan(req: ReRefineRequest, request: Request):
    """Re-validate a plan with the operator's answers to the open questions
    folded in — tightens the steps and raises the success score."""
    p = req.plan or {}
    lines = [f"Change title: {p.get('title', '')}", "Current plan steps:"]
    for s in (p.get("steps") or []):
        cmd = s.get("command") or "(manual)"
        lines.append(f"{s.get('order')}. [{s.get('phase', 'step')}] "
                     f"{s.get('description', '')}  ::  {cmd}")
    if p.get("backout_plan"):
        lines.append(f"Back-out plan: {p['backout_plan']}")
    lines.append("")
    lines.append("The operator has now answered the open questions / clarifications. "
                 "Incorporate these facts and re-issue the FULL validated plan, updating "
                 "commands, downtime, risk and the success-rate accordingly:")
    lines.append(req.answers)
    result = await changeplan.refine_plan("\n".join(lines), req.platform)
    await asyncio.to_thread(db.audit, _actor(request), "change_plan_rerefined",
                            {"chars": len(req.answers), "steps": len(result.get("steps", []))})
    return result


@app.post("/api/changes/upload-plan")
async def upload_change_plan(request: Request, file: UploadFile = File(...),
                             platform: str = Form("linux")):
    """Read an uploaded implementation-plan file (.txt/.md/.docx/.pdf) and run
    the same refinement/validation the pasted-text path uses."""
    raw = await file.read()
    if len(raw) > 5_000_000:
        raise HTTPException(status_code=413, detail="File too large (max 5 MB).")
    try:
        text = await asyncio.to_thread(changeplan.extract_text, file.filename or "", raw)
    except RuntimeError as exc:
        raise HTTPException(status_code=415, detail=str(exc))
    if len(text.strip()) < 20:
        raise HTTPException(status_code=422,
                            detail="Could not read enough text from that file — paste the plan instead.")
    result = await changeplan.refine_plan(
        text, "windows" if str(platform).lower() == "windows" else "linux")
    result["source_file"] = file.filename
    await asyncio.to_thread(db.audit, _actor(request), "change_plan_uploaded",
                            {"file": file.filename, "chars": len(text),
                             "steps": len(result.get("steps", [])),
                             "refined_by": result.get("refined_by")})
    return result


class ChangeRecommendRequest(BaseModel):
    context: str = Field(..., min_length=5, max_length=6000)
    platform: str = Field("linux", pattern=r"^(linux|windows)$")


@app.post("/api/changes/recommend")
async def recommend_change_fields(req: ChangeRecommendRequest):
    """Suggest CR attributes + an outline plan from a description (manual flow)."""
    return await changeplan.recommend_change(req.context, req.platform)


class ChangeCreateRequest(BaseModel):
    title: str = Field(..., min_length=5, max_length=300)
    description: str = Field("", max_length=8000)
    type: str = Field("Normal", max_length=40)
    category: str = Field("Minor", max_length=60)
    risk: str = Field("Medium", max_length=20)
    impact: str = Field("Medium", max_length=20)
    priority: str = Field("P3", max_length=10)
    downtime: bool = False
    workgroup: str = Field("", max_length=100)
    requestor: str = Field("", max_length=200)
    start: str = Field("", max_length=40)
    end: str = Field("", max_length=40)
    backout: str = Field("", max_length=4000)
    steps: list[dict] = Field(default_factory=list)   # the refined structured plan
    assessment: dict = Field(default_factory=dict)    # risk / success_rate / corrections


@app.post("/api/changes/create")
async def create_change_request(req: ChangeCreateRequest, request: Request):
    """Raise a CR in Summit and store the structured plan (with its risk /
    success-rate assessment) locally so the implementer can enforce it."""
    result = await asyncio.to_thread(itsm.create_change, req.model_dump())
    if result.get("ok"):
        cid = result.get("change_id") or f"local-{int(time.time())}"
        result["change_id"] = cid
        if req.steps or req.assessment:
            a = req.assessment or {}
            changeplan.save_plan(cid, {
                "title": req.title, "steps": req.steps,
                "downtime": req.downtime, "backout": req.backout,
                "corrections": a.get("corrections") or [],
                "suggestions": a.get("suggestions") or [],
                "risk_assessment": a.get("risk_assessment") or {},
                "success_rate": a.get("success_rate") or {},
            })
    await asyncio.to_thread(db.audit, _actor(request), "change_created",
                            {"ok": result.get("ok"),
                             "change_id": result.get("change_id") or "(unknown)",
                             "steps": len(req.steps), "downtime": req.downtime,
                             "success_rate": (req.assessment or {}).get("success_rate", {}).get("percent")})
    return result


class GeneratePlanRequest(BaseModel):
    server: str = Field("", max_length=100)     # target server (inventory name)
    os_family: str = Field("", max_length=40)   # linux / windows / …
    details: str = Field("", max_length=4000)   # operator-supplied specifics


@app.post("/api/changes/{change_id}/generate-plan")
async def generate_change_plan(change_id: str, request: Request,
                               req: GeneratePlanRequest | None = None):
    """Generate an executable implementation plan for a change that has none,
    from its Summit title/description plus operator-supplied specifics, and
    store it for the implementer."""
    req = req or GeneratePlanRequest()
    try:
        change = await asyncio.to_thread(itsm.get_change, change_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"SummitAI unavailable: {exc}")
    if change is None:
        raise HTTPException(status_code=404, detail="Change not found")
    srv = load_inventory().get(req.server)
    host_line = ""
    if srv is not None:
        host_line = (f"Target host: {srv.name} ({srv.host}); OS: "
                     f"{req.os_family or srv.os or 'linux'}; "
                     f"services: {', '.join(srv.services) or 'unknown'}\n")
    elif req.server:
        host_line = f"Target host: {req.server}; OS: {req.os_family or 'linux'}\n"
    # discovered facts give the AI real, server-specific grounding
    disco = discovery.facts_summary(req.server) if req.server else ""
    context = (f"Change {change_id}: {change.get('title', '')}\n"
               f"{change.get('description', '')}\n"
               f"Affected CI/server: {change.get('ci', '')}\n"
               f"Risk: {change.get('risk', '')}  Category: {change.get('category', '')}\n"
               + host_line
               + (f"\nDiscovered facts about the target server (use these — do not guess):\n{disco}\n"
                  if disco else "")
               + (f"\nOperator-supplied specifics: {req.details}\n" if req.details else ""))
    platform = "windows" if (srv is not None and srv.is_windows) else "linux"
    plan = await changeplan.generate_plan(context, platform)
    if not plan.get("steps"):
        # AI unavailable / produced nothing — don't store an empty plan
        raise HTTPException(status_code=503,
                            detail="Couldn't generate a plan — " + (plan.get("ai_error")
                                   or "the AI is unavailable on this server."))
    existing = changeplan.load_plan(change_id) or {}
    stored = changeplan.save_plan(change_id, {
        "title": change.get("title") or plan.get("title") or str(change_id),
        "steps": plan.get("steps", []),
        "backout": plan.get("backout_plan", ""),
        "corrections": plan.get("corrections", []),
        "suggestions": plan.get("suggestions", []),
        "risk_assessment": plan.get("risk_assessment", {}),
        "success_rate": plan.get("success_rate", {}),
        "platform": platform,   # governs the read-only gate's command dialect
        "server": req.server or existing.get("server", ""),
        # preserve any execution progress if a plan already existed
        "current_step": existing.get("current_step", 0),
        "results": existing.get("results", {}),
    })
    await asyncio.to_thread(db.audit, _actor(request), "change_plan_generated",
                            {"change_id": change_id, "steps": len(plan.get("steps", [])),
                             "refined_by": plan.get("refined_by")})
    return {"change": change, "plan": stored}


class ChangeRunStepRequest(BaseModel):
    order: int = Field(..., ge=1, le=500)
    server: str = Field(..., min_length=1, max_length=100)
    verify: bool = True   # False = execute only; caller verifies separately (two-phase UI)


@app.post("/api/changes/{change_id}/run-step")
async def change_run_step(change_id: str, req: ChangeRunStepRequest, request: Request):
    """Execute one step of the approved plan — sequence enforced server-side."""
    plan = changeplan.load_plan(change_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="No stored plan for this change")
    step = next((s for s in plan.get("steps", []) if int(s.get("order", 0)) == req.order), None)
    if step is None:
        raise HTTPException(status_code=404, detail="No such step in the plan")
    done = int(plan.get("current_step") or 0)
    if not step.get("command"):
        # manual step — record it done (verdict ok) but let the operator click
        # "Next step" to advance, consistent with command steps
        updated = changeplan.record_result(
            change_id, req.order,
            {"ok": True, "exit_code": None, "output": "(manual step confirmed done)"},
            {"verdict": "ok", "summary": "Manual step confirmed done by the operator.",
             "concern": "", "proceed": True, "verified_by": "manual"},
            advance=False)
        await asyncio.to_thread(db.audit, _actor(request), "change_step_manual_done",
                                {"change_id": change_id, "order": req.order})
        return {"ok": True, "manual": True,
                "current_step": (updated or plan).get("current_step")}
    if req.order > done + 1:
        await asyncio.to_thread(db.audit, _actor(request), "change_step_blocked",
                                {"change_id": change_id, "order": req.order,
                                 "reason": "out of sequence"})
        raise HTTPException(status_code=403,
                            detail=f"Step {done + 1} must complete before step {req.order}"
                                   " — the approved sequence is enforced")
    server = load_inventory().get(req.server)
    if server is None:
        raise HTTPException(status_code=404, detail=f"Server '{req.server}' not in inventory")
    platform = "windows" if server.is_windows else "linux"
    result = await _remote_exec(server, step["command"])
    if not req.verify:
        # execute only — the UI shows the CLI animation now and asks for the
        # AI verdict via /verify-step next (robot animation)
        updated = changeplan.record_result(change_id, req.order, result, advance=False)
        await asyncio.to_thread(db.audit, _actor(request), "change_step_executed",
                                {"change_id": change_id, "order": req.order,
                                 "server": req.server, "ok": result["ok"],
                                 "exit_code": result["exit_code"]})
        return {**result, "verified": False,
                "current_step": (updated or plan).get("current_step")}
    verification = await changeplan.verify_step(step, result, plan.get("title", ""), platform)
    updated = changeplan.record_result(change_id, req.order, result, verification)
    await asyncio.to_thread(db.audit, _actor(request), "change_step_executed",
                            {"change_id": change_id, "order": req.order,
                             "server": req.server, "ok": result["ok"],
                             "exit_code": result["exit_code"],
                             "verdict": verification.get("verdict")})
    return {**result, "verification": verification,
            "current_step": (updated or plan).get("current_step")}


class ChangeVerifyRequest(BaseModel):
    order: int = Field(..., ge=1, le=500)


@app.post("/api/changes/{change_id}/verify-step")
async def change_verify_step(change_id: str, req: ChangeVerifyRequest, request: Request):
    """AI-verify an already-executed step's stored output (two-phase UI)."""
    plan = changeplan.load_plan(change_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="No stored plan for this change")
    step = next((s for s in plan.get("steps", []) if int(s.get("order", 0)) == req.order), None)
    entry = (plan.get("results") or {}).get(str(req.order))
    if step is None or entry is None:
        raise HTTPException(status_code=404, detail="No executed step to verify")
    verification = await changeplan.verify_step(
        step, entry, plan.get("title", ""), plan.get("platform", "linux"))
    updated = changeplan.apply_verification(change_id, req.order, verification)
    await asyncio.to_thread(db.audit, _actor(request), "change_step_verified",
                            {"change_id": change_id, "order": req.order,
                             "verdict": verification.get("verdict")})
    return {"verification": verification,
            "current_step": (updated or plan).get("current_step")}


class ChangeAdvanceRequest(BaseModel):
    order: int = Field(..., ge=1, le=500)
    force: bool = False   # override a failed/unclean step and proceed anyway


@app.post("/api/changes/{change_id}/advance-step")
async def change_advance_step(change_id: str, req: ChangeAdvanceRequest, request: Request):
    """Operator confirms a step's result and moves to the next one."""
    updated = await asyncio.to_thread(changeplan.advance_step, change_id, req.order, req.force)
    if updated is None:
        raise HTTPException(status_code=404, detail="No stored plan for this change")
    await asyncio.to_thread(db.audit, _actor(request), "change_step_advanced",
                            {"change_id": change_id, "order": req.order, "forced": req.force,
                             "current_step": updated.get("current_step")})
    return {"current_step": updated.get("current_step")}


class ChangeRunCmdRequest(BaseModel):
    command: str = Field(..., min_length=1, max_length=2000)
    server: str = Field(..., min_length=1, max_length=100)


@app.post("/api/changes/{change_id}/run-cmd")
async def change_run_cmd(change_id: str, req: ChangeRunCmdRequest, request: Request):
    """Ad-hoc command during implementation. The gate allows ONLY commands
    from the approved plan (in sequence) or read-only diagnostics."""
    plan = changeplan.load_plan(change_id)
    server = load_inventory().get(req.server)
    if server is None:
        raise HTTPException(status_code=404, detail=f"Server '{req.server}' not in inventory")
    # the read-only gate must judge with the target's own command dialect
    if plan is not None:
        plan["platform"] = "windows" if server.is_windows else "linux"
    gate = changeplan.check_command(plan, req.command)
    if not gate["allowed"]:
        await asyncio.to_thread(db.audit, _actor(request), "change_cmd_blocked",
                                {"change_id": change_id, "command": req.command[:200],
                                 "kind": gate["kind"], "reason": gate["reason"]})
        raise HTTPException(status_code=403, detail=gate["reason"])
    result = await _remote_exec(server, req.command)
    verification = None
    if gate.get("step_order"):
        step = next((s for s in plan.get("steps", [])
                     if int(s.get("order", 0)) == gate["step_order"]), None)
        if step:
            verification = await changeplan.verify_step(
                step, result, plan.get("title", ""),
                "windows" if server.is_windows else "linux")
        changeplan.record_result(change_id, gate["step_order"], result, verification)
    await asyncio.to_thread(db.audit, _actor(request), "change_cmd_executed",
                            {"change_id": change_id, "command": req.command[:200],
                             "kind": gate["kind"], "server": req.server,
                             "ok": result["ok"]})
    return {**result, "gate": gate, "verification": verification}


class ChangeLogRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=8000)


@app.post("/api/changes/{change_id}/log")
async def change_post_log(change_id: str, req: ChangeLogRequest, request: Request):
    """Post an implementation-progress entry to the CR's information log."""
    result = await asyncio.to_thread(itsm.update_change_log, change_id, req.message)
    await asyncio.to_thread(db.audit, _actor(request), "change_log_posted",
                            {"change_id": change_id, "ok": result.get("ok"),
                             "chars": len(req.message)})
    return result


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


async def _remote_exec(server, command: str) -> dict:
    """Run one command on the target, no agent involved. Windows hosts use
    PowerShell over WinRM; everything else uses SSH."""
    if server.is_windows:
        return await winexec.run_ps(server, command, timeout=90)
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


# Backwards-compatible alias (older call sites).
_ssh_exec = _remote_exec


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
    verdict, why = cmdreview.classify(
        req.command, "windows" if server.is_windows else "linux")
    actor = _actor(request)
    if verdict == "blocked":
        await asyncio.to_thread(db.audit, actor, "adhoc_command_blocked",
                                {"session": session_id, "command": req.command[:500], "reason": why})
        raise HTTPException(status_code=403, detail=f"Blocked by policy: this command {why}")
    await asyncio.to_thread(db.audit, actor, "adhoc_command_run",
                            {"session": session_id, "command": req.command[:500],
                             "verdict": verdict})
    return await _remote_exec(server, req.command)


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


# sentinel the UI sends back when the WinRM password is set but unchanged, so
# the stored secret is never round-tripped through the browser.
_SECRET_KEPT = "__stored__"


class ServerEntry(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, pattern=r"^[\w.\-]+$")
    host: str = Field(..., min_length=1, max_length=255)
    user: str = Field(..., min_length=1, max_length=64)
    port: int = Field(22, ge=1, le=65535)
    ssh_key: str | None = Field(None, max_length=512)
    description: str = Field("", max_length=500)
    os: str = Field("", max_length=100)
    platform: str = Field("linux", pattern=r"^(linux|windows)$")
    tags: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    log_hints: list[str] = Field(default_factory=list)
    # Windows / WinRM (only meaningful when platform == windows)
    winrm_password: str = Field("", max_length=512)
    winrm_transport: str = Field("ntlm", max_length=16)
    winrm_port: int = Field(5985, ge=1, le=65535)
    winrm_scheme: str = Field("http", pattern=r"^(http|https)$")
    winrm_cert_validation: str = Field("ignore", pattern=r"^(ignore|validate)$")
    winrm_use_proxy: bool = False

    def to_yaml_dict(self) -> dict:
        out = {"name": self.name, "host": self.host, "port": self.port, "user": self.user}
        if self.ssh_key:
            out["ssh_key"] = self.ssh_key
        for key in ("description", "os"):
            if getattr(self, key):
                out[key] = getattr(self, key)
        if self.platform == "windows":
            out["platform"] = "windows"
            out["winrm_transport"] = self.winrm_transport
            out["winrm_port"] = self.winrm_port
            out["winrm_scheme"] = self.winrm_scheme
            out["winrm_cert_validation"] = self.winrm_cert_validation
            if self.winrm_use_proxy:
                out["winrm_use_proxy"] = True
        for key in ("tags", "services", "log_hints"):
            if getattr(self, key):
                out[key] = getattr(self, key)
        return out


def _redact_inventory(servers: list[dict]) -> list[dict]:
    """Never send the stored WinRM password to the browser — replace it with a
    sentinel so the editor can show 'set' without revealing the secret."""
    out = []
    for s in servers:
        s = dict(s)
        if s.get("winrm_password"):
            s["winrm_password"] = _SECRET_KEPT
        out.append(s)
    return out


@app.get("/api/admin/inventory")
async def admin_inventory():
    return {"servers": _redact_inventory(load_raw_inventory()),
            "path": str(writable_inventory_path())}


@app.put("/api/admin/inventory/{name}")
async def upsert_server(name: str, entry: ServerEntry, request: Request):
    servers = load_raw_inventory()
    prior = next((s for s in servers if s.get("name") == name), None)
    yaml_dict = entry.to_yaml_dict()
    if entry.platform == "windows":
        # preserve the stored password when the UI echoes the sentinel back
        if entry.winrm_password and entry.winrm_password != _SECRET_KEPT:
            yaml_dict["winrm_password"] = entry.winrm_password
        elif prior and prior.get("winrm_password"):
            yaml_dict["winrm_password"] = prior["winrm_password"]
    # remove the entry being edited (by its original name) and any entry that
    # collides with the (possibly renamed) new name
    servers = [s for s in servers if s.get("name") not in (name, entry.name)]
    servers.append(yaml_dict)
    save_inventory(servers)
    await asyncio.to_thread(
        db.audit, _actor(request), "inventory_upsert",
        {"name": entry.name, "renamed_from": name if name != entry.name else None,
         "host": entry.host},
    )
    return {"ok": True, "servers": _redact_inventory(servers)}


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
    """Reachability test for one inventory server (SSH for Linux, WinRM for
    Windows), 15s timeout."""
    import asyncio

    servers = load_inventory()
    server = servers.get(name)
    if server is None:
        raise HTTPException(status_code=404, detail=f"Server '{name}' not found")
    if server.is_windows:
        res = await winexec.run_ps(
            server,
            "\"CONNECTION_OK $(hostname) $((Get-CimInstance Win32_OperatingSystem).Caption)\"",
            timeout=15)
        if res.get("ok") and "CONNECTION_OK" in (res.get("output") or ""):
            return {"ok": True, "detail": res["output"].strip()}
        return {"ok": False, "detail": (res.get("output") or "WinRM test failed").strip()[:500]}
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


@app.post("/api/servers/{name}/discover")
async def run_discovery(name: str, request: Request):
    """SSH in and gather a full fact sheet (OS, virtualization, CPU/mem, disks,
    network, services, package manager…) so plans are grounded in reality."""
    server = load_inventory().get(name)
    if server is None:
        raise HTTPException(status_code=404, detail=f"Server '{name}' not in inventory")
    result = await discovery.discover(server)
    await asyncio.to_thread(db.audit, _actor(request), "server_discovered",
                            {"server": name, "ok": result.get("ok")})
    return result


@app.get("/api/servers/{name}/discovery")
async def get_discovery(name: str):
    return discovery.load_facts(name) or {"ok": False, "error": "not discovered yet"}


def _get_state(session_id: str) -> orchestrator.SessionState:
    state = orchestrator.SESSIONS.get(session_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return state
