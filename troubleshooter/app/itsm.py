"""ITSM integration — SummitAI (Symphony SUMMIT) service-management adapter.

Pulls active incidents (P1/P2 focus) and approved changes so the operator can
launch a troubleshooting session straight from an incident, with its context
pre-filled. Configuration is entirely env-driven; when nothing is configured
the adapter serves realistic DEMO data so the dashboard works out of the box
and can be wired to the real API later without any UI change.

Environment (all optional — unset => demo mode):
    SUMMITAI_BASE_URL        e.g. https://summit.bial.internal/api/v1
    SUMMITAI_TOKEN           bearer token / API key
    SUMMITAI_AUTH_HEADER     header carrying the token   (default: Authorization)
    SUMMITAI_AUTH_PREFIX     value prefix                (default: "Bearer ")
    SUMMITAI_VERIFY_TLS      "0" to disable cert verification (default: verify)
    SUMMITAI_INCIDENTS_PATH  path appended to base for incidents (default: /incidents)
    SUMMITAI_CHANGES_PATH    path for changes            (default: /changes)

Field names differ across SummitAI versions, so responses are normalised
defensively: several likely source keys are tried for each output field.
"""

import json
import os
import ssl
import time
import urllib.error
import urllib.request

DEMO = not os.environ.get("SUMMITAI_BASE_URL")


def configured() -> bool:
    return not DEMO


def _cfg():
    return {
        "base": os.environ.get("SUMMITAI_BASE_URL", "").rstrip("/"),
        "token": os.environ.get("SUMMITAI_TOKEN", ""),
        "auth_header": os.environ.get("SUMMITAI_AUTH_HEADER", "Authorization"),
        "auth_prefix": os.environ.get("SUMMITAI_AUTH_PREFIX", "Bearer "),
        "verify": os.environ.get("SUMMITAI_VERIFY_TLS", "1") != "0",
        "incidents_path": os.environ.get("SUMMITAI_INCIDENTS_PATH", "/incidents"),
        "changes_path": os.environ.get("SUMMITAI_CHANGES_PATH", "/changes"),
    }


def _first(d: dict, *keys, default=""):
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return default


def _norm_priority(v) -> str:
    s = str(v or "").upper().replace("PRIORITY", "").strip()
    for p in ("P1", "P2", "P3", "P4", "P5"):
        if p in s:
            return p
    # SummitAI sometimes uses "Critical/High/Medium/Low" or numeric urgency
    return {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4",
            "1": "P1", "2": "P2", "3": "P3", "4": "P4"}.get(s, s or "P3")


def _norm_incident(raw: dict) -> dict:
    return {
        "id": str(_first(raw, "IncidentID", "IncidentId", "id", "number", "Number",
                         "RequestID", "ticket")),
        "priority": _norm_priority(_first(raw, "Priority", "priority", "PriorityName")),
        "status": _first(raw, "Status", "status", "StatusName", default="Open"),
        "title": _first(raw, "Subject", "Title", "title", "summary", "ShortDescription",
                        default="(no subject)"),
        "description": _first(raw, "Description", "description", "Details", "Symptom",
                              "detail", default=""),
        "ci": _first(raw, "CI", "CIName", "AffectedCI", "Asset", "ConfigurationItem",
                     "Server", "Hostname", "host", default=""),
        "reported_at": _first(raw, "CreatedDateTime", "LoggedTime", "ReportedOn",
                              "createdAt", "OpenedTime", default=""),
        "raised_by": _first(raw, "Caller", "RaisedBy", "Requester", "ReportedBy",
                            "AffectedUser", default=""),
        "assignee": _first(raw, "AssignedTo", "Analyst", "Owner", "assignee",
                           "AssignedAnalyst", default="Unassigned"),
        "category": _first(raw, "Category", "category", "ClassName", default=""),
        "url": _first(raw, "URL", "url", "Link", default=""),
    }


def _norm_change(raw: dict) -> dict:
    return {
        "id": str(_first(raw, "ChangeID", "id", "number", "Number", default="")),
        "title": _first(raw, "Subject", "Title", "title", default="(no subject)"),
        "status": _first(raw, "Status", "status", default="Approved"),
        "risk": _first(raw, "Risk", "RiskLevel", "risk", default="Medium"),
        "type": _first(raw, "ChangeType", "Type", default="Normal"),
        "window": _first(raw, "ScheduledWindow", "Window", "PlannedStart", default=""),
        "ci": _first(raw, "CI", "CIName", "AffectedCI", "Server", default=""),
        "implementer": _first(raw, "Implementer", "AssignedTo", "Owner", default=""),
        "approver": _first(raw, "Approver", "ApprovedBy", default=""),
        "plan": raw.get("plan") or raw.get("ImplementationPlan") or [],
    }


def _get(path: str):
    cfg = _cfg()
    headers = {"Accept": "application/json"}
    if cfg["token"]:
        headers[cfg["auth_header"]] = f"{cfg['auth_prefix']}{cfg['token']}"
    url = cfg["base"] + path
    ctx = None
    if url.startswith("https"):
        ctx = ssl.create_default_context()
        if not cfg["verify"]:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
            status, raw = resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read().decode(errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise RuntimeError(f"SummitAI request failed: {e}") from e
    if status >= 400:
        raise RuntimeError(f"SummitAI returned HTTP {status}")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = []
    # accept either a bare list or a wrapped {data|result|items|Incidents: [...]}
    if isinstance(data, dict):
        for k in ("data", "result", "results", "items", "Incidents", "Changes", "value"):
            if isinstance(data.get(k), list):
                return data[k]
        return [data]
    return data if isinstance(data, list) else []


# ---------- public API ----------

def list_incidents(priorities: tuple[str, ...] = ("P1", "P2")) -> list[dict]:
    if DEMO:
        rows = _demo_incidents()
    else:
        rows = [_norm_incident(r) for r in _get(_cfg()["incidents_path"])]
    active = [i for i in rows
              if i["priority"] in priorities
              and str(i["status"]).lower() not in ("closed", "resolved", "cancelled")]
    order = {p: n for n, p in enumerate(("P1", "P2", "P3", "P4", "P5"))}
    active.sort(key=lambda i: (order.get(i["priority"], 9), i["id"]))
    return active


def get_incident(incident_id: str) -> dict | None:
    if DEMO:
        return next((i for i in _demo_incidents() if i["id"] == incident_id), None)
    rows = [_norm_incident(r) for r in _get(f"{_cfg()['incidents_path']}/{incident_id}")]
    return rows[0] if rows else None


def list_changes() -> list[dict]:
    if DEMO:
        return _demo_changes()
    return [_norm_change(r) for r in _get(_cfg()["changes_path"])]


def status() -> dict:
    return {"configured": configured(), "demo": DEMO,
            "source": "SummitAI" + (" (demo data)" if DEMO else "")}


# ---------- demo data (used until SUMMITAI_BASE_URL is set) ----------

def _demo_incidents() -> list[dict]:
    now = time.time()

    def ago(mins):
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now - mins * 60))

    return [
        {"id": "INC-100482", "priority": "P1", "status": "In Progress",
         "title": "Booking portal returning HTTP 503 — customers unable to check in online",
         "description": ("Multiple customer complaints from 14:35. The online check-in and "
                         "booking portal return 503 Service Unavailable. Load balancer shows "
                         "web-01 pool members unhealthy. No planned change in the window."),
         "ci": "web-01", "reported_at": ago(40), "raised_by": "NOC / ServiceDesk",
         "assignee": "Infra On-call", "category": "Application / Web", "url": ""},
        {"id": "INC-100487", "priority": "P1", "status": "Assigned",
         "title": "Database connection pool exhausted on db-prod-02",
         "description": ("Application logs show 'FATAL: remaining connection slots are "
                         "reserved'. Transactions timing out intermittently since ~15:10."),
         "ci": "db-prod-02", "reported_at": ago(18), "raised_by": "App Support",
         "assignee": "DBA Team", "category": "Database", "url": ""},
        {"id": "INC-100471", "priority": "P2", "status": "In Progress",
         "title": "Intermittent high latency on API gateway (api-gw-01)",
         "description": ("p95 latency crossed 2s on the payments API since 13:50. Zabbix "
                         "alerted on CPU steal and response time. Partial impact."),
         "ci": "api-gw-01", "reported_at": ago(95), "raised_by": "Monitoring (Zabbix)",
         "assignee": "Platform Team", "category": "Network / API", "url": ""},
        {"id": "INC-100465", "priority": "P2", "status": "Assigned",
         "title": "Disk space warning escalating on file-svr-03 (/data at 91%)",
         "description": ("Storage on /data grew from 78% to 91% in 3 hours. Risk of write "
                         "failures for the document service if it reaches 100%."),
         "ci": "file-svr-03", "reported_at": ago(150), "raised_by": "Monitoring",
         "assignee": "Storage Team", "category": "OS / Storage", "url": ""},
    ]


def _demo_changes() -> list[dict]:
    return [
        {"id": "CHG-4521", "title": "Apply Q3 security patches to web tier (web-01, web-02)",
         "status": "Approved", "risk": "Medium", "type": "Normal",
         "window": "2026-07-20 22:00–23:30 IST", "ci": "web-01, web-02",
         "implementer": "Infra Team", "approver": "CAB",
         "plan": ["Snapshot both VMs", "yum update security packages", "Rolling restart",
                  "Smoke test /health on both", "Rollback: restore snapshot if health fails"]},
        {"id": "CHG-4530", "title": "Increase connection pool + add read replica for db-prod-02",
         "status": "Approved", "risk": "High", "type": "Normal",
         "window": "2026-07-21 01:00–03:00 IST", "ci": "db-prod-02",
         "implementer": "DBA Team", "approver": "CAB",
         "plan": ["Back up postgresql.conf", "Raise max_connections to 400", "Reload config",
                  "Provision read replica", "Verify replication lag < 5s"]},
        {"id": "CHG-4536", "title": "TLS certificate renewal on api-gw-01",
         "status": "Approved", "risk": "Low", "type": "Standard",
         "window": "2026-07-19 23:00–23:30 IST", "ci": "api-gw-01",
         "implementer": "Platform Team", "approver": "Auto-approved (standard)",
         "plan": ["Back up current cert", "Install renewed cert", "Reload gateway",
                  "Verify chain + expiry"]},
    ]
