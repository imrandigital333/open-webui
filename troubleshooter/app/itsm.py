"""ITSM integration — SummitAI (Symphony SUMMIT) service-management adapter.

Two API styles are supported, selectable in Settings:

- summit_wcf (default): SummitAI's web-service endpoint, e.g.
      https://10.x.x.x/Chatbotproxy/REST/Summit_RESTWCF.svc
  The JSON operation path (default RESTService/CommonWS_JsonObjCall) is
  appended to that URL — the bare .svc address is WCF's SOAP endpoint and
  answers JSON with HTTP 415. Every operation is a POST of a JSON envelope:
      {"ServiceName": "<op>", "objCommonParameters": {"_ProxyDetails": {
          "AuthType": "APIKEY", "APIKey": "...", "ProxyID": 0,
          "ReturnType": "JSON", "OrgID": 1}, ...op params...}}
  The ServiceNames for listing/fetching differ per deployment, so they are
  configurable (IM_GetIncidentDetails etc.).

- rest: a plain REST API (GET base+path with a bearer-style header) for
  proxies/middleware that expose Summit data that way.

Configuration lives in itsm.yaml (managed from the Settings UI, chmod 600,
gitignored) with SUMMITAI_* environment variables as fallback. When no base
URL is configured, realistic DEMO data powers the dashboards so the UI works
before the integration is wired.

Responses are normalised defensively: SummitAI field names vary by version,
so several likely source keys are tried for every output field.
"""

import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request

import yaml

from .inventory import BASE_DIR

# UI-managed settings live here (chmod 600, gitignored); environment variables
# act as fallback so env-based deployments keep working.
CONFIG_PATH = BASE_DIR / "itsm.yaml"

DEFAULTS = {
    "api_style": "summit_wcf",          # summit_wcf | rest
    "base_url": "",
    "token": "",                        # API key (wcf) or bearer token (rest)
    "verify_tls": True,
    # internal endpoints must NOT be routed via the corporate proxy: the
    # system HTTP(S)_PROXY (set for Claude's internet access) would send
    # 10.x.x.x calls to the URL filter, which answers 403. Off by default.
    "use_proxy": False,
    # summit_wcf style
    # The bare ...Summit_RESTWCF.svc address is WCF's SOAP endpoint and
    # answers JSON POSTs with HTTP 415; the JSON envelope goes to this
    # operation path below it.
    "wcf_operation": "RESTService/CommonWS_JsonObjCall",
    "org_id": 1,
    "proxy_id": 0,
    "incidents_service": "IM_GetIncidentList",
    "incident_detail_service": "IM_GetIncidentDetailsAndChangeHistory",
    "update_service": "IM_LogOrUpdateIncident",
    "changes_service": "CM_FetchChanges",
    # sent as Ticket.Caller_EmailID on ticket updates (who the update is from)
    "caller_email": "",
    # IM_GetIncidentList requires an objIncidentCommonFilter block; these
    # feed its mandatory fields (the full status string matches the vendor
    # sample — P1/P2 + active filtering happens client-side afterwards).
    "instance": "IT",
    "incident_statuses": "New,In-Progress,Assigned,Pending,Resolved,Closed",
    "lookback_days": 30,
    "page_size": 100,
    "incidents_params": "",             # optional JSON merged into objCommonParameters
    # rest style
    "auth_header": "Authorization",
    "auth_prefix": "Bearer ",
    "incidents_path": "/incidents",
    "changes_path": "/changes",
}

_ENV_MAP = {
    "api_style": "SUMMITAI_API_STYLE",
    "base_url": "SUMMITAI_BASE_URL",
    "token": "SUMMITAI_TOKEN",
    "wcf_operation": "SUMMITAI_WCF_OPERATION",
    "instance": "SUMMITAI_INSTANCE",
    "incident_statuses": "SUMMITAI_INCIDENT_STATUSES",
    "lookback_days": "SUMMITAI_LOOKBACK_DAYS",
    "page_size": "SUMMITAI_PAGE_SIZE",
    "org_id": "SUMMITAI_ORG_ID",
    "proxy_id": "SUMMITAI_PROXY_ID",
    "incidents_service": "SUMMITAI_INCIDENTS_SERVICE",
    "incident_detail_service": "SUMMITAI_DETAIL_SERVICE",
    "update_service": "SUMMITAI_UPDATE_SERVICE",
    "changes_service": "SUMMITAI_CHANGES_SERVICE",
    "caller_email": "SUMMITAI_CALLER_EMAIL",
    "auth_header": "SUMMITAI_AUTH_HEADER",
    "auth_prefix": "SUMMITAI_AUTH_PREFIX",
    "incidents_path": "SUMMITAI_INCIDENTS_PATH",
    "changes_path": "SUMMITAI_CHANGES_PATH",
}


def load_config() -> dict:
    cfg = dict(DEFAULTS)
    for key, var in _ENV_MAP.items():
        val = os.environ.get(var)
        if val not in (None, ""):
            cfg[key] = val
    if os.environ.get("SUMMITAI_VERIFY_TLS") == "0":
        cfg["verify_tls"] = False
    if os.environ.get("SUMMITAI_USE_PROXY") == "1":
        cfg["use_proxy"] = True
    try:
        file_cfg = yaml.safe_load(CONFIG_PATH.read_text()) or {}
        for key in DEFAULTS:
            if file_cfg.get(key) not in (None, ""):
                cfg[key] = file_cfg[key]
        if isinstance(file_cfg.get("verify_tls"), bool):
            cfg["verify_tls"] = file_cfg["verify_tls"]
        if isinstance(file_cfg.get("use_proxy"), bool):
            cfg["use_proxy"] = file_cfg["use_proxy"]
    except (OSError, yaml.YAMLError):
        pass
    cfg["base_url"] = str(cfg["base_url"]).rstrip("/")
    if cfg["api_style"] not in ("summit_wcf", "rest"):
        cfg["api_style"] = "summit_wcf"
    if cfg["incidents_service"] == "IM_FetchIncidents":
        # pre-2.33 placeholder default that no deployment answers — configs
        # saved with it migrate to the real Summit list service.
        cfg["incidents_service"] = "IM_GetIncidentList"
    if cfg["incident_detail_service"] == "IM_GetIncidentDetails":
        # pre-2.35 placeholder — the vendor-confirmed detail service
        cfg["incident_detail_service"] = "IM_GetIncidentDetailsAndChangeHistory"
    return cfg


def save_config(cfg: dict) -> None:
    clean = {k: cfg.get(k, DEFAULTS[k]) for k in DEFAULTS}
    CONFIG_PATH.write_text(yaml.safe_dump(clean, sort_keys=False))
    os.chmod(CONFIG_PATH, 0o600)   # the API key lives in this file


def configured(cfg: dict | None = None) -> bool:
    return bool((cfg or load_config())["base_url"])


# ---------- field normalisation ----------

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
    return {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4",
            "1": "P1", "2": "P2", "3": "P3", "4": "P4"}.get(s, s or "P3")


def _norm_incident(raw: dict) -> dict:
    return {
        "id": str(_first(raw, "TicketNo", "Ticket_No", "TicketNumber", "IncidentID",
                         "IncidentId", "IncidentNo", "id", "number", "Number",
                         "RequestID", "ticket")),
        "priority": _norm_priority(_first(raw, "Priority", "Priority_Name", "priority",
                                          "PriorityName")),
        "status": _first(raw, "Status", "status", "StatusName", default="Open"),
        "title": _first(raw, "Symptom", "Subject", "Title", "title", "summary",
                        "ShortDescription", default="(no subject)"),
        "description": _first(raw, "Description", "description", "Details",
                              "TicketInformation", "detail", default=""),
        "ci": _first(raw, "CI_Value", "CI", "CIName", "AffectedCI", "Asset",
                     "ConfigurationItem", "Server", "Hostname", "host", default=""),
        "reported_at": _first(raw, "LoggedTime", "Log_Time", "CreatedDateTime",
                              "CreatedTime", "ReportedOn", "createdAt", "OpenedTime",
                              default=""),
        "raised_by": _first(raw, "Caller", "Caller_EmailID", "CallerName", "RaisedBy",
                            "Requester", "ReportedBy", "AffectedUser", default=""),
        "assignee": _first(raw, "AssignedTo", "Assigned_Analyst", "AssignedEngineer",
                           "Analyst", "Owner", "assignee", "Assigned_WorkGroup_Name",
                           default="Unassigned"),
        "workgroup": _first(raw, "Assigned_WorkGroup_Name", "WorkgroupName",
                            "Workgroup_Name", "Workgroup", "AssignedWorkgroup",
                            default=""),
        "category": _first(raw, "Category", "Category_Name", "category",
                           "Classification_Name", "ClassName", default=""),
        "url": _first(raw, "URL", "url", "Link", default=""),
    }


def _norm_change(raw: dict) -> dict:
    return {
        "id": str(_first(raw, "ChangeNo", "Change_No", "ChangeID", "id", "number",
                         "Number", default="")),
        "title": _first(raw, "Symptom", "Subject", "Title", "title", default="(no subject)"),
        "status": _first(raw, "Status", "status", default="Approved"),
        "risk": _first(raw, "Risk", "RiskLevel", "risk", default="Medium"),
        "type": _first(raw, "ChangeType", "Change_Type", "Type", default="Normal"),
        "window": _first(raw, "ScheduledWindow", "Window", "PlannedStart",
                         "Planned_Start_Time", default=""),
        "ci": _first(raw, "CI_Value", "CI", "CIName", "AffectedCI", "Server", default=""),
        "implementer": _first(raw, "Implementer", "AssignedTo", "Assigned_Analyst",
                              "Owner", default=""),
        "approver": _first(raw, "Approver", "ApprovedBy", default=""),
        "plan": raw.get("plan") or raw.get("ImplementationPlan") or [],
    }


# ---------- transports ----------

def _open(url: str, cfg: dict, data: bytes | None, headers: dict) -> tuple[int, str, str]:
    """POST/GET and return (status, body_text, content_type)."""
    handlers = []
    if not cfg.get("use_proxy"):
        handlers.append(urllib.request.ProxyHandler({}))   # go DIRECT, ignore HTTP(S)_PROXY
    if url.startswith("https"):
        ctx = ssl.create_default_context()
        if not cfg["verify_tls"]:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method="POST" if data is not None else "GET")
    try:
        with opener.open(req, timeout=25) as resp:
            return resp.status, _decode_body(resp), resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        return e.code, _decode_body(e), e.headers.get("Content-Type", "")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise RuntimeError(f"SummitAI request failed: {e}") from e


def _decode_body(resp) -> str:
    body = resp.read()
    enc = (resp.headers.get("Content-Encoding") or "").lower()
    if "gzip" in enc:
        import gzip
        try:
            body = gzip.decompress(body)
        except OSError:
            pass
    elif "deflate" in enc:
        import zlib
        try:
            body = zlib.decompress(body)
        except zlib.error:
            body = zlib.decompress(body, -zlib.MAX_WBITS)
    return body.decode(errors="replace")


def _parse_json(raw: str):
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    # Summit sometimes double-encodes: a JSON string containing JSON
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return data
    return data


def _find_rows(data, depth: int = 0):
    """Find the first list of dicts anywhere in a (possibly wrapped) response."""
    if depth > 6:
        return None
    if isinstance(data, list):
        if all(isinstance(x, dict) for x in data) and data:
            return data
        return [] if not data else None
    if isinstance(data, dict):
        for key in ("IncidentList", "TicketList", "Incidents", "Changes", "ChangeList",
                    "OutputObject", "Output", "Data", "data", "result", "results",
                    "items", "value", "Details", "TicketDetails"):
            if key in data:
                rows = _find_rows(data[key], depth + 1)
                if rows is not None:
                    return rows
        for v in data.values():
            if isinstance(v, (list, dict)):
                rows = _find_rows(v, depth + 1)
                if rows is not None:
                    return rows
    return None


def _ticket_no(incident_id):
    """Summit's samples pass TicketNo as a number — convert when possible."""
    s = str(incident_id).strip()
    return int(s) if s.isdigit() else s


def _wcf_call(service: str, params: dict | None, cfg: dict):
    """WCF call that expects row-shaped data back (lists/details)."""
    data = _wcf_raw(service, params, cfg)
    rows = _find_rows(data)
    if rows is None:
        # a single-object response (e.g. one ticket) — wrap it
        if isinstance(data, dict):
            inner = data.get("OutputObject") or data.get("Output") or data
            return [inner] if isinstance(inner, dict) else []
        return []
    return rows


def _wcf_raw(service: str, params: dict | None, cfg: dict):
    """WCF call returning the parsed response as-is (raises on any error)."""
    envelope = {
        "ServiceName": service,
        "objCommonParameters": {
            "_ProxyDetails": {
                "AuthType": "APIKey",
                "APIKey": cfg["token"],
                "ProxyID": int(cfg.get("proxy_id") or 0),
                "ReturnType": "JSON",
                "OrgID": int(cfg.get("org_id") or 1),
                "TokenID": "",
            },
            **(params or {}),
        },
    }
    url = cfg["base_url"]
    op = str(cfg.get("wcf_operation") or "").strip().strip("/")
    if op and not url.lower().endswith("/" + op.lower()):
        url = f"{url}/{op}"
    status, raw, ctype = _open(url, cfg,
                               json.dumps(envelope).encode(),
                               {"Content-Type": "application/json; charset=utf-8",
                                "Accept": "application/json"})
    if status >= 400:
        # surface Summit's own explanation (JSON error or proxy/WAF page text)
        snippet = " ".join(raw.split())[:220]
        hint = ""
        if status == 415:
            hint = (" — the endpoint rejected the JSON content type, which usually means"
                    " the operation path is wrong (a bare ...WCF.svc URL is the SOAP"
                    f" endpoint). Current path: {url}")
        raise RuntimeError(f"SummitAI returned HTTP {status} for {service}"
                           + (f" — response: {snippet}" if snippet else "") + hint)
    data = _parse_json(raw)
    if data is None:
        if not raw.strip():
            raise RuntimeError(
                f"SummitAI answered HTTP {status} with an EMPTY body for {service}"
                f" (content-type: {ctype or 'none'}). Summit typically does this when"
                " the ServiceName is unknown or not whitelisted for this API key —"
                " confirm the exact list/detail ServiceNames with your Summit admin.")
        raise RuntimeError(f"SummitAI returned non-JSON for {service}"
                           f" (content-type: {ctype or 'none'}): {raw[:160]}")
    if isinstance(data, dict):
        err = data.get("Errors") or data.get("Error") or data.get("ErrorMessage")
        if err:
            raise RuntimeError(f"SummitAI error from {service}: {str(err)[:300]}")
    return data


def _extra_params(cfg: dict) -> dict:
    try:
        extra = json.loads(cfg.get("incidents_params") or "{}")
        return extra if isinstance(extra, dict) else {}
    except json.JSONDecodeError:
        return {}


def _incident_list_params(cfg: dict) -> dict:
    """IM_GetIncidentList refuses to answer without an objIncidentCommonFilter
    block — build it from config, letting incidents_params override any key."""
    today = time.time()
    lookback = int(cfg.get("lookback_days") or 30)
    fmt = lambda ts: time.strftime("%Y-%m-%d", time.localtime(ts))  # noqa: E731
    flt = {
        "WorkgroupName": "",
        "CurrentPageIndex": 0,
        "PageSize": int(cfg.get("page_size") or 100),
        "OrgID": str(cfg.get("org_id") or 1),
        "Instance": cfg.get("instance") or "IT",
        "Status": cfg.get("incident_statuses")
                  or "New,In-Progress,Assigned,Pending,Resolved,Closed",
        "strUpdatedFromDate": fmt(today - lookback * 86400),
        "strUpdatedToDate": fmt(today + 86400),   # inclusive of today
        "IsWebServiceRequest": True,
    }
    extra = dict(_extra_params(cfg))
    override = extra.pop("objIncidentCommonFilter", None)
    if isinstance(override, dict):
        flt.update(override)
    return {"objIncidentCommonFilter": flt, **extra}


def _rest_get(path: str, cfg: dict):
    headers = {"Accept": "application/json"}
    if cfg["token"]:
        headers[cfg["auth_header"]] = f"{cfg['auth_prefix']}{cfg['token']}"
    status, raw, _ctype = _open(cfg["base_url"] + path, cfg, None, headers)
    if status >= 400:
        snippet = " ".join(raw.split())[:220]
        raise RuntimeError(f"SummitAI returned HTTP {status}"
                           + (f" — response: {snippet}" if snippet else ""))
    data = _parse_json(raw)
    rows = _find_rows(data)
    return rows if rows is not None else []


def _fetch_incident_rows(cfg: dict) -> list[dict]:
    if cfg["api_style"] == "rest":
        return _rest_get(cfg["incidents_path"], cfg)
    return _wcf_call(cfg["incidents_service"], _incident_list_params(cfg), cfg)


def _fetch_change_rows(cfg: dict) -> list[dict]:
    if cfg["api_style"] == "rest":
        return _rest_get(cfg["changes_path"], cfg)
    return _wcf_call(cfg["changes_service"], None, cfg)


# ---------- public API ----------

def list_incidents(priorities: tuple[str, ...] | None = ("P1", "P2"),
                   include_closed: bool = False) -> list[dict]:
    """Incidents from the configured window. priorities=None means all
    priorities; closed/resolved rows are kept only when include_closed."""
    cfg = load_config()
    if not configured(cfg):
        rows = _demo_incidents()
    else:
        rows = [_norm_incident(r) for r in _fetch_incident_rows(cfg)]
    kept = [i for i in rows
            if (not priorities or i["priority"] in priorities)
            and (include_closed
                 or str(i["status"]).lower() not in ("closed", "resolved", "cancelled"))]
    order = {p: n for n, p in enumerate(("P1", "P2", "P3", "P4", "P5"))}

    def newest_first(i):
        s = str(i["id"])
        return -int(s) if s.isdigit() else 0

    kept.sort(key=lambda i: (order.get(i["priority"], 9), newest_first(i), i["id"]))
    return kept


def get_incident(incident_id: str) -> dict | None:
    cfg = load_config()
    if not configured(cfg):
        return next((i for i in _demo_incidents() if i["id"] == incident_id), None)
    want = str(incident_id)
    if cfg["api_style"] == "summit_wcf":
        # The listing is the proven-working source — it is the base, and the
        # detail service (whose response shape varies wildly per deployment)
        # only ENRICHES it. A detail answer that doesn't clearly belong to
        # this ticket is discarded instead of being shown as the incident.
        base = next((i for i in (_norm_incident(r) for r in _fetch_incident_rows(cfg))
                     if i["id"] == want), None)
        detail = None
        try:
            rows = _wcf_call(cfg["incident_detail_service"],
                             {"TicketNo": _ticket_no(incident_id),
                              "RequestType": "RemoteCall"}, cfg)
            for r in rows:
                n = _norm_incident(r)
                looks_real = n["title"] != "(no subject)" or n["description"]
                # some deployments omit the ticket no from the detail body;
                # accept that only when we have the listing row to anchor it
                if n["id"] == want or (n["id"] == "" and base is not None and looks_real):
                    detail = n
                    break
        except RuntimeError:
            pass   # unknown/unwhitelisted detail service — the listing suffices
        if base and detail:
            # normaliser defaults must never overwrite real listing data
            placeholders = ("", None, "Unassigned", "(no subject)", "Open", "P3")
            merged = dict(base)
            for k, v in detail.items():
                if k != "id" and v not in placeholders:
                    merged[k] = v
            return merged
        return detail or base
    rows = [_norm_incident(r) for r in _rest_get(f"{cfg['incidents_path']}/{incident_id}", cfg)]
    return rows[0] if rows else None


def _find_ticket_no(data, depth: int = 0) -> str:
    """Pull the (new) ticket number out of a LogOrUpdateIncident response."""
    if depth > 5:
        return ""
    if isinstance(data, dict):
        for k in ("TicketNo", "Ticket_No", "TicketNumber", "IncidentID", "TicketID"):
            if data.get(k):
                return str(data[k])
        for v in data.values():
            found = _find_ticket_no(v, depth + 1)
            if found:
                return found
    if isinstance(data, str):
        m = re.search(r"\b(\d{4,})\b", data)   # e.g. "Ticket 318417 logged successfully"
        return m.group(1) if m else ""
    return ""


def create_incident(f: dict) -> dict:
    """Raise a new ticket via IM_LogOrUpdateIncident (the create variant of
    the vendor sample: Status New, no TicketNo). Only description and caller
    email are mandatory; every other field is passed through when supplied."""
    cfg = load_config()
    if not configured(cfg):
        return {"ok": False, "error": "SummitAI is not configured"}
    desc = str(f.get("description") or "").strip()
    caller = str(f.get("caller_email") or cfg.get("caller_email") or "").strip()
    if not desc:
        return {"ok": False, "error": "A description of the issue is required"}
    if "@" not in caller:
        return {"ok": False, "error": "A valid caller email is required"}
    ticket = {
        "IsFromWebService": True,
        "Priority_Name": str(f.get("priority") or ""),
        "Classification_Name": str(f.get("classification") or ""),
        "Sup_Function": "IT",
        "Caller_EmailID": caller,
        "Status": "New",
        "Urgency_Name": str(f.get("urgency") or ""),
        "Assigned_WorkGroup_Name": str(f.get("workgroup") or ""),
        "Medium": "Web",
        "Impact_Name": str(f.get("impact") or ""),
        "Category_Name": str(f.get("category") or ""),
        "CI_ID": "",
        "SLA_Name": "",
        "OpenCategory_Name": "",
        "Source": "Person",
        "Description": desc,
        "PageName": "LogTicket",
    }
    params = {
        "incidentParamsJSON": {
            "IncidentContainerJsonObj": {
                "Updater": "Caller",
                "CI_Key": "hostname",
                "CI_Value": str(f.get("ci") or ""),
                "Ticket": ticket,
                "TicketInformation": {
                    "Information": desc,
                    "InternalLog": "",
                    "UserLog": "",
                    "Solution": "",
                },
                "CustomFields": [],
            },
            "RequestType": "RemoteCall",
        }
    }
    try:
        data = _wcf_raw(cfg.get("update_service") or "IM_LogOrUpdateIncident",
                        params, cfg)
    except RuntimeError as exc:
        return {"ok": False, "error": str(exc)[:400]}
    reply = data if isinstance(data, str) else json.dumps(data, default=str)
    return {"ok": True, "ticket": _find_ticket_no(data), "response": reply[:400]}


def update_incident(incident_id: str, information: str,
                    status: str = "", solution: str = "") -> dict:
    """Write a work-log entry (and optionally a status/solution) to a ticket
    via IM_LogOrUpdateIncident — the operation this key is provisioned for.
    The envelope mirrors the vendor sample; only non-empty fields are sent."""
    cfg = load_config()
    if not configured(cfg):
        return {"ok": False, "error": "SummitAI is not configured"}
    if not str(information).strip():
        return {"ok": False, "error": "Update text is empty"}
    ticket = {
        "IsFromWebService": True,
        "TicketNo": _ticket_no(incident_id),
        "Sup_Function": "IT",
        "Medium": "Web",
        "Source": "Person",
        "PageName": "LogTicket",
    }
    if cfg.get("caller_email"):
        ticket["Caller_EmailID"] = cfg["caller_email"]
    if status:
        ticket["Status"] = status
    params = {
        "incidentParamsJSON": {
            "IncidentContainerJsonObj": {
                "Updater": "Caller",
                "CI_Key": "hostname",
                "CI_Value": "",
                "Ticket": ticket,
                "TicketInformation": {
                    "Information": information,
                    "InternalLog": "",
                    "UserLog": "",
                    "Solution": solution or "",
                },
                "CustomFields": [],
            },
            "RequestType": "RemoteCall",
        }
    }
    try:
        data = _wcf_raw(cfg.get("update_service") or "IM_LogOrUpdateIncident",
                        params, cfg)
    except RuntimeError as exc:
        return {"ok": False, "error": str(exc)[:400]}
    reply = data if isinstance(data, str) else json.dumps(data, default=str)
    return {"ok": True, "ticket": str(incident_id), "response": reply[:400]}


def list_changes() -> list[dict]:
    cfg = load_config()
    if not configured(cfg):
        return _demo_changes()
    return [_norm_change(r) for r in _fetch_change_rows(cfg)]


def status() -> dict:
    ok = configured()
    return {"configured": ok, "demo": not ok,
            "source": "SummitAI" + ("" if ok else " (demo data)")}


def public_config() -> dict:
    "Config for the settings UI; the API key never leaves the server."
    cfg = load_config()
    return {**{k: cfg[k] for k in DEFAULTS if k != "token"},
            "token_set": bool(cfg["token"]), "configured": configured(cfg)}


def _merged(overrides: dict | None) -> dict:
    """Stored config overlaid with (unsaved) form values; empty token in
    overrides means: use the stored one."""
    cfg = load_config()
    for k, v in (overrides or {}).items():
        if k in ("verify_tls", "use_proxy"):
            cfg[k] = bool(v)
        elif k in DEFAULTS and v not in (None, ""):
            cfg[k] = v
    cfg["base_url"] = str(cfg["base_url"]).rstrip("/")
    return cfg


def test_config(overrides: dict | None = None) -> dict:
    """Try the API with (unsaved) form values so the operator can verify
    before saving."""
    cfg = _merged(overrides)
    if not cfg["base_url"]:
        return {"ok": False, "error": "Base URL is required"}
    out = {"ok": True, "incidents": None, "changes": None, "changes_error": None}
    try:
        out["incidents"] = len(_fetch_incident_rows(cfg))
    except Exception as exc:  # noqa: BLE001
        out.update(ok=False, error=f"incidents: {exc}")
        return out
    try:
        out["changes"] = len(_fetch_change_rows(cfg))
    except Exception as exc:  # noqa: BLE001
        # incidents worked — a wrong changes ServiceName shouldn't fail the test
        out["changes_error"] = str(exc)[:300]
    return out


# ServiceNames seen across SummitAI deployments; wrong ones are harmless
# (Summit answers them with an empty body), so probing is read-only and safe.
_CANDIDATE_LIST_SERVICES = [
    "IM_FetchIncidents", "IM_GetIncidentList", "IM_GetIncidentDetailsList",
    "IM_FetchIncidentList", "GetIncidentsList", "IM_GetIncidents",
    "IM_GetMyIncidentList", "IM_FetchAssignedIncidents", "IM_GetTicketList",
]
_CANDIDATE_DETAIL_SERVICES = [
    "IM_GetIncidentDetailsAndChangeHistory", "IM_GetIncidentDetails",
    "IM_FetchIncidentDetails", "GetIncidentDetails",
]


def discover_services(overrides: dict | None = None, ticket_no: str = "") -> dict:
    """Probe common SummitAI ServiceNames so the operator can find the ones
    their deployment/key actually answers. List services are tried always;
    detail services only when a known ticket number is supplied."""
    cfg = _merged(overrides)
    if not cfg["base_url"]:
        return {"results": [], "error": "Base URL is required"}
    if cfg["api_style"] != "summit_wcf":
        return {"results": [], "error": "ServiceName discovery applies to the summit_wcf style"}

    def probe(name: str, kind: str, params: dict | None) -> dict:
        try:
            rows = _wcf_call(name, params, cfg)
            return {"service": name, "kind": kind, "ok": True, "rows": len(rows)}
        except RuntimeError as exc:
            msg = str(exc)
            empty = "EMPTY body" in msg
            return {"service": name, "kind": kind, "ok": False, "empty": empty,
                    "error": None if empty else msg[:180]}

    results = []
    for name in dict.fromkeys([cfg["incidents_service"], *_CANDIDATE_LIST_SERVICES]):
        results.append(probe(name, "list", _incident_list_params(cfg)))
    if ticket_no.strip():
        for name in dict.fromkeys([cfg["incident_detail_service"], *_CANDIDATE_DETAIL_SERVICES]):
            results.append(probe(name, "detail",
                                 {"TicketNo": _ticket_no(ticket_no),
                                  "RequestType": "RemoteCall"}))
    return {"results": results}


# ---------- demo data (used until a base URL is configured) ----------

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
