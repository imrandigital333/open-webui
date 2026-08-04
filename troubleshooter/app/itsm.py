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

from . import vaultclient
from .inventory import BASE_DIR

# UI-managed settings live here (chmod 600, gitignored); environment variables
# act as fallback so env-based deployments keep working. Once Vault is enabled
# and this config is migrated, "token"/"change_token" move to Vault instead —
# see save_config / migrate_to_vault — and only secret_in_vault stays here.
CONFIG_PATH = BASE_DIR / "itsm.yaml"
_SECRET_KEYS = ("token", "change_token")
_VAULT_PATH = "itsm"

DEFAULTS = {
    "api_style": "summit_wcf",          # summit_wcf | rest
    "base_url": "",
    "token": "",                        # API key (wcf) or bearer token (rest)
    "secret_in_vault": False,           # token/change_token stored in Vault instead of this file
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
    "change_detail_service": "CM_GetCR_Details",
    "change_update_service": "CM_LogOrUpdateCR",
    # Change operations use a DIFFERENT API key than incidents; when blank
    # they fall back to the incident token so existing setups keep working.
    "change_token": "",
    # change list filter (mirrors the incident list): a 30-day updated window
    "change_statuses": "",                       # optional Status filter (comma list)
    "change_list_filter_key": "objChangeCommonFilter",
    "change_lookback_days": 30,
    # CR creation requires a support-function display name (per the vendor
    # sample); deployment-specific, so it's configurable.
    "change_support_function": "IT",
    "change_support_function_name": "BIAL Services",
    # Create-time values mirroring the vendor's working sample. These are
    # deployment-specific record IDs/names — adjust in Settings if a create
    # is rejected for one of them.
    # The sample's status — with Change_Request_Id present, this validates.
    # (Omitting Status makes Summit NRE during create.)
    "change_create_status": "Initial Authorization",
    # Category NAME and ID must be a matching pair from Summit's category
    # master, so they're set together from config (not from free text / AI).
    "change_category_name": "Minor",
    "change_category_id": 132,
    "change_executive_id": "2",
    "change_owner_workgroup_id": "12",
    "change_default_workgroup": "Windows Server Support",
    # known-good Summit workgroup names offered as chips in the assistant
    "change_workgroups": "Windows Server Support,Unix Server Support",
    "change_classification": "Normal",
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
    "change_detail_service": "SUMMITAI_CHANGE_DETAIL_SERVICE",
    "change_update_service": "SUMMITAI_CHANGE_UPDATE_SERVICE",
    "change_token": "SUMMITAI_CHANGE_TOKEN",
    "change_statuses": "SUMMITAI_CHANGE_STATUSES",
    "change_list_filter_key": "SUMMITAI_CHANGE_FILTER_KEY",
    "change_lookback_days": "SUMMITAI_CHANGE_LOOKBACK_DAYS",
    "change_support_function": "SUMMITAI_CHANGE_SUPPORT_FUNCTION",
    "change_support_function_name": "SUMMITAI_CHANGE_SUPPORT_FUNCTION_NAME",
    "change_create_status": "SUMMITAI_CHANGE_CREATE_STATUS",
    "change_category_name": "SUMMITAI_CHANGE_CATEGORY_NAME",
    "change_category_id": "SUMMITAI_CHANGE_CATEGORY_ID",
    "change_executive_id": "SUMMITAI_CHANGE_EXECUTIVE_ID",
    "change_owner_workgroup_id": "SUMMITAI_CHANGE_OWNER_WORKGROUP_ID",
    "change_default_workgroup": "SUMMITAI_CHANGE_DEFAULT_WORKGROUP",
    "change_workgroups": "SUMMITAI_CHANGE_WORKGROUPS",
    "change_classification": "SUMMITAI_CHANGE_CLASSIFICATION",
    "caller_email": "SUMMITAI_CALLER_EMAIL",
    "auth_header": "SUMMITAI_AUTH_HEADER",
    "auth_prefix": "SUMMITAI_AUTH_PREFIX",
    "incidents_path": "SUMMITAI_INCIDENTS_PATH",
    "changes_path": "SUMMITAI_CHANGES_PATH",
}


def _read_raw() -> dict:
    """Env + file, with NO Vault resolution — the only safe base for
    re-writing the file (see integrations._read_raw for why)."""
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


def load_config() -> dict:
    cfg = _read_raw()
    if vaultclient.enabled() and cfg.get("secret_in_vault"):
        try:
            data = vaultclient.read_secret(_VAULT_PATH) or {}
            for key in _SECRET_KEYS:
                cfg[key] = data.get(key, "")
        except vaultclient.VaultError as exc:
            for key in _SECRET_KEYS:
                cfg[key] = ""
            cfg["vault_error"] = str(exc)
    return cfg


def save_config(cfg: dict) -> None:
    """Persist config. token/change_token go to Vault (instead of the file)
    once Vault is enabled — a Vault write failure raises rather than silently
    falling back to plaintext."""
    clean = {k: cfg.get(k, DEFAULTS[k]) for k in DEFAULTS if k not in _SECRET_KEYS}
    if vaultclient.enabled():
        vault_data = {key: str(cfg.get(key) or "") for key in _SECRET_KEYS}
        if any(vault_data.values()):
            vaultclient.write_secret(_VAULT_PATH, vault_data)
        clean["secret_in_vault"] = True
        for key in _SECRET_KEYS:
            clean[key] = ""
    else:
        clean["secret_in_vault"] = False
        for key in _SECRET_KEYS:
            clean[key] = cfg.get(key, DEFAULTS[key])
    CONFIG_PATH.write_text(yaml.safe_dump(clean, sort_keys=False))
    os.chmod(CONFIG_PATH, 0o600)   # the API key lives in this file (unless Vault-backed)


def migrate_to_vault() -> dict:
    """Move the locally-stored token/change_token into Vault."""
    if not vaultclient.enabled():
        return {"ok": False, "error": "Vault is not configured (VAULT_ADDR / VAULT_TOKEN unset)."}
    raw = _read_raw()
    if raw.get("secret_in_vault"):
        return {"ok": True, "migrated": False, "reason": "already in Vault"}
    vault_data = {key: raw.get(key, "") for key in _SECRET_KEYS}
    if not any(vault_data.values()):
        return {"ok": True, "migrated": False, "reason": "no API key set"}
    try:
        vaultclient.write_secret(_VAULT_PATH, vault_data)
    except vaultclient.VaultError as exc:
        return {"ok": False, "error": str(exc)}
    for key in _SECRET_KEYS:
        raw[key] = ""
    raw["secret_in_vault"] = True
    CONFIG_PATH.write_text(yaml.safe_dump(raw, sort_keys=False))
    os.chmod(CONFIG_PATH, 0o600)
    return {"ok": True, "migrated": True}


def configured(cfg: dict | None = None) -> bool:
    return bool((cfg or load_config())["base_url"])


# ---------- field normalisation ----------

def _first(d: dict, *keys, default=""):
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return default


# A ticket/change number looks like optional letters + 3+ digits (318543,
# INC318417, CR1842). Used to tell the human-facing number apart from opaque
# record handles (e.g. Ticket_ID = "36RUGsujKPUeZJh%2b...%3d%3d").
_ID_VAL_RE = re.compile(r"^[A-Za-z]{0,6}[-_]?\d{3,}$")
_ID_ENTITY = ("ticket", "incident", "change", "request", "problem", "sr", "call")

# preferred known id fields, per entity — space/underscore variants included
_INCIDENT_ID_KEYS = ("Incident ID", "IncidentID", "Incident_ID", "IncidentNo",
                     "Incident_No", "IncidentNumber", "TicketNo", "Ticket_No",
                     "TicketNumber", "RequestID", "Request_Id", "SR_ID", "SRID",
                     "CallID", "id", "number", "Number", "Ticket_ID", "TicketID")
_CHANGE_ID_KEYS = ("ChangeNo", "Change_No", "ChangeID", "Change_Request_Id",
                   "ChangeRequestID", "CR_ID", "CRID", "CR_No", "ChangeNumber",
                   "id", "number", "Number")


def _pick_id(raw: dict, known: tuple) -> str:
    """Choose the human-facing ticket/CR number. Collect candidates from the
    known fields plus any entity-id-shaped key, then PREFER one whose value
    looks like a real number (digits, optional short prefix) over opaque
    handles/tokens; fall back to the first non-empty candidate."""
    cands = []
    for k in known:
        v = raw.get(k)
        if v not in (None, "", 0):
            cands.append(str(v).strip())
    for k, v in raw.items():
        if not isinstance(v, (str, int)) or v in (None, "", 0):
            continue
        nk = re.sub(r"[^a-z0-9]", "", str(k).lower())
        if nk.startswith(_ID_ENTITY) and ("no" in nk or "number" in nk
                                          or "id" in nk or "code" in nk):
            cands.append(str(v).strip())
    for c in cands:                       # prefer a value shaped like a number
        if _ID_VAL_RE.match(c):
            return c
    return cands[0] if cands else ""


def _norm_priority(v) -> str:
    s = str(v or "").upper().replace("PRIORITY", "").strip()
    for p in ("P1", "P2", "P3", "P4", "P5"):
        if p in s:
            return p
    return {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4",
            "1": "P1", "2": "P2", "3": "P3", "4": "P4"}.get(s, s or "P3")


def _norm_incident(raw: dict) -> dict:
    return {
        "id": str(_pick_id(raw, _INCIDENT_ID_KEYS)),
        "priority": _norm_priority(_first(raw, "Priority", "Priority_Name", "priority",
                                          "PriorityName")),
        "status": _first(raw, "Status", "status", "StatusName", default="Open"),
        "title": _first(raw, "Symptom", "Subject", "Title", "title", "summary",
                        "ShortDescription", default="(no subject)"),
        "description": _first(raw, "Description", "description", "Details",
                              "TicketInformation", "detail", default=""),
        "ci": _first(raw, "CI_Value", "CI", "CIName", "AffectedCI", "Asset",
                     "ConfigurationItem", "Server", "Hostname", "host", default=""),
        "reported_at": _first(raw, "LoggedTime", "Logged Time", "Log_Time",
                              "CreatedDateTime", "CreatedTime", "ReportedOn",
                              "createdAt", "OpenedTime", default=""),
        "raised_by": _first(raw, "Caller", "Caller_EmailID", "CallerName", "RaisedBy",
                            "Requester", "ReportedBy", "AffectedUser", default=""),
        "assignee": _first(raw, "AssignedTo", "Assigned_Analyst", "Assigned_Engineer",
                           "AssignedEngineer", "Analyst", "Owner", "assignee",
                           default="Unassigned"),
        "workgroup": _first(raw, "Workgroup Name", "Assigned_WorkGroup_Name",
                            "WorkgroupName", "Workgroup_Name", "Workgroup",
                            "AssignedWorkgroup", default=""),
        "category": _first(raw, "Category", "FullCategory", "Category_Name", "category",
                           "Classification", "Classification_Name", "ClassName", default=""),
        "url": _first(raw, "URL", "url", "Link", default=""),
    }


def _norm_change(raw: dict) -> dict:
    return {
        "id": str(_pick_id(raw, _CHANGE_ID_KEYS)),
        "title": _first(raw, "Symptom", "Subject", "Title", "Information", "title",
                        default="(no subject)"),
        "status": _first(raw, "Status", "status", default="Approved"),
        "risk": _first(raw, "Risk", "RiskLevel", "risk", default="Medium"),
        "type": _first(raw, "ChangeType", "ChangeTypeName", "Change_Type", "Type",
                       default="Normal"),
        "category": _first(raw, "Category", "Category_Name", "Change_Category",
                           "ChangeCategoryName", default=""),
        "priority": _first(raw, "Priority_Name", "Priority", default=""),
        "downtime": bool(raw.get("Downtime_Required", False)),
        "description": _first(raw, "Description", "description", default=""),
        "window": _first(raw, "ScheduledWindow", "Window", "PlannedStart",
                         "Planned_Start_Time", "Actual_Start_Time", default=""),
        "window_end": _first(raw, "Planned_End_Time", "Actual_End_Time", default=""),
        "ci": _first(raw, "CI_Value", "CI", "CIName", "AffectedCI", "Server", default=""),
        "implementer": _first(raw, "Implementer", "AssignedTo", "Assigned_Analyst",
                              "Assigned_Workgroup", "Owner", default=""),
        "workgroup": _first(raw, "Owner_Workgroup", "Assigned_Workgroup", "Workgroup",
                            default=""),
        "approver": _first(raw, "Approver", "ApprovedBy", default=""),
        "backout": _first(raw, "Back_Out_Plan", "BackoutPlan", default=""),
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


def _change_list_params(cfg: dict) -> dict:
    """objChangeCommonFilter with a rolling updated-date window (default 30
    days), mirroring the incident list. The filter key name is configurable
    because it varies across SummitAI change deployments."""
    today = time.time()
    lookback = int(cfg.get("change_lookback_days") or 30)
    fmt = lambda ts: time.strftime("%Y-%m-%d", time.localtime(ts))  # noqa: E731
    flt = {
        "CurrentPageIndex": 0,
        "PageSize": int(cfg.get("page_size") or 100),
        "OrgID": str(cfg.get("org_id") or 1),
        "Instance": cfg.get("instance") or "IT",
        "strUpdatedFromDate": fmt(today - lookback * 86400),
        "strUpdatedToDate": fmt(today + 86400),
        "IsWebServiceRequest": True,
    }
    if cfg.get("change_statuses"):
        flt["Status"] = cfg["change_statuses"]
    key = cfg.get("change_list_filter_key") or "objChangeCommonFilter"
    return {key: flt}


def _fetch_change_rows(cfg: dict) -> list[dict]:
    ccfg = _change_cfg(cfg)
    if cfg["api_style"] == "rest":
        return _rest_get(cfg["changes_path"], ccfg)
    return _wcf_call(cfg["changes_service"], _change_list_params(cfg), ccfg)


# ---------- public API ----------

# Tickets raised through the app are tracked here and merged into the
# dashboard by their detail — this instance's IM_GetIncidentList only surfaces
# queued/routed tickets, so a brand-new unassigned incident won't appear in the
# list for a while even though it exists.
_CREATED_PATH = BASE_DIR / "data" / "created_incidents.json"
_CREATED_TTL = 7 * 86400   # keep showing an app-created ticket for 7 days


def _load_created() -> list[dict]:
    try:
        return json.loads(_CREATED_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return []


def record_created_incident(ticket_no) -> None:
    tid = str(ticket_no or "").strip()
    if not tid:
        return
    now = time.time()
    items = [x for x in _load_created()
             if str(x.get("id")) != tid and now - float(x.get("ts", 0)) < _CREATED_TTL]
    items.append({"id": tid, "ts": now})
    try:
        _CREATED_PATH.parent.mkdir(parents=True, exist_ok=True)
        _CREATED_PATH.write_text(json.dumps(items[-50:]))
    except OSError:
        pass


def _recent_created_ids() -> list[str]:
    now = time.time()
    return [str(x["id"]) for x in _load_created()
            if now - float(x.get("ts", 0)) < _CREATED_TTL]


def _incident_detail_only(cfg: dict, tid: str) -> dict | None:
    """Fetch one ticket via the detail service only (no list dependency)."""
    try:
        rows = _wcf_call(cfg["incident_detail_service"],
                         {"TicketNo": _ticket_no(tid), "TicketID": _ticket_no(tid),
                          "RequestType": "RemoteCall"}, cfg)
    except RuntimeError:
        return None
    for r in rows:
        n = _norm_incident(r)
        if n["id"] == str(tid) or n["title"] != "(no subject)" or n["description"]:
            if not n["id"]:
                n["id"] = str(tid)
            n["recent"] = True
            return n
    return None


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

    # merge in app-created tickets the list view hasn't surfaced yet
    if configured(cfg):
        present = {i["id"] for i in kept}
        for tid in _recent_created_ids():
            if tid in present:
                continue
            det = _incident_detail_only(cfg, tid)
            if not det:
                continue
            closed = str(det["status"]).lower() in ("closed", "resolved", "cancelled")
            if (include_closed or not closed) and (not priorities or det["priority"] in priorities):
                kept.insert(0, det)          # freshly created → show at the top
                present.add(tid)
    return kept


def incident_field_sample(n: int = 1) -> dict:
    """Diagnostic: expose the raw field names the list service returns and what
    the normaliser mapped, so id/title mapping can be verified for this
    instance. Values are truncated; use to confirm the ticket-number field."""
    cfg = load_config()
    if not configured(cfg):
        return {"configured": False}
    rows = _fetch_incident_rows(cfg)
    out = {"configured": True, "row_count": len(rows), "samples": []}
    for r in rows[:max(1, n)]:
        if not isinstance(r, dict):
            continue
        keys = sorted(r.keys())
        norm = _norm_incident(r)
        trimmed = {k: (str(v)[:60] if v not in (None, "") else "") for k, v in r.items()}
        out["samples"].append({
            "raw_keys": keys,
            "detected_id": norm["id"],
            "detected_title": norm["title"],
            "detected_status": norm["status"],
            "raw_values": trimmed,
        })
    return out


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
                              "TicketID": _ticket_no(incident_id),
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
        for k in ("TicketNo", "Ticket_No", "TicketNumber", "IncidentID", "TicketID",
                  "Change_Request_Id", "ChangeRequestID", "ChangeNo", "CR_ID", "ChangeID"):
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
    tno = _find_ticket_no(data)
    if tno:
        record_created_incident(tno)   # so the dashboard shows it before it routes
    return {"ok": True, "ticket": tno, "response": reply[:400]}


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


def _change_cfg(cfg: dict) -> dict:
    """Config with the CHANGE API key swapped in (falls back to the incident
    token when no separate change key is set)."""
    c = dict(cfg)
    if cfg.get("change_token"):
        c["token"] = cfg["change_token"]
    return c


def get_change(change_id: str) -> dict | None:
    """One change request via CM_GetCR_Details {ChangeRequestID: int}."""
    cfg = load_config()
    if not configured(cfg):
        return next((c for c in _demo_changes() if str(c["id"]) == str(change_id)), None)
    try:
        rows = _wcf_call(cfg.get("change_detail_service") or "CM_GetCR_Details",
                         {"ChangeRequestID": _ticket_no(change_id)}, _change_cfg(cfg))
    except RuntimeError:
        rows = []
    for r in rows:
        n = _norm_change(r)
        if n["id"] in (str(change_id), ""):
            if not n["id"]:
                n["id"] = str(change_id)
            return n
    return next((c for c in list_changes() if str(c["id"]) == str(change_id)), None)


def _fmt_dt(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _format_plan_text(steps: list, backout: str = "") -> str:
    """Render the structured implementation plan as a human-readable block so
    it can be written into Summit's CR text fields (the plan the change
    assistant builds otherwise lives only in this platform)."""
    lines: list[str] = []
    ordered = sorted(
        [s for s in (steps or []) if isinstance(s, dict)],
        key=lambda s: s.get("order") or 0,
    )
    for i, s in enumerate(ordered, 1):
        phase = str(s.get("phase") or "step").upper()
        risk = str(s.get("risk") or "").strip()
        head = f"{i}. [{phase}]" + (f" ({risk} risk)" if risk else "")
        desc = str(s.get("description") or "").strip()
        if desc:
            head += f" {desc}"
        lines.append(head)
        cmd = str(s.get("command") or "").strip()
        if cmd:
            lines.append(f"    $ {cmd}")
    plan = "\n".join(lines)
    backout = str(backout or "").strip()
    if backout:
        plan += ("\n\n" if plan else "") + "Back-out plan:\n" + backout
    return plan


def create_change(f: dict) -> dict:
    """Raise a change request via CM_LogOrUpdateCR. The envelope mirrors the
    vendor's working sample as closely as possible — all CR fields and the
    sibling containers (release/test/resource/…) — so Summit's create-time
    workflow validation passes. Operator values overlay the defaults; the
    deployment-specific IDs come from config."""
    cfg = load_config()
    if not configured(cfg):
        return {"ok": False, "error": "SummitAI is not configured"}
    title = str(f.get("title") or "").strip()
    requestor = str(f.get("requestor") or cfg.get("caller_email") or "").strip()
    if not title:
        return {"ok": False, "error": "A change title/summary is required"}
    if "@" not in requestor:
        return {"ok": False, "error": "A valid requestor email is required"}

    workgroup = str(f.get("workgroup") or cfg.get("change_default_workgroup") or "Windows Server Support")
    wg_id = str(cfg.get("change_owner_workgroup_id") or "12")
    now = time.time()
    start = str(f.get("start") or "").strip() or _fmt_dt(now + 86400)
    end = str(f.get("end") or "").strip() or _fmt_dt(now + 2 * 86400)
    pir_planned = _fmt_dt(now + 3 * 86400)

    # the change assistant's implementation plan, rendered for Summit's text
    # fields so it is visible inside the CR (not just in this platform)
    steps = [s for s in (f.get("steps") or []) if isinstance(s, dict)]
    backout = str(f.get("backout") or "").strip()
    plan_text = _format_plan_text(steps, backout)

    # Fill the CR's descriptive sections from the operator input + the AI risk
    # assessment, so the change isn't filed with empty Reason / Justification /
    # Impact / Scope fields. All of these are free text (no master-data
    # validation), so populating them can't cause a create rejection.
    desc = str(f.get("description") or "").strip()
    assess = f.get("assessment") if isinstance(f.get("assessment"), dict) else {}
    ra = assess.get("risk_assessment") or {}
    sr = assess.get("success_rate") or {}
    rationale = str(ra.get("rationale") or "").strip()
    factors = [str(x).strip() for x in (sr.get("factors") or []) if str(x).strip()]
    neg = [x for x in factors if x.lstrip().startswith("-")]
    pos = [x for x in factors if x.lstrip().startswith("+")]
    pct = sr.get("percent")
    justification = rationale or desc or title
    trigger = desc or title
    risk_of_failure = "; ".join(neg) or rationale or f"{f.get('risk') or 'Medium'} risk change"
    if pct is not None:
        risk_of_failure = f"Estimated success {pct}%. {risk_of_failure}"
    biz_impact = desc or f"{f.get('impact') or 'Medium'} business impact"
    not_impl = (f"If not implemented, the issue remains unaddressed: {desc}"
                if desc else "The underlying issue remains unaddressed.")
    scope_bits = []
    if steps:
        scope_bits.append(f"{len(steps)}-step implementation plan")
    if backout:
        scope_bits.append("back-out plan prepared")
    if pos:
        scope_bits.append("safeguards — " + "; ".join(pos))
    change_scope = ". ".join(scope_bits)
    downtime_remark = ("Downtime required during the change window."
                       if f.get("downtime") else "No downtime expected.")
    business_benefits = "; ".join(pos)

    # full CR container mirroring the working sample (order/keys preserved).
    # Change_Request_Id 0 = create a new CR — the sample's 1844 is an update,
    # and omitting the key entirely makes Summit NRE ("Object reference not
    # set to an instance of an object").
    create_status = str(cfg.get("change_create_status") or "").strip()
    container = {
        "Change_Request_Id": 0,
        "Status": create_status,
        "Support_Function": str(cfg.get("change_support_function") or "IT"),
        "Support_Function_Name": str(cfg.get("change_support_function_name") or "BIAL Services"),
        # name+ID must be a consistent pair from Summit's category master
        "Category": str(cfg.get("change_category_name") or "Minor"),
        "ChangeTypeName": str(f.get("type") or "Normal"),
        "Requestor_Name": requestor,
        "Requested_By_Name": requestor,
        "Owner_Workgroup": workgroup,
        "Assigned_Workgroup": workgroup,
        "Classification": str(cfg.get("change_classification") or "Normal"),
        "Change_CategoryID": int(cfg.get("change_category_id") or 132),
        "TriggerForChange": trigger,
        "Risk": str(f.get("risk") or "Medium"),
        "Impact": str(f.get("impact") or "Medium"),
        "Priority_Name": str(f.get("priority") or "P3"),
        "Criticality_Name": str(f.get("impact") or "Medium"),
        "Downtime_Required": bool(f.get("downtime")),
        "CustomerName": "All",
        "Customer": -1,
        "Information": title,
        "Description": str(f.get("description") or ""),
        "CurrencyName": "",
        "CustomerApprovalRequired": False,
        "CustomerTestRequired": False,
        "CabApprovalType": "After CAB Approval",
        "Communication_Plan_Required": False,
        "Communication_Plan_Details": "",
        "BusinessRisk": None, "OperationalRisk": None, "OverallRisk": None,
        "Closure_Code": "", "ClosureCategoryName": None, "CancelReason": None,
        "Risk_Of_Change_Failure": risk_of_failure,
        "Business_Impact_As_Per_User": biz_impact,
        "Business_Impact_Of_Change_Failure": risk_of_failure,
        "Back_Out_Plan": backout,
        "BackoutPlanTested": False,
        "BackOutPlanNotTestedReason": "Not yet tested",
        "SystemImpactRemarks": downtime_remark,
        "Impact_Of_Not_Implementing_Change": not_impl,
        "Information_Log": "", "Configuration_Team_Log": "",
        "Change_Manager_Log": "", "Change_Advisory_Board_Member_Log": "",
        "Justification": justification, "ProposedTemplateName": None, "ProposalJustification": None,
        "PreImplementationSteps": plan_text or None, "PostImplementationSteps": None, "RescheduleReason": None,
        "Is_Change_Implemented_Or_Rolledback": "",
        "Is_ChangeSucessful": "No",
        "Solution": plan_text, "ChangeScope": change_scope, "ChangeOutOfScope": "",
        "BusinessBenefits": business_benefits, "FinancialBenefits": "",
        "Assigned_Executive_Id": str(cfg.get("change_executive_id") or "2"),
        "Actual_Start_Time": start,
        "Actual_End_Time": end,
        "Planned_PIR_Date": pir_planned,
        "Actual_PIR_Date": pir_planned,
        "RleasePlanned_StartTime": None, "IsCIUpdation": None,
        "ManualEscalationLevelID": 0, "ManualEscalationRemarks": None,
    }
    params = {
        "cmParamsJSON": {
            "CMContainerJson": json.dumps(container),
            "CR_CI_Details": "[]",
            "CRReleaseDetails": {
                "RleasePlanned_StartTime": start, "RleasePlanned_EndTime": end,
                "ReleaseActual_StartTime": start, "ReleaseActual_EndTime": end,
                "ReleasePlan": plan_text or "As per implementation plan", "ReleaseAttachments": "",
                "ReleaseDocs": "", "ReleaseNotes": "", "Release_Workgroup": "",
                "Owner_Workgroup_Id": wg_id, "ReleaseAnalyst": "", "UserID": "0",
            },
            "CRTestDetails": {
                "TestPlanned_Time": end, "TestActual_Time": "",
                "TestResults": "", "TestPlan": "As per implementation plan",
                "TestOwnerEmail": requestor, "WorkgroupName": workgroup,
                "Owner_Workgroup_Id": wg_id, "Status": "", "Has_Attachments": "0",
                "Test_Stage": "NTP", "TestURL": "", "Test_Name": "Test Plan",
                "Org_Id": str(cfg.get("org_id") or 1), "UserID": "0",
            },
            "CR_ResourceRequirement": "[]",
            "CR_FinancialRequirement": "[]",
            "CR_TechnicalRequirement": "[]",
            "CR_ChecklistContainer": "[]",
            "CR_CustomerApproverTesters": "[]",
            "MVCustomFields": "[]",
            "CR_UserSelectedApproval": "[]",
        },
        "RequestType": "RemoteCall",
    }
    ccfg = _change_cfg(cfg)
    service = cfg.get("change_update_service") or "CM_LogOrUpdateCR"
    return _create_cr_with_recovery(service, container, params, ccfg, create_status)


_CANDIDATE_CREATE_STATUSES = [
    "Initial Authorization", "Draft", "Requested", "Submitted", "Registered",
    "New", "Open", "Logged", "Pending Authorization", "For Authorization",
]

# Summit validates several CR fields against master-data lists. When it rejects
# one ("Invalid <field> value/name"), fall back to the known-good sample value
# for that field and retry — so an AI-inferred value Summit doesn't recognise
# (e.g. Risk "High") never blocks creation.
_CR_FIELD_FALLBACKS = [
    (r"Invalid Risk\b", ["Risk"], "Medium"),
    (r"Invalid Impact\b", ["Impact"], "Medium"),
    (r"Invalid Criticality\b", ["Criticality_Name"], "Medium"),
    (r"Invalid Priority\b", ["Priority_Name"], "P3"),
    (r"Invalid (Change ?Type|ChangeType)\b", ["ChangeTypeName"], "Normal"),
    (r"Invalid Classification\b", ["Classification"], "Normal"),
    (r"Invalid Urgency\b", ["Urgency_Name"], "Medium"),
]


def _create_cr_with_recovery(service: str, container: dict, params: dict,
                             ccfg: dict, create_status: str) -> dict:
    """POST the CR, self-healing around Summit's master-data validation:
    walks initial statuses on 'Invalid Status Name' and substitutes known-good
    values for any other 'Invalid <field>' rejection, then retries."""
    statuses = [create_status] + [s for s in _CANDIDATE_CREATE_STATUSES
                                  if s != create_status]
    si = 0
    container["Status"] = statuses[si]
    adjusted = {}          # field -> value we had to fall back to
    tried_status = []
    for _ in range(16):    # bounded: statuses + a handful of field fixes
        params["cmParamsJSON"]["CMContainerJson"] = json.dumps(container)
        try:
            data = _wcf_raw(service, params, ccfg)
        except RuntimeError as exc:
            msg = str(exc)
            if "Invalid Status Name" in msg:
                tried_status.append(container.get("Status"))
                si += 1
                if si < len(statuses):
                    container["Status"] = statuses[si]
                    continue
                return {"ok": False, "status_tried": tried_status,
                        "error": ("Summit rejected every known initial status — ask the "
                                  "change admin for the first status in your CR workflow "
                                  "and set it in Settings.")}
            fixed = False
            for pat, keys, safe in _CR_FIELD_FALLBACKS:
                if re.search(pat, msg, re.I) and container.get(keys[0]) != safe:
                    for k in keys:
                        container[k] = safe
                    adjusted[keys[0]] = safe
                    fixed = True
                    break
            if fixed:
                continue
            return {"ok": False, "error": msg[:400], "adjusted": adjusted or None}
        # success — learn a working non-default status
        st = container.get("Status")
        if st and st != create_status:
            try:
                stored = load_config()
                stored["change_create_status"] = st
                save_config(stored)
            except OSError:
                pass
        reply = data if isinstance(data, str) else json.dumps(data, default=str)
        return {"ok": True, "change_id": _find_ticket_no(data), "response": reply[:400],
                "status_used": st, "adjusted": adjusted or None}
    return {"ok": False, "error": "Too many validation retries — check the CR field values.",
            "adjusted": adjusted or None}


def update_change_log(change_id: str, text: str) -> dict:
    """Append to a CR's information log via CM_LogOrUpdateCR."""
    cfg = load_config()
    if not configured(cfg):
        return {"ok": False, "error": "SummitAI is not configured"}
    if not str(text).strip():
        return {"ok": False, "error": "Log text is empty"}
    container = {
        "Change_Request_Id": _ticket_no(change_id),
        "Support_Function": "IT",
        "Information_Log": str(text),
    }
    params = {
        "cmParamsJSON": {"CMContainerJson": json.dumps(container)},
        "RequestType": "RemoteCall",
    }
    try:
        data = _wcf_raw(cfg.get("change_update_service") or "CM_LogOrUpdateCR",
                        params, _change_cfg(cfg))
    except RuntimeError as exc:
        return {"ok": False, "error": str(exc)[:400]}
    reply = data if isinstance(data, str) else json.dumps(data, default=str)
    return {"ok": True, "change_id": str(change_id), "response": reply[:400]}


def status() -> dict:
    ok = configured()
    return {"configured": ok, "demo": not ok,
            "source": "SummitAI" + ("" if ok else " (demo data)")}


def public_config() -> dict:
    "Config for the settings UI; the API keys never leave the server."
    cfg = load_config()
    return {**{k: cfg[k] for k in DEFAULTS if k not in _SECRET_KEYS},
            "token_set": bool(cfg["token"]),
            "change_token_set": bool(cfg["change_token"]),
            "vault_error": cfg.get("vault_error", ""),
            "configured": configured(cfg)}


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
    """Verify the INCIDENT integration with (unsaved) form values. Changes
    have their own key and Test button, so they're not probed here."""
    cfg = _merged(overrides)
    if not cfg["base_url"]:
        return {"ok": False, "error": "Base URL is required"}
    out = {"ok": True, "incidents": None}
    try:
        out["incidents"] = len(_fetch_incident_rows(cfg))
    except Exception as exc:  # noqa: BLE001
        out.update(ok=False, error=f"incidents: {exc}")
    return out


def test_change_config(overrides: dict | None = None, cr_id: str = "") -> dict:
    """Verify the CHANGE integration (separate API key). With a known CR
    number it reads that change via the detail service (a safe read); without
    one it tries the change list service, which may be unknown per deployment."""
    cfg = _merged(overrides)
    if not cfg["base_url"]:
        return {"ok": False, "error": "Base URL is required"}
    ccfg = _change_cfg(cfg)
    if not ccfg.get("token"):
        return {"ok": False, "error": "No change API key set (and no incident key to fall back on)"}
    if cr_id.strip():
        try:
            rows = _wcf_call(cfg.get("change_detail_service") or "CM_GetCR_Details",
                             {"ChangeRequestID": _ticket_no(cr_id)}, ccfg)
            return {"ok": True, "mode": "detail", "cr": cr_id.strip(),
                    "found": bool(rows)}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": f"change detail: {exc}"}
    try:
        return {"ok": True, "mode": "list", "changes": len(_fetch_change_rows(cfg))}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"changes list: {exc}",
                "hint": "Enter a known CR number to test the detail service instead,"
                        " or confirm the change list ServiceName with your Summit admin."}


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


_CANDIDATE_CHANGE_SERVICES = [
    "CM_GetCRList", "CM_GetChangeList", "CM_FetchChanges", "CM_GetCR_List",
    "CM_FetchCRList", "CM_GetChanges", "CM_FetchCR", "GetChangeList",
    "CM_GetCRDetailsList",
]
# filter key names that vary across change deployments
_CANDIDATE_CHANGE_FILTER_KEYS = ["objChangeCommonFilter", "objCRCommonFilter",
                                 "objCommonFilter"]


def discover_change_services(overrides: dict | None = None) -> dict:
    """Sweep common SummitAI change-LIST ServiceNames (with the change key)
    so the operator can find the one their deployment answers. For the
    configured/most-likely name we also try each candidate filter key, since
    the list call often needs a filter block to return rows."""
    cfg = _merged(overrides)
    if not cfg["base_url"]:
        return {"results": [], "error": "Base URL is required"}
    if cfg["api_style"] != "summit_wcf":
        return {"results": [], "error": "ServiceName discovery applies to the summit_wcf style"}
    ccfg = _change_cfg(cfg)

    def probe(name: str, filter_key: str) -> dict:
        params = _change_list_params({**cfg, "change_list_filter_key": filter_key})
        label = name + (f"  ·  {filter_key}" if filter_key != "objChangeCommonFilter" else "")
        try:
            rows = _wcf_call(name, params, ccfg)
            return {"service": name, "filter_key": filter_key, "label": label,
                    "ok": True, "rows": len(rows)}
        except RuntimeError as exc:
            msg = str(exc)
            empty = "EMPTY body" in msg
            return {"service": name, "filter_key": filter_key, "label": label,
                    "ok": False, "empty": empty,
                    "error": None if empty else msg[:180]}

    results = []
    names = list(dict.fromkeys([cfg["changes_service"], *_CANDIDATE_CHANGE_SERVICES]))
    for name in names:
        results.append(probe(name, "objChangeCommonFilter"))
    # if nothing answered, retry the top candidates with the other filter keys
    if not any(r["ok"] and r["rows"] for r in results):
        for name in names[:3]:
            for fk in _CANDIDATE_CHANGE_FILTER_KEYS[1:]:
                results.append(probe(name, fk))
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
