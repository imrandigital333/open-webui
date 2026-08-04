"""FastAPI app for the AI Troubleshooter UI.

Run with:  uvicorn app.main:app --host 0.0.0.0 --port 8090
"""

import asyncio
import contextlib
import json
import os
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import (FileResponse, JSONResponse, PlainTextResponse,
                               StreamingResponse)
from pydantic import BaseModel, Field

from . import (auth, changeplan, cmdreview, db, discovery, healthprobe,
               integrations, itsm, knowledge, orchestrator, platform_log,
               vaultclient, winexec)
from .datasources import load_datasources, missing_env_vars, to_public_dict
from .inventory import (
    load_inventory,
    load_raw_inventory,
    save_inventory,
    writable_inventory_path,
)
from .scriptlib import SCRIPTLIB_DIR, list_scripts

APP_VERSION = "3.16.0"

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
    """Operator identity — the signed-in user, else a fronting SSO proxy header."""
    user = getattr(request.state, "user", None)
    if user:
        return user.get("username") or user.get("id") or "user"
    return (
        request.headers.get("X-Remote-User")
        or request.headers.get("X-Forwarded-User")
        or (request.client.host if request.client else "anonymous")
    )


# ---------- auth enforcement ----------

# paths reachable without a session
_PUBLIC_PATHS = {"/", "/api/version", "/api/auth/login", "/favicon.ico",
                 "/openapi.json", "/docs", "/redoc"}
# endpoints a user with must_change=1 may still call (to change their password)
_MUST_CHANGE_OK = {"/api/auth/me", "/api/auth/logout", "/api/auth/change-password"}
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@app.middleware("http")
async def _auth_gate(request: Request, call_next):
    path = request.url.path
    request.state.user = None
    # let the SPA shell, static assets and public API endpoints through
    if path in _PUBLIC_PATHS or not path.startswith("/api/"):
        return await call_next(request)

    token = request.cookies.get(auth.COOKIE_NAME)
    user = await asyncio.to_thread(auth.user_from_token, token)
    if not user:
        return JSONResponse({"error": "authentication required", "code": "unauthenticated"},
                            status_code=401)
    request.state.user = user

    # CSRF: every authenticated, state-changing request must echo the CSRF
    # cookie (set at login) back as a header — see auth.verify_csrf.
    if request.method not in _SAFE_METHODS:
        presented = request.headers.get(auth.CSRF_HEADER_NAME, "")
        if not auth.verify_csrf(token, presented):
            return JSONResponse({"error": "CSRF validation failed — refresh and try again",
                                 "code": "csrf_failed"}, status_code=403)

    if user.get("must_change") and path not in _MUST_CHANGE_OK:
        return JSONResponse({"error": "password change required", "code": "must_change"},
                            status_code=403)

    need = auth.required_permission(request.method, path)
    if need == "admin" and not auth.is_admin(user):
        return JSONResponse({"error": "administrator access required", "code": "forbidden"},
                            status_code=403)
    if need and need != "admin" and not auth.can_access(user, need):
        return JSONResponse({"error": f"your role cannot access '{need}'", "code": "forbidden"},
                            status_code=403)
    return await call_next(request)


def _api_category(path: str) -> str:
    """Map an API path to a functionality category for the platform log."""
    p = path
    table = [
        ("/api/auth", "auth"),
        ("/api/admin/logs", "settings"),
        ("/api/admin/integrations", "integrations"),
        ("/api/admin/users", "access"), ("/api/admin/roles", "access"),
        ("/api/admin/ad-config", "access"),
        ("/api/admin/inventory", "inventory"),
        ("/api/admin/itsm", "itsm"), ("/api/itsm", "itsm"),
        ("/api/servers", "discovery"),
        ("/api/knowledge", "knowledge"), ("/api/kb", "knowledge"), ("/api/design", "knowledge"),
        ("/api/changes", "changes"), ("/api/change", "changes"),
        ("/api/sessions", "investigation"), ("/api/session", "investigation"),
        ("/api/admin", "settings"),
    ]
    for prefix, cat in table:
        if p.startswith(prefix):
            return cat
    return "api"


# request access logging is registered here so it wraps the auth gate (Starlette
# runs the most-recently-added middleware outermost) — every API call is logged
# with method, path, status, duration and the resolved actor.
@app.middleware("http")
async def _request_log(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/api/") or path == "/api/version":
        return await call_next(request)
    # don't log reads of the log itself — that would feed back on auto-refresh
    if path.startswith("/api/admin/logs") and request.method == "GET":
        return await call_next(request)
    start = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        dur_ms = round((time.perf_counter() - start) * 1000, 1)
        level = "ERROR" if status >= 500 else "WARNING" if status >= 400 else "INFO"
        actor = _actor(request)
        with contextlib.suppress(Exception):
            platform_log.event(
                _api_category(path),
                f"{request.method} {path} → {status} ({dur_ms} ms)",
                level=level, actor=actor,
                detail={"method": request.method, "path": path,
                        "status": status, "duration_ms": dur_ms})


# ---------- rate limiting (in-memory sliding window, per client IP) ----------
# Single-process limiter — fine for this deployment (one systemd-run instance);
# scaling to multiple workers/instances would need a shared store (e.g. Redis).
_RATE_WINDOW = 60.0
GENERAL_RATE_LIMIT = int(os.environ.get("TROUBLESHOOTER_RATE_LIMIT_PER_MIN", "240"))
LOGIN_RATE_LIMIT = int(os.environ.get("TROUBLESHOOTER_LOGIN_RATE_LIMIT_PER_MIN", "15"))
_general_hits: dict[str, deque] = defaultdict(deque)
_login_hits: dict[str, deque] = defaultdict(deque)


def _rate_check(buckets: dict[str, deque], key: str, limit: int) -> tuple[bool, float]:
    now = time.monotonic()
    dq = buckets[key]
    while dq and now - dq[0] > _RATE_WINDOW:
        dq.popleft()
    if len(dq) >= limit:
        return False, dq[0] + _RATE_WINDOW - now
    dq.append(now)
    return True, 0.0


# Only trust X-Forwarded-For if this instance sits behind a reverse proxy that
# overwrites/strips client-supplied values (nginx/F5/etc.) — otherwise a client
# can spoof the header and get a fresh rate-limit bucket on every request.
_TRUST_PROXY_HEADERS = os.environ.get("TROUBLESHOOTER_TRUST_PROXY_HEADERS", "").lower() in \
    ("1", "true", "yes")


def _rate_client(request: Request) -> str:
    if _TRUST_PROXY_HEADERS:
        fwd = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if fwd:
            return fwd
    return request.client.host if request.client else "unknown"


@app.middleware("http")
async def _rate_limit(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/api/"):
        return await call_next(request)
    client = _rate_client(request)
    if path == "/api/auth/login":
        ok, retry = _rate_check(_login_hits, client, LOGIN_RATE_LIMIT)
        if not ok:
            with contextlib.suppress(Exception):
                platform_log.event("auth", f"login rate-limited ({client})",
                                   level="WARNING", actor=client)
            return JSONResponse(
                {"error": "Too many login attempts — try again shortly.", "code": "rate_limited"},
                status_code=429, headers={"Retry-After": str(max(1, int(retry) + 1))})
    ok, retry = _rate_check(_general_hits, client, GENERAL_RATE_LIMIT)
    if not ok:
        with contextlib.suppress(Exception):
            platform_log.event("api", f"rate limit exceeded ({client}) {path}",
                               level="WARNING", actor=client)
        return JSONResponse(
            {"error": "Rate limit exceeded — slow down.", "code": "rate_limited"},
            status_code=429, headers={"Retry-After": str(max(1, int(retry) + 1))})
    return await call_next(request)


def _prune_rate_buckets() -> None:
    now = time.monotonic()
    for buckets in (_general_hits, _login_hits):
        for key in [k for k, dq in buckets.items()
                   if not dq or now - dq[-1] > _RATE_WINDOW * 5]:
            del buckets[key]


# ---------- security headers (defense in depth for a single-page app that
# loads no external scripts/styles/fonts/images — see index.html) ----------
_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
       "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; "
       "form-action 'self'; object-src 'none'")


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=(), usb=()")
    response.headers["Content-Security-Policy"] = _CSP
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.on_event("startup")
async def _startup():
    await asyncio.to_thread(platform_log.configure)
    platform_log.event("system", f"platform starting (v{APP_VERSION})")
    await asyncio.to_thread(db.init_db)
    await asyncio.to_thread(auth.ensure_bootstrap)
    await asyncio.to_thread(db.auth_sessions_purge_expired)

    async def retention_loop():
        while True:
            if RETENTION_DAYS > 0:
                with contextlib.suppress(Exception):
                    result = await asyncio.to_thread(db.purge_older_than, RETENTION_DAYS)
                    if result["sessions_purged"]:
                        await asyncio.to_thread(db.audit, "system", "retention_purge", result)
            await asyncio.sleep(24 * 3600)

    async def rate_bucket_prune_loop():
        while True:
            await asyncio.sleep(600)
            with contextlib.suppress(Exception):
                _prune_rate_buckets()

    asyncio.get_running_loop().create_task(rate_bucket_prune_loop())

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


# ---------- authentication ----------

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=120)
    password: str = Field(..., min_length=1, max_length=256)


def _me_payload(user: dict) -> dict:
    return {"authenticated": True,
            "user": {"id": user["id"], "username": user["username"],
                     "display_name": user["display_name"], "email": user["email"],
                     "role": user["role"], "auth_mode": user["auth_mode"],
                     "must_change": user["must_change"]},
            "is_admin": auth.is_admin(user),
            "pages": list(auth.PAGE_KEYS) if auth.is_admin(user) else auth.pages_for_role(user["role"]),
            "all_pages": auth.PAGES}


@app.post("/api/auth/login")
async def auth_login(req: LoginRequest, request: Request):
    ip = request.client.host if request.client else ""
    res = await asyncio.to_thread(auth.authenticate, req.username, req.password, ip)
    if not res.get("ok"):
        return JSONResponse({"ok": False, "error": res.get("error")}, status_code=401)
    user = res["user"]
    token = await asyncio.to_thread(auth.create_session, user["id"], ip)
    await asyncio.to_thread(db.audit, user["username"], "login", {"ip": ip})
    resp = JSONResponse(_me_payload(user))
    secure = request.url.scheme == "https"
    resp.set_cookie(auth.COOKIE_NAME, token, httponly=True, samesite="lax",
                    secure=secure, max_age=auth.SESSION_TTL, path="/")
    # readable (non-httponly) so the SPA can echo it back as the CSRF header;
    # it's useless to an attacker without the httponly session cookie to HMAC against
    resp.set_cookie(auth.CSRF_COOKIE_NAME, auth.csrf_token_for_session(token),
                    httponly=False, samesite="lax", secure=secure,
                    max_age=auth.SESSION_TTL, path="/")
    return resp


@app.post("/api/auth/logout")
async def auth_logout(request: Request):
    token = request.cookies.get(auth.COOKIE_NAME)
    await asyncio.to_thread(auth.destroy_session, token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.COOKIE_NAME, path="/")
    resp.delete_cookie(auth.CSRF_COOKIE_NAME, path="/")
    return resp


@app.get("/api/auth/me")
async def auth_me(request: Request):
    user = getattr(request.state, "user", None)
    if not user:
        return JSONResponse({"authenticated": False}, status_code=401)
    return _me_payload(user)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field("", max_length=256)
    new_password: str = Field(..., min_length=1, max_length=256)


@app.post("/api/auth/change-password")
async def auth_change_password(req: ChangePasswordRequest, request: Request):
    user = request.state.user
    if user["auth_mode"] != "local":
        raise HTTPException(status_code=400, detail="AD accounts change their password in AD.")
    # verify current password unless this is a forced first-login change
    if not user["must_change"]:
        stored = await asyncio.to_thread(db.user_password_hash, user["id"])
        if not (stored and auth.verify_password(req.current_password, stored)):
            raise HTTPException(status_code=400, detail="Current password is incorrect.")
    err = auth.password_ok(req.new_password)
    if err:
        raise HTTPException(status_code=400, detail=err)
    await asyncio.to_thread(db.user_update, user["id"],
                            {"password_hash": auth.hash_password(req.new_password),
                             "must_change": False})
    await asyncio.to_thread(db.audit, user["username"], "password_changed", None)
    return {"ok": True}


# ---------- administration: users, roles, AD config (admin only via middleware) ----------

class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=120)
    display_name: str = Field("", max_length=160)
    email: str = Field("", max_length=200)
    auth_mode: str = Field("local", pattern="^(local|ad)$")
    role: str = Field("viewer", max_length=60)
    password: str = Field("", max_length=256)
    enabled: bool = True
    must_change: bool = True


@app.get("/api/admin/users")
async def admin_users():
    return {"users": await asyncio.to_thread(db.user_list)}


@app.post("/api/admin/users")
async def admin_user_create(req: UserCreateRequest, request: Request):
    uname = req.username.strip().lower()
    if await asyncio.to_thread(db.user_get_by_name, uname):
        raise HTTPException(status_code=409, detail="A user with that username already exists.")
    if not await asyncio.to_thread(db.role_get, req.role):
        raise HTTPException(status_code=400, detail="Unknown role.")
    pw_hash = None
    if req.auth_mode == "local":
        if not req.password:
            raise HTTPException(status_code=400, detail="A local user needs an initial password.")
        err = auth.password_ok(req.password)
        if err:
            raise HTTPException(status_code=400, detail=err)
        pw_hash = auth.hash_password(req.password)
    import uuid as _uuid
    uid = _uuid.uuid4().hex[:16]
    await asyncio.to_thread(db.user_create, {
        "id": uid, "username": uname, "display_name": req.display_name,
        "email": req.email, "auth_mode": req.auth_mode, "password_hash": pw_hash,
        "role": req.role, "enabled": req.enabled,
        "must_change": req.must_change if req.auth_mode == "local" else False})
    await asyncio.to_thread(db.audit, _actor(request), "user_created",
                            {"username": uname, "role": req.role})
    return {"ok": True, "id": uid}


class UserUpdateRequest(BaseModel):
    display_name: str | None = Field(None, max_length=160)
    email: str | None = Field(None, max_length=200)
    role: str | None = Field(None, max_length=60)
    auth_mode: str | None = Field(None, pattern="^(local|ad)$")
    enabled: bool | None = None
    new_password: str | None = Field(None, max_length=256)


@app.put("/api/admin/users/{user_id}")
async def admin_user_update(user_id: str, req: UserUpdateRequest, request: Request):
    user = await asyncio.to_thread(db.user_get, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    fields: dict = {}
    for k in ("display_name", "email", "auth_mode"):
        v = getattr(req, k)
        if v is not None:
            fields[k] = v
    if req.role is not None:
        if not await asyncio.to_thread(db.role_get, req.role):
            raise HTTPException(status_code=400, detail="Unknown role.")
        # don't allow removing the last admin
        if user["role"] == "admin" and req.role != "admin":
            admins = [u for u in await asyncio.to_thread(db.user_list)
                      if u["role"] == "admin" and u["enabled"]]
            if len(admins) <= 1:
                raise HTTPException(status_code=400, detail="Cannot remove the last administrator.")
        fields["role"] = req.role
    if req.enabled is not None:
        if not req.enabled and user["role"] == "admin":
            admins = [u for u in await asyncio.to_thread(db.user_list)
                      if u["role"] == "admin" and u["enabled"]]
            if len(admins) <= 1:
                raise HTTPException(status_code=400, detail="Cannot disable the last administrator.")
        fields["enabled"] = req.enabled
        if req.enabled:
            fields["failed_count"] = 0
            fields["locked_until"] = None
    if req.new_password:
        err = auth.password_ok(req.new_password)
        if err:
            raise HTTPException(status_code=400, detail=err)
        fields["password_hash"] = auth.hash_password(req.new_password)
        fields["must_change"] = True
        fields["auth_mode"] = "local"
    await asyncio.to_thread(db.user_update, user_id, fields)
    await asyncio.to_thread(db.audit, _actor(request), "user_updated",
                            {"username": user["username"], "fields": list(fields)})
    return {"ok": True}


@app.delete("/api/admin/users/{user_id}")
async def admin_user_delete(user_id: str, request: Request):
    user = await asyncio.to_thread(db.user_get, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    if user["role"] == "admin":
        admins = [u for u in await asyncio.to_thread(db.user_list) if u["role"] == "admin"]
        if len(admins) <= 1:
            raise HTTPException(status_code=400, detail="Cannot delete the last administrator.")
    if request.state.user and request.state.user["id"] == user_id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")
    await asyncio.to_thread(db.user_delete, user_id)
    await asyncio.to_thread(db.audit, _actor(request), "user_deleted", {"username": user["username"]})
    return {"ok": True}


@app.get("/api/admin/roles")
async def admin_roles():
    return {"roles": await asyncio.to_thread(db.role_list), "pages": auth.PAGES}


class RoleRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=60, pattern="^[A-Za-z0-9_-]+$")
    description: str = Field("", max_length=300)
    pages: list[str] = Field(default_factory=list)


@app.post("/api/admin/roles")
async def admin_role_upsert(req: RoleRequest, request: Request):
    if req.name == "admin":
        raise HTTPException(status_code=400, detail="The admin role always has full access and can't be edited.")
    pages = [p for p in req.pages if p in auth.PAGE_KEYS]
    await asyncio.to_thread(db.role_upsert, req.name, req.description, pages, False)
    await asyncio.to_thread(db.audit, _actor(request), "role_saved",
                            {"role": req.name, "pages": pages})
    return {"ok": True}


@app.delete("/api/admin/roles/{name}")
async def admin_role_delete(name: str, request: Request):
    if name == "admin":
        raise HTTPException(status_code=400, detail="The admin role cannot be deleted.")
    users = [u for u in await asyncio.to_thread(db.user_list) if u["role"] == name]
    if users:
        raise HTTPException(status_code=400,
                            detail=f"{len(users)} user(s) still have this role. Reassign them first.")
    await asyncio.to_thread(db.role_delete, name)
    await asyncio.to_thread(db.audit, _actor(request), "role_deleted", {"role": name})
    return {"ok": True}


@app.get("/api/admin/integrations")
async def admin_integrations_get():
    return {"layers": integrations.LAYERS,
            "config": await asyncio.to_thread(integrations.public_config)}


class IntegrationRequest(BaseModel):
    key: str = Field(..., min_length=1, max_length=40)
    enabled: bool = False
    host: str = Field("", max_length=300)
    user: str = Field("", max_length=200)
    secret: str = Field("", max_length=512)
    verify_tls: bool = True
    notes: str = Field("", max_length=500)


@app.post("/api/admin/integrations")
async def admin_integrations_save(req: IntegrationRequest, request: Request):
    if req.key not in integrations.LAYER_KEYS:
        raise HTTPException(status_code=400, detail="Unknown integration.")
    try:
        pub = await asyncio.to_thread(integrations.save_layer, req.key, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    await asyncio.to_thread(db.audit, _actor(request), "integration_saved",
                            {"layer": req.key, "enabled": req.enabled})
    return {"ok": True, "config": pub}


@app.post("/api/admin/integrations/{key}/discover")
async def admin_integration_discover(key: str, request: Request):
    """Probe an infrastructure layer. mode=basic → reachability only;
    mode=detailed → also register the layer in the knowledge base."""
    if key not in integrations.LAYER_KEYS:
        raise HTTPException(status_code=400, detail="Unknown integration.")
    try:
        body = await request.json()
    except Exception:
        body = {}
    mode = "detailed" if (isinstance(body, dict) and body.get("mode") == "detailed") else "basic"
    result = await integrations.discover_layer(key, mode)
    if result.get("ok") and mode == "detailed" and result.get("report"):
        try:
            doc_id = await knowledge.store_local(
                result["report"], server=result.get("label", key), os_="layer",
                category="architecture", title=f"Infrastructure layer — {result.get('label', key)}",
                source_type="layer-discovery", source_class="device_data")
            result["stored_doc_id"] = doc_id
        except Exception as exc:  # noqa: BLE001 — surface, don't fail the probe
            result["kb_error"] = str(exc)[:200]
    await asyncio.to_thread(db.audit, _actor(request), "integration_discovered",
                            {"layer": key, "mode": mode, "reachable": result.get("reachable")})
    return result


# ---------- platform logs (admin only via middleware) ----------

@app.get("/api/admin/logs")
async def admin_logs_get(level: str = "", category: str = "", q: str = "",
                         since: float = 0.0, limit: int = 500, file: str = ""):
    entries = await asyncio.to_thread(platform_log.read, level, category, q,
                                      since, limit, file)
    meta = await asyncio.to_thread(platform_log.meta)
    return {"entries": entries, "meta": meta}


@app.get("/api/admin/logs/config")
async def admin_logs_config_get():
    return await asyncio.to_thread(platform_log.meta)


class LogConfigRequest(BaseModel):
    level: str = Field("INFO", max_length=10)
    strategy: str = Field("size", max_length=10)
    max_mb: int = Field(10, ge=1, le=1024)
    backup_count: int = Field(5, ge=0, le=100)
    when: str = Field("midnight", max_length=12)
    interval: int = Field(1, ge=1, le=90)
    path: str = Field("", max_length=500)
    capture_framework: bool = True


@app.post("/api/admin/logs/config")
async def admin_logs_config_save(req: LogConfigRequest, request: Request):
    cfg = await asyncio.to_thread(platform_log.save_config, req.model_dump())
    await asyncio.to_thread(db.audit, _actor(request), "logging_config_saved",
                            {"strategy": cfg["strategy"], "level": cfg["level"]})
    return {"ok": True, "config": cfg}


@app.post("/api/admin/logs/rotate")
async def admin_logs_rotate(request: Request):
    meta = await asyncio.to_thread(platform_log.rotate_now)
    await asyncio.to_thread(db.audit, _actor(request), "logs_rotated", {})
    return {"ok": True, "meta": meta}


@app.delete("/api/admin/logs")
async def admin_logs_clear(request: Request):
    meta = await asyncio.to_thread(platform_log.clear)
    await asyncio.to_thread(db.audit, _actor(request), "logs_cleared", {})
    return {"ok": True, "meta": meta}


@app.get("/api/admin/logs/download")
async def admin_logs_download():
    p = platform_log.current_file_path()
    if not p.exists():
        raise HTTPException(status_code=404, detail="No log file yet.")
    return FileResponse(str(p), filename=p.name, media_type="text/plain")


# ---------- secrets vault (HashiCorp Vault) ----------
# Read-only from the browser's point of view: VAULT_ADDR/VAULT_TOKEN are the
# app's OWN credentials to Vault and are configured only via environment
# variables (systemd EnvironmentFile) — never editable here, since typing them
# into a web form would defeat the point of moving secrets out of reach of the
# browser. This page shows connectivity + which secrets are Vault-backed vs.
# still local, and offers a one-click migration of whatever's still local.

def _migrate_inventory_to_vault() -> dict:
    """Move every Windows server's locally-stored WinRM password into Vault."""
    if not vaultclient.enabled():
        return {"ok": False, "error": "Vault is not configured (VAULT_ADDR / VAULT_TOKEN unset)."}
    servers = load_raw_inventory()
    migrated, skipped, errors = [], [], {}
    changed = False
    for s in servers:
        if str(s.get("platform", "linux")) != "windows":
            continue
        if s.get("secret_in_vault"):
            skipped.append(s["name"])
            continue
        pw = s.get("winrm_password")
        if not pw:
            skipped.append(s["name"])
            continue
        try:
            vaultclient.write_secret(_server_vault_path(s["name"]), {"winrm_password": pw})
            s["winrm_password"] = ""
            s["secret_in_vault"] = True
            migrated.append(s["name"])
            changed = True
        except vaultclient.VaultError as exc:
            errors[s["name"]] = str(exc)
    if changed:
        save_inventory(servers)
    return {"ok": True, "migrated": migrated, "skipped": skipped, "errors": errors}


@app.get("/api/admin/vault/status")
async def admin_vault_status():
    health = await asyncio.to_thread(vaultclient.health)
    itsm_cfg = await asyncio.to_thread(itsm.public_config)
    ad_cfg = await asyncio.to_thread(auth.public_ad_config)
    integ_cfg = await asyncio.to_thread(integrations.public_config)
    raw_servers = await asyncio.to_thread(load_raw_inventory)
    win_servers = [s for s in _redact_inventory(raw_servers) if str(s.get("platform", "linux")) == "windows"]
    return {
        "vault": health,
        "holders": {
            "itsm": {"label": "SummitAI (ITSM)", "in_vault": bool(itsm_cfg.get("secret_in_vault")),
                     "has_secret": bool(itsm_cfg.get("token_set") or itsm_cfg.get("change_token_set")),
                     "error": itsm_cfg.get("vault_error", "")},
            "ad": {"label": "Active Directory bind password", "in_vault": bool(ad_cfg.get("secret_in_vault")),
                  "has_secret": ad_cfg.get("bind_password") == "__stored__",
                  "error": ad_cfg.get("vault_error", "")},
            "integrations": [
                {"key": key, "label": next(l["label"] for l in integrations.LAYERS if l["key"] == key),
                 "in_vault": bool(row.get("secret_in_vault")), "has_secret": row.get("secret") == "__stored__",
                 "error": row.get("vault_error", "")}
                for key, row in integ_cfg.items()
            ],
            "servers": [
                {"key": s["name"], "label": f"{s['name']} (WinRM)",
                 "in_vault": bool(s.get("secret_in_vault")),
                 "has_secret": s.get("winrm_password") == "__stored__", "error": ""}
                for s in win_servers
            ],
        },
    }


@app.post("/api/admin/vault/migrate")
async def admin_vault_migrate(request: Request):
    if not vaultclient.enabled():
        raise HTTPException(status_code=400,
                            detail="Vault is not configured — set VAULT_ADDR and VAULT_TOKEN "
                                   "(see systemd/vault.service) and restart the app first.")
    results = {
        "itsm": await asyncio.to_thread(itsm.migrate_to_vault),
        "ad": await asyncio.to_thread(auth.migrate_ad_to_vault),
        "integrations": await asyncio.to_thread(integrations.migrate_to_vault),
        "inventory": await asyncio.to_thread(_migrate_inventory_to_vault),
    }
    await asyncio.to_thread(db.audit, _actor(request), "secrets_migrated_to_vault", results)
    return results


@app.get("/api/admin/ad-config")
async def admin_ad_get():
    return await asyncio.to_thread(auth.public_ad_config)


@app.post("/api/admin/ad-config")
async def admin_ad_save(request: Request):
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Invalid config.")
    await asyncio.to_thread(auth.save_ad_config, body)
    await asyncio.to_thread(db.audit, _actor(request), "ad_config_saved",
                            {"enabled": bool(body.get("enabled"))})
    return await asyncio.to_thread(auth.public_ad_config)


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


def _plan_server_context(server_name: str, fallback_platform: str = "linux") -> tuple[str, str]:
    """Ground plan generation in a real server: return (facts_prefix, platform).
    Uses whatever discovery already gathered for the server so the AI proposes
    OS-correct commands (e.g. yum on RHEL) instead of assuming."""
    name = (server_name or "").strip()
    if not name:
        return "", fallback_platform
    srv = load_inventory().get(name)
    if srv is None:
        return "", fallback_platform
    platform = "windows" if srv.is_windows else "linux"
    lines = [f"TARGET SERVER: {srv.name} ({srv.host}); platform: {platform}; "
             f"OS: {srv.os or 'unknown'}; services: {', '.join(srv.services) or 'unknown'}"]
    disco = discovery.facts_summary(name)
    if disco:
        lines.append("DISCOVERED SERVER FACTS (use these — do not guess):")
        lines.append(disco)
    return "\n".join(lines) + "\n\n", platform


class RefinePlanRequest(BaseModel):
    plan_text: str = Field(..., min_length=20, max_length=20000)
    platform: str = Field("linux", pattern=r"^(linux|windows)$")
    server: str = Field("", max_length=100)


@app.post("/api/changes/refine-plan")
async def refine_change_plan(req: RefinePlanRequest, request: Request):
    """AI pass over a pasted implementation-plan document: structured steps,
    validation/corrections, downtime verification, risk + success-rate,
    inferred CR fields, and still-missing mandatory fields."""
    prefix, platform = _plan_server_context(req.server, req.platform)
    kb = await knowledge.context_and_sources(req.plan_text, req.server)
    result = await changeplan.refine_plan(kb["text"] + prefix + req.plan_text, platform)
    result["kb_sources"] = kb["sources"]
    await asyncio.to_thread(db.audit, _actor(request), "change_plan_refined",
                            {"chars": len(req.plan_text), "steps": len(result.get("steps", [])),
                             "refined_by": result.get("refined_by")})
    return result


class ReRefineRequest(BaseModel):
    plan: dict = Field(...)                       # the current refined plan
    answers: str = Field(..., min_length=1, max_length=6000)
    platform: str = Field("linux", pattern=r"^(linux|windows)$")
    server: str = Field("", max_length=100)


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
    prefix, platform = _plan_server_context(req.server, req.platform)
    body = "\n".join(lines)
    kb = await knowledge.context_and_sources(body, req.server)
    result = await changeplan.refine_plan(kb["text"] + prefix + body, platform)
    result["kb_sources"] = kb["sources"]
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
    server: str = Field("", max_length=100)


@app.post("/api/changes/recommend")
async def recommend_change_fields(req: ChangeRecommendRequest):
    """Suggest CR attributes + an outline plan from a description (manual flow)."""
    prefix, platform = _plan_server_context(req.server, req.platform)
    kb = await knowledge.context_and_sources(req.context, req.server)
    out = await changeplan.recommend_change(kb["text"] + prefix + req.context, platform)
    out["kb_sources"] = kb["sources"]
    return out


# ---------- knowledge base (RAG) ----------

@app.get("/api/kb/overview")
async def kb_overview():
    """KB stats + Haiku model + cumulative token usage for the UI header."""
    return await asyncio.to_thread(knowledge.overview)


@app.get("/api/kb/tree")
async def kb_tree():
    """Smart taxonomy: server → OS → category → docs."""
    return {"tree": await asyncio.to_thread(knowledge.tree)}


@app.get("/api/kb/doc/{doc_id}")
async def kb_doc(doc_id: str):
    d = await asyncio.to_thread(db.kb_get_doc, doc_id)
    if d is None:
        raise HTTPException(status_code=404, detail="Document not found")
    return d


@app.delete("/api/kb/doc/{doc_id}")
async def kb_delete(doc_id: str, request: Request):
    await asyncio.to_thread(db.kb_delete_doc, doc_id)
    await asyncio.to_thread(db.audit, _actor(request), "kb_doc_deleted", {"id": doc_id})
    return {"ok": True}


class KbTextRequest(BaseModel):
    text: str = Field(..., min_length=3, max_length=200000)
    title: str = Field("", max_length=200)
    source_class: str = Field("document", max_length=20)


@app.post("/api/kb/add-text")
async def kb_add_text(req: KbTextRequest, request: Request):
    res = await knowledge.ingest(req.text, title_hint=req.title, source_type="text",
                                 actor=_actor(request),
                                 source_class=getattr(req, "source_class", "document"))
    if res.get("ok"):
        await asyncio.to_thread(db.audit, _actor(request), "kb_doc_added",
                                {"id": res["doc"]["id"], "server": res["doc"]["server"],
                                 "category": res["doc"]["category"]})
    return res


@app.post("/api/kb/upload")
async def kb_upload(request: Request, file: UploadFile = File(...),
                    source_class: str = Form("document")):
    raw = await file.read()
    if len(raw) > 10_000_000:
        raise HTTPException(status_code=413, detail="File too large (max 10 MB).")
    try:
        text = await asyncio.to_thread(changeplan.extract_text, file.filename or "", raw)
    except RuntimeError as exc:
        raise HTTPException(status_code=415, detail=str(exc))
    if len((text or "").strip()) < 3:
        raise HTTPException(status_code=422, detail="Could not read any text from that file.")
    res = await knowledge.ingest(text, title_hint=file.filename or "", source_type="upload",
                                 filename=file.filename, actor=_actor(request),
                                 source_class=source_class)
    if res.get("ok"):
        await asyncio.to_thread(db.audit, _actor(request), "kb_doc_uploaded",
                                {"id": res["doc"]["id"], "file": file.filename,
                                 "server": res["doc"]["server"], "category": res["doc"]["category"]})
    return res


class KbChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=8000)
    server: str = Field("", max_length=100)
    mode: str = Field("auto", pattern="^(auto|ask|teach)$")
    classes: list[str] = Field(default_factory=list)   # source filter; empty = all


@app.post("/api/kb/chat")
async def kb_chat(req: KbChatRequest, request: Request):
    res = await knowledge.chat(req.message, req.server, req.mode, classes=req.classes)
    if res.get("mode") == "teach" and res.get("ok"):
        await asyncio.to_thread(db.audit, _actor(request), "kb_doc_added",
                                {"via": "chat", "id": (res.get("stored") or {}).get("id")})
    return res


@app.post("/api/kb/architecture/live")
async def kb_architecture_live(server: str, request: Request):
    """Connect to the server live, discover its listeners + outbound connections,
    build the map, and store the findings in the knowledge base (local, no AI)."""
    if not server.strip():
        raise HTTPException(status_code=400, detail="server is required")
    g = await knowledge.live_architecture(server.strip())
    if g.get("ok"):
        await asyncio.to_thread(db.audit, _actor(request), "kb_live_topology",
                                {"server": server, "nodes": len(g.get("nodes", []))})
    return g


@app.get("/api/kb/architecture")
async def kb_architecture(server: str, ai: bool = False):
    """Architecture view for one CI from inventory + discovery + KB. Default is
    a deterministic LOCAL build (no AI tokens); ai=1 uses Haiku for a richer,
    more precise graph."""
    if not server.strip():
        raise HTTPException(status_code=400, detail="server is required")
    return await knowledge.architecture(server.strip(), use_ai=ai)


@app.get("/api/kb/design-docs")
async def kb_design_docs():
    """List uploaded HLD/LLD/design documents that can be rendered as a flow
    diagram, and whether each already has a cached diagram."""
    return {"docs": await asyncio.to_thread(knowledge.list_design_docs)}


@app.get("/api/kb/design-diagram")
async def kb_design_diagram(doc_id: str, regenerate: bool = False, brief: str = ""):
    """Flow/architecture diagram extracted from an HLD/LLD document. Served from
    the cached diagram unless regenerate=1 (which re-extracts with AI). `brief`
    steers depth/scope."""
    if not doc_id.strip():
        raise HTTPException(status_code=400, detail="doc_id is required")
    return await knowledge.design_diagram(doc_id.strip(), regenerate=regenerate,
                                          brief=brief.strip())


@app.get("/api/kb/design-peek")
async def kb_design_peek(q: str = "", server: str = "", doc_id: str = "",
                         broad: bool = False):
    """Return an EXISTING stored design for this component/topic without building
    one (no AI tokens). {ok:true, exists:false} when nothing is stored yet."""
    return await knowledge.design_peek(q.strip(), server.strip(),
                                       broad=broad, doc_id=doc_id.strip())


@app.get("/api/kb/design-list")
async def kb_design_list():
    """All stored design diagrams (shared cache) — for management/deletion."""
    return {"designs": await asyncio.to_thread(db.design_cache_list)}


class DesignDeleteRequest(BaseModel):
    key: str = Field(..., min_length=1, max_length=200)


@app.post("/api/kb/design-delete")
async def kb_design_delete(req: DesignDeleteRequest, request: Request):
    """Delete a stored design diagram by its cache key (shared, so it's removed
    for everyone). It can be regenerated later on demand."""
    ok = await asyncio.to_thread(db.design_cache_delete, req.key.strip())
    if ok:
        await asyncio.to_thread(db.audit, _actor(request), "design_deleted", {"key": req.key})
    return {"ok": ok}


@app.get("/api/kb/design-query")
async def kb_design_query(q: str = "", server: str = "", regenerate: bool = False,
                          broad: bool = False, brief: str = ""):
    """Build one architecture diagram synthesised across MULTIPLE knowledge-base
    sources relevant to the query (or the whole organisation when broad=1), and
    store it permanently in the shared cache. `brief` steers depth/scope.
    Reused (no tokens) once built."""
    return await knowledge.design_from_query(q.strip(), server.strip(),
                                             regenerate=regenerate, broad=broad,
                                             brief=brief.strip())


class DesignLayoutRequest(BaseModel):
    doc_id: str = Field("", max_length=64)
    query_key: str = Field("", max_length=200)
    layout: dict = Field(default_factory=dict)


@app.post("/api/kb/design-layout")
async def kb_design_layout(req: DesignLayoutRequest):
    """Persist operator-dragged node positions for a design diagram (either a
    single-document diagram via doc_id, or a cross-document one via query_key)."""
    if req.query_key.strip():
        ok = await asyncio.to_thread(knowledge.save_query_design_layout,
                                     req.query_key.strip(), req.layout)
    elif req.doc_id.strip():
        ok = await asyncio.to_thread(knowledge.save_design_layout,
                                     req.doc_id.strip(), req.layout)
    else:
        ok = False
    return {"ok": ok}


@app.get("/api/kb/search")
async def kb_search(q: str, server: str = ""):
    hits = await knowledge.retrieve(q, server, top_k=8)
    docs = {d["id"]: d for d in await asyncio.to_thread(db.kb_list_docs)}
    return {"hits": [{"text": h["text"], "score": h.get("_score"),
                      "server": h["server"], "os": h["os"], "category": h["category"],
                      "title": docs.get(h["doc_id"], {}).get("title", "entry"),
                      "doc_id": h["doc_id"]} for h in hits]}


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
    # the sessions table predates the token breakdown/model — overlay those
    # from the session's outcome.json for a completed (non-live) session
    if state is None:
        try:
            oc = json.loads((_session_workdir(session_id) / "outcome.json").read_text())
            for k in ("cache_read_tokens", "cache_write_tokens", "model"):
                out.setdefault(k, oc.get(k))
        except (OSError, json.JSONDecodeError):
            pass
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
        if s.get("winrm_password") or s.get("secret_in_vault"):
            s["winrm_password"] = _SECRET_KEPT
        out.append(s)
    return out


def _server_vault_path(name: str) -> str:
    return f"servers/{name}"


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
        new_pw = entry.winrm_password
        if new_pw and new_pw != _SECRET_KEPT:
            # a real new password was supplied — store it (Vault when enabled,
            # a Vault write failure raises rather than silently falling back)
            if vaultclient.enabled():
                await asyncio.to_thread(vaultclient.write_secret,
                                        _server_vault_path(entry.name), {"winrm_password": new_pw})
                yaml_dict["secret_in_vault"] = True
                if name != entry.name:
                    await asyncio.to_thread(vaultclient.delete_secret, _server_vault_path(name))
            else:
                yaml_dict["winrm_password"] = new_pw
        elif prior and prior.get("secret_in_vault"):
            # keep the existing Vault-backed secret; if renamed, move it to the new path
            yaml_dict["secret_in_vault"] = True
            if name != entry.name and vaultclient.enabled():
                with contextlib.suppress(vaultclient.VaultError):
                    data = await asyncio.to_thread(vaultclient.read_secret, _server_vault_path(name))
                    if data:
                        await asyncio.to_thread(vaultclient.write_secret,
                                                _server_vault_path(entry.name), data)
                        await asyncio.to_thread(vaultclient.delete_secret, _server_vault_path(name))
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


# ---------- bulk server import (CSV / Excel) ----------

_BULK_COLUMNS = ["name", "host", "user", "platform", "port", "os", "description",
                 "ssh_key", "winrm_password", "tags", "services"]
_BULK_MANDATORY = ["name", "host", "user"]

_SAMPLE_ROWS = [
    ["web-01", "10.70.5.10", "svc-ops", "linux", "22", "RHEL 9", "Prod web node",
     "/root/.ssh/id_ops", "", "web;prod", "httpd;nginx"],
    ["dc-01", "10.70.5.20", "Administrator", "windows", "5985", "Windows Server 2022",
     "Domain controller", "", "P@ssw0rd", "ad;prod", "ADWS;DNS"],
]


def _split_list(v: str) -> list[str]:
    return [x.strip() for x in re_split_semicomma(v) if x.strip()]


def re_split_semicomma(v: str) -> list[str]:
    import re as _re
    return _re.split(r"[;,]", str(v or ""))


def _bulk_parse(filename: str, raw: bytes) -> list[dict]:
    """Parse CSV or XLSX into a list of {column: value} row dicts (header-driven)."""
    name = (filename or "").lower()
    rows: list[dict] = []
    if name.endswith((".xlsx", ".xlsm")):
        import io
        import openpyxl
        wb = openpyxl.load_workbook(io.BytesIO(raw), read_only=True, data_only=True)
        ws = wb.active
        headers = None
        for r in ws.iter_rows(values_only=True):
            cells = ["" if c is None else str(c).strip() for c in r]
            if not any(cells):
                continue
            if headers is None:
                headers = [c.lower().strip() for c in cells]
                continue
            rows.append({headers[i]: (cells[i] if i < len(cells) else "")
                         for i in range(len(headers))})
        wb.close()
    else:
        import csv
        import io
        text = raw.decode("utf-8-sig", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        for r in reader:
            rows.append({(k or "").lower().strip(): (v or "").strip()
                         for k, v in r.items() if k})
    return rows


@app.get("/api/admin/inventory/sample")
async def inventory_sample(fmt: str = "csv"):
    """Downloadable template with the columns, an example Linux + Windows row,
    and which fields are mandatory."""
    if fmt == "xlsx":
        import io
        import openpyxl
        wb = openpyxl.Workbook()
        ws = wb.active; ws.title = "servers"
        ws.append(_BULK_COLUMNS)
        for row in _SAMPLE_ROWS:
            ws.append(row)
        notes = wb.create_sheet("instructions")
        notes.append(["Mandatory columns", ", ".join(_BULK_MANDATORY)])
        notes.append(["platform", "linux (SSH) or windows (WinRM). Default linux."])
        notes.append(["port", "SSH default 22; WinRM default 5985."])
        notes.append(["winrm_password", "Only for windows rows (stored server-side)."])
        notes.append(["tags / services", "Separate multiple values with ; or ,"])
        buf = io.BytesIO(); wb.save(buf); wb.close()
        return Response(
            content=buf.getvalue(),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": 'attachment; filename="server-inventory-template.xlsx"'})
    import csv
    import io
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(_BULK_COLUMNS)
    for row in _SAMPLE_ROWS:
        w.writerow(row)
    body = ("# Mandatory: name, host, user. platform = linux|windows (default linux).\n"
            "# port: SSH 22 / WinRM 5985. winrm_password only for windows. "
            "tags/services separated by ; or ,\n" + out.getvalue())
    return Response(content=body, media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="server-inventory-template.csv"'})


@app.post("/api/admin/inventory/bulk")
async def inventory_bulk(request: Request, file: UploadFile = File(...)):
    raw = await file.read()
    if len(raw) > 5_000_000:
        raise HTTPException(status_code=413, detail="File too large (max 5 MB).")
    try:
        rows = await asyncio.to_thread(_bulk_parse, file.filename or "", raw)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=f"Could not read the file: {exc}")
    if not rows:
        raise HTTPException(status_code=422, detail="No data rows found (need a header row + at least one server).")

    servers = load_raw_inventory()
    existing = {s.get("name") for s in servers}
    added, skipped, failed = 0, 0, []
    for i, r in enumerate(rows, start=2):   # row 1 is the header in the sheet
        nm = (r.get("name") or "").strip()
        if not nm or nm.startswith("#"):
            continue
        try:
            plat = (r.get("platform") or "linux").strip().lower() or "linux"
            data = {
                "name": nm, "host": (r.get("host") or "").strip(),
                "user": (r.get("user") or "").strip(),
                "platform": plat if plat in ("linux", "windows") else "linux",
                "os": (r.get("os") or "").strip(),
                "description": (r.get("description") or "").strip(),
                "ssh_key": (r.get("ssh_key") or "").strip() or None,
                "tags": _split_list(r.get("tags", "")),
                "services": _split_list(r.get("services", "")),
            }
            port = (r.get("port") or "").strip()
            if port:
                data["port"] = int(port)
            if data["platform"] == "windows":
                if not port:
                    data["port"] = 5985
                data["winrm_port"] = data.get("port", 5985)
                if (r.get("winrm_password") or "").strip():
                    data["winrm_password"] = r["winrm_password"].strip()
            miss = [m for m in _BULK_MANDATORY if not data.get(m)]
            if miss:
                raise ValueError(f"missing {', '.join(miss)}")
            entry = ServerEntry(**data)
        except Exception as exc:  # noqa: BLE001 - validation / parse
            failed.append({"row": i, "name": nm, "error": str(exc)[:160]})
            continue
        if entry.name in existing:
            skipped += 1
            failed.append({"row": i, "name": nm, "error": "already in inventory (skipped)"})
            continue
        yaml_dict = entry.to_yaml_dict()
        if entry.platform == "windows" and entry.winrm_password:
            if vaultclient.enabled():
                try:
                    await asyncio.to_thread(vaultclient.write_secret,
                                            _server_vault_path(entry.name),
                                            {"winrm_password": entry.winrm_password})
                    yaml_dict["secret_in_vault"] = True
                except vaultclient.VaultError as exc:
                    failed.append({"row": i, "name": nm, "error": f"Vault write failed: {exc}"[:160]})
                    continue
            else:
                yaml_dict["winrm_password"] = entry.winrm_password
        servers.append(yaml_dict)
        existing.add(entry.name)
        added += 1

    if added:
        save_inventory(servers)
    await asyncio.to_thread(db.audit, _actor(request), "inventory_bulk_import",
                            {"file": file.filename, "added": added, "skipped": skipped,
                             "failed": len(failed) - skipped})
    return {"ok": True, "added": added, "skipped": skipped,
            "failed": len([f for f in failed if "skipped" not in f["error"]]),
            "total": len([r for r in rows if (r.get("name") or "").strip()
                          and not (r.get("name") or "").startswith("#")]),
            "details": failed}


@app.delete("/api/admin/inventory/{name}")
async def delete_server(name: str, request: Request):
    servers = load_raw_inventory()
    removed = next((s for s in servers if s.get("name") == name), None)
    remaining = [s for s in servers if s.get("name") != name]
    if removed is None:
        raise HTTPException(status_code=404, detail=f"Server '{name}' not found")
    save_inventory(remaining)
    if removed.get("secret_in_vault") and vaultclient.enabled():
        with contextlib.suppress(vaultclient.VaultError):
            await asyncio.to_thread(vaultclient.delete_secret, _server_vault_path(name))
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


@app.post("/api/servers/{name}/discover/detailed")
async def run_detailed_discovery(name: str, request: Request):
    """Deep, read-only architecture scan (packages, dependencies, firewall,
    scheduled jobs, storage, …). The report is stored into the knowledge base as
    device_data so the knowledge bot can answer detailed / architecture reviews."""
    server = load_inventory().get(name)
    if server is None:
        raise HTTPException(status_code=404, detail=f"Server '{name}' not in inventory")
    result = await discovery.discover_detailed(server)
    if result.get("ok") and result.get("report"):
        facts = (discovery.load_facts(name) or {}).get("facts") or {}
        try:
            doc_id = await knowledge.store_local(
                result["report"], server=name, os_=facts.get("os_family", "") or "",
                category="architecture", title=f"Detailed discovery — {name}",
                source_type="deep-discovery", source_class="device_data")
            result["stored_doc_id"] = doc_id
        except Exception as exc:  # noqa: BLE001
            result["kb_error"] = str(exc)[:200]
    await asyncio.to_thread(db.audit, _actor(request), "server_deep_discovered",
                            {"server": name, "ok": result.get("ok"),
                             "stored": bool(result.get("stored_doc_id"))})
    return result


@app.get("/api/servers/{name}/discovery/detailed")
async def get_detailed_discovery(name: str):
    return discovery.load_detail(name) or {"ok": False, "error": "no deep scan yet"}


def _get_state(session_id: str) -> orchestrator.SessionState:
    state = orchestrator.SESSIONS.get(session_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return state
