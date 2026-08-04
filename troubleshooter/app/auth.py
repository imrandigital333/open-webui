"""Authentication & role-based access control.

Local accounts now (PBKDF2-hashed passwords, DB-backed sessions), with Active
Directory / LDAP kept ready behind a config so it can be switched on later —
per-user `auth_mode` decides which backend verifies the password.

Authorization is role → pages: the Admin role sees everything; every other role
is granted an explicit set of pages, editable from Settings → Users & Access.
Enforcement is server-side (see main.py middleware) as well as in the UI.

Secrets (local password hashes, the AD bind password) live only in the DB / a
chmod-600 ad.yaml and are never returned to the browser.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
import uuid

import yaml

from . import db
from .inventory import BASE_DIR

# ---------- pages (tabs) the UI exposes; roles are granted a subset ----------
PAGES = [
    {"key": "overview", "label": "Overview"},
    {"key": "incidents", "label": "Incidents"},
    {"key": "work", "label": "Investigations"},
    {"key": "changes", "label": "Changes"},
    {"key": "knowledge", "label": "Knowledge base"},
    {"key": "settings", "label": "Settings & administration"},
]
PAGE_KEYS = [p["key"] for p in PAGES]

SESSION_TTL = int(os.environ.get("TROUBLESHOOTER_SESSION_TTL", str(12 * 3600)))
COOKIE_NAME = "ai_sid"
CSRF_COOKIE_NAME = "ai_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"
MAX_FAILED = 5                     # lock the account after this many bad passwords
LOCK_SECONDS = 15 * 60

AD_CONFIG_PATH = BASE_DIR / "ad.yaml"
_REDACTED = "__stored__"           # sentinel returned to the browser instead of a secret

_AD_DEFAULTS = {
    "enabled": False,
    "server": "",                  # e.g. ldaps://dc01.bial.local
    "port": 636,
    "use_ssl": True,
    "base_dn": "",                 # e.g. DC=bial,DC=local
    "user_dn_template": "",        # e.g. {username}@bial.local  OR  CN={username},OU=Users,DC=bial,DC=local
    "user_search_attr": "sAMAccountName",
    "bind_user": "",               # optional service account for search-then-bind
    "bind_password": "",           # write-only
    "default_role": "viewer",      # role auto-assigned to AD users on first login
    "verify_tls": True,
}


# ---------- password hashing (PBKDF2-SHA256, stdlib) ----------

_ITERATIONS = 240_000


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)
    return f"pbkdf2_sha256${_ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_b64, hash_b64 = (stored or "").split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iters))
        return hmac.compare_digest(dk, expected)
    except Exception:  # noqa: BLE001
        return False


def password_ok(pw: str) -> str:
    """Return an error string if the password is too weak, else ''."""
    if not pw or len(pw) < 8:
        return "Password must be at least 8 characters."
    if pw.lower() in ("password", "changeme", "admin", "admin123", "12345678"):
        return "Please choose a less common password."
    return ""


# ---------- AD / LDAP configuration (secrets write-only) ----------

def load_ad_config() -> dict:
    cfg = dict(_AD_DEFAULTS)
    try:
        if AD_CONFIG_PATH.exists():
            file_cfg = yaml.safe_load(AD_CONFIG_PATH.read_text()) or {}
            for k in _AD_DEFAULTS:
                if k in file_cfg and file_cfg[k] not in (None, ""):
                    cfg[k] = file_cfg[k]
            for b in ("enabled", "use_ssl", "verify_tls"):
                if isinstance(file_cfg.get(b), bool):
                    cfg[b] = file_cfg[b]
    except (OSError, yaml.YAMLError):
        pass
    return cfg


def public_ad_config() -> dict:
    """AD config for the browser — the bind password is redacted."""
    cfg = load_ad_config()
    cfg = dict(cfg)
    cfg["bind_password"] = _REDACTED if cfg.get("bind_password") else ""
    cfg["ldap3_available"] = _ldap3_available()
    return cfg


def save_ad_config(new: dict) -> None:
    cur = load_ad_config()
    out = dict(cur)
    for k in _AD_DEFAULTS:
        if k in new:
            out[k] = new[k]
    # keep the stored bind password when the browser sends the redaction sentinel
    if new.get("bind_password") in (None, "", _REDACTED):
        out["bind_password"] = cur.get("bind_password", "")
    AD_CONFIG_PATH.write_text(yaml.safe_dump(out, sort_keys=False))
    os.chmod(AD_CONFIG_PATH, 0o600)


def _ldap3_available() -> bool:
    try:
        import ldap3  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def authenticate_ad(username: str, password: str) -> tuple[bool, str]:
    """Bind to AD as the user. Returns (ok, error)."""
    cfg = load_ad_config()
    if not cfg.get("enabled"):
        return False, "AD authentication is not enabled."
    if not _ldap3_available():
        return False, "AD support needs the 'ldap3' package installed on the server."
    if not cfg.get("server") or not cfg.get("user_dn_template"):
        return False, "AD is not fully configured (server / user DN template)."
    try:
        import ldap3
        tmpl = cfg["user_dn_template"]
        user_dn = tmpl.format(username=username) if "{username}" in tmpl else username
        server = ldap3.Server(cfg["server"], port=int(cfg.get("port") or 636),
                              use_ssl=bool(cfg.get("use_ssl", True)), get_info=None)
        conn = ldap3.Connection(server, user=user_dn, password=password,
                                authentication=ldap3.SIMPLE, auto_bind=True,
                                receive_timeout=10)
        conn.unbind()
        return True, ""
    except Exception as exc:  # noqa: BLE001
        return False, f"AD bind failed: {type(exc).__name__}: {exc}"[:200]


# ---------- users & authentication ----------

def authenticate(username: str, password: str, ip: str = "") -> dict:
    """Verify credentials for a known, enabled user. Returns
    {ok, user|error, must_change}."""
    username = (username or "").strip().lower()
    user = db.user_get_by_name(username)
    if not user:
        return {"ok": False, "error": "Invalid username or password."}
    if not user["enabled"]:
        return {"ok": False, "error": "This account is disabled."}
    if user.get("locked_until") and user["locked_until"] > time.time():
        mins = int((user["locked_until"] - time.time()) / 60) + 1
        return {"ok": False, "error": f"Account locked — try again in {mins} min."}

    if user["auth_mode"] == "ad":
        ok, err = authenticate_ad(username, password)
    else:
        stored = db.user_password_hash(user["id"])
        ok, err = (bool(stored) and verify_password(password, stored)), "Invalid username or password."

    if not ok:
        fails = (user.get("failed_count") or 0) + 1
        upd = {"failed_count": fails}
        if fails >= MAX_FAILED:
            upd["locked_until"] = time.time() + LOCK_SECONDS
            upd["failed_count"] = 0
            err = "Too many failed attempts — account locked for 15 minutes."
        db.user_update(user["id"], upd)
        return {"ok": False, "error": err}

    db.user_update(user["id"], {"failed_count": 0, "locked_until": None,
                                "last_login": time.time()})
    return {"ok": True, "user": user, "must_change": user["must_change"]}


def create_session(user_id: str, ip: str = "") -> str:
    token = secrets.token_urlsafe(36)
    db.auth_session_create(token, user_id, time.time() + SESSION_TTL, ip)
    return token


def user_from_token(token: str) -> dict | None:
    if not token:
        return None
    sess = db.auth_session_get(token)
    if not sess:
        return None
    if sess["expires_at"] < time.time():
        db.auth_session_delete(token)
        return None
    user = db.user_get(sess["user_id"])
    if not user or not user["enabled"]:
        return None
    return user


def destroy_session(token: str) -> None:
    if token:
        db.auth_session_delete(token)


# ---------- CSRF (signed double-submit cookie) ----------
# The session cookie (ai_sid) is httponly + SameSite=Lax, which already blocks
# cross-site form/fetch POSTs in modern browsers. This adds a second,
# defense-in-depth layer that enterprise security reviews expect explicitly: a
# token derived from HMAC(server secret, session token) is set in a *readable*
# cookie at login; the SPA echoes it back as a header on every mutating
# request; the server recomputes the HMAC from the (httponly, unspoofable)
# session cookie and compares. An attacker who can't read ai_sid can't forge
# a matching token even if they can plant an arbitrary ai_csrf cookie value.

_CSRF_SECRET_PATH = BASE_DIR / "data" / ".csrf_secret"
_csrf_secret_cache: bytes | None = None


def _csrf_secret() -> bytes:
    global _csrf_secret_cache
    if _csrf_secret_cache is not None:
        return _csrf_secret_cache
    try:
        _CSRF_SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
        if _CSRF_SECRET_PATH.exists():
            data = _CSRF_SECRET_PATH.read_bytes()
            if data:
                _csrf_secret_cache = data
                return data
        secret = secrets.token_bytes(32)
        _CSRF_SECRET_PATH.write_bytes(secret)
        os.chmod(_CSRF_SECRET_PATH, 0o600)
        _csrf_secret_cache = secret
        return secret
    except OSError:
        # last resort: an in-memory-only secret keeps CSRF protection working
        # for this process's lifetime even if the data dir isn't writable
        _csrf_secret_cache = secrets.token_bytes(32)
        return _csrf_secret_cache


def csrf_token_for_session(session_token: str) -> str:
    if not session_token:
        return ""
    return hmac.new(_csrf_secret(), session_token.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_csrf(session_token: str, presented: str) -> bool:
    if not session_token or not presented:
        return False
    return hmac.compare_digest(csrf_token_for_session(session_token), presented)


# ---------- roles / authorization ----------

def pages_for_role(role: str) -> list[str]:
    r = db.role_get(role)
    if not r:
        return []
    if "*" in (r["pages"] or []):
        return list(PAGE_KEYS)
    return [p for p in r["pages"] if p in PAGE_KEYS]


def is_admin(user: dict) -> bool:
    return bool(user) and user.get("role") == "admin"


def can_access(user: dict, page: str) -> bool:
    if not user:
        return False
    if is_admin(user):
        return True
    return page in pages_for_role(user.get("role", ""))


# ---------- request → required permission mapping (server-side enforcement) ----------

def required_permission(method: str, path: str):
    """What a request needs: 'admin', a page key, or None (any signed-in user)."""
    p = path
    if p.startswith("/api/admin/"):
        return "admin"
    if p.startswith("/api/kb"):
        return "knowledge"
    if p.startswith("/api/change"):
        return "changes"
    if p.startswith("/api/incidents"):
        return "incidents"
    if p.startswith(("/api/sessions", "/api/investigate", "/api/session/", "/api/exec")):
        return "work"
    # shared read-only data any authenticated user may fetch (populates dropdowns)
    if method == "GET" and p.startswith(
            ("/api/inventory", "/api/datasources", "/api/fleet", "/api/overview",
             "/api/health", "/api/ai/health", "/api/scripts")):
        return None
    # configuration / writes → admin only
    if p.startswith(("/api/inventory", "/api/itsm", "/api/scripts", "/api/discovery",
                     "/api/datasources")):
        return "admin"
    return None


# ---------- bootstrap: seed roles + the first admin ----------

_DEFAULT_ROLES = [
    ("admin", "Full access to every page and all administration.", ["*"], True),
    ("operator", "Investigations, Changes, Incidents and the Overview.",
     ["overview", "incidents", "work", "changes"], False),
    ("knowledge", "Knowledge base only.", ["knowledge"], False),
    ("viewer", "Read-only Overview.", ["overview"], False),
]


def ensure_bootstrap() -> None:
    """Seed the default roles and, if there are no users yet, the admin account."""
    if not db.role_list():
        for name, desc, pages, builtin in _DEFAULT_ROLES:
            db.role_upsert(name, desc, pages, builtin)
    if db.user_count() == 0:
        pw = os.environ.get("TROUBLESHOOTER_ADMIN_PASSWORD", "admin")
        db.user_create({
            "id": uuid.uuid4().hex[:16], "username": "admin",
            "display_name": "Administrator", "email": "", "auth_mode": "local",
            "password_hash": hash_password(pw), "role": "admin",
            "enabled": True, "must_change": True})
