"""HashiCorp Vault client — centralizes platform secrets in a self-hosted Vault
instead of the chmod-600 YAML files (itsm.yaml, ad.yaml, integrations.yaml).

Configuration is environment-only (VAULT_ADDR / VAULT_TOKEN / …) so the app's
own Vault credentials are never written to a file this app manages — feed them
via a systemd EnvironmentFile with tight permissions (see systemd/vault.service
and the README). Uses the stdlib (urllib) rather than the `hvac` package, for
the same reason itsm.py talks to SummitAI with urllib: no extra pip dependency
to fetch on a restricted/air-gapped enterprise network.

Opt-in and fail-safe by design:
  * enabled() is False until VAULT_ADDR + VAULT_TOKEN are set — every calling
    module keeps working exactly as before (plaintext-in-chmod-600-YAML) until
    an admin deliberately turns Vault on.
  * once a secret has been migrated into Vault, a read failure raises
    VaultError instead of silently returning nothing — callers surface that as
    an error rather than pretending the secret is unset (which could make an
    admin re-enter/overwrite a perfectly good credential, or let an app run
    with a blank credential when Vault is just temporarily unreachable).
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request

VAULT_ADDR = os.environ.get("VAULT_ADDR", "").rstrip("/")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "")
VAULT_NAMESPACE = os.environ.get("VAULT_NAMESPACE", "")       # Vault Enterprise only
VAULT_KV_MOUNT = os.environ.get("VAULT_KV_MOUNT", "secret")   # KV v2 mount point
VAULT_PATH_PREFIX = os.environ.get("VAULT_PATH_PREFIX", "troubleshooter")
VAULT_TIMEOUT = float(os.environ.get("VAULT_TIMEOUT", "5"))
VAULT_VERIFY_TLS = os.environ.get("VAULT_VERIFY_TLS", "1") != "0"


class VaultError(RuntimeError):
    """Vault is configured but a request failed (unreachable, sealed, denied)."""


def enabled() -> bool:
    return bool(VAULT_ADDR and VAULT_TOKEN)


def _url(path: str, *, metadata: bool = False) -> str:
    kind = "metadata" if metadata else "data"
    return f"{VAULT_ADDR}/v1/{VAULT_KV_MOUNT}/{kind}/{VAULT_PATH_PREFIX}/{path}"


def _ctx_for(url: str):
    if url.startswith("https://") and not VAULT_VERIFY_TLS:
        return ssl._create_unverified_context()
    return None


def _request(method: str, url: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("X-Vault-Token", VAULT_TOKEN)
    if VAULT_NAMESPACE:
        req.add_header("X-Vault-Namespace", VAULT_NAMESPACE)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=VAULT_TIMEOUT, context=_ctx_for(url)) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else {}


def read_secret(path: str) -> dict | None:
    """Latest version of a KV v2 secret at troubleshooter/<path>, or None if it
    doesn't exist (or Vault isn't configured). Raises VaultError on a real
    connectivity/auth/seal failure — never swallow that into a silent None."""
    if not enabled():
        return None
    try:
        resp = _request("GET", _url(path))
        return (resp.get("data") or {}).get("data")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise VaultError(f"Vault read '{path}' failed ({exc.code}): {exc.reason}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise VaultError(f"Vault unreachable while reading '{path}': {exc}") from exc


def write_secret(path: str, data: dict) -> None:
    if not enabled():
        raise VaultError("Vault is not configured (VAULT_ADDR / VAULT_TOKEN unset)")
    try:
        _request("POST", _url(path), {"data": data})
    except urllib.error.HTTPError as exc:
        raise VaultError(f"Vault write '{path}' failed ({exc.code}): {exc.reason}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise VaultError(f"Vault unreachable while writing '{path}': {exc}") from exc


def delete_secret(path: str) -> None:
    """Destroys ALL versions (metadata delete) — a rotated/removed credential
    should not be recoverable from Vault's version history."""
    if not enabled():
        return
    try:
        _request("DELETE", _url(path, metadata=True))
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise VaultError(f"Vault delete '{path}' failed ({exc.code}): {exc.reason}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise VaultError(f"Vault unreachable while deleting '{path}': {exc}") from exc


def health() -> dict:
    """For the Settings → Secrets vault status card."""
    if not VAULT_ADDR:
        return {"configured": False}
    out = {"configured": True, "addr": VAULT_ADDR, "mount": VAULT_KV_MOUNT,
          "token_configured": bool(VAULT_TOKEN)}
    url = f"{VAULT_ADDR}/v1/sys/health"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=VAULT_TIMEOUT, context=_ctx_for(url)) as resp:
            body = json.loads(resp.read())
        out.update(_health_fields(body, reachable=True))
    except urllib.error.HTTPError as exc:
        # Vault's health endpoint uses the HTTP status itself to signal state
        # (429=standby, 503=sealed, 501=not initialized, …), body still useful
        try:
            body = json.loads(exc.read())
            out.update(_health_fields(body, reachable=True))
        except (ValueError, OSError):
            out.update(reachable=False, error=f"HTTP {exc.code}: {exc.reason}")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        out.update(reachable=False, error=str(exc))
    if out.get("reachable") and VAULT_TOKEN:
        with_ttl = _token_ttl()
        if with_ttl is not None:
            out["token_ttl_seconds"] = with_ttl
    return out


def _health_fields(body: dict, *, reachable: bool) -> dict:
    return {"reachable": reachable, "sealed": bool(body.get("sealed")),
           "initialized": bool(body.get("initialized")), "version": body.get("version"),
           "standby": bool(body.get("standby"))}


def _token_ttl() -> int | None:
    """Best-effort: how long until the app's own Vault token expires, so an
    admin notices a soon-to-expire token before it locks the app out of Vault."""
    try:
        resp = _request("GET", f"{VAULT_ADDR}/v1/auth/token/lookup-self")
        ttl = (resp.get("data") or {}).get("ttl")
        return int(ttl) if ttl is not None else None
    except Exception:  # noqa: BLE001 — purely informational
        return None
