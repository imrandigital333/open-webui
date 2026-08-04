"""Pluggable AI provider connectors + per-function model assignment.

Every AI call site in this app is one of two shapes:
  * a simple one-shot "prompt in, JSON out" completion — knowledge base
    classify/chat/design, change plan refine/generate/recommend/verify,
    ad-hoc command risk review; or
  * the autonomous, multi-turn, tool-using investigation engine
    (orchestrator.py) that runs Bash/Read/Write/Grep tools across many turns
    to actually troubleshoot a server.

Both start out wired to Claude Code's own login (via claude_agent_sdk) with
NO extra configuration — that is the default for every function, so this
module is purely additive: until an admin explicitly reassigns a function to
a connector below in Settings → AI Providers, behavior is byte-identical to
before this module existed.

A "connector" is a named connection to an AI provider's API:
  * kind="anthropic" — the direct Anthropic Messages API (a different key
    than Claude Code's own login — e.g. a separate account, or a
    Bedrock/Vertex-fronted endpoint that speaks the Messages API).
  * kind="openai" — any OpenAI-compatible chat-completions API: OpenAI
    itself, Azure OpenAI, Ollama, LM Studio, vLLM, and most self-hosted model
    servers speak this same request/response shape.

API keys are secrets and follow the same pattern as itsm/ad/integrations/
inventory: stored in a chmod-600 ai_providers.yaml until Vault is enabled, at
which point they move to Vault (secret_in_vault marker, path
ai/providers/<id>) — see vaultclient.py. Uses stdlib urllib only, same reason
itsm.py/vaultclient.py avoid `requests`: no new pip dependency on a
restricted/air-gapped enterprise network.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import ssl
import urllib.error
import urllib.request

import yaml

from . import vaultclient
from .inventory import BASE_DIR

CONFIG_PATH = BASE_DIR / "ai_providers.yaml"
FUNCTIONS_PATH = BASE_DIR / "ai_functions.yaml"
_REDACTED = "__stored__"

KINDS = ["anthropic", "openai"]
_CONNECTOR_FIELDS = ("name", "kind", "base_url", "api_key", "verify_tls", "notes",
                     "enabled", "secret_in_vault")

# A synthetic, always-available "connector" that isn't an HTTP endpoint at all —
# it's this server's own Claude Code CLI login (claude_agent_sdk). It exists so
# every function has a real, explicit, editable model selection instead of a
# hidden/ambiguous "whatever the CLI defaults to" fallback. It can't be created,
# edited, or deleted like a normal connector.
NATIVE_CONNECTOR_ID = "__claude_native__"
NATIVE_MODELS = [
    {"id": "claude-opus-5", "label": "Claude Opus 5 — most capable, slower/costlier"},
    {"id": "claude-sonnet-5", "label": "Claude Sonnet 5 — balanced (recommended)"},
    {"id": "claude-haiku-4-5-20251001", "label": "Claude Haiku 4.5 — fastest/cheapest"},
]
_NATIVE_MODEL_IDS = {m["id"] for m in NATIVE_MODELS}


def _native_connector() -> dict:
    return {"id": NATIVE_CONNECTOR_ID, "name": "Claude Code (built-in)", "kind": "claude_native",
            "base_url": "", "api_key": "", "verify_tls": True,
            "notes": "Uses this server's own Claude Code CLI login — no API key needed.",
            "enabled": True, "secret_in_vault": False, "native": True}


# Every pluggable AI use case in the platform. "agentic": True marks the one
# function (the investigation engine) that isn't a simple one-shot completion —
# assigning it to an external connector switches orchestrator.py to a generic
# tool-calling loop instead of the Claude Agent SDK's autonomous agent (see
# orchestrator.py). "default_model" is the specific model used until an admin
# picks something else in Settings → AI Providers — every function resolves to
# an explicit, visible choice, never an unlabeled "default".
FUNCTIONS = [
    {"key": "kb_classify", "group": "Knowledge base", "label": "Classify uploads",
     "hint": "Tags & summarizes newly ingested documents/configs",
     "default_label": "Claude Haiku 4.5", "default_model": "claude-haiku-4-5-20251001"},
    {"key": "kb_chat", "group": "Knowledge base", "label": "Chat / Q&A answering",
     "hint": "Answers operator questions from retrieved knowledge",
     "default_label": "Claude Haiku 4.5", "default_model": "claude-haiku-4-5-20251001"},
    {"key": "kb_design", "group": "Knowledge base", "label": "Architecture & design diagrams",
     "hint": "Synthesizes HLD/LLD service-map diagrams from stored knowledge",
     "default_label": "Claude Haiku 4.5", "default_model": "claude-haiku-4-5-20251001"},
    {"key": "change_refine", "group": "Change management", "label": "Plan refinement",
     "hint": "Turns a pasted change plan into structured steps + risk/downtime scoring",
     "default_label": "Claude Sonnet 5", "default_model": "claude-sonnet-5"},
    {"key": "change_generate", "group": "Change management", "label": "Plan generation",
     "hint": "Generates a full change plan from a text description",
     "default_label": "Claude Sonnet 5", "default_model": "claude-sonnet-5"},
    {"key": "change_recommend", "group": "Change management", "label": "CR recommendation",
     "hint": "Suggests CR attributes/outline from a description",
     "default_label": "Claude Sonnet 5", "default_model": "claude-sonnet-5"},
    {"key": "change_verify", "group": "Change management", "label": "Step verification",
     "hint": "Judges whether an executed change step succeeded from its output",
     "default_label": "Claude Haiku 4.5", "default_model": "claude-haiku-4-5-20251001"},
    {"key": "cmd_review", "group": "Command review", "label": "Ad-hoc command risk review",
     "hint": "Assesses risk/impact of an operator-typed command before it runs",
     "default_label": "Claude Haiku 4.5", "default_model": "claude-haiku-4-5-20251001"},
    {"key": "investigation", "group": "Core", "label": "Investigation engine",
     "hint": "The autonomous agent that connects to servers and runs the actual "
             "troubleshooting session — reassigning this to an external connector "
             "uses an experimental generic tool-calling loop; subagent delegation "
             "is Claude-only.",
     "default_label": "Claude Sonnet 5", "default_model": "claude-sonnet-5", "agentic": True},
]
FUNCTION_KEYS = {f["key"] for f in FUNCTIONS}
_FUNCTION_BY_KEY = {f["key"]: f for f in FUNCTIONS}


class AIProviderError(RuntimeError):
    """A connector call failed (unreachable, auth error, bad response)."""


# ---------- connector storage (Vault-aware, same shape as integrations.py) ----------

def _read_raw() -> dict:
    """Exactly what's on disk (no Vault resolution) — the only safe base for
    re-writing the file; see integrations._read_raw for why."""
    try:
        if CONFIG_PATH.exists():
            data = yaml.safe_load(CONFIG_PATH.read_text()) or {}
            if isinstance(data, dict) and isinstance(data.get("connectors"), list):
                return data
    except (OSError, yaml.YAMLError):
        pass
    return {"connectors": []}


def _write_yaml(raw: dict) -> None:
    CONFIG_PATH.write_text(yaml.safe_dump(raw, sort_keys=False))
    os.chmod(CONFIG_PATH, 0o600)


def _vault_path(connector_id: str) -> str:
    return f"ai/providers/{connector_id}"


def load_connectors() -> list[dict]:
    """Vault-resolved connector list — the real api_key for Vault-backed ones."""
    raw = _read_raw()
    connectors = [dict(c) for c in raw.get("connectors", [])]
    if vaultclient.enabled():
        for c in connectors:
            if not c.get("secret_in_vault"):
                continue
            try:
                data = vaultclient.read_secret(_vault_path(c["id"]))
                c["api_key"] = (data or {}).get("api_key", "")
            except vaultclient.VaultError as exc:
                c["api_key"] = ""
                c["vault_error"] = str(exc)
    return connectors


def public_connectors() -> list[dict]:
    """Connector list for the browser — every api_key redacted. Always leads
    with the built-in native connector so it's a normal, selectable option."""
    out = [_native_connector()]
    for c in load_connectors():
        c = dict(c)
        c["api_key"] = _REDACTED if (c.get("api_key") or c.get("secret_in_vault")) else ""
        out.append(c)
    return out


def get_connector(connector_id: str) -> dict | None:
    if connector_id == NATIVE_CONNECTOR_ID:
        return _native_connector()
    return next((c for c in load_connectors() if c["id"] == connector_id), None)


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    return slug or "connector"


def save_connector(data: dict) -> dict:
    """Create (no id) or update (id given) a connector. A real api_key value
    is written to Vault instead of the file when Vault is enabled — a Vault
    write failure raises rather than silently falling back to plaintext."""
    if data.get("id") == NATIVE_CONNECTOR_ID:
        raise ValueError("the built-in Claude Code connector can't be edited")
    raw = _read_raw()
    connectors = raw.get("connectors", [])
    cur = next((c for c in connectors if c["id"] == data.get("id")), None)
    if cur is None and data.get("kind") not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")  # required to CREATE a connector
    if "kind" in data and data["kind"] not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")  # if changing it, it must be valid
    cid = data.get("id") or _slugify(data.get("name", ""))
    base_cid, n = cid, 2
    existing_ids = {c["id"] for c in connectors if c["id"] != data.get("id")}
    while cid in existing_ids:
        cid = f"{base_cid}-{n}"
        n += 1
    out = {f: cur.get(f) for f in _CONNECTOR_FIELDS} if cur else \
        {"name": "", "kind": "openai", "base_url": "", "api_key": "",
         "verify_tls": True, "notes": "", "enabled": True, "secret_in_vault": False}
    out["id"] = cid
    for f in ("name", "kind", "base_url", "notes"):
        if f in data:
            out[f] = str(data[f] or "")
    if "verify_tls" in data:
        out["verify_tls"] = bool(data["verify_tls"])
    if "enabled" in data:
        out["enabled"] = bool(data["enabled"])
    sec = data.get("api_key")
    if sec in (None, "", _REDACTED):
        pass  # keep whatever's already stored (file or Vault) unchanged
    elif vaultclient.enabled():
        vaultclient.write_secret(_vault_path(cid), {"api_key": str(sec)})
        out["api_key"] = ""
        out["secret_in_vault"] = True
    else:
        out["api_key"] = str(sec)
        out["secret_in_vault"] = False
    connectors = [c for c in connectors if c["id"] not in (cid, data.get("id"))]
    connectors.append(out)
    raw["connectors"] = connectors
    _write_yaml(raw)
    pub = dict(out)
    pub["api_key"] = _REDACTED if (out.get("api_key") or out.get("secret_in_vault")) else ""
    return pub


def delete_connector(connector_id: str) -> None:
    if connector_id == NATIVE_CONNECTOR_ID:
        raise ValueError("the built-in Claude Code connector can't be deleted")
    raw = _read_raw()
    raw["connectors"] = [c for c in raw.get("connectors", []) if c["id"] != connector_id]
    _write_yaml(raw)
    if vaultclient.enabled():
        try:
            vaultclient.delete_secret(_vault_path(connector_id))
        except vaultclient.VaultError:
            pass
    # unassign any function pointing at the connector being deleted
    raw_fn = _read_raw_functions()
    changed = False
    for key, assignment in list(raw_fn.items()):
        if isinstance(assignment, dict) and assignment.get("connector_id") == connector_id:
            del raw_fn[key]
            changed = True
    if changed:
        _write_functions(raw_fn)


def migrate_to_vault() -> dict:
    """Move every connector's locally-stored API key into Vault."""
    if not vaultclient.enabled():
        return {"ok": False, "error": "Vault is not configured (VAULT_ADDR / VAULT_TOKEN unset)."}
    raw = _read_raw()
    migrated, skipped, errors = [], [], {}
    for c in raw.get("connectors", []):
        if c.get("secret_in_vault"):
            skipped.append(c["id"])
            continue
        if not c.get("api_key"):
            skipped.append(c["id"])
            continue
        try:
            vaultclient.write_secret(_vault_path(c["id"]), {"api_key": c["api_key"]})
            c["api_key"] = ""
            c["secret_in_vault"] = True
            migrated.append(c["id"])
        except vaultclient.VaultError as exc:
            errors[c["id"]] = str(exc)
    _write_yaml(raw)
    return {"ok": True, "migrated": migrated, "skipped": skipped, "errors": errors}


# ---------- function → connector assignment ----------

def _read_raw_functions() -> dict:
    try:
        if FUNCTIONS_PATH.exists():
            data = yaml.safe_load(FUNCTIONS_PATH.read_text()) or {}
            return data if isinstance(data, dict) else {}
    except (OSError, yaml.YAMLError):
        pass
    return {}


def _write_functions(raw: dict) -> None:
    FUNCTIONS_PATH.write_text(yaml.safe_dump(raw, sort_keys=False))


def get_assignment(function_key: str) -> dict | None:
    """The connector+model this function actually runs on right now. If an
    admin hasn't explicitly reassigned it, this resolves to the built-in
    native connector + that function's default_model — never an unlabeled
    "default"; the resolved value is always something Settings → AI Providers
    can show and let the admin change."""
    a = _read_raw_functions().get(function_key)
    if isinstance(a, dict) and a.get("connector_id"):
        return a
    fn = _FUNCTION_BY_KEY.get(function_key)
    default_model = fn.get("default_model") if fn else None
    if default_model:
        return {"connector_id": NATIVE_CONNECTOR_ID, "model": default_model}
    return None


def get_assignments() -> dict:
    return {f["key"]: get_assignment(f["key"]) for f in FUNCTIONS}


def set_assignment(function_key: str, connector_id: str | None, model: str | None) -> None:
    if function_key not in FUNCTION_KEYS:
        raise ValueError("unknown function")
    raw = _read_raw_functions()
    if connector_id:
        raw[function_key] = {"connector_id": connector_id, "model": model or ""}
    else:
        raw.pop(function_key, None)
    _write_functions(raw)


# ---------- provider HTTP calls (stdlib only) ----------

def _ctx_for(connector: dict, url: str):
    if url.startswith("https://") and not connector.get("verify_tls", True):
        return ssl._create_unverified_context()
    return None


def http_json(url: str, connector: dict, headers: dict, body: dict | None, timeout_s: int) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if body is not None else "GET")
    for k, v in headers.items():
        req.add_header(k, v)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=_ctx_for(connector, url)) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode(errors="replace")[:200]
        except Exception:  # noqa: BLE001
            pass
        raise AIProviderError(f"{connector.get('name', connector.get('id'))}: "
                              f"HTTP {exc.code} — {detail or exc.reason}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise AIProviderError(f"{connector.get('name', connector.get('id'))}: unreachable — {exc}") from exc


def _openai_chat(connector: dict, model: str, prompt: str, timeout_s: int) -> str:
    url = connector["base_url"].rstrip("/") + "/chat/completions"
    headers = {}
    if connector.get("api_key"):
        headers["Authorization"] = f"Bearer {connector['api_key']}"
    body = {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0}
    data = http_json(url, connector, headers, body, timeout_s)
    choices = data.get("choices") or []
    if not choices:
        raise AIProviderError(f"{connector['name']}: no choices in response")
    return (choices[0].get("message") or {}).get("content", "") or ""


def _anthropic_message(connector: dict, model: str, prompt: str, timeout_s: int) -> str:
    base = connector.get("base_url") or "https://api.anthropic.com"
    url = base.rstrip("/") + "/v1/messages"
    headers = {"anthropic-version": "2023-06-01"}
    if connector.get("api_key"):
        headers["x-api-key"] = connector["api_key"]
    body = {"model": model, "max_tokens": 4096, "messages": [{"role": "user", "content": prompt}]}
    data = http_json(url, connector, headers, body, timeout_s)
    parts = data.get("content") or []
    return "".join(p.get("text", "") for p in parts if p.get("type") == "text")


def _list_models_raw(connector: dict, timeout_s: int = 15) -> list[dict]:
    headers = {}
    if connector["kind"] == "openai":
        url = connector["base_url"].rstrip("/") + "/models"
        if connector.get("api_key"):
            headers["Authorization"] = f"Bearer {connector['api_key']}"
    elif connector["kind"] == "anthropic":
        base = connector.get("base_url") or "https://api.anthropic.com"
        url = base.rstrip("/") + "/v1/models"
        headers["anthropic-version"] = "2023-06-01"
        if connector.get("api_key"):
            headers["x-api-key"] = connector["api_key"]
    else:
        raise AIProviderError(f"unknown connector kind '{connector['kind']}'")
    data = http_json(url, connector, headers, None, timeout_s)
    return [{"id": m.get("id")} for m in (data.get("data") or []) if m.get("id")]


def list_models(connector_id: str) -> list[dict]:
    if connector_id == NATIVE_CONNECTOR_ID:
        return NATIVE_MODELS
    connector = get_connector(connector_id)
    if not connector:
        raise AIProviderError("unknown connector")
    return _list_models_raw(connector)


def test_connector(connector_id: str) -> dict:
    """Lightweight connectivity check — reuses the model-list call."""
    if connector_id == NATIVE_CONNECTOR_ID:
        return {"ok": True, "detail": "Built-in — uses this server's own Claude Code CLI login."}
    try:
        models = list_models(connector_id)
        return {"ok": True, "detail": f"Reachable — {len(models)} model(s) available."}
    except AIProviderError as exc:
        return {"ok": False, "detail": str(exc)}


# ---------- the unifying one-shot completion entrypoint ----------

async def complete_json(function_key: str, prompt: str, *, timeout_s: int = 90,
                        default_fn=None) -> tuple[dict | None, str | None, dict]:
    """Route a one-shot prompt->JSON call through whatever connector/model is
    assigned to `function_key` (see get_assignment — this always resolves to
    something, defaulting to the built-in native connector). The native
    connector runs through `default_fn(model)` (today's Claude Agent SDK call,
    unchanged, now told which model to pin). `default_fn` is an async callable
    taking the resolved model string (or None) and returning the SAME
    (data, error, usage) contract.

    An assigned-but-broken EXTERNAL connector is a visible error, never a
    silent fallback — the same fail-safe rule as Vault-backed secrets: a
    misconfiguration should surface, not be masked."""
    assignment = get_assignment(function_key)
    connector_id = assignment.get("connector_id") if assignment else None
    model = (assignment.get("model") or "") if assignment else ""
    if not connector_id or connector_id == NATIVE_CONNECTOR_ID:
        if default_fn is None:
            raise ValueError(f"no built-in implementation for function '{function_key}'")
        return await default_fn(model or None)
    connector = get_connector(connector_id)
    if not connector:
        return None, (f"Assigned AI connector '{assignment['connector_id']}' no longer exists — "
                      "reassign this function in Settings → AI Providers."), {}
    if not connector.get("enabled"):
        return None, (f"Assigned AI connector '{connector['name']}' is disabled — "
                      "enable it or reassign this function."), {}
    model = assignment.get("model") or ""
    usage = {"connector": connector["id"], "connector_name": connector["name"], "model": model}
    try:
        if connector["kind"] == "openai":
            text = await asyncio.to_thread(_openai_chat, connector, model, prompt, timeout_s)
        elif connector["kind"] == "anthropic":
            text = await asyncio.to_thread(_anthropic_message, connector, model, prompt, timeout_s)
        else:
            return None, f"Unknown connector kind '{connector['kind']}'", usage
    except AIProviderError as exc:
        return None, str(exc), usage
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None, "AI response was not JSON: " + " ".join(text.split())[:180], usage
    try:
        return json.loads(m.group()), None, usage
    except json.JSONDecodeError as exc:
        return None, f"AI response JSON was invalid ({exc})", usage
