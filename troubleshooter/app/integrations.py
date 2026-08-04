"""Observability / infrastructure layer integrations.

Connection settings for the platforms we plan to read logs & inventory from for
a holistic view — VMware vCenter, Commvault, SolarWinds and Zabbix. This module
stores the configuration (a chmod-600, gitignored integrations.yaml with the
secret write-only); the actual log/inventory collectors are added later and will
read from here. Enable a layer once its collector is wired up.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from urllib.parse import urlparse

import yaml

from .inventory import BASE_DIR

CONFIG_PATH = BASE_DIR / "integrations.yaml"
_REDACTED = "__stored__"

# the layers surfaced in Settings → Integrations
LAYERS = [
    {"key": "vmware", "label": "VMware vCenter", "icon": "🖥️",
     "hint": "ESXi hosts / VMs — inventory & logs", "host_label": "vCenter host / URL"},
    {"key": "commvault", "label": "Commvault", "icon": "💾",
     "hint": "Backup jobs, clients & logs", "host_label": "CommServe host / URL"},
    {"key": "solarwinds", "label": "SolarWinds", "icon": "📈",
     "hint": "Network & performance monitoring", "host_label": "Orion server / URL"},
    {"key": "zabbix", "label": "Zabbix", "icon": "📟",
     "hint": "Monitoring, metrics & alerts", "host_label": "Zabbix API URL"},
]
LAYER_KEYS = {l["key"] for l in LAYERS}

_FIELDS = ("enabled", "host", "user", "secret", "verify_tls", "notes")


def _defaults() -> dict:
    return {l["key"]: {"enabled": False, "host": "", "user": "", "secret": "",
                       "verify_tls": True, "notes": ""} for l in LAYERS}


def load_config() -> dict:
    cfg = _defaults()
    try:
        if CONFIG_PATH.exists():
            data = yaml.safe_load(CONFIG_PATH.read_text()) or {}
            for key in LAYER_KEYS:
                lc = data.get(key) or {}
                if isinstance(lc, dict):
                    for f in _FIELDS:
                        if f in lc and lc[f] not in (None,):
                            cfg[key][f] = lc[f]
    except (OSError, yaml.YAMLError):
        pass
    return cfg


def public_config() -> dict:
    """Config for the browser — every layer's secret is redacted."""
    cfg = load_config()
    for key in cfg:
        cfg[key] = dict(cfg[key])
        cfg[key]["secret"] = _REDACTED if cfg[key].get("secret") else ""
    return cfg


def save_layer(key: str, new: dict) -> dict:
    """Persist one layer's settings, keeping the stored secret when the browser
    sends the redaction sentinel (or nothing)."""
    if key not in LAYER_KEYS:
        raise ValueError("unknown integration")
    cfg = load_config()
    cur = cfg.get(key, {})
    out = dict(cur)
    for f in ("host", "user", "notes"):
        if f in new:
            out[f] = str(new[f] or "")
    if "enabled" in new:
        out["enabled"] = bool(new["enabled"])
    if "verify_tls" in new:
        out["verify_tls"] = bool(new["verify_tls"])
    sec = new.get("secret")
    if sec in (None, "", _REDACTED):
        out["secret"] = cur.get("secret", "")
    else:
        out["secret"] = str(sec)
    cfg[key] = out
    CONFIG_PATH.write_text(yaml.safe_dump(cfg, sort_keys=False))
    os.chmod(CONFIG_PATH, 0o600)
    pub = dict(out); pub["secret"] = _REDACTED if out.get("secret") else ""
    return pub


# ---------------------------------------------------------------------------
# Layer discovery. Each layer gets the same two-mode contract as a server:
#   * basic    — a live reachability probe of the configured endpoint
#   * detailed — the full inventory / topology pull (fed to the knowledge bot)
# The vendor collectors (VMware/Commvault/SolarWinds/Zabbix API clients) are
# wired in a later pass; until then a detailed scan registers the layer in the
# knowledge base (what it is, its role, its endpoint, reachability) so the bot
# is aware of it, and clearly reports the collector as pending.
# ---------------------------------------------------------------------------

_DEFAULT_PORT = {"vmware": 443, "commvault": 443, "solarwinds": 443, "zabbix": 443}

# what a detailed scan will gather once each collector is wired
_LAYER_SCOPE = {
    "vmware": ["ESXi hosts & clusters", "VM inventory (vCPU/RAM/disk)",
               "datastores & networks", "vCenter events / alarms"],
    "commvault": ["Backup clients & subclients", "storage policies",
                  "recent job status (success/failed)", "SLA & job logs"],
    "solarwinds": ["Monitored nodes & interfaces", "up/down status",
                   "performance metrics", "active alerts"],
    "zabbix": ["Monitored hosts & templates", "items & triggers",
               "current problems / alerts", "event history"],
}
_LAYER_BY_KEY = {l["key"]: l for l in LAYERS}


def _host_port(raw: str, default_port: int) -> tuple[str, int]:
    """Extract (host, port) from a plain host, host:port, or URL."""
    raw = (raw or "").strip()
    if not raw:
        return "", default_port
    if "://" in raw:
        u = urlparse(raw)
        return (u.hostname or ""), (u.port or (443 if u.scheme == "https" else 80))
    m = re.match(r"^\[?([^\]/:]+)\]?(?::(\d+))?", raw)
    if m:
        return m.group(1), int(m.group(2)) if m.group(2) else default_port
    return raw, default_port


async def _tcp_reachable(host: str, port: int, timeout: float = 5.0) -> tuple[bool, str]:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, f"TCP {host}:{port} reachable"
    except asyncio.TimeoutError:
        return False, f"TCP {host}:{port} timed out after {timeout:g}s"
    except (OSError, ValueError) as exc:
        return False, f"TCP {host}:{port} unreachable: {exc}"


def _layer_report(layer: dict, cfg: dict, reachable: bool, detail: str,
                  host: str, port: int) -> str:
    scope = _LAYER_SCOPE.get(layer["key"], [])
    L = [f"# Infrastructure layer — {layer['label']}", "",
         f"- **Type:** {layer['hint']}",
         f"- **Endpoint:** {host}:{port}" + (f"  (configured: {cfg.get('host')})" if cfg.get("host") else ""),
         f"- **Reachability:** {'✅ reachable' if reachable else '⚠️ ' + detail}",
         f"- **Enabled:** {'yes' if cfg.get('enabled') else 'no'}",
         "- **Collector status:** pending — connection registered; log/inventory "
         "collection goes live once the vendor collector is wired.", ""]
    if scope:
        L.append("## Data this layer will contribute")
        L += [f"- {s}" for s in scope]
    if cfg.get("notes"):
        L += ["", f"**Notes:** {cfg['notes']}"]
    return "\n".join(L).strip()


async def discover_layer(key: str, mode: str = "basic") -> dict:
    """Probe an infrastructure layer. `basic` = reachability only; `detailed`
    additionally returns a markdown registration report for the knowledge base."""
    layer = _LAYER_BY_KEY.get(key)
    if layer is None:
        return {"ok": False, "error": "unknown integration"}
    cfg = load_config().get(key, {})
    host_raw = cfg.get("host", "")
    if not host_raw:
        return {"ok": False, "key": key, "mode": mode,
                "error": f"No endpoint configured for {layer['label']}. "
                         "Set the host and Save first."}
    host, port = _host_port(host_raw, _DEFAULT_PORT.get(key, 443))
    reachable, detail = await _tcp_reachable(host, port)
    result = {"ok": True, "key": key, "label": layer["label"], "mode": mode,
              "enabled": bool(cfg.get("enabled")), "host": host, "port": port,
              "reachable": reachable, "detail": detail, "collector_pending": True,
              "scope": _LAYER_SCOPE.get(key, []), "ts": time.time()}
    if mode == "detailed":
        result["report"] = _layer_report(layer, cfg, reachable, detail, host, port)
    return result
