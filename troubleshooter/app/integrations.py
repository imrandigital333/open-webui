"""Observability / infrastructure layer integrations.

Connection settings for the platforms we plan to read logs & inventory from for
a holistic view — VMware vCenter, Commvault, SolarWinds and Zabbix. This module
stores the configuration (a chmod-600, gitignored integrations.yaml with the
secret write-only); the actual log/inventory collectors are added later and will
read from here. Enable a layer once its collector is wired up.
"""

from __future__ import annotations

import os

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
