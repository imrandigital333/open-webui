"""Evidence-layer data source configuration (Zabbix, VMware, ITSM/REST, SSH)."""

import os
from pathlib import Path

import yaml

from .inventory import BASE_DIR

VALID_TYPES = {"zabbix", "vmware", "rest", "ssh"}


def datasources_path() -> Path:
    env = os.environ.get("TROUBLESHOOTER_DATASOURCES")
    if env:
        return Path(env)
    candidate = BASE_DIR / "datasources.yaml"
    if candidate.exists():
        return candidate
    return BASE_DIR / "datasources.example.yaml"


def load_datasources() -> dict[str, dict]:
    """Load data sources keyed by name. Secrets stay as env-var *names*."""
    path = datasources_path()
    if not path.exists():
        return {}
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    out: dict[str, dict] = {}
    for entry in data.get("datasources", []):
        name = entry.get("name")
        ds_type = entry.get("type")
        if not name or ds_type not in VALID_TYPES:
            continue
        out[name] = entry
    return out


def to_public_dict(ds: dict) -> dict:
    """Representation safe for the UI — no hosts/urls/credential refs."""
    return {
        "name": ds["name"],
        "type": ds["type"],
        "layer": ds.get("layer", "other"),
        "description": ds.get("description", ""),
    }


def missing_env_vars(ds: dict) -> list[str]:
    """Env vars this source needs that are not currently set (for UI health)."""
    needed: list[str] = []
    for key in ("token_env", "username_env", "password_env"):
        var = ds.get(key)
        if var:
            needed.append(var)
    auth_value = ds.get("auth_value", "")
    if "${" in auth_value:
        import re

        needed += re.findall(r"\$\{(\w+)\}", auth_value)
    return [v for v in needed if not os.environ.get(v)]
