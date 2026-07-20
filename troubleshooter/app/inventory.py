"""Server inventory loading for the AI Troubleshooter."""

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent


@dataclass
class Server:
    name: str
    host: str
    user: str
    port: int = 22
    ssh_key: str | None = None
    description: str = ""
    os: str = ""
    # linux (SSH/bash) or windows (WinRM/PowerShell). Defaults to linux for
    # backward compatibility with existing inventories.
    platform: str = "linux"
    tags: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    log_hints: list[str] = field(default_factory=list)
    # Windows / WinRM connection details (used only when platform == windows).
    # The account is `user`; the password is a secret kept server-side.
    winrm_password: str = ""
    winrm_transport: str = "ntlm"      # ntlm | kerberos | basic | credssp | ssl
    winrm_port: int = 5985             # 5985 http, 5986 https by convention
    winrm_scheme: str = "http"         # http | https
    winrm_cert_validation: str = "ignore"   # ignore | validate

    @property
    def is_windows(self) -> bool:
        return (self.platform or "").strip().lower() == "windows" \
            or "windows" in (self.os or "").lower()

    def ssh_command(self) -> str:
        """The base ssh command the agent should use to reach this server."""
        parts = [
            "ssh",
            "-o BatchMode=yes",
            "-o ConnectTimeout=10",
            "-o StrictHostKeyChecking=accept-new",
        ]
        if self.ssh_key:
            parts.append(f"-i {self.ssh_key}")
        if self.port != 22:
            parts.append(f"-p {self.port}")
        parts.append(f"{self.user}@{self.host}")
        return " ".join(parts)

    def winrm_endpoint(self) -> str:
        return f"{self.winrm_scheme}://{self.host}:{self.winrm_port}/wsman"

    def to_public_dict(self) -> dict:
        """Representation safe to send to the UI (no key paths, no secrets)."""
        return {
            "name": self.name,
            "host": self.host,
            "description": self.description,
            "os": self.os,
            "platform": "windows" if self.is_windows else "linux",
            "tags": self.tags,
            "services": self.services,
        }


def inventory_path() -> Path:
    env = os.environ.get("TROUBLESHOOTER_INVENTORY")
    if env:
        return Path(env)
    candidate = BASE_DIR / "inventory.yaml"
    if candidate.exists():
        return candidate
    return BASE_DIR / "inventory.example.yaml"


def writable_inventory_path() -> Path:
    """Where UI edits are written. Never the bundled example file."""
    env = os.environ.get("TROUBLESHOOTER_INVENTORY")
    return Path(env) if env else BASE_DIR / "inventory.yaml"


def load_raw_inventory() -> list[dict]:
    """The inventory as plain dicts (full detail, for the admin/settings UI)."""
    path = inventory_path()
    if not path.exists():
        return []
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    return list(data.get("servers", []))


def save_inventory(servers: list[dict]) -> None:
    """Atomically write the inventory. NOTE: YAML comments are not preserved."""
    path = writable_inventory_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".yaml.tmp")
    with open(tmp, "w") as f:
        f.write("# Managed by the AI Troubleshooter settings UI.\n")
        yaml.safe_dump({"servers": servers}, f, sort_keys=False, allow_unicode=True)
    tmp.replace(path)


def load_inventory() -> dict[str, Server]:
    path = inventory_path()
    if not path.exists():
        return {}
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    servers: dict[str, Server] = {}
    for entry in data.get("servers", []):
        server = Server(
            name=entry["name"],
            host=entry["host"],
            user=entry["user"],
            port=int(entry.get("port", 22)),
            ssh_key=entry.get("ssh_key"),
            description=entry.get("description", ""),
            os=entry.get("os", ""),
            platform=str(entry.get("platform", "linux") or "linux"),
            tags=list(entry.get("tags", [])),
            services=list(entry.get("services", [])),
            log_hints=list(entry.get("log_hints", [])),
            winrm_password=str(entry.get("winrm_password", "") or ""),
            winrm_transport=str(entry.get("winrm_transport", "ntlm") or "ntlm"),
            winrm_port=int(entry.get("winrm_port", 5985)),
            winrm_scheme=str(entry.get("winrm_scheme", "http") or "http"),
            winrm_cert_validation=str(entry.get("winrm_cert_validation", "ignore") or "ignore"),
        )
        servers[server.name] = server
    return servers
