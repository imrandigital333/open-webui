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
    tags: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    log_hints: list[str] = field(default_factory=list)

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

    def to_public_dict(self) -> dict:
        """Representation safe to send to the UI (no key paths)."""
        return {
            "name": self.name,
            "host": self.host,
            "description": self.description,
            "os": self.os,
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
            tags=list(entry.get("tags", [])),
            services=list(entry.get("services", [])),
            log_hints=list(entry.get("log_hints", [])),
        )
        servers[server.name] = server
    return servers
