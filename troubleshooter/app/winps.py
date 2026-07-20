"""CLI shim so the investigation agent can run PowerShell on a Windows host.

The autonomous agent only has a Bash tool, and Windows hosts are reached over
WinRM (not SSH). This module lets the agent run a read-only PowerShell command
on an inventory Windows server from its Bash tool:

    python3 -m app.winps <server-name> '<powershell command>'

stdout/stderr from the host are printed; the process exits with the host's
PowerShell exit code (non-zero on failure). Intended for read-only diagnostics
during investigation — the same command-review gate still guards any
operator-driven execution elsewhere.
"""

import asyncio
import sys

from .inventory import load_inventory
from . import winexec


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: python3 -m app.winps <server-name> '<powershell>'", file=sys.stderr)
        return 2
    name, script = argv[1], argv[2]
    server = load_inventory().get(name)
    if server is None:
        print(f"server '{name}' not in inventory", file=sys.stderr)
        return 3
    if not server.is_windows:
        print(f"server '{name}' is not a Windows host (use ssh for Linux)", file=sys.stderr)
        return 4
    result = asyncio.run(winexec.run_ps(server, script))
    sys.stdout.write(result.get("output", ""))
    if not result.get("output", "").endswith("\n"):
        sys.stdout.write("\n")
    code = result.get("exit_code")
    return int(code) if isinstance(code, int) and code >= 0 else (0 if result.get("ok") else 1)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
