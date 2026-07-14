"""Collector CLI the troubleshooting agent uses to query evidence layers.

Usage (from a session working directory, which contains datasources.json):

    python3 -m collectors list
    python3 -m collectors <datasource-name> <command> [args...]

Examples:
    python3 -m collectors zabbix problems --host web-01 --since 6h
    python3 -m collectors vcenter get /api/vcenter/vm --param names=web-01
    python3 -m collectors summit-ai get /api/v1/changes --param days=2

Secrets are read from environment variables named in the config — they are
never stored in datasources.json and never printed.
"""

import argparse
import json
import sys
from pathlib import Path

from ._http import emit


def load_config(path: str) -> dict[str, dict]:
    p = Path(path)
    if not p.exists():
        print(f"error: config {path} not found (run from the session directory)", file=sys.stderr)
        raise SystemExit(2)
    data = json.loads(p.read_text())
    return {ds["name"]: ds for ds in data.get("datasources", [])}


def main() -> None:
    parser = argparse.ArgumentParser(prog="collectors", add_help=True)
    parser.add_argument("--config", default="./datasources.json")
    parser.add_argument("target", help="'list' or a datasource name")
    parser.add_argument("rest", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    sources = load_config(args.config)

    if args.target == "list":
        emit([
            {
                "name": ds["name"], "type": ds["type"], "layer": ds.get("layer"),
                "description": ds.get("description", ""),
                "hints": ds.get("agent_hints", []),
            }
            for ds in sources.values()
        ])
        return

    ds = sources.get(args.target)
    if ds is None:
        print(
            f"error: unknown datasource '{args.target}'. Available: {', '.join(sources) or '(none)'}",
            file=sys.stderr,
        )
        raise SystemExit(2)

    ds_type = ds.get("type")
    if ds_type == "zabbix":
        from . import zabbix

        zabbix.run(ds, args.rest)
    elif ds_type == "vmware":
        from . import vmware

        vmware.run(ds, args.rest)
    elif ds_type == "rest":
        from . import rest

        rest.run(ds, args.rest)
    elif ds_type == "ssh":
        print(
            f"error: '{args.target}' is an SSH source — use its wrapper script instead: "
            f"./remote-{ds['name']} '<command>'",
            file=sys.stderr,
        )
        raise SystemExit(2)
    else:
        print(f"error: unsupported datasource type '{ds_type}'", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
