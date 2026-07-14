"""Zabbix JSON-RPC collector (Zabbix 6.0+, API-token auth)."""

import os
import re
import sys
import time

from ._http import emit, request


def _since_to_epoch(since: str) -> int:
    """'2h', '45m', '3d' or an epoch/ISO string -> epoch seconds."""
    m = re.fullmatch(r"(\d+)([mhd])", since.strip())
    if m:
        n, unit = int(m.group(1)), m.group(2)
        secs = n * {"m": 60, "h": 3600, "d": 86400}[unit]
        return int(time.time()) - secs
    if since.isdigit():
        return int(since)
    from datetime import datetime

    return int(datetime.fromisoformat(since).timestamp())


def _call(ds: dict, method: str, params: dict) -> object:
    token_env = ds.get("token_env", "ZABBIX_API_TOKEN")
    token = os.environ.get(token_env)
    if not token:
        print(f"error: environment variable {token_env} is not set", file=sys.stderr)
        raise SystemExit(2)
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    headers = {"Authorization": f"Bearer {token}"}
    if ds.get("auth_style") == "param":  # legacy Zabbix < 6.4
        payload["auth"] = token
        headers = {}
    status, data = request(
        "POST", ds["url"], headers=headers, body=payload,
        verify_tls=ds.get("verify_tls", True),
    )
    if isinstance(data, dict) and data.get("error"):
        print(f"error: zabbix API error: {data['error']}", file=sys.stderr)
        raise SystemExit(1)
    if status >= 400:
        print(f"error: HTTP {status}: {data}", file=sys.stderr)
        raise SystemExit(1)
    return data.get("result") if isinstance(data, dict) else data


def add_parser(sub):
    p = sub.add_parser("zabbix-cmds", help="internal")
    return p


def run(ds: dict, argv: list[str]) -> None:
    import argparse

    parser = argparse.ArgumentParser(prog=f"collectors {ds['name']}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("problems", help="active problems (optionally for one host)")
    p.add_argument("--host")
    p.add_argument("--since", default="24h")
    p.add_argument("--limit", type=int, default=100)

    p = sub.add_parser("events", help="events history")
    p.add_argument("--host")
    p.add_argument("--since", default="24h")
    p.add_argument("--limit", type=int, default=200)

    p = sub.add_parser("hosts", help="look up hosts by name substring")
    p.add_argument("--search", required=True)

    p = sub.add_parser("items", help="items (metrics) on a host")
    p.add_argument("--host", required=True)
    p.add_argument("--search", default="")

    p = sub.add_parser("history", help="metric history for an item id")
    p.add_argument("--itemid", required=True)
    p.add_argument("--since", default="4h")
    p.add_argument("--value-type", type=int, default=0, help="0=float 3=uint")
    p.add_argument("--limit", type=int, default=500)

    p = sub.add_parser("raw", help="arbitrary API method")
    p.add_argument("--method", required=True)
    p.add_argument("--params-json", default="{}")

    args = parser.parse_args(argv)

    def host_ids(name: str) -> list[str]:
        hosts = _call(ds, "host.get", {"search": {"host": name}, "output": ["hostid"]})
        return [h["hostid"] for h in hosts]

    if args.cmd == "problems":
        params: dict = {
            "output": "extend", "sortfield": ["eventid"], "sortorder": "DESC",
            "time_from": _since_to_epoch(args.since), "limit": args.limit,
            "selectTags": "extend",
        }
        if args.host:
            params["hostids"] = host_ids(args.host)
        emit(_call(ds, "problem.get", params))
    elif args.cmd == "events":
        params = {
            "output": "extend", "sortfield": ["clock"], "sortorder": "DESC",
            "time_from": _since_to_epoch(args.since), "limit": args.limit,
        }
        if args.host:
            params["hostids"] = host_ids(args.host)
        emit(_call(ds, "event.get", params))
    elif args.cmd == "hosts":
        emit(_call(ds, "host.get", {
            "search": {"host": args.search},
            "output": ["hostid", "host", "name", "status"],
            "selectInterfaces": ["ip"],
        }))
    elif args.cmd == "items":
        params = {
            "output": ["itemid", "name", "key_", "lastvalue", "units", "value_type"],
            "hostids": host_ids(args.host),
        }
        if args.search:
            params["search"] = {"key_": args.search}
        emit(_call(ds, "item.get", params))
    elif args.cmd == "history":
        emit(_call(ds, "history.get", {
            "itemids": [args.itemid], "history": args.value_type,
            "time_from": _since_to_epoch(args.since),
            "sortfield": "clock", "sortorder": "DESC", "limit": args.limit,
        }))
    elif args.cmd == "raw":
        import json

        emit(_call(ds, args.method, json.loads(args.params_json)))
