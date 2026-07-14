"""VMware vCenter Automation REST API collector (session auth)."""

import base64
import json
import os
import sys

from ._http import emit, request


def _login(ds: dict) -> str:
    user_env = ds.get("username_env", "VCENTER_USERNAME")
    pass_env = ds.get("password_env", "VCENTER_PASSWORD")
    user, password = os.environ.get(user_env), os.environ.get(pass_env)
    if not user or not password:
        print(f"error: {user_env} / {pass_env} not set", file=sys.stderr)
        raise SystemExit(2)
    basic = base64.b64encode(f"{user}:{password}".encode()).decode()
    status, data = request(
        "POST", ds["url"].rstrip("/") + "/api/session",
        headers={"Authorization": f"Basic {basic}"},
        verify_tls=ds.get("verify_tls", True),
    )
    if status >= 400:
        print(f"error: vCenter login failed (HTTP {status}): {data}", file=sys.stderr)
        raise SystemExit(1)
    return data if isinstance(data, str) else str(data)


def run(ds: dict, argv: list[str]) -> None:
    import argparse

    parser = argparse.ArgumentParser(prog=f"collectors {ds['name']}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("get", help="authenticated GET, e.g. get /api/vcenter/vm")
    p.add_argument("path")
    p.add_argument("--param", action="append", default=[], help="k=v query param")

    p = sub.add_parser("post", help="authenticated POST with JSON body")
    p.add_argument("path")
    p.add_argument("--data", default="{}")

    args = parser.parse_args(argv)
    token = _login(ds)
    headers = {"vmware-api-session-id": token.strip('"')}
    url = ds["url"].rstrip("/") + "/" + args.path.lstrip("/")
    verify = ds.get("verify_tls", True)

    if args.cmd == "get":
        params = dict(p.split("=", 1) for p in args.param)
        status, data = request("GET", url, headers=headers, params=params, verify_tls=verify)
    else:
        status, data = request("POST", url, headers=headers, body=json.loads(args.data), verify_tls=verify)
    if status >= 400:
        print(f"error: HTTP {status}", file=sys.stderr)
        emit(data)
        raise SystemExit(1)
    emit(data)
