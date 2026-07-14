"""Generic authenticated REST collector (ITSM tools like SummitAI, ELK, custom APIs)."""

import json

from ._http import emit, expand_env, request


def _headers(ds: dict) -> dict[str, str]:
    headers: dict[str, str] = {}
    if ds.get("auth_header") and ds.get("auth_value"):
        headers[ds["auth_header"]] = expand_env(ds["auth_value"])
    for key, value in (ds.get("extra_headers") or {}).items():
        headers[key] = expand_env(str(value))
    return headers


def run(ds: dict, argv: list[str]) -> None:
    import argparse

    parser = argparse.ArgumentParser(prog=f"collectors {ds['name']}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("get", help="authenticated GET, e.g. get /api/v1/changes")
    p.add_argument("path")
    p.add_argument("--param", action="append", default=[], help="k=v query param")

    p = sub.add_parser("post", help="authenticated POST with JSON body")
    p.add_argument("path")
    p.add_argument("--data", default="{}")

    args = parser.parse_args(argv)
    url = ds["url"].rstrip("/") + "/" + args.path.lstrip("/")
    verify = ds.get("verify_tls", True)

    if args.cmd == "get":
        params = dict(p.split("=", 1) for p in args.param)
        status, data = request("GET", url, headers=_headers(ds), params=params, verify_tls=verify)
    else:
        status, data = request(
            "POST", url, headers=_headers(ds), body=json.loads(args.data), verify_tls=verify
        )
    if status >= 400:
        print(f"error: HTTP {status}", flush=True)
        emit(data)
        raise SystemExit(1)
    emit(data)
