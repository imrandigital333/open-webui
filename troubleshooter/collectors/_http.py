"""Tiny stdlib HTTP helper shared by the collectors (no external deps)."""

import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


def expand_env(value: str) -> str:
    """Expand ${VAR} from the environment; fail loudly if a var is missing."""

    def repl(match: re.Match) -> str:
        var = match.group(1)
        val = os.environ.get(var)
        if val is None:
            print(f"error: environment variable {var} is not set", file=sys.stderr)
            raise SystemExit(2)
        return val

    return re.sub(r"\$\{(\w+)\}", repl, value)


def request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    body: dict | list | None = None,
    verify_tls: bool = True,
    timeout: int = 30,
) -> tuple[int, object]:
    if params:
        sep = "&" if "?" in url else "?"
        url = url + sep + urllib.parse.urlencode(params)
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    hdrs.setdefault("Accept", "application/json")
    ctx = None
    if url.startswith("https"):
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode(errors="replace")
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        status = e.code
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(f"error: request to {url} failed: {e}", file=sys.stderr)
        raise SystemExit(1)
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, raw


def emit(obj: object) -> None:
    if isinstance(obj, str):
        print(obj)
    else:
        print(json.dumps(obj, indent=2, default=str))
