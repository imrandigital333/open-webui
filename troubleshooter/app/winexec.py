"""Windows remote execution over WinRM (PowerShell Remoting).

Windows inventory hosts (platform: windows) are reached with WinRM instead of
SSH. A single PowerShell script is submitted per call; stdout+stderr and the
PowerShell exit code come back in the same shape the SSH path returns, so the
rest of the app (run-cmd, run-step, discovery, the change implementer) treats
Windows and Linux targets uniformly.

pywinrm is an OPTIONAL dependency. If it is not installed — or the host is
unreachable — the call returns a normal error result with a clear message
rather than raising, so a Linux-only deployment never has to install it and a
misconfigured Windows host never takes down the request.
"""

import asyncio

from .inventory import Server

try:
    import winrm  # pywinrm
    WINRM_AVAILABLE = True
    _IMPORT_ERROR = ""
except Exception as exc:  # noqa: BLE001 - any import failure degrades gracefully
    winrm = None
    WINRM_AVAILABLE = False
    _IMPORT_ERROR = str(exc)

# pywinrm read/operation timeouts. operation must be <= read.
_OPERATION_TIMEOUT = 55
_READ_TIMEOUT = 60


def _session(server: Server):
    cert = "validate" if str(server.winrm_cert_validation).lower() == "validate" else "ignore"
    return winrm.Session(
        server.winrm_endpoint(),
        auth=(server.user, server.winrm_password or ""),
        transport=(server.winrm_transport or "ntlm"),
        server_cert_validation=cert,
        operation_timeout_sec=_OPERATION_TIMEOUT,
        read_timeout_sec=_READ_TIMEOUT,
    )


def _run_ps_sync(server: Server, script: str) -> dict:
    session = _session(server)
    result = session.run_ps(script)
    out = result.std_out or b""
    err = result.std_err or b""
    text = out.decode(errors="replace")
    if err:
        etext = err.decode(errors="replace").strip()
        # pywinrm returns PowerShell error records as CLIXML on std_err; keep it
        # readable but don't try to fully parse it.
        if etext:
            text = (text + "\n" + etext).strip() if text.strip() else etext
    return {
        "ok": result.status_code == 0,
        "exit_code": result.status_code,
        "output": text[-8000:],
    }


async def run_ps(server: Server, script: str, timeout: int = 90) -> dict:
    """Run one PowerShell script on a Windows host over WinRM.

    Returns {ok, exit_code, output} — the same shape as the SSH executor.
    Never raises: import/connection/timeout failures come back as ok=False.
    """
    if not WINRM_AVAILABLE:
        hint = f" ({_IMPORT_ERROR})" if _IMPORT_ERROR else ""
        return {"ok": False, "exit_code": -1,
                "output": "WinRM support is not installed on the troubleshooter "
                          f"host — run: pip install pywinrm{hint}"}
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_run_ps_sync, server, script), timeout=timeout)
    except asyncio.TimeoutError:
        return {"ok": False, "exit_code": -1,
                "output": f"WinRM command timed out after {timeout}s"}
    except Exception as exc:  # noqa: BLE001 - surface connection errors as output
        return {"ok": False, "exit_code": -1,
                "output": f"WinRM connection error to {server.host}: {exc}"}
