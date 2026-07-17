"""Agentless live health probe over SSH — powers the always-live health strip.

Runs the same six collection groups as an agent health check, but collects and
scores everything deterministically in Python: no agent, no tokens, seconds
instead of minutes. Used whenever the open session doesn't produce its own
health data (investigations, historical report views) so the strip shows the
server's health NOW instead of the last health check's results.
"""

import asyncio
import re
import time

from .inventory import Server

# state per server: {"running", "complete", "ts", "checks": {...}}
PROBES: dict[str, dict] = {}

FRESH_SECONDS = 45          # a completed probe younger than this is reused
GROUP_TIMEOUT = 45          # per-group SSH timeout

_SKIP_FS = ("tmpfs", "devtmpfs", "overlay", "squashfs", "efivarfs")


def state(name: str) -> dict:
    st = PROBES.get(name) or {}
    return {"running": bool(st.get("running")), "complete": bool(st.get("complete")),
            "ts": st.get("ts", 0), "checks": st.get("checks") or {}}


async def _ssh(server: Server, cmd: str) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        *server.ssh_command().split(), cmd,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=GROUP_TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        return -1, "timeout"
    return proc.returncode or 0, out.decode(errors="replace")


def _sections(text: str) -> dict:
    """Split '@@name\\n...' delimited output into {name: body}."""
    out: dict[str, str] = {}
    cur = None
    for line in text.splitlines():
        if line.startswith("@@"):
            cur = line[2:].strip()
            out[cur] = ""
        elif cur is not None:
            out[cur] += line + "\n"
    return out


def _c(status: str, value: str, note: str = "") -> dict:
    return {"status": status, "value": value, "note": note}


def _pct(p: float, warn: float = 80, crit: float = 90) -> str:
    return "critical" if p >= crit else "warning" if p >= warn else "ok"


def _num(text: str) -> int:
    m = re.search(r"\d+", text or "")
    return int(m.group()) if m else 0


# ---------- group collectors ----------

async def _g_basics(server: Server) -> dict:
    t0 = time.time()
    rc, out = await _ssh(server, "echo @@up; cat /proc/uptime 2>/dev/null; echo @@ok; echo probe_ok")
    ms = int((time.time() - t0) * 1000)
    if rc != 0 or "probe_ok" not in out:
        return {"connectivity": _c("critical", "unreachable",
                                   (out or "ssh failed").strip()[:160])}
    s = _sections(out)
    checks = {"connectivity": _c("ok", f"ssh ok · {ms} ms")}
    try:
        secs = float(s.get("up", "0").split()[0])
        d, h = int(secs // 86400), int(secs % 86400 // 3600)
        val = f"up {d}d {h}h" if d else f"up {h}h {int(secs % 3600 // 60)}m"
        checks["uptime"] = (_c("warning", val, "rebooted less than an hour ago")
                            if secs < 3600 else _c("ok", val))
    except (ValueError, IndexError):
        checks["uptime"] = _c("ok", "n/a", "could not read /proc/uptime")
    return checks


async def _g_compute(server: Server) -> dict:
    rc, out = await _ssh(server,
        "echo @@nproc; nproc 2>/dev/null; echo @@load; cat /proc/loadavg 2>/dev/null; "
        "echo @@mem; free -m 2>/dev/null; "
        "echo @@cpu; top -b -n1 2>/dev/null | grep -i '%cpu' | head -1")
    s = _sections(out)
    checks = {}
    cores = max(_num(s.get("nproc", "1")), 1)
    # cpu from the top summary line: usage = 100 - idle
    m = re.search(r"([\d.]+)\s*(?:%?\s*)id", s.get("cpu", ""))
    if m:
        usage = max(0.0, 100.0 - float(m.group(1)))
        checks["cpu"] = _c(_pct(usage, 75, 90), f"{usage:.0f}%", f"{cores} cores")
    else:
        checks["cpu"] = _c("ok", "n/a", "top unavailable")
    try:
        load1 = float(s.get("load", "0").split()[0])
        checks["load"] = _c("critical" if load1 > 2 * cores else
                            "warning" if load1 > cores else "ok",
                            f"{load1:g} / {cores} cores")
    except (ValueError, IndexError):
        checks["load"] = _c("ok", "n/a")
    mem = re.search(r"^Mem:\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)",
                    s.get("mem", ""), re.MULTILINE)
    if mem:
        total, avail = int(mem.group(1)), int(mem.group(2))
        used = 100 * (total - avail) / max(total, 1)
        checks["memory"] = _c(_pct(used), f"{used:.0f}%", f"{total - avail}/{total} MB used")
    else:
        checks["memory"] = _c("ok", "n/a", "free unavailable")
    swap = re.search(r"^Swap:\s+(\d+)\s+(\d+)", s.get("mem", ""), re.MULTILINE)
    if swap and int(swap.group(1)) > 0:
        pct = 100 * int(swap.group(2)) / int(swap.group(1))
        checks["swap"] = _c(_pct(pct, 40, 80), f"{pct:.0f}%")
    else:
        checks["swap"] = _c("ok", "0%", "no swap configured")
    return checks


async def _g_storage(server: Server) -> dict:
    rc, out = await _ssh(server,
        "echo @@df; df -hP 2>/dev/null; echo @@di; df -iP 2>/dev/null; "
        "echo @@vm; vmstat 1 2 2>/dev/null")
    s = _sections(out)
    checks = {}

    def worst(body: str) -> tuple[int, str]:
        top, mount = -1, ""
        for line in body.splitlines()[1:]:
            f = line.split()
            if len(f) >= 6 and not any(x in f[0] for x in _SKIP_FS) and f[4].endswith("%"):
                p = _num(f[4])
                if p > top:
                    top, mount = p, f[5]
        return top, mount

    p, mnt = worst(s.get("df", ""))
    checks["storage"] = (_c(_pct(p), f"{p}% {mnt}", "worst filesystem")
                         if p >= 0 else _c("ok", "n/a", "df unavailable"))
    p, mnt = worst(s.get("di", ""))
    checks["inodes"] = (_c(_pct(p), f"{p}% {mnt}", "worst filesystem inode usage")
                        if p >= 0 else _c("ok", "n/a"))
    vm = s.get("vm", "").splitlines()
    try:
        hdr = next(line for line in vm if " wa" in line).split()
        wa = int(vm[-1].split()[hdr.index("wa")])
        checks["disk_io"] = _c(_pct(wa, 20, 40), f"{wa}% iowait")
    except (StopIteration, ValueError, IndexError):
        checks["disk_io"] = _c("ok", "n/a", "vmstat unavailable")
    return checks


async def _g_runtime(server: Server) -> dict:
    rc, out = await _ssh(server,
        "echo @@failed; systemctl list-units --state=failed --no-legend --plain 2>/dev/null; "
        "echo @@z; ps -eo stat 2>/dev/null | grep -c '^Z'; "
        "echo @@lsn; ss -ltn 2>/dev/null | tail -n +2 | wc -l; "
        "echo @@dns; (getent hosts localhost >/dev/null 2>&1 && echo lo_ok || echo lo_fail); "
        "(timeout 3 getent hosts \"$(hostname -f 2>/dev/null || echo localhost)\" >/dev/null 2>&1 "
        "&& echo fqdn_ok || echo fqdn_fail); "
        "echo @@ts; timedatectl 2>/dev/null | grep -i synchronized "
        "|| chronyc tracking 2>/dev/null | head -3 || echo unavail")
    s = _sections(out)
    checks = {}
    failed = [line for line in s.get("failed", "").splitlines() if line.strip()]
    checks["services"] = (_c("critical", f"{len(failed)} failed", failed[0].split()[0])
                          if failed else _c("ok", "0 failed"))
    z = _num(s.get("z", "0"))
    checks["processes"] = _c("warning" if z > 5 else "ok", f"{z} zombies")
    checks["network"] = _c("ok", f"{_num(s.get('lsn', '0'))} listeners")
    dns = s.get("dns", "")
    checks["dns"] = (_c("critical", "failing", "localhost lookup failed") if "lo_fail" in dns
                     else _c("warning", "fqdn lookup failed", "host fqdn does not resolve")
                     if "fqdn_fail" in dns else _c("ok", "resolving"))
    ts = s.get("ts", "").lower()
    if "yes" in ts or "leap status     : normal" in ts:
        checks["time_sync"] = _c("ok", "synced")
    elif "unavail" in ts or not ts.strip():
        checks["time_sync"] = _c("ok", "n/a", "no timedatectl/chrony")
    else:
        checks["time_sync"] = _c("warning", "not synced", ts.strip().splitlines()[0][:80])
    return checks


async def _g_security(server: Server) -> dict:
    rc, out = await _ssh(server,
        "echo @@ufw; ufw status 2>/dev/null | head -1; "
        "echo @@ipt; iptables -S 2>/dev/null | wc -l; "
        "echo @@lastb; lastb -n 50 2>/dev/null | grep -cE '^[a-zA-Z0-9]'; "
        "echo @@se; getenforce 2>/dev/null || echo n/a; "
        "echo @@rr; [ -f /var/run/reboot-required ] && echo yes || echo no; "
        "echo @@upg; apt list --upgradable 2>/dev/null | grep -c upgradable "
        "|| yum -q check-update 2>/dev/null | grep -c '^[a-zA-Z0-9]'; "
        "echo @@cert; (echo | timeout 3 openssl s_client -connect localhost:443 2>/dev/null "
        "| openssl x509 -noout -enddate 2>/dev/null) || echo nocert")
    s = _sections(out)
    checks = {}
    ufw = s.get("ufw", "").lower()
    ipt = _num(s.get("ipt", "0"))
    if "active" in ufw and "inactive" not in ufw:
        checks["firewall"] = _c("ok", "ufw active")
    elif ipt > 5:
        checks["firewall"] = _c("ok", f"iptables · {ipt} rules")
    elif "inactive" in ufw:
        checks["firewall"] = _c("warning", "ufw inactive")
    else:
        checks["firewall"] = _c("warning", "none detected", "no ufw/iptables rules found")
    bad = _num(s.get("lastb", "0"))
    se = s.get("se", "").strip()
    checks["security"] = _c("warning" if bad > 10 else "ok",
                            f"{bad} failed logins" if bad else "clean",
                            f"selinux {se.lower()}" if se and se != "n/a" else "")
    cert = s.get("cert", "")
    m = re.search(r"notAfter=(.+)", cert)
    if m:
        try:
            from email.utils import parsedate_to_datetime

            exp = parsedate_to_datetime(m.group(1).strip().replace(" GMT", " +0000"))
            days = int((exp.timestamp() - time.time()) / 86400)
            checks["certificates"] = _c("critical" if days < 7 else
                                        "warning" if days < 30 else "ok",
                                        f"{days}d left" if days >= 0 else "EXPIRED",
                                        "cert on :443")
        except Exception:  # noqa: BLE001
            checks["certificates"] = _c("ok", "found", "could not parse expiry")
    else:
        checks["certificates"] = _c("ok", "n/a", "no TLS listener on 443")
    pending = _num(s.get("upg", "0"))
    rr = "yes" in s.get("rr", "")
    checks["patching"] = _c("warning" if rr or pending >= 20 else "ok",
                            f"{pending} pending",
                            "reboot required" if rr else "")
    return checks


async def _g_logs(server: Server) -> dict:
    rc, out = await _ssh(server,
        "echo @@dmesg; dmesg --level=err,crit 2>/dev/null | tail -20; "
        "echo @@journal; journalctl -q -p err --since '-2 hours' --no-pager 2>/dev/null | tail -30")
    s = _sections(out)
    checks = {}
    dm = [line for line in s.get("dmesg", "").splitlines() if line.strip()]
    checks["kernel"] = (_c("warning" if len(dm) <= 5 else "critical",
                           f"{len(dm)} err/crit", dm[-1][:100]) if dm
                        else _c("ok", "clean", "no err/crit in dmesg"))
    jl = [line for line in s.get("journal", "").splitlines()
          if line.strip() and "No entries" not in line]
    checks["logs"] = (_c("warning" if len(jl) <= 30 else "critical",
                         f"{len(jl)} errors / 2h", jl[-1][:100]) if jl
                      else _c("ok", "no recent errors"))
    return checks


_GROUPS = [_g_basics, _g_compute, _g_storage, _g_runtime, _g_security, _g_logs]

_ALL_ASPECTS = [
    "connectivity", "uptime", "cpu", "load", "memory", "swap", "storage",
    "inodes", "disk_io", "services", "processes", "network", "dns",
    "time_sync", "firewall", "security", "certificates", "patching",
    "kernel", "logs",
]


async def run_probe(server: Server, force: bool = False) -> None:
    """Probe the server group by group, updating PROBES[server.name] live."""
    st = PROBES.setdefault(server.name, {})
    if st.get("running"):
        return
    if not force and st.get("complete") and time.time() - st.get("ts", 0) < FRESH_SECONDS:
        return
    st.update(running=True, complete=False, ts=time.time(), checks={})
    try:
        for group in _GROUPS:
            try:
                st["checks"].update(await group(server))
            except Exception:  # noqa: BLE001 - a failed group must not kill the probe
                pass
            st["ts"] = time.time()
            if (st["checks"].get("connectivity") or {}).get("status") == "critical":
                for aspect in _ALL_ASPECTS:
                    st["checks"].setdefault(
                        aspect, _c("unknown", "unreachable", "server not reachable over ssh"))
                break
        st["complete"] = True
    finally:
        st["running"] = False
