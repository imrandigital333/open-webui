"""Reusable diagnostic script library.

The agent checks here before writing new diagnostic scripts, reuses what fits
and contributes new parameterized scripts back — cutting token usage on every
subsequent investigation. Scripts carry a structured comment header that this
module parses for the UI and for the agent's own catalog listing.
"""

import os
import re
from pathlib import Path

from .inventory import BASE_DIR

SCRIPTLIB_DIR = Path(os.environ.get("TROUBLESHOOTER_SCRIPTLIB", BASE_DIR / "data" / "scriptlib"))

HEADER_FIELDS = ("name", "description", "usage", "tags")

SEED_VERSION = 2

SEED_SCRIPT = '''#!/usr/bin/env bash
# name: health_sweep
# version: 2
# description: One-shot server health sweep over SSH - uptime, load, cpu, memory, swap, disk, inodes, io, failed services, zombies, listening ports, dns, time sync, firewall, failed logins, certificates, pending updates, kernel + recent log errors. Output is section-delimited for easy parsing.
# usage: SSHP="<full ssh command prefix>" bash health_sweep.sh          (e.g. SSHP="ssh -i /key -p 22 user@host")
# tags: health, sweep, generic, baseline
set -o pipefail
if [ -z "$SSHP" ]; then echo "usage: SSHP='<ssh command prefix>' bash $0" >&2; exit 2; fi

$SSHP 'echo "=== date_uptime ==="; date; uptime;
echo "=== load ==="; cat /proc/loadavg; nproc 2>/dev/null;
echo "=== cpu_top ==="; top -b -n1 2>/dev/null | head -15;
echo "=== memory_swap ==="; free -m 2>/dev/null;
echo "=== disk ==="; df -h 2>/dev/null;
echo "=== inodes ==="; df -i 2>/dev/null | awk "NR==1 || \\$5+0>60";
echo "=== disk_io ==="; vmstat 1 2 2>/dev/null | tail -2 || echo "no vmstat";
echo "=== failed_services ==="; systemctl list-units --state=failed --no-pager 2>/dev/null || echo "no systemd";
echo "=== zombies_dstate ==="; ps -eo stat,pid,ppid,comm 2>/dev/null | awk "\\$1~/^Z/ || \\$1~/^D/" | head -10;
echo "=== listening_ports ==="; ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null || echo "no ss/netstat";
echo "=== dns ==="; (getent hosts localhost >/dev/null && echo localhost_ok) ; timeout 3 getent hosts $(hostname -f 2>/dev/null || echo localhost) >/dev/null 2>&1 && echo fqdn_ok || echo fqdn_lookup_failed;
echo "=== time_sync ==="; timedatectl 2>/dev/null | grep -iE "synchronized|ntp" || chronyc tracking 2>/dev/null | head -5 || echo "unavailable";
echo "=== firewall ==="; ufw status 2>/dev/null || iptables -S 2>/dev/null | head -20 || echo "unavailable";
echo "=== failed_logins ==="; lastb -n 15 2>/dev/null | head -16 || echo "unavailable";
echo "=== certificates ==="; for p in 443 8443; do timeout 3 bash -c "echo | openssl s_client -connect localhost:$p 2>/dev/null | openssl x509 -noout -enddate" 2>/dev/null && echo "(port $p)"; done; echo "(no output above = no local TLS listener on 443/8443)";
echo "=== pending_updates ==="; [ -f /var/run/reboot-required ] && echo REBOOT-REQUIRED; apt list --upgradable 2>/dev/null | head -15 || yum check-update 2>/dev/null | head -15 || echo "unavailable";
echo "=== kernel_dmesg ==="; dmesg --level=err,crit 2>/dev/null | tail -15 || dmesg 2>/dev/null | tail -15 || echo "unavailable";
echo "=== recent_log_errors ==="; (journalctl -p err --since "-2 hours" --no-pager 2>/dev/null | tail -30) || (grep -iE "error|crit|fail|oom" /var/log/syslog 2>/dev/null | tail -30) || (grep -iE "error|crit|fail|oom" /var/log/messages 2>/dev/null | tail -30) || echo "no readable logs"'
echo "=== NOTE ==="
echo "log sections above cover the RECENT window only. For incidents older than ~2h,"
echo "collect logs bracketing the actual failure timestamp separately."
'''


def _seed_version(text: str) -> int:
    m = re.search(r"^#\s*version:\s*(\d+)", text, re.MULTILINE)
    return int(m.group(1)) if m else 1


def ensure_scriptlib() -> Path:
    SCRIPTLIB_DIR.mkdir(parents=True, exist_ok=True)
    seed = SCRIPTLIB_DIR / "health_sweep.sh"
    if not seed.exists():
        seed.write_text(SEED_SCRIPT)
        seed.chmod(0o755)
    else:
        # upgrade OUR seed in place when we ship a newer sweep; never touch a
        # script the operator or the agents renamed/authored themselves
        try:
            current = seed.read_text(errors="replace")
            if "# name: health_sweep" in current and _seed_version(current) < SEED_VERSION:
                seed.write_text(SEED_SCRIPT)
                seed.chmod(0o755)
        except OSError:
            pass
    return SCRIPTLIB_DIR


def parse_header(path: Path) -> dict:
    meta = {"file": path.name, "size": path.stat().st_size}
    try:
        head = path.read_text(errors="replace")[:2000]
    except OSError:
        return meta
    for field in HEADER_FIELDS:
        m = re.search(rf"^#\s*{field}:\s*(.+)$", head, re.MULTILINE)
        if m:
            meta[field] = m.group(1).strip()
    meta.setdefault("name", path.stem)
    return meta


def list_scripts() -> list[dict]:
    ensure_scriptlib()
    return sorted(
        (parse_header(p) for p in SCRIPTLIB_DIR.glob("*.sh") if p.is_file()),
        key=lambda m: m["name"],
    )
