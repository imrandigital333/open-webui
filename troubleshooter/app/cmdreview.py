"""Pre-execution review gate for operator-typed commands.

Every ad-hoc command from the remediation chat is reviewed BEFORE it can run:

1. A deterministic policy layer classifies it (readonly / modifies /
   dangerous / blocked). Catastrophic patterns (rm -rf /, mkfs, dd onto a
   disk, fork bombs…) are hard-BLOCKED — no override exists, and run-cmd
   enforces the same check server-side.
2. A one-turn Claude assessment (no tools) adds a plain-language impact
   summary, a suggested backup command, and the worst-case damage. The AI can
   only RAISE severity, never lower what the policy layer decided.

If the AI is unavailable the policy verdict ships alone with generic wording,
so the gate never blocks on the model being reachable.
"""

import asyncio
import json
import re

from .inventory import Server

SEVERITY = {"readonly": 0, "modifies": 1, "dangerous": 2, "blocked": 3}

# catastrophic — never executed, no override
BLOCKED = [
    (r"\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*\s+)+(-[a-zA-Z]*\s+)*(/|/\*)\s*(;|&&|\|\||$)",
     "recursively deletes the root filesystem"),
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "is a fork bomb — exhausts all processes"),
    (r"\bdd\b[^|;&]*\bof=/dev/(sd|vd|nvme|xvd|hd|mapper)", "overwrites a raw disk device"),
    (r"\bmkfs(\.\w+)?\b", "formats a filesystem, destroying all data on it"),
    (r"\bwipefs\b.*(-a|--all)", "wipes filesystem signatures from a disk"),
    (r">\s*/dev/(sd|vd|nvme|xvd|hd)", "writes directly over a disk device"),
    (r"\bchmod\s+(-[a-zA-Z]*R[a-zA-Z]*\s+)+[0-7]+\s+/\s*($|;|&&)", "recursively re-permissions the root filesystem"),
]

# destructive or availability-impacting — allowed only after double confirmation
DANGEROUS = [
    (r"\brm\s+-[a-zA-Z]*[rR]", "deletes recursively"),
    (r"\bfind\b.*(-delete|-exec\s+rm)", "bulk-deletes files"),
    (r"\b(shutdown|poweroff|halt)\b", "powers the server off"),
    (r"\breboot\b", "reboots the server"),
    (r"\biptables\s+(-F|--flush)", "flushes all firewall rules"),
    (r"\bufw\s+disable\b", "disables the firewall"),
    (r"\b(userdel|groupdel)\b", "deletes an account"),
    (r"\bchmod\s+-[a-zA-Z]*R", "changes permissions recursively"),
    (r"\bchown\s+-[a-zA-Z]*R", "changes ownership recursively"),
    (r"\bkill\s+(-\w+\s+)?1(\s|$)", "signals PID 1 (init)"),
    (r"\bsystemctl\s+(stop|disable|mask)\b", "stops or disables a service"),
    (r"\b(shred|truncate)\b", "destroys file contents"),
    (r"\bcrontab\s+-r", "removes all cron jobs"),
    (r"\bdd\b", "low-level copies data (device-capable)"),
    (r"\bhistory\s+-c", "clears the shell audit trail"),
]

# changes state — backup-first flow
MODIFIES = [
    (r"\bsystemctl\s+(restart|start|reload|enable|daemon-reload)\b", "restarts/starts a service"),
    (r"\b(apt|apt-get|yum|dnf|zypper|snap)\b(?!\S*\s+(list|search|info|show|check-update|--version))",
     "installs, upgrades or removes packages"),
    (r"\bsed\s+-[a-zA-Z]*i", "edits a file in place"),
    (r"\bupdate-crypto-policies\b.*--set", "changes the system crypto policy"),
    (r"\b(useradd|usermod|groupadd|passwd|chpasswd)\b", "modifies an account"),
    (r"\bufw\s+(allow|deny|delete|enable)\b", "changes firewall rules"),
    (r"\biptables\s+-[AIDRP]", "changes firewall rules"),
    (r"\bsetenforce\b", "changes SELinux enforcement"),
    (r"\bsysctl\s+-w", "changes a kernel parameter"),
    (r"\b(chmod|chown|chgrp)\b", "changes permissions/ownership"),
    (r"\b(mv|cp|rsync|ln|mkdir|touch|tee)\b", "creates or moves files"),
    (r"\brm\b", "deletes a file"),
    (r"(?<![|&>])>{1,2}\s*\S", "writes/appends to a file"),
    (r"\bcurl\b.*(-X\s*(POST|PUT|DELETE|PATCH)|--data|-d\s)", "sends a modifying HTTP request"),
    (r"\b(git|svn)\b.*\b(pull|checkout|reset|clean)\b", "changes a working tree"),
    (r"\b(mount|umount|swapon|swapoff)\b", "changes mounts"),
    (r"\bhostnamectl\s+set", "changes the hostname"),
    (r"\btimedatectl\s+set", "changes the clock"),
]


# ---- Windows / PowerShell policy (case-insensitive: PowerShell is) ----

# catastrophic — never executed, no override
WIN_BLOCKED = [
    (r"(?i)\bformat(-volume|\.com)?\b", "formats a volume, destroying all data on it"),
    (r"(?i)\bclear-disk\b", "wipes a disk, destroying all data on it"),
    (r"(?i)\b(remove-partition|remove-item)\b[^\n]*\b[a-z]:\\?\s*(-recurse|/s)", "recursively deletes a whole drive"),
    (r"(?i)\brd\s+/s\s+/q\s+[a-z]:\\?\s*$", "recursively deletes a whole drive"),
    (r"(?i)\bdiskpart\b[^\n]*\bclean\b", "wipes a disk via diskpart"),
    (r"(?i)\bcipher\s+/w:", "securely wipes free space"),
]

# destructive or availability-impacting — double confirmation
WIN_DANGEROUS = [
    (r"(?i)\b(stop-computer|restart-computer)\b", "powers off / reboots the server"),
    (r"(?i)\bshutdown(\.exe)?\b\s+/(s|r|p)", "powers off / reboots the server"),
    (r"(?i)\bremove-item\b[^\n]*-recurse", "deletes recursively"),
    (r"(?i)\b(rd|rmdir)\b[^\n]*/s", "deletes a directory tree"),
    (r"(?i)\b(stop-service|suspend-service)\b", "stops a service"),
    (r"(?i)\bset-service\b[^\n]*-startuptype\s+disabled", "disables a service"),
    (r"(?i)\bremove-service\b", "deletes a service"),
    (r"(?i)\bdisable-netadapter\b", "takes a network adapter down"),
    (r"(?i)\bset-netfirewallprofile\b[^\n]*-enabled\s+(false|\$false)", "disables the firewall"),
    (r"(?i)\bnetsh\s+advfirewall\s+set\b[^\n]*\bstate\s+off", "disables the firewall"),
    (r"(?i)\b(remove-localuser|remove-aduser)\b", "deletes an account"),
    (r"(?i)\bnet\s+user\b[^\n]*/del", "deletes an account"),
    (r"(?i)\b(uninstall|remove)-windowsfeature\b", "removes a server role/feature"),
    (r"(?i)\b(clear-eventlog|wevtutil\s+cl)\b", "clears an event log (audit trail)"),
    (r"(?i)\bremove-item\b[^\n]*\bhk(lm|cu|cr|u):", "deletes registry keys"),
    (r"(?i)\bstop-process\b[^\n]*-force", "force-kills a process"),
]

# changes state — backup-first flow
WIN_MODIFIES = [
    (r"(?i)\b(restart|start)-service\b", "starts/restarts a service"),
    (r"(?i)\b(restart|start|stop)-webapppool\b", "cycles an IIS app pool"),
    (r"(?i)\biisreset\b", "restarts IIS"),
    (r"(?i)\bset-service\b", "reconfigures a service"),
    (r"(?i)\b(install|add)-windowsfeature\b", "installs a server role/feature"),
    (r"(?i)\b(set|new|remove)-itemproperty\b", "changes the registry"),
    (r"(?i)\breg\s+(add|delete|import)\b", "changes the registry"),
    (r"(?i)\b(new|copy|move|rename)-item\b", "creates/moves/renames files"),
    (r"(?i)\b(set|add)-content\b", "writes to a file"),
    (r"(?i)\bout-file\b", "writes to a file"),
    (r"(?i)(?<![|&>])>{1,2}\s*\S", "writes/appends to a file"),
    (r"(?i)\b(set|new)-netipaddress\b", "changes an IP address"),
    (r"(?i)\bset-dnsclientserveraddress\b", "changes DNS settings"),
    (r"(?i)\bnetsh\s+interface\b[^\n]*\bset\b", "changes network configuration"),
    (r"(?i)\b(new|set)-netfirewallrule\b", "changes firewall rules"),
    (r"(?i)\b(new|set)-localuser\b", "modifies an account"),
    (r"(?i)\badd-localgroupmember\b", "grants group membership"),
    (r"(?i)\bnet\s+user\b", "modifies an account"),
    (r"(?i)\bset-executionpolicy\b", "changes the PowerShell execution policy"),
    (r"(?i)\b(set-timezone|set-date)\b", "changes the clock"),
    (r"(?i)\brename-computer\b", "renames the server"),
    (r"(?i)\benable-netadapter\b", "brings a network adapter up"),
    (r"(?i)\b(winget|choco|chocolatey)\b\s+(install|upgrade|uninstall|remove)", "installs/removes packages"),
    (r"(?i)\bset-mppreference\b", "changes Windows Defender settings"),
]


def classify(cmd: str, platform: str = "linux") -> tuple[str, str]:
    """Deterministic policy verdict — the floor the AI can only raise."""
    if str(platform).lower() == "windows":
        blocked, dangerous, modifies = WIN_BLOCKED, WIN_DANGEROUS, WIN_MODIFIES
    else:
        blocked, dangerous, modifies = BLOCKED, DANGEROUS, MODIFIES
    for pattern, why in blocked:
        if re.search(pattern, cmd):
            return "blocked", why
    for pattern, why in dangerous:
        if re.search(pattern, cmd):
            return "dangerous", why
    for pattern, why in modifies:
        if re.search(pattern, cmd):
            return "modifies", why
    return "readonly", "no state-changing pattern detected"


async def _ai_assess(cmd: str, server: Server) -> dict | None:
    try:
        from claude_agent_sdk import ClaudeAgentOptions, query
        from claude_agent_sdk.types import ResultMessage
    except ImportError:
        return None
    services = ", ".join(server.services) or "unknown"
    win = server.is_windows
    shell = "PowerShell (via WinRM)" if win else "shell"
    os_label = server.os or ("Windows" if win else "linux")
    backup_hint = ("ONE PowerShell command that backs up whatever this changes "
                   "(e.g. Copy-Item to a dated path, Export registry key), or "
                   if win else
                   "ONE shell command that backs up whatever this changes (dated copy), or ")
    prompt = f"""You are a {"Windows" if win else "Linux"} change-review gate for production servers.
An operator wants to run this {shell} command on server "{server.name}"
(OS: {os_label}, key services: {services}):

{cmd}

Reply with ONLY this JSON (no fences, no other text):
{{"risk": "readonly | modifies | dangerous",
 "impact": "2-3 plain sentences: exactly what the command does and its operational impact on this server",
 "backup_command": "{backup_hint}"" if it changes nothing",
 "damage": "worst case if it goes wrong, one line, or "" if none"}}

risk rules: readonly = inspects only; modifies = changes files/services/config;
dangerous = can destroy data, break access, or take the server down."""
    text = ""
    try:
        async with asyncio.timeout(35):
            options = ClaudeAgentOptions(max_turns=1, allowed_tools=[])
            async for message in query(prompt=prompt, options=options):
                if isinstance(message, ResultMessage) and not message.is_error:
                    text = message.result or ""
    except Exception:  # noqa: BLE001 - review must not fail on AI hiccups
        return None
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        data = json.loads(m.group())
    except json.JSONDecodeError:
        return None
    if data.get("risk") not in SEVERITY:
        data["risk"] = None
    return data


async def review(cmd: str, server: Server) -> dict:
    verdict, reason = classify(cmd, "windows" if server.is_windows else "linux")
    if verdict == "blocked":
        return {"verdict": "blocked", "reason": reason,
                "impact": f"This command {reason}. It is hard-blocked by policy and will not be executed.",
                "backup_command": "", "damage": reason, "source": "policy"}
    ai = await _ai_assess(cmd, server)
    impact, backup, damage = "", "", ""
    if ai:
        if ai.get("risk") and SEVERITY[ai["risk"]] > SEVERITY[verdict]:
            verdict, reason = ai["risk"], "assessed by AI review"
        impact = str(ai.get("impact") or "")[:700]
        backup = str(ai.get("backup_command") or "")[:300]
        damage = str(ai.get("damage") or "")[:300]
    if not impact:
        impact = {
            "readonly": "Read-only diagnostic — it does not change server state.",
            "modifies": f"This command changes server state: it {reason}.",
            "dangerous": f"High-risk command: it {reason}.",
        }[verdict]
    return {"verdict": verdict, "reason": reason, "impact": impact,
            "backup_command": backup, "damage": damage,
            "source": "ai+policy" if ai else "policy"}
