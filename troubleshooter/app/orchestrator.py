"""Runs troubleshooting sessions by driving Claude Code through the Claude Agent SDK.

Each session gets its own working directory under data/sessions/<id>/ where the
agent stores collected logs and writes the final report (report.json + report.md).
The SDK talks to the locally installed, already-authenticated Claude Code — no
API key is needed on a machine where `claude` is logged in.
"""

import asyncio
import contextlib
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import db
from .inventory import BASE_DIR, Server
from .scriptlib import SCRIPTLIB_DIR, ensure_scriptlib

SESSIONS_DIR = Path(os.environ.get("TROUBLESHOOTER_DATA", BASE_DIR / "data" / "sessions"))

REPORT_SCHEMA = """{
  "summary": "one-paragraph plain-language summary of what happened",
  "probable_root_cause": "the single most likely root cause",
  "root_cause_layer": "server | application | virtualization | network | monitoring | change/itsm | external | unknown",
  "confidence": "high | medium | low",
  "layers_checked": [
    {"layer": "layer or datasource name", "verdict": "clean | suspicious | root cause | unreachable", "note": "one line"}
  ],
  "evidence": [
    {"source": "file or command the evidence came from", "finding": "what it shows"}
  ],
  "incident_timeline": [
    {"time": "timestamp as it appears in the logs", "source": "which log/layer", "event": "what happened at this moment — include normal state, first anomaly, escalation, failure, aftermath"}
  ],
  "logs_reviewed": [
    {"source": "log file / journal unit / API queried", "covers": "time range the reviewed extract covered", "note": "relevant findings or 'nothing relevant'"}
  ],
  "impact": "what is affected and how badly",
  "recommended_fix": ["ordered, concrete remediation steps with exact commands where possible"],
  "remediation_plan": [
    {"order": 1, "phase": "backup | fix | verify | rollback", "command": "one exact shell command for the TARGET server", "description": "plain language: what this command does and why it is needed", "risk": "low | medium | high"}
  ],
  "preventive_measures": ["changes that would stop this recurring (monitoring, config, capacity...)"],
  "needs_followup": ["open questions or data that could not be collected, if any"]
}"""

REMEDIATION_RULES = """   remediation_plan rules — the operator may execute it as-is, so be precise:
   - ALWAYS start with backup steps preserving everything the fix will touch
     (config files, certs, current service state), e.g. cp -a with a dated
     suffix. Never a fix step before its backup step.
   - Then fix steps (one command each), then verify steps that PROVE recovery
     (service active, port listening, HTTP 200), then rollback steps that
     restore the backups if the fix fails.
   - Each entry: a single exact command, a plain-language description of what
     it does and why, and an honest risk level.
   - Assume the operator runs them with appropriate privileges (sudo/root).
   - You never execute these yourself — your investigation stays read-only.
"""


DEPTH_TURNS = {"quick": 35, "standard": 90, "deep": 160}

# canonical health aspects — keep in sync with HEALTH_SECTION and the UI's ASPECTS
HEALTH_ASPECTS = [
    "connectivity", "uptime", "cpu", "load", "memory", "swap", "storage",
    "inodes", "disk_io", "services", "processes", "network", "dns",
    "time_sync", "firewall", "security", "certificates", "patching",
    "kernel", "logs",
]

DEPTH_GUIDANCE = {
    "quick": (
        "QUICK triage: you are time-boxed. Check only the 2-3 most likely "
        "evidence sources for this problem, collect small targeted extracts, "
        "and give your best assessment. Mark anything unchecked in "
        "needs_followup."
    ),
    "standard": (
        "STANDARD investigation: check every selected evidence layer at least "
        "briefly, go deep on the ones that show anomalies, and correlate "
        "across layers before concluding."
    ),
    "deep": (
        "DEEP investigation: be exhaustive. Query every selected layer, widen "
        "time windows if the incident start is unclear, cross-check every "
        "hypothesis against at least two independent sources, and explicitly "
        "rule out each layer you clear (say what you checked and why it's "
        "clean)."
    ),
}


INVESTIGATE_PHASES = ["triage", "pinpoint", "collect", "analyze", "report"]
HEALTHCHECK_PHASES = ["connect", "sweep", "report"]
REMEDIATE_PHASES = ["backup", "fix", "verify", "report"]


def build_remediation_prompt(server: Server, remediation: dict, workdir: Path) -> str:
    plan_lines = []
    for step in remediation.get("plan", []):
        plan_lines.append(
            f"{step.get('order', '?')}. [{step.get('phase', '?').upper()}] "
            f"(risk: {step.get('risk', '?')}) `{step.get('command', '')}`\n"
            f"   purpose: {step.get('description', '')}"
        )
    plan_text = "\n".join(plan_lines) or "(empty plan)"
    return f"""You are an SRE executing an APPROVED remediation plan on a server. A human
operator reviewed this exact plan and authorized its execution.

{workdir_section(workdir)}
## Target server
- Name: {server.name} ({server.description or "no description"})
- Connect with EXACTLY this command prefix for every remote command:
  `{server.ssh_command()} '<remote command>'`

## Incident context
- Original problem: {remediation.get("problem", "(unknown)")}
- Confirmed root cause: {remediation.get("root_cause", "(see plan)")}

## APPROVED REMEDIATION PLAN (execute exactly this, in order)
{plan_text}

## Progress markers
When you enter a new phase, start the FIRST line of your next message with
exactly one of: PHASE: BACKUP | PHASE: FIX | PHASE: VERIFY | PHASE: REPORT

## Execution rules — read carefully
- Execute ONLY the commands in the plan, in the given order. You may also run
  READ-ONLY checks (systemctl status, tail, grep, curl to localhost) between
  steps to confirm state — but NO state-changing command outside the plan.
- BACKUP steps come first. If a backup step fails, STOP — do not run any fix.
- After every command, check it succeeded (exit code + output) and save the
  output under ./logs/ with the step number in the filename.
- If a fix step fails, or the verify steps show the issue is NOT resolved,
  execute the plan's rollback steps, then report honestly.
- If a command fails with insufficient permissions, STOP and report exactly
  which permission is missing. Do not invent workarounds.
- REPORT: write report.md (readable) and report.json EXACTLY:
{{
  "summary": "what was executed and the outcome, in plain language",
  "outcome": "fixed | failed | rolled_back | partial",
  "steps": [
    {{"order": 1, "phase": "backup", "command": "...", "status": "success | failed | skipped", "output": "trimmed relevant output"}}
  ],
  "verification": "the evidence that the issue is resolved (or exactly how it is still broken)",
  "followup": ["anything the operator should still do"]
}}

Finish only after both report files are written."""

def script_library_section() -> str:
    lib = ensure_scriptlib()
    return f"""## Script library (reuse before you write!)
A persistent library of tested diagnostic scripts lives at:
  {lib}
Rules — this saves significant time and tokens:
1. BEFORE writing any multi-command diagnostic script, list the library
   (`ls {lib}` and read the `# description:` headers with
   `head -5 {lib}/*.sh`) and REUSE a script when one fits.
2. Invocation convention: scripts take the ssh prefix via the SSHP env var:
   `SSHP="<the exact ssh command prefix for this server>" bash {lib}/<script>.sh [args]`
3. When you write a NEW diagnostic script during this session that is
   reusable (parameterized, not tied to one host or one incident), SAVE it
   to the library as {lib}/<short_name>.sh with EXACTLY this header:
     #!/usr/bin/env bash
     # name: <short_name>
     # description: <one line: what it collects/checks>
     # usage: SSHP="<ssh prefix>" bash <short_name>.sh [args]
     # tags: <comma, separated, keywords>
   Make it generic (use $SSHP, take service names/paths as arguments),
   and `chmod +x` it. Do NOT store one-off greps or host-specific commands.
4. If an existing library script has a bug or gap you had to work around,
   fix it in place (keep the header).
5. IMPORTANT LIMIT: library sweep scripts collect CURRENT/recent state
   (e.g. last couple of hours of logs). They are a starting point, NEVER a
   substitute for the failure-time-anchored log collection in the workflow —
   for any incident older than the sweep's window you must still bracket
   the logs around the actual failure timestamp yourself.
"""


HEALTH_SECTION = """## Live health checklist (./health.json)
Maintain a machine-readable health snapshot of the target server in
./health.json so the operator's dashboard updates live:
- IMMEDIATELY after your first message, write the initial file with every
  aspect set to {"status": "unknown"}.
- PROGRESSIVE UPDATES ARE MANDATORY. Collect in SIX ordered groups, ONE
  combined SSH command per group, and rewrite ./health.json IMMEDIATELY after
  each group returns — the operator's dashboard animates the group being
  checked, so running everything as one big sweep (or batching the writes)
  is a FAILURE even if the values are correct. The groups, in this exact order:
  G1 basics   (connectivity, uptime): date; uptime; who -b
  G2 compute  (cpu, load, memory, swap): nproc; cat /proc/loadavg;
     top -b -n1 | head -12; free -m
  G3 storage  (storage, inodes, disk_io): df -h; df -i; vmstat 1 2 | tail -2
  G4 runtime  (services, processes, network, dns, time_sync):
     systemctl list-units --state=failed; ps -eo stat,pid,comm | awk '$1~/^Z|^D/';
     ss -ltn; getent hosts localhost; timeout 3 getent hosts $(hostname -f);
     timedatectl 2>/dev/null || chronyc tracking 2>/dev/null
  G5 security (firewall, security, certificates, patching):
     ufw status 2>/dev/null || iptables -S | head -20; lastb -n 15 2>/dev/null;
     getenforce 2>/dev/null; [ -f /var/run/reboot-required ] && echo reboot-required;
     apt list --upgradable 2>/dev/null | head -15 || yum check-update 2>/dev/null | head -15;
     for TLS listeners: echo | timeout 3 openssl s_client -connect localhost:443 2>/dev/null
       | openssl x509 -noout -enddate  ("n/a — no TLS services" is a valid ok value)
  G6 logs     (kernel, logs): dmesg --level=err,crit 2>/dev/null | tail -15;
     journalctl -p err --since "-2 hours" --no-pager | tail -20
- Statuses: "ok" | "warning" | "critical" | "unknown". Judge like an SRE:
  disk/inodes >90% critical, >80% warning; load1 > cores warning, > 2x cores
  critical; swap >40% used or active si/so warning, >80% critical; iowait >20%
  warning, >40% critical; any failed key service critical; zombies >5 or a
  D-state pileup warning; DNS resolution failure critical; clock unsynced or
  offset >1s warning, >30s critical; cert expiring <30d warning, expired or <7d
  critical; burst of failed logins warning; reboot-required or pending security
  updates warning; OOM/hardware/I-O errors in dmesg warning or critical.
- EXACT format — ALL TWENTY keys always present:
{
  "checks": {
    "connectivity": {"status": "...", "value": "reachable, ssh ok", "note": "one line"},
    "uptime":       {"status": "...", "value": "up 41 days", "note": "no unexpected reboot"},
    "cpu":          {"status": "...", "value": "23%", "note": "top consumer: java 18%"},
    "load":         {"status": "...", "value": "0.8 / 4 cores", "note": "load1 well under core count"},
    "memory":       {"status": "...", "value": "78%", "note": "no OOM events"},
    "swap":         {"status": "...", "value": "12%", "note": "no active swapping (si/so 0)"},
    "storage":      {"status": "...", "value": "91% /var", "note": "worst filesystem"},
    "inodes":       {"status": "...", "value": "34% /", "note": "worst filesystem inode usage"},
    "disk_io":      {"status": "...", "value": "3% iowait", "note": "no device saturation"},
    "services":     {"status": "...", "value": "1 failed", "note": "fakeapp down since 14:31"},
    "processes":    {"status": "...", "value": "0 zombies", "note": "no D-state pileup; top hog: mysqld"},
    "network":      {"status": "...", "value": "ports ok", "note": "expected listeners present, no drops"},
    "dns":          {"status": "...", "value": "resolving", "note": "internal + external lookups ok"},
    "time_sync":    {"status": "...", "value": "synced", "note": "chrony offset 0.2ms"},
    "firewall":     {"status": "...", "value": "ufw active", "note": "no recent rule changes"},
    "security":     {"status": "...", "value": "clean", "note": "no failed-login bursts; selinux enforcing"},
    "certificates": {"status": "...", "value": "ok, 148d", "note": "nearest expiry: web cert 2026-12-11"},
    "patching":     {"status": "...", "value": "12 pending", "note": "3 security updates; no reboot-required"},
    "kernel":       {"status": "...", "value": "clean", "note": "no err/crit in dmesg"},
    "logs":         {"status": "...", "value": "error burst", "note": "kernel OOM messages at 14:31"}
  }
}
- Start each value with "NN%" when a percentage applies (cpu, memory, swap,
  storage, inodes, disk_io) so the dashboard can draw a gauge.
"""


def build_healthcheck_prompt(server: Server, workdir: Path | None = None) -> str:
    hints = "\n".join(f"  - {h}" for h in server.log_hints) or "  - (none provided)"
    services = ", ".join(server.services) or "(unknown)"
    wd_section = workdir_section(workdir) if workdir else ""
    return f"""You are an SRE running a PROACTIVE HEALTH CHECK on a server — there is no
reported incident. Assess its health quickly and thoroughly.

{wd_section}
## Target server
- Name: {server.name} ({server.description or "no description"})
- OS: {server.os or "unknown"}
- Key services: {services}
- Connect with EXACTLY this command prefix for every remote command:
  `{server.ssh_command()} '<remote command>'`
- Log locations / hints:
{hints}

{script_library_section()}
{HEALTH_SECTION}
## Progress markers
When you enter a new phase, start the FIRST line of your next message with
exactly one of: PHASE: CONNECT | PHASE: SWEEP | PHASE: REPORT
Library tip: reuse per-group scripts (health_g1.sh … health_g6.sh) from the
library when they exist, and save parameterized ones back after a successful
run. Do NOT use the all-in-one health_sweep.sh for an interactive check — it
returns everything at once, which defeats the live group-by-group progress.

## Hard rules
- READ-ONLY on the remote server: diagnostic and log-reading commands only.
  Never change any state.
- Be fast: this is a sweep, not an investigation. Use a few combined SSH
  commands, and only dig deeper into an aspect that looks unhealthy (e.g.
  check WHY a service is down, WHAT is filling a disk).
- Save command outputs under ./logs/ for the operator.

## Workflow
1. CONNECT: verify reachability, and write the initial all-unknown
   ./health.json.
2. SWEEP: run groups G1→G6 in order — one SSH call per group, then
   immediately update ./health.json for that group's aspects before starting
   the next group. Briefly investigate anything warning/critical after its
   group completes.
3. COMPLETE THE CHECKLIST: re-read ./health.json — EVERY one of the twenty
   aspects MUST have a verdict. Assess any aspect still "unknown" now; if
   something is genuinely not measurable on this OS, set status "ok" or
   "warning" with value "n/a" and a note explaining why. A finished check
   with any aspect left "unknown" is an incomplete job.
4. REPORT: write two files:
   - `report.md` — a short health report.
   - `report.json` — EXACTLY this JSON (valid JSON, no fences):
{{
  "summary": "2-4 sentence overall health assessment",
  "anomalies": [
    {{"aspect": "which health aspect", "severity": "warning | critical", "finding": "what is wrong, with evidence", "recommendation": "what to do about it"}}
  ],
  "logs_reviewed": [
    {{"source": "log/command", "covers": "time range or 'live'", "note": "one line"}}
  ]
}}
  (empty anomalies array if the server is fully healthy)

Finish only after health.json shows no "unknown" aspects — all twenty
assessed — and both report files are written."""


@dataclass
class SessionState:
    id: str
    server: str
    problem: str
    created_at: float
    status: str = "running"  # running | completed | failed | cancelled
    mode: str = "investigate"  # investigate | healthcheck | remediate
    layers: list[str] = field(default_factory=list)
    depth: str = "standard"
    incident_time: str | None = None
    phase: str | None = None
    duration_ms: int | None = None
    cost_usd: float | None = None
    num_turns: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    events: list[dict] = field(default_factory=list)
    report: dict | None = None
    error: str | None = None
    _cond: asyncio.Condition = field(default_factory=asyncio.Condition)
    _task: asyncio.Task | None = None

    def cancel(self) -> bool:
        if self.status == "running" and self._task is not None:
            self._task.cancel()
            return True
        return False

    @property
    def workdir(self) -> Path:
        return SESSIONS_DIR / self.id

    async def emit(self, event_type: str, data: dict[str, Any]) -> None:
        event = {"type": event_type, "ts": time.time(), **data}
        async with self._cond:
            self.events.append(event)
            self._cond.notify_all()
        try:
            await asyncio.to_thread(db.add_event, self.id, event)
        except Exception:  # noqa: BLE001 - a DB hiccup must not kill the session
            pass

    async def follow(self):
        """Yield stored events, then live events until the session finishes."""
        index = 0
        while True:
            async with self._cond:
                while index >= len(self.events):
                    if self.status != "running":
                        return
                    await self._cond.wait()
                batch = self.events[index:]
                index = len(self.events)
            for event in batch:
                yield event
                if event["type"] in ("completed", "failed"):
                    return

    def to_dict(self, include_events: bool = False) -> dict:
        out = {
            "id": self.id,
            "server": self.server,
            "problem": self.problem,
            "created_at": self.created_at,
            "status": self.status,
            "mode": self.mode,
            "layers": self.layers,
            "depth": self.depth,
            "incident_time": self.incident_time,
            "phase": self.phase,
            "duration_ms": self.duration_ms,
            "cost_usd": self.cost_usd,
            "num_turns": self.num_turns,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "report": self.report,
            "error": self.error,
        }
        if include_events:
            out["events"] = self.events
        return out


SESSIONS: dict[str, SessionState] = {}


def _layer_usage(ds: dict) -> str:
    name, ds_type = ds["name"], ds["type"]
    if ds_type == "zabbix":
        return (
            f"Query with: `python3 -m collectors {name} problems --host <host> --since 6h`, "
            f"`... events --since 6h`, `... hosts --search <name>`, "
            f"`... items --host <host> --search cpu`, `... history --itemid <id> --since 4h`, "
            f"`... raw --method <api.method> --params-json '{{...}}'`"
        )
    if ds_type in ("vmware", "rest"):
        return (
            f"Query with: `python3 -m collectors {name} get <api-path> [--param k=v]` "
            f"(and `post <api-path> --data '<json>'` where the API requires POST)"
        )
    if ds_type == "ssh":
        return f"Query with the wrapper script: `./remote-{name} '<read-only command>'`"
    return ""


def build_layers_section(layer_sources: list[dict]) -> str:
    if not layer_sources:
        return (
            "\n## Additional evidence layers\nNone selected — this investigation "
            "is scoped to the target server only.\n"
        )
    parts = ["\n## Additional evidence layers",
             "The operator selected these extra evidence sources (recent "
             "changes, monitoring history, the virtualization layer and the "
             "network can all hold the real cause). Save each query's output "
             "under ./logs/ with a descriptive name, e.g. `python3 -m "
             "collectors zabbix problems --host web-01 > logs/zabbix_problems.json`.\n"
             "IMPORTANT — protect your turn budget: the affected server itself "
             "is always the PRIMARY evidence; complete that investigation "
             "first. Then query layers in order of relevance to the problem. "
             "If a layer query fails twice (auth error, timeout, unreachable "
             "host), STOP trying that layer, record it as 'unreachable' in "
             "layers_checked, and move on — never let a broken source consume "
             "the investigation."]
    for ds in layer_sources:
        hints = "".join(f"\n  - {h}" for h in ds.get("agent_hints", []))
        parts.append(
            f"\n### {ds['name']}  (layer: {ds.get('layer', 'other')}, type: {ds['type']})\n"
            f"- {ds.get('description', 'no description')}\n"
            f"- {_layer_usage(ds)}"
            + (f"\n- Hints:{hints}" if hints else "")
        )
    parts.append(
        "\nRun `python3 -m collectors list` to re-check what is available. "
        "Credentials are handled inside the collectors — never print "
        "environment variables or ask for tokens."
    )
    return "\n".join(parts) + "\n"


def workdir_section(workdir: Path) -> str:
    return f"""## Working directory — read carefully
Your working directory is: {workdir}
Every relative path in this brief (./logs/, ./health.json, report.md,
report.json, datasources.json) means inside THAT directory. Do not cd away
from it; when in doubt use the absolute paths. The deliverables MUST end up
at exactly:
  {workdir}/health.json
  {workdir}/report.md
  {workdir}/report.json
  {workdir}/logs/<evidence files>
A report or health file written anywhere else is LOST — the operator's
dashboard only reads these exact paths.
"""


def build_history_section(past: list[dict]) -> str:
    """Compact per-server incident memory — a few lines, high signal."""
    if not past:
        return ""
    lines = ["\n## Known history of this server (previous confirmed investigations)"]
    for p in past:
        when = time.strftime("%Y-%m-%d", time.localtime(p["created_at"]))
        lines.append(
            f'- {when} ({p["confidence"]} confidence) — problem: "{p["problem"]}" '
            f"— root cause: {p['cause']}"
        )
    lines.append(
        "Use this as investigative context: early on, verify whether "
        "previously-implicated components (configs, certs, policies, services) "
        "are still or again in a bad state, and check what changed since "
        "(package/dnf/apt history, config mtimes). Do NOT assume the same "
        "cause — verify against current evidence."
    )
    return "\n".join(lines) + "\n"


def build_prompt(
    server: Server,
    problem: str,
    layer_sources: list[dict] | None = None,
    depth: str = "standard",
    incident_time: str | None = None,
    workdir: Path | None = None,
    past: list[dict] | None = None,
) -> str:
    hints = "\n".join(f"  - {h}" for h in server.log_hints) or "  - (none provided; discover them)"
    services = ", ".join(server.services) or "(unknown)"
    layers_section = build_layers_section(layer_sources or [])
    history_section = build_history_section(past or [])
    depth_guidance = DEPTH_GUIDANCE.get(depth, DEPTH_GUIDANCE["standard"])
    if incident_time:
        submitted = time.strftime("%Y-%m-%d %H:%M:%S %Z")
        incident_line = (
            f'\nOperator-estimated problem start time: "{incident_time}" '
            f"(free-form text, written at {submitted} — resolve relative "
            "phrases like '1 hour ago' or 'yesterday evening' against that "
            "submission time, and verify against the server clock). Treat it "
            "as a strong hint, not a fact: begin your log review AT LEAST "
            "30 minutes BEFORE this time, and still verify the actual failure "
            "timestamp yourself in the PINPOINT step (operator estimates are "
            "often late — users notice problems after they start)."
        )
    else:
        incident_line = (
            "\nThe operator did not provide a start time — determining WHEN the "
            "problem began is part of your job (PINPOINT step)."
        )
    # NOTE: this prompt is deliberately the lean v2.4.1 shape — no health
    # checklist, no phase markers, no script library, no extra duties. Field
    # experience showed side-quests dilute the root-cause hunt (e.g. the agent
    # assesses patching/firewall instead of running `dnf history`). Keep it
    # focused; auxiliary features live in healthcheck mode.
    return f"""You are an SRE troubleshooting agent investigating a production incident.

## Target server
- Name: {server.name} ({server.description or "no description"})
- OS: {server.os or "unknown"}
- Key services: {services}
- Connect with EXACTLY this command prefix for every remote command:
  `{server.ssh_command()} '<remote command>'`
- Known log locations / hints:
{hints}
{layers_section}
## Problem statement (from the operator)
{problem}
{incident_line}
{history_section}
## Investigation depth
{depth_guidance}

## Hard rules
- READ-ONLY on the remote server. You may run diagnostic and log-reading
  commands only (cat, tail, grep, journalctl, systemctl status, df, free,
  ps, top -b -n1, ss, netstat, dmesg, uptime, etc.). NEVER restart services,
  edit files, delete anything, or change any state on the remote host.
- Save everything you collect into ./logs/ in your working directory so the
  operator can review the raw evidence later.
- If the server is unreachable, report that clearly as the finding instead of
  guessing.

## Workflow
1. TRIAGE: from the problem statement, decide which services, logs, metrics
   AND evidence layers are relevant. Post a short plan listing what you will
   check in each selected layer.
2. PINPOINT THE FAILURE TIME — do this BEFORE pulling any logs. The incident
   may be hours or days old; the operator's timing information may be vague
   or wrong. Establish when the affected service actually stopped working:
   - `systemctl status <service>` (the "Active: ... since <timestamp>" line)
     and `systemctl show <service> -p ActiveState,InactiveEnterTimestamp,ExecMainStartTimestamp,NRestarts`
   - the LAST lines of the service's own log (when did it stop writing?)
   - `journalctl -u <service> -n 50` and file mtimes
     (`ls -l --time-style=full-iso /var/log/...`)
   - process start times (`ps -eo pid,lstart,cmd | grep <svc>`), `uptime`
   State the failure timestamp explicitly before moving on.
3. COLLECT — server first: use the log-collector subagent (or do it directly)
   to pull the relevant server logs and diagnostics over SSH into ./logs/.
   ANCHOR EVERY EXTRACT TO THE FAILURE TIMESTAMP FROM STEP 2, NEVER TO THE
   CURRENT TIME: the window that matters runs from ~60 minutes BEFORE the
   failure to ~15 minutes after it (the cause precedes the failure; what
   happened afterwards is mostly symptoms and noise).
   - `journalctl --since '<failure minus 60min>' --until '<failure plus 15min>'`
   - grep plain log files by the timestamp prefixes of that window
   - `tail -n` alone is NOT sufficient — after collecting, CHECK the first
     and last timestamps of each extract actually cover the failure window,
     and re-collect with a wider window or timestamp grep if they don't.
   This is the primary evidence — finish it before touching other layers.
   Prefer targeted extracts over whole multi-GB files.
   Then enrich from the selected evidence layers via the collectors CLI /
   layer wrappers (fail fast on broken sources — two failed attempts max per
   layer), querying the SAME time window around the failure, saving all
   outputs into ./logs/.
4. ANALYZE: use the log-analyzer subagent to correlate timestamps ACROSS ALL
   collected files — server logs, monitoring alerts, change records,
   virtualization events, network logs — identify the failure chain, and
   separate root cause from symptoms. Pay special attention to changes or
   events in the 60 minutes immediately preceding the failure timestamp.
   State clearly which layer the root cause lives in.
5. REPORT: write two files in the working directory:
   - `report.md` — a readable incident report for the operator.
   - `report.json` — EXACTLY this JSON structure (valid JSON, no markdown
     fences, no comments). Populate `incident_timeline` with the key events
     in chronological order (normal state → first anomaly → escalation →
     failure → aftermath), each tied to its source log. Populate
     `logs_reviewed` with EVERY log file, journal unit and layer API you
     actually examined — including ones that showed nothing relevant — and
     the time range each reviewed extract covered:
{REPORT_SCHEMA}
{REMEDIATION_RULES}
Finish only after both report files are written."""


def _agent_definitions():
    # Imported lazily with the SDK so the web app can start without it installed.
    from claude_agent_sdk import AgentDefinition

    return {
        "log-collector": AgentDefinition(
            description=(
                "Collects evidence: server logs and diagnostics over SSH, plus "
                "monitoring/virtualization/ITSM/network data via the collectors "
                "CLI (python3 -m collectors ...). Use for pulling everything "
                "into the local ./logs/ directory."
            ),
            prompt=(
                "You collect evidence from a remote Linux server over SSH using the "
                "exact ssh command prefix given in the task. You are strictly "
                "read-only on the remote host: only run commands that read logs or "
                "system state. Save every output into the local ./logs/ directory "
                "with descriptive filenames (e.g. logs/nginx_error_last2h.log, "
                "logs/journal_gunicorn.log, logs/df_h.txt). Pull targeted extracts, "
                "not entire huge files. CRITICAL: anchor extracts to the incident/"
                "failure timestamp given in the task, never to the current time — "
                "use `journalctl --since/--until` bracketing that timestamp and "
                "grep files by its timestamp prefix; then verify each extract's "
                "first/last lines actually cover the failure window and re-collect "
                "wider if not (`tail -n` alone often misses old incidents). When "
                "done, list what you collected and any commands that failed."
            ),
            tools=["Bash", "Write", "Read"],
        ),
        "log-analyzer": AgentDefinition(
            description=(
                "Analyzes already-collected log files in ./logs/ to find the root "
                "cause of an incident. Use after logs have been collected."
            ),
            prompt=(
                "You are an expert log analyst. Work only on local files under "
                "./logs/ — do not SSH anywhere. Build a timeline of events across "
                "all files, correlate errors with resource metrics, distinguish the "
                "root cause from downstream symptoms, and state your confidence. "
                "Quote the exact log lines that support each conclusion, with file "
                "names."
            ),
            tools=["Read", "Grep", "Glob", "Bash"],
        ),
    }


def _write_datasources_json(workdir: Path, layer_sources: list[dict]) -> None:
    """Config for the collectors CLI. Contains env var NAMES, never secrets."""
    api_sources = [ds for ds in layer_sources if ds.get("type") != "ssh"]
    (workdir / "datasources.json").write_text(
        json.dumps({"datasources": api_sources}, indent=2)
    )


def _write_layer_wrappers(workdir: Path, layer_sources: list[dict]) -> None:
    """One ./remote-<name> wrapper per ssh-type evidence source."""
    for ds in layer_sources:
        if ds.get("type") != "ssh":
            continue
        srv = Server(
            name=ds["name"],
            host=ds["host"],
            user=ds["user"],
            port=int(ds.get("port", 22)),
            ssh_key=ds.get("ssh_key"),
        )
        ssh_parts = [
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=accept-new",
        ]
        if srv.ssh_key:
            ssh_parts += ["-i", srv.ssh_key]
        if srv.port != 22:
            ssh_parts += ["-p", str(srv.port)]
        ssh_parts.append(f"{srv.user}@{srv.host}")
        ssh_array = " ".join(f"'{p}'" for p in ssh_parts)
        script = f"""#!/usr/bin/env bash
# Read-only diagnostics on evidence source {srv.name}. Usage: ./remote-{srv.name} '<command>'
set -o pipefail
CMD="${{1:?usage: ./remote-{srv.name} '<command>'}}"
SSH=({ssh_array})
exec "${{SSH[@]}}" "bash -c $(printf '%q' "$CMD")"
"""
        path = workdir / f"remote-{srv.name}"
        path.write_text(script)
        path.chmod(0o700)


async def run_session(
    state: SessionState,
    server: Server,
    layer_sources: list[dict] | None = None,
    remediation: dict | None = None,
) -> None:
    try:
        from claude_agent_sdk import ClaudeAgentOptions, query
        from claude_agent_sdk.types import (
            AssistantMessage,
            ResultMessage,
            TextBlock,
            ToolUseBlock,
        )
    except ImportError:
        state.status = "failed"
        state.error = (
            "claude-agent-sdk is not installed. Run: pip install claude-agent-sdk "
            "(and make sure the Claude Code CLI is installed and logged in)."
        )
        await state.emit("failed", {"error": state.error})
        return

    workdir = state.workdir
    (workdir / "logs").mkdir(parents=True, exist_ok=True)
    layer_sources = layer_sources or []
    _write_layer_wrappers(workdir, layer_sources)
    _write_datasources_json(workdir, layer_sources)

    # PYTHONPATH lets the agent run `python3 -m collectors ...` from the
    # session dir; secrets stay in this process's env (inherited), referenced
    # by name only.
    env: dict[str, str] = {"PYTHONPATH": str(BASE_DIR)}

    # Capture the Claude Code CLI's stderr — the only place startup problems
    # (auth, network, CLI errors) are visible when a session hangs silently.
    stderr_path = workdir / "claude-stderr.log"
    stderr_file = open(stderr_path, "a", buffering=1)

    def _on_stderr(line: str) -> None:
        stderr_file.write(line.rstrip("\n") + "\n")

    if state.mode == "healthcheck":
        max_turns = 32  # twenty aspects now — a few extra turns for the deeper sweep
    elif state.mode == "remediate":
        max_turns = 40
    else:
        max_turns = DEPTH_TURNS.get(state.depth, DEPTH_TURNS["standard"])
    if os.environ.get("TROUBLESHOOTER_MAX_TURNS"):
        max_turns = min(max_turns, int(os.environ["TROUBLESHOOTER_MAX_TURNS"]))

    # Script library is for health checks only: investigations generate their
    # diagnostics from scratch (operator decision — a reused generic sweep can
    # anchor an investigation on recent-window data and hurt RCA quality).
    scriptlib_dirs = [str(ensure_scriptlib())] if state.mode == "healthcheck" else []
    options = ClaudeAgentOptions(
        env=env,
        stderr=_on_stderr,
        add_dirs=scriptlib_dirs,
        cwd=str(workdir),
        system_prompt=(
            "You are an autonomous infrastructure troubleshooting agent running in "
            "a headless pipeline. Nobody can answer questions mid-run: never ask "
            "for confirmation, just proceed within the stated read-only rules."
        ),
        allowed_tools=["Bash", "Read", "Write", "Grep", "Glob", "TodoWrite", "Task"],
        disallowed_tools=["WebSearch", "WebFetch"],
        permission_mode="acceptEdits",
        agents=_agent_definitions(),
        max_turns=max_turns,
        model=os.environ.get("TROUBLESHOOTER_MODEL") or None,
    )

    await state.emit(
        "started",
        {
            "server": server.name,
            "workdir": str(workdir),
            "layers": [ds["name"] for ds in layer_sources],
            "depth": state.depth,
        },
    )

    got_first_message = asyncio.Event()

    async def _startup_watchdog() -> None:
        try:
            await asyncio.wait_for(got_first_message.wait(), timeout=120)
        except asyncio.TimeoutError:
            await state.emit("agent_text", {"text": (
                "⚠ No output from the Claude Code process for 2 minutes. "
                "Likely causes: Claude Code is not logged in for the account "
                "running this service (test with: claude -p 'say ok'), no "
                "network path to the Claude API, or a CLI update/consent "
                f"prompt. Check {stderr_path} for the CLI's own errors. "
                "The session will keep waiting; cancel it if this persists."
            )})

    watchdog = asyncio.create_task(_startup_watchdog())
    timeout_s = int(os.environ.get("TROUBLESHOOTER_SESSION_TIMEOUT", "3600"))

    health_path = workdir / "health.json"

    def _read_health() -> dict | None:
        try:
            return json.loads(health_path.read_text())
        except (OSError, json.JSONDecodeError):
            return None

    async def _health_watcher() -> None:
        last: str | None = None
        while True:
            await asyncio.sleep(2)
            try:
                text = health_path.read_text()
            except OSError:
                continue
            if text != last:
                last = text
                health = _read_health()
                if health:
                    await state.emit("health", {"health": health})

    health_watcher = asyncio.create_task(_health_watcher())

    try:
        if state.mode == "healthcheck":
            prompt = build_healthcheck_prompt(server, workdir=workdir)
        elif state.mode == "remediate":
            prompt = build_remediation_prompt(server, remediation or {}, workdir)
        else:
            try:
                past = await asyncio.to_thread(db.past_incidents, server.name, state.id)
            except Exception:  # noqa: BLE001
                past = []
            prompt = build_prompt(
                server,
                state.problem,
                layer_sources=layer_sources,
                depth=state.depth,
                incident_time=state.incident_time,
                workdir=workdir,
                past=past,
            )
        # Debug artifacts: exactly what this run was asked to do (no secrets)
        (workdir / "prompt.txt").write_text(prompt)
        (workdir / "meta.json").write_text(json.dumps({
            "session": state.id,
            "server": server.name,
            "mode": state.mode,
            "created_at": state.created_at,
            "depth": state.depth,
            "max_turns": max_turns,
            "layers": [ds["name"] for ds in layer_sources],
            "incident_time": state.incident_time,
        }, indent=2))
        deadline = time.monotonic() + timeout_s
        phase_re = re.compile(r"^\s*PHASE:\s*([A-Za-z]+)\s*$", re.MULTILINE)
        async for message in query(prompt=prompt, options=options):
            got_first_message.set()
            if time.monotonic() > deadline:
                raise TimeoutError(
                    f"Session exceeded TROUBLESHOOTER_SESSION_TIMEOUT ({timeout_s}s)"
                )
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock) and block.text.strip():
                        text = block.text
                        m = phase_re.search(text)
                        if m:
                            state.phase = m.group(1).lower()
                            await state.emit("phase", {"phase": state.phase})
                            try:
                                await asyncio.to_thread(db.session_phase, state.id, state.phase)
                            except Exception:  # noqa: BLE001
                                pass
                            text = phase_re.sub("", text).strip()
                        if text:
                            await state.emit("agent_text", {"text": text})
                    elif isinstance(block, ToolUseBlock):
                        await state.emit(
                            "tool_use",
                            {"tool": block.name, "input": _summarize_input(block.name, block.input)},
                        )
            elif isinstance(message, ResultMessage):
                state.duration_ms = message.duration_ms
                state.cost_usd = message.total_cost_usd
                state.num_turns = message.num_turns
                usage = getattr(message, "usage", None) or {}
                # total input = fresh + cache-created + cache-read tokens
                state.input_tokens = (usage.get("input_tokens", 0)
                                      + usage.get("cache_creation_input_tokens", 0)
                                      + usage.get("cache_read_input_tokens", 0)) or None
                state.output_tokens = usage.get("output_tokens") or None
                if message.is_error:
                    state.status = "failed"
                    if message.subtype == "error_max_turns":
                        state.error = (
                            "Ran out of investigation turns before finishing. "
                            "Re-run with Deep depth, or deselect evidence "
                            "layers that aren't relevant to this problem."
                        )
                    else:
                        state.error = message.result or message.subtype
                    # Surface whatever report was written before the run died
                    # (e.g. when the max-turns cap hits after the report step).
                    report = _load_report(workdir, allow_empty=True)
                    if report:
                        state.report = report
                    await state.emit("failed", {"error": state.error, "report": report})
                    return
    except asyncio.CancelledError:
        state.status = "cancelled"
        state.error = "Cancelled by the operator"
        report = _load_report(workdir, allow_empty=True)
        if report:
            state.report = report
        await state.emit("failed", {"error": state.error, "report": report})
        return
    except Exception as exc:  # noqa: BLE001 - surface any agent failure to the UI
        state.status = "failed"
        state.error = f"{type(exc).__name__}: {exc}"
        await state.emit("failed", {"error": state.error})
        return
    finally:
        watchdog.cancel()
        health_watcher.cancel()
        stderr_file.close()
        # Final health snapshot — the 2s watcher can miss the last write
        final_health = _read_health()
        if final_health and state.mode == "healthcheck":
            # backstop: every tracked aspect gets an explicit verdict so the
            # dashboard and history never show silent gaps
            checks = final_health.setdefault("checks", {})
            for aspect in HEALTH_ASPECTS:
                cur = checks.get(aspect) or {}
                if (cur.get("status") or "unknown") == "unknown":
                    checks[aspect] = {"status": "unknown", "value": "not assessed",
                                      "note": cur.get("note") or
                                      "the agent did not assess this aspect"}
            with contextlib.suppress(OSError):
                health_path.write_text(json.dumps(final_health, indent=1))
        if final_health:
            await state.emit("health", {"health": final_health})
            try:
                await asyncio.to_thread(
                    db.add_health_snapshot, state.id, state.server,
                    final_health.get("checks") or {},
                )
            except Exception:  # noqa: BLE001
                pass
        _write_outcome(state)

    state.report = _load_report(workdir)
    state.status = "completed"
    _write_outcome(state)
    await state.emit("completed", {"report": state.report})


def _summarize_input(tool: str, tool_input: dict) -> str:
    if tool == "Bash":
        return str(tool_input.get("command", ""))[:500]
    if tool in ("Read", "Write", "Edit"):
        return str(tool_input.get("file_path", ""))
    if tool == "Task":
        return f"{tool_input.get('subagent_type', 'agent')}: {str(tool_input.get('description', ''))[:200]}"
    if tool == "Grep":
        return str(tool_input.get("pattern", ""))[:200]
    return json.dumps(tool_input, default=str)[:300]


def _load_report(workdir: Path, allow_empty: bool = False) -> dict:
    report: dict = {}
    json_path = workdir / "report.json"
    md_path = workdir / "report.md"
    if json_path.exists():
        try:
            report = json.loads(json_path.read_text())
        except (json.JSONDecodeError, OSError):
            report = {}
    if md_path.exists():
        try:
            report["markdown"] = md_path.read_text()
        except OSError:
            pass
    if not report and not allow_empty:
        report = {"summary": "The agent finished but did not produce report files.", "confidence": "low"}
    return report


def _write_outcome(state: SessionState) -> None:
    """Persist the run outcome (disk + database)."""
    if state.status == "running":
        return
    try:
        db.session_finished(state.to_dict())
    except Exception:  # noqa: BLE001
        pass
    try:
        (state.workdir / "outcome.json").write_text(json.dumps({
            "session": state.id,
            "server": state.server,
            "mode": state.mode,
            "status": state.status,
            "created_at": state.created_at,
            "duration_ms": state.duration_ms,
            "cost_usd": state.cost_usd,
            "num_turns": state.num_turns,
            "input_tokens": state.input_tokens,
            "output_tokens": state.output_tokens,
            "confidence": (state.report or {}).get("confidence"),
            "root_cause_layer": (state.report or {}).get("root_cause_layer"),
        }, indent=2))
    except OSError:
        pass


def scan_fleet() -> dict:
    """Per-server last-known state + global stats, from disk (survives restarts)
    merged with in-memory running sessions."""
    latest: dict[str, dict] = {}
    latest_checks: dict[str, dict] = {}   # newest health.json per server, any session
    stats = {"total": 0, "completed": 0, "failed": 0, "running": 0,
             "high_confidence": 0, "cost_usd": 0.0, "healthchecks": 0,
             "tokens_in": 0, "tokens_out": 0}
    if SESSIONS_DIR.exists():
        for d in SESSIONS_DIR.iterdir():
            meta_path = d / "meta.json"
            if not d.is_dir() or not meta_path.exists():
                continue
            try:
                meta = json.loads(meta_path.read_text())
            except (OSError, json.JSONDecodeError):
                continue

            def _load(name: str) -> dict:
                try:
                    return json.loads((d / name).read_text())
                except (OSError, json.JSONDecodeError):
                    return {}

            outcome = _load("outcome.json")
            health = _load("health.json")
            sid = meta.get("session") or d.name
            live = SESSIONS.get(sid)
            status = live.status if live else outcome.get("status", "unknown")
            created = meta.get("created_at") or d.stat().st_mtime

            stats["total"] += 1
            if status == "running":
                stats["running"] += 1
            elif status == "completed":
                stats["completed"] += 1
            elif status in ("failed", "cancelled"):
                stats["failed"] += 1
            if meta.get("mode") == "healthcheck":
                stats["healthchecks"] += 1
            if outcome.get("cost_usd"):
                stats["cost_usd"] += float(outcome["cost_usd"])
            stats["tokens_in"] += int(outcome.get("input_tokens") or 0)
            stats["tokens_out"] += int(outcome.get("output_tokens") or 0)
            if outcome.get("confidence") == "high":
                stats["high_confidence"] += 1

            server = meta.get("server")
            if not server:
                continue
            entry = {
                "session": sid,
                "created_at": created,
                "mode": meta.get("mode", "investigate"),
                "status": status,
                "checks": health.get("checks"),
            }
            if server not in latest or created > latest[server]["created_at"]:
                latest[server] = entry
            if health.get("checks") and (
                    server not in latest_checks or created > latest_checks[server]["ts"]):
                latest_checks[server] = {"ts": created, "session": sid,
                                         "checks": health["checks"]}
    stats["cost_usd"] = round(stats["cost_usd"], 2)
    return {"latest": latest, "latest_checks": latest_checks, "stats": stats}


def start_session(
    server: Server,
    problem: str,
    layer_sources: list[dict] | None = None,
    depth: str = "standard",
    incident_time: str | None = None,
    mode: str = "investigate",
    remediation: dict | None = None,
) -> SessionState:
    state = SessionState(
        id=uuid.uuid4().hex[:12],
        server=server.name,
        problem=problem,
        created_at=time.time(),
        mode=mode if mode in ("investigate", "healthcheck", "remediate") else "investigate",
        layers=[ds["name"] for ds in (layer_sources or [])],
        depth=depth if depth in DEPTH_TURNS else "standard",
        incident_time=incident_time,
    )
    SESSIONS[state.id] = state
    state.workdir.mkdir(parents=True, exist_ok=True)
    try:
        db.session_started(state.to_dict())
    except Exception:  # noqa: BLE001 - a DB outage must not block investigations
        pass
    state._task = asyncio.get_running_loop().create_task(
        run_session(state, server, layer_sources, remediation)
    )
    return state
