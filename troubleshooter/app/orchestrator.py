"""Runs troubleshooting sessions by driving Claude Code through the Claude Agent SDK.

Each session gets its own working directory under data/sessions/<id>/ where the
agent stores collected logs and writes the final report (report.json + report.md).
The SDK talks to the locally installed, already-authenticated Claude Code — no
API key is needed on a machine where `claude` is logged in.
"""

import asyncio
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .inventory import BASE_DIR, Server

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
  "impact": "what is affected and how badly",
  "recommended_fix": ["ordered, concrete remediation steps with exact commands where possible"],
  "preventive_measures": ["changes that would stop this recurring (monitoring, config, capacity...)"],
  "needs_followup": ["open questions or data that could not be collected, if any"]
}"""


DEPTH_TURNS = {"quick": 35, "standard": 90, "deep": 160}

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


@dataclass
class SessionState:
    id: str
    server: str
    problem: str
    created_at: float
    status: str = "running"  # running | completed | failed | cancelled
    layers: list[str] = field(default_factory=list)
    depth: str = "standard"
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
            "layers": self.layers,
            "depth": self.depth,
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


def build_prompt(
    server: Server,
    problem: str,
    sudo_available: bool = False,
    layer_sources: list[dict] | None = None,
    depth: str = "standard",
) -> str:
    hints = "\n".join(f"  - {h}" for h in server.log_hints) or "  - (none provided; discover them)"
    services = ", ".join(server.services) or "(unknown)"
    layers_section = build_layers_section(layer_sources or [])
    depth_guidance = DEPTH_GUIDANCE.get(depth, DEPTH_GUIDANCE["standard"])
    if sudo_available:
        access = """- Run every remote command through the wrapper script in your working directory:
  `./remote '<remote command>'`
- If (and only if) a command fails with "Permission denied" or needs elevated
  privileges to read a log, retry it through the sudo wrapper:
  `./remote-sudo '<remote command>'`
  Sudo authentication is handled inside the wrapper. Never print, read, or
  reference the TS_SUDO_PASS environment variable, and do not cat or modify
  the wrapper scripts. Sudo does NOT relax the read-only rule below."""
    else:
        access = """- Run every remote command through the wrapper script in your working directory:
  `./remote '<remote command>'`
- sudo is NOT available on this server; if a log needs elevated privileges,
  note it in the report under needs_followup instead of trying workarounds."""
    return f"""You are an SRE troubleshooting agent investigating a production incident.

## Target server
- Name: {server.name} ({server.description or "no description"})
- OS: {server.os or "unknown"}
- Key services: {services}
{access}
- Known log locations / hints:
{hints}
{layers_section}
## Problem statement (from the operator)
{problem}

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
2. COLLECT — server first: use the log-collector subagent (or do it directly)
   to pull the relevant server logs and diagnostics over SSH into ./logs/.
   This is the primary evidence — finish it before touching other layers.
   Prefer targeted extracts (last few hours, grep for errors, around the
   incident time) over whole multi-GB files. Use `tail -n`, `grep`,
   `journalctl --since` etc.
   Then enrich from the selected evidence layers via the collectors CLI /
   layer wrappers (fail fast on broken sources — two failed attempts max per
   layer), saving all outputs into ./logs/.
3. ANALYZE: use the log-analyzer subagent to correlate timestamps ACROSS ALL
   collected files — server logs, monitoring alerts, change records,
   virtualization events, network logs — identify the failure chain, and
   separate root cause from symptoms. Pay special attention to changes or
   events that immediately precede the incident start. State clearly which
   layer the root cause lives in.
4. REPORT: write two files in the working directory:
   - `report.md` — a readable incident report for the operator.
   - `report.json` — EXACTLY this JSON structure (valid JSON, no markdown
     fences, no comments):
{REPORT_SCHEMA}

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
                "You collect evidence from a remote Linux server using the ./remote "
                "wrapper script from the working directory (and ./remote-sudo when "
                "the task says sudo is available and a file needs elevated read "
                "access). Never print or inspect the TS_SUDO_PASS environment "
                "variable or the wrapper scripts themselves. You are strictly "
                "read-only on the remote host: only run commands that read logs or "
                "system state. Save every output into the local ./logs/ directory "
                "with descriptive filenames (e.g. logs/nginx_error_last2h.log, "
                "logs/journal_gunicorn.log, logs/df_h.txt). Pull targeted extracts, "
                "not entire huge files. When done, list what you collected and any "
                "commands that failed."
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


def _write_wrappers(workdir: Path, server: Server, with_sudo: bool) -> None:
    """Write per-session SSH wrapper scripts.

    The agent only ever calls ./remote / ./remote-sudo. The sudo password is
    NOT stored in the scripts or anywhere on disk — ./remote-sudo reads it
    from the TS_SUDO_PASS environment variable, which the backend injects
    into the Claude Code subprocess for this session only.
    """
    ssh_parts = [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new",
    ]
    if server.ssh_key:
        ssh_parts += ["-i", server.ssh_key]
    if server.port != 22:
        ssh_parts += ["-p", str(server.port)]
    ssh_parts.append(f"{server.user}@{server.host}")
    ssh_array = " ".join(f"'{p}'" for p in ssh_parts)

    remote = f"""#!/usr/bin/env bash
# Run a read-only diagnostic command on {server.name}. Usage: ./remote '<command>'
set -o pipefail
CMD="${{1:?usage: ./remote '<command>'}}"
SSH=({ssh_array})
exec "${{SSH[@]}}" "bash -c $(printf '%q' "$CMD")"
"""
    path = workdir / "remote"
    path.write_text(remote)
    path.chmod(0o700)

    if with_sudo:
        remote_sudo = f"""#!/usr/bin/env bash
# Run a read-only diagnostic command on {server.name} under sudo.
# Usage: ./remote-sudo '<command>'  (password comes from TS_SUDO_PASS, never stored)
set -o pipefail
CMD="${{1:?usage: ./remote-sudo '<command>'}}"
if [ -z "$TS_SUDO_PASS" ]; then echo "no sudo password configured for this session" >&2; exit 1; fi
SSH=({ssh_array})
printf '%s\\n' "$TS_SUDO_PASS" | exec "${{SSH[@]}}" "sudo -S -p '' -- bash -c $(printf '%q' "$CMD")"
"""
        path = workdir / "remote-sudo"
        path.write_text(remote_sudo)
        path.chmod(0o700)


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
    sudo_password: str | None = None,
    layer_sources: list[dict] | None = None,
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
    sudo_available = bool(sudo_password)
    layer_sources = layer_sources or []
    _write_wrappers(workdir, server, with_sudo=sudo_available)
    _write_layer_wrappers(workdir, layer_sources)
    _write_datasources_json(workdir, layer_sources)

    # PYTHONPATH lets the agent run `python3 -m collectors ...` from the
    # session dir; secrets stay in this process's env (inherited), referenced
    # by name only.
    env: dict[str, str] = {"PYTHONPATH": str(BASE_DIR)}
    if sudo_available:
        env["TS_SUDO_PASS"] = sudo_password

    max_turns = DEPTH_TURNS.get(state.depth, DEPTH_TURNS["standard"])
    if os.environ.get("TROUBLESHOOTER_MAX_TURNS"):
        max_turns = min(max_turns, int(os.environ["TROUBLESHOOTER_MAX_TURNS"]))

    options = ClaudeAgentOptions(
        env=env,
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
            "sudo": sudo_available,
            "layers": [ds["name"] for ds in layer_sources],
            "depth": state.depth,
        },
    )

    try:
        prompt = build_prompt(
            server,
            state.problem,
            sudo_available=sudo_available,
            layer_sources=layer_sources,
            depth=state.depth,
        )
        async for message in query(prompt=prompt, options=options):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock) and block.text.strip():
                        await state.emit("agent_text", {"text": block.text})
                    elif isinstance(block, ToolUseBlock):
                        await state.emit(
                            "tool_use",
                            {"tool": block.name, "input": _summarize_input(block.name, block.input)},
                        )
            elif isinstance(message, ResultMessage):
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

    state.report = _load_report(workdir)
    state.status = "completed"
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


def start_session(
    server: Server,
    problem: str,
    sudo_password: str | None = None,
    layer_sources: list[dict] | None = None,
    depth: str = "standard",
) -> SessionState:
    # The sudo password is deliberately NOT stored on SessionState (it would
    # leak into /api/sessions responses and events); it lives only in the
    # closure of this one run and the agent subprocess environment.
    state = SessionState(
        id=uuid.uuid4().hex[:12],
        server=server.name,
        problem=problem,
        created_at=time.time(),
        layers=[ds["name"] for ds in (layer_sources or [])],
        depth=depth if depth in DEPTH_TURNS else "standard",
    )
    SESSIONS[state.id] = state
    state.workdir.mkdir(parents=True, exist_ok=True)
    state._task = asyncio.get_running_loop().create_task(
        run_session(state, server, sudo_password, layer_sources)
    )
    return state
