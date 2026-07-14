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
  "confidence": "high | medium | low",
  "evidence": [
    {"source": "file or command the evidence came from", "finding": "what it shows"}
  ],
  "impact": "what is affected and how badly",
  "recommended_fix": ["ordered, concrete remediation steps with exact commands where possible"],
  "preventive_measures": ["changes that would stop this recurring (monitoring, config, capacity...)"],
  "needs_followup": ["open questions or data that could not be collected, if any"]
}"""


@dataclass
class SessionState:
    id: str
    server: str
    problem: str
    created_at: float
    status: str = "running"  # running | completed | failed
    events: list[dict] = field(default_factory=list)
    report: dict | None = None
    error: str | None = None
    _cond: asyncio.Condition = field(default_factory=asyncio.Condition)

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
            "report": self.report,
            "error": self.error,
        }
        if include_events:
            out["events"] = self.events
        return out


SESSIONS: dict[str, SessionState] = {}


def build_prompt(server: Server, problem: str, sudo_available: bool = False) -> str:
    hints = "\n".join(f"  - {h}" for h in server.log_hints) or "  - (none provided; discover them)"
    services = ", ".join(server.services) or "(unknown)"
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

## Problem statement (from the operator)
{problem}

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
1. TRIAGE: from the problem statement, decide which services, logs and system
   metrics are relevant. Post a short plan.
2. COLLECT: use the log-collector subagent (or do it directly) to pull the
   relevant logs and diagnostics over SSH into ./logs/. Prefer targeted
   extracts (last few hours, grep for errors, around the incident time) over
   whole multi-GB files. Use `tail -n`, `grep`, `journalctl --since` etc.
3. ANALYZE: use the log-analyzer subagent to correlate timestamps across the
   collected files, identify the failure chain, and separate root cause from
   symptoms.
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
                "Collects logs and diagnostics from a remote server over SSH. "
                "Use for pulling log files, journalctl output, and system state "
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


async def run_session(state: SessionState, server: Server, sudo_password: str | None = None) -> None:
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
    _write_wrappers(workdir, server, with_sudo=sudo_available)

    options = ClaudeAgentOptions(
        env={"TS_SUDO_PASS": sudo_password} if sudo_available else {},
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
        max_turns=int(os.environ.get("TROUBLESHOOTER_MAX_TURNS", "80")),
        model=os.environ.get("TROUBLESHOOTER_MODEL") or None,
    )

    await state.emit(
        "started",
        {"server": server.name, "workdir": str(workdir), "sudo": sudo_available},
    )

    try:
        prompt = build_prompt(server, state.problem, sudo_available=sudo_available)
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
                    state.error = message.result or message.subtype
                    # Surface whatever report was written before the run died
                    # (e.g. when the max-turns cap hits after the report step).
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


def start_session(server: Server, problem: str, sudo_password: str | None = None) -> SessionState:
    # The sudo password is deliberately NOT stored on SessionState (it would
    # leak into /api/sessions responses and events); it lives only in the
    # closure of this one run and the agent subprocess environment.
    state = SessionState(
        id=uuid.uuid4().hex[:12],
        server=server.name,
        problem=problem,
        created_at=time.time(),
    )
    SESSIONS[state.id] = state
    state.workdir.mkdir(parents=True, exist_ok=True)
    asyncio.get_running_loop().create_task(run_session(state, server, sudo_password))
    return state
