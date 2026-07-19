"""Change implementation plans: storage, AI refinement, and the execution gate.

The change implementer executes ONLY what the approved plan says, in order:

- Plan storage: data/changeplans/<change_id>.json — the machine-readable plan
  (steps with commands, downtime flags, risk) plus execution state
  (current_step pointer, per-step results). The human-readable version lives
  in the CR itself; this file is what the implementer enforces against.

- refine_plan(): a one-turn Claude pass converts a pasted implementation-plan
  document (any org template) into structured steps, verifies each step's
  downtime claim, and suggests improvements (missing backups, missing
  verification, wrong ordering). No tools, bounded time; if the AI is
  unavailable a plain line-per-step fallback is produced so the flow never
  hard-depends on the model.

- The gate (check_command): a command is allowed iff it is the CURRENT step's
  exact command (whitespace-normalised), a re-run of an already-completed
  step, or classified read-only by the deterministic policy in cmdreview.
  Anything else is refused server-side — the UI never gets to decide.
"""

import asyncio
import json
import re
import time

from .cmdreview import classify
from .inventory import BASE_DIR

PLANS_DIR = BASE_DIR / "data" / "changeplans"


def _path(change_id: str):
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", str(change_id))[:64]
    return PLANS_DIR / f"{safe}.json"


def load_plan(change_id: str) -> dict | None:
    try:
        return json.loads(_path(change_id).read_text())
    except (OSError, json.JSONDecodeError):
        return None


def save_plan(change_id: str, plan: dict) -> dict:
    PLANS_DIR.mkdir(parents=True, exist_ok=True)
    plan.setdefault("change_id", str(change_id))
    plan.setdefault("current_step", 0)      # number of COMPLETED steps
    plan.setdefault("results", {})
    plan.setdefault("created_at", time.time())
    _path(change_id).write_text(json.dumps(plan, indent=1, default=str))
    return plan


def _norm_cmd(cmd: str) -> str:
    return " ".join(str(cmd or "").split())


def check_command(plan: dict | None, command: str) -> dict:
    """The deterministic gate. Returns {allowed, kind, step_order?, reason}."""
    cmd = _norm_cmd(command)
    if not cmd:
        return {"allowed": False, "kind": "empty", "reason": "Empty command"}
    steps = (plan or {}).get("steps") or []
    done = int((plan or {}).get("current_step") or 0)
    for s in steps:
        if _norm_cmd(s.get("command")) == cmd:
            order = int(s.get("order") or 0)
            if order == done + 1:
                return {"allowed": True, "kind": "plan-step", "step_order": order,
                        "reason": f"step {order} of the approved plan (current step)"}
            if order <= done:
                return {"allowed": True, "kind": "plan-rerun", "step_order": order,
                        "reason": f"re-run of completed step {order}"}
            return {"allowed": False, "kind": "out-of-sequence", "step_order": order,
                    "reason": f"this is step {order} but step {done + 1} must run first"
                              " — the approved sequence is enforced"}
    verdict, why = classify(cmd)
    if verdict == "readonly":
        return {"allowed": True, "kind": "readonly",
                "reason": "not in the plan, but read-only diagnostics are permitted"}
    return {"allowed": False, "kind": verdict,
            "reason": f"not in the approved implementation plan and not read-only"
                      f" (policy: {why}) — only plan steps and read-only checks may run"}


def record_result(change_id: str, order: int, result: dict) -> dict | None:
    plan = load_plan(change_id)
    if plan is None:
        return None
    plan.setdefault("results", {})[str(order)] = {
        "ok": bool(result.get("ok")), "exit_code": result.get("exit_code"),
        "output": str(result.get("output") or "")[-4000:], "ts": time.time(),
    }
    if result.get("ok") and order == int(plan.get("current_step") or 0) + 1:
        plan["current_step"] = order
    return save_plan(change_id, plan)


def mark_manual_done(change_id: str, order: int) -> dict | None:
    plan = load_plan(change_id)
    if plan is None:
        return None
    if order == int(plan.get("current_step") or 0) + 1:
        plan["current_step"] = order
        plan.setdefault("results", {})[str(order)] = {
            "ok": True, "exit_code": None, "output": "(manual step confirmed done)",
            "ts": time.time(),
        }
        return save_plan(change_id, plan)
    return plan


# ---------- AI plan refinement ----------

_REFINE_PROMPT = """You are a change-management reviewer for production Linux servers at an
enterprise (an airport IT operation). An operator pasted their change
implementation plan below, written against their organisation's template.

Convert it into a structured, machine-executable plan AND review it:

- Break it into ordered steps. Each step is either an exact shell command
  (put it in "command") or a manual action ("command": "").
- VERIFY each step's downtime claim: decide yourself whether the step really
  requires downtime (service restarts, reboots, network changes usually do;
  file backups and read-only checks do not). If the plan's claim is wrong,
  correct it and explain in "downtime_note".
- Add anything critical that is missing as suggestions: backup steps before
  state changes, verification steps after them, a rollback/back-out plan.
- Keep every step the plan author intended — refine, do not invent scope.

Reply with ONLY this JSON (no fences, no prose outside it):
{"title": "one-line change title",
 "summary": "2-3 sentences: what this change does",
 "steps": [{"order": 1, "phase": "pre|implement|verify|rollback",
            "description": "what this step does",
            "command": "exact shell command or empty string for manual steps",
            "downtime_required": false,
            "downtime_note": "why downtime is/is not needed, esp. if you corrected the plan",
            "risk": "low|medium|high"}],
 "suggestions": ["improvement the author should consider", "..."],
 "downtime_overall": {"required": false, "note": "overall downtime verdict for the CR form"},
 "backout_plan": "concise back-out plan derived from (or added to) the document"}

THE PLAN DOCUMENT:
%s
"""


def _fallback_steps(plan_text: str) -> dict:
    """No-AI fallback: one manual step per non-empty line, no commands."""
    lines = [ln.strip(" -*\t") for ln in plan_text.splitlines() if ln.strip()]
    steps = [{"order": i + 1, "phase": "implement", "description": ln[:300],
              "command": "", "downtime_required": False,
              "downtime_note": "", "risk": "medium"}
             for i, ln in enumerate(lines[:40])]
    return {"title": (lines[0][:120] if lines else "Change plan"),
            "summary": "AI refinement unavailable — plan imported line-by-line as manual steps.",
            "steps": steps, "suggestions":
                ["AI refinement was unavailable; commands must be added manually."],
            "downtime_overall": {"required": False, "note": "not assessed"},
            "backout_plan": "", "refined_by": "fallback"}


async def refine_plan(plan_text: str) -> dict:
    text = ""
    try:
        from claude_agent_sdk import ClaudeAgentOptions, query
        from claude_agent_sdk.types import ResultMessage
        async with asyncio.timeout(120):
            options = ClaudeAgentOptions(max_turns=1, allowed_tools=[])
            async for message in query(prompt=_REFINE_PROMPT % plan_text[:12000],
                                       options=options):
                if isinstance(message, ResultMessage) and not message.is_error:
                    text = message.result or ""
    except Exception:  # noqa: BLE001 — refinement must degrade, not fail
        return _fallback_steps(plan_text)
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return _fallback_steps(plan_text)
    try:
        data = json.loads(m.group())
    except json.JSONDecodeError:
        return _fallback_steps(plan_text)
    steps = []
    for i, s in enumerate(data.get("steps") or []):
        if not isinstance(s, dict):
            continue
        steps.append({
            "order": i + 1,
            "phase": str(s.get("phase") or "implement"),
            "description": str(s.get("description") or "")[:500],
            "command": str(s.get("command") or "")[:500],
            "downtime_required": bool(s.get("downtime_required")),
            "downtime_note": str(s.get("downtime_note") or "")[:300],
            "risk": str(s.get("risk") or "medium").lower(),
        })
    if not steps:
        return _fallback_steps(plan_text)
    return {
        "title": str(data.get("title") or "")[:150],
        "summary": str(data.get("summary") or "")[:800],
        "steps": steps,
        "suggestions": [str(x)[:400] for x in (data.get("suggestions") or [])][:12],
        "downtime_overall": {
            "required": bool((data.get("downtime_overall") or {}).get("required")),
            "note": str((data.get("downtime_overall") or {}).get("note") or "")[:400],
        },
        "backout_plan": str(data.get("backout_plan") or "")[:2000],
        "refined_by": "ai",
    }
