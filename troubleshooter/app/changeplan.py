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
    platform = (plan or {}).get("platform") or "linux"
    verdict, why = classify(cmd, platform)
    if verdict == "readonly":
        return {"allowed": True, "kind": "readonly",
                "reason": "not in the plan, but read-only diagnostics are permitted"}
    return {"allowed": False, "kind": verdict,
            "reason": f"not in the approved implementation plan and not read-only"
                      f" (policy: {why}) — only plan steps and read-only checks may run"}


def record_result(change_id: str, order: int, result: dict,
                  verification: dict | None = None, advance: bool = True) -> dict | None:
    plan = load_plan(change_id)
    if plan is None:
        return None
    entry = {
        "ok": bool(result.get("ok")), "exit_code": result.get("exit_code"),
        "output": str(result.get("output") or "")[-4000:], "ts": time.time(),
    }
    if verification:
        entry.update(verdict=verification.get("verdict"),
                     summary=verification.get("summary"),
                     concern=verification.get("concern"),
                     proceed=verification.get("proceed"),
                     verified_by=verification.get("verified_by"))
    else:
        entry["pending_verify"] = True
    plan.setdefault("results", {})[str(order)] = entry
    # advance only when the command ran AND the AI didn't judge it failed
    verdict_ok = (verification or {}).get("verdict") != "failed"
    if advance and result.get("ok") and verdict_ok and order == int(plan.get("current_step") or 0) + 1:
        plan["current_step"] = order
    return save_plan(change_id, plan)


def apply_verification(change_id: str, order: int, verification: dict) -> dict | None:
    """Attach the AI verdict to an already-recorded step and advance the
    pointer if it didn't fail (used by the two-phase run/verify UI)."""
    plan = load_plan(change_id)
    if plan is None:
        return None
    entry = (plan.get("results") or {}).get(str(order))
    if entry is None:
        return plan
    entry.pop("pending_verify", None)
    entry.update(verdict=verification.get("verdict"),
                 summary=verification.get("summary"),
                 concern=verification.get("concern"),
                 proceed=verification.get("proceed"),
                 verified_by=verification.get("verified_by"))
    # NOTE: does not advance current_step — the operator reads the output and
    # clicks "Next step" (advance_step) to move on.
    return save_plan(change_id, plan)


def advance_step(change_id: str, order: int, force: bool = False) -> dict | None:
    """Operator-confirmed move to the next step. Normally only advances when
    the step ran and the AI didn't judge it failed; force=True lets the
    operator override a failed/unclean step and proceed anyway (recorded)."""
    plan = load_plan(change_id)
    if plan is None:
        return None
    cur = int(plan.get("current_step") or 0)
    if order != cur + 1:
        return plan
    entry = (plan.get("results") or {}).get(str(order))
    clean = entry and entry.get("ok") and entry.get("verdict") != "failed"
    if clean or (force and entry):
        if force and not clean:
            entry["overridden"] = True
        plan["current_step"] = order
        return save_plan(change_id, plan)
    return plan


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

# Prepended to the Linux-worded prompts below when the target is a Windows
# host, so the model emits PowerShell (run over WinRM) instead of bash.
_WINDOWS_DIRECTIVE = """IMPORTANT — THE TARGET OS IS WINDOWS SERVER (PowerShell over WinRM).
Every "command" MUST be a PowerShell command that runs DIRECTLY on the target
host via an existing WinRM session — never bash, never ssh, never Linux tools.
Wherever the guidance below refers to Linux, a shell, sudo, yum/dnf/apt,
systemctl, journalctl or POSIX paths, substitute the correct Windows/PowerShell
equivalent:
- services: Get-Service / Restart-Service / Set-Service   (not systemctl/service)
- roles, features & packages: Install-WindowsFeature, winget/choco, Install-Module
- OS patching: Windows Update (Install-WindowsUpdate, or wusa.exe for a .msu);
  a reboot (Restart-Computer) is ALWAYS downtime, exactly like a Linux kernel patch
- backups: Copy-Item to a dated path, `reg export` for registry keys,
  Checkpoint-VM/snapshot where relevant   (not tar/cp)
- verification: Get-Service, Get-WinEvent/Get-EventLog, Test-NetConnection,
  Get-Counter, Get-Hotfix
- use Windows paths (C:\\...) and PowerShell syntax; do NOT emit any bash.

"""


def _os_directive(platform: str) -> str:
    return _WINDOWS_DIRECTIVE if str(platform).lower() == "windows" else ""


_REFINE_PROMPT = """You are a senior change-management reviewer for production Linux servers at an
enterprise (an airport IT operation, 24x7 safety-critical). An operator gave you
their change implementation plan below (written against their org template, or
free text). Your job is to REDUCE FAILED CHANGES: turn it into a correct,
executable, low-risk plan and honestly score it.

Do ALL of this:

1. Break the plan into ordered steps. Phases: pre | implement | verify |
   rollback. For EVERY step that can be performed from a Linux shell, WRITE the
   exact executable command in "command" — even when the plan document only
   describes the action in words (e.g. "patch the kernel" → the concrete
   yum/dnf command; "take a backup of the config" → the concrete tar/cp
   command with dated filenames). The implementer assistant executes these
   commands verbatim ON the target host (do NOT wrap them in ssh to another
   host; write each as typed at a shell on the target itself, sudo is fine), so
   a step without a command cannot be automated. Leave "command" empty ONLY for
   inherently manual actions (approvals, physical work, coordination). Use
   concrete names from the plan; if a name is uncertain, still write the most
   likely command and flag it in suggestions.
2. VALIDATE AND CORRECT the commands and steps: fix wrong/unsafe syntax, add
   missing quoting, split compound risky commands, and put steps in a safe order
   (backups BEFORE state changes, verification AFTER). Record every change you
   made in "corrections".
3. VERIFY each step's downtime claim yourself and correct it in
   downtime_required, explaining in downtime_note. HARD RULES: kernel patches/
   upgrades ALWAYS require downtime (a reboot is needed for the new kernel to
   take effect) unless the plan explicitly uses live patching (kpatch/ksplice/
   livepatch); reboots and shutdowns are always downtime; restarting or
   stopping a service is downtime for that service unless a redundant node
   demonstrably takes over; backups and read-only checks are not downtime.
   Never mark a kernel/reboot step as no-downtime.
4. Ensure there is a real, tested-style BACK-OUT plan. If missing or weak, write
   one derived from the steps (how to undo each state change) and set
   backout_validated accordingly.
5. INFER the CR attributes from the work itself: category (Minor/Major/
   Significant), change type (Normal/Standard/Emergency), risk (Low/Medium/High),
   impact (Low/Medium/High), priority (P1-P4), likely owner workgroup.
6. Assess overall RISK (level + rationale) and a SUCCESS-RATE estimate as a
   percentage with the concrete factors that raise or lower it (missing backups,
   no verification, wide blast radius, downtime in business hours, untested
   rollback, etc.).
7. List still-MISSING mandatory information the operator must supply that you
   cannot infer (e.g. requestor email, exact maintenance window, approver).

Keep the author's intended scope — refine and correct, do not invent new work.

Reply with ONLY this JSON (no fences, no prose outside it):
{"title": "clear industry-standard change title — concise, action-first, names the target system, notes reboot/downtime if any (rewrite the operator's rough wording; e.g. 'Apply monthly kernel security patch to app-02 (reboot required)')",
 "summary": "2-3 sentences: what this change does",
 "steps": [{"order": 1, "phase": "pre|implement|verify|rollback",
            "description": "what this step does",
            "command": "exact shell command or empty string for manual steps",
            "downtime_required": false,
            "downtime_note": "why downtime is/is not needed (note corrections)",
            "risk": "low|medium|high"}],
 "corrections": ["what you fixed or reordered and why", "..."],
 "suggestions": ["further improvement the author should consider", "..."],
 "downtime_overall": {"required": false, "note": "overall downtime verdict"},
 "backout_plan": "concrete back-out plan (undo each state change)",
 "backout_validated": true,
 "inferred_fields": {"category": "Minor", "type": "Normal", "risk": "Medium",
                     "impact": "Medium", "priority": "P3", "workgroup": ""},
 "risk_assessment": {"level": "Low|Medium|High", "rationale": "one paragraph"},
 "success_rate": {"percent": 85, "factors": ["+ has backups", "- restart in business hours"]},
 "missing_fields": ["requestor email", "maintenance window"]}

THE PLAN DOCUMENT:
%s
"""

_RECOMMEND_PROMPT = """You are a senior change-management advisor for production Linux servers at an
enterprise airport IT operation. The operator is raising a change and has given
this description (and any fields so far):

%s

Recommend sensible CR attributes and an outline plan to reduce the chance of a
failed change. Also rewrite the operator's rough summary into a clear,
industry-standard change TITLE (concise, action-first, includes the target
system; e.g. "Apply monthly kernel security patch to app-02 (reboot required)").
Reply with ONLY this JSON (no fences):
{"title": "polished change title",
 "category": "Minor|Major|Significant", "type": "Normal|Standard|Emergency",
 "risk": "Low|Medium|High", "impact": "Low|Medium|High", "priority": "P1|P2|P3|P4",
 "downtime_required": false, "workgroup": "suggested owner workgroup or ''",
 "rationale": "2-3 sentences on why these were chosen",
 "outline_steps": ["short step the operator should include", "..."],
 "backout_hint": "a starting back-out approach for this kind of change"}
"""


_GENERATE_PROMPT = """You are a senior Linux change implementer at an enterprise airport IT
operation (24x7, safety-critical). No implementation-plan document exists yet —
GENERATE a complete, safe, executable plan for this change from its description:

%s

Commands run DIRECTLY on the target host via an existing session — do NOT wrap
them in ssh to another host (no `ssh user@host '...'`); write the command as it
would be typed at a shell on the target itself (sudo is fine).

Produce the full plan yourself: the exact shell commands to carry it out on the
target Linux host, in a safe order (backups/snapshots BEFORE any state change,
the change itself, then verification), plus a rollback/back-out path. Use
concrete, runnable commands (real package/service names inferred from the
description; dated backup filenames). Assess downtime per step honestly (kernel
patches and reboots ALWAYS need downtime unless live patching), score the risk
and success rate, and note anything the operator must confirm before running.

Reply with ONLY this JSON (identical schema to a refined plan; no fences):
{"title": "clear industry-standard change title — concise, action-first, names the target host, notes reboot/downtime if any",
 "summary": "...",
 "steps": [{"order": 1, "phase": "pre|implement|verify|rollback",
            "description": "...", "command": "exact shell command or '' if manual",
            "downtime_required": false, "downtime_note": "...", "risk": "low|medium|high"}],
 "corrections": [], "suggestions": ["..."],
 "downtime_overall": {"required": false, "note": "..."},
 "backout_plan": "...", "backout_validated": true,
 "inferred_fields": {"category": "", "type": "", "risk": "", "impact": "", "priority": "", "workgroup": ""},
 "risk_assessment": {"level": "Low|Medium|High", "rationale": "..."},
 "success_rate": {"percent": 80, "factors": ["..."]},
 "missing_fields": ["..."]}
"""


async def generate_plan(context: str, platform: str = "linux") -> dict:
    """Build an executable plan from a change goal/description (no document)."""
    data, err = await _one_shot_json(
        _os_directive(platform) + _GENERATE_PROMPT % context[:6000], timeout_s=150)
    shaped = _shape_refined(data) if data else None
    if shaped:
        return shaped
    # never fabricate steps from the description — say clearly it failed
    return {
        "title": "", "summary": "AI plan generation is unavailable on this server.",
        "steps": [], "corrections": [], "suggestions": [],
        "downtime_overall": {"required": False, "note": ""},
        "backout_plan": "", "backout_validated": False, "inferred_fields": {},
        "risk_assessment": {"level": "", "rationale": ""},
        "success_rate": {"percent": None, "factors": []},
        "missing_fields": [], "refined_by": "unavailable",
        "ai_error": err or "the AI returned no usable plan",
    }


def _fallback_steps(plan_text: str) -> dict:
    """No-AI fallback: one manual step per non-empty line, no commands.
    The downtime policy floor still applies to the imported lines."""
    lines = [ln.strip(" -*\t") for ln in plan_text.splitlines() if ln.strip()]
    steps = [{"order": i + 1, "phase": "implement", "description": ln[:300],
              "command": "", "downtime_required": False,
              "downtime_note": "", "risk": "medium"}
             for i, ln in enumerate(lines[:40])]
    return _enforce_downtime({
            "title": (lines[0][:120] if lines else "Change plan"),
            "summary": "AI refinement unavailable — plan imported line-by-line as manual steps.",
            "steps": steps,
            "corrections": [],
            "suggestions": ["AI refinement was unavailable; commands and risk must be reviewed manually."],
            "downtime_overall": {"required": False, "note": "not assessed"},
            "backout_plan": "", "backout_validated": False,
            "inferred_fields": {},
            "risk_assessment": {"level": "Medium", "rationale": "Not assessed — AI unavailable."},
            "success_rate": {"percent": None, "factors": ["not assessed"]},
            "missing_fields": [],
            "refined_by": "fallback"})


# Deterministic downtime floor — patterns whose downtime the AI is never
# allowed to wave away (the kernel-patch case: "no downtime" is exactly the
# kind of wrong claim that causes failed changes).
_FORCED_DOWNTIME = [
    (r"\breboot\b|\bshutdown\s+-r\b|\binit\s+6\b|\btelinit\s+6\b",
     "a reboot always requires downtime"),
    (r"kernel|vmlinuz|linux-image|kernel-core|\bdracut\b|grub2?-(mkconfig|install)",
     "kernel changes require a reboot to take effect — downtime is required"),
    (r"\bsystemctl\s+(restart|stop)\b|\bservice\s+\S+\s+(restart|stop)\b",
     "restarting/stopping a service interrupts it"),
    (r"\b(ifdown|nmcli\s+con(nection)?\s+down|ip\s+link\s+set\s+\S+\s+down)\b",
     "taking a network interface down interrupts connectivity"),
    # Windows / PowerShell equivalents
    (r"(?i)\brestart-computer\b|\bshutdown(\.exe)?\b\s+/r",
     "a Windows reboot always requires downtime"),
    (r"(?i)\b(restart|stop)-service\b|\biisreset\b|\b(restart|stop)-webapppool\b",
     "restarting/stopping a Windows service interrupts it"),
    (r"(?i)install-windowsupdate|\bwusa(\.exe)?\b|\bhotpatch\b.*reboot",
     "installing Windows updates typically requires a reboot — downtime is required"),
    (r"(?i)\bdisable-netadapter\b",
     "disabling a network adapter interrupts connectivity"),
]
_LIVEPATCH = re.compile(r"kpatch|ksplice|livepatch|hotpatch", re.I)


def _enforce_downtime(result: dict) -> dict:
    """Policy floor over the AI verdicts: steps matching forced-downtime
    patterns are marked downtime_required no matter what the model said."""
    forced = []
    for s in result.get("steps") or []:
        text = f"{s.get('command') or ''} {s.get('description') or ''}"
        if _LIVEPATCH.search(text):
            continue   # explicit live patching is the one legitimate exception
        cmd = s.get("command") or ""
        # a read-only command can't cause downtime (e.g. uname -r / Get-Service);
        # judge against BOTH dialects since the plan platform isn't threaded here
        if cmd and classify(cmd, "linux")[0] == "readonly" \
                and classify(cmd, "windows")[0] == "readonly":
            continue
        for pattern, why in _FORCED_DOWNTIME:
            if re.search(pattern, text, re.I):
                if not s.get("downtime_required"):
                    s["downtime_required"] = True
                    note = (s.get("downtime_note") or "").strip()
                    s["downtime_note"] = (f"[policy] {why}" + (f" — {note}" if note else ""))[:300]
                    forced.append(f"step {s.get('order')}: {why}")
                break
    if forced:
        overall = result.setdefault("downtime_overall", {})
        if not overall.get("required"):
            overall["required"] = True
            overall["note"] = "Downtime required (kernel/reboot/service-restart steps)."
        # one concise correction line, not one per step
        nums = sorted({int(re.match(r"step (\d+)", f).group(1)) for f in forced
                       if re.match(r"step (\d+)", f)})
        if nums:
            plural = "s" if len(nums) > 1 else ""
            result.setdefault("corrections", []).append(
                f"Downtime forced ON for step{plural} "
                f"{', '.join(map(str, nums))} — reboot/restart requires downtime (policy).")
    return result


async def refine_plan(plan_text: str, platform: str = "linux") -> dict:
    data, err = await _one_shot_json(
        _os_directive(platform) + _REFINE_PROMPT % plan_text[:12000], timeout_s=150)
    if data:
        shaped = _shape_refined(data)
        if shaped:
            return shaped
        err = err or "the AI response could not be parsed into steps"
    fb = _fallback_steps(plan_text)
    fb["ai_error"] = err or "AI returned no usable plan"
    return fb


def _shape_refined(data: dict) -> dict | None:
    """Normalise an AI plan dict into the canonical shape (with the downtime
    policy floor applied). Returns None if it has no usable steps."""
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
        return None
    inf = data.get("inferred_fields") or {}
    ra = data.get("risk_assessment") or {}
    sr = data.get("success_rate") or {}
    pct = sr.get("percent")
    try:
        pct = max(0, min(100, int(pct))) if pct is not None else None
    except (TypeError, ValueError):
        pct = None
    out = {
        "title": str(data.get("title") or "")[:150],
        "summary": str(data.get("summary") or "")[:800],
        "steps": steps,
        "corrections": [str(x)[:400] for x in (data.get("corrections") or [])][:20],
        "suggestions": [str(x)[:400] for x in (data.get("suggestions") or [])][:12],
        "downtime_overall": {
            "required": bool((data.get("downtime_overall") or {}).get("required")),
            "note": str((data.get("downtime_overall") or {}).get("note") or "")[:400],
        },
        "backout_plan": str(data.get("backout_plan") or "")[:2000],
        "backout_validated": bool(data.get("backout_validated")),
        "inferred_fields": {
            "category": str(inf.get("category") or "")[:40],
            "type": str(inf.get("type") or "")[:40],
            "risk": str(inf.get("risk") or "")[:20],
            "impact": str(inf.get("impact") or "")[:20],
            "priority": str(inf.get("priority") or "")[:10],
            "workgroup": str(inf.get("workgroup") or "")[:100],
        },
        "risk_assessment": {
            "level": str(ra.get("level") or "Medium")[:20],
            "rationale": str(ra.get("rationale") or "")[:800],
        },
        "success_rate": {
            "percent": pct,
            "factors": [str(x)[:200] for x in (sr.get("factors") or [])][:12],
        },
        "missing_fields": [str(x)[:120] for x in (data.get("missing_fields") or [])][:12],
        "refined_by": "ai",
    }
    return _enforce_downtime(out)


async def _one_shot_json(prompt: str, timeout_s: int = 90):
    """Run a single-turn tool-less query, returning (parsed_json, error).
    Exactly one of the two is set. error is a short human string for the UI."""
    text = ""
    try:
        from claude_agent_sdk import ClaudeAgentOptions, query
        from claude_agent_sdk.types import ResultMessage
    except Exception as exc:  # noqa: BLE001
        return None, f"Claude Agent SDK not installed on the server ({exc})"
    try:
        async with asyncio.timeout(timeout_s):
            options = ClaudeAgentOptions(max_turns=1, allowed_tools=[])
            async for message in query(prompt=prompt, options=options):
                if isinstance(message, ResultMessage):
                    if message.is_error:
                        return None, f"AI call returned an error: {getattr(message, 'result', '') or getattr(message, 'subtype', 'error')}"[:300]
                    text = message.result or ""
    except TimeoutError:
        return None, f"AI call timed out after {timeout_s}s"
    except Exception as exc:  # noqa: BLE001
        return None, f"AI call failed: {type(exc).__name__}: {exc}"[:300]
    if not text.strip():
        return None, "AI returned an empty response (check the Claude Code login / credentials for the service account)"
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None, "AI response was not JSON: " + " ".join(text.split())[:180]
    try:
        return json.loads(m.group()), None
    except json.JSONDecodeError as exc:
        return None, f"AI response JSON was invalid ({exc})"


async def recommend_change(context: str, platform: str = "linux") -> dict:
    """Suggest CR attributes + an outline plan from a description (no attachment
    flow). Degrades to neutral defaults if the AI is unavailable."""
    data, err = await _one_shot_json(_os_directive(platform) + _RECOMMEND_PROMPT % context[:6000])
    if not data:
        return {"available": False, "ai_error": err,
                "category": "Minor", "type": "Normal", "risk": "Medium",
                "impact": "Medium", "priority": "P3", "downtime_required": False,
                "workgroup": "", "rationale": "AI recommendations unavailable — pick values manually.",
                "outline_steps": [], "backout_hint": ""}
    return {
        "available": True,
        "title": str(data.get("title") or "")[:150],
        "category": str(data.get("category") or "Minor")[:40],
        "type": str(data.get("type") or "Normal")[:40],
        "risk": str(data.get("risk") or "Medium")[:20],
        "impact": str(data.get("impact") or "Medium")[:20],
        "priority": str(data.get("priority") or "P3")[:10],
        "downtime_required": bool(data.get("downtime_required")),
        "workgroup": str(data.get("workgroup") or "")[:100],
        "rationale": str(data.get("rationale") or "")[:600],
        "outline_steps": [str(x)[:200] for x in (data.get("outline_steps") or [])][:12],
        "backout_hint": str(data.get("backout_hint") or "")[:600],
    }


_VERIFY_PROMPT = """You are a change implementer verifying a step you just ran on a production
%s server. Read the ACTUAL command output — do not trust the exit code alone
(a command can exit 0 yet clearly fail, or exit non-zero yet be benign).

Change: %s
Step %s [%s]: %s
Command: %s
Exit code: %s
Output:
%s

Decide whether this step achieved its intent and whether it is safe to continue.
Reply with ONLY this JSON (no fences):
{"verdict": "ok|warning|failed",
 "summary": "1-2 plain sentences: what the output shows / what happened",
 "concern": "any red flag to watch, or '' if none",
 "proceed": true}
verdict rules: ok = did what it should; warning = worked but something needs
attention; failed = did not achieve its intent or broke something. proceed =
false only when continuing would be unsafe."""


async def verify_step(step: dict, result: dict, change_title: str = "",
                      platform: str = "linux") -> dict:
    """AI reads a step's real output and judges success/summary/concern.
    Falls back to an exit-code verdict if the AI is unavailable."""
    out = (result.get("output") or "")[:4000]
    os_label = "Windows" if str(platform).lower() == "windows" else "Linux"
    data, err = await _one_shot_json(_VERIFY_PROMPT % (
        os_label, change_title or "(change)", step.get("order"), step.get("phase", "step"),
        step.get("description", ""), step.get("command") or "(manual step)",
        result.get("exit_code"), out or "(no output)"), timeout_s=60)
    if not data:
        ok = bool(result.get("ok"))
        tail = " ".join(out.split())[:200]
        return {"verdict": "ok" if ok else "failed",
                "summary": (f"Exit {result.get('exit_code')}. " + (tail or "(no output)"))[:300],
                "concern": "" if ok else "Command reported a non-zero exit.",
                "proceed": ok, "verified_by": "exit-code"}
    v = str(data.get("verdict") or "").lower()
    if v not in ("ok", "warning", "failed"):
        v = "ok" if result.get("ok") else "failed"
    return {"verdict": v,
            "summary": str(data.get("summary") or "")[:400],
            "concern": str(data.get("concern") or "")[:300],
            "proceed": bool(data.get("proceed", v != "failed")),
            "verified_by": "ai"}


def extract_text(filename: str, data: bytes) -> str:
    """Best-effort text extraction from an uploaded implementation-plan file.
    Text/markdown always work; docx/pdf need optional libs (graceful message)."""
    name = (filename or "").lower()
    if name.endswith((".txt", ".md", ".markdown", ".text", ".log", ".csv", ".rtf")):
        return data.decode("utf-8", errors="replace")
    if name.endswith(".docx"):
        try:
            import io
            from docx import Document
            doc = Document(io.BytesIO(data))
            parts = [p.text for p in doc.paragraphs]
            for tbl in doc.tables:
                for row in tbl.rows:
                    parts.append("\t".join(c.text for c in row.cells))
            return "\n".join(p for p in parts if p is not None)
        except ImportError:
            raise RuntimeError("This server can't read .docx yet (python-docx not installed)."
                               " Paste the plan text, or install python-docx.")
    if name.endswith(".pdf"):
        try:
            import io
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(data))
            return "\n".join((pg.extract_text() or "") for pg in reader.pages)
        except ImportError:
            raise RuntimeError("This server can't read .pdf yet (pypdf not installed)."
                               " Paste the plan text, or install pypdf.")
    # unknown extension — try utf-8 and hope it's text
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise RuntimeError(f"Unsupported file type: {filename}. Upload .txt, .md, .docx or .pdf,"
                           " or paste the plan text.")
