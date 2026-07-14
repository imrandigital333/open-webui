# AI Troubleshooter — agentic server troubleshooting UI on Claude Code

A small web app for an Ubuntu jump/ops server where **Claude Code is already
installed and logged in** (e.g. with an enterprise plan). It gives operators a
UI to:

1. **Pick a server** from a YAML inventory.
2. **Describe the problem** ("502s since 14:30", "disk alerts on db-01", ...).
3. Watch **predefined agents** (a *log-collector* and a *log-analyzer* driven
   by Claude Code) SSH into the affected server, pull the relevant logs and
   diagnostics, and correlate them.
4. Get a structured **incident report**: probable root cause, confidence,
   evidence (with the exact log lines), impact, a step-by-step recommended
   fix, and preventive measures.

The backend drives Claude Code through the **Claude Agent SDK for Python**
(`claude-agent-sdk`), so it reuses the machine's existing Claude Code
authentication — no `ANTHROPIC_API_KEY` is required when the service account
is logged in via `claude`.

```
Browser UI  ──►  FastAPI backend  ──►  Claude Agent SDK  ──►  Claude Code
   ▲  live SSE stream                     │
   └──────────────────────────────────────┤ subagents:
                                          │  • log-collector  (ssh → ./logs/)
                                          │  • log-analyzer   (local analysis)
                                          ▼
                              read-only SSH to the selected server
```

The agents are **strictly read-only on the remote hosts**: they only run
log-reading and diagnostic commands, save all evidence locally under the
session directory, and *suggest* fixes — they never apply them.

---

## Requirements

- Ubuntu server with **Node.js and the Claude Code CLI** installed, and the
  service account logged in (`claude` → `/login`, or your enterprise SSO flow).
  Verify with `claude -p "say ok"` as that user.
- **Python 3.11+**.
- **Key-based SSH access** from this machine to every server in the inventory
  (ideally a dedicated `claude-ro` user on the targets with membership in the
  `adm`/`systemd-journal` groups so it can read logs, and nothing more).

## Install

```bash
# as the service account (e.g. aitrouble)
cd /opt/ai-troubleshooter
git clone <this-repo> src && cd src/troubleshooter    # or copy this folder
python3 -m venv /opt/ai-troubleshooter/venv
source /opt/ai-troubleshooter/venv/bin/activate
pip install -r requirements.txt

# configure your servers
cp inventory.example.yaml inventory.yaml
$EDITOR inventory.yaml

# smoke test
uvicorn app.main:app --host 127.0.0.1 --port 8090
# open http://<server>:8090 (or tunnel: ssh -L 8090:127.0.0.1:8090 <server>)
```

### Run as a service

```bash
sudo cp systemd/ai-troubleshooter.service /etc/systemd/system/
# edit paths/user inside the unit to match your layout, then:
sudo systemctl daemon-reload
sudo systemctl enable --now ai-troubleshooter
```

Put nginx (with auth) or your SSO proxy in front of port 8090 — the app itself
has **no authentication**; anyone who can reach it can run SSH diagnostics on
your inventory hosts.

## Configuration

| Environment variable | Default | Purpose |
|---|---|---|
| `TROUBLESHOOTER_INVENTORY` | `./inventory.yaml` (falls back to the example) | Path to the server inventory |
| `TROUBLESHOOTER_DATA` | `./data/sessions` | Where session evidence + reports are stored |
| `TROUBLESHOOTER_MODEL` | Claude Code's configured default | Optional model override (e.g. `claude-opus-4-8`) |
| `TROUBLESHOOTER_MAX_TURNS` | `80` | Safety cap on agent turns per investigation |

The inventory format is documented inline in `inventory.example.yaml` —
including per-server `log_hints` that tell the agents where to look first.

## How a session works

1. `POST /api/sessions` creates a working directory
   `data/sessions/<id>/` and launches a Claude Code run scoped (`cwd`) to it.
2. The main agent triages the problem statement, then delegates:
   - **log-collector** — runs targeted read-only commands over SSH
     (`journalctl --since`, `tail`, `grep`, `df`, `free`, `ss`,
     `systemctl status`, ...) and saves every output under `logs/`.
   - **log-analyzer** — works only on the collected files, builds a timeline,
     and separates root cause from symptoms, quoting exact log lines.
3. The agent writes `report.md` (human-readable) and `report.json`
   (structured), which the backend parses and the UI renders.
4. Everything streams live to the browser over SSE (`/api/sessions/<id>/events`),
   and the raw evidence stays on disk for later review.

### API

| Endpoint | Description |
|---|---|
| `GET /api/inventory` | Servers available for troubleshooting |
| `POST /api/sessions` | `{"server": "web-01", "problem": "..."}` → starts an investigation |
| `GET /api/sessions` | All sessions with status |
| `GET /api/sessions/{id}` | Session detail incl. events and report |
| `GET /api/sessions/{id}/events` | SSE stream of live agent activity |

## Sudo on the target servers

If protected logs on a target need `sudo`, you have two options:

1. **Preferred — passwordless, command-scoped sudo.** On each target, allow
   the diagnostics user to run only read commands without a password:

   ```
   # /etc/sudoers.d/claude-ro
   claude-ro ALL=(root) NOPASSWD: /usr/bin/journalctl, /usr/bin/tail, /usr/bin/cat, /usr/bin/grep, /usr/bin/ls, /usr/bin/du
   ```

   No password ever enters the UI, and sudo stays limited to those binaries.

2. **UI sudo password (optional field on the investigation form).** The
   password is used once for that investigation. Handling is deliberately
   conservative: it is never written to disk, never stored on the session,
   never logged, and never placed in the AI prompt — the agent runs commands
   through a generated `./remote-sudo` wrapper that reads the password from an
   environment variable of the session subprocess. Residual risk: any process
   environment can in principle be echoed, so the agent is instructed never to
   print it — if that risk is unacceptable, use option 1. Serve the UI over
   HTTPS (reverse proxy) so the password is encrypted in transit.

## Security notes

- **Read-only by design, enforced by prompt + credentials.** The prompt forbids
  state changes, but your real enforcement should be the SSH account: use a
  dedicated user on the targets that can read logs and run diagnostics only
  (no sudo). Optionally add a `ForceCommand`/rbash wrapper or an OpenSSH
  `Match` block to restrict it further.
- Session directories contain raw log extracts — treat `data/` with the same
  sensitivity as the logs themselves.
- Keep the app on localhost or behind an authenticated reverse proxy.
- Log data is sent to the Claude API for analysis; make sure that is
  acceptable under your data-handling policy (enterprise plans have
  corresponding data controls).

## Extending

- **Auto-remediation with approval**: add a second phase where the agent
  proposes exact commands and the UI asks a human to approve before a separate
  (write-enabled) run applies them.
- **More subagents**: e.g. a `metrics-collector` querying Prometheus, or a
  `change-checker` that diffs recent deploys — add them in
  `app/orchestrator.py::_agent_definitions`.
- **Persistence**: sessions currently live in memory (evidence and reports are
  on disk); add SQLite if you need session history across restarts.
