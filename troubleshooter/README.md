# AI Troubleshooter — multi-layer agentic root cause analysis on Claude Code

A web app for an Ubuntu jump/ops server where **Claude Code is already
installed and logged in** (e.g. with an enterprise plan). It investigates
incidents the way a senior SRE does — never stopping at server logs:

1. **Pick the affected server** from a YAML inventory.
2. **Select the evidence layers** to investigate: monitoring (Zabbix),
   virtualization (VMware vCenter), ITSM / recent changes (SummitAI or any
   REST API), network log collectors (SSH) — all configurable in
   `datasources.yaml`.
3. **Choose a depth** (quick / standard / deep) and **describe the problem**
   ("502s since 14:30", "disk alerts on db-01", ...).
4. Watch **predefined agents** (a *log-collector* and a *log-analyzer* driven
   by Claude Code) pull evidence from every selected layer, correlate
   timestamps across all of it — server logs vs. monitoring alerts vs. change
   records vs. VM events vs. network logs — and separate cause from symptom.
5. Get a structured **incident report**: probable root cause **and the layer
   it lives in**, confidence, per-layer verdicts, evidence with exact log
   lines, impact, a step-by-step fix, and preventive measures.

The backend drives Claude Code through the **Claude Agent SDK for Python**
(`claude-agent-sdk`), so it reuses the machine's existing Claude Code
authentication — no `ANTHROPIC_API_KEY` is required when the service account
is logged in via `claude`.

```
Browser UI ──► FastAPI backend ──► Claude Agent SDK ──► Claude Code agents
  ▲ live SSE stream                                        │
  └────────────────────────────────────────────────────────┤
        ┌──────────────┬──────────────┬────────────────────┼──────────────┐
        ▼              ▼              ▼                    ▼              ▼
   target server   Zabbix API    vCenter API        ITSM/REST API    network log
   (read-only      (problems,    (VM events,        (recent changes, hosts (SSH,
   SSH wrappers)   metrics)      host health)       incidents)       read-only)
```

The agents are **strictly read-only everywhere**: they only run log-reading
and diagnostic commands / GET-style API queries, save all evidence locally
under the session directory, and *suggest* fixes — they never apply them.

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

### HTTPS / TLS

The app can serve HTTPS directly (no reverse proxy needed) — set the cert and
key env vars and it will start on TLS:

```bash
export TROUBLESHOOTER_SSL_CERTFILE=/root/.ssl/streamlit/streamlit-bundle.pem
export TROUBLESHOOTER_SSL_KEYFILE=/root/.ssl/streamlit/streamlit.key
python -m app                      # reads host/port/SSL from the environment
# → https://<server>:8090
```

For the systemd service, uncomment the `TROUBLESHOOTER_SSL_*` lines in the unit
file. The cert/key must be **readable by the `User=` account** — `/root/.ssl/…`
paths require `User=root` (or copy the files somewhere the service account can
read). To serve on the standard HTTPS port, set `TROUBLESHOOTER_PORT=443`.

Quick test with the raw uvicorn CLI instead:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8090 \
  --ssl-certfile /root/.ssl/streamlit/streamlit-bundle.pem \
  --ssl-keyfile  /root/.ssl/streamlit/streamlit.key
```

## Configuration

| Environment variable | Default | Purpose |
|---|---|---|
| `TROUBLESHOOTER_INVENTORY` | `./inventory.yaml` (falls back to the example) | Path to the server inventory |
| `TROUBLESHOOTER_DATASOURCES` | `./datasources.yaml` (falls back to the example) | Path to the evidence-layer config |
| `TROUBLESHOOTER_DATA` | `./data/sessions` | Where session evidence + reports are stored |
| `TROUBLESHOOTER_MODEL` | Claude Code's configured default | Optional model override (e.g. `claude-opus-4-8`) |
| `TROUBLESHOOTER_MAX_TURNS` | unset | Optional hard cap on agent turns (caps all depths) |
| `TROUBLESHOOTER_DB` | `sqlite:///<app>/data/troubleshooter.db` | Database URL (SQLite or PostgreSQL) |
| `TROUBLESHOOTER_HOST` | `0.0.0.0` | Bind address (used by `python -m app`) |
| `TROUBLESHOOTER_PORT` | `8090` | Listen port (used by `python -m app`) |
| `TROUBLESHOOTER_SSL_CERTFILE` | unset | TLS certificate (PEM/bundle) — set with the key to serve HTTPS |
| `TROUBLESHOOTER_SSL_KEYFILE` | unset | TLS private key — set with the cert to serve HTTPS |
| `TROUBLESHOOTER_SSL_KEY_PASSWORD` | unset | Passphrase, only if the private key is encrypted |
| `TROUBLESHOOTER_RETENTION_DAYS` | `90` | Purge sessions (DB rows + evidence dirs) older than this; `0` disables |
| `TROUBLESHOOTER_SCRIPTLIB` | `<app>/data/scriptlib` | Location of the agent script library |

### Database

Sessions, events, per-server health history, and the audit log persist in a
database (the session list survives restarts). Default is zero-ops SQLite.
For production, use PostgreSQL:

```bash
sudo -u postgres psql -c "CREATE USER aitrouble_app WITH PASSWORD '...';"
sudo -u postgres psql -c "CREATE DATABASE aitroubleshooter OWNER aitrouble_app;"
/opt/ai-troubleshooter/venv/bin/pip install "psycopg[binary]"
# systemd unit:
# Environment=TROUBLESHOOTER_DB=postgresql+psycopg://aitrouble_app:***@localhost/aitroubleshooter
```

Tables are created automatically on startup. A daily retention job purges
sessions older than `TROUBLESHOOTER_RETENTION_DAYS` (database rows **and**
the on-disk evidence directories). Every session start/cancel, inventory
change, and script deletion is written to the `audit_log` table with the
operator identity taken from the `X-Remote-User` / `X-Forwarded-User` header
your SSO reverse proxy sets (falling back to client IP) — browse it at
`GET /api/audit`.

The inventory format is documented inline in `inventory.example.yaml` —
including per-server `log_hints` that tell the agents where to look first.

### Evidence layers (`datasources.yaml`)

Copy `datasources.example.yaml` to `datasources.yaml` and configure your
layers. Supported connector types:

| Type | For | Auth |
|---|---|---|
| `zabbix` | Zabbix 6.0+ (problems, events, hosts, items, metric history, raw API) | API token via `token_env` |
| `vmware` | vCenter Automation REST API (VM state, host health, events) | username/password via `username_env`/`password_env` |
| `rest` | Any REST API — SummitAI ITSM, ELK/Graylog, NetBox, custom apps | static header via `auth_header` + `auth_value: "Bearer ${VAR}"` |
| `ssh` | Network/syslog log collector hosts | SSH key, like inventory servers |

**Secrets never live in YAML files** — the config names environment
variables; set the actual values in the systemd unit (or an
`EnvironmentFile=/opt/ai-troubleshooter/secrets.env` with mode 600):

```ini
Environment=ZABBIX_API_TOKEN=...
Environment=VCENTER_USERNAME=svc-claude-ro
Environment=VCENTER_PASSWORD=...
Environment=SUMMIT_API_TOKEN=...
```

Use **read-only accounts** for every layer (Zabbix user with read
permissions, vCenter read-only role, ITSM report user). The UI shows each
source as ready / missing-credentials on load.

Each source's `agent_hints` are free text handed to the agent — use them to
encode tribal knowledge ("host names match inventory", "check change windows
first", "device logs under /var/log/network/<device>/").

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
| `GET /api/datasources` | Configured evidence layers + credential readiness |
| `POST /api/sessions` | `{"server", "problem", "layers": [...], "depth", "sudo_password"?}` → starts an investigation |
| `GET /api/sessions` | All sessions with status |
| `GET /api/sessions/{id}` | Session detail incl. events and report |
| `GET /api/sessions/{id}/events` | SSE stream of live agent activity |
| `POST /api/sessions/{id}/cancel` | Cancel a running investigation |
| `GET /api/sessions/{id}/files` | Collected evidence files |
| `GET /api/sessions/{id}/files/{path}` | View one evidence file |
| `GET /api/sessions/{id}/report.md` | Download the incident report |

## Sudo on the target servers

There is deliberately **no sudo password option in the UI**. If protected
logs on a target need elevated read access, grant the diagnostics user
passwordless, command-scoped sudo on that target — no password ever enters
the system and sudo stays limited to read commands:

```
# /etc/sudoers.d/claude-ro
claude-ro ALL=(root) NOPASSWD: /usr/bin/journalctl, /usr/bin/tail, /usr/bin/cat, /usr/bin/grep, /usr/bin/ls, /usr/bin/du
```

(Adding the user to the `adm` and `systemd-journal` groups already covers
most log files on Ubuntu without any sudo.)

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
