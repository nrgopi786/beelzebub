# Xpods Console

A web console, running in its own container, for managing the per-client Xpods
in [`deploy/`](../deploy/README.md) and investigating what attackers do on them.

```bash
cd console
./console.sh up        # first run prints the admin password
# open http://127.0.0.1:8088  (remote: ssh -L 8088:127.0.0.1:8088 <host>)
```

## What it does

**Analysis and investigation**
- **Overview**: event, IP, session, login and command counts; an activity timeline by
  protocol; top source IPs, credentials, usernames, passwords, shell commands, HTTP
  requests, user agents and TCP payloads. Every list is clickable and drills down.
- **Events**: full-text search across commands, URIs, credentials, bodies, payloads and
  user agents, with filters for Xpod, protocol, status, source IP and time range.
  An inspector panel shows the parsed fields and the raw JSON.
- **Sessions**: SSH, Telnet and TCP sessions, replayed as a terminal transcript
  (commands and the Xpod's responses, in order).
- **Attackers and IP profile**: per-IP first/last seen, protocols, targeted Xpods,
  client software, credentials, commands, HTTP requests, sessions and daily activity.
  Also tags and investigation notes, plus links to AbuseIPDB, GreyNoise, Shodan and
  VirusTotal.
- **Export**: CSV or NDJSON of any filtered view, and a plain IP list for blocklists or
  IOC feeds.

**Assistant (local LLM)**
- A chat assistant backed by a local model (Ollama, default `qwen2.5:3b`) running in the same
  compose stack. No event data leaves the host.
- It answers from live data through read-only tools: overview stats, event search, sessions and
  transcripts, attacker lists, IP profiles, Xpod status, config validation and the audit log.
  Every tool call is shown in the chat and can be expanded to see the exact data it returned.
- It can **propose** changes (deploy, restart, stop, settings, new Xpod, IP notes). Nothing runs
  until you click Approve on the proposal card. Settings proposals show an `old → new` diff.
- "Ask assistant" buttons on the overview, IP and session pages start a pre-filled investigation.

**Management** (every action runs `deploy/deploy.sh`, so the CLI and the UI never drift)
- Create Xpods; edit domain, fake hostname, bind IP, services, TLS, resources,
  log rotation and shipping.
- Deploy, redeploy, restart, stop, validate and issue certificates. `deploy.sh` output
  streams live in the browser.
- Edit per-client custom lures (`clients/<name>/custom/*.yaml`).
- Show egress-lockdown firewall rules.
- **Audit log** of logins, setting changes, lifecycle actions and exports.

## How it works

```
console container (host netns, 127.0.0.1:8088)
 ├─ FastAPI + SQLite (console/data/console.db)
 ├─ assistant ──► ollama container (127.0.0.1:11500, models in a named volume)
 ├─ ingester: tails deploy/clients/*/data/logs/beelzebub.log + rotated *.gz every 3s
 └─ docker CLI + deploy.sh ──► /var/run/docker.sock ──► hp-<client> stacks
```

- The repo is mounted at the **same absolute path** as on the host, because
  `deploy.sh` passes bind-mount paths to the Docker daemon.
- The ingester tracks the file offset plus a hash of the first bytes, so it notices
  truncation by the rotation sidecar. Rows are de-duplicated by line hash, so
  re-reading an archive that overlaps the live log is harmless.
- The raw log files remain the source of truth. Deleting `console/data/console.db`
  rebuilds the index from them on the next start.

## Security

The console can start containers, which is **root-equivalent on the host**, and it
displays attacker-controlled strings. It is built accordingly:

- Mandatory login: a scrypt password hash in `.env`, an HMAC-signed `HttpOnly`,
  `SameSite=Strict` session cookie, and exponential lockout after failed attempts.
- CSRF: state-changing requests need both the SameSite cookie and an
  `X-Requested-With` header.
- XSS: the frontend builds the DOM with text nodes only (no `innerHTML`), and a strict
  CSP (`script-src 'self'`, no inline scripts or styles) acts as a second layer.
- CSV exports escape formula prefixes (`= + - @`), because attackers do put formulas in
  user agents.
- Settings are validated per key before being written to a client `.env`; values
  containing shell metacharacters are rejected. Client and lure file names are
  confined to the client directory. Secrets are masked in the UI.
- The container runs as your uid (not root), with a read-only root filesystem and
  `cap_drop: ALL`. It listens on `127.0.0.1` by default.

**Remote access:** use an SSH tunnel or VPN, or put it behind a TLS reverse proxy with
extra authentication (set `CONSOLE_HOST`, and `CONSOLE_COOKIE_SECURE=true` behind
HTTPS). Never expose it directly on an Xpod host's public IP.

### Assistant safety

Everything the assistant analyses was written by attackers, so its context is attacker-controlled
(prompt injection). The design assumes the model *will* be manipulated sometimes:

- Read-only tools run freely. Write tools only create a pending action that a human must approve.
  Actions are single-use, bound to the user, and expire after 30 minutes. Approvals and rejections
  are audited.
- Proposed arguments are validated before a card is shown, so invalid or no-op changes go back to
  the model as errors instead of reaching you.
- Tool results are scanned for text aimed at AI assistants ("ignore previous instructions", tool
  names...). A match raises a warning in the chat, and every later proposal in that conversation
  is flagged **possible prompt injection** and needs a second click to approve.
- Model output is rendered as text only, the same as event data.

Small CPU models are imperfect. Treat answers as a starting point, check them against the linked
data, and never approve an action you didn't ask for. With a GPU, set a stronger model in `.env`
(`CONSOLE_LLM_MODEL`, e.g. `qwen2.5:14b`), then run `./console.sh model` and `./console.sh up`.

On this host's CPU (8 vCPU, no GPU) expect about a minute per answer: the first request after
idle also loads the model (~40 s). Answers keep generating and are saved even if you navigate away.

## Operations

| Command | |
|---|---|
| `./console.sh up` / `down` / `status` / `logs` | lifecycle |
| `./console.sh passwd` | set a new admin password |
| `./console.sh model` | download the assistant model (`CONSOLE_LLM_MODEL`) |

Settings live in `console/.env`: `CONSOLE_PORT`, `CONSOLE_SESSION_HOURS`, and
`CONSOLE_RETENTION_DAYS` (prunes the index only; raw logs follow the per-client rotation
settings).

Tests: `docker run --rm --user 0 -v $PWD/tests:/app/tests:ro --entrypoint sh xpods-console:local -c "pip install -q pytest && python -m pytest -q tests"`
