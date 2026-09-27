# Honeypot Console

A web console, running in its own container, for managing the per-client honeypots
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
  user agents, with filters for honeypot, protocol, status, source IP and time range.
  An inspector panel shows the parsed fields and the raw JSON.
- **Sessions**: SSH, Telnet and TCP sessions, replayed as a terminal transcript
  (commands and the honeypot's responses, in order).
- **Attackers and IP profile**: per-IP first/last seen, protocols, targeted honeypots,
  client software, credentials, commands, HTTP requests, sessions and daily activity.
  Also tags and investigation notes, plus links to AbuseIPDB, GreyNoise, Shodan and
  VirusTotal.
- **Export**: CSV or NDJSON of any filtered view, and a plain IP list for blocklists or
  IOC feeds.

**Management** (every action runs `deploy/deploy.sh`, so the CLI and the UI never drift)
- Create honeypots; edit domain, fake hostname, bind IP, services, TLS, resources,
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
HTTPS). Never expose it directly on a honeypot host's public IP.

## Operations

| Command | |
|---|---|
| `./console.sh up` / `down` / `status` / `logs` | lifecycle |
| `./console.sh passwd` | set a new admin password |

Settings live in `console/.env`: `CONSOLE_PORT`, `CONSOLE_SESSION_HOURS`, and
`CONSOLE_RETENTION_DAYS` (prunes the index only; raw logs follow the per-client rotation
settings).

Tests: `docker run --rm --user 0 -v $PWD/tests:/app/tests:ro --entrypoint sh honeypot-console:local -c "pip install -q pytest && python -m pytest -q tests"`
