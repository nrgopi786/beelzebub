# Per-client honeypot deployment

Standalone, containerised honeypot instances built on beelzebub. Each client gets
its own isolated compose project (`hp-<client>`), config, TLS certificate, SSH host
key, and event log. The client's DNS A record points at the honeypot host, so
scanners and attackers targeting that name hit the decoy services.

Nothing runs on the host except Docker: the build, TLS issuance, log rotation, and
log shipping all run in containers.

A web UI for managing these instances and investigating attacker activity lives in
[`console/`](../console/README.md) (`cd console && ./console.sh up`).

## Quick start

```bash
cd deploy
./deploy.sh new acme acme-portal.example.com web01   # scaffold clients/acme/
$EDITOR clients/acme/.env                            # services, bind IP, hostname
./deploy.sh validate acme                            # render + schema check
./deploy.sh up acme                                  # build + start
./deploy.sh events acme                              # recent attacker events
```

Then create or change the client's DNS record:
`acme-portal.example.com. A <honeypot public IP>`.

## Commands

| Command | Purpose |
|---|---|
| `new <client> <domain> [hostname]` | Scaffold `clients/<client>/` from `template/` |
| `up <client>` | Render config, check ports, build the image, start the stack |
| `down <client>` / `restart <client>` | Stop / restart the stack |
| `status [client]` | Container status (all `hp-*` projects when no client is given) |
| `logs <client>` | Follow container stdout |
| `events <client> [n]` | Last *n* lines of the JSON event log |
| `validate <client>` | Render the config and run `beelzebub validate` on it |
| `cert <client>` | Issue or renew a Let's Encrypt certificate (certbot, HTTP-01) |
| `firewall <client>` | Print `DOCKER-USER` iptables rules that block honeypot egress |
| `list` | List configured clients |

## Layout

```
deploy/
├── Dockerfile            hardened scratch image (non-root, stripped binary)
├── compose.yml           shared stack: beelzebub + logrotate (+ shipper profile)
├── deploy.sh             lifecycle tooling
├── template/             client.env, core beelzebub.yaml
├── vector/vector.yaml    optional HTTP log shipper
└── clients/<client>/     gitignored per-client instance
    ├── .env              settings (chmod 600)
    ├── custom/           client-specific service YAMLs (copied verbatim)
    ├── certs/            fullchain.pem + privkey.pem
    ├── config/           GENERATED on every `up`; do not edit
    ├── compose.ports.yml GENERATED from the enabled services' `address:` fields
    └── data/
        ├── logs/         beelzebub.log (+ rotated *.log.gz)
        ├── keys/         persistent SSH host keys
        └── vector/       shipper disk buffer / checkpoints
```

## How the config is rendered

On every `up`/`validate`, `config/` is rebuilt from:

1. `HP_SERVICES` in `.env`: each name is copied from `configurations/services/<name>.yaml`,
   so upstream lure improvements are picked up when you merge upstream.
2. Per-client tweaks: SSH/Telnet `serverName` is set to `HP_HOSTNAME`. Each SSH service
   gets `hostKeyPath` so its fingerprint survives restarts and rebuilds. A fingerprint
   that changes on every restart is an easy honeypot tell.
3. `https-443`: synthesised from `http-80` with the client certificate.
4. `custom/*.yaml`: copied last, replacing any generated file with the same name.

Published ports are derived from the rendered files, so adding a service is only an
edit to `HP_SERVICES` or a drop-in under `custom/`.

## Security posture

- The container runs as the deploying user's uid (non-root), with a read-only root
  filesystem, `cap_drop: ALL`, `no-new-privileges`, and memory/CPU/PID limits. It binds
  low ports through the namespaced `net.ipv4.ip_unprivileged_port_start=0` sysctl
  instead of `CAP_NET_BIND_SERVICE`.
- The runtime image is `scratch`: no shell or package manager inside. Services are
  emulated and never execute attacker input.
- Config is mounted read-only; only `data/logs` and `data/keys` are writable.
- Metrics are published on `127.0.0.1:<HP_METRICS_PORT>` only.
- Egress: apply the rules from `./deploy.sh firewall <client>` on the host. They stop a
  compromised or abused honeypot from initiating outbound connections. Skip or adjust
  them if you use the LLM or RabbitMQ integrations.

## Host preparation (once per honeypot host)

1. **Free the ports.** The honeypot needs 22, 80, 443, and the others. Move the real
   sshd to another port (for example `Port 2222` in `/etc/ssh/sshd_config`) and restrict
   it to your admin IPs. `deploy.sh up` refuses to start while a published port is
   in use.
2. **Preserve attacker source IPs.** External traffic is DNAT'd by iptables, so events
   record the real source IP. Connections handled by Docker's userland proxy (loopback,
   and IPv6 when Docker IPv6 is off) show the bridge gateway (`172.x.0.1`) instead. Set
   `{"userland-proxy": false}` in `/etc/docker/daemon.json`. If the client's record also
   has an AAAA, enable IPv6 in Docker too.
3. **One public IP per client** when several clients share one host: set `HP_BIND_IP`
   in each client's `.env`. Metrics ports are assigned uniquely by `new`.

## TLS

- `HP_TLS=selfsigned` (default): generated on first `up` for `HP_DOMAIN` and `www.HP_DOMAIN`.
- `HP_TLS=letsencrypt`: set `HP_LETSENCRYPT_EMAIL`, point DNS at the host, then run
  `./deploy.sh cert <client>`. Port 80 is freed for a few seconds during issuance. Re-run
  the command from cron roughly monthly to renew. Issuance publishes the name in
  Certificate Transparency logs, which draws more scanner traffic. For a honeypot that
  is usually what you want.

## Events and log shipping

`data/logs/beelzebub.log` is JSON lines. Attacker activity is in records with an
`event` object: `SourceIp`, `Protocol`, `User`, `Password`, `Command`, `RequestURI`,
`UserAgent`, `Body`, and so on. The `logrotate` sidecar rotates the log at
`HP_LOG_MAX_MB` and deletes archives older than `HP_LOG_KEEP_DAYS`.

To centralise events, set `HP_SHIP_URL` (and optionally `HP_SHIP_AUTH_HEADER`) and run
`up` again. A Vector sidecar then posts newline-delimited JSON, tagged with
`honeypot_client` and `honeypot_domain`, with a disk buffer for collector outages.
Change the sink in `vector/vector.yaml` for Elasticsearch, Splunk HEC, Loki, S3, and
other targets.

Prometheus counters (`beelzebub_events_total`, `beelzebub_ssh_events_total`, and others)
are served at `http://127.0.0.1:<HP_METRICS_PORT>/metrics`.

## Keeping up with upstream

```bash
git fetch upstream && git merge upstream/main   # then ./deploy.sh restart <client>
```
