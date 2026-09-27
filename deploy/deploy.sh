#!/usr/bin/env bash
# Per-client honeypot lifecycle on top of beelzebub, fully containerised.
#
#   ./deploy.sh new <client> <domain> [fake-hostname]   scaffold clients/<client>/
#   ./deploy.sh up <client>                              render config, build, start
#   ./deploy.sh down <client>                            stop and remove containers
#   ./deploy.sh restart <client>                         down + up
#   ./deploy.sh status [client]                          container status
#   ./deploy.sh logs <client>                            follow container stdout
#   ./deploy.sh events <client> [n]                      last n attacker events (default 50)
#   ./deploy.sh validate <client>                        render + schema-validate config
#   ./deploy.sh cert <client>                            issue/renew Let's Encrypt cert
#   ./deploy.sh firewall <client>                        print host egress-lockdown rules
#   ./deploy.sh list                                     list configured clients
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$DEPLOY_DIR")"
CLIENTS_DIR="$DEPLOY_DIR/clients"
SERVICES_SRC="$REPO_DIR/configurations/services"
IMAGE="beelzebub-honeypot:local"

die()  { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }
warn() { echo "warning: $*" >&2; }

if docker info >/dev/null 2>&1; then
  :
elif sg docker -c "docker info" >/dev/null 2>&1; then
  # Group membership granted but not yet active in this login session.
  docker() { sg docker -c "docker $(printf '%q ' "$@")"; }
else
  die "cannot talk to the Docker daemon (is it running, and are you in the docker group?)"
fi

client_dir() { echo "$CLIENTS_DIR/$1"; }

require_client() {
  [[ -n "${1:-}" ]] || die "client name required"
  [[ -f "$(client_dir "$1")/.env" ]] || die "unknown client '$1' (run: $0 new $1 <domain>)"
}

load_env() {
  set -a
  # shellcheck disable=SC1091
  source "$(client_dir "$1")/.env"
  set +a
  export HP_UID HP_GID
  HP_UID="$(id -u)"
  HP_GID="$(id -g)"
}

compose() {
  local client=$1; shift
  local dir; dir="$(client_dir "$client")"
  local args=(compose --project-directory "$DEPLOY_DIR" -f "$DEPLOY_DIR/compose.yml" --env-file "$dir/.env")
  [[ -f "$dir/compose.ports.yml" ]] && args+=(-f "$dir/compose.ports.yml")
  [[ -n "${HP_SHIP_URL:-}" ]] && args+=(--profile ship)
  HP_UID="$(id -u)" HP_GID="$(id -g)" docker "${args[@]}" "$@"
}

# ---------------------------------------------------------------------------

cmd_new() {
  local client=${1:-} domain=${2:-} hostname=${3:-srv01}
  [[ -n "$client" && -n "$domain" ]] || die "usage: $0 new <client> <domain> [fake-hostname]"
  [[ "$client" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "client name must be lowercase alnum/dash, max 31 chars"
  local dir; dir="$(client_dir "$client")"
  [[ -e "$dir" ]] && die "client '$client' already exists at $dir"

  # Next free loopback metrics port, starting at 21120.
  local port=21120
  while grep -qs "^HP_METRICS_PORT=$port$" "$CLIENTS_DIR"/*/.env; do port=$((port + 1)); done

  mkdir -p "$dir"/{config/services,custom,certs,data/logs,data/keys,data/vector}
  sed -e "s/__CLIENT__/$client/g" -e "s/__DOMAIN__/$domain/g" \
      -e "s/__HOSTNAME__/$hostname/g" -e "s/__METRICS_PORT__/$port/g" \
      "$DEPLOY_DIR/template/client.env" > "$dir/.env"
  chmod 600 "$dir/.env"
  cp "$DEPLOY_DIR/template/custom/README.md" "$dir/custom/"

  info "created $dir"
  echo "    1. review $dir/.env (services, bind IP, hostname)"
  echo "    2. point the A record for $domain at this host's public IP"
  echo "    3. $0 up $client"
}

# Build clients/<c>/config from .env + upstream service definitions + custom/.
cmd_render() {
  local client=$1
  local dir; dir="$(client_dir "$client")"
  load_env "$client"

  local out="$dir/config/services"
  rm -rf "$dir/config"
  mkdir -p "$out" "$dir"/data/{logs,keys,vector}
  cp "$DEPLOY_DIR/template/beelzebub.yaml" "$dir/config/beelzebub.yaml"

  local svc
  for svc in $HP_SERVICES; do
    if [[ "$svc" == "https-443" ]]; then
      render_https "$client" "$out"
      continue
    fi
    local src="$SERVICES_SRC/$svc.yaml"
    [[ -f "$src" ]] || die "unknown service '$svc' in HP_SERVICES (no $src)"
    local dst="$out/$svc.yaml"
    cp "$src" "$dst"
    local proto; proto="$(yaml_value protocol "$dst")"
    if [[ "$proto" == "ssh" || "$proto" == "telnet" ]]; then
      sed -i -E "s/^serverName:.*/serverName: \"$HP_HOSTNAME\"/" "$dst"
    fi
    if [[ "$proto" == "ssh" ]]; then
      local p; p="$(service_port "$dst")"
      ensure_newline "$dst"
      echo "hostKeyPath: \"/data/keys/ssh_host_ed25519_key_$p\"" >> "$dst"
    fi
  done

  local f
  for f in "$dir"/custom/*.yaml; do
    [[ -e "$f" ]] || continue
    cp "$f" "$out/"
  done

  write_ports "$client"
}

render_https() {
  local client=$1 out=$2
  local dir; dir="$(client_dir "$client")"
  ensure_cert "$client"
  local dst="$out/https-443.yaml"
  sed -E 's/^address:.*/address: ":443"/' "$SERVICES_SRC/http-80.yaml" > "$dst"
  ensure_newline "$dst"
  cat >> "$dst" <<EOF
tlsCertPath: "/config/certs/fullchain.pem"
tlsKeyPath: "/config/certs/privkey.pem"
EOF
  mkdir -p "$dir/config/certs"
  cp "$dir/certs/fullchain.pem" "$dir/certs/privkey.pem" "$dir/config/certs/"
}

ensure_newline() { [[ -z "$(tail -c1 "$1")" ]] || echo >> "$1"; }

yaml_value() { sed -nE "s/^$1:[[:space:]]*\"?([^\"]*)\"?[[:space:]]*$/\1/p" "$2" | head -n1; }

service_port() {
  local addr; addr="$(yaml_value address "$1")"
  echo "${addr##*:}"
}

write_ports() {
  local client=$1
  local dir; dir="$(client_dir "$client")"
  local file="$dir/compose.ports.yml"
  {
    echo "# Generated by deploy.sh from config/services — do not edit."
    echo "services:"
    echo "  beelzebub:"
    echo "    ports:"
    echo "      - \"127.0.0.1:${HP_METRICS_PORT}:2112/tcp\""
    local f p seen=" "
    for f in "$dir"/config/services/*.yaml; do
      p="$(service_port "$f")"
      [[ "$p" =~ ^[0-9]+$ ]] || die "cannot parse port from $f"
      [[ "$seen" == *" $p "* ]] && die "port $p declared by more than one service"
      seen+="$p "
      echo "      - \"${HP_BIND_IP}:${p}:${p}/tcp\""
    done
  } > "$file"
}

ensure_cert() {
  local client=$1
  local dir; dir="$(client_dir "$client")"
  [[ -s "$dir/certs/fullchain.pem" && -s "$dir/certs/privkey.pem" ]] && return
  [[ "${HP_TLS:-selfsigned}" == "letsencrypt" ]] && die "no certificate yet; run: $0 cert $client"
  info "generating self-signed certificate for $HP_DOMAIN"
  docker run --rm --user "$(id -u):$(id -g)" -v "$dir/certs:/certs" alpine/openssl:3.5.4 \
    req -x509 -newkey rsa:2048 -nodes -days 397 \
    -subj "/CN=$HP_DOMAIN" -addext "subjectAltName=DNS:$HP_DOMAIN,DNS:www.$HP_DOMAIN" \
    -keyout /certs/privkey.pem -out /certs/fullchain.pem >/dev/null 2>&1 \
    || die "certificate generation failed"
}

check_ports_free() {
  local client=$1
  local dir; dir="$(client_dir "$client")"
  local mine; mine="$(docker ps -q --filter "label=com.docker.compose.project=hp-$client")"
  [[ -n "$mine" ]] && return  # already running; compose will reconcile
  local p busy=()
  for p in $(grep -oE ':[0-9]+:[0-9]+/tcp' "$dir/compose.ports.yml" | cut -d: -f2); do
    if ss -Hltn "sport = :$p" 2>/dev/null | grep -q .; then busy+=("$p"); fi
  done
  if ((${#busy[@]})); then
    die "host ports already in use: ${busy[*]} (move the host service, e.g. sshd to 2222, or drop it from HP_SERVICES)"
  fi
}

cmd_validate() {
  local client=$1
  cmd_render "$client"
  info "validating rendered configuration"
  docker image inspect "$IMAGE" >/dev/null 2>&1 || compose "$client" build beelzebub
  local dir; dir="$(client_dir "$client")"
  docker run --rm --user "$(id -u):$(id -g)" --network none \
    -v "$dir/config:/config:ro" -v "$dir/data/keys:/data/keys" \
    --entrypoint /beelzebub "$IMAGE" validate \
    --conf-core /config/beelzebub.yaml --conf-services /config/services/
}

cmd_up() {
  local client=$1
  cmd_render "$client"
  check_ports_free "$client"
  info "building image and starting hp-$client"
  compose "$client" up -d --build --remove-orphans
  compose "$client" ps
  echo
  info "honeypot for $HP_DOMAIN is up. Ports:"
  grep -oE '"[^"]+/tcp"' "$(client_dir "$client")/compose.ports.yml" | tr -d '"' | sed 's/^/    /'
  echo "    events: $0 events $client"
}

cmd_down()    { load_env "$1"; compose "$1" --profile ship down --remove-orphans; }
cmd_restart() { cmd_down "$1"; cmd_up "$1"; }
cmd_logs()    { load_env "$1"; compose "$1" logs -f --tail 100; }

cmd_status() {
  if [[ -n "${1:-}" ]]; then
    require_client "$1"; load_env "$1"; compose "$1" ps
  else
    docker ps --filter "label=com.docker.compose.project" \
      --format 'table {{.Label "com.docker.compose.project"}}\t{{.Names}}\t{{.Status}}' | grep -E '^(PROJECT|hp-)' || true
  fi
}

cmd_events() {
  local client=$1 n=${2:-50}
  local log; log="$(client_dir "$client")/data/logs/beelzebub.log"
  [[ -f "$log" ]] || die "no events logged yet ($log)"
  tail -n "$n" "$log"
}

cmd_cert() {
  local client=$1
  load_env "$client"
  [[ -n "${HP_LETSENCRYPT_EMAIL:-}" ]] || die "set HP_LETSENCRYPT_EMAIL in $(client_dir "$client")/.env"
  local dir; dir="$(client_dir "$client")"
  local le="$dir/data/letsencrypt"
  mkdir -p "$le"
  local running; running="$(docker ps -q --filter "label=com.docker.compose.project=hp-$client" --filter "label=com.docker.compose.service=beelzebub")"
  [[ -n "$running" ]] && { info "stopping honeypot briefly to free port 80"; compose "$client" stop beelzebub; }
  info "requesting certificate for $HP_DOMAIN (HTTP-01, standalone)"
  local rc=0
  docker run --rm -p "${HP_BIND_IP}:80:80" -v "$le:/etc/letsencrypt" certbot/certbot:v5.1.0 \
    certonly --standalone --non-interactive --agree-tos --keep-until-expiring \
    -m "$HP_LETSENCRYPT_EMAIL" -d "$HP_DOMAIN" || rc=$?
  if ((rc == 0)); then
    # certbot runs as root; copy the live material out with our ownership.
    docker run --rm -v "$le:/le:ro" -v "$dir/certs:/certs" --user 0 alpine:3.22 sh -c \
      "cp -L /le/live/$HP_DOMAIN/fullchain.pem /le/live/$HP_DOMAIN/privkey.pem /certs/ && chown $(id -u):$(id -g) /certs/*.pem && chmod 600 /certs/privkey.pem"
    info "certificate installed in $dir/certs"
  fi
  [[ -n "$running" ]] && cmd_up "$client"
  return $rc
}

cmd_firewall() {
  local client=$1
  load_env "$client"
  local net="hp-${client}_honeynet"
  local subnet; subnet="$(docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "$net" 2>/dev/null)" \
    || die "network $net not found; start the client first"
  cat <<EOF
# Block honeypot-initiated outbound traffic (replies to attackers are still allowed).
# Review, then run as root. Persist with iptables-persistent or your firewall manager.
iptables -I DOCKER-USER -s $subnet -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -I DOCKER-USER 2 -s $subnet -j DROP
EOF
  if [[ -n "${HP_RABBITMQ_URI:-}${OPEN_AI_SECRET_KEY:-}" ]]; then
    echo "# NOTE: RabbitMQ/LLM integrations need outbound access; add ACCEPT rules for those hosts above the DROP."
  fi
}

cmd_list() {
  local d
  for d in "$CLIENTS_DIR"/*/; do
    [[ -f "$d/.env" ]] || continue
    ( set -a; source "$d/.env"; printf '%-20s %-30s bind=%s metrics=127.0.0.1:%s\n' "$HP_CLIENT" "$HP_DOMAIN" "$HP_BIND_IP" "$HP_METRICS_PORT" )
  done
}

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

main() {
  local cmd=${1:-}; shift || true
  case "$cmd" in
    new)      cmd_new "$@" ;;
    list)     cmd_list ;;
    status)   cmd_status "$@" ;;
    up|down|restart|logs|events|validate|cert|firewall|render)
      require_client "${1:-}"
      "cmd_$cmd" "$@" ;;
    -h|--help|help|"") usage ;;
    *) usage 1 ;;
  esac
}

main "$@"
