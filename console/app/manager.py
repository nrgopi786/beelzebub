"""Honeypot instance management. All lifecycle work is delegated to deploy/deploy.sh."""
import ipaddress
import os
import re
import subprocess
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field

from . import config

CLIENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")
CUSTOM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}\.yaml$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
SAFE_VALUE_RE = re.compile(r'^[^"$`\\\n\r]*$')
MASK = "••••••"
SECRET_KEYS = {"HP_SHIP_AUTH_HEADER", "HP_RABBITMQ_URI", "OPEN_AI_SECRET_KEY"}
ACTIONS = {"up", "down", "restart", "validate", "cert"}


class ValidationError(ValueError):
    pass


def available_services() -> list[str]:
    names = sorted(p.stem for p in config.SERVICES_DIR.glob("*.yaml"))
    return sorted(names + ["https-443"])


def _int_range(lo, hi):
    def check(v):
        if not v.isdigit() or not lo <= int(v) <= hi:
            raise ValidationError(f"must be an integer between {lo} and {hi}")
    return check


def _regex(rx, msg, allow_empty=False):
    def check(v):
        if (allow_empty and v == "") or re.fullmatch(rx, v):
            return
        raise ValidationError(msg)
    return check


def _ip(v):
    try:
        ipaddress.ip_address(v)
    except ValueError:
        raise ValidationError("must be an IP address") from None


def _services(v):
    names = v.split()
    if not names:
        raise ValidationError("select at least one service")
    unknown = set(names) - set(available_services())
    if unknown:
        raise ValidationError(f"unknown services: {', '.join(sorted(unknown))}")


def _domain(v):
    if not DOMAIN_RE.match(v):
        raise ValidationError("must be a valid domain name")


EDITABLE = {
    "HP_DOMAIN": _domain,
    "HP_HOSTNAME": _regex(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", "letters, digits and dashes only"),
    "HP_BIND_IP": _ip,
    "HP_SERVICES": _services,
    "HP_TLS": _regex(r"selfsigned|letsencrypt", "selfsigned or letsencrypt"),
    "HP_LETSENCRYPT_EMAIL": _regex(r"[^@\s]+@[^@\s]+\.[^@\s]+", "must be an email address", True),
    "HP_METRICS_PORT": _int_range(1024, 65535),
    "HP_CONTAINER_MEM": _regex(r"\d{2,6}[mg]", "e.g. 384m or 1g"),
    "HP_MEM_LIMIT_MIB": _int_range(32, 65536),
    "HP_CPUS": _regex(r"\d{1,2}(\.\d{1,2})?", "e.g. 1.0"),
    "HP_LOG_MAX_MB": _int_range(1, 100000),
    "HP_LOG_KEEP_DAYS": _int_range(1, 3650),
    "HP_SHIP_URL": _regex(r"https?://[^\s]+", "must be an http(s) URL", True),
    "HP_SHIP_AUTH_HEADER": _regex(r"[ -~]{0,4096}", "printable ASCII only", True),
    "HP_RABBITMQ_ENABLED": _regex(r"true|false", "true or false"),
    "HP_RABBITMQ_URI": _regex(r"amqps?://[^\s]+", "must be an amqp(s) URI", True),
    "OPEN_AI_SECRET_KEY": _regex(r"[ -~]{0,512}", "printable ASCII only", True),
}


# --------------------------------------------------------------------------- env files

def _env_path(client: str):
    if not CLIENT_RE.match(client):
        raise ValidationError("invalid client name")
    path = config.CLIENTS_DIR / client / ".env"
    if not path.is_file():
        raise KeyError(client)
    return path


def _parse_env(text: str) -> dict[str, str]:
    env = {}
    for line in text.splitlines():
        m = re.match(r"^([A-Z_][A-Z0-9_]*)=(.*)$", line)
        if m:
            val = m.group(2).strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                val = val[1:-1]
            env[m.group(1)] = val
    return env


def read_env(client: str, mask: bool = True) -> dict[str, str]:
    env = _parse_env(_env_path(client).read_text())
    if mask:
        for k in SECRET_KEYS:
            if env.get(k):
                env[k] = MASK
    return env


def update_env(client: str, changes: dict[str, str]) -> list[str]:
    """Validate and apply changes in place, keeping comments/order. Returns changed keys."""
    path = _env_path(client)
    current = _parse_env(path.read_text())
    apply = {}
    for key, value in changes.items():
        if key not in EDITABLE:
            raise ValidationError(f"{key} is not editable")
        value = str(value).strip()
        if key in SECRET_KEYS and value == MASK:
            continue
        if key == "HP_SERVICES":
            value = " ".join(value.split())
        if not SAFE_VALUE_RE.match(value):
            raise ValidationError(f"{key}: quotes, $, backticks and backslashes are not allowed")
        try:
            EDITABLE[key](value)
        except ValidationError as exc:
            raise ValidationError(f"{key}: {exc}") from None
        if current.get(key) != value:
            apply[key] = value
    if not apply:
        return []

    lines, seen = path.read_text().splitlines(), set()
    for i, line in enumerate(lines):
        m = re.match(r"^([A-Z_][A-Z0-9_]*)=", line)
        if m and m.group(1) in apply:
            lines[i] = f'{m.group(1)}="{apply[m.group(1)]}"'
            seen.add(m.group(1))
    lines += [f'{k}="{v}"' for k, v in apply.items() if k not in seen]
    tmp = path.with_suffix(".tmp")
    tmp.write_text("\n".join(lines) + "\n")
    tmp.chmod(0o600)
    tmp.replace(path)
    return sorted(apply)


# --------------------------------------------------------------------------- docker status

def container_status() -> dict[str, list[dict]]:
    """Map client name -> containers of its hp-<client> compose project."""
    fmt = '{{.Label "com.docker.compose.project"}}\t{{.Label "com.docker.compose.service"}}\t{{.State}}\t{{.Status}}\t{{.Ports}}'
    try:
        out = subprocess.run(
            ["docker", "ps", "-a", "--filter", "label=com.docker.compose.project", "--format", fmt],
            capture_output=True, text=True, timeout=15, check=True,
        ).stdout
    except (subprocess.SubprocessError, OSError):
        return {}
    result: dict[str, list[dict]] = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 5 or not parts[0].startswith("hp-"):
            continue
        result.setdefault(parts[0][3:], []).append(
            {"service": parts[1], "state": parts[2], "status": parts[3], "ports": parts[4]}
        )
    return result


def list_clients() -> list[dict]:
    status = container_status()
    clients = []
    if not config.CLIENTS_DIR.is_dir():
        return clients
    for d in sorted(config.CLIENTS_DIR.iterdir()):
        if not (d / ".env").is_file() or not CLIENT_RE.match(d.name):
            continue
        env = read_env(d.name)
        containers = status.get(d.name, [])
        hp = next((c for c in containers if c["service"] == "beelzebub"), None)
        clients.append({
            "name": d.name,
            "domain": env.get("HP_DOMAIN", ""),
            "hostname": env.get("HP_HOSTNAME", ""),
            "bind_ip": env.get("HP_BIND_IP", ""),
            "services": env.get("HP_SERVICES", "").split(),
            "state": hp["state"] if hp else "not deployed",
            "containers": containers,
            "job": jobs.running_for(d.name),
        })
    return clients


# --------------------------------------------------------------------------- custom lures

def _custom_dir(client: str):
    _env_path(client)
    d = config.CLIENTS_DIR / client / "custom"
    d.mkdir(exist_ok=True)
    return d


def _custom_path(client: str, name: str):
    if not CUSTOM_RE.match(name):
        raise ValidationError("file name must match [A-Za-z0-9_.-]+.yaml")
    return _custom_dir(client) / name


def list_custom(client: str) -> list[dict]:
    return [{"name": p.name, "size": p.stat().st_size}
            for p in sorted(_custom_dir(client).glob("*.yaml"))]


def read_custom(client: str, name: str) -> str:
    return _custom_path(client, name).read_text()


def write_custom(client: str, name: str, content: str) -> None:
    if len(content) > 1024 * 1024:
        raise ValidationError("file too large (max 1 MiB)")
    _custom_path(client, name).write_text(content)


def delete_custom(client: str, name: str) -> None:
    _custom_path(client, name).unlink(missing_ok=True)


# --------------------------------------------------------------------------- deploy.sh jobs

def run_sync(args: list[str], timeout: int = 120) -> tuple[int, str]:
    proc = subprocess.run(
        [str(config.DEPLOY_SH), *args], capture_output=True, text=True,
        timeout=timeout, stdin=subprocess.DEVNULL,
    )
    return proc.returncode, (proc.stdout + proc.stderr)[-20000:]


def create_client(name: str, domain: str, hostname: str) -> str:
    if not CLIENT_RE.match(name):
        raise ValidationError("name: lowercase letters, digits and dashes, max 31 chars")
    _domain(domain)
    EDITABLE["HP_HOSTNAME"](hostname)
    rc, out = run_sync(["new", name, domain, hostname])
    if rc != 0:
        raise ValidationError(out.strip().splitlines()[-1] if out.strip() else "deploy.sh new failed")
    return out


@dataclass
class Job:
    id: str
    client: str
    action: str
    user: str
    started: float = field(default_factory=time.time)
    finished: float | None = None
    returncode: int | None = None
    lines: deque = field(default_factory=lambda: deque(maxlen=3000))

    def to_dict(self, output: bool = True) -> dict:
        d = {
            "id": self.id, "client": self.client, "action": self.action, "user": self.user,
            "started": self.started, "finished": self.finished, "returncode": self.returncode,
            "state": "running" if self.finished is None else ("ok" if self.returncode == 0 else "failed"),
        }
        if output:
            d["output"] = "".join(self.lines)
        return d


class JobRunner:
    def __init__(self, keep: int = 50):
        self.jobs: dict[str, Job] = {}
        self.order: deque = deque(maxlen=keep)
        self.lock = threading.Lock()

    def running_for(self, client: str) -> str | None:
        with self.lock:
            for job in self.jobs.values():
                if job.client == client and job.finished is None:
                    return job.id
        return None

    def start(self, client: str, action: str, user: str) -> Job:
        if action not in ACTIONS:
            raise ValidationError(f"unknown action {action}")
        _env_path(client)
        with self.lock:
            if any(j.client == client and j.finished is None for j in self.jobs.values()):
                raise RuntimeError(f"another operation is already running for {client}")
            job = Job(id=uuid.uuid4().hex[:12], client=client, action=action, user=user)
            if len(self.order) == self.order.maxlen:
                self.jobs.pop(self.order[0], None)
            self.order.append(job.id)
            self.jobs[job.id] = job
        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return job

    def _run(self, job: Job) -> None:
        try:
            proc = subprocess.Popen(
                [str(config.DEPLOY_SH), job.action, job.client],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                text=True, bufsize=1, env={**os.environ, "BUILDKIT_PROGRESS": "plain"},
            )
            for line in proc.stdout:
                job.lines.append(line)
            job.returncode = proc.wait()
        except OSError as exc:
            job.lines.append(f"failed to start deploy.sh: {exc}\n")
            job.returncode = 127
        finally:
            job.finished = time.time()

    def get(self, job_id: str) -> Job | None:
        return self.jobs.get(job_id)

    def recent(self) -> list[dict]:
        with self.lock:
            return [self.jobs[i].to_dict(output=False) for i in reversed(self.order) if i in self.jobs]


jobs = JobRunner()
