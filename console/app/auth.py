"""Single-admin authentication: scrypt password hash + HMAC-signed session cookie."""
import base64
import hashlib
import hmac
import json
import secrets
import threading
import time

from . import config

COOKIE = "hp_console"
_N, _R, _P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    # ':' separators: '$' would be interpolated by docker compose env files.
    return f"scrypt:{_N}:{_R}:{_P}:{salt.hex()}:{digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, n, r, p, salt, digest = encoded.split(":")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt),
                              n=int(n), r=int(r), p=int(p), dklen=len(bytes.fromhex(digest)))
        return hmac.compare_digest(calc, bytes.fromhex(digest))
    except (ValueError, TypeError):
        return False


def _sign(payload: bytes) -> str:
    return hmac.new(config.SECRET_KEY.encode(), payload, hashlib.sha256).hexdigest()


def issue_token(user: str) -> str:
    payload = base64.urlsafe_b64encode(
        json.dumps({"u": user, "exp": int(time.time()) + config.SESSION_HOURS * 3600}).encode()
    )
    return f"{payload.decode()}.{_sign(payload)}"


def read_token(token: str | None) -> str | None:
    if not token or "." not in token:
        return None
    payload, sig = token.rsplit(".", 1)
    if not hmac.compare_digest(sig, _sign(payload.encode())):
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(payload))
    except ValueError:
        return None
    if data.get("exp", 0) < time.time():
        return None
    return data.get("u")


class LoginThrottle:
    """Per-source exponential lockout after repeated failures."""

    def __init__(self, free_attempts: int = 5):
        self.free = free_attempts
        self.state: dict[str, tuple[int, float]] = {}
        self.lock = threading.Lock()

    def retry_after(self, key: str) -> int:
        with self.lock:
            fails, until = self.state.get(key, (0, 0.0))
            return max(0, int(until - time.time()))

    def failure(self, key: str) -> None:
        with self.lock:
            fails, _ = self.state.get(key, (0, 0.0))
            fails += 1
            delay = 0 if fails < self.free else min(900, 2 ** (fails - self.free) * 5)
            self.state[key] = (fails, time.time() + delay)

    def success(self, key: str) -> None:
        with self.lock:
            self.state.pop(key, None)


def check_login(user: str, password: str) -> bool:
    user_ok = hmac.compare_digest(user.encode(), config.ADMIN_USER.encode())
    pass_ok = verify_password(password, config.ADMIN_PASSWORD_HASH)
    return user_ok and pass_ok
