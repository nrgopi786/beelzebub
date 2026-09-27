import os
from pathlib import Path

REPO_DIR = Path(os.environ.get("REPO_DIR", "/repo"))
DEPLOY_DIR = REPO_DIR / "deploy"
CLIENTS_DIR = DEPLOY_DIR / "clients"
DEPLOY_SH = DEPLOY_DIR / "deploy.sh"
SERVICES_DIR = REPO_DIR / "configurations" / "services"

DB_PATH = Path(os.environ.get("CONSOLE_DB", "/data/console.db"))
SECRET_KEY = os.environ.get("CONSOLE_SECRET_KEY", "")
ADMIN_USER = os.environ.get("CONSOLE_ADMIN_USER", "admin")
ADMIN_PASSWORD_HASH = os.environ.get("CONSOLE_ADMIN_PASSWORD_HASH", "")
COOKIE_SECURE = os.environ.get("CONSOLE_COOKIE_SECURE", "false").lower() == "true"
SESSION_HOURS = int(os.environ.get("CONSOLE_SESSION_HOURS", "12"))
RETENTION_DAYS = int(os.environ.get("CONSOLE_RETENTION_DAYS", "0"))
INGEST_INTERVAL = float(os.environ.get("CONSOLE_INGEST_INTERVAL", "3"))

LLM_URL = os.environ.get("CONSOLE_LLM_URL", f"http://127.0.0.1:{os.environ.get('CONSOLE_LLM_PORT', '11500')}")
LLM_MODEL = os.environ.get("CONSOLE_LLM_MODEL", "qwen2.5:3b")
