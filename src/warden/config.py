"""Configuration management for WARDEN.

Settings come from process environment variables. Entry points (the runner and
the helper scripts) call :func:`load_environment` to merge the repository-root
``.env`` into the environment first, so behaviour does not depend on the current
working directory. Library code never loads ``.env`` implicitly.
"""

from __future__ import annotations

import os
import re
import urllib.parse
import secrets
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from pydantic import BaseModel, Field

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
DEFAULT_ENV_FILE: Path = REPO_ROOT / ".env"

VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_TRUE = {"true", "1", "yes", "on"}
_FALSE = {"false", "0", "no", "off"}

MIN_SECRET_KEY_LENGTH = 32
PLACEHOLDER_MARKERS = ("your_", "changeme", "change_me", "placeholder", "example", "<", ">")


class ConfigError(ValueError):
    """Raised when WARDEN configuration is missing, malformed or insecure."""


def is_placeholder(value: str) -> bool:
    """Return True when a value looks like a template placeholder rather than a real secret."""
    lowered = (value or "").strip().lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def load_environment(env_file: Optional[Path | str] = None) -> Optional[Path]:
    """Merge a ``.env`` file into ``os.environ`` without overriding real environment variables.

    The file is ``WARDEN_ENV_FILE`` if set, else ``<repo root>/.env`` regardless of the
    current working directory. Returns the path loaded, or ``None`` if it does not exist.
    """
    path = Path(env_file or os.getenv("WARDEN_ENV_FILE") or DEFAULT_ENV_FILE)
    if not path.is_absolute():
        path = REPO_ROOT / path
    if not path.is_file():
        return None
    load_dotenv(path, override=False)
    return path


def resolve_repo_path(value: str | Path) -> Path:
    """Resolve a configured path; relative paths are anchored at the repository root."""
    p = Path(value).expanduser()
    if not p.is_absolute():
        p = REPO_ROOT / p
    return p.resolve()


def env_bool(name: str, default: bool) -> bool:
    """Parse a strict boolean setting. Unrecognised values are an error, never silently False."""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    lowered = raw.strip().lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    raise ConfigError(f"{name} must be one of true/false/1/0/yes/no/on/off (got an unrecognised value).")


def _always_on(name: str) -> bool:
    """Safety controls that the pipeline enforces unconditionally.

    The policy engine always applies workspace containment and destructive-action approval, so
    these settings can only be left on. Turning one off is rejected rather than silently ignored.
    """
    if not env_bool(name, True):
        raise ConfigError(f"{name} cannot be disabled: this control is always enforced.")
    return True


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    """Parse a bounded integer setting; malformed or out-of-range values are an error."""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        raise ConfigError(f"{name} must be an integer between {minimum} and {maximum}.") from None
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be an integer between {minimum} and {maximum}.")
    return value


AGENT_ADDRESS_PATTERN = re.compile(r"^agent1[a-z0-9]{50,70}$")
RISK_ANALYST_MODES = {"local", "remote", "off"}


def _auditor_address() -> Optional[str]:
    """Address of the one remote Auditor whose attestations WARDEN will trust."""
    raw = (os.getenv("WARDEN_AUDITOR_ADDRESS") or "").strip()
    if not raw:
        return None
    if not AGENT_ADDRESS_PATTERN.match(raw):
        raise ConfigError("WARDEN_AUDITOR_ADDRESS must be a uAgents address (agent1...).")
    return raw


def _risk_analyst_mode() -> str:
    raw = (os.getenv("WARDEN_RISK_ANALYST") or "local").strip().lower()
    if raw not in RISK_ANALYST_MODES:
        raise ConfigError(f"WARDEN_RISK_ANALYST must be one of {sorted(RISK_ANALYST_MODES)}.")
    return raw


def _risk_analyst_address() -> Optional[str]:
    """Address of the one Risk Analyst agent whose signed assessments WARDEN will accept."""
    raw = (os.getenv("WARDEN_RISK_ANALYST_ADDRESS") or "").strip()
    if not raw:
        return None
    if not AGENT_ADDRESS_PATTERN.match(raw):
        raise ConfigError("WARDEN_RISK_ANALYST_ADDRESS must be a uAgents address (agent1...).")
    return raw


def _risk_analyst_endpoint() -> Optional[str]:
    """Optional fixed endpoint for the analyst (e.g. a sidecar on loopback); otherwise Almanac resolves it."""
    raw = (os.getenv("WARDEN_RISK_ANALYST_ENDPOINT") or "").strip()
    if not raw:
        return None
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.path.rstrip("/") != "/submit":
        raise ConfigError("WARDEN_RISK_ANALYST_ENDPOINT must be an absolute URL ending in /submit.")
    if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ConfigError("WARDEN_RISK_ANALYST_ENDPOINT may use plain http only on loopback.")
    return raw.rstrip("/")


def _log_level() -> str:
    level = os.getenv("WARDEN_LOG_LEVEL", "INFO").strip().upper() or "INFO"
    if level not in VALID_LOG_LEVELS:
        raise ConfigError(f"WARDEN_LOG_LEVEL must be one of {sorted(VALID_LOG_LEVELS)}.")
    return level


def _secret_key() -> str:
    """Authorization-token signing key.

    Tokens and pending approvals are in-memory and short-lived, so persistence across
    restarts is not required: when unset, a fresh random key is generated per process.
    A configured key must be strong.
    """
    raw = os.getenv("WARDEN_SECRET_KEY")
    if raw is None or raw.strip() == "":
        return secrets.token_hex(32)
    key = raw.strip()
    if is_placeholder(key) or len(key) < MIN_SECRET_KEY_LENGTH:
        raise ConfigError(
            f"WARDEN_SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters and not a "
            "placeholder. Leave it unset to use a random per-process key."
        )
    return key


def _workspace_root() -> Path:
    return resolve_repo_path(os.getenv("WARDEN_WORKSPACE_ROOT") or "./temp_workspace")


def _audit_log() -> Optional[Path]:
    """Persistent JSONL audit log location; an explicitly empty value disables persistence."""
    raw = os.getenv("WARDEN_AUDIT_LOG")
    if raw is not None and raw.strip() == "":
        return None
    return resolve_repo_path(raw or "./logs/audit.jsonl")


class WardenConfig(BaseModel):
    """Runtime configuration for WARDEN."""
    env: str = Field(default_factory=lambda: os.getenv("WARDEN_ENV", "development"))
    log_level: str = Field(default_factory=_log_level)
    workspace_root: Path = Field(default_factory=_workspace_root)
    enforce_workspace_containment: bool = Field(
        default_factory=lambda: _always_on("WARDEN_ENFORCE_WORKSPACE_CONTAINMENT")
    )
    require_approval_for_destructive: bool = Field(
        default_factory=lambda: _always_on("WARDEN_REQUIRE_APPROVAL_FOR_DESTRUCTIVE")
    )
    audit_log: Optional[Path] = Field(default_factory=_audit_log)
    approval_ttl_seconds: int = Field(
        default_factory=lambda: env_int("WARDEN_APPROVAL_TTL_SECONDS", 300, 10, 86400)
    )
    max_pending_approvals: int = Field(
        default_factory=lambda: env_int("WARDEN_MAX_PENDING_APPROVALS", 50, 1, 10000)
    )
    # Opt-in remote Auditor. Off unless explicitly enabled; enabling it requires a trusted address.
    remote_auditor: bool = Field(default_factory=lambda: env_bool("WARDEN_REMOTE_AUDITOR", False))
    auditor_address: Optional[str] = Field(default_factory=_auditor_address)
    auditor_timeout_seconds: int = Field(
        default_factory=lambda: env_int("WARDEN_AUDITOR_TIMEOUT_SECONDS", 10, 1, 120)
    )
    # Risk Analyst (advisory only). "local" runs it in-process; "remote" asks a separate uAgent.
    risk_analyst: str = Field(default_factory=_risk_analyst_mode)
    risk_analyst_address: Optional[str] = Field(default_factory=_risk_analyst_address)
    risk_analyst_endpoint: Optional[str] = Field(default_factory=_risk_analyst_endpoint)
    risk_analyst_timeout_seconds: int = Field(
        default_factory=lambda: env_int("WARDEN_RISK_ANALYST_TIMEOUT_SECONDS", 5, 1, 60)
    )

    secret_key: str = Field(default_factory=_secret_key, repr=False)

    def __init__(self, **data) -> None:
        super().__init__(**data)
        if self.remote_auditor and not self.auditor_address:
            raise ConfigError("WARDEN_REMOTE_AUDITOR=true requires WARDEN_AUDITOR_ADDRESS.")
        if self.risk_analyst == "remote" and not self.risk_analyst_address:
            raise ConfigError("WARDEN_RISK_ANALYST=remote requires WARDEN_RISK_ANALYST_ADDRESS.")


_DEFAULT_CONFIG: WardenConfig | None = None


def get_config() -> WardenConfig:
    """Retrieve the singleton or default configuration."""
    global _DEFAULT_CONFIG
    if _DEFAULT_CONFIG is None:
        _DEFAULT_CONFIG = WardenConfig()
    return _DEFAULT_CONFIG


def set_config(config: WardenConfig) -> None:
    """Explicitly override configuration (useful for testing)."""
    global _DEFAULT_CONFIG
    _DEFAULT_CONFIG = config
