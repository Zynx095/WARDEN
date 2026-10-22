"""Configuration management for WARDEN.

Settings come from process environment variables. Entry points (the runner and
the helper scripts) call :func:`load_environment` to merge the repository-root
``.env`` into the environment first, so behaviour does not depend on the current
working directory. Library code never loads ``.env`` implicitly.
"""

from __future__ import annotations

import os
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
    secret_key: str = Field(default_factory=_secret_key, repr=False)


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
