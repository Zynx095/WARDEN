"""Configuration for the optional Auditor uAgent."""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field

from warden.config import env_bool, resolve_repo_path
from warden.identity import validate_seed, MIN_SEED_LENGTH


def _auditor_enabled() -> bool:
    raw = os.getenv("WARDEN_AUDITOR_UAGENT_ENABLED")
    if raw is None or raw.strip() == "":
        return False
    return env_bool("WARDEN_AUDITOR_UAGENT_ENABLED", default=False)


def _auditor_port() -> int:
    raw = os.getenv("WARDEN_AUDITOR_PORT", "8001")
    try:
        return int(raw.strip())
    except ValueError:
        return 8001


def _auditor_timeout() -> float:
    raw = os.getenv("WARDEN_AUDITOR_TIMEOUT_SECONDS", "5.0")
    try:
        return max(0.5, float(raw.strip()))
    except ValueError:
        return 5.0


def _auditor_seed() -> str:
    raw = os.getenv("WARDEN_AUDITOR_SEED")
    if raw and raw.strip():
        return validate_seed(raw.strip())
    # Safe ephemeral per-process seed if none configured
    return secrets.token_hex(32)


class AuditorConfig(BaseModel):
    """Runtime configuration for the Auditor uAgent."""
    enabled: bool = Field(default_factory=_auditor_enabled)
    port: int = Field(default_factory=_auditor_port)
    timeout_seconds: float = Field(default_factory=_auditor_timeout)
    seed: str = Field(default_factory=_auditor_seed, repr=False)
    max_cached_results: int = Field(default=1000)


_DEFAULT_AUDITOR_CONFIG: Optional[AuditorConfig] = None


def get_auditor_config() -> AuditorConfig:
    global _DEFAULT_AUDITOR_CONFIG
    if _DEFAULT_AUDITOR_CONFIG is None:
        _DEFAULT_AUDITOR_CONFIG = AuditorConfig()
    return _DEFAULT_AUDITOR_CONFIG


def set_auditor_config(config: Optional[AuditorConfig]) -> None:
    global _DEFAULT_AUDITOR_CONFIG
    _DEFAULT_AUDITOR_CONFIG = config
