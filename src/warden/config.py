"""Configuration management for WARDEN."""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from pydantic import BaseModel, Field


class WardenConfig(BaseModel):
    """Runtime configuration for WARDEN."""
    env: str = Field(default_factory=lambda: os.getenv("WARDEN_ENV", "development"))
    log_level: str = Field(default_factory=lambda: os.getenv("WARDEN_LOG_LEVEL", "INFO"))
    workspace_root: Path = Field(
        default_factory=lambda: Path(os.getenv("WARDEN_WORKSPACE_ROOT", "./temp_workspace")).resolve()
    )
    enforce_workspace_containment: bool = Field(
        default_factory=lambda: os.getenv("WARDEN_ENFORCE_WORKSPACE_CONTAINMENT", "true").lower() in {"true", "1", "yes"}
    )
    require_approval_for_destructive: bool = Field(
        default_factory=lambda: os.getenv("WARDEN_REQUIRE_APPROVAL_FOR_DESTRUCTIVE", "true").lower() in {"true", "1", "yes"}
    )
    secret_key: str = Field(
        default_factory=lambda: os.getenv("WARDEN_SECRET_KEY", secrets.token_hex(32))
    )


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
