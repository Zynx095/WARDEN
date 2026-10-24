"""Configuration for the hosted (externally run, Agentverse-registered) WARDEN agent."""

from __future__ import annotations

import os
import urllib.parse
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from warden.config import ConfigError, env_bool, env_int, resolve_repo_path

DEFAULT_HOSTED_WORKSPACE = "./hosted_workspace"
DEFAULT_AGENT_NAME = "warden-verification-agent"


def _port() -> int:
    # Container platforms inject PORT; WARDEN_AGENT_PORT is the project's own name for it.
    raw = (os.getenv("PORT") or "").strip()
    if raw:
        try:
            value = int(raw)
        except ValueError:
            raise ConfigError("PORT must be an integer between 1 and 65535.") from None
        if not 1 <= value <= 65535:
            raise ConfigError("PORT must be an integer between 1 and 65535.")
        return value
    return env_int("WARDEN_AGENT_PORT", 8000, 1, 65535)


def validate_public_endpoint(raw: Optional[str], allow_insecure: bool = False) -> str:
    """The URL Agentverse and ASI:One deliver messages to. HTTPS is required outside local testing."""
    value = (raw or "").strip()
    if not value:
        raise ConfigError("WARDEN_PUBLIC_ENDPOINT is required in hosted mode (e.g. https://<host>/submit).")
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in ("https", "http") or not parsed.netloc:
        raise ConfigError("WARDEN_PUBLIC_ENDPOINT must be an absolute URL such as https://<host>/submit.")
    if parsed.scheme != "https" and not allow_insecure:
        raise ConfigError("WARDEN_PUBLIC_ENDPOINT must use https:// (plain http is only for local testing).")
    if parsed.path.rstrip("/") != "/submit":
        raise ConfigError("WARDEN_PUBLIC_ENDPOINT must end with /submit, the uAgents message route.")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ConfigError("WARDEN_PUBLIC_ENDPOINT must not contain credentials, a query or a fragment.")
    return value.rstrip("/")


class HostedConfig(BaseModel):
    """Settings the hosted entry point needs in addition to the core WardenConfig."""
    agent_name: str = Field(default_factory=lambda: (os.getenv("AGENTVERSE_AGENT_NAME") or DEFAULT_AGENT_NAME).strip())
    port: int = Field(default_factory=_port)
    workspace_root: Path = Field(
        default_factory=lambda: resolve_repo_path(os.getenv("WARDEN_WORKSPACE_ROOT") or DEFAULT_HOSTED_WORKSPACE)
    )
    # Local loopback testing only: lets the endpoint be http://127.0.0.1:<port>/submit.
    allow_insecure_endpoint: bool = Field(
        default_factory=lambda: env_bool("WARDEN_HOSTED_ALLOW_INSECURE_ENDPOINT", False)
    )
    public_endpoint: str = ""
    description: str = Field(default_factory=lambda: (os.getenv("AGENTVERSE_DESCRIPTION") or
        "Action-security agent: deterministic policy, exact-action approval and independent "
        "verification for file actions in a synthetic demo workspace.").strip())
    readme_path: Optional[str] = Field(default_factory=lambda: os.getenv("AGENTVERSE_README_PATH") or None)

    def __init__(self, **data) -> None:
        super().__init__(**data)
        if not self.public_endpoint:
            self.public_endpoint = validate_public_endpoint(
                os.getenv("WARDEN_PUBLIC_ENDPOINT"), self.allow_insecure_endpoint
            )
        else:
            self.public_endpoint = validate_public_endpoint(self.public_endpoint, self.allow_insecure_endpoint)
