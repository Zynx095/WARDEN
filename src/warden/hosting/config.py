"""Configuration for the hosted (externally run, Agentverse-registered) WARDEN agent."""

from __future__ import annotations

import os
import urllib.parse
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from warden.config import APPROVAL_MODES, ConfigError, env_bool, env_int, resolve_repo_path

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
    # Must be chosen explicitly when hosted: "independent" (recommended, with
    # WARDEN_APPROVER_ADDRESSES) or "self" (a requester approves their own actions; demo only).
    approval_mode: Optional[str] = Field(default_factory=lambda: (os.getenv("WARDEN_APPROVAL_MODE") or "").strip().lower() or None)
    approvers: list = Field(default_factory=lambda: [a.strip() for a in (os.getenv("WARDEN_APPROVER_ADDRESSES") or "").split(",") if a.strip()])
    # Durable approval state is mandatory when hosted: a restart must never forget a consumed approval.
    state_db: Optional[Path] = Field(
        default_factory=lambda: resolve_repo_path(os.getenv("WARDEN_STATE_DB")) if (os.getenv("WARDEN_STATE_DB") or "").strip() else None
    )
    # Largest HTTP request body accepted. A chat envelope with a 4000-character message is a few KB.
    max_request_bytes: int = Field(
        default_factory=lambda: env_int("WARDEN_MAX_REQUEST_BYTES", 256 * 1024, 4096, 4 * 1024 * 1024)
    )
    # ASI:One Interactive Cards are on by default when hosted; every reply still leads with plain text.
    interactive_cards: bool = Field(default_factory=lambda: env_bool("WARDEN_INTERACTIVE_CARDS", True))
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
        if self.approval_mode not in APPROVAL_MODES:
            raise ConfigError("WARDEN_APPROVAL_MODE must be set explicitly in hosted mode: 'independent' "
                              "(recommended; needs WARDEN_APPROVER_ADDRESSES) or 'self' (requesters approve "
                              "their own actions; demo only).")
        if self.approval_mode == "independent" and not self.approvers:
            raise ConfigError("WARDEN_APPROVAL_MODE=independent needs WARDEN_APPROVER_ADDRESSES (the approvers' "
                              "agent addresses).")
        if self.state_db is None:
            raise ConfigError("WARDEN_STATE_DB is required in hosted mode (e.g. /app/state/warden.db on a "
                              "persistent volume) so approvals survive restarts.")
