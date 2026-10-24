"""Configuration for the standalone Auditor process (never read by the WARDEN core agent)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field

from warden.config import ConfigError, env_int, resolve_repo_path
from warden.identity import derive_agent_address, validate_seed


def _workspace_root() -> Path:
    return resolve_repo_path(
        os.getenv("WARDEN_AUDITOR_WORKSPACE_ROOT") or os.getenv("WARDEN_WORKSPACE_ROOT") or "./temp_workspace"
    )


def _allowed_requesters() -> List[str]:
    return [a.strip() for a in (os.getenv("WARDEN_AUDITOR_ALLOWED_REQUESTER") or "").split(",") if a.strip()]


class AuditorConfig(BaseModel):
    """Runtime configuration for the Auditor uAgent. A seed and an allowed requester are mandatory."""
    seed: Optional[str] = Field(default_factory=lambda: (os.getenv("WARDEN_AUDITOR_SEED") or "").strip() or None, repr=False)
    port: int = Field(default_factory=lambda: env_int("WARDEN_AUDITOR_PORT", 8001, 1, 65535))
    workspace_root: Path = Field(default_factory=_workspace_root)
    allowed_requesters: List[str] = Field(default_factory=_allowed_requesters)

    def validated_seed(self, warden_seed: Optional[str] = None) -> str:
        """The Auditor must have its own identity: never absent, weak, or the same as WARDEN's."""
        if not self.seed:
            raise ConfigError("WARDEN_AUDITOR_SEED is required: the Auditor needs its own distinct identity.")
        seed = validate_seed(self.seed)
        warden_seed = warden_seed if warden_seed is not None else os.getenv("AGENT_SEED")
        if warden_seed and warden_seed.strip():
            if seed == warden_seed.strip() or derive_agent_address(seed) == derive_agent_address(warden_seed.strip()):
                raise ConfigError("WARDEN_AUDITOR_SEED must differ from AGENT_SEED (distinct identities).")
        return seed

    def validated_requesters(self) -> List[str]:
        if not self.allowed_requesters:
            raise ConfigError("WARDEN_AUDITOR_ALLOWED_REQUESTER (the WARDEN agent address) is required.")
        return list(self.allowed_requesters)
