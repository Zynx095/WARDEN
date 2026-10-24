"""Configuration for the standalone Risk Analyst process (never read by the WARDEN core agent)."""

from __future__ import annotations

import os
from typing import List, Optional

from pydantic import BaseModel, Field

from warden.config import ConfigError, env_int
from warden.identity import derive_agent_address, validate_seed


def _allowed_requesters() -> List[str]:
    return [a.strip() for a in (os.getenv("WARDEN_RISK_ANALYST_ALLOWED_REQUESTER") or "").split(",") if a.strip()]


class RiskAnalystConfig(BaseModel):
    """Runtime configuration for the Risk Analyst uAgent. Its own seed and an allowed requester are mandatory."""
    seed: Optional[str] = Field(
        default_factory=lambda: (os.getenv("WARDEN_RISK_ANALYST_SEED") or "").strip() or None, repr=False
    )
    port: int = Field(default_factory=lambda: env_int("WARDEN_RISK_ANALYST_PORT", 8002, 1, 65535))
    allowed_requesters: List[str] = Field(default_factory=_allowed_requesters)

    def validated_seed(self, warden_seed: Optional[str] = None) -> str:
        """The analyst must have its own identity: never absent, weak, or the same as WARDEN's."""
        if not self.seed:
            raise ConfigError("WARDEN_RISK_ANALYST_SEED is required: the Risk Analyst needs its own identity.")
        seed = validate_seed(self.seed)
        warden_seed = warden_seed if warden_seed is not None else os.getenv("AGENT_SEED")
        if warden_seed and warden_seed.strip():
            if seed == warden_seed.strip() or derive_agent_address(seed) == derive_agent_address(warden_seed.strip()):
                raise ConfigError("WARDEN_RISK_ANALYST_SEED must differ from AGENT_SEED (distinct identities).")
        return seed

    def validated_requesters(self) -> List[str]:
        if not self.allowed_requesters:
            raise ConfigError("WARDEN_RISK_ANALYST_ALLOWED_REQUESTER (the WARDEN agent address) is required.")
        return list(self.allowed_requesters)
