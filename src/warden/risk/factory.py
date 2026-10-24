"""Selects the Risk Analyst WARDEN uses: in-process by default, the remote agent only when configured."""

from __future__ import annotations

from typing import Optional, Union

from uagents.crypto import Identity
from uagents.resolver import RulesBasedResolver

from warden.config import ConfigError, WardenConfig, get_config
from warden.risk.analyst import LocalRiskAnalyst, RemoteRiskAnalyst
from warden.risk.wire import UAgentRiskTransport

RiskAnalyst = Union[LocalRiskAnalyst, RemoteRiskAnalyst]


def build_risk_analyst(agent_seed: Optional[str], config: Optional[WardenConfig] = None) -> Optional[RiskAnalyst]:
    """Return the configured analyst, or None when ``WARDEN_RISK_ANALYST=off``.

    Remote mode signs requests with WARDEN's existing identity (derived from AGENT_SEED; no new
    identity is created) and trusts exactly one analyst address, which must not be WARDEN's own.
    """
    cfg = config or get_config()
    if cfg.risk_analyst == "off":
        return None
    if cfg.risk_analyst == "local":
        return LocalRiskAnalyst()
    if not agent_seed:
        raise ConfigError("WARDEN_RISK_ANALYST=remote needs WARDEN's AGENT_SEED to sign requests.")
    sender = Identity.from_seed(agent_seed, 0)
    if cfg.risk_analyst_address == sender.address:
        raise ConfigError("WARDEN_RISK_ANALYST_ADDRESS must be a different identity from WARDEN's own address.")
    resolver = (RulesBasedResolver({cfg.risk_analyst_address: cfg.risk_analyst_endpoint})
                if cfg.risk_analyst_endpoint else None)
    transport = UAgentRiskTransport(cfg.risk_analyst_address, sender, resolver=resolver)
    return RemoteRiskAnalyst(transport, cfg.risk_analyst_address, cfg.risk_analyst_timeout_seconds)
