"""uAgents wiring for the Risk Analyst agent."""

from __future__ import annotations

import asyncio
from typing import List, Optional, Tuple, Union

from uagents import Agent, Context, Protocol
from uagents.crypto import Identity
from uagents.resolver import Resolver

from warden.risk.wire import RISK_PROTOCOL_NAME, RISK_PROTOCOL_VERSION, RiskAssessmentWire, RiskRequestWire
from warden.risk_analyst.config import RiskAnalystConfig
from warden.risk_analyst.service import RiskAnalystService


def create_risk_protocol(service: RiskAnalystService) -> Protocol:
    """Protocol answering RiskRequestWire with a signed RiskAssessmentWire, or nothing."""
    proto = Protocol(name=RISK_PROTOCOL_NAME, version=RISK_PROTOCOL_VERSION)

    @proto.on_message(model=RiskRequestWire, replies={RiskAssessmentWire})
    async def handle_risk_request(ctx: Context, sender: str, msg: RiskRequestWire):
        reply = service.handle(msg.payload, sender)
        if reply is None:
            return  # unauthorized, malformed or expired: stay silent
        await ctx.send(sender, RiskAssessmentWire(payload=reply))

    return proto


def build_risk_analyst_agent(
    config: Optional[RiskAnalystConfig] = None,
    name: str = "warden-risk-analyst",
    endpoint: Optional[Union[str, List[str]]] = None,
    warden_seed: Optional[str] = None,
    resolver: Optional[Resolver] = None,
) -> Tuple[Agent, RiskAnalystService]:
    """Build the Risk Analyst agent. Requires its own seed and an explicit allowed requester.

    The analyst only advises: it does not authorize, execute, approve or read the workspace.
    """
    cfg = config or RiskAnalystConfig()
    seed = cfg.validated_seed(warden_seed)
    service = RiskAnalystService(Identity.from_seed(seed, 0), cfg.validated_requesters())
    agent = Agent(
        name=name,
        seed=seed,
        port=cfg.port,
        endpoint=endpoint,
        resolve=resolver,
        loop=asyncio.new_event_loop(),
        enable_agent_inspector=False,
    )
    agent.include(create_risk_protocol(service))
    return agent, service
