"""uAgents wiring for the independent Auditor agent."""

from __future__ import annotations

import asyncio
import logging
from typing import List, Optional, Tuple, Union

from uagents import Agent, Context, Protocol
from uagents.crypto import Identity

from warden.audit.wire import AuditAttestationWire, AuditRequestWire
from warden.auditor.config import AuditorConfig
from warden.auditor.service import AuditorService

logger = logging.getLogger("warden.auditor.agent")

AUDITOR_PROTOCOL_NAME = "WardenAuditorProtocol"
AUDITOR_PROTOCOL_VERSION = "1.0.0"


def create_auditor_protocol(service: AuditorService) -> Protocol:
    """Protocol answering AuditRequestWire with a signed AuditAttestationWire, or nothing."""
    proto = Protocol(name=AUDITOR_PROTOCOL_NAME, version=AUDITOR_PROTOCOL_VERSION)

    @proto.on_message(model=AuditRequestWire, replies={AuditAttestationWire})
    async def handle_audit_request(ctx: Context, sender: str, msg: AuditRequestWire):
        reply = service.handle(msg.payload, sender)
        if reply is None:
            return  # unauthorized or malformed: stay silent, never act as an oracle
        await ctx.send(sender, AuditAttestationWire(payload=reply))

    return proto


def build_auditor_agent(
    config: Optional[AuditorConfig] = None,
    name: str = "warden-auditor-agent",
    endpoint: Optional[Union[str, List[str]]] = None,
    warden_seed: Optional[str] = None,
) -> Tuple[Agent, AuditorService]:
    """Build the Auditor agent. Requires its own seed and an explicit allowed requester.

    The Auditor is a reactive, read-only service: it does not authorize, execute or approve.
    """
    cfg = config or AuditorConfig()
    seed = cfg.validated_seed(warden_seed)
    requesters = cfg.validated_requesters()

    service = AuditorService(cfg.workspace_root, Identity.from_seed(seed, 0), requesters)
    agent = Agent(
        name=name,
        seed=seed,
        port=cfg.port,
        endpoint=endpoint,
        loop=asyncio.new_event_loop(),
    )
    agent.include(create_auditor_protocol(service))
    return agent, service
