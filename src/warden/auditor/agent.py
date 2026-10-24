"""uAgents implementation and Protocol for the independent Auditor agent."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import List, Optional, Union

from uagents import Agent, Context, Protocol
from uagents.crypto import Identity

from warden.auditor.config import AuditorConfig, get_auditor_config
from warden.auditor.models import AuditAttestation, AuditRequest
from warden.auditor.service import AuditorService

logger = logging.getLogger("warden.auditor.agent")

AUDITOR_PROTOCOL_NAME = "WardenAuditorProtocol"
AUDITOR_PROTOCOL_VERSION = "1.0.0"


def create_auditor_protocol(service: AuditorService) -> Protocol:
    """Create a uAgents Protocol defining the audit verification request/attestation schema."""
    proto = Protocol(name=AUDITOR_PROTOCOL_NAME, version=AUDITOR_PROTOCOL_VERSION)

    @proto.on_message(model=AuditRequest, replies={AuditAttestation})
    async def handle_audit_request(ctx: Context, sender: str, req: AuditRequest):
        ctx.logger.info(f"Auditor received AuditRequest {req.audit_id[:8]} for action {req.action_id[:8]} from {sender}")
        attestation = service.process_audit_request(req, sender=sender)
        await ctx.send(sender, attestation)
        ctx.logger.info(f"Auditor dispatched AuditAttestation {attestation.attestation_id[:8]} with verdict {attestation.verdict} to {sender}")

    return proto


def build_auditor_agent(
    name: str = "warden-auditor-agent",
    seed: Optional[str] = None,
    port: Optional[int] = None,
    endpoint: Optional[Union[str, List[str]]] = None,
    service: Optional[AuditorService] = None,
    config: Optional[AuditorConfig] = None,
) -> tuple[Agent, AuditorService]:
    """Build and configure a standalone uAgents Agent serving independent audit attestations.

    Security guarantees:
    - Derives a distinct agent identity from configured or ephemeral seed.
    - Operates purely as a reactive verification service; does not authorize or execute.
    """
    aud_cfg = config or get_auditor_config()
    aud_seed = seed or aud_cfg.seed
    aud_port = port or aud_cfg.port

    derived_address = Identity.from_seed(aud_seed, 0).address
    aud_service = service or AuditorService(auditor_address=derived_address, max_cached_results=aud_cfg.max_cached_results)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    agent = Agent(
        name=name,
        seed=aud_seed,
        port=aud_port,
        endpoint=endpoint,
        loop=loop,
    )

    proto = create_auditor_protocol(aud_service)
    agent.include(proto)

    return agent, aud_service
