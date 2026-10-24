"""uAgents transport for the remote Auditor: one synchronous request, one response."""

from __future__ import annotations

import asyncio
import json
import logging
import math
from typing import Any, Optional

from uagents.communication import send_sync_message
from uagents.resolver import Resolver

from warden.audit.attestation import AuditRequest
from warden.audit.wire import AuditAttestationWire, AuditRequestWire

logger = logging.getLogger(__name__)


class UAgentAuditTransport:
    """Sends an AuditRequest to the configured Auditor address and returns the raw attestation dict.

    Returns None for any non-attestation outcome (delivery failure, wrong type); the verifier
    treats that as UNVERIFIED. The sender identity signs the envelope; the response is further
    authenticated by ``check_attestation`` against the trusted Auditor address, so a reply from
    any other party fails verification regardless of transport.
    """

    def __init__(self, auditor_address: str, sender_identity: Any, resolver: Optional[Resolver] = None) -> None:
        self.auditor_address = auditor_address
        self.sender_identity = sender_identity
        self.resolver = resolver

    def __call__(self, request: AuditRequest, timeout: float) -> Optional[dict]:
        response = asyncio.run(
            send_sync_message(
                self.auditor_address,
                AuditRequestWire(payload=request.model_dump_json()),
                response_type=AuditAttestationWire,
                sender=self.sender_identity,
                resolver=self.resolver,
                timeout=max(1, math.ceil(timeout)),
            )
        )
        if not isinstance(response, AuditAttestationWire):
            logger.error("Auditor exchange failed: %s", type(response).__name__)
            return None
        return json.loads(response.payload)
