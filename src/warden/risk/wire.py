"""uAgents wire envelopes and transport for the Risk Analyst exchange.

As with the audit exchange, the wire models carry the contract's canonical JSON as an
opaque string; ``warden.risk.contract`` is the single schema and both sides re-validate it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
from typing import Any, Optional

from uagents import Model
from uagents.communication import send_sync_message
from uagents.resolver import Resolver

from warden.risk.contract import RiskRequest

logger = logging.getLogger(__name__)

RISK_PROTOCOL_NAME = "WardenRiskAnalystProtocol"
RISK_PROTOCOL_VERSION = "1.0.0"


class RiskRequestWire(Model):
    payload: str  # RiskRequest.model_dump_json()


class RiskAssessmentWire(Model):
    payload: str  # RiskAssessment.model_dump_json()


class UAgentRiskTransport:
    """One signed request to the Risk Analyst agent, one response. None for anything else.

    The envelope is signed by WARDEN's identity; the reply is authenticated separately by
    ``check_assessment`` against the trusted analyst address.
    """

    def __init__(self, analyst_address: str, sender_identity: Any, resolver: Optional[Resolver] = None) -> None:
        self.analyst_address = analyst_address
        self.sender_identity = sender_identity
        self.resolver = resolver

    def __call__(self, request: RiskRequest, timeout: float) -> Optional[dict]:
        response = asyncio.run(
            send_sync_message(
                self.analyst_address,
                RiskRequestWire(payload=request.model_dump_json()),
                response_type=RiskAssessmentWire,
                sender=self.sender_identity,
                resolver=self.resolver,
                timeout=max(1, math.ceil(timeout)),
            )
        )
        if not isinstance(response, RiskAssessmentWire):
            logger.error("Risk Analyst exchange failed: %s", type(response).__name__)
            return None
        return json.loads(response.payload)
