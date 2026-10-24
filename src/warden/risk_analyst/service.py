"""Service behind the Risk Analyst uAgent.

It speaks the contract in ``warden.risk.contract`` and runs ``warden.risk.analysis``. It never
imports the policy engine, authorization manager, executor or WardenAgent, holds no WARDEN
key or token, and touches no filesystem: it can advise, never authorize or act.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional, Set, Tuple

from warden.risk.analyst import assessment_for
from warden.risk.contract import RISK_REQUEST_SCHEMA, RiskRequest, signing_digest

logger = logging.getLogger("warden.risk_analyst.service")


def _parse(ts: str) -> Optional[datetime]:
    try:
        value = datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class RiskAnalystService:
    """Turns a validated RiskRequest from an allowed requester into a signed RiskAssessment."""

    def __init__(
        self,
        identity: Any,
        allowed_requesters: Iterable[str],
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        max_cached: int = 1000,
    ) -> None:
        self.identity = identity
        self.allowed_requesters: Set[str] = {a.strip() for a in allowed_requesters if a and a.strip()}
        if not self.allowed_requesters:
            raise ValueError("At least one allowed requester address is required.")
        self.clock = clock
        self.max_cached = max_cached
        # (sender, request_id) -> (nonce, assessment json): duplicate delivery gets the same answer
        self._cache: "OrderedDict[Tuple[str, str], Tuple[str, str]]" = OrderedDict()

    @property
    def address(self) -> str:
        return self.identity.address

    def handle(self, payload: str, sender: str) -> Optional[str]:
        """Signed assessment JSON, or None to stay silent (unauthorized, malformed, expired, reused id)."""
        if sender not in self.allowed_requesters:
            logger.warning("Ignoring risk request from a sender that is not an allowed requester")
            return None
        try:
            request = RiskRequest.model_validate_json(payload)
        except Exception:
            logger.warning("Ignoring malformed risk request")
            return None
        if request.schema_version != RISK_REQUEST_SCHEMA:
            return None
        expires = _parse(request.expires_at)
        if expires is None or self.clock() > expires:
            logger.warning("Ignoring expired risk request")
            return None

        key = (sender, request.request_id)
        cached = self._cache.get(key)
        if cached is not None:
            # Same request redelivered: same answer. Same id with a new nonce: refuse silently.
            return cached[1] if cached[0] == request.nonce else None

        unsigned = assessment_for(request, analyst_address=self.address, now=self.clock())
        signed = unsigned.model_copy(update={"signature": self.identity.sign_digest(signing_digest(unsigned))})
        reply = signed.model_dump_json()
        if len(self._cache) >= self.max_cached:
            self._cache.popitem(last=False)
        self._cache[key] = (request.nonce, reply)
        return reply
