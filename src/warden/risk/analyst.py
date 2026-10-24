"""The Risk Analyst stage as WARDEN sees it: build a request, get advice, never fail open.

Two interchangeable analysts implement ``assess(request) -> RiskOutcome``:

- ``LocalRiskAnalyst`` runs the deterministic analysis in-process (default).
- ``RemoteRiskAnalyst`` sends the request to a separate Risk Analyst uAgent over signed
  uAgents envelopes and accepts only a valid, signed, request-bound assessment from the one
  trusted analyst address.

Either way the outcome is advisory. ``assess`` never raises: any failure becomes an
UNAVAILABLE outcome, and the policy decision is made exactly as it would be without it.
"""

from __future__ import annotations

import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional

from warden.deadline import call_with_deadline
from warden.risk.analysis import analyze
from warden.risk.contract import RiskAssessment, RiskOutcome, RiskRequest, check_assessment
from warden.security.digest import sha256_text

logger = logging.getLogger(__name__)

# transport(request, timeout_seconds) -> raw assessment (dict / RiskAssessment) or None
Transport = Callable[[RiskRequest, float], Any]


def build_risk_request(
    action: Any,
    action_digest: Optional[str],
    target_display: Optional[str],
    state: Optional[Dict[str, Any]],
    protected_names: Iterable[str],
    request_text: Optional[str] = None,
    batch_size: int = 1,
    ttl_seconds: int = 30,
    now: Optional[datetime] = None,
) -> RiskRequest:
    """Describe one proposed action for the analyst: paths workspace-relative, no file content."""
    now = now or datetime.now(timezone.utc)
    text = "".join(ch if ch.isprintable() or ch in "\n\t" else " " for ch in (request_text or ""))[:4000]
    state = state or {}
    return RiskRequest(
        request_id=str(uuid.uuid4()),
        nonce=secrets.token_hex(16),
        action_id=action.action_id,
        correlation_id=getattr(action, "correlation_id", None) or action.action_id,
        action_digest=action_digest or "",
        operation=action.operation.upper(),
        target=(target_display or action.target or "").replace("\\", "/"),
        requested_target="".join(ch if ch.isprintable() else "?" for ch in (action.target or ""))[:400],
        destination=(action.destination or "").replace("\\", "/") or None,
        content_sha256=sha256_text(action.content) if action.content is not None else None,
        content_length=len(action.content) if action.content is not None else None,
        content_preview=action.content[:2000] if action.content is not None else None,
        target_state=state.get("target") if action_digest else None,
        destination_state=state.get("destination") if action_digest else None,
        request_text=text,
        batch_size=max(1, int(batch_size)),
        protected_names=sorted({p.lower() for p in protected_names}),
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=ttl_seconds)).isoformat(),
    )


def assessment_for(request: RiskRequest, analyst_address: str = "",
                   now: Optional[datetime] = None) -> RiskAssessment:
    """Run the deterministic analysis and wrap it as an (unsigned) assessment of ``request``."""
    result = analyze(request)
    return RiskAssessment(
        request_id=request.request_id,
        nonce=request.nonce,
        action_id=request.action_id,
        correlation_id=request.correlation_id,
        action_digest=request.action_digest,
        analyst_address=analyst_address,
        risk_level=result.risk_level,
        recommendation=result.recommendation,
        uncertainty=result.uncertainty,
        findings=list(result.findings),
        summary=result.summary,
        assessed_at=(now or datetime.now(timezone.utc)).isoformat(),
    )


class LocalRiskAnalyst:
    """In-process analyst: same contract and analysis, no separate identity."""
    source = "local"

    def assess(self, request: RiskRequest) -> RiskOutcome:
        try:
            return RiskOutcome.from_assessment(assessment_for(request), self.source)
        except Exception as exc:
            logger.error("Local risk analysis failed: %s", type(exc).__name__)
            return RiskOutcome.unavailable(request, self.source, "Risk analysis failed; policy decision unaffected.")


class RemoteRiskAnalyst:
    """Client for the Risk Analyst uAgent. Any failure is UNAVAILABLE, never a guess."""
    source = "remote"

    def __init__(self, transport: Transport, trusted_analyst_address: str, timeout_seconds: float,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        if not trusted_analyst_address or not trusted_analyst_address.strip():
            raise ValueError("A trusted Risk Analyst address is required.")
        self.transport = transport
        self.trusted_analyst_address = trusted_analyst_address.strip()
        self.timeout_seconds = float(timeout_seconds)
        self.clock = clock

    def assess(self, request: RiskRequest) -> RiskOutcome:
        raw, error = call_with_deadline(lambda: self.transport(request, self.timeout_seconds),
                                        self.timeout_seconds, "risk-analyst")
        if error:
            return RiskOutcome.unavailable(
                request, self.source, f"Risk Analyst unavailable ({error}); policy decision unaffected.")
        check = check_assessment(request, raw, self.trusted_analyst_address, now=self.clock())
        if not check.valid:
            logger.warning("Risk assessment refused: %s", check.reason)
            return RiskOutcome.unavailable(
                request, self.source, f"Risk assessment not accepted: {check.reason} Policy decision unaffected.")
        return RiskOutcome.from_assessment(check.assessment, self.source)
