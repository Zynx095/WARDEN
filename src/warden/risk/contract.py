"""Risk Analyst contract: structured request, signed assessment and its verification.

WARDEN-owned. The Risk Analyst receives a ``RiskRequest`` describing one proposed action
(already canonicalised and digested by WARDEN) and answers with a ``RiskAssessment``:
findings with evidence, a risk level and a recommendation. An assessment is advice. It is
never an authorization: the deterministic policy engine alone decides ALLOW, BLOCK or
REQUIRE_APPROVAL, and nothing in an assessment is consulted by policy, approval or execution.

Fail-safe rule: an assessment that is missing, late, malformed, unsigned, from an untrusted
signer or bound to a different request, action or digest is not used; WARDEN records the
risk analysis as UNAVAILABLE and continues under policy alone.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

RISK_REQUEST_SCHEMA = "warden.risk.request.v2"
RISK_ASSESSMENT_SCHEMA = "warden.risk.assessment.v2"

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
# Candidates only: the deterministic policy engine makes every decision.
Recommendation = Literal["ALLOW_CANDIDATE", "ESCALATE", "BLOCK_CANDIDATE"]
Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
Uncertainty = Literal["LOW", "MEDIUM", "HIGH"]
FindingCode = Literal[
    "DESTRUCTIVE_IMPACT",
    "PROTECTED_TARGET",
    "SENSITIVE_NAME",
    "UNRESOLVED_TARGET",
    "EXCESSIVE_SCOPE",
    "AMBIGUOUS_REQUEST",
    "AUTHORITY_CLAIM",
    "UNCERTAIN_STATE",
    "PATH_TRAVERSAL",
    "SYMLINK_TARGET",
    "OVERWRITE",
    "CONTENT_INJECTION",
    "COLLATERAL_EFFECT",
]

MAX_FINDINGS = 16
MAX_EVIDENCE_CHARS = 200
MAX_REQUEST_TEXT_CHARS = 4000
MAX_CONTENT_PREVIEW_CHARS = 2000
CLOCK_SKEW = timedelta(seconds=30)


class RiskRequest(BaseModel):
    """What WARDEN asks the Risk Analyst to assess. Contains no file content."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = RISK_REQUEST_SCHEMA
    request_id: str
    nonce: str
    action_id: str                        # correlates every stage of one action
    correlation_id: str                   # audit correlation id (the action id unless set upstream)
    action_digest: str                    # canonical digest; '' when the action cannot be bound
    operation: str
    target: str                           # workspace-relative when bound, else as requested
    requested_target: str = ""            # the target exactly as proposed (before canonicalisation)
    destination: Optional[str] = None
    content_sha256: Optional[str] = None
    content_length: Optional[int] = None
    # Start of the content the action would write (user-supplied, never a file that was read).
    content_preview: Optional[str] = Field(default=None, max_length=MAX_CONTENT_PREVIEW_CHARS)
    target_state: Optional[Dict[str, Any]] = None       # describe_path_state(); None when unbound
    destination_state: Optional[Dict[str, Any]] = None
    request_text: str = Field(default="", max_length=MAX_REQUEST_TEXT_CHARS)
    batch_size: int = Field(default=1, ge=1)            # actions proposed by the same instruction
    protected_names: List[str] = Field(default_factory=list)
    issued_at: str
    expires_at: str


class RiskFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    code: FindingCode
    severity: Severity
    evidence: str = Field(max_length=MAX_EVIDENCE_CHARS)


class RiskAssessment(BaseModel):
    """The Risk Analyst's signed advice about one request."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = RISK_ASSESSMENT_SCHEMA
    request_id: str
    nonce: str
    action_id: str
    correlation_id: str
    action_digest: str
    analyst_address: str
    risk_level: RiskLevel
    recommendation: Recommendation
    uncertainty: Uncertainty
    findings: List[RiskFinding] = Field(default_factory=list, max_length=MAX_FINDINGS)
    summary: str = Field(default="", max_length=300)
    assessed_at: str
    signature: str = ""


def signing_digest(assessment: RiskAssessment) -> bytes:
    """32-byte digest the analyst signs: canonical JSON of every field except the signature."""
    payload = assessment.model_dump(mode="json")
    payload.pop("signature", None)
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8")).digest()


def _parse_ts(value: str) -> Optional[datetime]:
    try:
        ts = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _default_verify(address: str, digest: bytes, signature: str) -> bool:
    from uagents.crypto import Identity
    return bool(Identity.verify_digest(address, digest, signature))


@dataclass(frozen=True)
class AssessmentCheck:
    valid: bool
    reason: str
    assessment: Optional[RiskAssessment] = None


def check_assessment(
    request: RiskRequest,
    raw: Any,
    trusted_analyst_address: Optional[str],
    now: Optional[datetime] = None,
    verify: Callable[[str, bytes, str], bool] = _default_verify,
) -> AssessmentCheck:
    """Validate a remote assessment against the request that produced it. Never raises."""
    try:
        if not trusted_analyst_address:
            return AssessmentCheck(False, "No trusted Risk Analyst address is configured.")
        if raw is None:
            return AssessmentCheck(False, "No assessment received.")
        try:
            assessment = raw if isinstance(raw, RiskAssessment) else RiskAssessment.model_validate(raw)
        except Exception:
            return AssessmentCheck(False, "Assessment is malformed.")
        if assessment.schema_version != RISK_ASSESSMENT_SCHEMA:
            return AssessmentCheck(False, "Unsupported assessment schema version.")
        if assessment.analyst_address != trusted_analyst_address:
            return AssessmentCheck(False, "Assessment signer is not the trusted Risk Analyst.")
        if not assessment.signature:
            return AssessmentCheck(False, "Assessment is unsigned.")
        for name in ("request_id", "nonce", "action_id", "correlation_id", "action_digest"):
            if getattr(assessment, name) != getattr(request, name):
                return AssessmentCheck(False, f"Assessment {name} does not match the request.")
        now = now or datetime.now(timezone.utc)
        issued, expires = _parse_ts(request.issued_at), _parse_ts(request.expires_at)
        assessed = _parse_ts(assessment.assessed_at)
        if issued is None or expires is None or assessed is None:
            return AssessmentCheck(False, "Assessment or request timestamp is malformed.")
        if now > expires + CLOCK_SKEW:
            return AssessmentCheck(False, "Risk request expired before an assessment was accepted.")
        if assessed < issued - CLOCK_SKEW or assessed > expires + CLOCK_SKEW:
            return AssessmentCheck(False, "Assessment was made outside the request validity window.")
        try:
            signature_ok = verify(assessment.analyst_address, signing_digest(assessment), assessment.signature)
        except Exception:
            signature_ok = False
        if not signature_ok:
            return AssessmentCheck(False, "Assessment signature is invalid.")
        return AssessmentCheck(True, "Assessment accepted.", assessment)
    except Exception:  # fail closed on anything unforeseen
        return AssessmentCheck(False, "Assessment could not be evaluated.")


ASSESSED = "ASSESSED"
UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class RiskOutcome:
    """What WARDEN keeps from the risk stage for one action, local or remote, valid or not."""
    status: str                                   # ASSESSED | UNAVAILABLE
    source: str                                   # "local" | "remote"
    action_id: str
    action_digest: str
    risk_level: Optional[str] = None
    recommendation: Optional[str] = None
    uncertainty: Optional[str] = None
    findings: List[Dict[str, str]] = field(default_factory=list)
    summary: str = ""
    analyst_address: Optional[str] = None
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None
    assessed_at: Optional[str] = None

    @classmethod
    def from_assessment(cls, assessment: RiskAssessment, source: str) -> "RiskOutcome":
        return cls(
            status=ASSESSED,
            source=source,
            action_id=assessment.action_id,
            action_digest=assessment.action_digest,
            risk_level=assessment.risk_level,
            recommendation=assessment.recommendation,
            uncertainty=assessment.uncertainty,
            findings=[f.model_dump() for f in assessment.findings],
            summary=assessment.summary,
            analyst_address=assessment.analyst_address or None,
            request_id=assessment.request_id,
            correlation_id=assessment.correlation_id,
            assessed_at=assessment.assessed_at,
        )

    @classmethod
    def unavailable(cls, request: RiskRequest, source: str, reason: str) -> "RiskOutcome":
        return cls(status=UNAVAILABLE, source=source, action_id=request.action_id,
                   action_digest=request.action_digest, summary=reason[:300], request_id=request.request_id,
                   correlation_id=request.correlation_id)

    def as_dict(self) -> Dict[str, Any]:
        """Display/audit form. Advisory only: never read by policy, approval or execution."""
        return {
            "status": self.status,
            "source": self.source,
            "action_id": self.action_id,
            "action_digest": self.action_digest,
            "risk_level": self.risk_level,
            "recommendation": self.recommendation,
            "uncertainty": self.uncertainty,
            "findings": list(self.findings),
            "summary": self.summary,
            "analyst_address": self.analyst_address,
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "assessed_at": self.assessed_at,
        }
