"""Stable wire schemas and verification for out-of-process audit attestations.

WARDEN-owned contract. An optional Auditor agent receives an ``AuditRequest`` and answers
with a signed ``AuditAttestation``. The request deliberately carries WARDEN's *expected*
post-condition and *pre-execution* observations, never the Executor's success message,
so the Auditor can only judge what it observes itself.

All timestamps are ISO-8601 UTC strings so both sides sign and verify identical bytes.
Fail-safe rule: anything missing, late, malformed, unsigned, mismatched or from an
untrusted signer is reported by ``check_attestation`` as not valid, and the caller must
then report UNVERIFIED or FAILED, never VERIFIED.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

REQUEST_SCHEMA = "warden.audit.request.v1"
ATTESTATION_SCHEMA = "warden.audit.attestation.v1"

Verdict = Literal["VERIFIED", "FAILED", "UNVERIFIED"]

# Clock-skew tolerance when checking attestation timestamps.
CLOCK_SKEW = timedelta(seconds=30)


class AuditRequest(BaseModel):
    """What WARDEN asks an Auditor to verify. Contains no Executor claim."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = REQUEST_SCHEMA
    request_id: str
    nonce: str
    action_digest: str
    operation: str
    target: str                                   # workspace-relative path
    destination: Optional[str] = None             # workspace-relative path (RENAME)
    expected_content_sha256: Optional[str] = None  # CREATE/WRITE post-condition
    workspace_id: str                             # sha256 of the canonical workspace root
    pre_state: Dict[str, Any] = Field(default_factory=dict)            # capture_target_state()
    pre_parent_snapshot: Dict[str, List[Any]] = Field(default_factory=dict)  # name -> [is_dir,size,mtime_ns]
    issued_at: str
    expires_at: str


class AuditAttestation(BaseModel):
    """An Auditor's signed observation of actual post-execution state."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = ATTESTATION_SCHEMA
    request_id: str
    nonce: str
    action_digest: str
    workspace_id: str
    auditor_address: str
    verdict: Verdict
    post_state: Dict[str, Any] = Field(default_factory=dict)
    post_parent_snapshot: Dict[str, List[Any]] = Field(default_factory=dict)
    unexpected_changes: List[str] = Field(default_factory=list)
    details: str = ""
    observed_at: str
    signature: str = ""


def signing_digest(attestation: AuditAttestation) -> bytes:
    """32-byte digest an Auditor signs: canonical JSON of every field except the signature."""
    payload = attestation.model_dump(mode="json")
    payload.pop("signature", None)
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8")).digest()


@dataclass(frozen=True)
class AttestationCheck:
    valid: bool
    verdict: Verdict        # VERIFIED only when valid and the Auditor itself said VERIFIED
    reason: str


def _unverified(reason: str) -> AttestationCheck:
    return AttestationCheck(valid=False, verdict="UNVERIFIED", reason=reason)


def _parse_ts(value: str) -> Optional[datetime]:
    try:
        ts = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _default_verify(address: str, digest: bytes, signature: str) -> bool:
    from uagents.crypto import Identity
    return bool(Identity.verify_digest(address, digest, signature))


def check_attestation(
    request: AuditRequest,
    attestation: Any,
    trusted_auditor_address: Optional[str],
    now: Optional[datetime] = None,
    verify: Callable[[str, bytes, str], bool] = _default_verify,
) -> AttestationCheck:
    """Validate an attestation against the request that produced it. Never raises."""
    try:
        if not trusted_auditor_address or not trusted_auditor_address.strip():
            return _unverified("No trusted auditor address is configured.")
        if attestation is None:
            return _unverified("No attestation received.")
        if not isinstance(attestation, AuditAttestation):
            try:
                attestation = AuditAttestation.model_validate(attestation)
            except Exception:
                return _unverified("Attestation is malformed.")

        if attestation.schema_version != ATTESTATION_SCHEMA:
            return _unverified("Unsupported attestation schema version.")
        if attestation.auditor_address != trusted_auditor_address.strip():
            return _unverified("Attestation signer is not the trusted auditor.")
        if not attestation.signature:
            return _unverified("Attestation is unsigned.")
        for name in ("request_id", "nonce", "action_digest", "workspace_id"):
            if getattr(attestation, name) != getattr(request, name):
                return _unverified(f"Attestation {name} does not match the request.")

        now = now or datetime.now(timezone.utc)
        issued, expires = _parse_ts(request.issued_at), _parse_ts(request.expires_at)
        observed = _parse_ts(attestation.observed_at)
        if issued is None or expires is None or observed is None:
            return _unverified("Attestation or request timestamp is malformed.")
        if now > expires + CLOCK_SKEW:
            return _unverified("Audit request expired before an attestation was accepted.")
        if observed < issued - CLOCK_SKEW or observed > expires + CLOCK_SKEW:
            return _unverified("Attestation was observed outside the request validity window.")

        try:
            signature_ok = verify(attestation.auditor_address, signing_digest(attestation), attestation.signature)
        except Exception:
            signature_ok = False
        if not signature_ok:
            return _unverified("Attestation signature is invalid.")

        if attestation.verdict == "VERIFIED" and attestation.unexpected_changes:
            return AttestationCheck(False, "FAILED", "Auditor reported VERIFIED alongside unexpected changes.")
        return AttestationCheck(True, attestation.verdict, attestation.details or "Attestation accepted.")
    except Exception:  # fail closed on anything unforeseen
        return _unverified("Attestation could not be evaluated.")
