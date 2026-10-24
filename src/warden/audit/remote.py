"""Opt-in verification through a remote Auditor, layered on top of the local check.

Invariants:
- The local OutcomeAuditor always runs. A remote VERIFIED can never rescue a local failure.
- VERIFIED requires BOTH a passing local check AND a valid, signed, request-bound
  attestation from the single trusted Auditor address that says VERIFIED.
- Timeout, transport error, malformed/unsigned/forged/mismatched/replayed attestation or an
  unreachable Auditor yield UNVERIFIED (never VERIFIED). A valid attestation that reports a
  problem yields FAILED.
- The remote Auditor shares this machine's trust domain unless deployed otherwise; a
  separate uAgent address is a distinct identity, not privilege isolation.
"""

from __future__ import annotations

import logging
import queue
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from warden.audit.attestation import AuditRequest, check_attestation
from warden.audit.auditor import MUTATING_OPERATIONS, OutcomeAuditor
from warden.audit.request_builder import AuditRequestError, build_audit_request
from warden.execution.workspace import Workspace
from warden.models import Action, ExecutionResult, ExecutionStatus, VerificationResult
from warden.security.path_validation import PathValidator

logger = logging.getLogger(__name__)

# transport(request, timeout_seconds) -> raw attestation (dict / AuditAttestation) or None
Transport = Callable[[AuditRequest, float], Any]


class RemoteAuditVerifier:
    """Drop-in replacement for OutcomeAuditor that adds a remote attestation requirement."""

    def __init__(
        self,
        workspace: Workspace,
        transport: Transport,
        trusted_auditor_address: str,
        timeout_seconds: float,
        path_validator: Optional[PathValidator] = None,
        local: Optional[OutcomeAuditor] = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if not trusted_auditor_address or not trusted_auditor_address.strip():
            raise ValueError("A trusted Auditor address is required for remote verification.")
        self.workspace = workspace
        self.path_validator = path_validator or PathValidator(workspace.root_path)
        self.local = local or OutcomeAuditor(workspace, path_validator=self.path_validator)
        self.transport = transport
        self.trusted_auditor_address = trusted_auditor_address.strip()
        self.timeout_seconds = float(timeout_seconds)
        self.clock = clock

    def capture_pre_state(self, action: Action) -> Dict[str, Any]:
        return self.local.capture_pre_state(action)

    def verify_outcome(
        self,
        action: Action,
        exec_result: ExecutionResult,
        pre_state: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:
        local = self.local.verify_outcome(action, exec_result, pre_state)
        # Nothing to attest for failed executions or reads; a local failure is final.
        if not local.verified or action.operation.upper() not in MUTATING_OPERATIONS:
            return local

        remote_info: Dict[str, Any] = {"enabled": True}

        def result(status: ExecutionStatus, note: str) -> VerificationResult:
            remote_info["note"] = note
            return VerificationResult(
                action=action,
                status=status,
                verified=False,
                observed_state={**local.observed_state, "remote_auditor": remote_info},
                details=f"{note} Local check: {local.details}",
            )

        try:
            request = build_audit_request(
                action, pre_state, self.workspace.root_path, self.path_validator,
                ttl_seconds=int(self.timeout_seconds) + 5, now=self.clock(),
            )
        except AuditRequestError as exc:
            return result(ExecutionStatus.UNVERIFIED, f"Remote audit not possible: {exc}")
        remote_info["request_id"] = request.request_id

        raw, error = self._send(request)
        if error:
            return result(ExecutionStatus.UNVERIFIED, f"Remote audit unavailable ({error}); outcome is unverified.")

        check = check_attestation(request, raw, self.trusted_auditor_address, now=self.clock())
        remote_info["verdict"] = check.verdict
        remote_info["valid"] = check.valid
        if check.verdict == "FAILED":
            return result(ExecutionStatus.FAILED, f"Remote auditor rejected the outcome: {check.reason}")
        if not check.valid or check.verdict != "VERIFIED":
            return result(ExecutionStatus.UNVERIFIED, f"Remote attestation not accepted: {check.reason}")

        disagreement = self._post_state_disagreement(local, raw)
        if disagreement:
            return result(ExecutionStatus.UNVERIFIED, disagreement)

        remote_info["note"] = "Remote attestation accepted."
        return VerificationResult(
            action=action,
            status=ExecutionStatus.VERIFIED,
            verified=True,
            observed_state={**local.observed_state, "remote_auditor": remote_info},
            details=f"{local.details} Independently attested by the trusted remote auditor.",
        )

    def _send(self, request: AuditRequest):
        """Run the transport with a hard deadline; the caller never waits longer than the timeout."""
        box: "queue.Queue[tuple[str, Any]]" = queue.Queue(maxsize=1)

        def run() -> None:
            try:
                box.put(("ok", self.transport(request, self.timeout_seconds)))
            except Exception as exc:
                box.put(("error", type(exc).__name__))

        worker = threading.Thread(target=run, name="warden-remote-audit", daemon=True)
        worker.start()
        try:
            kind, value = box.get(timeout=self.timeout_seconds)
        except queue.Empty:
            logger.error("Remote auditor did not answer within %.1fs", self.timeout_seconds)
            return None, "timeout"
        if kind == "error":
            logger.error("Remote auditor transport failed: %s", value)
            return None, "transport error"
        if value is None:
            return None, "no response"
        return value, None

    @staticmethod
    def _post_state_disagreement(local: VerificationResult, raw: Any) -> Optional[str]:
        """A signed attestation whose observed target differs from the local observation is not trusted."""
        post = getattr(raw, "post_state", None)
        if post is None and isinstance(raw, dict):
            post = raw.get("post_state")
        local_post = local.observed_state.get("post_target_state")
        remote_post = post.get("target") if isinstance(post, dict) else None
        if local_post is None or remote_post is None:
            return "Attestation did not include a comparable post-state; outcome is unverified."
        for key in ("exists", "kind", "sha256"):
            if local_post.get(key) != remote_post.get(key):
                return "Remote and local observations of the target disagree; outcome is unverified."
        return None
