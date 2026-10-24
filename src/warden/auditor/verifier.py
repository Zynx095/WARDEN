"""Verification adapter integrating the Auditor uAgent into WARDEN pipelines."""

from __future__ import annotations

import concurrent.futures
import logging
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from warden.audit.auditor import OutcomeAuditor
from warden.auditor.config import AuditorConfig, get_auditor_config
from warden.auditor.digest import compute_action_digest
from warden.auditor.models import AuditAttestation, AuditRequest, AuditVerdict
from warden.auditor.service import AuditorService
from warden.auditor.workspace_view import ReadOnlyWorkspaceView
from warden.execution.workspace import Workspace
from warden.models import (
    Action,
    ExecutionResult,
    ExecutionStatus,
    VerificationResult,
)
from warden.security.path_validation import PathValidator

logger = logging.getLogger("warden.auditor.verifier")


class AuditorTimeoutError(Exception):
    """Raised when the Auditor uAgent fails to return an attestation within the timeout window."""
    pass


class AuditorAttestationError(ValueError):
    """Raised when an attestation received from the Auditor is missing, corrupted or invalid."""
    pass


class AuditorUAgentVerifier:
    """Verifies action execution outcomes using an independent Auditor uAgent.

    Invariants:
    1. Disabled by Default: When disabled, transparently falls back to local OutcomeAuditor.
    2. Fail-Closed: If the Auditor times out, throws an exception, or returns an invalid
       attestation or UNVERIFIED verdict, verification fails closed (ExecutionStatus.FAILED, verified=False).
    3. Independent Attestation: Physical filesystem state is attested by the Auditor service,
       never trusting the executor's success claim.
    4. Anti-Tampering: Action digests bind the request; mismatches are rejected.
    5. Collateral Damage Tracking: Pre-state manifests are submitted to detect unintended deletions.
    """

    def __init__(
        self,
        workspace: Workspace,
        path_validator: Optional[PathValidator] = None,
        auditor_service: Optional[AuditorService] = None,
        config: Optional[AuditorConfig] = None,
        transport_call: Optional[Callable[[AuditRequest], AuditAttestation]] = None,
    ) -> None:
        self.workspace = workspace
        self.path_validator = path_validator or PathValidator(self.workspace.root_path)
        self.config = config or get_auditor_config()
        self.fallback_auditor = OutcomeAuditor(workspace, path_validator=self.path_validator)
        self.auditor_service = auditor_service or AuditorService()
        self.transport_call = transport_call
        self.workspace_view = ReadOnlyWorkspaceView(self.workspace.root_path)

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def capture_pre_state(self, action: Action) -> Dict[str, Any]:
        """Capture filesystem snapshot prior to an operation, including workspace file manifest."""
        state = self.fallback_auditor.capture_pre_state(action)
        # Capture manifest of all files currently in workspace for collateral damage detection
        state["workspace_manifest"] = self.workspace_view.capture_manifest()
        return state

    def verify_outcome(
        self,
        action: Action,
        exec_result: ExecutionResult,
        pre_state: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:
        """Verify action outcome, delegating to the Auditor uAgent when enabled."""
        if not self.enabled:
            return self.fallback_auditor.verify_outcome(action, exec_result, pre_state)

        # Build structured audit request with action digest binding
        action_digest = compute_action_digest(action, self.workspace.root_path)
        pre_manifest = pre_state.get("workspace_manifest", {}) if pre_state else {}

        req = AuditRequest.from_action(
            action=action,
            workspace_root=self.workspace.root_path,
            executor_claimed_success=exec_result.success,
            pre_state_manifest=pre_manifest,
            action_digest=action_digest,
        )

        try:
            attestation = self._call_auditor_with_timeout(req)
        except AuditorTimeoutError as exc:
            logger.error("Auditor uAgent verification timed out: %s", exc)
            return VerificationResult(
                action=action,
                status=ExecutionStatus.FAILED,
                verified=False,
                observed_state={"auditor_timeout": True},
                details="Auditor verification timed out (fail-closed).",
            )
        except Exception as exc:
            logger.error("Auditor uAgent verification error: %s", exc)
            return VerificationResult(
                action=action,
                status=ExecutionStatus.FAILED,
                verified=False,
                observed_state={"auditor_error": str(exc)},
                details=f"Auditor attestation invalid or missing: {exc} (fail-closed).",
            )

        # Validate attestation structure
        if not isinstance(attestation, AuditAttestation):
            return VerificationResult(
                action=action,
                status=ExecutionStatus.FAILED,
                verified=False,
                observed_state={"invalid_attestation_type": type(attestation).__name__},
                details="Auditor returned an invalid attestation object (fail-closed).",
            )

        # Enforce fail-closed semantics based on Auditor verdict
        if attestation.verdict == AuditVerdict.VERIFIED.value:
            return VerificationResult(
                action=action,
                status=ExecutionStatus.VERIFIED,
                verified=True,
                observed_state=attestation.observed_state,
                details=f"Auditor attestation VERIFIED by {attestation.auditor_address or 'auditor'}: {attestation.details}",
            )
        elif attestation.verdict == AuditVerdict.FAILED.value:
            return VerificationResult(
                action=action,
                status=ExecutionStatus.FAILED,
                verified=False,
                observed_state=attestation.observed_state,
                details=f"Auditor attestation FAILED: {attestation.details}",
            )
        else:  # UNVERIFIED or unknown verdict fails closed
            return VerificationResult(
                action=action,
                status=ExecutionStatus.FAILED,
                verified=False,
                observed_state=attestation.observed_state,
                details=f"Auditor attestation UNVERIFIED: {attestation.details} (fail-closed).",
            )

    def _call_auditor_with_timeout(self, req: AuditRequest) -> AuditAttestation:
        """Call the auditor dispatch with configurable timeout."""
        timeout = self.config.timeout_seconds

        def _invoke() -> AuditAttestation:
            if self.transport_call is not None:
                return self.transport_call(req)
            return self.auditor_service.process_audit_request(req)

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_invoke)
            try:
                return future.result(timeout=timeout)
            except concurrent.futures.TimeoutError as exc:
                raise AuditorTimeoutError(f"Auditor did not reply within {timeout:.1f}s") from exc
