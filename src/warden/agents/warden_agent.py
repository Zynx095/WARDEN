"""Central WARDEN coordination agent separating proposal, authorization, execution, and verification."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from warden.audit.auditor import OutcomeAuditor
from warden.audit.events import AuditLogger
from warden.config import ConfigError, WardenConfig, get_config
from warden.execution.executor import RestrictedExecutor
from warden.execution.workspace import Workspace
from warden.models import (
    Action,
    ActionType,
    AuditEvent,
    AuthorizationToken,
    Decision,
    ExecutionRequest,
    ExecutionResult,
    ExecutionStatus,
    PolicyResult,
    VerificationResult,
)
from warden.security.authorization import (
    ApprovalExpired,
    AuthorizationError,
    AuthorizationManager,
    PendingQueueFull,
)
from warden.security.digest import (
    capture_target_state,
    compute_action_digest,
    compute_state_digest,
    sha256_text,
)
from warden.security.path_validation import PathValidator
from warden.security.policy import PolicyEngine


@dataclass(frozen=True)
class ActionBinding:
    """Canonical identity and observed state of one proposed action."""
    action_digest: str
    state_digest: str
    target_path: Path
    destination_path: Optional[Path]
    target_display: str


class WardenAgent:
    """End-to-end WARDEN action verification and execution orchestrator.
    
    Coordinates the four distinct stages:
    1. Proposal: Ingesting an action proposal from user or upstream LLM.
    2. Deterministic Authorization: Evaluating action strictly via PolicyEngine.
    3. Controlled Execution: Executing authorized actions via RestrictedExecutor.
    4. Independent Verification: Verifying physical filesystem outcome via OutcomeAuditor.
    """

    def __init__(
        self,
        workspace: Optional[Workspace] = None,
        config: Optional[WardenConfig] = None,
        audit_log_file: Optional[Path] = None,
        auditor: Optional[Any] = None,
    ) -> None:
        self.config = config or get_config()
        self.workspace = workspace or Workspace(self.config.workspace_root)
        self.path_validator = PathValidator(self.workspace.root_path)
        self.policy_engine = PolicyEngine(self.workspace.root_path)
        self.auth_manager = AuthorizationManager(self.config.secret_key)
        self.executor = RestrictedExecutor(
            self.workspace,
            auth_manager=self.auth_manager,
            path_validator=self.path_validator,
        )
        if auditor is None and self.config.remote_auditor:
            # Fail closed: never fall back to local-only verification when the operator asked for a remote one.
            raise ConfigError("WARDEN_REMOTE_AUDITOR is enabled but no remote auditor was supplied.")
        self.auditor = auditor or OutcomeAuditor(self.workspace, path_validator=self.path_validator)
        self.audit_logger = AuditLogger(audit_log_file)

    def _bind(self, action: Action) -> Optional[ActionBinding]:
        """Canonicalize an action and fingerprint the paths it touches; None if it cannot be bound."""
        allow_root = (action.operation.upper() == ActionType.READ.value)
        target_val = self.path_validator.validate_path(action.target, allow_root=allow_root)
        if not target_val.is_safe or not target_val.canonical_path:
            return None
        dest_path: Optional[Path] = None
        if action.destination:
            dest_val = self.path_validator.validate_path(action.destination)
            if not dest_val.is_safe or not dest_val.canonical_path:
                return None
            dest_path = dest_val.canonical_path
        return ActionBinding(
            action_digest=compute_action_digest(
                action.operation, target_val.canonical_path, dest_path, action.content, self.workspace.root_path
            ),
            state_digest=compute_state_digest(capture_target_state(target_val.canonical_path, dest_path)),
            target_path=target_val.canonical_path,
            destination_path=dest_path,
            target_display=target_val.relative_path or action.target,
        )

    def handle_action_request(
        self,
        action: Action,
        auto_execute_allowed: bool = True,
        authorized_approvers: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """Process an action request through the complete verification pipeline.

        ``authorized_approvers``, when given, is bound into a resulting approval request: only
        those identities can later approve or reject it, whatever channel the decision uses.
        """
        correlation_id = action.correlation_id or action.action_id

        # Step 1: Log proposal
        self.audit_logger.record(
            AuditEvent(
                correlation_id=correlation_id,
                operation=action.operation,
                target=action.target,
                destination=action.destination,
                execution_status=ExecutionStatus.PROPOSED,
                metadata={"reason": action.reason},
            )
        )

        # Step 2: Deterministic Policy Evaluation
        policy_result: PolicyResult = self.policy_engine.evaluate(action)

        # Handle BLOCKED decisions
        if policy_result.decision == Decision.BLOCK:
            self.audit_logger.record(
                AuditEvent(
                    correlation_id=correlation_id,
                    operation=action.operation,
                    target=action.target,
                    destination=action.destination,
                    decision=Decision.BLOCK,
                    policy_id=policy_result.policy_id,
                    execution_status=ExecutionStatus.BLOCKED,
                    error=policy_result.reason,
                )
            )
            return {
                "action_id": action.action_id,
                "correlation_id": correlation_id,
                "status": ExecutionStatus.BLOCKED,
                "decision": Decision.BLOCK,
                "policy_id": policy_result.policy_id,
                "reason": policy_result.reason,
                "executed": False,
                "verified": False,
            }

        # Handle REQUIRE_APPROVAL decisions
        if policy_result.decision == Decision.REQUIRE_APPROVAL:
            binding = self._bind(action)
            if binding is None:
                return self._refuse(action, correlation_id, "Action could not be canonically bound; no approval was requested.")
            try:
                pending_id = self.auth_manager.register_pending_approval(
                    action,
                    policy_result,
                    action_digest=binding.action_digest,
                    state_digest=binding.state_digest,
                    authorized_approvers=authorized_approvers,
                )
            except PendingQueueFull as exc:
                return self._refuse(action, correlation_id, str(exc))
            pending = self.auth_manager.get_pending_approval(pending_id)
            self.audit_logger.record(
                AuditEvent(
                    correlation_id=correlation_id,
                    operation=action.operation,
                    target=action.target,
                    destination=action.destination,
                    decision=Decision.REQUIRE_APPROVAL,
                    policy_id=policy_result.policy_id,
                    execution_status=ExecutionStatus.AWAITING_APPROVAL,
                    metadata={"pending_id": pending_id, "action_digest": binding.action_digest},
                )
            )
            return {
                "action_id": action.action_id,
                "correlation_id": correlation_id,
                "status": ExecutionStatus.AWAITING_APPROVAL,
                "decision": Decision.REQUIRE_APPROVAL,
                "policy_id": policy_result.policy_id,
                "pending_id": pending_id,
                "reason": policy_result.reason,
                "operation": action.operation.upper(),
                "target": binding.target_display,
                "destination": action.destination,
                "content_sha256": sha256_text(action.content) if action.content is not None else None,
                "action_digest": binding.action_digest,
                "expires_at": pending.expires_at.isoformat() if pending and pending.expires_at else None,
                "executed": False,
                "verified": False,
            }

        # Step 3: Authorization Grant
        binding = self._bind(action)
        if binding is None:
            return self._refuse(action, correlation_id, "Action could not be canonically bound; nothing was authorized.")
        auth_token = self.auth_manager.issue_token(
            action=action,
            target_canonical=binding.target_path,
            destination_canonical=binding.destination_path,
            workspace_root=self.workspace.root_path,
            policy_id=policy_result.policy_id,
            state_digest=binding.state_digest,
        )

        self.audit_logger.record(
            AuditEvent(
                correlation_id=correlation_id,
                operation=action.operation,
                target=action.target,
                destination=action.destination,
                decision=Decision.ALLOW,
                policy_id=policy_result.policy_id,
                execution_status=ExecutionStatus.AUTHORIZED,
                metadata={"token_id": auth_token.token_id},
            )
        )

        if not auto_execute_allowed:
            return {
                "action_id": action.action_id,
                "correlation_id": correlation_id,
                "status": ExecutionStatus.AUTHORIZED,
                "decision": Decision.ALLOW,
                "auth_token": auth_token,
                "executed": False,
                "verified": False,
            }

        # Step 4: Controlled Execution (pre-execution evidence is captured first so the
        # auditor can later establish what actually changed)
        pre_state = self.auditor.capture_pre_state(action)
        exec_request = ExecutionRequest(action=action, authorization=auth_token)
        exec_result: ExecutionResult = self.executor.execute(exec_request)

        if not exec_result.success:
            self.audit_logger.record(
                AuditEvent(
                    correlation_id=correlation_id,
                    operation=action.operation,
                    target=action.target,
                    destination=action.destination,
                    execution_status=ExecutionStatus.FAILED,
                    error=exec_result.error,
                )
            )
            return {
                "action_id": action.action_id,
                "correlation_id": correlation_id,
                "status": ExecutionStatus.FAILED,
                "error": exec_result.error,
                "executed": False,
                "verified": False,
            }

        # Step 5: Independent Outcome Verification
        verification: VerificationResult = self.auditor.verify_outcome(action, exec_result, pre_state)

        final_status = self._final_status(verification)

        self.audit_logger.record(
            AuditEvent(
                correlation_id=correlation_id,
                operation=action.operation,
                target=action.target,
                destination=action.destination,
                execution_status=final_status,
                verification_status=final_status.value,
                metadata={
                    "action_digest": binding.action_digest,
                    "details": verification.details,
                    "observed": verification.observed_state,
                },
            )
        )

        return {
            "action_id": action.action_id,
            "correlation_id": correlation_id,
            "status": final_status,
            "executed": True,
            "verified": verification.verified,
            "output": exec_result.output,
            "verification_details": verification.details,
            "observed_state": verification.observed_state,
        }

    @staticmethod
    def _final_status(verification: VerificationResult) -> ExecutionStatus:
        """VERIFIED only on a positive verification; an unconfirmed outcome is UNVERIFIED, never VERIFIED."""
        if verification.verified:
            return ExecutionStatus.VERIFIED
        if verification.status == ExecutionStatus.UNVERIFIED:
            return ExecutionStatus.UNVERIFIED
        return ExecutionStatus.FAILED

    def _refuse(self, action: Action, correlation_id: str, reason: str) -> Dict[str, Any]:
        """Fail closed: record why nothing was authorized or approved and report a FAILED result."""
        self.audit_logger.record(
            AuditEvent(
                correlation_id=correlation_id,
                operation=action.operation,
                target=action.target,
                destination=action.destination,
                execution_status=ExecutionStatus.FAILED,
                error=reason,
            )
        )
        return {
            "action_id": action.action_id,
            "correlation_id": correlation_id,
            "status": ExecutionStatus.FAILED,
            "error": reason,
            "executed": False,
            "verified": False,
        }

    def approve_and_execute(
        self,
        action_id: str,
        approver_id: str,
        expected_digest: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Explicitly approve a pending action and execute it through verification.

        ``expected_digest`` is the action digest the operator was shown; when supplied it must
        match the pending action. The touched paths are re-fingerprinted and the approval is
        invalidated if they changed since it was requested.
        """
        try:
            pending = self.auth_manager.lookup_pending(action_id)
        except AuthorizationError as exc:
            return self._decision_refused(action_id, exc)

        action = pending.action
        correlation_id = action.correlation_id or action.action_id
        binding = self._bind(action)
        if binding is None:
            return self._refuse(action, correlation_id, "Target path invalid upon approval.")

        try:
            auth_token = self.auth_manager.approve_pending_action(
                action_id=action_id,
                approver_id=approver_id,
                target_canonical=binding.target_path,
                destination_canonical=binding.destination_path,
                workspace_root=self.workspace.root_path,
                expected_digest=expected_digest,
                current_state_digest=binding.state_digest,
            )
        except AuthorizationError as exc:
            return {**self._refuse(action, correlation_id, str(exc)), **self._describe(action, binding)}

        self.audit_logger.record(
            AuditEvent(
                correlation_id=correlation_id,
                operation=action.operation,
                target=action.target,
                destination=action.destination,
                decision=Decision.ALLOW,
                policy_id="WDN-004-APPROVED",
                execution_status=ExecutionStatus.AUTHORIZED,
                metadata={"approved_by": approver_id, "action_digest": binding.action_digest,
                          "token_id": auth_token.token_id},
            )
        )

        # Execute approved action
        pre_state = self.auditor.capture_pre_state(action)
        exec_request = ExecutionRequest(action=action, authorization=auth_token)
        exec_result = self.executor.execute(exec_request)

        if not exec_result.success:
            self.audit_logger.record(
                AuditEvent(
                    correlation_id=correlation_id,
                    operation=action.operation,
                    target=action.target,
                    destination=action.destination,
                    execution_status=ExecutionStatus.FAILED,
                    error=exec_result.error,
                    metadata={"approved_by": approver_id, "action_digest": binding.action_digest},
                )
            )
            return {
                "action_id": action_id,
                "correlation_id": correlation_id,
                "status": ExecutionStatus.FAILED,
                "error": exec_result.error,
                "executed": False,
                "verified": False,
                **self._describe(action, binding),
            }

        verification = self.auditor.verify_outcome(action, exec_result, pre_state)
        final_status = self._final_status(verification)

        self.audit_logger.record(
            AuditEvent(
                correlation_id=correlation_id,
                operation=action.operation,
                target=action.target,
                destination=action.destination,
                execution_status=final_status,
                verification_status=final_status.value,
                metadata={
                    "approved_by": approver_id,
                    "action_digest": binding.action_digest,
                    "details": verification.details,
                    "observed": verification.observed_state,
                },
            )
        )

        return {
            "action_id": action_id,
            "correlation_id": correlation_id,
            "status": final_status,
            "executed": True,
            "verified": verification.verified,
            "output": exec_result.output,
            "verification_details": verification.details,
            "observed_state": verification.observed_state,
            **self._describe(action, binding),
        }

    def reject_pending(
        self,
        action_id: str,
        approver_id: str,
        expected_digest: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Explicitly reject a pending action; it is removed and can never be approved afterwards.

        The same rules as approval apply to who may decide and which digest must be named.
        """
        try:
            pending = self.auth_manager.reject_pending_action(action_id, approver_id, expected_digest)
        except AuthorizationError as exc:
            return self._decision_refused(action_id, exc)

        action = pending.action
        correlation_id = action.correlation_id or action.action_id
        self.audit_logger.record(
            AuditEvent(
                correlation_id=correlation_id,
                operation=action.operation,
                target=action.target,
                destination=action.destination,
                execution_status=ExecutionStatus.REJECTED,
                metadata={"rejected_by": approver_id, "action_digest": pending.action_digest},
            )
        )
        return {
            "action_id": action_id,
            "correlation_id": correlation_id,
            "status": ExecutionStatus.REJECTED,
            "reason": "Rejected by an authorized approver. Nothing was executed.",
            "executed": False,
            "verified": False,
            **self._describe(action, None),
        }

    @staticmethod
    def _describe(action: Action, binding: Optional[ActionBinding]) -> Dict[str, Any]:
        """Display fields for a decided action (workspace-relative, never an absolute path)."""
        return {
            "operation": action.operation.upper(),
            "target": binding.target_display if binding else action.target,
            "destination": action.destination,
        }

    def _decision_refused(self, action_id: str, exc: AuthorizationError) -> Dict[str, Any]:
        """A decision that could not be applied. Expiry is reported as EXPIRED; everything else FAILED."""
        status = ExecutionStatus.EXPIRED if isinstance(exc, ApprovalExpired) else ExecutionStatus.FAILED
        result: Dict[str, Any] = {
            "action_id": action_id,
            "status": status,
            "error": str(exc),
            "executed": False,
            "verified": False,
        }
        resolved = self.auth_manager.get_resolved(action_id)
        if resolved is not None:
            action = resolved.action
            correlation_id = action.correlation_id or action.action_id
            result.update(correlation_id=correlation_id, **self._describe(action, None))
            self.audit_logger.record(
                AuditEvent(
                    correlation_id=correlation_id,
                    operation=action.operation,
                    target=action.target,
                    destination=action.destination,
                    execution_status=status,
                    error=str(exc),
                    metadata={"decision_refused": type(exc).__name__},
                )
            )
        return result
