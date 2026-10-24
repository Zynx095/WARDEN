"""Central WARDEN coordination agent separating proposal, authorization, execution, and verification."""

from __future__ import annotations

from dataclasses import dataclass, field
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
from warden.security.state_store import StateStore
from warden.risk.analyst import LocalRiskAnalyst, build_risk_request


@dataclass(frozen=True)
class ActionBinding:
    """Canonical identity and observed state of one proposed action."""
    action_digest: str
    state_digest: str
    target_path: Path
    destination_path: Optional[Path]
    target_display: str
    state: Dict[str, Any] = field(default_factory=dict)


class WardenAgent:
    """End-to-end WARDEN action verification and execution orchestrator.
    
    Coordinates the four distinct stages:
    1. Proposal: Ingesting an action proposal from user or upstream LLM.
    2. Deterministic Authorization: Evaluating action strictly via PolicyEngine.
    3. Controlled Execution: Executing authorized actions via RestrictedExecutor.
    4. Independent Verification: Verifying physical filesystem outcome via OutcomeAuditor.

    Between proposal and authorization an optional Risk Analyst adds an advisory assessment
    (evidence and a recommendation). It is recorded and shown, and never consulted by policy,
    approval or execution.
    """

    def __init__(
        self,
        workspace: Optional[Workspace] = None,
        config: Optional[WardenConfig] = None,
        audit_log_file: Optional[Path] = None,
        auditor: Optional[Any] = None,
        risk_analyst: Optional[Any] = None,
    ) -> None:
        self.config = config or get_config()
        self.workspace = workspace or Workspace(self.config.workspace_root)
        self.path_validator = PathValidator(self.workspace.root_path)
        self.policy_engine = PolicyEngine(self.workspace.root_path)
        # Durable approval state when WARDEN_STATE_DB is set; an unusable store refuses startup.
        self.state_store = StateStore(self.config.state_db) if self.config.state_db else None
        self.auth_manager = AuthorizationManager(self.config.secret_key, store=self.state_store)
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
        if risk_analyst is None and self.config.risk_analyst == "remote":
            raise ConfigError("WARDEN_RISK_ANALYST=remote is set but no remote Risk Analyst was supplied.")
        if risk_analyst is None and self.config.risk_analyst == "local":
            risk_analyst = LocalRiskAnalyst()
        self.risk_analyst = risk_analyst

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
        state = capture_target_state(target_val.canonical_path, dest_path)
        return ActionBinding(
            action_digest=compute_action_digest(
                action.operation, target_val.canonical_path, dest_path, action.content, self.workspace.root_path
            ),
            state_digest=compute_state_digest(state),
            target_path=target_val.canonical_path,
            destination_path=dest_path,
            target_display=target_val.relative_path or action.target,
            state=state,
        )

    def _assess_risk(
        self,
        action: Action,
        binding: Optional[ActionBinding],
        correlation_id: str,
        request_text: Optional[str],
        batch_size: int,
    ) -> Optional[Dict[str, Any]]:
        """Advisory risk stage. Returns the outcome as a dict, or None when no analyst is configured."""
        if self.risk_analyst is None:
            return None
        request = build_risk_request(
            action,
            binding.action_digest if binding else None,
            binding.target_display if binding else None,
            binding.state if binding else None,
            self.policy_engine.protected_files,
            request_text=request_text,
            batch_size=batch_size,
        )
        try:
            risk = self.risk_analyst.assess(request).as_dict()
        except Exception as exc:  # an analyst must never break the pipeline
            risk = {"status": "UNAVAILABLE", "source": getattr(self.risk_analyst, "source", "unknown"),
                    "action_id": action.action_id, "action_digest": request.action_digest,
                    "summary": f"Risk analysis failed ({type(exc).__name__}); policy decision unaffected.",
                    "findings": [], "request_id": request.request_id}
        self.audit_logger.record(
            AuditEvent(
                correlation_id=correlation_id,
                operation=action.operation,
                target=action.target,
                destination=action.destination,
                execution_status=ExecutionStatus.PROPOSED,
                metadata={"stage": "risk_analysis", "risk_status": risk["status"], "risk_source": risk["source"],
                          "risk_level": risk.get("risk_level"), "recommendation": risk.get("recommendation"),
                          "action_digest": risk["action_digest"], "risk_request_id": risk.get("request_id"),
                          "finding_codes": [f.get("code") for f in risk.get("findings", [])]},
            )
        )
        return risk

    def handle_action_request(
        self,
        action: Action,
        auto_execute_allowed: bool = True,
        authorized_approvers: Optional[Iterable[str]] = None,
        request_text: Optional[str] = None,
        batch_size: int = 1,
        requester: Optional[str] = None,
        independent_approval: bool = False,
        proposal: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Process an action request through the complete verification pipeline.

        ``authorized_approvers``, when given, is bound into a resulting approval request: only
        those identities can later approve or reject it, whatever channel the decision uses.
        ``request_text`` and ``batch_size`` (the instruction and how many actions it produced)
        are context for the advisory Risk Analyst only. ``requester`` is bound into an approval
        request; with ``independent_approval`` the requester can never approve it.
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
                metadata={"reason": action.reason, **({"proposal": proposal} if proposal else {})},
            )
        )

        # Step 1b: Advisory risk analysis of the exact, canonically bound action
        bound = self._bind(action)
        risk = self._assess_risk(action, bound, correlation_id, request_text, batch_size)
        extra: Dict[str, Any] = {"risk": risk} if risk is not None else {}

        # Step 2: Deterministic Policy Evaluation (the risk assessment is not an input)
        policy_result: PolicyResult = self.policy_engine.evaluate(action)
        if (self.config.risk_required and policy_result.decision == Decision.ALLOW
                and action.operation.upper() != ActionType.READ.value
                and (risk is None or risk.get("status") != "ASSESSED")):
            # Deterministic rule on missing evidence: without a valid assessment a change needs a human.
            policy_result = PolicyResult(
                decision=Decision.REQUIRE_APPROVAL,
                policy_id="WDN-006",
                reason="A required risk assessment was unavailable; this change needs approval.",
                context=policy_result.context,
            )

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
                **self._describe(action, None),
                **extra,
            }

        # Handle REQUIRE_APPROVAL decisions
        if policy_result.decision == Decision.REQUIRE_APPROVAL:
            binding = bound
            if binding is None:
                return {**self._refuse(action, correlation_id,
                                       "Action could not be canonically bound; no approval was requested."), **extra}
            try:
                pending_id = self.auth_manager.register_pending_approval(
                    action,
                    policy_result,
                    action_digest=binding.action_digest,
                    state_digest=binding.state_digest,
                    authorized_approvers=authorized_approvers,
                    risk=risk,
                    requester=requester,
                    independent=independent_approval,
                )
            except PendingQueueFull as exc:
                return {**self._refuse(action, correlation_id, str(exc)), **extra}
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
                "independent_approval": bool(independent_approval),
                "expires_at": pending.expires_at.isoformat() if pending and pending.expires_at else None,
                "executed": False,
                "verified": False,
                **extra,
            }

        # Step 3: Authorization Grant
        binding = bound
        if binding is None:
            return {**self._refuse(action, correlation_id,
                                   "Action could not be canonically bound; nothing was authorized."), **extra}
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
                **extra,
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
                "policy_id": policy_result.policy_id,
                "error": exec_result.error,
                "executed": False,
                "execution_attempted": True,
                "verified": False,
                **self._describe(action, binding),
                **extra,
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
            "policy_id": policy_result.policy_id,
            "executed": True,
            "execution_attempted": True,
            "verified": verification.verified,
            "output": exec_result.output,
            "verification_details": verification.details,
            "observed_state": verification.observed_state,
            **self._describe(action, binding),
            **extra,
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
        """Approve a pending action and execute it through verification (see ``_approve_and_execute``).

        The result is marked ``decided`` so reports can tell a decision apart from a new request.
        """
        return {**self._approve_and_execute(action_id, approver_id, expected_digest), "decided": True}

    def _approve_and_execute(
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

        # Policy is evaluated again: a request that policy now blocks is cancelled, never executed.
        current = self.policy_engine.evaluate(action)
        if current.decision == Decision.BLOCK:
            self.auth_manager.invalidate_pending(action_id, by=approver_id)
            return {**self._refuse(action, correlation_id,
                                   f"Policy now blocks this action ({current.policy_id}: {current.reason}); "
                                   "the request was cancelled."),
                    "policy_id": current.policy_id, **self._describe(action, binding), **self._risk_of(pending)}

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
            return {**self._refuse(action, correlation_id, str(exc)), **self._describe(action, binding), **self._risk_of(pending)}

        self.audit_logger.record(
            AuditEvent(
                correlation_id=correlation_id,
                operation=action.operation,
                target=action.target,
                destination=action.destination,
                decision=Decision.ALLOW,
                policy_id=auth_token.policy_id,
                execution_status=ExecutionStatus.AUTHORIZED,
                metadata={"approved_by": approver_id, "action_digest": binding.action_digest,
                          "token_id": auth_token.token_id, "requester": pending.requester,
                          "independent_approval": pending.independent},
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
            self.auth_manager.record_outcome(action_id, ExecutionStatus.FAILED.value)
            return {
                "action_id": action_id,
                "correlation_id": correlation_id,
                "status": ExecutionStatus.FAILED,
                "policy_id": pending.policy_result.policy_id,
                "error": exec_result.error,
                "executed": False,
                "execution_attempted": True,
                "verified": False,
                **self._describe(action, binding),
                **self._risk_of(pending),
            }

        verification = self.auditor.verify_outcome(action, exec_result, pre_state)
        final_status = self._final_status(verification)
        self.auth_manager.record_outcome(action_id, final_status.value)

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
            "policy_id": pending.policy_result.policy_id,
            "executed": True,
            "execution_attempted": True,
            "verified": verification.verified,
            "output": exec_result.output,
            "verification_details": verification.details,
            "observed_state": verification.observed_state,
            **self._describe(action, binding),
            **self._risk_of(pending),
        }

    def reject_pending(
        self,
        action_id: str,
        approver_id: str,
        expected_digest: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Reject a pending action (see ``_reject_pending``); the result is marked ``decided``."""
        return {**self._reject_pending(action_id, approver_id, expected_digest), "decided": True}

    def _reject_pending(
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
            "policy_id": pending.policy_result.policy_id,
            "reason": "Rejected by an authorized approver. Nothing was executed.",
            "executed": False,
            "verified": False,
            **self._describe(action, None),
            **self._risk_of(pending),
        }

    @staticmethod
    def _risk_of(pending: Any) -> Dict[str, Any]:
        """The advisory assessment recorded with a pending request, for the decision's result."""
        risk = getattr(pending, "risk", None)
        return {"risk": risk} if risk is not None else {}

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
