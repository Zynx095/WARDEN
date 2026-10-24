"""Authorization token issuance, verification, and human-in-the-loop approval workflow."""

from __future__ import annotations

import hmac
import hashlib
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, Optional, Tuple
from warden.config import get_config
from warden.models import (
    Action,
    AuthorizationToken,
    Decision,
    PolicyResult,
)
from warden.security.digest import compute_action_digest, digest_matches


def _canonical_str(p: Optional[Path | str]) -> str:
    if p is None:
        return ""
    return str(Path(p).resolve()).lower()


class AuthorizationError(Exception):
    """Raised when authorization verification fails."""
    pass


class PendingQueueFull(AuthorizationError):
    """Raised when the bounded pending-approval queue has no free slot."""
    pass


class ApprovalNotFound(AuthorizationError):
    """No approval was ever requested under this id (or its record has aged out)."""


class ApprovalExpired(AuthorizationError):
    """The approval window closed before a decision arrived."""


class ApprovalAlreadyResolved(AuthorizationError):
    """The request was already approved, rejected or invalidated; it cannot be decided again."""


class ApprovalNotAuthorized(AuthorizationError):
    """The deciding party is not an authorized approver for this request."""


class ApprovalDigestMismatch(AuthorizationError):
    """The supplied digest does not match the authoritative pending record."""


class ApprovalStateChanged(AuthorizationError):
    """The touched paths changed after the request was recorded."""


# Outcomes remembered after a pending request leaves the live queue.
RESOLVED_APPROVED = "APPROVED"
RESOLVED_REJECTED = "REJECTED"
RESOLVED_EXPIRED = "EXPIRED"
RESOLVED_INVALIDATED = "INVALIDATED"
MAX_RESOLVED_RECORDS = 1000


class PendingApproval:
    """Represents an action awaiting explicit human approval."""

    def __init__(
        self,
        action: Action,
        policy_result: PolicyResult,
        action_digest: Optional[str] = None,
        state_digest: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        authorized_approvers: Optional[Iterable[str]] = None,
    ) -> None:
        self.action = action
        self.policy_result = policy_result
        self.action_digest = action_digest
        self.state_digest = state_digest
        self.created_at = datetime.now(timezone.utc)
        self.expires_at = expires_at
        # None keeps the programmatic API's behaviour (any caller may decide); a set restricts it.
        self.authorized_approvers: Optional[FrozenSet[str]] = (
            frozenset(a for a in authorized_approvers if a) if authorized_approvers is not None else None
        )
        self.is_approved = False
        self.approved_by: Optional[str] = None
        self.approved_at: Optional[datetime] = None

    def approve(self, approver_id: str) -> None:
        self.is_approved = True
        self.approved_by = approver_id
        self.approved_at = datetime.now(timezone.utc)


@dataclass(frozen=True)
class ResolvedApproval:
    """What happened to a request that is no longer pending (kept so replies stay precise)."""
    outcome: str
    action: Action
    action_digest: Optional[str]
    resolved_at: datetime
    resolved_by: Optional[str] = None


class AuthorizationManager:
    """Manages cryptographic authorization tokens and human-in-the-loop approvals.
    
    Ensures that the LLM cannot fabricate an authorization grant to bypass policy,
    and guarantees actions requiring approval cannot proceed without explicit validation.
    """

    def __init__(
        self,
        secret_key: Optional[str] = None,
        approval_ttl_seconds: Optional[int] = None,
        max_pending: Optional[int] = None,
    ) -> None:
        self.secret_key = (secret_key or get_config().secret_key).encode("utf-8")
        self.approval_ttl_seconds = (
            approval_ttl_seconds if approval_ttl_seconds is not None else get_config().approval_ttl_seconds
        )
        self.max_pending = max_pending if max_pending is not None else get_config().max_pending_approvals
        self._pending_approvals: Dict[str, PendingApproval] = {}
        # Bounded memory of requests that left the queue, so a late decision gets a precise answer.
        self._resolved: "OrderedDict[str, ResolvedApproval]" = OrderedDict()

    def _compute_signature(
        self,
        token_id: str,
        action_id: str,
        operation: str,
        target_canonical: str,
        destination_canonical: str,
        workspace_root: str,
        expires_at_iso: str,
        policy_id: str,
        action_digest: str = "",
        state_digest: str = "",
    ) -> str:
        payload = (
            f"{token_id}|{action_id}|{operation.upper()}|"
            f"{target_canonical}|{destination_canonical}|"
            f"{workspace_root}|{expires_at_iso}|{policy_id}|"
            f"{action_digest}|{state_digest}"
        )
        return hmac.new(self.secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def issue_token(
        self,
        action: Action,
        target_canonical: Path,
        destination_canonical: Optional[Path],
        workspace_root: Path,
        policy_id: str,
        validity_seconds: int = 300,
        state_digest: Optional[str] = None,
    ) -> AuthorizationToken:
        """Issue a tamper-proof authorization token for an authorized action.

        The token is bound to a digest of the exact operation, canonical target and
        destination, content hash and workspace, and optionally to the observed
        pre-execution state of the touched paths.
        """
        import uuid
        token_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=validity_seconds)

        norm_target = _canonical_str(target_canonical)
        norm_dest = _canonical_str(destination_canonical)
        norm_ws = _canonical_str(workspace_root)

        action_digest = compute_action_digest(
            action.operation, target_canonical, destination_canonical, action.content, workspace_root
        )
        sig = self._compute_signature(
            token_id=token_id,
            action_id=action.action_id,
            operation=action.operation,
            target_canonical=norm_target,
            destination_canonical=norm_dest,
            workspace_root=norm_ws,
            expires_at_iso=expires_at.isoformat(),
            policy_id=policy_id,
            action_digest=action_digest,
            state_digest=state_digest or "",
        )

        return AuthorizationToken(
            token_id=token_id,
            action_id=action.action_id,
            operation=action.operation.upper(),
            target_canonical=norm_target,
            destination_canonical=norm_dest if destination_canonical else None,
            workspace_root=norm_ws,
            issued_at=now,
            expires_at=expires_at,
            policy_id=policy_id,
            action_digest=action_digest,
            state_digest=state_digest,
            signature=sig,
        )

    def verify_token(
        self,
        token: Optional[AuthorizationToken],
        action: Action,
        target_canonical: Path,
        destination_canonical: Optional[Path],
        workspace_root: Path,
        current_state_digest: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Verify an authorization token against expected action parameters and cryptographic signature.

        ``current_state_digest`` is the freshly observed state of the touched paths; when the
        token carries a state digest the two must match, otherwise the grant is stale.
        """
        if token is None:
            return False, "Missing authorization token."

        now = datetime.now(timezone.utc)
        if now > token.expires_at:
            return False, "Authorization token has expired."

        if token.action_id != action.action_id:
            return False, f"Authorization token action_id mismatch: expected {action.action_id}, got {token.action_id}."

        if token.operation.upper() != action.operation.upper():
            return False, f"Authorization token operation mismatch: expected {action.operation}, got {token.operation}."

        norm_target = _canonical_str(target_canonical)
        if token.target_canonical.lower() != norm_target:
            return False, f"Authorization token target mismatch: expected {norm_target}, got {token.target_canonical}."

        norm_dest = _canonical_str(destination_canonical)
        expected_dest = norm_dest if destination_canonical else ""
        token_dest = token.destination_canonical.lower() if token.destination_canonical else ""
        if token_dest != expected_dest:
            return False, f"Authorization token destination mismatch: expected {expected_dest}, got {token_dest}."

        norm_ws = _canonical_str(workspace_root)
        if token.workspace_root.lower() != norm_ws:
            return False, f"Authorization token workspace mismatch: expected {norm_ws}, got {token.workspace_root}."

        expected_digest = compute_action_digest(
            action.operation, target_canonical, destination_canonical, action.content, workspace_root
        )
        if not token.action_digest or token.action_digest != expected_digest:
            return False, "Authorization token is not bound to this exact action (digest mismatch)."

        if token.state_digest is not None and token.state_digest != current_state_digest:
            return False, "Target state changed since authorization was granted."

        # Verify cryptographic signature
        expected_sig = self._compute_signature(
            token_id=token.token_id,
            action_id=token.action_id,
            operation=token.operation,
            target_canonical=token.target_canonical,
            destination_canonical=token_dest,
            workspace_root=token.workspace_root,
            expires_at_iso=token.expires_at.isoformat(),
            policy_id=token.policy_id,
            action_digest=token.action_digest or "",
            state_digest=token.state_digest or "",
        )

        if not hmac.compare_digest(expected_sig, token.signature):
            return False, "Invalid authorization signature (token tampered or forged)."

        return True, None

    def _resolve(self, action_id: str, pending: PendingApproval, outcome: str, by: Optional[str] = None) -> None:
        """Move a request out of the live queue, remembering how it ended."""
        self._pending_approvals.pop(action_id, None)
        self._resolved[action_id] = ResolvedApproval(
            outcome=outcome,
            action=pending.action,
            action_digest=pending.action_digest,
            resolved_at=datetime.now(timezone.utc),
            resolved_by=by,
        )
        self._resolved.move_to_end(action_id)
        while len(self._resolved) > MAX_RESOLVED_RECORDS:
            self._resolved.popitem(last=False)

    def purge_expired(self) -> None:
        """Drop approvals whose validity window has ended."""
        now = datetime.now(timezone.utc)
        for aid, p in [(a, p) for a, p in self._pending_approvals.items() if p.expires_at and now > p.expires_at]:
            self._resolve(aid, p, RESOLVED_APPROVED if p.is_approved else RESOLVED_EXPIRED, p.approved_by)

    def register_pending_approval(
        self,
        action: Action,
        policy_result: PolicyResult,
        action_digest: Optional[str] = None,
        state_digest: Optional[str] = None,
        authorized_approvers: Optional[Iterable[str]] = None,
    ) -> str:
        """Register an action that requires explicit approval before execution.

        The queue is bounded: when it is full of live, unapproved entries the request is
        refused rather than evicting an older one the operator may still be reviewing.
        ``authorized_approvers``, when given, is the only set of identities that may decide it.
        """
        self.purge_expired()
        waiting = sum(1 for p in self._pending_approvals.values() if not p.is_approved)
        if action.action_id not in self._pending_approvals and waiting >= self.max_pending:
            raise PendingQueueFull(f"Too many actions awaiting approval (limit {self.max_pending}).")
        self._pending_approvals[action.action_id] = PendingApproval(
            action,
            policy_result,
            action_digest=action_digest,
            state_digest=state_digest,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.approval_ttl_seconds),
            authorized_approvers=authorized_approvers,
        )
        return action.action_id

    def get_pending_approval(self, action_id: str) -> Optional[PendingApproval]:
        """Retrieve a live pending approval by action_id (expired ones are discarded)."""
        self.purge_expired()
        return self._pending_approvals.get(action_id)

    def get_resolved(self, action_id: str) -> Optional[ResolvedApproval]:
        """How a request that is no longer pending ended, if still remembered."""
        self.purge_expired()
        return self._resolved.get(action_id)

    def lookup_pending(self, action_id: str) -> PendingApproval:
        """The live, undecided request for ``action_id``, or a typed error explaining why not."""
        pending = self.get_pending_approval(action_id)
        if pending is not None:
            if pending.is_approved:
                raise ApprovalAlreadyResolved(f"Action {action_id} has already been approved.")
            return pending
        resolved = self._resolved.get(action_id)
        if resolved is None:
            raise ApprovalNotFound(f"No pending approval found for action_id {action_id}.")
        if resolved.outcome == RESOLVED_EXPIRED:
            raise ApprovalExpired(f"The approval window for action {action_id} has expired; nothing was executed.")
        if resolved.outcome == RESOLVED_APPROVED:
            raise ApprovalAlreadyResolved(f"Action {action_id} has already been approved.")
        if resolved.outcome == RESOLVED_REJECTED:
            raise ApprovalAlreadyResolved(f"Action {action_id} was rejected and cannot be decided again.")
        raise ApprovalAlreadyResolved(
            f"Action {action_id} was invalidated because its target changed; request it again."
        )

    @staticmethod
    def _check_decider(pending: PendingApproval, approver_id: str, expected_digest: Optional[str]) -> None:
        """Shared by approve and reject: the decider must be authorized and name this exact action."""
        if pending.authorized_approvers is not None and approver_id not in pending.authorized_approvers:
            raise ApprovalNotAuthorized("This sender is not an authorized approver for the request; nothing was decided.")
        if expected_digest is not None:
            if not pending.action_digest or not digest_matches(pending.action_digest, expected_digest):
                raise ApprovalDigestMismatch(
                    "Approval digest does not match the pending action; nothing was approved."
                )

    def reject_pending_action(
        self,
        action_id: str,
        approver_id: str,
        expected_digest: Optional[str] = None,
    ) -> PendingApproval:
        """Explicitly reject a pending action. It can never be approved afterwards."""
        pending = self.lookup_pending(action_id)
        self._check_decider(pending, approver_id, expected_digest)
        self._resolve(action_id, pending, RESOLVED_REJECTED, approver_id)
        return pending

    def approve_pending_action(
        self,
        action_id: str,
        approver_id: str,
        target_canonical: Path,
        destination_canonical: Optional[Path],
        workspace_root: Path,
        expected_digest: Optional[str] = None,
        current_state_digest: Optional[str] = None,
    ) -> AuthorizationToken:
        """Explicitly approve a pending action, producing a valid authorization token.

        ``expected_digest`` is the digest the operator saw and echoed back; a mismatch
        refuses the approval without consuming it, as does an unauthorized approver. If the
        touched paths changed since the request was recorded, the pending entry is invalidated.
        """
        pending = self.lookup_pending(action_id)
        self._check_decider(pending, approver_id, expected_digest)

        if pending.state_digest is not None and pending.state_digest != current_state_digest:
            self._resolve(action_id, pending, RESOLVED_INVALIDATED, approver_id)
            raise ApprovalStateChanged(
                "Target state changed since approval was requested; the request was invalidated."
            )

        pending.approve(approver_id)

        # Issue authorization token with policy ID indicating approved exception
        return self.issue_token(
            action=pending.action,
            target_canonical=target_canonical,
            destination_canonical=destination_canonical,
            workspace_root=workspace_root,
            policy_id="WDN-004-APPROVED",
            state_digest=pending.state_digest,
        )
