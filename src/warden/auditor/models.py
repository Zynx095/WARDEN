"""Data structures and protocol models for the Auditor uAgent."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from uagents import Model

from warden.auditor.digest import compute_action_digest
from warden.models import Action


class AuditVerdict(str, Enum):
    """Verdict returned by the independent Auditor."""
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    UNVERIFIED = "UNVERIFIED"


class AuditRequest(Model):
    """Structured audit verification request sent to the Auditor uAgent.

    Binds the action parameters to an unforgeable action digest and supplies
    pre-state manifest for collateral damage checking.
    """
    audit_id: str
    correlation_id: str
    action_id: str
    operation: str
    target: str
    destination: Optional[str] = None
    content: Optional[str] = None
    action_digest: str
    executor_claimed_success: bool = False
    workspace_root: str
    pre_state_manifest: Dict[str, Optional[str]] = {}
    timestamp: str = ""

    @classmethod
    def from_action(
        cls,
        action: Action,
        workspace_root: str | Path,
        executor_claimed_success: bool = False,
        pre_state_manifest: Optional[Dict[str, Optional[str]]] = None,
        correlation_id: Optional[str] = None,
        action_digest: Optional[str] = None,
    ) -> AuditRequest:
        """Construct an AuditRequest from an Action and workspace path."""
        digest = action_digest or compute_action_digest(action, workspace_root)
        return cls(
            audit_id=str(uuid.uuid4()),
            correlation_id=correlation_id or action.correlation_id or action.action_id,
            action_id=action.action_id,
            operation=action.operation.upper(),
            target=action.target,
            destination=action.destination,
            content=action.content,
            action_digest=digest,
            executor_claimed_success=executor_claimed_success,
            workspace_root=str(Path(workspace_root).resolve()),
            pre_state_manifest=pre_state_manifest or {},
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def to_action(self) -> Action:
        """Convert this audit request back into a domain Action model."""
        return Action(
            action_id=self.action_id,
            operation=self.operation,
            target=self.target,
            destination=self.destination,
            content=self.content,
            correlation_id=self.correlation_id,
        )


class AuditAttestation(Model):
    """Cryptographically attributable structured attestation from the Auditor uAgent.

    Contains observed disk state, expected state, specific evidence items,
    collateral mutation records, and final verdict.
    """
    attestation_id: str
    audit_id: str
    correlation_id: str
    action_id: str
    action_digest: str
    digest_valid: bool
    verdict: str  # maps to AuditVerdict: VERIFIED, FAILED, UNVERIFIED
    observed_state: Dict[str, Any] = {}
    expected_state: Dict[str, Any] = {}
    evidence: List[str] = []
    collateral_mutations: List[str] = []
    details: str = ""
    auditor_address: Optional[str] = None
    timestamp: str = ""
