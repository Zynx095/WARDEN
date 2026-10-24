"""Domain models and typed data structures for WARDEN."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field


class ActionType(str, Enum):
    """Explicitly supported operations in WARDEN."""
    READ = "READ"
    CREATE = "CREATE"
    WRITE = "WRITE"
    DELETE = "DELETE"
    RENAME = "RENAME"


class Decision(str, Enum):
    """Deterministic authorization decisions."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ExecutionStatus(str, Enum):
    """Lifecycle states of an action execution and verification."""
    PROPOSED = "PROPOSED"
    VERIFYING = "VERIFYING"
    AUTHORIZED = "AUTHORIZED"
    BLOCKED = "BLOCKED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    EXECUTED = "EXECUTED"
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"  # executed, but the outcome could not be independently confirmed
    FAILED = "FAILED"


def _generate_uuid() -> str:
    return str(uuid.uuid4())


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class Action(BaseModel):
    """Action requested by an agent or user."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    operation: str
    target: str
    reason: str = ""
    action_id: str = Field(default_factory=_generate_uuid)
    destination: Optional[str] = None
    content: Optional[str] = None
    actor_id: Optional[str] = None
    correlation_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=_now_utc)

    def __init__(
        self,
        operation: str = "",
        target: str = "",
        reason: str = "",
        action_id: Optional[str] = None,
        destination: Optional[str] = None,
        content: Optional[str] = None,
        actor_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        **kwargs: Any,
    ) -> None:
        data: Dict[str, Any] = {}
        if operation:
            data["operation"] = operation
        if target:
            data["target"] = target
        if reason:
            data["reason"] = reason
        if action_id:
            data["action_id"] = action_id
        if destination:
            data["destination"] = destination
        if content:
            data["content"] = content
        if actor_id:
            data["actor_id"] = actor_id
        if correlation_id:
            data["correlation_id"] = correlation_id
        if timestamp is not None:
            data["timestamp"] = timestamp
        data.update(kwargs)
        super().__init__(**data)


class PolicyResult(BaseModel):
    """Decision returned by deterministic policy evaluation."""
    model_config = ConfigDict(frozen=True)

    decision: Decision
    policy_id: str
    reason: str
    decision_id: str = Field(default_factory=_generate_uuid)
    timestamp: datetime = Field(default_factory=_now_utc)
    context: Dict[str, Any] = Field(default_factory=dict)

    def __init__(
        self,
        decision: Optional[Decision] = None,
        policy_id: Optional[str] = None,
        reason: Optional[str] = None,
        decision_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        context: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        data: Dict[str, Any] = {}
        if decision is not None:
            data["decision"] = decision
        if policy_id is not None:
            data["policy_id"] = policy_id
        if reason is not None:
            data["reason"] = reason
        if decision_id is not None:
            data["decision_id"] = decision_id
        if timestamp is not None:
            data["timestamp"] = timestamp
        if context is not None:
            data["context"] = context
        data.update(kwargs)
        super().__init__(**data)


class AuthorizationToken(BaseModel):
    """Cryptographically or structurally verifiable authorization grant.
    
    Issued strictly by trusted policy code and verified by the executor.
    LLMs cannot fabricate this token to bypass deterministic checks.
    """
    model_config = ConfigDict(frozen=True)

    token_id: str = Field(default_factory=_generate_uuid)
    action_id: str
    operation: str
    target_canonical: str
    destination_canonical: Optional[str] = None
    workspace_root: str
    issued_at: datetime = Field(default_factory=_now_utc)
    expires_at: datetime
    policy_id: str
    action_digest: Optional[str] = None
    state_digest: Optional[str] = None
    signature: str


class ExecutionRequest(BaseModel):
    """Request submitted to the controlled executor."""
    model_config = ConfigDict(frozen=True)

    action: Action
    authorization: Optional[AuthorizationToken] = None


class ExecutionResult(BaseModel):
    """Result of an attempted operation execution."""
    model_config = ConfigDict(frozen=True)

    execution_id: str = Field(default_factory=_generate_uuid)
    action: Action
    status: ExecutionStatus
    success: bool
    output: Optional[str] = None
    error: Optional[str] = None
    executed_at: datetime = Field(default_factory=_now_utc)


class VerificationResult(BaseModel):
    """Independent outcome verification result checking actual filesystem state."""
    model_config = ConfigDict(frozen=True)

    verification_id: str = Field(default_factory=_generate_uuid)
    action: Action
    status: ExecutionStatus
    verified: bool
    observed_state: Dict[str, Any] = Field(default_factory=dict)
    details: str = ""
    verified_at: datetime = Field(default_factory=_now_utc)


class AuditEvent(BaseModel):
    """Structured audit log entry recording state transitions."""
    model_config = ConfigDict(frozen=True)

    event_id: str = Field(default_factory=_generate_uuid)
    correlation_id: str = Field(default_factory=_generate_uuid)
    timestamp: datetime = Field(default_factory=_now_utc)
    operation: str
    target: str
    destination: Optional[str] = None
    decision: Optional[Decision] = None
    policy_id: Optional[str] = None
    execution_status: ExecutionStatus
    error: Optional[str] = None
    verification_status: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
