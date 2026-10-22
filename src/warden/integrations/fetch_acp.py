"""Agent Chat Protocol (ACP) message schemas and Fetch.ai ecosystem integration models."""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    """Incoming user or agent conversational message."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    text: str
    sender: Optional[str] = None
    timestamp: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ActionCard(BaseModel):
    """ASI Interactive Card representation for action verification and approval."""
    card_type: str = "warden.action_verification"
    action_id: str
    operation: str
    target: str
    destination: Optional[str] = None
    decision: str
    policy_id: str
    reason: str
    status: str
    requires_user_approval: bool = False
    details: Optional[str] = None


class ChatResponse(BaseModel):
    """Outgoing conversational reply formatted for ACP / ASI:One."""
    response_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    text: str
    card: Optional[ActionCard] = None
    status: str = "completed"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ActionApprovalRequest(BaseModel):
    """Interactive approval request for destructive or policy-gated operations."""
    approval_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_id: str
    operation: str
    target: str
    destination: Optional[str] = None
    reason: str
    requested_by: str
    status: str = "pending"


class ActionApprovalResponse(BaseModel):
    """Approval or rejection submitted by user via ASI:One conversation."""
    approval_id: str
    action_id: str
    decision: str  # "APPROVED" or "REJECTED"
    approver: str
    comment: Optional[str] = None
