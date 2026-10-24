"""Intent stage: turns a chat request into validated, versioned action proposals.

The Intent Agent has no execution permission and no authority: its output is a proposal that
the Risk Analyst assesses and the Policy Guard decides on. Parser output (deterministic rules,
or the ASI:One model when configured) is treated as untrusted and validated here; anything
malformed is dropped with a stated reason rather than repaired. Each proposal records whether
the user named the target or it was inferred, so assumptions stay visible.

This is an in-process component, not a separate agent identity.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from warden.agents.intent_engine import IntentEngine
from warden.models import Action, ActionType
from warden.security.digest import sha256_text

PROPOSAL_SCHEMA = "warden.intent.proposal.v1"
MAX_PROPOSALS_PER_REQUEST = 10
MAX_TARGET_CHARS = 400
MAX_CONTENT_CHARS = 100_000


class ActionProposal(BaseModel):
    """One validated proposal. ``proposal_id`` becomes the action id used by every later stage."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = PROPOSAL_SCHEMA
    proposal_id: str
    request_id: str                       # the chat request this proposal came from
    operation: Literal["READ", "CREATE", "WRITE", "DELETE", "RENAME"]
    target: str = Field(min_length=1, max_length=MAX_TARGET_CHARS)
    destination: Optional[str] = Field(default=None, max_length=MAX_TARGET_CHARS)
    content_sha256: Optional[str] = None
    content_length: Optional[int] = None
    reason: str = Field(default="", max_length=300)
    source: Literal["deterministic", "llm"]
    target_named_by_user: bool
    assumptions: List[str] = Field(default_factory=list)

    def audit_metadata(self) -> Dict[str, Any]:
        return {"proposal_schema": self.schema_version, "request_id": self.request_id, "source": self.source,
                "target_named_by_user": self.target_named_by_user, "assumptions": list(self.assumptions)}


@dataclass
class ProposalBatch:
    request_id: str
    proposals: List[ActionProposal] = field(default_factory=list)
    actions: List[Action] = field(default_factory=list)   # aligned with ``proposals``
    rejected: List[str] = field(default_factory=list)     # why parser output was dropped


def _name(path: str) -> str:
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()


def _invalid(action: Action) -> Optional[str]:
    op = (action.operation or "").upper()
    if op not in {o.value for o in ActionType}:
        return f"unsupported operation {op[:20]!r}"
    for label, value in (("target", action.target), ("destination", action.destination)):
        if value is None:
            continue
        if not value.strip() or len(value) > MAX_TARGET_CHARS:
            return f"{label} is empty or too long"
        if any(not ch.isprintable() for ch in value):
            return f"{label} contains control characters"
    if op == "RENAME" and not (action.destination or "").strip():
        return "rename without a destination"
    if action.content is not None and len(action.content) > MAX_CONTENT_CHARS:
        return "content is larger than 100000 characters"
    return None


class IntentAgent:
    def __init__(self, engine: Optional[IntentEngine] = None) -> None:
        self.engine = engine or IntentEngine()

    def propose(self, text: str, context: Optional[Dict[str, Any]] = None) -> ProposalBatch:
        batch = ProposalBatch(request_id=str(uuid.uuid4()))
        raw = self.engine.parse_intent(text, context=context)
        source = "llm" if getattr(self.engine, "last_source", "deterministic") == "llm" else "deterministic"
        lowered = re.sub(r"\s+", " ", (text or "").lower())
        for action in raw:
            if len(batch.proposals) >= MAX_PROPOSALS_PER_REQUEST:
                batch.rejected.append(f"more than {MAX_PROPOSALS_PER_REQUEST} actions in one request; the rest were "
                                      "dropped, ask for them separately")
                break
            why = _invalid(action)
            if why:
                batch.rejected.append(why)
                continue
            named = bool(_name(action.target)) and _name(action.target) in lowered
            assumptions = [] if named or action.target.strip() in {".", "./"} else [
                f"target {_name(action.target)} was inferred, not named in the request"]
            action = action.model_copy(update={"operation": action.operation.upper()})
            proposal = ActionProposal(
                proposal_id=action.action_id,
                request_id=batch.request_id,
                operation=action.operation,
                target=action.target,
                destination=action.destination,
                content_sha256=sha256_text(action.content) if action.content is not None else None,
                content_length=len(action.content) if action.content is not None else None,
                reason="".join(ch for ch in (action.reason or "") if ch.isprintable())[:300],
                source=source,
                target_named_by_user=named,
                assumptions=assumptions,
            )
            batch.proposals.append(proposal)
            batch.actions.append(action)
        return batch
