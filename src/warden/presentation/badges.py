"""Status badge and icon constants for WARDEN's presentation layer.

Defines the consistent visual vocabulary used across text-based reports,
Interactive Card payloads, and workflow traces.

All symbols are drawn from the Unicode Basic Multilingual Plane and chosen
for broad terminal / chat-client compatibility.  Avoid emoji sequences that
require a Variation Selector — stick to single code-points or neutral symbols.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from warden.models import Decision, ExecutionStatus


# ---------------------------------------------------------------------------
# Status badges — rendered inline in markdown text replies
# ---------------------------------------------------------------------------
# Each badge must be scannable at a glance in a conversational interface and
# clearly distinguish the nine lifecycle states.

STATUS_BADGES: Dict[str, str] = {
    # Positive outcomes
    ExecutionStatus.VERIFIED.value:          "✅ VERIFIED",
    # Soft outcomes
    ExecutionStatus.UNVERIFIED.value:        "⚠️  UNVERIFIED",
    ExecutionStatus.AUTHORIZED.value:        "🔑 AUTHORIZED",
    ExecutionStatus.EXECUTED.value:          "⚙️  EXECUTED",
    # Gating states
    ExecutionStatus.AWAITING_APPROVAL.value: "🔒 AWAITING APPROVAL",
    ExecutionStatus.PROPOSED.value:          "📋 PROPOSED",
    ExecutionStatus.VERIFYING.value:         "🔍 VERIFYING",
    # Negative outcomes
    ExecutionStatus.BLOCKED.value:           "🚫 BLOCKED",
    ExecutionStatus.FAILED.value:            "❌ FAILED",
    # Extra named states used in presentation only
    "REJECTED":                              "🚫 REJECTED",
    "EXPIRED":                               "⏱️  EXPIRED",
    "UNKNOWN":                               "❓ UNKNOWN",
}

# Decision badges map policy decisions to compact one-liners
DECISION_BADGES: Dict[str, str] = {
    Decision.ALLOW.value:            "✅ ALLOW",
    Decision.BLOCK.value:            "🚫 BLOCK",
    Decision.REQUIRE_APPROVAL.value: "🔒 REQUIRE APPROVAL",
}

# Operation icons — shown next to action type
OPERATION_ICONS: Dict[str, str] = {
    "READ":   "📖",
    "CREATE": "📝",
    "WRITE":  "✏️ ",
    "DELETE": "🗑️ ",
    "RENAME": "📁",
}

# Risk tier labels used in approval cards
RISK_LABELS: Dict[str, str] = {
    "low":      "Low",
    "medium":   "Medium",
    "high":     "High",
    "critical": "Critical",
}

# Policy IDs → human-readable explanations
POLICY_DESCRIPTIONS: Dict[str, str] = {
    "WDN-001": "Path traversal prevented — target outside workspace boundary",
    "WDN-002": "Reserved system target — operation on restricted path refused",
    "WDN-003": "Protected resource — modification of sensitive file blocked",
    "WDN-004": "Destructive action gate — explicit human approval required",
    "WDN-004-APPROVED": "Human-approved destructive action — approval verified",
    "WDN-005": "Content policy violation — action refused",
    "OPERATOR-REJECTED": "Operator explicitly cancelled this request",
}


def badge(status: Any) -> str:
    """Return the display badge for an ExecutionStatus value or string."""
    key = status.value if isinstance(status, ExecutionStatus) else str(status).upper()
    return STATUS_BADGES.get(key, f"❓ {key}")


def op_icon(operation: Any) -> str:
    """Return the operation icon for a given operation string."""
    return OPERATION_ICONS.get(str(operation).upper(), "🔧")


def policy_description(policy_id: Optional[str]) -> str:
    """Return a human-readable description for a known policy ID."""
    if not policy_id:
        return "No policy on record"
    return POLICY_DESCRIPTIONS.get(str(policy_id), str(policy_id))


def risk_from_operation(operation: str) -> str:
    """Infer a display risk tier from operation type — conservative, not security-relevant."""
    op = str(operation).upper()
    if op == "DELETE":
        return "High — permanent removal"
    if op == "WRITE":
        return "Medium — content modification"
    if op == "RENAME":
        return "Medium — path relocation"
    if op == "CREATE":
        return "Low — new file creation"
    if op == "READ":
        return "None — read-only, no side effects"
    return "Unknown"
