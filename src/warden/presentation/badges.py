"""Status badges, operation icons and policy descriptions for WARDEN's presentation layer.

Consistent visual vocabulary for text reports, card titles and workflow traces. Badges are
labels only: they are derived from statuses the backend already decided.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from warden.models import Decision, ExecutionStatus

STATUS_BADGES: Dict[str, str] = {
    ExecutionStatus.VERIFIED.value:          "✅ VERIFIED",
    ExecutionStatus.UNVERIFIED.value:        "⚠️ UNVERIFIED",
    ExecutionStatus.AUTHORIZED.value:        "🔑 AUTHORIZED",
    ExecutionStatus.EXECUTED.value:          "⚙️ EXECUTED",
    ExecutionStatus.AWAITING_APPROVAL.value: "🔒 AWAITING APPROVAL",
    ExecutionStatus.PROPOSED.value:          "📋 PROPOSED",
    ExecutionStatus.VERIFYING.value:         "🔍 VERIFYING",
    ExecutionStatus.BLOCKED.value:           "🚫 BLOCKED",
    ExecutionStatus.REJECTED.value:          "🚫 REJECTED",
    ExecutionStatus.EXPIRED.value:           "⏱️ EXPIRED",
    ExecutionStatus.FAILED.value:            "❌ FAILED",
    "UNKNOWN":                               "❓ UNKNOWN",
}

DECISION_BADGES: Dict[str, str] = {
    Decision.ALLOW.value:            "✅ ALLOW",
    Decision.BLOCK.value:            "🚫 BLOCK",
    Decision.REQUIRE_APPROVAL.value: "🔒 REQUIRE APPROVAL",
}

OPERATION_ICONS: Dict[str, str] = {
    "READ":   "📖",
    "CREATE": "📝",
    "WRITE":  "✏️",
    "DELETE": "🗑️",
    "RENAME": "📁",
}

RISK_ICONS: Dict[str, str] = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}

# Policy identifiers used by warden.security.policy and the pipeline.
POLICY_DESCRIPTIONS: Dict[str, str] = {
    "WDN-000": "Baseline policy: permitted without approval",
    "WDN-001": "Unsupported operation or missing rename destination",
    "WDN-002": "Invalid path or outside the workspace boundary",
    "WDN-003": "Protected resource: reading or changing it is prohibited",
    "WDN-004": "Destructive action: explicit human approval required",
    "WDN-005": "Existing content: overwrite needs approval, replacement by rename is prohibited",
    "WDN-006": "Required risk assessment unavailable: change needs approval",
}


def badge(status: Any) -> str:
    """Display badge for an ExecutionStatus value or string."""
    key = status.value if isinstance(status, ExecutionStatus) else str(status).upper()
    return STATUS_BADGES.get(key, f"❓ {key}")


def op_icon(operation: Any) -> str:
    return OPERATION_ICONS.get(str(operation).upper(), "🔧")


def policy_description(policy_id: Optional[str]) -> str:
    """Human-readable description for a policy id; ``-APPROVED`` ids describe the approved exception."""
    if not policy_id:
        return "No policy on record"
    pid = str(policy_id)
    if pid.endswith("-APPROVED"):
        return f"Approved exception to {pid[:-len('-APPROVED')]}"
    return POLICY_DESCRIPTIONS.get(pid, pid)


def risk_label(risk: Optional[Dict[str, Any]]) -> str:
    """Short label for an advisory risk assessment dict (``result['risk']``)."""
    if not isinstance(risk, dict):
        return "not assessed"
    if risk.get("status") != "ASSESSED":
        return "unavailable"
    level = str(risk.get("risk_level") or "?")
    return f"{RISK_ICONS.get(level, '❔')} {level}"
