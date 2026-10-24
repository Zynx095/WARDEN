"""Workflow trace: what each stage actually did for one action.

Intent → Risk Analyst → Policy Guard → Approval → Executor → Auditor

Built only from fields the backend put in the result dict. A stage the action never reached
is shown as not reached; nothing is inferred or simulated. Each stage gets one of:
DONE, PENDING, SKIPPED (not configured or not needed), NOT_REACHED, BLOCKED, REJECTED,
EXPIRED, TIMED_OUT, UNAVAILABLE, FAILED, UNVERIFIED, VERIFIED.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from warden.models import ExecutionStatus
from warden.presentation.badges import policy_description, risk_label
from warden.presentation.sanitize import sanitize

STAGES: Tuple[Tuple[str, str], ...] = (
    ("intent", "Intent"),
    ("risk", "Risk Analyst"),
    ("policy", "Policy Guard"),
    ("approval", "Approval"),
    ("executor", "Executor"),
    ("auditor", "Auditor"),
)

MARKERS: Dict[str, str] = {
    "DONE": "✅", "VERIFIED": "✅", "PENDING": "🔒", "SKIPPED": "⬚", "NOT_REACHED": "⬚",
    "BLOCKED": "🚫", "REJECTED": "🚫", "EXPIRED": "⏱️", "TIMED_OUT": "⏱️", "UNAVAILABLE": "⚠️",
    "FAILED": "❌", "UNVERIFIED": "⚠️",
}

Stage = Dict[str, str]


def _status(value: Any) -> Optional[ExecutionStatus]:
    try:
        return value if isinstance(value, ExecutionStatus) else ExecutionStatus(str(value))
    except ValueError:
        return None


def _stage(state: str, note: str = "") -> Stage:
    return {"state": state, "note": sanitize(note, limit=140)}


def stages_from_result(result: Dict[str, Any]) -> Dict[str, Stage]:
    """Map one canonical WARDEN result (pipeline or decision) to per-stage outcomes."""
    status = _status(result.get("status"))
    policy_id = str(result.get("policy_id") or "")
    attempted = bool(result.get("execution_attempted"))
    stages: Dict[str, Stage] = {}

    op, target = str(result.get("operation") or "").upper(), str(result.get("target") or "")
    stages["intent"] = _stage("DONE", f"{op} {target}".strip())

    risk = result.get("risk")
    if not isinstance(risk, dict):
        stages["risk"] = _stage("SKIPPED", "no Risk Analyst configured")
    elif risk.get("status") == "ASSESSED":
        stages["risk"] = _stage("DONE", f"{risk_label(risk)} ({risk.get('source')}), advisory")
    else:
        summary = str(risk.get("summary") or "")
        stages["risk"] = _stage("TIMED_OUT" if "timeout" in summary else "UNAVAILABLE", summary)

    decided = result.get("decided")  # set on results of an approve/reject decision
    if status == ExecutionStatus.BLOCKED:
        stages["policy"] = _stage("BLOCKED", f"{policy_id}: {policy_description(policy_id)}")
    elif status == ExecutionStatus.AWAITING_APPROVAL or decided:
        stages["policy"] = _stage("DONE", f"{policy_id or 'approval'} requires approval")
    elif status == ExecutionStatus.FAILED and not attempted:
        stages["policy"] = _stage("FAILED", str(result.get("error") or "the action could not be authorized"))
    else:
        stages["policy"] = _stage("DONE", f"{policy_id or 'WDN-000'}: allowed")

    if status == ExecutionStatus.AWAITING_APPROVAL:
        stages["approval"] = _stage("PENDING", "waiting for an authorized decision")
    elif status == ExecutionStatus.REJECTED:
        stages["approval"] = _stage("REJECTED", "an authorized party declined")
    elif status == ExecutionStatus.EXPIRED:
        stages["approval"] = _stage("EXPIRED", "no decision before the window closed")
    elif decided and not attempted:
        stages["approval"] = _stage("FAILED", str(result.get("error") or "decision refused"))
    elif decided:
        stages["approval"] = _stage("DONE", "approved by an authorized party")
    elif status == ExecutionStatus.BLOCKED:
        stages["approval"] = _stage("NOT_REACHED")
    else:
        stages["approval"] = _stage("SKIPPED", "not required by policy")

    if not attempted:
        stages["executor"] = _stage("NOT_REACHED")
        stages["auditor"] = _stage("NOT_REACHED")
        return stages
    if not result.get("executed"):
        stages["executor"] = _stage("FAILED", str(result.get("error") or "execution failed"))
        stages["auditor"] = _stage("NOT_REACHED")
        return stages
    stages["executor"] = _stage("DONE", "ran the exact authorized action")
    remote = ((result.get("observed_state") or {}).get("remote_auditor") or {})
    source = "local + remote attestation" if remote.get("valid") else "local check"
    if status == ExecutionStatus.VERIFIED:
        stages["auditor"] = _stage("VERIFIED", source)
    elif status == ExecutionStatus.UNVERIFIED:
        stages["auditor"] = _stage("UNVERIFIED", str(remote.get("note") or result.get("verification_details") or ""))
    else:
        stages["auditor"] = _stage("FAILED", str(result.get("verification_details") or result.get("error") or ""))
    return stages


def format_trace_line(stages: Dict[str, Stage]) -> str:
    """One-line trace for chat reports, e.g. ``Intent ✅ → Risk Analyst ✅ → Policy Guard 🔒 …``."""
    parts: List[str] = []
    for key, name in STAGES:
        stage = stages.get(key) or _stage("NOT_REACHED")
        parts.append(f"{name} {MARKERS.get(stage['state'], '❓')}")
    return " → ".join(parts)


def format_workflow_trace(stages: Dict[str, Stage], action_summary: Optional[str] = None) -> str:
    """Multi-line trace with a note per stage."""
    lines = ["**Workflow trace**"]
    if action_summary:
        lines.append(f"Action: {sanitize(action_summary, limit=120)}")
    for i, (key, name) in enumerate(STAGES):
        stage = stages.get(key) or _stage("NOT_REACHED")
        branch = "└─" if i == len(STAGES) - 1 else "├─"
        state = stage["state"].replace("_", " ").lower()
        note = f": {stage['note']}" if stage.get("note") else ""
        lines.append(f"{branch} {MARKERS.get(stage['state'], '❓')} **{name}** ({state}){note}")
    return "\n".join(lines)
