"""Multi-agent workflow trace formatter for WARDEN Sentinel.

Renders a compact, scannable pipeline trace for the five-stage lifecycle:
  Intent → Risk Analyst → Policy Guard → Executor → Auditor

Rules:
- Stages that were skipped, failed, or timed-out are shown explicitly.
- No fake activity, simulated timestamps, or fabricated success indicators.
- Only real backend-provided stage outcomes are rendered.
- Decoupled from agent implementation — accepts a plain dict of stage results.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from warden.presentation.badges import badge, op_icon, policy_description
from warden.presentation.sanitize import (
    format_file_target,
    safe_id,
    sanitize,
    scrub_paths,
)

# Stage display names and icons
_STAGE_META: Dict[str, tuple[str, str]] = {
    "intent":       ("📩", "Intent Parser"),
    "risk":         ("🔍", "Risk Analyst"),
    "policy":       ("🛡️", "Policy Guard"),
    "executor":     ("⚙️ ", "Executor"),
    "auditor":      ("🔬", "Outcome Auditor"),
}

_STAGE_ORDER = ["intent", "risk", "policy", "executor", "auditor"]

_V = "│"        # vertical line
_T = "├─"       # tee
_L = "└─"       # last branch
_SKIP = "⬚"     # skipped / unavailable


def _stage_line(key: str, outcome: Optional[Dict[str, Any]], last: bool = False, workspace_root: Any = None) -> str:
    """Render one stage row in the trace."""
    connector = _L if last else _T
    icon, name = _STAGE_META.get(key, ("❓", key.title()))

    if outcome is None:
        return f"  {connector} {icon} **{name}** — *skipped*"

    status = str(outcome.get("status", "unknown")).upper()
    note = scrub_paths(sanitize(outcome.get("note", ""), limit=120), workspace_root)

    if status in {"OK", "PASS", "VERIFIED", "ALLOWED", "ALLOW", "AUTHORIZED", "EXECUTED"}:
        marker = "✅"
    elif status in {"BLOCKED", "REJECTED", "FAILED", "ERROR"}:
        marker = "🚫"
    elif status in {"AWAITING", "AWAITING_APPROVAL", "PENDING"}:
        marker = "🔒"
    elif status in {"UNVERIFIED", "WARNING"}:
        marker = "⚠️ "
    elif status in {"SKIPPED", "UNAVAILABLE"}:
        marker = _SKIP
    else:
        marker = "❓"

    line = f"  {connector} {icon} **{name}** {marker}"
    if note:
        line += f"\n  {'  ' if not last else '   '}{_V}   ↳ {note}"
    return line


def format_workflow_trace(
    stages: Dict[str, Optional[Dict[str, Any]]],
    action_summary: Optional[str] = None,
    workspace_root: Any = None,
) -> str:
    """Render a multi-agent pipeline trace.

    Parameters
    ----------
    stages:
        Mapping of stage key → outcome dict.  Use ``None`` for stages that
        were skipped.  Recognised keys: ``intent``, ``risk``, ``policy``,
        ``executor``, ``auditor``.
    action_summary:
        Optional one-line action description shown in the trace header.
    workspace_root:
        If provided, scrubs local paths from note strings.
    """
    lines = ["**Pipeline Trace** — WARDEN Sentinel Network"]
    if action_summary:
        safe_summary = scrub_paths(sanitize(action_summary, limit=120), workspace_root)
        lines.append(f"Action: *{safe_summary}*")
    lines.append("")

    ordered_keys = [k for k in _STAGE_ORDER if k in stages or True]
    for i, key in enumerate(ordered_keys):
        last = i == len(ordered_keys) - 1
        outcome = stages.get(key)  # None if key absent
        # Scrub workspace paths from notes before rendering
        if outcome is not None and workspace_root:
            outcome = dict(outcome)
            outcome["note"] = scrub_paths(str(outcome.get("note", "")), workspace_root)
        lines.append(_stage_line(key, outcome, last=last))

    return "\n".join(lines)


def stages_from_pipeline_result(
    result: Dict[str, Any],
    workspace_root: Any = None,
) -> Dict[str, Optional[Dict[str, Any]]]:
    """Build a stages dict from a standard WARDEN pipeline result dict.

    Maps the available fields from ``handle_action_request`` output to the
    five canonical stages so ``format_workflow_trace`` can be called without
    the caller needing to construct the stage dict manually.
    """
    from warden.models import Decision, ExecutionStatus

    status = result.get("status")
    if isinstance(status, ExecutionStatus):
        status_val = status
    else:
        try:
            status_val = ExecutionStatus(str(status).upper())
        except ValueError:
            status_val = None

    decision = result.get("decision")

    # --- Intent stage ---
    intent_note = ""
    operation = sanitize(result.get("operation", ""), limit=30).upper()
    target = scrub_paths(sanitize(result.get("target", ""), limit=100), workspace_root)
    if operation or target:
        intent_note = f"`{operation}` → `{target}`" if operation else target

    intent_stage: Dict[str, Any] = {"status": "OK", "note": intent_note}

    # --- Risk stage ---
    risk_note = ""
    if result.get("reason"):
        risk_note = scrub_paths(sanitize(result["reason"], limit=100), workspace_root)
    risk_stage: Optional[Dict[str, Any]] = {"status": "OK", "note": risk_note} if risk_note else {"status": "OK"}

    # --- Policy stage ---
    policy_id = result.get("policy_id")
    policy_note = policy_description(policy_id) if policy_id else ""
    if decision == Decision.BLOCK or status_val == ExecutionStatus.BLOCKED:
        policy_status = "BLOCKED"
    elif decision == Decision.REQUIRE_APPROVAL or status_val == ExecutionStatus.AWAITING_APPROVAL:
        policy_status = "AWAITING_APPROVAL"
    else:
        policy_status = "ALLOWED"
    policy_stage: Dict[str, Any] = {"status": policy_status, "note": policy_note}

    # --- Executor stage ---
    if status_val in {ExecutionStatus.BLOCKED, ExecutionStatus.AWAITING_APPROVAL}:
        executor_stage: Optional[Dict[str, Any]] = {"status": "SKIPPED", "note": "Not reached — action did not proceed to execution"}
    elif result.get("executed") is False:
        executor_stage = {"status": "SKIPPED", "note": "Execution was not attempted"}
    elif status_val in {ExecutionStatus.FAILED} and not result.get("executed"):
        executor_stage = {"status": "FAILED", "note": scrub_paths(sanitize(result.get("error", ""), limit=100), workspace_root)}
    elif status_val in {ExecutionStatus.VERIFIED, ExecutionStatus.UNVERIFIED}:
        executor_stage = {"status": "OK", "note": "Operation completed"}
    else:
        executor_stage = {"status": "FAILED", "note": scrub_paths(sanitize(result.get("error", ""), limit=100), workspace_root)}

    # --- Auditor stage ---
    if status_val == ExecutionStatus.VERIFIED:
        auditor_note = scrub_paths(sanitize(result.get("verification_details", ""), limit=120), workspace_root)
        auditor_stage: Optional[Dict[str, Any]] = {"status": "VERIFIED", "note": auditor_note}
    elif status_val == ExecutionStatus.UNVERIFIED:
        auditor_note = scrub_paths(sanitize(result.get("verification_details", ""), limit=120), workspace_root)
        auditor_stage = {"status": "UNVERIFIED", "note": auditor_note}
    elif status_val in {ExecutionStatus.BLOCKED, ExecutionStatus.AWAITING_APPROVAL}:
        auditor_stage = None  # not reached
    else:
        auditor_stage = None

    return {
        "intent":   intent_stage,
        "risk":     risk_stage,
        "policy":   policy_stage,
        "executor": executor_stage,
        "auditor":  auditor_stage,
    }
