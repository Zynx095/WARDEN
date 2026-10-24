"""Conversational text reports for WARDEN's ACP chat replies.

Every reply leads with this text; Interactive Cards are an optional extra on top of it, so
the text alone must carry everything needed to understand the outcome and, for a pending
action, the exact command to approve or reject it.

Input is the canonical result dict from ``WardenAgent`` (pipeline or decision). Nothing here
decides anything; untrusted values are sanitized and bounded, and the caller scrubs local
paths from the finished text.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from warden.models import ExecutionStatus
from warden.presentation.badges import badge, op_icon, policy_description
from warden.presentation.sanitize import sanitize, sanitize_block, truncate_report
from warden.presentation.workflow_trace import format_trace_line, format_workflow_trace, stages_from_result

HEADER = "**WARDEN Sentinel** · Security Verification Report"
DECISION_HEADER = "**WARDEN Sentinel** · Decision"
RECOMMENDATION_TEXT = {"ALLOW_CANDIDATE": "no concerns", "ESCALATE": "review carefully",
                       "BLOCK_CANDIDATE": "advises against"}


def _status(value: Any) -> Optional[ExecutionStatus]:
    try:
        return value if isinstance(value, ExecutionStatus) else ExecutionStatus(str(value))
    except ValueError:
        return None


def _code(value: Any, limit: int = 200) -> str:
    return sanitize(value, limit=limit, code_span=True)


def risk_line(result: Dict[str, Any], limit: int = 200) -> str:
    """One line describing the advisory assessment. Its text comes from another agent: bounded, no markup."""
    risk = result.get("risk")
    if not isinstance(risk, dict):
        return ""
    if risk.get("status") != "ASSESSED":
        text = f"unavailable: {risk.get('summary') or 'no assessment'}"
    else:
        advice = RECOMMENDATION_TEXT.get(str(risk.get("recommendation")), "advisory")
        text = f"{risk.get('risk_level')} ({advice}): {risk.get('summary') or ''}"
    return sanitize(text, limit=limit, code_span=True)


def _subject(r: Dict[str, Any]) -> str:
    op = sanitize(r.get("operation") or "", limit=20).upper()
    subject = f"{op_icon(op)} `{op}` `{_code(r.get('target') or '?')}`" if op else "`action`"
    if r.get("destination"):
        subject += f" → `{_code(r['destination'])}`"
    return subject


def _approval_commands(r: Dict[str, Any]) -> List[str]:
    pending_id = _code(r.get("pending_id") or r.get("action_id"), 64)
    digest = _code(r.get("action_digest"), 64)
    who = ("an independent approver (not the requester)" if r.get("independent_approval")
           else "the requester or a configured approver")
    return [
        f"   - **Action ID:** `{pending_id}`",
        f"   - **Action digest:** `{digest}`",
        f"   - **Expires:** {sanitize(r.get('expires_at') or 'unknown', limit=40)}",
        f"   - **Who can approve:** {who}",
        "   - **To approve exactly this action, reply:**",
        f"     `APPROVE {pending_id} {digest}`",
        f"     or reject it: `REJECT {pending_id} {digest}`",
    ]


def format_result_block(r: Dict[str, Any], idx: int) -> str:
    status = _status(r.get("status"))
    lines = [f"**{idx}. {badge(status or 'UNKNOWN')}** · {_subject(r)}"]
    if r.get("policy_id"):
        lines.append(f"   - **Policy:** `{_code(r['policy_id'], 30)}` — {policy_description(r['policy_id'])}")
    if r.get("reason") and status in (ExecutionStatus.BLOCKED, ExecutionStatus.AWAITING_APPROVAL):
        lines.append(f"   - **Reason:** {sanitize(r['reason'], limit=200)}")
    rl = risk_line(r)
    if rl:
        lines.append(f"   - **Risk (advisory, not an authorization):** {rl}")

    if status == ExecutionStatus.VERIFIED:
        lines.append(f"   - **Auditor:** {sanitize(r.get('verification_details'), limit=300)}")
        output = r.get("output")
        if output is not None and str(output).strip():
            lines.append(f"   - **Output:**\n```\n{sanitize_block(output)}\n```")
    elif status == ExecutionStatus.UNVERIFIED:
        lines.append("   - **Result:** It ran, but the outcome could NOT be independently confirmed.")
        lines.append(f"   - **Detail:** {sanitize(r.get('verification_details'), limit=300)}")
    elif status == ExecutionStatus.BLOCKED:
        lines.append("   - **Result:** Blocked by deterministic policy before execution; nothing was changed.")
    elif status == ExecutionStatus.AWAITING_APPROVAL:
        if r.get("content_sha256"):
            lines.append(f"   - **Content SHA-256:** `{_code(r['content_sha256'], 64)}`")
        lines.extend(_approval_commands(r))
    else:
        lines.append(f"   - **Error:** {sanitize(r.get('error') or 'Execution or verification failed.', limit=300)}")
        lines.append("   - **Result:** Not completed. No success is claimed.")
    lines.append(f"   - **Trace:** {format_trace_line(stages_from_result(r))}")
    return "\n".join(lines)


def format_pipeline_report(user_text: str, results: List[Dict[str, Any]], workspace_root: Any = None) -> str:
    """Report for a new request: one block per proposed action."""
    word = "operation" if len(results) == 1 else "operations"
    lines = [HEADER, f"Request: *{sanitize(user_text, limit=200)}*", f"Evaluated {len(results)} {word}:", ""]
    for idx, r in enumerate(results, 1):
        lines.extend([format_result_block(r, idx), ""])
    return truncate_report("\n".join(lines).rstrip())


DECISION_TEXT = {
    ExecutionStatus.VERIFIED: "Executed after approval, and the actual outcome was independently confirmed.",
    ExecutionStatus.UNVERIFIED: "Executed after approval, but the outcome could NOT be independently confirmed.",
    ExecutionStatus.REJECTED: "Rejected. Nothing was executed. The request is closed and cannot be approved later.",
    ExecutionStatus.EXPIRED: "This request EXPIRED before a decision arrived; nothing was executed. "
                             "Ask again to get a fresh request.",
}


def format_decision_report(action_id: str, r: Dict[str, Any], workspace_root: Any = None) -> str:
    """Report for an approve/reject decision, including refusals."""
    status = _status(r.get("status"))
    short = _code(action_id, 36)
    lines = [DECISION_HEADER, f"{badge(status or 'UNKNOWN')} · {_subject(r)} · action `{short}`", ""]
    if r.get("refused") or (status == ExecutionStatus.FAILED and not r.get("execution_attempted")):
        lines.append(f"**Approval refused** for `{short[:8]}`: {sanitize(r.get('error'), limit=400)}")
        lines.append("Nothing was executed.")
    elif status in DECISION_TEXT:
        lines.append(DECISION_TEXT[status])
        if status in (ExecutionStatus.VERIFIED, ExecutionStatus.UNVERIFIED):
            lines.append(f"- **Auditor:** {sanitize(r.get('verification_details'), limit=400)}")
    else:
        lines.append("Not completed. No success is claimed.")
        lines.append(f"- **Error:** {sanitize(r.get('error'), limit=400)}")
    rl = risk_line(r)
    if rl:
        lines.append(f"- **Risk (advisory, not an authorization):** {rl}")
    output = r.get("output")
    if status == ExecutionStatus.VERIFIED and output is not None and str(output).strip():
        lines.append(f"- **Output:**\n```\n{sanitize_block(output)}\n```")
    lines.extend(["", format_workflow_trace(stages_from_result(r))])
    return truncate_report("\n".join(lines))


def format_no_action(user_text: str) -> str:
    safe = re.sub(r"<[^>]{0,60}>", "", sanitize(user_text, limit=200))
    return "\n".join([
        HEADER,
        f"Request: *{safe}*",
        "",
        "No filesystem operation was proposed for this input.",
        "Supported operations: `READ` · `CREATE` · `WRITE` · `DELETE` · `RENAME`.",
        "Describe the specific file and the action you want, for example `read README.txt`.",
    ])
