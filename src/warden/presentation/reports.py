"""Polished text-based report formatters for WARDEN's ACP chat responses.

These formatters produce the markdown text that appears in ASI:One chat
alongside (or instead of) Interactive Cards.  The output is human-scannable,
restrained, and enterprise-grade — not a wall of raw JSON or generic AI output.

Design rules
------------
- One clear status badge per action at the top of each block.
- Short action ID (8 chars) inline — full ID available in the card payload.
- Fields appear only when they carry genuine information.
- Evidence is always attributed ("Auditor verified…", "Policy blocked…").
- "WARDEN Sentinel" branding in the report header — concise, not verbose.
- Approval commands stand out in a dedicated code block.
- Reports are truncated before hitting the 4 000 character ACP limit.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from warden.models import ExecutionStatus
from warden.presentation.badges import (
    badge,
    op_icon,
    policy_description,
    risk_from_operation,
)
from warden.presentation.sanitize import (
    format_file_target,
    redact_digest,
    safe_id,
    sanitize,
    scrub_paths,
    truncate_report,
)

# ---------------------------------------------------------------------------
# Section dividers
# ---------------------------------------------------------------------------
_RULE = "─" * 48


def _header(title: str) -> str:
    return f"**{title}**\n{_RULE}"


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def format_verified(
    r: Dict[str, Any],
    idx: int,
    workspace_root: Any = None,
) -> str:
    """Format a VERIFIED execution result block."""
    action_id = safe_id(r.get("action_id", "unknown"))
    operation = sanitize(r.get("operation", ""), limit=20).upper()
    target = format_file_target(r.get("target", ""), workspace_root)
    details = scrub_paths(sanitize(r.get("verification_details", ""), limit=200), workspace_root)
    output = r.get("output")

    icon = op_icon(operation) if operation else "⚙️"
    lines = [
        f"{idx}. {badge(ExecutionStatus.VERIFIED)}  {icon} `{operation}` → `{target}`",
        f"   Auditor confirmed: {details}" if details else "   Auditor independently confirmed execution.",
    ]
    if output and str(output).strip():
        out_text = scrub_paths(sanitize(output, limit=400), workspace_root)
        lines.append(f"   Output:\n```\n{out_text}\n```")
    return "\n".join(lines)


def format_unverified(
    r: Dict[str, Any],
    idx: int,
    workspace_root: Any = None,
) -> str:
    """Format an UNVERIFIED execution result block."""
    action_id = safe_id(r.get("action_id", "unknown"))
    operation = sanitize(r.get("operation", ""), limit=20).upper()
    target = format_file_target(r.get("target", ""), workspace_root)
    details = scrub_paths(sanitize(r.get("verification_details", ""), limit=200), workspace_root)

    icon = op_icon(operation) if operation else "⚙️"
    return "\n".join([
        f"{idx}. {badge(ExecutionStatus.UNVERIFIED)}  {icon} `{operation}` → `{target}`",
        f"   Action ran, but the auditor could not independently confirm the outcome.",
        f"   Detail: {details}" if details else "",
    ]).rstrip()


def format_blocked(
    r: Dict[str, Any],
    idx: int,
    workspace_root: Any = None,
) -> str:
    """Format a BLOCKED result block."""
    action_id = safe_id(r.get("action_id", "unknown"))
    operation = sanitize(r.get("operation", ""), limit=20).upper()
    target = format_file_target(r.get("target", ""), workspace_root)
    policy_id = sanitize(r.get("policy_id", ""), limit=20)
    reason = scrub_paths(sanitize(r.get("reason", ""), limit=200), workspace_root)
    policy_desc = policy_description(policy_id)

    icon = op_icon(operation) if operation else "⚙️"
    lines = [
        f"{idx}. {badge(ExecutionStatus.BLOCKED)}  {icon} `{operation}` → `{target}`",
        f"   Policy `{policy_id}`: {policy_desc}",
    ]
    if reason:
        lines.append(f"   Reason: {reason}")
    lines.append(f"   *Blocked before execution — no filesystem change was made.*")
    return "\n".join(lines)


def format_awaiting_approval(
    r: Dict[str, Any],
    idx: int,
    workspace_root: Any = None,
) -> str:
    """Format an AWAITING APPROVAL result block with the exact approval command."""
    action_id = safe_id(r.get("action_id", "unknown"))
    pending_id = sanitize(r.get("pending_id", r.get("action_id", "")), limit=64, code_span=True)
    operation = sanitize(r.get("operation", ""), limit=20).upper()
    target = format_file_target(r.get("target", ""), workspace_root)
    destination = r.get("destination")
    content_sha = r.get("content_sha256")
    policy_id = sanitize(r.get("policy_id", "WDN-004"), limit=20)
    reason = scrub_paths(sanitize(r.get("reason", ""), limit=200), workspace_root)
    action_digest = sanitize(r.get("action_digest", ""), limit=64, code_span=True)
    expires_at = sanitize(r.get("expires_at", ""), limit=40)
    risk = risk_from_operation(operation)

    icon = op_icon(operation) if operation else "⚙️"
    lines = [
        f"{idx}. {badge(ExecutionStatus.AWAITING_APPROVAL)}  {icon} `{operation}` → `{target}`",
        f"   Risk: {risk}",
    ]
    if reason:
        lines.append(f"   Gate reason: {reason}")
    if destination:
        lines.append(f"   Destination: `{format_file_target(destination, workspace_root)}`")
    if content_sha:
        lines.append(f"   Content SHA-256: `{sanitize(content_sha, limit=64, code_span=True)}`")
    lines.append(f"   Policy: `{policy_id}` — {policy_description(policy_id)}")
    lines.append(f"   Digest (leading 16): `{redact_digest(action_digest)}`")
    if expires_at:
        lines.append(f"   Expires: {expires_at} UTC")
    lines.extend([
        "",
        "   To authorise **exactly** this operation, reply:",
        f"   ```",
        f"   APPROVE {pending_id} {action_digest}",
        f"   ```",
        "   Or send `REJECT <action_id>` to cancel.",
    ])
    return "\n".join(lines)


def format_failed(
    r: Dict[str, Any],
    idx: int,
    workspace_root: Any = None,
) -> str:
    """Format a FAILED result block."""
    operation = sanitize(r.get("operation", ""), limit=20).upper()
    target = format_file_target(r.get("target", ""), workspace_root)
    error = scrub_paths(sanitize(r.get("error", "Execution or verification failed."), limit=300), workspace_root)

    icon = op_icon(operation) if operation else "⚙️"
    lines = [
        f"{idx}. {badge(ExecutionStatus.FAILED)}  {icon} `{operation}` → `{target}`",
        f"   Error: {error}",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Report header / footer
# ---------------------------------------------------------------------------

def _sentinel_header() -> str:
    return "**WARDEN Sentinel** · Security Verification Report"


def format_no_action(user_text: str) -> str:
    """Format a 'no action proposed' response."""
    # Strip HTML-like angle-bracket sequences before echoing user input
    import re as _re
    safe_input = sanitize(user_text, limit=200)
    safe_input = _re.sub(r"<[^>]{0,60}>", "", safe_input)
    return "\n".join([
        _sentinel_header(),
        "",
        f"Request understood: *{safe_input}*",
        "",
        "No filesystem operation was proposed for this input.",
        "Supported operations: `READ` · `CREATE` · `WRITE` · `DELETE` · `RENAME`",
        "",
        "For help, describe the specific file and action you want to perform.",
    ])


def format_pipeline_report(
    user_text: str,
    results: List[Dict[str, Any]],
    workspace_root: Any = None,
) -> str:
    """Format a full pipeline report for one or more action results.

    Replaces the plain ``_format_pipeline_response`` in ``WardenACPHandler``.
    """
    safe_query = sanitize(user_text, limit=200)
    op_word = "operation" if len(results) == 1 else "operations"
    lines = [
        _sentinel_header(),
        "",
        f"Request: *{safe_query}*",
        f"Evaluated {len(results)} {op_word}:",
        "",
    ]

    for idx, r in enumerate(results, 1):
        status = r.get("status")
        if isinstance(status, ExecutionStatus):
            status_val = status
        else:
            try:
                status_val = ExecutionStatus(str(status).upper())
            except ValueError:
                status_val = None

        if status_val == ExecutionStatus.VERIFIED:
            block = format_verified(r, idx, workspace_root)
        elif status_val == ExecutionStatus.UNVERIFIED:
            block = format_unverified(r, idx, workspace_root)
        elif status_val == ExecutionStatus.BLOCKED:
            block = format_blocked(r, idx, workspace_root)
        elif status_val == ExecutionStatus.AWAITING_APPROVAL:
            block = format_awaiting_approval(r, idx, workspace_root)
        else:
            block = format_failed(r, idx, workspace_root)

        lines.append(block)
        lines.append("")

    return truncate_report("\n".join(lines).rstrip())


def format_approval_executed(action_id: str, res: Dict[str, Any], workspace_root: Any = None) -> str:
    """Format the response after a human approval is acted upon."""
    status = res.get("status")
    if isinstance(status, ExecutionStatus):
        status_str = status.value
    else:
        status_str = str(status or "UNKNOWN").upper()

    details = scrub_paths(
        sanitize(res.get("verification_details", ""), limit=300), workspace_root
    )
    error = scrub_paths(sanitize(res.get("error", ""), limit=300), workspace_root)
    output = res.get("output")

    lines = [
        _sentinel_header(),
        "",
        f"Approval executed for action `{safe_id(action_id)}`",
        "",
        f"Status: {badge(status_str)}",
    ]

    if status_str == ExecutionStatus.VERIFIED.value:
        lines.append(f"Auditor evidence: {details}" if details else "Auditor independently confirmed execution.")
    elif status_str == ExecutionStatus.UNVERIFIED.value:
        lines.append("Action ran, but the auditor could not independently confirm the outcome.")
        if details:
            lines.append(f"Detail: {details}")
    else:
        lines.append(f"Error: {error}" if error else "The action could not be completed.")

    if output and str(output).strip():
        out_text = scrub_paths(sanitize(output, limit=400), workspace_root)
        lines.append(f"\nOutput:\n```\n{out_text}\n```")

    return "\n".join(lines)
