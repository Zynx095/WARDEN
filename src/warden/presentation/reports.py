"""Conversational text reports for WARDEN's ACP chat replies.

Every reply leads with this text; Interactive Cards are an optional extra on top of it, so the
text alone always carries what is needed to understand the outcome and, for a pending action,
the exact command to approve or reject it. It stays readable where a client renders plain
text only: a headline, one status badge per action, short bullet fields, no tables.

With ``compact=True`` (a valid card accompanies the text) a pending action's advisory risk,
effect, expiry, approver and content hash are left to its review card; status, target, policy,
execution, verification, read output, the typed-command fallback, the trace and the audit
reference always stay in the text. Result cards are glanceable only, so a finished action's
risk stays in the text too.

Input is the canonical result dict from ``WardenAgent`` (pipeline or decision). Nothing here
decides anything; untrusted values are sanitized and bounded, and the caller scrubs local
paths from the finished text.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from warden.models import ExecutionStatus
from warden.presentation.badges import badge, policy_description
from warden.presentation.sanitize import sanitize, sanitize_block, truncate_report
from warden.presentation.workflow_trace import format_trace_path, stages_from_result

BRAND = "WARDEN Sentinel"
RECOMMENDATION_TEXT = {"ALLOW_CANDIDATE": "no concerns", "ESCALATE": "review carefully",
                       "BLOCK_CANDIDATE": "advises against"}
HEADLINES = {
    ExecutionStatus.VERIFIED: "Action verified",
    ExecutionStatus.UNVERIFIED: "Outcome unverified",
    ExecutionStatus.BLOCKED: "Action blocked",
    ExecutionStatus.AWAITING_APPROVAL: "Approval required",
    ExecutionStatus.REJECTED: "Action rejected",
    ExecutionStatus.EXPIRED: "Approval expired",
    ExecutionStatus.FAILED: "Action failed",
}
REFUSED_HEADLINE = "Decision refused"
# Above this many actions every block is brief, so all typed commands fit in one message.
FULL_BLOCKS_UP_TO = 3
EFFECTS = {
    "READ": "reads {target}",
    "CREATE": "creates {target} with the proposed content",
    "WRITE": "overwrites {target} with the proposed content",
    "DELETE": "permanently deletes {target}",
    "RENAME": "renames {target} to {destination}",
}
# What the deterministic parser understands; RENAME needs the ASI:One model parser.
EXAMPLES = [
    "list the files in the workspace",
    "read README.txt",
    'create report.txt with content "Build complete"',
    'write report.txt with content "Updated report"',
    "delete report.txt",
    "clean up temporary files",
]
RENAME_EXAMPLE = "rename report.txt to report-old.txt"


def _status(value: Any) -> Optional[ExecutionStatus]:
    try:
        return value if isinstance(value, ExecutionStatus) else ExecutionStatus(str(value))
    except ValueError:
        return None


def _code(value: Any, limit: int = 200) -> str:
    return sanitize(value, limit=limit, code_span=True)


def _clause(value: Any, limit: int = 300) -> str:
    """Untrusted text as one clause: single line, bounded, without a trailing full stop."""
    return " ".join(sanitize(value, limit=limit).split()).rstrip(" .")


def headline(text: str) -> str:
    return f"**{BRAND} — {text}**"


def expiry_text(expires_at: Optional[str], now: Optional[datetime] = None) -> str:
    """``in 5 min (11:15 UTC)`` for an ISO-8601 expiry; ``unknown`` if it cannot be read."""
    if not expires_at:
        return "unknown"
    try:
        when = datetime.fromisoformat(str(expires_at))
    except ValueError:
        return "unknown"
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    minutes = max(0, int(((when - (now or datetime.now(timezone.utc))).total_seconds() + 59) // 60))
    return f"in {minutes} min ({when.astimezone(timezone.utc).strftime('%H:%M UTC')})"


def approver_text(r: Dict[str, Any]) -> str:
    return "an independent approver (not you)" if r.get("independent_approval") else "you or a configured approver"


def effect_text(r: Dict[str, Any], markup: bool = True) -> str:
    """What executing this exact action would do, from its operation and workspace-relative paths.

    ``markup=False`` gives plain text for card fields, which render no Markdown.
    """
    op = str(r.get("operation") or "").upper()
    quote = (lambda v: f"`{_code(v)}`") if markup else (lambda v: _code(v))
    template = EFFECTS.get(op, "runs {op} on {target}")
    return template.format(op=quote(op), target=quote(r.get("target") or "?"),
                           destination=quote(r.get("destination") or "?"))


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


def is_refused(r: Dict[str, Any]) -> bool:
    """A decision that was not applied, so nothing ran (as opposed to an execution that failed)."""
    return bool(r.get("refused")) or (bool(r.get("decided")) and _status(r.get("status")) == ExecutionStatus.FAILED
                                      and not r.get("execution_attempted"))


def _subject(r: Dict[str, Any]) -> str:
    op = sanitize(r.get("operation") or "", limit=20).upper()
    subject = f"`{op}` `{_code(r.get('target') or '?')}`" if op else f"action `{_code(r.get('action_id'), 36)}`"
    if r.get("destination"):
        subject += f" → `{_code(r['destination'])}`"
    return subject


def _identity_lines(r: Dict[str, Any]) -> List[str]:
    if not r.get("operation"):
        return [f"- **Action:** `{_code(r.get('pending_id') or r.get('action_id'), 36)}`"]
    lines = [f"- **Operation:** `{_code(str(r['operation']).upper(), 20)}`",
             f"- **Target:** `{_code(r.get('target') or '?')}`"]
    if r.get("destination"):
        lines.append(f"- **Destination:** `{_code(r['destination'])}`")
    return lines


def _policy_lines(r: Dict[str, Any], status: Optional[ExecutionStatus]) -> List[str]:
    lines = []
    if r.get("policy_id"):
        lines.append(f"- **Policy:** `{_code(r['policy_id'], 30)}` — {policy_description(r['policy_id'])}")
    if status == ExecutionStatus.BLOCKED and r.get("reason"):
        lines.append(f"- **Reason:** {sanitize(r['reason'], limit=200)}")
    return lines


def _execution_lines(r: Dict[str, Any], status: Optional[ExecutionStatus]) -> List[str]:
    """What actually happened at the executor and the auditor. Never claims more than the result says."""
    if is_refused(r):
        return ["- **Execution:** none. Nothing was executed."]
    if status == ExecutionStatus.BLOCKED:
        return ["- **Execution:** prevented. Blocked by deterministic policy before execution; nothing was changed."]
    if status == ExecutionStatus.AWAITING_APPROVAL:
        return ["- **Execution:** not started. Nothing runs until an authorized approver decides."]
    if status == ExecutionStatus.REJECTED:
        return ["- **Execution:** none. Rejected by an authorized approver; nothing was executed and the request "
                "is closed."]
    if status == ExecutionStatus.EXPIRED:
        return ["- **Execution:** none. The approval window closed before a decision; nothing was executed. "
                "Ask again for a fresh request."]
    details = _clause(r.get("verification_details") or "no details")
    # VERIFIED and UNVERIFIED only ever follow an execution.
    if r.get("executed") or status in (ExecutionStatus.VERIFIED, ExecutionStatus.UNVERIFIED):
        ran = "- **Execution:** completed"
        if r.get("output") and str(r.get("operation") or "").upper() != "READ":
            ran += f" ({_clause(r['output'], 160)})"
        if status == ExecutionStatus.VERIFIED:
            return [ran, f"- **Verification:** {details}."]
        if status == ExecutionStatus.UNVERIFIED:
            return [ran, f"- **Verification:** not confirmed. It ran, but the outcome could NOT be independently "
                         f"confirmed: {details}."]
        return [ran, f"- **Verification:** failed: {details}. No success is claimed."]
    error = _clause(r.get("error") or "execution or verification failed")
    if r.get("execution_attempted"):
        return [f"- **Execution:** failed: {error}. No success is claimed.", "- **Verification:** not performed"]
    return [f"- **Execution:** not executed: {error}. No success is claimed."]


def _decision_lines(r: Dict[str, Any], compact: bool) -> List[str]:
    """The typed-command fallback for a pending action (a card, when shown, carries the same decision)."""
    pending_id = _code(r.get("pending_id") or r.get("action_id"), 64)
    digest = _code(r.get("action_digest"), 64)
    lead = ("Use the card's buttons, or reply with one line exactly as shown:" if compact
            else "**Decide** by replying with one line exactly as shown:")
    return [lead, f"- Approve: `APPROVE {pending_id} {digest}`", f"- Reject: `REJECT {pending_id} {digest}`"]


def _risk_lines(r: Dict[str, Any]) -> List[str]:
    rl = risk_line(r)
    return [f"- **Risk (advisory):** {rl}"] if rl else []


def _pending_lines(r: Dict[str, Any]) -> List[str]:
    """What approving would do, who may decide and until when (the review card shows the same)."""
    lines = [f"- **If approved:** {effect_text(r)}"]
    if r.get("content_sha256"):
        lines.append(f"- **Content SHA-256:** `{_code(r['content_sha256'], 64)}`")
    lines.append(f"- **Approver:** {approver_text(r)}")
    lines.append(f"- **Expires:** {expiry_text(r.get('expires_at'))}")
    return lines


def _output_lines(r: Dict[str, Any], status: Optional[ExecutionStatus]) -> List[str]:
    output = r.get("output")
    if status == ExecutionStatus.VERIFIED and str(r.get("operation") or "").upper() == "READ" \
            and output is not None and str(output).strip():
        return [f"- **Output:**\n```\n{sanitize_block(output)}\n```"]
    return []


def _footer_lines(r: Dict[str, Any]) -> List[str]:
    lines = [f"- **Trace:** {format_trace_path(stages_from_result(r))}"]
    if r.get("correlation_id"):
        lines.append(f"- **Audit ref:** `{_code(r['correlation_id'], 64)}`")
    return lines


def _body(r: Dict[str, Any], status: Optional[ExecutionStatus], compact: bool, with_identity: bool) -> List[str]:
    lines = _identity_lines(r) if with_identity else []
    lines += _policy_lines(r, status)
    if r.get("decided") and r.get("execution_attempted"):
        lines.append("- **Approval:** approved by an authorized approver")
    lines += _execution_lines(r, status)
    pending = status == ExecutionStatus.AWAITING_APPROVAL
    # A review card repeats risk and the pending details; a result card shows neither.
    if not (compact and pending):
        lines += _risk_lines(r) + (_pending_lines(r) if pending else [])
    lines += _output_lines(r, status)
    if pending:
        lines += [""] + _decision_lines(r, compact) + [""]
    return lines + _footer_lines(r)


def format_result_block(r: Dict[str, Any], idx: int, compact: bool = False, brief: bool = False) -> str:
    """One numbered action within a multi-action report.

    ``brief`` (many actions in one reply) keeps only the policy, what happened and, for a pending
    action, its two commands, so that every action's commands fit in one message.
    """
    status = _status(r.get("status"))
    heading = f"**{idx}. {badge(status or 'UNKNOWN')}** — {_subject(r)}"
    if not brief:
        return "\n".join([heading] + _body(r, status, compact, with_identity=False))
    if r.get("policy_id"):
        heading += f" · `{_code(r['policy_id'], 30)}`"
    if status == ExecutionStatus.AWAITING_APPROVAL:
        return "\n".join([heading] + _decision_lines(r, compact)[1:])
    return "\n".join([heading] + _execution_lines(r, status)[:1])


def _single(r: Dict[str, Any], compact: bool, note: Optional[str] = None) -> List[str]:
    status = _status(r.get("status"))
    title = REFUSED_HEADLINE if is_refused(r) else HEADLINES.get(status, "Result")
    lines = [headline(title), "", f"**Status:** {badge(status or 'UNKNOWN')}", ""]
    if note:
        lines += [note, ""]
    return lines + _body(r, status, compact, with_identity=True)


def _summary(results: List[Dict[str, Any]]) -> str:
    counts: Dict[str, int] = {}
    for r in results:
        status = _status(r.get("status"))
        key = status.value.replace("_", " ").lower() if status else "unknown"
        counts[key] = counts.get(key, 0) + 1
    return " · ".join(f"{n} {key}" for key, n in counts.items())


def format_pipeline_report(user_text: str, results: List[Dict[str, Any]], workspace_root: Any = None,
                           compact: bool = False) -> str:
    """Report for a new request: the outcome of every action it produced (the request is not echoed)."""
    if len(results) == 1:
        return truncate_report("\n".join(_single(results[0], compact)).rstrip())
    brief = len(results) > FULL_BLOCKS_UP_TO
    lines = [headline(f"{len(results)} actions evaluated"), "", f"**Summary:** {_summary(results)}", ""]
    if brief and any(_status(r.get("status")) == ExecutionStatus.AWAITING_APPROVAL for r in results):
        lines += ["Nothing marked AWAITING APPROVAL has run. Approve or reject each one separately, "
                  "with its own line exactly as shown" + (" or with the card's buttons." if compact else "."), ""]
    for idx, r in enumerate(results, 1):
        lines.extend([format_result_block(r, idx, compact, brief), ""])
    return truncate_report("\n".join(lines).rstrip())


def format_decision_report(action_id: str, r: Dict[str, Any], workspace_root: Any = None,
                           compact: bool = False) -> str:
    """Report for an approve/reject decision, including refused decisions."""
    note = None
    if is_refused(r):
        note = f"**Approval refused** for `{_code(action_id, 36)[:8]}`: {sanitize(r.get('error'), limit=400)}"
    return truncate_report("\n".join(_single(r, compact, note)).rstrip())


def format_no_action(user_text: str = "", rename_supported: bool = False) -> str:
    """Reply to a message that named no supported file action. The message itself is not echoed."""
    examples = EXAMPLES + ([RENAME_EXAMPLE] if rename_supported else [])
    operations = "`READ` · `CREATE` · `WRITE` · `DELETE`" + (" · `RENAME`" if rename_supported else "")
    return "\n".join([
        headline("No action taken"),
        "",
        "WARDEN Sentinel checks, runs and verifies file actions in its sandboxed workspace. This message "
        "did not name a supported file action, so nothing was proposed or run.",
        "",
        "Try, for example:",
        *[f"- `{example}`" for example in examples],
        "",
        f"Supported operations: {operations}. Deletes and overwrites wait for an authorized approval; "
        "protected files such as `production.env` are never read or changed.",
    ])


def format_notice(title: str, *lines: str) -> str:
    """A short reply that is not about an action (empty, oversized or unreadable messages)."""
    return "\n".join([headline(title), "", *lines])
