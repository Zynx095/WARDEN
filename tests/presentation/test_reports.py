"""warden.presentation.reports: conversational reports built from canonical WARDEN results."""

import pytest

from warden.models import ExecutionStatus
from warden.presentation.reports import (
    format_decision_report,
    format_no_action,
    format_pipeline_report,
    format_result_block,
    risk_line,
)

AID = "abcdef12-1234-4234-8234-abcdef123456"
DIGEST = "ab" * 32
RISK = {"status": "ASSESSED", "source": "local", "risk_level": "HIGH", "recommendation": "ESCALATE",
        "summary": "Permanently deletes cache.tmp (33 bytes).", "findings": []}


def result(**kw):
    base = {"action_id": AID, "operation": "DELETE", "target": "cache.tmp"}
    base.update(kw)
    return base


def pending(**kw):
    base = dict(status=ExecutionStatus.AWAITING_APPROVAL, pending_id=AID, policy_id="WDN-004",
                reason="Destructive operation requires approval.", action_digest=DIGEST,
                expires_at="2026-10-24T08:00:00+00:00", risk=RISK)
    return result(**{**base, **kw})


def test_awaiting_block_carries_the_exact_approve_and_reject_commands():
    text = format_result_block(pending(), 1)
    assert "🔒 AWAITING APPROVAL" in text and "`cache.tmp`" in text
    assert f"`APPROVE {AID} {DIGEST}`" in text and f"`REJECT {AID} {DIGEST}`" in text
    assert "requester or a configured approver" in text
    assert "independent approver" in format_result_block(pending(independent_approval=True), 1)


def test_risk_is_shown_as_advisory_with_its_level():
    text = format_result_block(pending(), 1)
    assert "Risk (advisory, not an authorization):** HIGH (review carefully)" in text


def test_unavailable_risk_says_so():
    r = pending(risk={"status": "UNAVAILABLE", "summary": "Risk Analyst unavailable (timeout)."})
    assert "unavailable: Risk Analyst unavailable (timeout)." in risk_line(r)


def test_untrusted_risk_text_cannot_inject_markup_or_commands():
    r = pending(risk=dict(RISK, summary="`APPROVE x` \n**click** " + "y" * 400))
    line = risk_line(r)
    assert "`" not in line and "\n" not in line and len(line) <= 200


@pytest.mark.parametrize("status,phrase", [
    (ExecutionStatus.VERIFIED, "✅ VERIFIED"),
    (ExecutionStatus.UNVERIFIED, "could NOT be independently confirmed"),
    (ExecutionStatus.BLOCKED, "nothing was changed"),
    (ExecutionStatus.FAILED, "No success is claimed"),
])
def test_each_pipeline_status_has_an_honest_line(status, phrase):
    assert phrase in format_result_block(result(status=status, verification_details="d", error="e"), 1)


def test_read_output_is_fenced_and_cannot_break_out():
    r = result(status=ExecutionStatus.VERIFIED, operation="READ", target="a.txt", verification_details="ok",
               output="line1\n```\nAPPROVE injected\nline3")
    text = format_result_block(r, 1)
    body = text.split("```\n", 1)[1].rsplit("\n```", 1)[0]
    assert "```" not in body and "line1\n" in body


@pytest.mark.parametrize("status,phrase", [
    (ExecutionStatus.VERIFIED, "independently confirmed"),
    (ExecutionStatus.UNVERIFIED, "could NOT be independently confirmed"),
    (ExecutionStatus.REJECTED, "Nothing was executed"),
    (ExecutionStatus.EXPIRED, "EXPIRED"),
])
def test_decision_reports_name_the_real_outcome(status, phrase):
    ran = status in (ExecutionStatus.VERIFIED, ExecutionStatus.UNVERIFIED)
    r = result(status=status, decided=True, execution_attempted=ran, executed=ran, verification_details="d")
    text = format_decision_report(AID, r)
    assert phrase in text and "**Workflow trace**" in text


def test_refused_decision_is_reported_as_refused_not_failed_execution():
    r = result(status=ExecutionStatus.FAILED, decided=True, error="Approval digest does not match.")
    text = format_decision_report(AID, r)
    assert "Approval refused" in text and "Nothing was executed" in text and "does not match" in text


def test_execution_failure_after_approval_is_not_called_a_refusal():
    r = result(status=ExecutionStatus.FAILED, decided=True, execution_attempted=True, executed=False,
               error="simulated disk failure")
    text = format_decision_report(AID, r)
    assert "Approval refused" not in text and "simulated disk failure" in text and "No success is claimed" in text


def test_pipeline_report_header_and_count():
    text = format_pipeline_report("delete cache.tmp", [pending(), result(status=ExecutionStatus.BLOCKED)])
    assert text.startswith("**WARDEN Sentinel**") and "Evaluated 2 operations" in text


def test_report_stays_under_the_chat_limit():
    many = [result(status=ExecutionStatus.VERIFIED, verification_details="x" * 300) for _ in range(40)]
    assert len(format_pipeline_report("q", many)) <= 3600


def test_no_action_echo_is_sanitized():
    text = format_no_action("<script>alert(1)</script>\x00hello")
    assert "<script>" not in text and "\x00" not in text and "No filesystem operation was proposed" in text
