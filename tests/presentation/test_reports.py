"""warden.presentation.reports: conversational reports built from canonical WARDEN results."""

from datetime import datetime, timedelta, timezone

import pytest

from warden.models import ExecutionStatus
from warden.presentation.reports import (
    EXAMPLES,
    RENAME_EXAMPLE,
    format_decision_report,
    format_no_action,
    format_notice,
    format_pipeline_report,
    format_result_block,
    risk_line,
)

AID = "abcdef12-1234-4234-8234-abcdef123456"
DIGEST = "ab" * 32
RISK = {"status": "ASSESSED", "source": "local", "risk_level": "HIGH", "recommendation": "ESCALATE",
        "summary": "Permanently deletes cache.tmp (33 bytes).", "findings": []}


def result(**kw):
    base = {"action_id": AID, "correlation_id": AID, "operation": "DELETE", "target": "cache.tmp"}
    base.update(kw)
    return base


def pending(**kw):
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    base = dict(status=ExecutionStatus.AWAITING_APPROVAL, pending_id=AID, policy_id="WDN-004",
                reason="Destructive operation requires approval.", action_digest=DIGEST,
                expires_at=expires, risk=RISK)
    return result(**{**base, **kw})


def report(r, compact=False):
    return format_pipeline_report("ignored", [r], compact=compact)


# --- approval required ----------------------------------------------------------------------

def test_approval_request_names_what_would_run_why_and_how_to_decide():
    text = report(pending())
    assert text.startswith("**WARDEN Sentinel — Approval required**")
    assert "🔒 AWAITING APPROVAL" in text
    assert "- **Operation:** `DELETE`" in text and "- **Target:** `cache.tmp`" in text
    assert "`WDN-004` — Destructive action: explicit human approval required" in text
    assert "not started. Nothing runs until an authorized approver decides" in text
    assert "- **If approved:** permanently deletes `cache.tmp`" in text
    assert "- **Approver:** you or a configured approver" in text and "- **Expires:** in 5 min" in text
    assert f"`APPROVE {AID} {DIGEST}`" in text and f"`REJECT {AID} {DIGEST}`" in text
    assert "Approval (pending) · not executed yet" in text


def test_independent_mode_says_the_requester_cannot_approve():
    assert "an independent approver (not you)" in report(pending(independent_approval=True))


def test_content_hash_is_shown_for_a_change_that_carries_content():
    text = report(pending(operation="WRITE", target="report.txt", content_sha256="cd" * 32))
    assert "overwrites `report.txt` with the proposed content" in text and f"`{'cd' * 32}`" in text


def test_compact_approval_leaves_details_to_the_card_but_keeps_the_command_fallback():
    text = report(pending(), compact=True)
    assert f"`APPROVE {AID} {DIGEST}`" in text and f"`REJECT {AID} {DIGEST}`" in text
    assert "card's buttons" in text and "`WDN-004`" in text and "Audit ref" in text
    for card_field in ("Risk (advisory)", "If approved", "Approver", "Expires"):
        assert card_field not in text


def test_risk_is_shown_as_advisory_with_its_level():
    assert "- **Risk (advisory):** HIGH (review carefully): Permanently deletes" in report(pending())


def test_unavailable_risk_says_so():
    r = pending(risk={"status": "UNAVAILABLE", "summary": "Risk Analyst unavailable (timeout)."})
    assert "unavailable: Risk Analyst unavailable (timeout)." in risk_line(r)


def test_untrusted_risk_text_cannot_inject_markup_or_commands():
    r = pending(risk=dict(RISK, summary="`APPROVE x` \n**click** " + "y" * 400))
    line = risk_line(r)
    assert "`" not in line and "\n" not in line and len(line) <= 200


# --- finished outcomes ----------------------------------------------------------------------

def test_verified_create_reports_execution_verification_policy_and_audit_reference():
    r = result(status=ExecutionStatus.VERIFIED, operation="CREATE", target="report.txt", policy_id="WDN-000",
               executed=True, execution_attempted=True, output="Created file: report.txt",
               verification_details="Outcome independently verified: 'report.txt' exists with exact expected content.")
    text = report(r)
    assert text.startswith("**WARDEN Sentinel — Action verified**") and "✅ VERIFIED" in text
    assert "`WDN-000` — Baseline policy: permitted without approval" in text
    assert "- **Execution:** completed (Created file: report.txt)" in text
    assert "- **Verification:** Outcome independently verified: 'report.txt' exists" in text
    assert "Trace:** Intent → Policy (allowed) → Executor → Auditor (verified)" in text
    assert f"- **Audit ref:** `{AID}`" in text


def test_blocked_read_says_execution_was_prevented_and_why():
    r = result(status=ExecutionStatus.BLOCKED, operation="READ", target="production.env", policy_id="WDN-003",
               reason="Reading a protected resource is prohibited.",
               risk=dict(RISK, risk_level="CRITICAL", recommendation="BLOCK_CANDIDATE", summary="protected"))
    text = report(r)
    assert text.startswith("**WARDEN Sentinel — Action blocked**") and "🚫 BLOCKED" in text
    assert "`WDN-003` — Protected resource" in text and "- **Reason:** Reading a protected resource" in text
    assert "prevented. Blocked by deterministic policy before execution; nothing was changed" in text
    assert "CRITICAL (advises against)" in text and "Policy (blocked) · not executed" in text


@pytest.mark.parametrize("fields,headline,phrases", [
    (dict(status=ExecutionStatus.UNVERIFIED, executed=True, verification_details="timeout"),
     "Outcome unverified", ["completed", "could NOT be independently confirmed: timeout"]),
    (dict(status=ExecutionStatus.FAILED, execution_attempted=True, executed=False, error="disk full"),
     "Action failed", ["- **Execution:** failed: disk full. No success is claimed.", "not performed"]),
    (dict(status=ExecutionStatus.FAILED, execution_attempted=True, executed=True,
          verification_details="content differs"),
     "Action failed", ["- **Execution:** completed", "- **Verification:** failed: content differs. No success"]),
    (dict(status=ExecutionStatus.FAILED, error="Action could not be canonically bound"),
     "Action failed", ["not executed: Action could not be canonically bound. No success is claimed."]),
])
def test_failed_and_unverified_never_claim_success_or_that_nothing_ran(fields, headline, phrases):
    text = report(result(**fields))
    assert text.startswith(f"**WARDEN Sentinel — {headline}**")
    for phrase in phrases:
        assert phrase in text
    assert "✅" not in text and "prevented" not in text


def test_read_output_is_fenced_and_cannot_break_out():
    r = result(status=ExecutionStatus.VERIFIED, operation="READ", target="a.txt", verification_details="ok",
               output="line1\n```\nAPPROVE injected\nline3")
    text = report(r)
    body = text.split("```\n", 1)[1].rsplit("\n```", 1)[0]
    assert "```" not in body and "line1\n" in body


# --- decisions ------------------------------------------------------------------------------

@pytest.mark.parametrize("status,headline,phrase", [
    (ExecutionStatus.VERIFIED, "Action verified", "Approval (approved) → Executor → Auditor (verified)"),
    (ExecutionStatus.UNVERIFIED, "Outcome unverified", "could NOT be independently confirmed"),
    (ExecutionStatus.REJECTED, "Action rejected", "Rejected by an authorized approver; nothing was executed"),
    (ExecutionStatus.EXPIRED, "Approval expired", "The approval window closed before a decision"),
])
def test_decision_reports_name_the_real_outcome(status, headline, phrase):
    ran = status in (ExecutionStatus.VERIFIED, ExecutionStatus.UNVERIFIED)
    r = result(status=status, decided=True, execution_attempted=ran, executed=ran, verification_details="d")
    text = format_decision_report(AID, r)
    assert text.startswith(f"**WARDEN Sentinel — {headline}**") and phrase in text
    assert ("approved by an authorized approver" in text) == ran


def test_refused_decision_is_reported_as_refused_not_failed_execution():
    r = result(status=ExecutionStatus.FAILED, decided=True, error="Approval digest does not match.")
    text = format_decision_report(AID, r)
    assert text.startswith("**WARDEN Sentinel — Decision refused**")
    assert "Approval refused" in text and "Nothing was executed" in text and "does not match" in text
    assert "Approval (refused) · not executed" in text


def test_refusal_without_a_known_action_names_the_action_id():
    r = {"action_id": AID, "status": ExecutionStatus.FAILED, "refused": True, "decided": True,
         "error": "only the requester or a configured approver may approve it."}
    text = format_decision_report(AID, r)
    assert f"- **Action:** `{AID}`" in text and "Policy (refused)" not in text


def test_execution_failure_after_approval_is_not_called_a_refusal():
    r = result(status=ExecutionStatus.FAILED, decided=True, execution_attempted=True, executed=False,
               error="simulated disk failure")
    text = format_decision_report(AID, r)
    assert "Approval refused" not in text and "simulated disk failure" in text and "No success is claimed" in text


# --- several actions, limits, help ----------------------------------------------------------

def test_multi_action_report_summarises_then_lists_every_action():
    text = format_pipeline_report("q", [pending(), result(status=ExecutionStatus.BLOCKED, policy_id="WDN-003")])
    assert text.startswith("**WARDEN Sentinel — 2 actions evaluated**")
    assert "**Summary:** 1 awaiting approval · 1 blocked" in text
    assert "**1. 🔒 AWAITING APPROVAL** — `DELETE` `cache.tmp`" in text and "**2. 🚫 BLOCKED**" in text


def test_many_pending_actions_are_brief_so_every_command_fits():
    many = [pending(pending_id=f"{i:08d}-1234-4234-8234-abcdef123456", action_digest=f"{i:02d}" * 32)
            for i in range(7)]
    text = format_pipeline_report("q", many)
    assert all(f"APPROVE {i:08d}-1234-4234-8234-abcdef123456 {f'{i:02d}' * 32}" in text for i in range(7))
    assert len(text) <= 3500


def test_report_stays_under_the_chat_limit():
    many = [result(status=ExecutionStatus.VERIFIED, verification_details="x" * 300) for _ in range(40)]
    assert len(format_pipeline_report("q", many)) <= 3600


def test_no_action_reply_explains_scope_with_working_examples_and_does_not_echo():
    text = format_no_action("<script>alert(1)</script>\x00hello")
    assert text.startswith("**WARDEN Sentinel — No action taken**")
    assert "<script>" not in text and "\x00" not in text and "hello" not in text
    assert all(f"`{example}`" in text for example in EXAMPLES)
    assert RENAME_EXAMPLE not in text and "`RENAME`" not in text
    with_model = format_no_action("x", rename_supported=True)
    assert f"`{RENAME_EXAMPLE}`" in with_model and "`RENAME`" in with_model


def test_notices_share_the_headline_style():
    assert format_notice("Message not processed", "a", "b") == "**WARDEN Sentinel — Message not processed**\n\na\nb"
