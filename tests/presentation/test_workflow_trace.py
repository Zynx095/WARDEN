"""warden.presentation.workflow_trace: stages come only from real result fields."""

from warden.models import ExecutionStatus
from warden.presentation.workflow_trace import format_trace_line, format_workflow_trace, stages_from_result

RISK = {"status": "ASSESSED", "source": "remote", "risk_level": "HIGH"}


def states(result):
    return {k: v["state"] for k, v in stages_from_result(result).items()}


def test_blocked_action_never_reaches_approval_executor_or_auditor():
    s = states({"status": ExecutionStatus.BLOCKED, "policy_id": "WDN-003", "risk": RISK})
    assert s == {"intent": "DONE", "risk": "DONE", "policy": "BLOCKED", "approval": "NOT_REACHED",
                 "executor": "NOT_REACHED", "auditor": "NOT_REACHED"}


def test_pending_action_is_pending_at_approval():
    s = states({"status": ExecutionStatus.AWAITING_APPROVAL, "policy_id": "WDN-004"})
    assert s["approval"] == "PENDING" and s["executor"] == "NOT_REACHED" and s["risk"] == "SKIPPED"


def test_allowed_and_verified_with_remote_attestation():
    r = {"status": ExecutionStatus.VERIFIED, "policy_id": "WDN-000", "execution_attempted": True, "executed": True,
         "observed_state": {"remote_auditor": {"valid": True}}, "risk": RISK}
    stages = stages_from_result(r)
    assert stages["approval"]["state"] == "SKIPPED" and stages["auditor"]["state"] == "VERIFIED"
    assert "remote attestation" in stages["auditor"]["note"]


def test_approved_then_unverified():
    r = {"status": ExecutionStatus.UNVERIFIED, "decided": True, "execution_attempted": True, "executed": True,
         "verification_details": "Remote audit unavailable (timeout)"}
    s = states(r)
    assert s["approval"] == "DONE" and s["executor"] == "DONE" and s["auditor"] == "UNVERIFIED"


def test_executor_failure_is_failed_not_skipped():
    r = {"status": ExecutionStatus.FAILED, "decided": True, "execution_attempted": True, "executed": False,
         "error": "disk full"}
    s = states(r)
    assert s["executor"] == "FAILED" and s["auditor"] == "NOT_REACHED"


def test_refused_decision_rejected_and_expired():
    assert states({"status": ExecutionStatus.FAILED, "decided": True, "error": "digest"})["approval"] == "FAILED"
    assert states({"status": ExecutionStatus.REJECTED, "decided": True})["approval"] == "REJECTED"
    assert states({"status": ExecutionStatus.EXPIRED, "decided": True})["approval"] == "EXPIRED"


def test_risk_timeout_and_unavailable_are_distinguished():
    assert states({"status": "BLOCKED", "risk": {"status": "UNAVAILABLE", "summary": "unavailable (timeout)"}})["risk"] \
        == "TIMED_OUT"
    assert states({"status": "BLOCKED", "risk": {"status": "UNAVAILABLE", "summary": "malformed"}})["risk"] \
        == "UNAVAILABLE"


def test_renderers_cover_every_stage_in_order():
    stages = stages_from_result({"status": ExecutionStatus.AWAITING_APPROVAL})
    line = format_trace_line(stages)
    assert line.index("Intent") < line.index("Risk Analyst") < line.index("Policy Guard") < line.index("Approval") \
        < line.index("Executor") < line.index("Auditor")
    tree = format_workflow_trace(stages, "DELETE cache.tmp")
    assert tree.count("\n") == 7 and "(pending)" in tree
