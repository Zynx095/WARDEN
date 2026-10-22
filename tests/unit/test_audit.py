"""Unit tests for audit event logging and independent outcome verification."""

import pytest
from pathlib import Path
from warden.audit.auditor import OutcomeAuditor
from warden.audit.events import AuditLogger
from warden.execution.workspace import Workspace
from warden.models import (
    Action,
    ActionType,
    AuditEvent,
    Decision,
    ExecutionResult,
    ExecutionStatus,
)


@pytest.fixture
def workspace_fixture(tmp_path: Path) -> Workspace:
    ws_dir = tmp_path / "audit_ws"
    ws = Workspace(ws_dir)
    return ws


@pytest.fixture
def auditor(workspace_fixture: Workspace) -> OutcomeAuditor:
    return OutcomeAuditor(workspace_fixture)


def test_audit_logger_records_and_filters():
    logger = AuditLogger()
    event1 = AuditEvent(
        correlation_id="corr-1",
        operation="READ",
        target="file.txt",
        decision=Decision.ALLOW,
        policy_id="WDN-000",
        execution_status=ExecutionStatus.EXECUTED,
    )
    event2 = AuditEvent(
        correlation_id="corr-2",
        operation="DELETE",
        target=".env",
        decision=Decision.BLOCK,
        policy_id="WDN-003",
        execution_status=ExecutionStatus.BLOCKED,
    )

    logger.record(event1)
    logger.record(event2)

    assert len(logger.get_events()) == 2
    assert len(logger.get_events(correlation_id="corr-1")) == 1
    assert len(logger.get_events(status=ExecutionStatus.BLOCKED)) == 1


def test_outcome_verification_create_success(
    auditor: OutcomeAuditor,
    workspace_fixture: Workspace,
):
    action = Action(operation="CREATE", target="new_doc.txt", content="audit verified content")
    # Actually create file on disk to simulate executor result
    workspace_fixture.create_synthetic_file("new_doc.txt", "audit verified content")

    exec_result = ExecutionResult(
        action=action,
        status=ExecutionStatus.EXECUTED,
        success=True,
    )

    verification = auditor.verify_outcome(action, exec_result)
    assert verification.status == ExecutionStatus.VERIFIED
    assert verification.verified is True
    assert verification.observed_state.get("content_matched") is True


def test_outcome_verification_create_content_mismatch_fails(
    auditor: OutcomeAuditor,
    workspace_fixture: Workspace,
):
    action = Action(operation="CREATE", target="new_doc.txt", content="expected content")
    # Simulate attacker or faulty executor writing different content
    workspace_fixture.create_synthetic_file("new_doc.txt", "tampered content")

    exec_result = ExecutionResult(
        action=action,
        status=ExecutionStatus.EXECUTED,
        success=True,
    )

    verification = auditor.verify_outcome(action, exec_result)
    assert verification.status == ExecutionStatus.FAILED
    assert verification.verified is False
    assert "does not match" in verification.details


def test_outcome_verification_delete_success(
    auditor: OutcomeAuditor,
    workspace_fixture: Workspace,
):
    action = Action(operation="DELETE", target="obsolete.log")
    # File does NOT exist on disk
    exec_result = ExecutionResult(
        action=action,
        status=ExecutionStatus.EXECUTED,
        success=True,
    )

    verification = auditor.verify_outcome(action, exec_result)
    assert verification.status == ExecutionStatus.VERIFIED
    assert verification.verified is True


def test_outcome_verification_delete_still_exists_fails(
    auditor: OutcomeAuditor,
    workspace_fixture: Workspace,
):
    action = Action(operation="DELETE", target="surviving.log")
    # File still exists on disk despite executor claiming success
    workspace_fixture.create_synthetic_file("surviving.log", "I survived!")

    exec_result = ExecutionResult(
        action=action,
        status=ExecutionStatus.EXECUTED,
        success=True,
    )

    verification = auditor.verify_outcome(action, exec_result)
    assert verification.status == ExecutionStatus.FAILED
    assert verification.verified is False
    assert "still exists" in verification.details


def test_outcome_verification_rename_success(
    auditor: OutcomeAuditor,
    workspace_fixture: Workspace,
):
    action = Action(operation="RENAME", target="src.txt", destination="dst.txt")
    workspace_fixture.create_synthetic_file("dst.txt", "moved")

    exec_result = ExecutionResult(
        action=action,
        status=ExecutionStatus.EXECUTED,
        success=True,
    )

    verification = auditor.verify_outcome(action, exec_result)
    assert verification.status == ExecutionStatus.VERIFIED
    assert verification.verified is True


def test_outcome_verification_failed_execution_never_verified(
    auditor: OutcomeAuditor,
):
    action = Action(operation="WRITE", target="data.txt", content="payload")
    exec_result = ExecutionResult(
        action=action,
        status=ExecutionStatus.FAILED,
        success=False,
        error="Permission denied.",
    )

    verification = auditor.verify_outcome(action, exec_result)
    assert verification.status == ExecutionStatus.FAILED
    assert verification.verified is False
