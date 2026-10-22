"""Unit tests for cryptographic authorization tokens and approvals."""

import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from warden.models import Action, Decision, PolicyResult
from warden.security.authorization import AuthorizationManager, AuthorizationError


@pytest.fixture
def auth_manager() -> AuthorizationManager:
    return AuthorizationManager(secret_key="test-secret-key-12345")


@pytest.fixture
def workspace_path(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    return ws


def test_issue_and_verify_token_success(auth_manager: AuthorizationManager, workspace_path: Path):
    target = workspace_path / "test.txt"
    action = Action(operation="WRITE", target="test.txt")

    token = auth_manager.issue_token(
        action=action,
        target_canonical=target,
        destination_canonical=None,
        workspace_root=workspace_path,
        policy_id="WDN-000",
    )

    valid, err = auth_manager.verify_token(
        token=token,
        action=action,
        target_canonical=target,
        destination_canonical=None,
        workspace_root=workspace_path,
    )
    assert valid is True
    assert err is None


def test_missing_token_rejected(auth_manager: AuthorizationManager, workspace_path: Path):
    target = workspace_path / "test.txt"
    action = Action(operation="WRITE", target="test.txt")

    valid, err = auth_manager.verify_token(
        token=None,
        action=action,
        target_canonical=target,
        destination_canonical=None,
        workspace_root=workspace_path,
    )
    assert valid is False
    assert "Missing authorization token" in (err or "")


def test_tampered_signature_rejected(auth_manager: AuthorizationManager, workspace_path: Path):
    target = workspace_path / "test.txt"
    action = Action(operation="WRITE", target="test.txt")

    token = auth_manager.issue_token(
        action=action,
        target_canonical=target,
        destination_canonical=None,
        workspace_root=workspace_path,
        policy_id="WDN-000",
    )

    tampered_token = token.model_copy(update={"signature": "tampered_signature_value"})
    valid, err = auth_manager.verify_token(
        token=tampered_token,
        action=action,
        target_canonical=target,
        destination_canonical=None,
        workspace_root=workspace_path,
    )
    assert valid is False
    assert "Invalid authorization signature" in (err or "")


def test_expired_token_rejected(auth_manager: AuthorizationManager, workspace_path: Path):
    target = workspace_path / "test.txt"
    action = Action(operation="WRITE", target="test.txt")

    token = auth_manager.issue_token(
        action=action,
        target_canonical=target,
        destination_canonical=None,
        workspace_root=workspace_path,
        policy_id="WDN-000",
        validity_seconds=-10,  # Already expired
    )

    valid, err = auth_manager.verify_token(
        token=token,
        action=action,
        target_canonical=target,
        destination_canonical=None,
        workspace_root=workspace_path,
    )
    assert valid is False
    assert "expired" in (err or "")


def test_mismatched_target_rejected(auth_manager: AuthorizationManager, workspace_path: Path):
    target1 = workspace_path / "test.txt"
    target2 = workspace_path / "other.txt"
    action = Action(operation="WRITE", target="test.txt")

    token = auth_manager.issue_token(
        action=action,
        target_canonical=target1,
        destination_canonical=None,
        workspace_root=workspace_path,
        policy_id="WDN-000",
    )

    valid, err = auth_manager.verify_token(
        token=token,
        action=action,
        target_canonical=target2,
        destination_canonical=None,
        workspace_root=workspace_path,
    )
    assert valid is False
    assert "target mismatch" in (err or "")


def test_mismatched_operation_rejected(auth_manager: AuthorizationManager, workspace_path: Path):
    target = workspace_path / "test.txt"
    action = Action(operation="READ", target="test.txt")
    other_action = Action(operation="DELETE", target="test.txt", action_id=action.action_id)

    token = auth_manager.issue_token(
        action=action,
        target_canonical=target,
        destination_canonical=None,
        workspace_root=workspace_path,
        policy_id="WDN-000",
    )

    valid, err = auth_manager.verify_token(
        token=token,
        action=other_action,
        target_canonical=target,
        destination_canonical=None,
        workspace_root=workspace_path,
    )
    assert valid is False
    assert "operation mismatch" in (err or "")


def test_pending_approval_workflow(auth_manager: AuthorizationManager, workspace_path: Path):
    target = workspace_path / "critical.log"
    action = Action(operation="DELETE", target="critical.log")
    policy_res = PolicyResult(
        decision=Decision.REQUIRE_APPROVAL,
        policy_id="WDN-004",
        reason="Destructive operation requires approval.",
    )

    action_id = auth_manager.register_pending_approval(action, policy_res)
    pending = auth_manager.get_pending_approval(action_id)
    assert pending is not None
    assert pending.is_approved is False

    # Explicit human approval
    token = auth_manager.approve_pending_action(
        action_id=action_id,
        approver_id="security_officer_alice",
        target_canonical=target,
        destination_canonical=None,
        workspace_root=workspace_path,
    )
    assert token is not None
    assert pending.is_approved is True
    assert pending.approved_by == "security_officer_alice"

    # Cannot approve twice
    with pytest.raises(AuthorizationError):
        auth_manager.approve_pending_action(
            action_id=action_id,
            approver_id="security_officer_bob",
            target_canonical=target,
            destination_canonical=None,
            workspace_root=workspace_path,
        )
