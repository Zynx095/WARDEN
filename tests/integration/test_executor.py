"""Integration tests for RestrictedExecutor with workspace containment."""

import pytest
from pathlib import Path
from warden.execution.executor import RestrictedExecutor
from warden.execution.workspace import Workspace
from warden.models import (
    Action,
    ActionType,
    AuthorizationToken,
    ExecutionRequest,
    ExecutionStatus,
)
from warden.security.authorization import AuthorizationManager


@pytest.fixture
def sandbox_workspace(tmp_path: Path) -> Workspace:
    ws_dir = tmp_path / "sandbox_ws"
    ws = Workspace(ws_dir)
    return ws


@pytest.fixture
def auth_mgr() -> AuthorizationManager:
    return AuthorizationManager(secret_key="integration-test-secret-key")


@pytest.fixture
def executor(sandbox_workspace: Workspace, auth_mgr: AuthorizationManager) -> RestrictedExecutor:
    return RestrictedExecutor(sandbox_workspace, auth_manager=auth_mgr)


def test_authorized_create_and_read(
    executor: RestrictedExecutor,
    sandbox_workspace: Workspace,
    auth_mgr: AuthorizationManager,
):
    action_create = Action(operation="CREATE", target="hello.txt", content="Hello, WARDEN!")
    target_path = sandbox_workspace.get_canonical_path("hello.txt")

    token_create = auth_mgr.issue_token(
        action=action_create,
        target_canonical=target_path,
        destination_canonical=None,
        workspace_root=sandbox_workspace.root_path,
        policy_id="WDN-000",
    )

    req_create = ExecutionRequest(action=action_create, authorization=token_create)
    res_create = executor.execute(req_create)

    assert res_create.status == ExecutionStatus.EXECUTED
    assert res_create.success is True
    assert (sandbox_workspace.root_path / "hello.txt").read_text(encoding="utf-8") == "Hello, WARDEN!"

    # Now read it
    action_read = Action(operation="READ", target="hello.txt")
    token_read = auth_mgr.issue_token(
        action=action_read,
        target_canonical=target_path,
        destination_canonical=None,
        workspace_root=sandbox_workspace.root_path,
        policy_id="WDN-000",
    )
    res_read = executor.execute(ExecutionRequest(action=action_read, authorization=token_read))
    assert res_read.status == ExecutionStatus.EXECUTED
    assert res_read.success is True
    assert res_read.output == "Hello, WARDEN!"

    # Now read the workspace root directory
    sandbox_workspace.create_synthetic_file("another.log", "data")
    action_read_dir = Action(operation="READ", target=".")
    token_read_dir = auth_mgr.issue_token(
        action=action_read_dir,
        target_canonical=sandbox_workspace.root_path,
        destination_canonical=None,
        workspace_root=sandbox_workspace.root_path,
        policy_id="WDN-000",
    )
    res_dir = executor.execute(ExecutionRequest(action=action_read_dir, authorization=token_read_dir))
    assert res_dir.status == ExecutionStatus.EXECUTED
    assert res_dir.success is True
    assert "another.log" in res_dir.output
    assert "hello.txt" in res_dir.output


def test_authorized_write_modifies_file(
    executor: RestrictedExecutor,
    sandbox_workspace: Workspace,
    auth_mgr: AuthorizationManager,
):
    sandbox_workspace.create_synthetic_file("data.txt", "initial content")
    target_path = sandbox_workspace.get_canonical_path("data.txt")

    action_write = Action(operation="WRITE", target="data.txt", content="updated content")
    token = auth_mgr.issue_token(
        action=action_write,
        target_canonical=target_path,
        destination_canonical=None,
        workspace_root=sandbox_workspace.root_path,
        policy_id="WDN-000",
    )
    res = executor.execute(ExecutionRequest(action=action_write, authorization=token))
    assert res.status == ExecutionStatus.EXECUTED
    assert res.success is True
    assert (sandbox_workspace.root_path / "data.txt").read_text(encoding="utf-8") == "updated content"


def test_authorized_delete_removes_file(
    executor: RestrictedExecutor,
    sandbox_workspace: Workspace,
    auth_mgr: AuthorizationManager,
):
    sandbox_workspace.create_synthetic_file("temp.log", "debug data")
    target_path = sandbox_workspace.get_canonical_path("temp.log")

    action_del = Action(operation="DELETE", target="temp.log")
    token = auth_mgr.issue_token(
        action=action_del,
        target_canonical=target_path,
        destination_canonical=None,
        workspace_root=sandbox_workspace.root_path,
        policy_id="WDN-004-APPROVED",
    )
    res = executor.execute(ExecutionRequest(action=action_del, authorization=token))
    assert res.status == ExecutionStatus.EXECUTED
    assert res.success is True
    assert not (sandbox_workspace.root_path / "temp.log").exists()


def test_authorized_rename_moves_file(
    executor: RestrictedExecutor,
    sandbox_workspace: Workspace,
    auth_mgr: AuthorizationManager,
):
    sandbox_workspace.create_synthetic_file("old.txt", "move me")
    src_path = sandbox_workspace.get_canonical_path("old.txt")
    dest_path = sandbox_workspace.get_canonical_path("new.txt")

    action_rename = Action(operation="RENAME", target="old.txt", destination="new.txt")
    token = auth_mgr.issue_token(
        action=action_rename,
        target_canonical=src_path,
        destination_canonical=dest_path,
        workspace_root=sandbox_workspace.root_path,
        policy_id="WDN-004-APPROVED",
    )
    res = executor.execute(ExecutionRequest(action=action_rename, authorization=token))
    assert res.status == ExecutionStatus.EXECUTED
    assert res.success is True
    assert not src_path.exists()
    assert dest_path.read_text(encoding="utf-8") == "move me"


def test_missing_authorization_cannot_execute(
    executor: RestrictedExecutor,
    sandbox_workspace: Workspace,
):
    sandbox_workspace.create_synthetic_file("data.txt", "data")
    action = Action(operation="WRITE", target="data.txt", content="hacked")

    res = executor.execute(ExecutionRequest(action=action, authorization=None))
    assert res.status == ExecutionStatus.FAILED
    assert res.success is False
    assert "Authorization rejected" in (res.error or "")
    # Ensure file was not modified
    assert (sandbox_workspace.root_path / "data.txt").read_text(encoding="utf-8") == "data"


def test_tampered_authorization_cannot_execute(
    executor: RestrictedExecutor,
    sandbox_workspace: Workspace,
    auth_mgr: AuthorizationManager,
):
    action = Action(operation="CREATE", target="evil.txt", content="bad")
    target_path = sandbox_workspace.get_canonical_path("evil.txt")
    token = auth_mgr.issue_token(
        action=action,
        target_canonical=target_path,
        destination_canonical=None,
        workspace_root=sandbox_workspace.root_path,
        policy_id="WDN-000",
    )
    tampered_token = token.model_copy(update={"signature": "forged_hex_signature"})

    res = executor.execute(ExecutionRequest(action=action, authorization=tampered_token))
    assert res.status == ExecutionStatus.FAILED
    assert res.success is False
    assert not target_path.exists()


def test_protected_resource_modification_blocked_even_with_fake_token(
    executor: RestrictedExecutor,
    sandbox_workspace: Workspace,
    auth_mgr: AuthorizationManager,
):
    action = Action(operation="DELETE", target=".env")
    target_path = sandbox_workspace.get_canonical_path(".env")
    # Even if an attacker somehow concocted an authorization token
    token = auth_mgr.issue_token(
        action=action,
        target_canonical=target_path,
        destination_canonical=None,
        workspace_root=sandbox_workspace.root_path,
        policy_id="FORGED-POLICY",
    )

    res = executor.execute(ExecutionRequest(action=action, authorization=token))
    assert res.status == ExecutionStatus.FAILED
    assert res.success is False
    assert "protected resource" in (res.error or "").lower()


def test_workspace_escape_rejected_by_executor(
    executor: RestrictedExecutor,
    sandbox_workspace: Workspace,
):
    action = Action(operation="READ", target="../../outside.txt")
    res = executor.execute(ExecutionRequest(action=action, authorization=None))
    assert res.status == ExecutionStatus.FAILED
    assert res.success is False
    assert "validation failed" in (res.error or "").lower()


def test_nonexistent_read_reported_as_failed(
    executor: RestrictedExecutor,
    sandbox_workspace: Workspace,
    auth_mgr: AuthorizationManager,
):
    action = Action(operation="READ", target="ghost_file.txt")
    target_path = sandbox_workspace.get_canonical_path("ghost_file.txt")
    token = auth_mgr.issue_token(
        action=action,
        target_canonical=target_path,
        destination_canonical=None,
        workspace_root=sandbox_workspace.root_path,
        policy_id="WDN-000",
    )
    res = executor.execute(ExecutionRequest(action=action, authorization=token))
    assert res.status == ExecutionStatus.FAILED
    assert res.success is False
    assert "File not found" in (res.error or "")
