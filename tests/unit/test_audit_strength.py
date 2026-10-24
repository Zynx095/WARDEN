"""The auditor judges actual state against pre-execution evidence and cannot be fooled by claims."""

import pytest

from warden.agents.warden_agent import WardenAgent
from warden.audit.auditor import OutcomeAuditor
from warden.execution.workspace import Workspace
from warden.models import Action, ExecutionResult, ExecutionStatus


@pytest.fixture
def ws(tmp_path) -> Workspace:
    w = Workspace(tmp_path / "ws")
    w.create_synthetic_file("target.tmp", "target data")
    w.create_synthetic_file("bystander.txt", "keep me")
    return w


@pytest.fixture
def auditor(ws) -> OutcomeAuditor:
    return OutcomeAuditor(ws)


def claimed_success(action):
    return ExecutionResult(action=action, status=ExecutionStatus.EXECUTED, success=True)


@pytest.mark.parametrize("action", [
    Action(operation="DELETE", target="target.tmp"),
    Action(operation="CREATE", target="new.txt", content="x"),
    Action(operation="WRITE", target="target.tmp", content="x"),
    Action(operation="RENAME", target="target.tmp", destination="renamed.tmp"),
])
def test_mutation_without_pre_state_is_never_verified(auditor, ws, action):
    if action.operation == "CREATE":
        ws.create_synthetic_file("new.txt", "x")
    result = auditor.verify_outcome(action, claimed_success(action))
    assert result.verified is False and result.status == ExecutionStatus.FAILED
    assert "pre-execution" in result.details


def test_delete_of_file_that_never_existed_is_not_verified(auditor):
    action = Action(operation="DELETE", target="ghost.tmp")
    pre = auditor.capture_pre_state(action)
    result = auditor.verify_outcome(action, claimed_success(action), pre)
    assert result.verified is False
    assert "did not exist before" in result.details


def test_delete_that_also_removes_another_file_is_failed(auditor, ws):
    action = Action(operation="DELETE", target="target.tmp")
    pre = auditor.capture_pre_state(action)
    (ws.root_path / "target.tmp").unlink()
    (ws.root_path / "bystander.txt").unlink()
    result = auditor.verify_outcome(action, claimed_success(action), pre)
    assert result.verified is False
    assert "bystander.txt removed" in result.details


def test_delete_that_modifies_a_sibling_is_failed(auditor, ws):
    action = Action(operation="DELETE", target="target.tmp")
    pre = auditor.capture_pre_state(action)
    (ws.root_path / "target.tmp").unlink()
    (ws.root_path / "bystander.txt").write_text("tampered, and longer")
    result = auditor.verify_outcome(action, claimed_success(action), pre)
    assert result.verified is False
    assert "bystander.txt modified" in result.details


def test_write_that_also_drops_an_extra_file_is_failed(auditor, ws):
    action = Action(operation="WRITE", target="target.tmp", content="new")
    pre = auditor.capture_pre_state(action)
    (ws.root_path / "target.tmp").write_bytes(b"new")
    (ws.root_path / "dropped.bin").write_text("payload")
    result = auditor.verify_outcome(action, claimed_success(action), pre)
    assert result.verified is False
    assert "dropped.bin added" in result.details


def test_write_with_wrong_content_is_failed_and_exact_content_verified(auditor, ws):
    action = Action(operation="WRITE", target="target.tmp", content="line1\nline2")
    pre = auditor.capture_pre_state(action)
    (ws.root_path / "target.tmp").write_bytes(b"line1\nline2 plus extra")
    assert auditor.verify_outcome(action, claimed_success(action), pre).verified is False

    (ws.root_path / "target.tmp").write_bytes(b"line1\nline2")
    ok = auditor.verify_outcome(action, claimed_success(action), pre)
    assert ok.verified is True and ok.observed_state["content_matched"] is True


def test_create_over_a_file_that_already_existed_is_failed(auditor, ws):
    action = Action(operation="CREATE", target="target.tmp", content="target data")
    pre = auditor.capture_pre_state(action)
    result = auditor.verify_outcome(action, claimed_success(action), pre)
    assert result.verified is False
    assert "already existed" in result.details


def test_rename_that_alters_content_is_failed(auditor, ws):
    action = Action(operation="RENAME", target="target.tmp", destination="renamed.tmp")
    pre = auditor.capture_pre_state(action)
    (ws.root_path / "target.tmp").unlink()
    (ws.root_path / "renamed.tmp").write_text("not the original")
    result = auditor.verify_outcome(action, claimed_success(action), pre)
    assert result.verified is False
    assert "differs from the original" in result.details


def test_clean_rename_is_verified(auditor, ws):
    action = Action(operation="RENAME", target="target.tmp", destination="renamed.tmp")
    pre = auditor.capture_pre_state(action)
    (ws.root_path / "target.tmp").rename(ws.root_path / "renamed.tmp")
    assert auditor.verify_outcome(action, claimed_success(action), pre).verified is True


def test_rogue_executor_collateral_damage_is_not_reported_as_success(ws, monkeypatch):
    """End to end: the executor says success, but it also deleted another file."""
    warden = WardenAgent(workspace=ws)
    res = warden.handle_action_request(Action(operation="DELETE", target="target.tmp"))
    original = warden.executor.execute

    def rogue(request):
        outcome = original(request)
        (ws.root_path / "bystander.txt").unlink()
        return outcome

    monkeypatch.setattr(warden.executor, "execute", rogue)
    result = warden.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])

    assert result["executed"] is True
    assert result["verified"] is False
    assert result["status"] == ExecutionStatus.FAILED
    assert "bystander.txt removed" in result["verification_details"]


def test_multiline_write_is_byte_exact_and_verified_end_to_end(ws):
    warden = WardenAgent(workspace=ws)
    content = "alpha\nbeta\ngamma\n"
    pending = warden.handle_action_request(Action(operation="WRITE", target="target.tmp", content=content))
    # target.tmp already exists, so the overwrite needs approval (WDN-005) before it runs.
    assert pending["status"] == ExecutionStatus.AWAITING_APPROVAL and pending["policy_id"] == "WDN-005"
    result = warden.approve_and_execute(pending["pending_id"], "alice", expected_digest=pending["action_digest"])

    assert result["status"] == ExecutionStatus.VERIFIED
    assert (ws.root_path / "target.tmp").read_bytes() == content.encode("utf-8")
