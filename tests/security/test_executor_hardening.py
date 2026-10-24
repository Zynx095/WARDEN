"""Restricted executor: revalidation right before mutation, no silent replacement, atomic writes, symlinks."""

import os

import pytest

from warden.agents.warden_agent import WardenAgent
from warden.execution.workspace import Workspace
from warden.models import Action, ExecutionRequest, ExecutionStatus


@pytest.fixture
def ws(tmp_path):
    w = Workspace(tmp_path / "ws")
    w.create_synthetic_file("a.txt", "alpha")
    w.create_synthetic_file("b.txt", "beta")
    (tmp_path / "outside.txt").write_text("outside")
    return w


def token_for(warden, action):
    b = warden._bind(action)
    return warden.auth_manager.issue_token(action, b.target_path, b.destination_path, warden.workspace.root_path,
                                           "TEST", state_digest=b.state_digest)


def symlink_or_skip(src, dst):
    try:
        os.symlink(src, dst)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are not available here")


def test_rename_never_replaces_an_existing_destination_even_with_a_valid_token(ws):
    w = WardenAgent(workspace=ws)
    action = Action(operation="RENAME", target="a.txt", destination="c.txt")
    token = token_for(w, action)
    ws.create_synthetic_file("c.txt", "appeared later")  # destination appears after authorization
    res = w.executor.execute(ExecutionRequest(action=action, authorization=token))
    assert not res.success and (ws.root_path / "c.txt").read_text() == "appeared later"
    assert (ws.root_path / "a.txt").read_text() == "alpha"


def test_executor_itself_refuses_a_rename_onto_an_existing_file(ws):
    # Token bound to the current state, which already includes the existing destination.
    w = WardenAgent(workspace=ws)
    action = Action(operation="RENAME", target="a.txt", destination="b.txt")
    res = w.executor.execute(ExecutionRequest(action=action, authorization=token_for(w, action)))
    assert not res.success and "already exists" in res.error
    assert (ws.root_path / "b.txt").read_text() == "beta" and (ws.root_path / "a.txt").is_file()


def test_create_fails_if_the_file_appears_after_authorization(ws):
    w = WardenAgent(workspace=ws)
    action = Action(operation="CREATE", target="new.txt", content="mine")
    token = token_for(w, action)
    ws.create_synthetic_file("new.txt", "someone else's")
    res = w.executor.execute(ExecutionRequest(action=action, authorization=token))
    assert not res.success and (ws.root_path / "new.txt").read_text() == "someone else's"


def test_write_is_atomic_and_leaves_no_temporary_files(ws):
    w = WardenAgent(workspace=ws)
    action = Action(operation="WRITE", target="a.txt", content="replaced")
    res = w.executor.execute(ExecutionRequest(action=action, authorization=token_for(w, action)))
    assert res.success and (ws.root_path / "a.txt").read_text() == "replaced"
    assert sorted(p.name for p in ws.root_path.iterdir()) == ["a.txt", "b.txt"]


def test_failed_write_keeps_the_original_content(ws, monkeypatch):
    w = WardenAgent(workspace=ws)
    action = Action(operation="WRITE", target="a.txt", content="replaced")
    token = token_for(w, action)
    monkeypatch.setattr(os, "replace", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    res = w.executor.execute(ExecutionRequest(action=action, authorization=token))
    assert not res.success and res.status == ExecutionStatus.FAILED
    assert (ws.root_path / "a.txt").read_text() == "alpha"
    assert sorted(p.name for p in ws.root_path.iterdir()) == ["a.txt", "b.txt"]


def test_symlink_escaping_the_workspace_is_blocked(ws, tmp_path):
    symlink_or_skip(tmp_path / "outside.txt", ws.root_path / "link.txt")
    w = WardenAgent(workspace=ws)
    for op in ("READ", "WRITE", "DELETE"):
        res = w.handle_action_request(Action(operation=op, target="link.txt", content="x"))
        assert res["status"] == ExecutionStatus.BLOCKED, op
    assert (tmp_path / "outside.txt").read_text() == "outside"


def test_target_swapped_for_a_symlink_while_pending_is_never_followed(ws, tmp_path):
    w = WardenAgent(workspace=ws)
    res = w.handle_action_request(Action(operation="DELETE", target="a.txt"))
    os.remove(ws.root_path / "a.txt")
    symlink_or_skip(ws.root_path / "b.txt", ws.root_path / "a.txt")  # now points at another file
    out = w.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])
    assert out["status"] != ExecutionStatus.VERIFIED and (ws.root_path / "b.txt").read_text() == "beta"


@pytest.mark.parametrize("target", ["../outside.txt", "..\\outside.txt", "sub/../../outside.txt",
                                    "C:/Windows/win.ini", "/etc/passwd", "a.txt\x00.png"])
def test_traversal_and_absolute_targets_are_blocked(ws, tmp_path, target):
    res = WardenAgent(workspace=ws).handle_action_request(Action(operation="DELETE", target=target))
    assert res["status"] in (ExecutionStatus.BLOCKED, ExecutionStatus.FAILED)
    assert (tmp_path / "outside.txt").read_text() == "outside"
