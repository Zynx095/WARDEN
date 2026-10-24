"""Authorization tokens are bound to the exact action and to the observed target state."""

import pytest

from warden.execution.executor import RestrictedExecutor
from warden.execution.workspace import Workspace
from warden.models import Action, ExecutionRequest
from warden.security.authorization import AuthorizationManager
from warden.security.digest import capture_target_state, compute_state_digest


@pytest.fixture
def ws(tmp_path):
    return Workspace(tmp_path / "ws")


@pytest.fixture
def auth():
    return AuthorizationManager(secret_key="test-secret-key-12345")


def _state(path):
    return compute_state_digest(capture_target_state(path))


def test_token_rejected_when_content_is_swapped_under_same_action_id(ws, auth):
    approved = Action(operation="WRITE", target="note.txt", content="harmless")
    target = ws.root_path / "note.txt"
    token = auth.issue_token(approved, target, None, ws.root_path, "WDN-000")

    swapped = Action(operation="WRITE", target="note.txt", content="evil payload", action_id=approved.action_id)
    ok, err = auth.verify_token(token, swapped, target, None, ws.root_path)

    assert ok is False
    assert "digest" in err


def test_executor_will_not_write_swapped_content(ws, auth):
    approved = Action(operation="WRITE", target="note.txt", content="harmless")
    target = ws.root_path / "note.txt"
    token = auth.issue_token(approved, target, None, ws.root_path, "WDN-000")
    swapped = Action(operation="WRITE", target="note.txt", content="evil payload", action_id=approved.action_id)

    result = RestrictedExecutor(ws, auth).execute(ExecutionRequest(action=swapped, authorization=token))

    assert result.success is False
    assert not target.exists()


def test_executor_rejects_when_target_changed_after_authorization(ws, auth):
    ws.create_synthetic_file("cache.tmp", "original")
    target = ws.root_path / "cache.tmp"
    action = Action(operation="DELETE", target="cache.tmp")
    token = auth.issue_token(action, target, None, ws.root_path, "WDN-004-APPROVED", state_digest=_state(target))

    target.write_text("someone replaced this file")
    result = RestrictedExecutor(ws, auth).execute(ExecutionRequest(action=action, authorization=token))

    assert result.success is False
    assert "state changed" in result.error
    assert target.exists()


def test_executor_accepts_unchanged_state(ws, auth):
    ws.create_synthetic_file("cache.tmp", "original")
    target = ws.root_path / "cache.tmp"
    action = Action(operation="DELETE", target="cache.tmp")
    token = auth.issue_token(action, target, None, ws.root_path, "WDN-004-APPROVED", state_digest=_state(target))

    result = RestrictedExecutor(ws, auth).execute(ExecutionRequest(action=action, authorization=token))

    assert result.success is True
    assert not target.exists()


def test_tampering_with_the_digest_invalidates_the_signature(ws, auth):
    action = Action(operation="WRITE", target="note.txt", content="a")
    target = ws.root_path / "note.txt"
    token = auth.issue_token(action, target, None, ws.root_path, "WDN-000")
    forged = token.model_copy(update={"state_digest": "0" * 64})

    ok, _ = auth.verify_token(forged, action, target, None, ws.root_path, current_state_digest="0" * 64)

    assert ok is False


def test_token_without_digest_is_rejected(ws, auth):
    action = Action(operation="WRITE", target="note.txt", content="a")
    target = ws.root_path / "note.txt"
    token = auth.issue_token(action, target, None, ws.root_path, "WDN-000")
    stripped = token.model_copy(update={"action_digest": None})

    ok, _ = auth.verify_token(stripped, action, target, None, ws.root_path)

    assert ok is False
