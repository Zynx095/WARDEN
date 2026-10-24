"""Unit tests for the enhanced deterministic PolicyEngine."""

import pytest
from pathlib import Path
from warden.models import Action, ActionType, Decision
from warden.security.policy import PolicyEngine


@pytest.fixture
def workspace_path(tmp_path: Path) -> Path:
    ws = tmp_path / "sandbox"
    ws.mkdir()
    return ws


@pytest.fixture
def policy_engine(workspace_path: Path) -> PolicyEngine:
    return PolicyEngine(workspace_root=workspace_path)


def test_safe_read_operation(policy_engine: PolicyEngine):
    action = Action(operation="READ", target="docs/readme.txt")
    res = policy_engine.evaluate(action)
    assert res.decision == Decision.ALLOW
    assert res.policy_id == "WDN-000"


def test_safe_create_operation(policy_engine: PolicyEngine):
    action = Action(operation="CREATE", target="new_script.py", content="print('hello')")
    res = policy_engine.evaluate(action)
    assert res.decision == Decision.ALLOW
    assert res.policy_id == "WDN-000"


def test_safe_write_operation(policy_engine: PolicyEngine):
    action = Action(operation="WRITE", target="data.json", content="{}")
    res = policy_engine.evaluate(action)
    assert res.decision == Decision.ALLOW
    assert res.policy_id == "WDN-000"


def test_unsupported_operation_blocked(policy_engine: PolicyEngine):
    action = Action(operation="SPAWN_PROCESS", target="script.sh")
    res = policy_engine.evaluate(action)
    assert res.decision == Decision.BLOCK
    assert res.policy_id == "WDN-001"
    assert "Unsupported operation" in res.reason


def test_empty_target_blocked(policy_engine: PolicyEngine):
    action = Action(operation="READ", target="   ")
    res = policy_engine.evaluate(action)
    assert res.decision == Decision.BLOCK
    assert res.policy_id == "WDN-002"


def test_protected_file_write_blocked(policy_engine: PolicyEngine):
    action = Action(operation="WRITE", target=".env", content="MALICIOUS=true")
    res = policy_engine.evaluate(action)
    assert res.decision == Decision.BLOCK
    assert res.policy_id == "WDN-003"


def test_protected_file_create_blocked(policy_engine: PolicyEngine):
    action = Action(operation="CREATE", target="secrets.json", content="{}")
    res = policy_engine.evaluate(action)
    assert res.decision == Decision.BLOCK
    assert res.policy_id == "WDN-003"


def test_protected_file_delete_blocked(policy_engine: PolicyEngine):
    action = Action(operation="DELETE", target="production.env")
    res = policy_engine.evaluate(action)
    assert res.decision == Decision.BLOCK
    assert res.policy_id == "WDN-003"


def test_protected_file_rename_source_blocked(policy_engine: PolicyEngine):
    action = Action(operation="RENAME", target="credentials.json", destination="creds_backup.json")
    res = policy_engine.evaluate(action)
    assert res.decision == Decision.BLOCK
    assert res.policy_id == "WDN-003"


@pytest.mark.parametrize("target", ["production.env", ".env", "sub/secrets.json", "CREDENTIALS.JSON"])
def test_protected_file_read_blocked(policy_engine: PolicyEngine, target: str):
    # A read result is sent back to a remote chat peer, so reading a credential would leak it.
    res = policy_engine.evaluate(Action(operation="READ", target=target))
    assert res.decision == Decision.BLOCK
    assert res.policy_id == "WDN-003"


def test_rename_targeting_protected_destination_blocked(policy_engine: PolicyEngine):
    action = Action(operation="RENAME", target="harmless.txt", destination=".env")
    res = policy_engine.evaluate(action)
    assert res.decision == Decision.BLOCK
    assert res.policy_id == "WDN-003"


def test_rename_missing_destination_blocked(policy_engine: PolicyEngine):
    action = Action(operation="RENAME", target="file_a.txt", destination=None)
    res = policy_engine.evaluate(action)
    assert res.decision == Decision.BLOCK
    assert res.policy_id == "WDN-001"
    assert "requires an explicit destination path" in res.reason


def test_rename_destination_escaping_workspace_blocked(policy_engine: PolicyEngine):
    action = Action(operation="RENAME", target="file_a.txt", destination="../../escaped.txt")
    res = policy_engine.evaluate(action)
    assert res.decision == Decision.BLOCK
    assert res.policy_id == "WDN-002"


def test_destructive_delete_requires_approval(policy_engine: PolicyEngine):
    action = Action(operation="DELETE", target="temp.txt")
    res = policy_engine.evaluate(action)
    assert res.decision == Decision.REQUIRE_APPROVAL
    assert res.policy_id == "WDN-004"


def test_destructive_rename_requires_approval(policy_engine: PolicyEngine):
    action = Action(operation="RENAME", target="old_name.txt", destination="new_name.txt")
    res = policy_engine.evaluate(action)
    assert res.decision == Decision.REQUIRE_APPROVAL
    assert res.policy_id == "WDN-004"


def test_policy_result_context_contains_action_metadata(policy_engine: PolicyEngine):
    action = Action(operation="READ", target="config.yaml", reason="Inspection")
    res = policy_engine.evaluate(action)
    assert res.context.get("action_id") == action.action_id
    assert res.context.get("operation") == "READ"
    assert res.context.get("target") == "config.yaml"


def test_read_workspace_root_allowed(policy_engine: PolicyEngine):
    action = Action(operation="READ", target=".", reason="List workspace contents")
    res = policy_engine.evaluate(action)
    assert res.decision == Decision.ALLOW
    assert res.policy_id == "WDN-000"


def test_mutations_on_workspace_root_blocked(policy_engine: PolicyEngine):
    for op in ("DELETE", "WRITE", "CREATE", "RENAME"):
        action = Action(operation=op, target=".", destination="new_dir" if op == "RENAME" else None)
        res = policy_engine.evaluate(action)
        assert res.decision == Decision.BLOCK
        assert res.policy_id == "WDN-002"
