"""Unit tests for WardenAgent orchestration pipeline."""

import pytest
from pathlib import Path
from warden.agents.warden_agent import WardenAgent
from warden.execution.workspace import Workspace
from warden.models import (
    Action,
    ActionType,
    Decision,
    ExecutionStatus,
)


@pytest.fixture
def agent_workspace(tmp_path: Path) -> Workspace:
    ws_dir = tmp_path / "agent_ws"
    return Workspace(ws_dir)


@pytest.fixture
def warden(agent_workspace: Workspace) -> WardenAgent:
    return WardenAgent(workspace=agent_workspace)


def test_end_to_end_permitted_creation(warden: WardenAgent, agent_workspace: Workspace):
    action = Action(
        operation="CREATE",
        target="hello_warden.txt",
        content="Autonomous verification verified.",
        reason="Demonstration artifact",
    )

    result = warden.handle_action_request(action)

    assert result["status"] == ExecutionStatus.VERIFIED
    assert result["executed"] is True
    assert result["verified"] is True
    assert agent_workspace.exists("hello_warden.txt") is True


def test_end_to_end_permitted_read_directory(warden: WardenAgent, agent_workspace: Workspace):
    agent_workspace.create_synthetic_file("doc1.txt", "content 1")
    agent_workspace.create_synthetic_file("doc2.log", "content 2")

    action = Action(
        operation="READ",
        target=".",
        reason="List workspace files",
    )

    result = warden.handle_action_request(action)

    assert result["status"] == ExecutionStatus.VERIFIED
    assert result["executed"] is True
    assert result["verified"] is True
    assert "doc1.txt" in result["output"]
    assert "doc2.log" in result["output"]
    assert "directory exists and was accessible" in result["verification_details"]


def test_end_to_end_blocked_modification(warden: WardenAgent, agent_workspace: Workspace):
    action = Action(
        operation="WRITE",
        target=".env",
        content="LEAKED_KEY=12345",
        reason="Malicious injection attempt",
    )

    result = warden.handle_action_request(action)

    assert result["status"] == ExecutionStatus.BLOCKED
    assert result["decision"] == Decision.BLOCK
    assert result["policy_id"] == "WDN-003"
    assert result["executed"] is False
    assert result["verified"] is False
    assert not agent_workspace.exists(".env")


def test_end_to_end_human_approval_pipeline(warden: WardenAgent, agent_workspace: Workspace):
    # Setup file to be deleted
    agent_workspace.create_synthetic_file("old_cache.tmp", "temp data")
    assert agent_workspace.exists("old_cache.tmp") is True

    action = Action(
        operation="DELETE",
        target="old_cache.tmp",
        reason="Cache maintenance",
    )

    # 1. Pipeline pauses for approval
    res = warden.handle_action_request(action)
    assert res["status"] == ExecutionStatus.AWAITING_APPROVAL
    assert res["decision"] == Decision.REQUIRE_APPROVAL
    assert res["policy_id"] == "WDN-004"
    assert res["executed"] is False
    # File still exists
    assert agent_workspace.exists("old_cache.tmp") is True

    # 2. Human explicitly approves
    approval_res = warden.approve_and_execute(
        action_id=action.action_id,
        approver_id="security_auditor_bob",
    )
    assert approval_res["status"] == ExecutionStatus.VERIFIED
    assert approval_res["executed"] is True
    assert approval_res["verified"] is True
    # File is now deleted
    assert not agent_workspace.exists("old_cache.tmp")
