"""Integration tests for the Auditor uAgent covering all required verification scenarios.

Covers:
1. Correct execution and valid attestation.
2. Executor falsely claiming success.
3. An unexpected extra file deletion (collateral damage).
4. Changed action digest (anti-tampering).
5. Missing or invalid attestation (fail-closed).
6. Auditor timeout (fail-closed).
7. Duplicate audit messages (idempotent caching).
8. Existing protected-file policy still blocks execution (WDN-003 intact).
9. The original end-to-end demo still passes cleanly.
"""

import time
from pathlib import Path
from typing import Any
import pytest

from warden import demo
from warden.agents.warden_agent import WardenAgent
from warden.auditor.config import AuditorConfig
from warden.auditor.digest import compute_action_digest
from warden.auditor.models import AuditAttestation, AuditRequest, AuditVerdict
from warden.auditor.service import AuditorService
from warden.auditor.verifier import AuditorUAgentVerifier
from warden.execution.workspace import Workspace
from warden.models import (
    Action,
    ExecutionResult,
    ExecutionStatus,
    VerificationResult,
)


@pytest.fixture
def isolated_workspace(tmp_path: Path) -> Workspace:
    ws_dir = tmp_path / "auditor_integration_ws"
    ws = Workspace(ws_dir)
    ws.create_synthetic_file("cache.tmp", "transient_cache_content\n")
    ws.create_synthetic_file("debug.log", "[2026-10-24 10:00:00] test log line\n")
    ws.create_synthetic_file("production.env", "DATABASE_URL=postgres://synthetic_demo:5432/db\n")
    return ws


@pytest.fixture
def enabled_config() -> AuditorConfig:
    return AuditorConfig(
        enabled=True,
        timeout_seconds=2.0,
        seed="auditor_test_seed_0123456789abcdef",
    )


def test_1_correct_execution_and_valid_attestation(isolated_workspace: Workspace, enabled_config: AuditorConfig):
    """1. Correct execution produces a valid VERIFIED attestation from the Auditor."""
    service = AuditorService(auditor_address="agent1q_test_auditor")
    verifier = AuditorUAgentVerifier(
        workspace=isolated_workspace,
        auditor_service=service,
        config=enabled_config,
    )

    action = Action(operation="DELETE", target="cache.tmp")
    pre_state = verifier.capture_pre_state(action)

    # Simulate executor performing the authorized deletion
    target_path = isolated_workspace.get_canonical_path("cache.tmp")
    target_path.unlink()

    exec_result = ExecutionResult(
        action=action,
        status=ExecutionStatus.EXECUTED,
        success=True,
    )

    res = verifier.verify_outcome(action, exec_result, pre_state)

    assert isinstance(res, VerificationResult)
    assert res.verified is True
    assert res.status == ExecutionStatus.VERIFIED
    assert "agent1q_test_auditor" in res.details
    assert not isolated_workspace.exists("cache.tmp")


def test_2_executor_falsely_claiming_success(isolated_workspace: Workspace, enabled_config: AuditorConfig):
    """2. When executor falsely claims success but disk state is absent or wrong, Auditor returns FAILED."""
    service = AuditorService(auditor_address="agent1q_test_auditor")
    verifier = AuditorUAgentVerifier(
        workspace=isolated_workspace,
        auditor_service=service,
        config=enabled_config,
    )

    # Case A: DELETE claimed, but file was NOT deleted (still exists on disk)
    del_action = Action(operation="DELETE", target="cache.tmp")
    pre_state_del = verifier.capture_pre_state(del_action)

    false_del_result = ExecutionResult(
        action=del_action,
        status=ExecutionStatus.EXECUTED,
        success=True,  # False claim
    )

    res_del = verifier.verify_outcome(del_action, false_del_result, pre_state_del)
    assert res_del.verified is False
    assert res_del.status == ExecutionStatus.FAILED
    assert "still exists on disk" in res_del.details

    # Case B: CREATE claimed, but file does not exist on disk
    create_action = Action(operation="CREATE", target="ghost_file.txt", content="payload")
    pre_state_create = verifier.capture_pre_state(create_action)

    false_create_result = ExecutionResult(
        action=create_action,
        status=ExecutionStatus.EXECUTED,
        success=True,  # False claim
    )

    res_create = verifier.verify_outcome(create_action, false_create_result, pre_state_create)
    assert res_create.verified is False
    assert res_create.status == ExecutionStatus.FAILED
    assert "was not found" in res_create.details


def test_3_unexpected_extra_file_deletion(isolated_workspace: Workspace, enabled_config: AuditorConfig):
    """3. Detect unexpected collateral file deletion outside the action's permitted scope."""
    service = AuditorService(auditor_address="agent1q_test_auditor")
    verifier = AuditorUAgentVerifier(
        workspace=isolated_workspace,
        auditor_service=service,
        config=enabled_config,
    )

    action = Action(operation="DELETE", target="cache.tmp")
    pre_state = verifier.capture_pre_state(action)

    # Executor deletes target cache.tmp BUT ALSO maliciously/accidentally deletes debug.log
    isolated_workspace.get_canonical_path("cache.tmp").unlink()
    isolated_workspace.get_canonical_path("debug.log").unlink()

    exec_result = ExecutionResult(
        action=action,
        status=ExecutionStatus.EXECUTED,
        success=True,
    )

    res = verifier.verify_outcome(action, exec_result, pre_state)
    assert res.verified is False
    assert res.status == ExecutionStatus.FAILED
    assert "collateral damage" in res.details.lower()
    assert "debug.log" in res.details


def test_4_changed_action_digest(isolated_workspace: Workspace, enabled_config: AuditorConfig):
    """4. Tampered or mismatched action digest causes the Auditor to reject with UNVERIFIED (fail-closed)."""
    service = AuditorService(auditor_address="agent1q_test_auditor")

    # Hook transport to simulate in-flight digest tampering
    def _tampering_transport(req: AuditRequest) -> AuditAttestation:
        tampered_req = AuditRequest.parse_raw(req.json())
        tampered_req.action_digest = "deadbeef" * 8
        return service.process_audit_request(tampered_req)

    verifier = AuditorUAgentVerifier(
        workspace=isolated_workspace,
        auditor_service=service,
        config=enabled_config,
        transport_call=_tampering_transport,
    )

    action = Action(operation="DELETE", target="cache.tmp")
    pre_state = verifier.capture_pre_state(action)
    isolated_workspace.get_canonical_path("cache.tmp").unlink()

    exec_result = ExecutionResult(action=action, status=ExecutionStatus.EXECUTED, success=True)
    res = verifier.verify_outcome(action, exec_result, pre_state)

    assert res.verified is False
    assert res.status == ExecutionStatus.FAILED
    assert "unverified" in res.details.lower() or "mismatch" in res.details.lower()


def test_5_missing_or_invalid_attestation(isolated_workspace: Workspace, enabled_config: AuditorConfig):
    """5. Missing, corrupted, or non-attestation responses fail closed."""
    # Transport returns invalid object (e.g. dict instead of AuditAttestation)
    def _corrupted_transport(_req: AuditRequest) -> Any:
        return "Not an attestation"

    verifier = AuditorUAgentVerifier(
        workspace=isolated_workspace,
        config=enabled_config,
        transport_call=_corrupted_transport,
    )

    action = Action(operation="DELETE", target="cache.tmp")
    exec_result = ExecutionResult(action=action, status=ExecutionStatus.EXECUTED, success=True)

    res = verifier.verify_outcome(action, exec_result)
    assert res.verified is False
    assert res.status == ExecutionStatus.FAILED
    assert "invalid attestation" in res.details.lower() or "fail-closed" in res.details.lower()


def test_6_auditor_timeout(isolated_workspace: Workspace):
    """6. When the Auditor uAgent times out, verification fails closed."""
    short_timeout_cfg = AuditorConfig(enabled=True, timeout_seconds=0.5)

    def _hanging_transport(_req: AuditRequest) -> AuditAttestation:
        time.sleep(1.2)  # Exceeds 0.5s timeout
        return AuditAttestation(
            attestation_id="att-late",
            audit_id="audit-late",
            correlation_id="corr-late",
            action_id="act-late",
            action_digest="dig-late",
            digest_valid=True,
            verdict=AuditVerdict.VERIFIED.value,
        )

    verifier = AuditorUAgentVerifier(
        workspace=isolated_workspace,
        config=short_timeout_cfg,
        transport_call=_hanging_transport,
    )

    action = Action(operation="DELETE", target="cache.tmp")
    exec_result = ExecutionResult(action=action, status=ExecutionStatus.EXECUTED, success=True)

    res = verifier.verify_outcome(action, exec_result)
    assert res.verified is False
    assert res.status == ExecutionStatus.FAILED
    assert "timed out" in res.details.lower()
    assert res.observed_state.get("auditor_timeout") is True


def test_7_duplicate_audit_messages(isolated_workspace: Workspace):
    """7. Duplicate audit messages with identical audit_id return cached attestations idempotently."""
    service = AuditorService(auditor_address="agent1q_auditor")
    action = Action(operation="DELETE", target="cache.tmp")
    isolated_workspace.get_canonical_path("cache.tmp").unlink()

    req = AuditRequest.from_action(
        action=action,
        workspace_root=isolated_workspace.root_path,
        executor_claimed_success=True,
    )

    first_attestation = service.process_audit_request(req)
    second_attestation = service.process_audit_request(req)

    assert first_attestation.attestation_id == second_attestation.attestation_id
    assert first_attestation.timestamp == second_attestation.timestamp
    assert first_attestation.verdict == AuditVerdict.VERIFIED.value


def test_8_existing_protected_file_policy_still_blocks_execution(isolated_workspace: Workspace, enabled_config: AuditorConfig):
    """8. Existing deterministic policy engine blocks protected file mutation prior to execution or auditing."""
    warden = WardenAgent(workspace=isolated_workspace)
    # Attach enabled AuditorUAgentVerifier to coordinator
    warden.auditor = AuditorUAgentVerifier(
        workspace=isolated_workspace,
        config=enabled_config,
    )

    action = Action(
        operation="DELETE",
        target="production.env",
        reason="Malicious attempt to delete protected config",
    )

    initial_env_bytes = isolated_workspace.get_canonical_path("production.env").read_bytes()

    res = warden.handle_action_request(action)

    # Must be BLOCKED deterministically by policy WDN-003
    assert res["status"] == ExecutionStatus.BLOCKED
    assert res["policy_id"] == "WDN-003"
    assert res["executed"] is False
    assert res["verified"] is False
    assert "Protected resource modification is prohibited" in res["reason"]

    # File on disk must remain strictly untouched
    assert isolated_workspace.exists("production.env") is True
    assert isolated_workspace.get_canonical_path("production.env").read_bytes() == initial_env_bytes


def test_9_original_demo_passes_with_auditor_feature(tmp_path: Path):
    """9. The original end-to-end WARDEN demonstration runs and passes completely."""
    demo_ws = tmp_path / "demo_ws"
    demo_log = tmp_path / "demo_audit.jsonl"

    report = demo.run_demo(workspace_dir=demo_ws, audit_log=demo_log, out=lambda _: None)
    assert len(report.checks) >= 12
    assert (demo_ws / "production.env").exists()
    assert not (demo_ws / "session_cache.tmp").exists()
