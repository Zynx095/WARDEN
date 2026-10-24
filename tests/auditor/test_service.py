"""Unit tests for ReadOnlyWorkspaceView and AuditorService."""

from pathlib import Path
import pytest

from warden.auditor.digest import compute_action_digest
from warden.auditor.models import AuditRequest, AuditVerdict
from warden.auditor.service import AuditorService
from warden.auditor.workspace_view import ReadOnlyWorkspaceView
from warden.models import Action


@pytest.fixture
def test_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "service_test_workspace"
    ws.mkdir()
    (ws / "cache.tmp").write_text("dummy_cache", encoding="utf-8")
    (ws / "important.txt").write_text("important_content", encoding="utf-8")
    return ws


def test_readonly_workspace_view(test_workspace: Path):
    view = ReadOnlyWorkspaceView(test_workspace)

    assert view.exists("cache.tmp") is True
    assert view.is_file("cache.tmp") is True
    assert view.is_dir("cache.tmp") is False
    assert view.read_bytes("cache.tmp") == b"dummy_cache"
    assert view.compute_sha256("cache.tmp") is not None

    # Path traversal outside workspace boundary returns None
    assert view.get_canonical_path("../outside.txt") is None
    assert view.exists("../outside.txt") is False

    # Manifest capture
    manifest = view.capture_manifest()
    assert "cache.tmp" in manifest
    assert "important.txt" in manifest


def test_auditor_verifies_correct_deletion(test_workspace: Path):
    service = AuditorService(auditor_address="agent1q_auditor")
    action = Action(operation="DELETE", target="cache.tmp")

    # Capture pre-state manifest before deletion
    view = ReadOnlyWorkspaceView(test_workspace)
    pre_manifest = view.capture_manifest()

    # Simulate executor deleting the file
    (test_workspace / "cache.tmp").unlink()

    req = AuditRequest.from_action(
        action=action,
        workspace_root=test_workspace,
        executor_claimed_success=True,
        pre_state_manifest=pre_manifest,
    )

    attestation = service.process_audit_request(req)
    assert attestation.digest_valid is True
    assert attestation.verdict == AuditVerdict.VERIFIED.value
    assert attestation.observed_state["target_exists"] is False
    assert attestation.collateral_mutations == []


def test_auditor_detects_false_executor_claim_on_deletion(test_workspace: Path):
    """Executor falsely claims success, but file still exists on physical disk."""
    service = AuditorService(auditor_address="agent1q_auditor")
    action = Action(operation="DELETE", target="cache.tmp")

    # File was NOT deleted, but executor claims success
    req = AuditRequest.from_action(
        action=action,
        workspace_root=test_workspace,
        executor_claimed_success=True,
    )

    attestation = service.process_audit_request(req)
    assert attestation.digest_valid is True
    assert attestation.verdict == AuditVerdict.FAILED.value
    assert attestation.observed_state["target_exists"] is True
    assert "still exists on disk" in attestation.details


def test_auditor_detects_false_executor_claim_on_creation(test_workspace: Path):
    """Executor falsely claims CREATE success, but file was never written."""
    service = AuditorService(auditor_address="agent1q_auditor")
    action = Action(operation="CREATE", target="new_file.txt", content="created_content")

    # File does not exist on disk
    req = AuditRequest.from_action(
        action=action,
        workspace_root=test_workspace,
        executor_claimed_success=True,
    )

    attestation = service.process_audit_request(req)
    assert attestation.digest_valid is True
    assert attestation.verdict == AuditVerdict.FAILED.value
    assert attestation.observed_state["target_exists"] is False
    assert "was not found" in attestation.details


def test_auditor_detects_unexpected_extra_file_deletion(test_workspace: Path):
    """Action requested deleting cache.tmp, but important.txt was also deleted (collateral damage)."""
    service = AuditorService(auditor_address="agent1q_auditor")
    action = Action(operation="DELETE", target="cache.tmp")

    view = ReadOnlyWorkspaceView(test_workspace)
    pre_manifest = view.capture_manifest()

    # Simulate intended deletion of cache.tmp AND unintended deletion of important.txt
    (test_workspace / "cache.tmp").unlink()
    (test_workspace / "important.txt").unlink()

    req = AuditRequest.from_action(
        action=action,
        workspace_root=test_workspace,
        executor_claimed_success=True,
        pre_state_manifest=pre_manifest,
    )

    attestation = service.process_audit_request(req)
    assert attestation.digest_valid is True
    assert attestation.verdict == AuditVerdict.FAILED.value
    assert "unexpected_deletion:important.txt" in attestation.collateral_mutations
    assert "collateral damage" in attestation.details.lower()


def test_auditor_rejects_mismatched_action_digest(test_workspace: Path):
    """If action parameters were tampered with after digest creation, Auditor returns UNVERIFIED."""
    service = AuditorService(auditor_address="agent1q_auditor")
    action = Action(operation="DELETE", target="cache.tmp")

    # Generate a tampered digest
    fake_digest = "0" * 64

    req = AuditRequest.from_action(
        action=action,
        workspace_root=test_workspace,
        executor_claimed_success=True,
        action_digest=fake_digest,
    )

    attestation = service.process_audit_request(req)
    assert attestation.digest_valid is False
    assert attestation.verdict == AuditVerdict.UNVERIFIED.value
    assert "Action digest mismatch" in attestation.details


def test_auditor_returns_cached_attestation_for_duplicate_request(test_workspace: Path):
    """Duplicate requests with identical audit_id return cached attestation idempotently."""
    service = AuditorService(auditor_address="agent1q_auditor")
    action = Action(operation="DELETE", target="cache.tmp")
    (test_workspace / "cache.tmp").unlink()

    req = AuditRequest.from_action(
        action=action,
        workspace_root=test_workspace,
        executor_claimed_success=True,
    )

    first = service.process_audit_request(req)
    second = service.process_audit_request(req)

    assert first.attestation_id == second.attestation_id
    assert first.timestamp == second.timestamp
    assert first.verdict == second.verdict == AuditVerdict.VERIFIED.value
