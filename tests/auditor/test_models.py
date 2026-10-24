"""Unit tests for Auditor models and action digest computation."""

from pathlib import Path
import pytest

from warden.auditor.digest import compute_action_digest
from warden.auditor.models import AuditAttestation, AuditRequest, AuditVerdict
from warden.models import Action


def test_action_digest_is_deterministic():
    action = Action(
        action_id="act-1234",
        operation="DELETE",
        target="cache.tmp",
    )
    ws = Path("/tmp/test_workspace")
    digest1 = compute_action_digest(action, ws)
    digest2 = compute_action_digest(action, ws)
    assert digest1 == digest2
    assert len(digest1) == 64  # SHA-256 hex string


def test_action_digest_tamper_detection():
    ws = Path("/tmp/test_workspace")
    base_action = Action(
        action_id="act-1234",
        operation="DELETE",
        target="cache.tmp",
    )
    base_digest = compute_action_digest(base_action, ws)

    # 1. Tampered target
    tampered_target = Action(action_id="act-1234", operation="DELETE", target="production.env")
    assert compute_action_digest(tampered_target, ws) != base_digest

    # 2. Tampered operation
    tampered_op = Action(action_id="act-1234", operation="READ", target="cache.tmp")
    assert compute_action_digest(tampered_op, ws) != base_digest

    # 3. Tampered action_id
    tampered_id = Action(action_id="act-9999", operation="DELETE", target="cache.tmp")
    assert compute_action_digest(tampered_id, ws) != base_digest

    # 4. Tampered destination
    tampered_dest = Action(action_id="act-1234", operation="DELETE", target="cache.tmp", destination="dest.tmp")
    assert compute_action_digest(tampered_dest, ws) != base_digest

    # 5. Tampered content
    tampered_content = Action(action_id="act-1234", operation="DELETE", target="cache.tmp", content="evil")
    assert compute_action_digest(tampered_content, ws) != base_digest

    # 6. Tampered workspace root
    assert compute_action_digest(base_action, Path("/tmp/other_workspace")) != base_digest


def test_audit_request_from_action_and_to_action():
    ws = Path("/tmp/test_workspace")
    action = Action(
        action_id="act-777",
        operation="CREATE",
        target="hello.txt",
        content="Hello world",
        correlation_id="corr-999",
    )
    req = AuditRequest.from_action(
        action=action,
        workspace_root=ws,
        executor_claimed_success=True,
        pre_state_manifest={"cache.tmp": "0x123"},
    )

    assert req.action_id == "act-777"
    assert req.operation == "CREATE"
    assert req.target == "hello.txt"
    assert req.content == "Hello world"
    assert req.executor_claimed_success is True
    assert req.pre_state_manifest == {"cache.tmp": "0x123"}
    assert req.action_digest == compute_action_digest(action, ws)

    # Verify round-trip conversion to Action
    recovered_action = req.to_action()
    assert recovered_action.action_id == action.action_id
    assert recovered_action.operation == action.operation
    assert recovered_action.target == action.target
    assert recovered_action.content == action.content


def test_models_serialization_and_deserialization():
    att = AuditAttestation(
        attestation_id="att-001",
        audit_id="audit-001",
        correlation_id="corr-001",
        action_id="act-001",
        action_digest="a" * 64,
        digest_valid=True,
        verdict=AuditVerdict.VERIFIED.value,
        observed_state={"target_exists": False},
        expected_state={"target_exists": False},
        evidence=["Target deleted"],
        collateral_mutations=[],
        details="Verification succeeded",
        auditor_address="agent1q_test_auditor",
        timestamp="2026-10-24T12:00:00Z",
    )

    json_str = att.json()
    assert "att-001" in json_str
    assert "VERIFIED" in json_str

    deserialized = AuditAttestation.parse_raw(json_str)
    assert deserialized.attestation_id == att.attestation_id
    assert deserialized.verdict == AuditVerdict.VERIFIED.value
    assert deserialized.observed_state == {"target_exists": False}
