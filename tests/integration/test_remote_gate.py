"""Final-gate invariants for remote mode that cut across components."""

import hashlib
from pathlib import Path

import pytest
from uagents.crypto import Identity

from warden.agents.warden_agent import WardenAgent
from warden.audit.auditor import OutcomeAuditor
from warden.audit.remote import RemoteAuditVerifier
from warden.auditor.service import AuditorService
from warden.execution.workspace import Workspace
from warden.models import Action, ExecutionStatus

WARDEN_ID = Identity.from_seed("gate-test-warden-seed-not-a-real-id-1", 0)
AUDITOR_ID = Identity.from_seed("gate-test-auditor-seed-not-a-real-id2", 0)


@pytest.fixture
def ws(tmp_path) -> Workspace:
    w = Workspace(tmp_path / "ws")
    w.create_synthetic_file("old.tmp", "junk")
    w.create_synthetic_file("production.env", "SECRET=1")
    w.create_synthetic_file("bystander.txt", "keep me")
    return w


def tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        h.update(str(p.relative_to(root)).encode())
        if p.is_file():
            h.update(p.read_bytes())
            h.update(str(p.stat().st_mtime_ns).encode())
    return h.hexdigest()


class RecordingLocal(OutcomeAuditor):
    def __init__(self, ws, events):
        super().__init__(ws)
        self.events = events

    def verify_outcome(self, action, exec_result, pre_state=None):
        self.events.append("local")
        return super().verify_outcome(action, exec_result, pre_state)


def test_local_check_runs_before_the_remote_is_consulted(ws):
    events = []
    service = AuditorService(ws.root_path, AUDITOR_ID, [WARDEN_ID.address])

    def transport(request, timeout):
        events.append("remote")
        import json
        return json.loads(service.handle(request.model_dump_json(), WARDEN_ID.address))

    verifier = RemoteAuditVerifier(ws, transport, AUDITOR_ID.address, 5, local=RecordingLocal(ws, events))
    warden = WardenAgent(workspace=ws, auditor=verifier)
    res = warden.handle_action_request(Action(operation="DELETE", target="old.tmp"))
    result = warden.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])

    assert result["status"] == ExecutionStatus.VERIFIED
    assert events == ["local", "remote"]


def test_protected_file_stays_blocked_in_remote_mode_and_remote_is_never_asked(ws):
    calls = []
    verifier = RemoteAuditVerifier(ws, lambda r, t: calls.append(r), AUDITOR_ID.address, 5)
    warden = WardenAgent(workspace=ws, auditor=verifier)

    for op in ("DELETE", "WRITE", "RENAME"):
        res = warden.handle_action_request(
            Action(operation=op, target="production.env", content="x", destination="other.env")
        )
        assert res["status"] == ExecutionStatus.BLOCKED
    assert ws.exists("production.env") and calls == []


def test_handling_requests_never_changes_the_workspace(ws):
    service = AuditorService(ws.root_path, AUDITOR_ID, [WARDEN_ID.address])
    captured = []
    verifier = RemoteAuditVerifier(ws, lambda r, t: captured.append(r) or None, AUDITOR_ID.address, 5)
    warden = WardenAgent(workspace=ws, auditor=verifier)
    res = warden.handle_action_request(Action(operation="DELETE", target="old.tmp"))
    warden.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])

    before = tree_hash(ws.root_path)
    for request in captured:
        for sender in (WARDEN_ID.address, "agent1qintruder"):
            service.handle(request.model_dump_json(), sender)
            service.handle("not json", sender)
    assert tree_hash(ws.root_path) == before


def test_local_only_mode_is_the_default_and_needs_no_remote_configuration(ws):
    warden = WardenAgent(workspace=ws)
    assert isinstance(warden.auditor, OutcomeAuditor)
    res = warden.handle_action_request(Action(operation="DELETE", target="old.tmp"))
    result = warden.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])
    assert result["status"] == ExecutionStatus.VERIFIED
    assert "remote_auditor" not in result["observed_state"]
