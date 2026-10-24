"""Real uAgents round trip over loopback HTTP (no network, no Almanac, throwaway test identities)."""

import socket
import threading
import time

import pytest
from uagents.crypto import Identity
from uagents.resolver import RulesBasedResolver

from warden.agents.warden_agent import WardenAgent
from warden.audit.remote import RemoteAuditVerifier
from warden.audit.transport import UAgentAuditTransport
from warden.auditor.agent import build_auditor_agent
from warden.auditor.config import AuditorConfig
from warden.execution.workspace import Workspace
from warden.models import Action, ExecutionStatus

WARDEN_SEED = "live-test-warden-seed-not-a-real-id-001"
AUDITOR_SEED = "live-test-auditor-seed-not-a-real-id-02"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def ws(tmp_path) -> Workspace:
    w = Workspace(tmp_path / "ws")
    w.create_synthetic_file("old.tmp", "junk")
    return w


def delete_old(warden):
    res = warden.handle_action_request(Action(operation="DELETE", target="old.tmp"))
    return warden.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])


def test_real_uagent_auditor_attests_a_delete(ws):
    warden_id = Identity.from_seed(WARDEN_SEED, 0)
    port = free_port()
    cfg = AuditorConfig(seed=AUDITOR_SEED, port=port, workspace_root=ws.root_path, allowed_requesters=[warden_id.address])
    agent, service = build_auditor_agent(cfg, warden_seed=WARDEN_SEED)
    threading.Thread(target=agent.run, daemon=True).start()

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            break
        except OSError:
            time.sleep(0.3)
    else:
        pytest.fail("auditor agent did not start listening")

    resolver = RulesBasedResolver({service.address: f"http://127.0.0.1:{port}/submit"})
    transport = UAgentAuditTransport(service.address, warden_id, resolver=resolver)
    verifier = RemoteAuditVerifier(ws, transport, service.address, timeout_seconds=15)

    result = delete_old(WardenAgent(workspace=ws, auditor=verifier))

    assert result["status"] == ExecutionStatus.VERIFIED
    assert result["observed_state"]["remote_auditor"]["valid"] is True
    assert not ws.exists("old.tmp")


def test_unreachable_real_auditor_is_unverified_not_verified(ws):
    warden_id = Identity.from_seed(WARDEN_SEED, 0)
    auditor_id = Identity.from_seed(AUDITOR_SEED, 0)
    dead = f"http://127.0.0.1:{free_port()}/submit"  # nothing listens here
    transport = UAgentAuditTransport(
        auditor_id.address, warden_id, resolver=RulesBasedResolver({auditor_id.address: dead})
    )
    verifier = RemoteAuditVerifier(ws, transport, auditor_id.address, timeout_seconds=3)

    result = delete_old(WardenAgent(workspace=ws, auditor=verifier))

    assert result["status"] == ExecutionStatus.UNVERIFIED and result["verified"] is False
