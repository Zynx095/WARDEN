"""Remote Auditor mode: VERIFIED needs a valid signed attestation on top of the local check."""

import json
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from uagents.crypto import Identity

from warden.agents.warden_agent import WardenAgent
from warden.audit.attestation import AuditAttestation, AuditRequest, signing_digest
from warden.audit.auditor import OutcomeAuditor
from warden.audit.remote import RemoteAuditVerifier
from warden.auditor.service import AuditorService
from warden.config import ConfigError, WardenConfig
from warden.execution.workspace import Workspace
from warden.models import Action, ExecutionStatus, VerificationResult
from warden.security.digest import describe_path_state

# Throwaway identities for tests only; never persisted, never project identities.
WARDEN_ID = Identity.from_seed("remote-test-warden-seed-not-real-0001", 0)
AUDITOR_ID = Identity.from_seed("remote-test-auditor-seed-not-real-0002", 0)
OTHER_ID = Identity.from_seed("remote-test-other-seed-not-real-00003", 0)


@pytest.fixture
def ws(tmp_path) -> Workspace:
    w = Workspace(tmp_path / "ws")
    w.create_synthetic_file("old.tmp", "junk")
    w.create_synthetic_file("bystander.txt", "keep me")
    return w


def make_service(ws, identity=AUDITOR_ID, **kw) -> AuditorService:
    return AuditorService(ws.root_path, identity, [WARDEN_ID.address], **kw)


class Loopback:
    """In-process stand-in for the network: JSON in, JSON out, through the real service."""

    def __init__(self, service, sender=WARDEN_ID.address, mutate_request=None, mutate_reply=None):
        self.service, self.sender = service, sender
        self.mutate_request, self.mutate_reply = mutate_request, mutate_reply
        self.requests, self.replies = [], []

    def __call__(self, request: AuditRequest, timeout: float):
        payload = request.model_dump_json()
        self.requests.append(payload)
        if self.mutate_request:
            payload = self.mutate_request(payload)
        out = self.service.handle(payload, self.sender)
        self.replies.append(out)
        if out is None:
            return None
        data = json.loads(out)
        return self.mutate_reply(data) if self.mutate_reply else data


def make_verifier(ws, transport, timeout=5.0, local=None, trusted=AUDITOR_ID.address) -> RemoteAuditVerifier:
    return RemoteAuditVerifier(ws, transport, trusted, timeout, local=local)


def make_warden(ws, verifier) -> WardenAgent:
    return WardenAgent(workspace=ws, auditor=verifier)


def delete_old(warden):
    res = warden.handle_action_request(Action(operation="DELETE", target="old.tmp"))
    return warden.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])


class LenientLocal(OutcomeAuditor):
    """Local check that wrongly passes: proves the remote Auditor is a real second line."""

    def verify_outcome(self, action, exec_result, pre_state=None):
        target, _ = self._resolve(action)
        return VerificationResult(
            action=action, status=ExecutionStatus.VERIFIED, verified=True,
            observed_state={"post_target_state": describe_path_state(target)}, details="lenient local pass",
        )


# --- disabled by default / configuration ---------------------------------------------------

def test_remote_auditor_is_disabled_by_default(ws, monkeypatch):
    monkeypatch.delenv("WARDEN_REMOTE_AUDITOR", raising=False)
    cfg = WardenConfig()
    assert cfg.remote_auditor is False and cfg.auditor_address is None
    warden = WardenAgent(workspace=ws)
    assert isinstance(warden.auditor, OutcomeAuditor)
    assert delete_old(warden)["status"] == ExecutionStatus.VERIFIED


def test_enabling_requires_a_trusted_address(monkeypatch):
    monkeypatch.setenv("WARDEN_REMOTE_AUDITOR", "true")
    monkeypatch.delenv("WARDEN_AUDITOR_ADDRESS", raising=False)
    with pytest.raises(ConfigError):
        WardenConfig()
    monkeypatch.setenv("WARDEN_AUDITOR_ADDRESS", "not-an-address")
    with pytest.raises(ConfigError):
        WardenConfig()
    monkeypatch.setenv("WARDEN_AUDITOR_ADDRESS", AUDITOR_ID.address)
    assert WardenConfig().remote_auditor is True


def test_remote_enabled_without_a_verifier_fails_closed(ws, monkeypatch):
    monkeypatch.setenv("WARDEN_REMOTE_AUDITOR", "true")
    monkeypatch.setenv("WARDEN_AUDITOR_ADDRESS", AUDITOR_ID.address)
    with pytest.raises(ConfigError):
        WardenAgent(workspace=ws, config=WardenConfig())


def test_factory_refuses_wardens_own_address_as_auditor(ws, monkeypatch):
    from warden.audit.factory import build_remote_auditor_if_enabled
    monkeypatch.setenv("WARDEN_REMOTE_AUDITOR", "true")
    monkeypatch.setenv("WARDEN_AUDITOR_ADDRESS", WARDEN_ID.address)
    with pytest.raises(ConfigError):
        build_remote_auditor_if_enabled(ws, "remote-test-warden-seed-not-real-0001", WardenConfig())


def test_factory_returns_none_when_disabled(ws, monkeypatch):
    from warden.audit.factory import build_remote_auditor_if_enabled
    monkeypatch.delenv("WARDEN_REMOTE_AUDITOR", raising=False)
    assert build_remote_auditor_if_enabled(ws, "remote-test-warden-seed-not-real-0001", WardenConfig()) is None


# --- success path ---------------------------------------------------------------------------

def test_remote_mode_verifies_a_clean_delete_end_to_end(ws):
    transport = Loopback(make_service(ws))
    result = delete_old(make_warden(ws, make_verifier(ws, transport)))

    assert result["status"] == ExecutionStatus.VERIFIED and result["verified"] is True
    assert result["observed_state"]["remote_auditor"]["valid"] is True
    assert len(transport.requests) == 1
    assert not ws.exists("old.tmp")


def test_request_leaks_no_content_claim_or_absolute_path(ws):
    transport = Loopback(make_service(ws))
    make_warden(ws, make_verifier(ws, transport)).handle_action_request(
        Action(operation="WRITE", target="note.txt", content="TOP-SECRET-PAYLOAD")
    )
    sent = transport.requests[0]
    assert "TOP-SECRET-PAYLOAD" not in sent
    assert str(ws.root_path) not in sent and str(ws.root_path).lower() not in sent.lower()
    assert not re.search(r"success|executed|output", sent, re.I)


# --- attestation failure modes: never VERIFIED -----------------------------------------------

def assert_executed_but_not_verified(result, ws, deleted=True):
    assert result["status"] == ExecutionStatus.UNVERIFIED
    assert result["verified"] is False
    assert result["executed"] is True
    assert ws.exists("old.tmp") is (not deleted)


def test_forged_signature_is_unverified(ws):
    def resign_with_wrong_key(data):
        att = AuditAttestation(**{**data, "signature": ""})
        data["signature"] = OTHER_ID.sign_digest(signing_digest(att))
        return data

    result = delete_old(make_warden(ws, make_verifier(ws, Loopback(make_service(ws), mutate_reply=resign_with_wrong_key))))
    assert_executed_but_not_verified(result, ws)
    assert "signature" in result["verification_details"].lower()


def test_unsigned_attestation_is_unverified(ws):
    result = delete_old(make_warden(ws, make_verifier(ws, Loopback(make_service(ws), mutate_reply=lambda d: {**d, "signature": ""}))))
    assert_executed_but_not_verified(result, ws)


def test_untrusted_signer_is_unverified(ws):
    service = make_service(ws, identity=OTHER_ID)  # a perfectly valid attestation, from the wrong party
    result = delete_old(make_warden(ws, make_verifier(ws, Loopback(service))))
    assert_executed_but_not_verified(result, ws)
    assert "trusted auditor" in result["verification_details"]


def test_attestation_tampered_after_signing_is_unverified(ws):
    result = delete_old(make_warden(ws, make_verifier(ws, Loopback(make_service(ws), mutate_reply=lambda d: {**d, "details": "edited"}))))
    assert_executed_but_not_verified(result, ws)


def test_digest_mismatch_in_request_is_unverified(ws):
    def corrupt_digest(payload):
        data = json.loads(payload)
        data["action_digest"] = "0" * 64
        return json.dumps(data)

    transport = Loopback(make_service(ws), mutate_request=corrupt_digest)
    result = delete_old(make_warden(ws, make_verifier(ws, transport)))
    assert_executed_but_not_verified(result, ws)


def test_attestation_for_a_different_digest_is_unverified(ws):
    result = delete_old(make_warden(ws, make_verifier(ws, Loopback(make_service(ws), mutate_reply=lambda d: {**d, "action_digest": "f" * 64}))))
    assert_executed_but_not_verified(result, ws)


def test_replayed_attestation_from_an_earlier_request_is_unverified(ws):
    ws.create_synthetic_file("second.tmp", "junk2")
    transport = Loopback(make_service(ws))
    warden = make_warden(ws, make_verifier(ws, transport))
    assert delete_old(warden)["status"] == ExecutionStatus.VERIFIED
    first_reply = json.loads(transport.replies[0])

    replaying = Loopback(make_service(ws), mutate_reply=lambda _fresh: first_reply)
    warden2 = make_warden(ws, make_verifier(ws, replaying))
    res = warden2.handle_action_request(Action(operation="DELETE", target="second.tmp"))
    result = warden2.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])

    assert result["status"] == ExecutionStatus.UNVERIFIED and result["verified"] is False


def test_timeout_returns_promptly_and_is_unverified(ws):
    def hangs(request, timeout):
        time.sleep(4)

    started = time.monotonic()
    result = delete_old(make_warden(ws, make_verifier(ws, hangs, timeout=0.5)))
    assert time.monotonic() - started < 2.5
    assert_executed_but_not_verified(result, ws)
    assert "timeout" in result["verification_details"]


@pytest.mark.parametrize("response", [None, "garbage", 42, {}, {"verdict": "VERIFIED"}, [1, 2]])
def test_missing_or_malformed_response_is_unverified(ws, response):
    result = delete_old(make_warden(ws, make_verifier(ws, lambda r, t: response)))
    assert_executed_but_not_verified(result, ws)


def test_unreachable_auditor_is_unverified(ws):
    def down(request, timeout):
        raise ConnectionError("auditor offline")

    assert_executed_but_not_verified(delete_old(make_warden(ws, make_verifier(ws, down))), ws)


def test_unauthorized_requester_gets_no_reply_and_nothing_verifies(ws):
    service = AuditorService(ws.root_path, AUDITOR_ID, [OTHER_ID.address])  # does not allow WARDEN
    transport = Loopback(service)
    assert_executed_but_not_verified(delete_old(make_warden(ws, make_verifier(ws, transport))), ws)
    assert transport.replies == [None]


def test_expired_request_is_unverified(ws):
    late = make_service(ws, clock=lambda: datetime.now(timezone.utc) + timedelta(hours=1))
    assert_executed_but_not_verified(delete_old(make_warden(ws, make_verifier(ws, Loopback(late)))), ws)


# --- the remote Auditor is a real second line of defence --------------------------------------

def test_false_executor_success_is_failed_by_the_remote_auditor_even_if_local_is_fooled(ws, monkeypatch):
    warden = make_warden(ws, make_verifier(ws, Loopback(make_service(ws)), local=LenientLocal(ws)))
    res = warden.handle_action_request(Action(operation="DELETE", target="old.tmp"))

    from warden.models import ExecutionResult
    monkeypatch.setattr(
        warden.executor, "execute",
        lambda request: ExecutionResult(action=request.action, status=ExecutionStatus.EXECUTED, success=True, output="Deleted"),
    )
    result = warden.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])

    assert result["verified"] is False and result["status"] == ExecutionStatus.FAILED
    assert "still exists" in result["verification_details"]
    assert ws.exists("old.tmp")


def test_collateral_modification_is_failed_by_the_remote_auditor_even_if_local_is_fooled(ws, monkeypatch):
    warden = make_warden(ws, make_verifier(ws, Loopback(make_service(ws)), local=LenientLocal(ws)))
    res = warden.handle_action_request(Action(operation="DELETE", target="old.tmp"))
    original = warden.executor.execute

    def rogue(request):
        outcome = original(request)
        (ws.root_path / "bystander.txt").write_text("tampered by a rogue executor")
        return outcome

    monkeypatch.setattr(warden.executor, "execute", rogue)
    result = warden.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])

    assert result["verified"] is False and result["status"] == ExecutionStatus.FAILED
    assert "bystander.txt modified" in result["verification_details"]


def test_local_failure_cannot_be_rescued_by_a_remote_verified(ws, monkeypatch):
    transport = Loopback(make_service(ws))
    warden = make_warden(ws, make_verifier(ws, transport))
    res = warden.handle_action_request(Action(operation="DELETE", target="old.tmp"))
    original = warden.executor.execute

    def rogue(request):
        outcome = original(request)
        (ws.root_path / "bystander.txt").unlink()
        return outcome

    monkeypatch.setattr(warden.executor, "execute", rogue)
    result = warden.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])

    assert result["verified"] is False and result["status"] == ExecutionStatus.FAILED
    assert transport.requests == []  # a local failure is final; the remote is not even asked


def test_conflicting_nonce_for_same_request_id_is_unverified(ws):
    service = make_service(ws)
    transport = Loopback(service)
    delete_old(make_warden(ws, make_verifier(ws, transport)))
    data = json.loads(transport.requests[0])
    data["nonce"] = "different-nonce"
    reply = json.loads(service.handle(json.dumps(data), WARDEN_ID.address))
    assert reply["verdict"] == "UNVERIFIED"


def test_redelivered_identical_request_returns_the_same_attestation(ws):
    service = make_service(ws)
    transport = Loopback(service)
    delete_old(make_warden(ws, make_verifier(ws, transport)))
    assert service.handle(transport.requests[0], WARDEN_ID.address) == transport.replies[0]


# --- local-only mode is unchanged -------------------------------------------------------------

def test_local_mode_still_flags_collateral_damage(ws, monkeypatch):
    warden = WardenAgent(workspace=ws)
    res = warden.handle_action_request(Action(operation="DELETE", target="old.tmp"))
    original = warden.executor.execute

    def rogue(request):
        outcome = original(request)
        (ws.root_path / "bystander.txt").unlink()
        return outcome

    monkeypatch.setattr(warden.executor, "execute", rogue)
    result = warden.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])
    assert result["verified"] is False


def test_unverified_is_reported_to_the_user_not_as_success(ws):
    from uagents_core.contrib.protocols.chat import ChatMessage, TextContent
    from warden.agents.intent_engine import IntentEngine
    from warden.integrations.acp_adapter import WardenACPHandler

    warden = make_warden(ws, make_verifier(ws, lambda r, t: None))
    handler = WardenACPHandler(warden=warden, intent_engine=IntentEngine(api_key=None))
    say = lambda text: handler.process_chat_message(ChatMessage(content=[TextContent(type="text", text=text)]), sender="alice")[1].content[0].text

    cmd = re.search(r"APPROVE\s+[a-f0-9\-]+\s+[a-f0-9]{64}", say("delete old.tmp")).group(0)
    reply = say(cmd)

    assert "UNVERIFIED" in reply and "NOT be independently confirmed" in reply
    assert "Verified" not in reply.replace("UNVERIFIED", "")


# --- the other operations through the remote Auditor ------------------------------------------

def run_op(ws, action, rogue=None, local=None):
    transport = Loopback(make_service(ws))
    warden = make_warden(ws, make_verifier(ws, transport, local=local))
    if rogue is not None:
        original = warden.executor.execute

        def wrapped(request):
            outcome = original(request)
            rogue()
            return outcome

        warden.executor.execute = wrapped
    res = warden.handle_action_request(action)
    if res["status"] == ExecutionStatus.AWAITING_APPROVAL:
        res = warden.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])
    return res


def test_write_and_create_and_rename_are_verified_remotely(ws):
    assert run_op(ws, Action(operation="CREATE", target="new.txt", content="a\nb\n"))["verified"] is True
    assert run_op(ws, Action(operation="WRITE", target="bystander.txt", content="rewritten"))["verified"] is True
    renamed = run_op(ws, Action(operation="RENAME", target="old.tmp", destination="renamed.tmp"))
    assert renamed["verified"] is True and ws.exists("renamed.tmp")


def test_remote_auditor_fails_wrong_written_content_even_if_local_is_fooled(ws):
    result = run_op(
        ws, Action(operation="WRITE", target="bystander.txt", content="expected"),
        rogue=lambda: (ws.root_path / "bystander.txt").write_bytes(b"something else"), local=LenientLocal(ws),
    )
    assert result["verified"] is False and result["status"] == ExecutionStatus.FAILED
    assert "content" in result["verification_details"]


def test_remote_auditor_fails_altered_rename_content_even_if_local_is_fooled(ws):
    result = run_op(
        ws, Action(operation="RENAME", target="old.tmp", destination="renamed.tmp"),
        rogue=lambda: (ws.root_path / "renamed.tmp").write_text("not the original"), local=LenientLocal(ws),
    )
    assert result["verified"] is False and result["status"] == ExecutionStatus.FAILED


def test_remote_auditor_flags_dropped_extra_file_on_create(ws):
    result = run_op(
        ws, Action(operation="CREATE", target="new.txt", content="x"),
        rogue=lambda: (ws.root_path / "dropped.bin").write_text("payload"), local=LenientLocal(ws),
    )
    assert result["verified"] is False
    assert "dropped.bin added" in result["verification_details"]
