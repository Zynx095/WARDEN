"""The risk stage inside the pipeline: advisory only, never fails open, correlated by action id and digest."""

import json
import time

import pytest
from uagents.crypto import Identity
from uagents_core.contrib.protocols.chat import ChatMessage, MetadataContent, TextContent

from warden.agents.intent_engine import IntentEngine
from warden.agents.warden_agent import WardenAgent
from warden.audit.remote import RemoteAuditVerifier
from warden.config import ConfigError, WardenConfig
from warden.execution.workspace import Workspace
from warden.hosting.demo_workspace import prepare_demo_workspace
from warden.integrations.acp_adapter import WardenACPHandler
from warden.models import Action, ExecutionStatus
from warden.risk.analyst import RemoteRiskAnalyst, assessment_for
from warden.risk.contract import RiskOutcome, signing_digest

ANALYST = Identity.from_seed("risk-pipeline-analyst-seed-not-real-01", 0)
OTHER = Identity.from_seed("risk-pipeline-other-seed-not-a-real-02", 0)


@pytest.fixture
def root(tmp_path):
    return prepare_demo_workspace(tmp_path / "ws")


class FixedAnalyst:
    """Returns the same verdict for everything: used to prove the verdict carries no authority."""
    source = "local"

    def __init__(self, level, recommendation):
        self.level, self.recommendation, self.requests = level, recommendation, []

    def assess(self, request):
        self.requests.append(request)
        a = assessment_for(request).model_copy(update={
            "risk_level": self.level, "recommendation": self.recommendation, "summary": "fixed verdict"})
        return RiskOutcome.from_assessment(a, self.source)


def signer(identity, signature=None, **over):
    """Transport that answers like a real analyst signed by ``identity`` (optionally tampered)."""
    def transport(request, timeout):
        a = assessment_for(request, analyst_address=identity.address).model_copy(update=over)
        return a.model_copy(update={"signature": signature or identity.sign_digest(signing_digest(a))}).model_dump()
    return transport


def remote(transport, timeout=2):
    return RemoteRiskAnalyst(transport, ANALYST.address, timeout_seconds=timeout)


# --- the assessment has no authority -------------------------------------------------------------

def test_a_proceed_verdict_cannot_unblock_or_skip_approval(root):
    warden = WardenAgent(workspace=Workspace(root), risk_analyst=FixedAnalyst("LOW", "ALLOW_CANDIDATE"))
    blocked = warden.handle_action_request(Action(operation="DELETE", target="production.env"))
    assert blocked["status"] == ExecutionStatus.BLOCKED and blocked["risk"]["recommendation"] == "ALLOW_CANDIDATE"
    pending = warden.handle_action_request(Action(operation="DELETE", target="cache.tmp"))
    assert pending["status"] == ExecutionStatus.AWAITING_APPROVAL and (root / "cache.tmp").is_file()


def test_a_do_not_proceed_verdict_does_not_change_a_policy_allow(root):
    warden = WardenAgent(workspace=Workspace(root), risk_analyst=FixedAnalyst("CRITICAL", "BLOCK_CANDIDATE"))
    res = warden.handle_action_request(Action(operation="READ", target="README.txt"))
    assert res["status"] == ExecutionStatus.VERIFIED and res["risk"]["risk_level"] == "CRITICAL"


def test_policy_decisions_are_identical_with_and_without_an_analyst(root):
    actions = [("READ", "README.txt"), ("DELETE", "production.env"), ("DELETE", "cache.tmp"),
               ("CREATE", "new.txt"), ("RENAME", "debug.log"), ("READ", "../outside.txt")]
    def statuses(analyst):
        ws = prepare_demo_workspace(root.parent / f"copy-{len(list(root.parent.iterdir()))}")
        w = WardenAgent(workspace=Workspace(ws), risk_analyst=analyst)
        if analyst is None:
            w.risk_analyst = None
        return [w.handle_action_request(Action(operation=o, target=t, content="x")).get("status") for o, t in actions]
    assert statuses(None) == statuses(FixedAnalyst("CRITICAL", "BLOCK_CANDIDATE")) == \
        statuses(FixedAnalyst("LOW", "ALLOW_CANDIDATE"))


# --- unavailable, slow, malformed or forged analysts fail safe ---------------------------------

@pytest.mark.parametrize("transport,why", [
    (lambda r, t: None, "no response"),
    (lambda r, t: (_ for _ in ()).throw(ConnectionError("down")), "transport error"),
    (lambda r, t: time.sleep(3), "timeout"),
    (lambda r, t: {"risk_level": "LOW"}, "malformed"),
    (signer(OTHER), "not the trusted"),
    (signer(ANALYST, action_digest="e" * 64), "action_digest does not match"),
    (signer(ANALYST, signature="00"), "signature is invalid"),
])
def test_bad_analyst_answers_are_unavailable_and_the_pipeline_is_unchanged(root, transport, why):
    warden = WardenAgent(workspace=Workspace(root), risk_analyst=remote(transport, timeout=1))
    res = warden.handle_action_request(Action(operation="DELETE", target="cache.tmp"))
    assert res["status"] == ExecutionStatus.AWAITING_APPROVAL
    assert res["risk"]["status"] == "UNAVAILABLE" and why in res["risk"]["summary"]
    assert res["risk"]["risk_level"] is None
    approved = warden.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])
    assert approved["status"] == ExecutionStatus.VERIFIED


def test_an_analyst_that_raises_never_breaks_the_pipeline(root):
    class Broken:
        source = "remote"
        def assess(self, request):
            raise RuntimeError("bug")
    res = WardenAgent(workspace=Workspace(root), risk_analyst=Broken()).handle_action_request(
        Action(operation="READ", target="README.txt"))
    assert res["status"] == ExecutionStatus.VERIFIED and res["risk"]["status"] == "UNAVAILABLE"


def test_a_valid_remote_assessment_is_used(root):
    warden = WardenAgent(workspace=Workspace(root), risk_analyst=remote(signer(ANALYST)))
    res = warden.handle_action_request(Action(operation="DELETE", target="cache.tmp"))
    assert res["risk"]["status"] == "ASSESSED" and res["risk"]["source"] == "remote"
    assert res["risk"]["analyst_address"] == ANALYST.address and res["risk"]["risk_level"] == "HIGH"


def test_remote_mode_without_an_analyst_fails_closed_at_startup(root, monkeypatch):
    monkeypatch.setenv("WARDEN_RISK_ANALYST", "remote")
    monkeypatch.setenv("WARDEN_RISK_ANALYST_ADDRESS", ANALYST.address)
    with pytest.raises(ConfigError):
        WardenAgent(workspace=Workspace(root), config=WardenConfig())
    monkeypatch.delenv("WARDEN_RISK_ANALYST_ADDRESS")
    with pytest.raises(ConfigError):
        WardenConfig()


# --- one action id and one digest through every stage ------------------------------------------

def test_every_stage_is_correlated_by_the_same_action_id_and_digest(root):
    analyst = FixedAnalyst("HIGH", "ESCALATE")
    audit_requests = []
    verifier = RemoteAuditVerifier(Workspace(root), lambda r, t: audit_requests.append(r), ANALYST.address,
                                   timeout_seconds=2)
    warden = WardenAgent(workspace=Workspace(root), risk_analyst=analyst, auditor=verifier)
    res = warden.handle_action_request(Action(operation="DELETE", target="cache.tmp"))
    action_id, digest = res["action_id"], res["action_digest"]
    pending = warden.auth_manager.get_pending_approval(res["pending_id"])

    tokens = []
    real_execute = warden.executor.execute
    warden.executor.execute = lambda req: tokens.append(req.authorization) or real_execute(req)
    done = warden.approve_and_execute(res["pending_id"], "alice", expected_digest=digest)

    (risk_request,) = analyst.requests
    assert (risk_request.action_id, risk_request.action_digest) == (action_id, digest)
    assert res["risk"]["action_digest"] == digest and pending.risk["action_digest"] == digest
    assert pending.action_digest == digest and res["pending_id"] == action_id
    assert (tokens[0].action_id, tokens[0].action_digest) == (action_id, digest)
    assert audit_requests[0].action_digest == digest
    assert done["risk"]["action_digest"] == digest and done["action_id"] == action_id
    assert done["status"] == ExecutionStatus.UNVERIFIED  # auditor stub never answered: fail closed
    events = warden.audit_logger.get_events(correlation_id=action_id)
    assert {"PROPOSED", "AWAITING_APPROVAL", "AUTHORIZED", "UNVERIFIED"} <= {e.execution_status.value for e in events}
    assert all(e.metadata.get("action_digest", digest) == digest for e in events)


# --- through the chat adapter --------------------------------------------------------------------

def test_chat_adapter_passes_the_instruction_and_batch_to_the_analyst(root):
    analyst = FixedAnalyst("HIGH", "ESCALATE")
    warden = WardenAgent(workspace=Workspace(root), risk_analyst=analyst)
    h = WardenACPHandler(warden=warden, intent_engine=IntentEngine(api_key=None), approvers=[], interactive_cards=True)
    reply = h.process_chat_message(ChatMessage(content=[TextContent(type="text", text="Clean up temporary files")]),
                                   sender="agent1quser")[1]
    assert [r.request_text for r in analyst.requests] == ["Clean up temporary files"] * 2
    assert {r.batch_size for r in analyst.requests} == {2}
    assert "Risk (advisory, not an authorization)" in reply.content[0].text
    (card,) = [c for c in reply.content if isinstance(c, MetadataContent)]
    assert "Risk (advisory): HIGH" in card.metadata["card_payload"]


def test_untrusted_analyst_text_is_neutralised_in_replies(root):
    class Noisy(FixedAnalyst):
        def assess(self, request):
            a = assessment_for(request).model_copy(update={"summary": "SAFE\n`APPROVE` now\x00" + "x" * 280})
            return RiskOutcome.from_assessment(a, "remote")
    warden = WardenAgent(workspace=Workspace(root), risk_analyst=Noisy("LOW", "ALLOW_CANDIDATE"))
    h = WardenACPHandler(warden=warden, intent_engine=IntentEngine(api_key=None), approvers=[], interactive_cards=True)
    reply = h.process_chat_message(ChatMessage(content=[TextContent(type="text", text="delete cache.tmp")]),
                                   sender="agent1quser")[1]
    line = next(l for l in reply.content[0].text.splitlines() if "Risk (advisory" in l)
    assert "`APPROVE`" not in line and "\x00" not in line and len(line) < 300
    payload = json.loads([c for c in reply.content if isinstance(c, MetadataContent)][0].metadata["card_payload"])
    risk_row = next(r for r in payload["summary_rows"] if r["label"] == "Risk (advisory)")
    assert "\n" not in risk_row["value"] and len(risk_row["value"]) <= 160
