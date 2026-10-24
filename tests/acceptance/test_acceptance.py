"""Acceptance scenarios through the hosted chat handler (the canonical path), one per requirement.

Every scenario drives ``WardenACPHandler`` the way an ASI:One message would, on the synthetic
demo workspace with durable state. The complete multi-agent round trip over real uAgents
envelopes is ``tests/integration/test_sentinel_network_live.py``. Real ASI:One rendering and
button behaviour are not covered by any local test.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest
from uagents.crypto import Identity
from uagents_core.contrib.protocols.chat import ChatMessage, MetadataContent, TextContent

from warden.agents.intent_engine import IntentEngine
from warden.agents.warden_agent import WardenAgent
from warden.audit.remote import RemoteAuditVerifier
from warden.config import WardenConfig
from warden.execution.workspace import Workspace
from warden.hosting.demo_workspace import prepare_demo_workspace
from warden.integrations.acp_adapter import DUPLICATE_AFTER_RESTART, WardenACPHandler
from warden.integrations.cards import SELECTION_SCHEMA, validate_card_metadata
from warden.models import ExecutionResult, ExecutionStatus
from warden.risk.analyst import RemoteRiskAnalyst

USER, OTHER = "agent1qacceptuser", "agent1qacceptother"
AUDITOR = Identity.from_seed("acceptance-auditor-seed-not-a-real-id1", 0)
ANALYST = Identity.from_seed("acceptance-analyst-seed-not-a-real-id1", 0)


@pytest.fixture
def env(tmp_path):
    root = prepare_demo_workspace(tmp_path / "ws")
    return {"root": root, "db": tmp_path / "state.db", "tmp": tmp_path}


def make(env, auditor=None, risk_analyst=None, mode="self", approvers=()):
    cfg = WardenConfig(state_db=env["db"])
    warden = WardenAgent(workspace=Workspace(env["root"]), config=cfg, auditor=auditor, risk_analyst=risk_analyst)
    h = WardenACPHandler(warden=warden, intent_engine=IntentEngine(api_key=None), approvers=list(approvers),
                         interactive_cards=True, approval_mode=mode)
    return warden, h


def send(h, text, sender=USER, msg=None):
    return h.process_chat_message(msg or ChatMessage(content=[TextContent(type="text", text=text)]), sender=sender)[1]


def text(reply):
    return reply.content[0].text


def card(reply):
    (c,) = [c for c in reply.content if isinstance(c, MetadataContent)]
    validate_card_metadata(c.metadata)
    return c.metadata


def selection(reply, which="approve_cta"):
    return json.loads(card(reply)["card_payload"])[which]["selection"]


def badge(reply):
    root = json.loads(card(reply)["card_payload"])["root"]
    return next(c["label"] for c in root["children"] if c["type"] == "badge")


def command(sel, verb="APPROVE"):
    return f"{verb} {sel['action_id']} {sel['digest']}"


# 1 ------------------------------------------------------------------------------------------
def test_01_permitted_harmless_operation_is_verified(env):
    _, h = make(env)
    reply = send(h, "read README.txt")
    assert "✅ VERIFIED" in text(reply) and badge(reply) == "VERIFIED"


# 2 ------------------------------------------------------------------------------------------
def test_02_risky_operation_requires_approval_and_nothing_runs(env):
    _, h = make(env)
    reply = send(h, "delete cache.tmp")
    assert "🔒 AWAITING APPROVAL" in text(reply) and card(reply)["card_kind"] == "review"
    assert (env["root"] / "cache.tmp").is_file()


# 3, 4 ---------------------------------------------------------------------------------------
@pytest.mark.parametrize("channel", ["card", "text"])
def test_03_04_card_and_text_approval_take_the_same_canonical_path(env, channel, monkeypatch):
    warden, h = make(env)
    sel = selection(send(h, "delete cache.tmp"))
    calls = []
    real = warden.approve_and_execute
    monkeypatch.setattr(warden, "approve_and_execute", lambda **kw: calls.append(kw) or real(**kw))
    reply = send(h, json.dumps(sel) if channel == "card" else command(sel))
    assert calls == [{"action_id": sel["action_id"], "approver_id": USER, "expected_digest": sel["digest"]}]
    assert badge(reply) == "VERIFIED" and not (env["root"] / "cache.tmp").exists()


# 5 ------------------------------------------------------------------------------------------
def test_05_rejected_approval_is_final(env):
    _, h = make(env)
    review = send(h, "delete cache.tmp")
    assert badge(send(h, json.dumps(selection(review, "reject_cta")))) == "REJECTED"
    assert badge(send(h, command(selection(review)))) == "FAILED" and (env["root"] / "cache.tmp").is_file()


# 6 ------------------------------------------------------------------------------------------
def test_06_expired_approval(env):
    warden, h = make(env)
    sel = selection(send(h, "delete cache.tmp"))
    warden.auth_manager.get_pending_approval(sel["action_id"]).expires_at = datetime.now(timezone.utc) - timedelta(1)
    assert badge(send(h, json.dumps(sel))) == "EXPIRED" and (env["root"] / "cache.tmp").is_file()


# 7 ------------------------------------------------------------------------------------------
def test_07_replayed_and_duplicate_approvals_run_once(env):
    _, h = make(env)
    sel = selection(send(h, "delete cache.tmp"))
    msg = ChatMessage(content=[TextContent(type="text", text=json.dumps(sel))])
    first = send(h, "", msg=msg)
    assert send(h, "", msg=msg) is first
    (env["root"] / "cache.tmp").write_text("recreated")
    assert "already been approved" in text(send(h, command(sel)))
    assert (env["root"] / "cache.tmp").read_text() == "recreated"


# 8 ------------------------------------------------------------------------------------------
@pytest.mark.parametrize("request_text", ["delete production.env", "read production.env",
                                          "write .warden-demo-workspace"])
def test_08_protected_resources_are_blocked(env, request_text):
    _, h = make(env)
    reply = send(h, request_text)
    assert "🚫 BLOCKED" in text(reply) and "DEMO_ONLY" not in text(reply)
    assert "DEMO_ONLY" in (env["root"] / "production.env").read_text()


# 9 ------------------------------------------------------------------------------------------
@pytest.mark.parametrize("transport", [lambda r, t: __import__("time").sleep(3), lambda r, t: {"risk_level": "LOW"}])
def test_09_risk_analyst_timeout_or_malformed_answer_fails_safe(env, transport):
    _, h = make(env, risk_analyst=RemoteRiskAnalyst(transport, ANALYST.address, timeout_seconds=1))
    reply = send(h, "delete cache.tmp")
    assert "🔒 AWAITING APPROVAL" in text(reply) and "unavailable" in text(reply)


# 10 -----------------------------------------------------------------------------------------
def test_10_unauthorized_or_mismatched_responses_decide_nothing(env):
    warden, h = make(env)
    sel = selection(send(h, "delete cache.tmp"))
    assert badge(send(h, json.dumps(sel), sender=OTHER)) == "FAILED"
    assert badge(send(h, json.dumps(dict(sel, digest="0" * 64)))) == "FAILED"
    assert "nothing was decided" in text(send(h, json.dumps(dict(sel, warden="evil.v1"))))
    assert warden.auth_manager.get_pending_approval(sel["action_id"]) is not None


def test_10b_independent_mode_refuses_self_approval(env):
    _, h = make(env, mode="independent", approvers=[OTHER])
    sel = selection(send(h, "delete cache.tmp"))
    assert "Independent approval is required" in text(send(h, json.dumps(sel)))
    assert badge(send(h, json.dumps(sel), sender=OTHER)) == "VERIFIED"


# 11 -----------------------------------------------------------------------------------------
def test_11_target_changed_between_proposal_and_execution(env):
    _, h = make(env)
    sel = selection(send(h, "delete cache.tmp"))
    (env["root"] / "cache.tmp").write_text("changed")
    reply = send(h, json.dumps(sel))
    assert badge(reply) == "FAILED" and "state changed" in text(reply)
    assert (env["root"] / "cache.tmp").read_text() == "changed"


# 12 -----------------------------------------------------------------------------------------
def test_12_executor_failure_is_reported_as_failed(env, monkeypatch):
    warden, h = make(env)
    sel = selection(send(h, "delete cache.tmp"))
    monkeypatch.setattr(warden.executor, "execute", lambda r: ExecutionResult(
        action=r.action, status=ExecutionStatus.FAILED, success=False, error="simulated disk failure"))
    reply = send(h, json.dumps(sel))
    assert badge(reply) == "FAILED" and "simulated disk failure" in text(reply) and "VERIFIED" not in text(reply)


# 13 -----------------------------------------------------------------------------------------
@pytest.mark.parametrize("transport", [
    lambda r, t: None,                                    # unreachable / no answer
    lambda r, t: __import__("time").sleep(4),             # timeout
    lambda r, t: {"verdict": "VERIFIED"},                 # forged, unsigned
])
def test_13_auditor_failure_is_never_verified(env, transport):
    verifier = RemoteAuditVerifier(Workspace(env["root"]), transport, AUDITOR.address, timeout_seconds=2)
    _, h = make(env, auditor=verifier)
    assert badge(send(h, json.dumps(selection(send(h, "delete cache.tmp"))))) == "UNVERIFIED"


# 14, 15 -------------------------------------------------------------------------------------
def test_14_15_pending_actions_consumption_and_dedup_survive_restart(env):
    _, h = make(env)
    sel = selection(send(h, "delete cache.tmp"))
    approve = ChatMessage(content=[TextContent(type="text", text=json.dumps(sel))])
    _, h2 = make(env)                                              # restart: pending request recovered
    assert badge(send(h2, "", msg=approve)) == "VERIFIED"
    _, h3 = make(env)                                              # restart again
    assert text(send(h3, "", msg=approve)) == DUPLICATE_AFTER_RESTART  # same message: not processed again
    assert "already been approved" in text(send(h3, command(sel)))  # new message, same approval: refused


# 16 -----------------------------------------------------------------------------------------
@pytest.mark.parametrize("payload", [
    {"warden": SELECTION_SCHEMA, "decision": "execute", "action_id": "1b4e28ba-2fa1-11d2-883f-0016d3cca427",
     "digest": "ab" * 32},
    {"warden": SELECTION_SCHEMA, "decision": "approve"},
    {"warden": SELECTION_SCHEMA, "decision": "approve", "action_id": "1b4e28ba-2fa1-11d2-883f-0016d3cca427",
     "digest": "ab" * 32},
])
def test_16_invalid_or_stale_card_interactions_execute_nothing(env, payload):
    _, h = make(env)
    send(h, "delete cache.tmp")
    reply = send(h, json.dumps(payload))
    assert "VERIFIED" not in text(reply) and (env["root"] / "cache.tmp").is_file()


# 17 -----------------------------------------------------------------------------------------
def test_17_result_cards_show_every_final_status(env, monkeypatch):
    seen = set()
    _, h = make(env)
    seen.add(badge(send(h, "read README.txt")))                    # VERIFIED
    seen.add(badge(send(h, "delete production.env")))              # BLOCKED
    r = send(h, "delete cache.tmp")
    seen.add(badge(send(h, json.dumps(selection(r, "reject_cta")))))  # REJECTED
    w, h = make(env)
    sel = selection(send(h, "delete debug.log"))
    w.auth_manager.get_pending_approval(sel["action_id"]).expires_at = datetime.now(timezone.utc) - timedelta(1)
    seen.add(badge(send(h, json.dumps(sel))))                       # EXPIRED
    seen.add(badge(send(h, "read missing.txt")))                    # FAILED
    verifier = RemoteAuditVerifier(Workspace(env["root"]), lambda r, t: None, AUDITOR.address, timeout_seconds=1)
    _, h = make(env, auditor=verifier)
    seen.add(badge(send(h, json.dumps(selection(send(h, "delete debug.log")))))) # UNVERIFIED
    assert seen == {"VERIFIED", "BLOCKED", "REJECTED", "EXPIRED", "FAILED", "UNVERIFIED"}


# 18 -----------------------------------------------------------------------------------------
def test_18_secrets_paths_and_internal_errors_never_reach_the_user(env, monkeypatch):
    warden, h = make(env)
    replies = [send(h, m) for m in ("read README.txt", "delete cache.tmp", "read production.env")]
    blob = " ".join(c.text if isinstance(c, TextContent) else json.dumps(dict(c.metadata))
                     for r in replies for c in r.content)
    assert str(env["root"]) not in blob and str(env["root"]).replace("\\", "\\\\") not in blob
    assert warden.auth_manager.secret_key.decode() not in blob and "DEMO_ONLY" not in blob
    monkeypatch.setattr(warden, "handle_action_request", lambda *a, **k: 1 / 0)
    crash = text(send(h, "delete debug.log"))
    assert "could not be processed safely" in crash and "ZeroDivision" not in crash


# 19 -----------------------------------------------------------------------------------------
@pytest.mark.parametrize("request_text", ["delete ../outside.txt", "read ../../etc/passwd",
                                          "write ..\\escape.txt with content 'x'"])
def test_19_path_traversal_is_blocked(env, request_text):
    (env["tmp"] / "outside.txt").write_text("outside")
    _, h = make(env)
    send(h, request_text)
    # Nothing outside the workspace is read back, changed or created. (For the write, the parser
    # keeps only the file name, so any file it creates lands inside the workspace.)
    assert (env["tmp"] / "outside.txt").read_text() == "outside" and not (env["tmp"] / "escape.txt").exists()
    if request_text.startswith(("delete", "read")):
        assert "root:" not in text(send(h, request_text)) and (env["tmp"] / "outside.txt").exists()
