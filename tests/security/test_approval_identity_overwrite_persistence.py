"""Independent approval, overwrite policy, policy change while pending, durable state and restart recovery."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from uagents_core.contrib.protocols.chat import ChatMessage, MetadataContent, TextContent

from warden.agents.intent_engine import IntentEngine
from warden.agents.warden_agent import WardenAgent
from warden.config import WardenConfig
from warden.execution.workspace import Workspace
from warden.hosting.demo_workspace import prepare_demo_workspace
from warden.integrations.acp_adapter import DUPLICATE_AFTER_RESTART, WardenACPHandler
from warden.models import Action, ExecutionStatus
from warden.security.state_store import StateStoreError

REQUESTER = "agent1qrequester"
APPROVER = "agent1qapprover"
STRANGER = "agent1qstranger"


@pytest.fixture
def root(tmp_path):
    return prepare_demo_workspace(tmp_path / "ws")


def agent(root, db=None, **cfg):
    return WardenAgent(workspace=Workspace(root), config=WardenConfig(state_db=db, **cfg))


def handler(warden, mode="self", approvers=()):
    return WardenACPHandler(warden=warden, intent_engine=IntentEngine(api_key=None), approvers=list(approvers),
                            interactive_cards=True, approval_mode=mode)


def say(h, text, sender=REQUESTER, msg=None):
    msg = msg or ChatMessage(content=[TextContent(type="text", text=text)])
    return h.process_chat_message(msg, sender=sender)[1]


def review_selection(reply, which="approve_cta"):
    (card,) = [c for c in reply.content if isinstance(c, MetadataContent)]
    return json.loads(card.metadata["card_payload"])[which]["selection"]


# --- independent approval ----------------------------------------------------------------------

def test_independent_mode_refuses_self_approval_by_text_and_by_card(root):
    h = handler(agent(root), mode="independent", approvers=[APPROVER])
    sel = review_selection(say(h, "delete cache.tmp"))
    by_card = say(h, json.dumps(sel))
    by_text = say(h, f"APPROVE {sel['action_id']} {sel['digest']}")
    for reply in (by_card, by_text):
        assert "Independent approval is required" in reply.content[0].text
    assert (root / "cache.tmp").is_file()
    assert "VERIFIED" in say(h, json.dumps(sel), sender=APPROVER).content[0].text
    assert not (root / "cache.tmp").exists()


def test_independent_mode_lets_the_requester_cancel_but_not_strangers(root):
    h = handler(agent(root), mode="independent", approvers=[APPROVER])
    sel = review_selection(say(h, "delete cache.tmp"), "reject_cta")
    assert "REJECTED" not in say(h, json.dumps(sel), sender=STRANGER).content[0].text
    assert "REJECTED" in say(h, json.dumps(sel)).content[0].text
    assert (root / "cache.tmp").is_file()


def test_self_mode_still_lets_the_requester_approve(root):
    h = handler(agent(root), mode="self")
    sel = review_selection(say(h, "delete cache.tmp"))
    assert "VERIFIED" in say(h, json.dumps(sel)).content[0].text


def test_unknown_approval_mode_is_rejected(root, monkeypatch):
    from warden.config import ConfigError
    with pytest.raises(ConfigError):
        handler(agent(root), mode="anyone")
    monkeypatch.setenv("WARDEN_APPROVAL_MODE", "anyone")
    with pytest.raises(ConfigError):
        WardenConfig()


# --- overwrite policy ----------------------------------------------------------------------------

def test_overwriting_an_existing_file_needs_approval(root):
    w = agent(root)
    res = w.handle_action_request(Action(operation="WRITE", target="README.txt", content="replaced"))
    assert res["status"] == ExecutionStatus.AWAITING_APPROVAL and res["policy_id"] == "WDN-005"
    assert "synthetic" in (root / "README.txt").read_text()
    new = w.handle_action_request(Action(operation="WRITE", target="fresh.txt", content="new"))
    assert new["status"] == ExecutionStatus.VERIFIED


def test_rename_onto_an_existing_file_is_blocked(root):
    res = agent(root).handle_action_request(Action(operation="RENAME", target="cache.tmp", destination="debug.log"))
    assert res["status"] == ExecutionStatus.BLOCKED and res["policy_id"] == "WDN-005"
    assert (root / "cache.tmp").is_file() and "debug" in (root / "debug.log").read_text()


# --- policy change while pending -------------------------------------------------------------------

def test_policy_change_while_pending_cancels_the_request(root):
    w = agent(root)
    res = w.handle_action_request(Action(operation="DELETE", target="cache.tmp"))
    w.policy_engine.protected_files.add("cache.tmp")  # policy now protects the target
    out = w.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])
    assert out["status"] == ExecutionStatus.FAILED and "Policy now blocks" in out["error"]
    assert (root / "cache.tmp").is_file()
    again = w.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])
    assert "invalidated" in again["error"]


# --- durable state and restart recovery ------------------------------------------------------------

def test_pending_approval_survives_a_restart_and_still_executes_once(root, tmp_path):
    db = tmp_path / "state.db"
    res = agent(root, db).handle_action_request(Action(operation="DELETE", target="cache.tmp"))
    restarted = agent(root, db)
    done = restarted.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])
    assert done["status"] == ExecutionStatus.VERIFIED and not (root / "cache.tmp").exists()
    (root / "cache.tmp").write_text("recreated")
    replay = agent(root, db).approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])
    assert "already been approved" in replay["error"] and (root / "cache.tmp").read_text() == "recreated"


def test_approver_binding_and_digest_survive_a_restart(root, tmp_path):
    db = tmp_path / "state.db"
    w = agent(root, db)
    res = w.handle_action_request(Action(operation="DELETE", target="cache.tmp"), authorized_approvers={APPROVER},
                                  requester=REQUESTER, independent_approval=True)
    restarted = agent(root, db)
    assert "Independent approval" in restarted.approve_and_execute(res["pending_id"], REQUESTER,
                                                                   expected_digest=res["action_digest"])["error"]
    assert "does not match" in restarted.approve_and_execute(res["pending_id"], APPROVER,
                                                             expected_digest="0" * 64)["error"]
    assert restarted.approve_and_execute(res["pending_id"], APPROVER,
                                         expected_digest=res["action_digest"])["status"] == ExecutionStatus.VERIFIED


def test_expired_approval_stays_expired_after_restart(root, tmp_path):
    db = tmp_path / "state.db"
    w = agent(root, db)
    res = w.handle_action_request(Action(operation="DELETE", target="cache.tmp"))
    pending = w.auth_manager.get_pending_approval(res["pending_id"])
    pending.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    w.state_store.save_pending(res["pending_id"], pending.to_record())
    out = agent(root, db).approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])
    assert out["status"] == ExecutionStatus.EXPIRED and (root / "cache.tmp").is_file()


def test_rejection_is_final_across_restart(root, tmp_path):
    db = tmp_path / "state.db"
    w = agent(root, db)
    res = w.handle_action_request(Action(operation="DELETE", target="cache.tmp"))
    w.reject_pending(res["pending_id"], "alice", expected_digest=res["action_digest"])
    out = agent(root, db).approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])
    assert "rejected" in out["error"] and (root / "cache.tmp").is_file()


def test_interrupted_execution_is_never_rerun_or_reported_as_success(root, tmp_path):
    db = tmp_path / "state.db"
    w = agent(root, db)
    res = w.handle_action_request(Action(operation="DELETE", target="cache.tmp"))
    binding = w._bind(w.auth_manager.get_pending_approval(res["pending_id"]).action)
    # Approval consumed, then the process "dies" before execution or outcome recording.
    w.auth_manager.approve_pending_action(res["pending_id"], "alice", binding.target_path, None, root,
                                          expected_digest=res["action_digest"], current_state_digest=binding.state_digest)
    restarted = agent(root, db)
    assert restarted.auth_manager.get_resolved(res["pending_id"]).final_status == "INTERRUPTED"
    out = restarted.approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])
    assert out["status"] == ExecutionStatus.FAILED and "stopped before its outcome" in out["error"]
    assert (root / "cache.tmp").is_file()


def test_target_changed_during_downtime_invalidates_the_request(root, tmp_path):
    db = tmp_path / "state.db"
    res = agent(root, db).handle_action_request(Action(operation="DELETE", target="cache.tmp"))
    (root / "cache.tmp").write_text("changed while WARDEN was down")
    out = agent(root, db).approve_and_execute(res["pending_id"], "alice", expected_digest=res["action_digest"])
    assert "state changed" in out["error"] and (root / "cache.tmp").read_text() == "changed while WARDEN was down"


def test_duplicate_message_after_restart_is_not_processed_again(root, tmp_path):
    db = tmp_path / "state.db"
    msg = ChatMessage(content=[TextContent(type="text", text="delete cache.tmp")])
    first = handler(agent(root, db))
    say(first, "", msg=msg)
    restarted_agent = agent(root, db)
    reply = say(handler(restarted_agent), "", msg=msg)
    assert reply.content[0].text == DUPLICATE_AFTER_RESTART
    assert len(restarted_agent.auth_manager._pending_approvals) == 1  # only the original request


def test_state_db_holds_no_keys_or_read_contents(root, tmp_path):
    db = tmp_path / "state.db"
    w = agent(root, db)
    h = handler(w)
    say(h, "read README.txt")
    sel = review_selection(say(h, "delete cache.tmp"))
    say(h, json.dumps(sel))
    raw = b"".join(p.read_bytes() for p in tmp_path.glob("state.db*"))
    assert w.auth_manager.secret_key not in raw
    assert b"Every file here is synthetic test data" not in raw  # README content was read, not stored
    assert b"signature" not in raw and b"token_id" not in raw


def test_corrupt_state_db_refuses_to_start(root, tmp_path):
    db = tmp_path / "state.db"
    db.write_bytes(b"this is not a sqlite database" * 100)
    with pytest.raises(StateStoreError):
        agent(root, db)


# --- mandatory risk assessment -----------------------------------------------------------------------

def test_required_risk_assessment_missing_means_a_change_needs_approval(root):
    class Down:
        source = "remote"
        def assess(self, request):
            raise TimeoutError
    w = WardenAgent(workspace=Workspace(root), config=WardenConfig(risk_required=True), risk_analyst=Down())
    res = w.handle_action_request(Action(operation="CREATE", target="new.txt", content="x"))
    assert res["status"] == ExecutionStatus.AWAITING_APPROVAL and res["policy_id"] == "WDN-006"
    read = w.handle_action_request(Action(operation="READ", target="README.txt"))
    assert read["status"] == ExecutionStatus.VERIFIED  # reads change nothing
    ok = WardenAgent(workspace=Workspace(root), config=WardenConfig(risk_required=True))
    assert ok.handle_action_request(Action(operation="CREATE", target="new2.txt", content="x"))["status"] \
        == ExecutionStatus.VERIFIED
