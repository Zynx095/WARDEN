"""The whole Sentinel Network over real uAgents envelopes on loopback (no internet, throwaway identities).

ASI:One stand-in --chat--> hosted WARDEN --signed RiskRequest--> Risk Analyst agent (own process)
                                         policy -> review card -> click -> restricted executor
                                         --signed AuditRequest--> Auditor agent (own process)
                                         -> verified result card

Startup calls that would publish the test identities are disabled and any non-loopback HTTP
request fails the test, so nothing leaves this machine. This is a local integration test; it
says nothing about Agentverse or ASI:One themselves.
"""

import asyncio
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

import aiohttp
import pytest
import requests
from uagents import Agent, Context, Protocol
from uagents.crypto import Identity
from uagents.resolver import RulesBasedResolver
from uagents_core.contrib.protocols.chat import (
    ChatAcknowledgement,
    ChatMessage,
    MetadataContent,
    TextContent,
    chat_protocol_spec,
)

import warden.config
from warden.agents.warden_agent import WardenAgent
from warden.config import REPO_ROOT
from warden.execution.workspace import Workspace
from warden.hosting.config import HostedConfig
from warden.hosting.server import build_hosted_agent
from warden.models import Action
from warden.risk.analyst import RemoteRiskAnalyst
from warden.risk.wire import UAgentRiskTransport

PEER = Path(__file__).with_name("sentinel_peer.py")

WARDEN_SEED = "sentinel-live-warden-seed-not-a-real-01"
ANALYST_SEED = "sentinel-live-analyst-seed-not-a-real-2"
AUDITOR_SEED = "sentinel-live-auditor-seed-not-a-real-3"
CLIENT_SEED = "sentinel-live-client-seed-not-a-real-04"
LOOPBACK = {"127.0.0.1", "localhost"}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_port(port, deadline=15):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.2)
    pytest.fail(f"nothing listening on {port}")


@pytest.fixture
def offline(monkeypatch):
    blocked = []
    original_aiohttp = aiohttp.ClientSession._request
    original_requests = requests.Session.request

    async def guarded_aiohttp(self, method, url, *a, **kw):
        if urlparse(str(url)).hostname not in LOOPBACK:
            blocked.append(str(url))
            raise aiohttp.ClientConnectionError("network disabled in tests")
        return await original_aiohttp(self, method, url, *a, **kw)

    def guarded_requests(self, method, url, *a, **kw):
        if urlparse(str(url)).hostname not in LOOPBACK:
            blocked.append(str(url))
            raise requests.ConnectionError("network disabled in tests")
        return original_requests(self, method, url, *a, **kw)

    async def nothing(self, *a, **kw):
        return None

    from uagents import asgi
    monkeypatch.setattr(asgi, "_read_asgi_body", asgi._read_asgi_body)
    monkeypatch.setattr(aiohttp.ClientSession, "_request", guarded_aiohttp)
    monkeypatch.setattr(requests.Session, "request", guarded_requests)
    monkeypatch.setattr(Agent, "_update_agent_status", nothing)
    monkeypatch.setattr(Agent, "publish_manifest", nothing)
    monkeypatch.setattr(Agent, "start_registration_loop", lambda self: None)
    return blocked


def start_peer(kind, env, port):
    child_env = {**os.environ, **env, "PYTHONPATH": str(REPO_ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.Popen([sys.executable, str(PEER), kind], env=child_env, cwd=str(PEER.parent.parent.parent),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_for_port(port, deadline=30)
    except BaseException:
        proc.kill()
        raise
    return proc


def test_full_sentinel_network_round_trip(tmp_path, monkeypatch, offline):
    warden_id, analyst_id, auditor_id, client_id = (
        Identity.from_seed(s, 0) for s in (WARDEN_SEED, ANALYST_SEED, AUDITOR_SEED, CLIENT_SEED))
    warden_port, analyst_port, auditor_port, client_port = (free_port() for _ in range(4))
    url = lambda port: f"http://127.0.0.1:{port}/submit"  # noqa: E731

    # WARDEN is configured exactly as an operator would: by environment.
    for name, value in {
        "WARDEN_RISK_ANALYST": "remote", "WARDEN_RISK_ANALYST_ADDRESS": analyst_id.address,
        "WARDEN_RISK_ANALYST_ENDPOINT": url(analyst_port), "WARDEN_RISK_ANALYST_TIMEOUT_SECONDS": "10",
        "WARDEN_REMOTE_AUDITOR": "true", "WARDEN_AUDITOR_ADDRESS": auditor_id.address,
        "WARDEN_AUDITOR_ENDPOINT": url(auditor_port), "WARDEN_AUDITOR_TIMEOUT_SECONDS": "10",
        "WARDEN_HOSTED_ALLOW_INSECURE_ENDPOINT": "true", "WARDEN_AUDIT_LOG": str(tmp_path / "audit.jsonl"),
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(warden.config, "_DEFAULT_CONFIG", None)

    cfg = HostedConfig(public_endpoint=url(warden_port), port=warden_port, workspace_root=tmp_path / "hosted")
    hosted = build_hosted_agent(cfg, seed=WARDEN_SEED, resolver=RulesBasedResolver({client_id.address: url(client_port)}),
                                loop=asyncio.new_event_loop())
    hosted._report_events = False

    peers = [
        start_peer("risk", {"WARDEN_RISK_ANALYST_SEED": ANALYST_SEED, "WARDEN_RISK_ANALYST_PORT": str(analyst_port),
                            "WARDEN_RISK_ANALYST_ALLOWED_REQUESTER": warden_id.address}, analyst_port),
        start_peer("auditor", {"WARDEN_AUDITOR_SEED": AUDITOR_SEED, "WARDEN_AUDITOR_PORT": str(auditor_port),
                               "WARDEN_AUDITOR_WORKSPACE_ROOT": str(cfg.workspace_root),
                               "WARDEN_AUDITOR_ALLOWED_REQUESTER": warden_id.address}, auditor_port),
    ]
    try:
        run_network(cfg, hosted, warden_id, analyst_id, client_id, warden_port, client_port, url, tmp_path, offline)
    finally:
        for proc in peers:
            proc.kill()
            proc.wait(timeout=10)


def run_network(cfg, hosted, warden_id, analyst_id, client_id, warden_port, client_port, url, tmp_path, offline):

    outbox: "queue.Queue[str]" = queue.Queue()
    inbox: "queue.Queue[tuple]" = queue.Queue()
    client = Agent(name="asi-one-stand-in", seed=CLIENT_SEED, port=client_port, endpoint=[url(client_port)],
                   resolve=RulesBasedResolver({warden_id.address: url(warden_port)}), loop=asyncio.new_event_loop(),
                   report_events=False, publish_agent_details=False, mark_inactive_on_shutdown=False,
                   enable_agent_inspector=False)
    chat = Protocol(spec=chat_protocol_spec)

    @chat.on_message(model=ChatMessage)
    async def got_reply(ctx: Context, sender: str, msg: ChatMessage):
        inbox.put(("".join(c.text for c in msg.content if isinstance(c, TextContent)),
                   [dict(c.metadata) for c in msg.content if isinstance(c, MetadataContent)]))
        await ctx.send(sender, ChatAcknowledgement(acknowledged_msg_id=msg.msg_id))

    @chat.on_message(model=ChatAcknowledgement)
    async def got_ack(ctx: Context, sender: str, ack: ChatAcknowledgement):
        pass

    client.include(chat)

    @client.on_interval(period=0.3)
    async def pump(ctx: Context):
        while not outbox.empty():
            await ctx.send(warden_id.address, ChatMessage(content=[TextContent(type="text", text=outbox.get())]))

    for agent in (hosted, client):
        threading.Thread(target=agent.run, daemon=True).start()
    for port in (warden_port, client_port):
        wait_for_port(port)

    def ask(text, timeout=30):
        outbox.put(text)
        return inbox.get(timeout=timeout)

    # 1. Protected target: the analyst says CRITICAL, policy blocks; nothing is touched.
    text, cards = ask("delete production.env")
    assert "🚫 BLOCKED" in text and "CRITICAL" in text
    assert (cfg.workspace_root / "production.env").is_file()

    # 2. Destructive request: remote assessment, then approval required; nothing runs yet.
    text, (review,) = ask("delete debug.log")
    assert "🔒 AWAITING APPROVAL" in text and (cfg.workspace_root / "debug.log").is_file()
    payload = json.loads(review["card_payload"])
    rows = {r["label"]: r["value"] for r in payload["summary_rows"]}
    assert rows["Risk (advisory)"].startswith("HIGH") and "debug.log" in rows["Risk (advisory)"]
    selection = payload["approve_cta"]["selection"]

    # WARDEN accepted a signed remote assessment for exactly this action id and digest.
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    risk_events = [e["metadata"] for e in events if e["correlation_id"] == selection["action_id"]
                   and e["metadata"].get("stage") == "risk_analysis"]
    assert risk_events == [dict(risk_events[0], risk_status="ASSESSED", risk_source="remote",
                                action_digest=selection["digest"], risk_level="HIGH")]

    # 3. Click Approve: restricted executor runs exactly that action; the Auditor agent attests it.
    text, (result,) = ask(json.dumps(selection))
    assert "VERIFIED" in text and "Independently attested by the trusted remote auditor" in text
    assert result["is_terminal"] == "true" and '"label":"VERIFIED"' in result["card_payload"]
    assert "Risk analysis (advisory): HIGH" in result["card_payload"]
    assert not (cfg.workspace_root / "debug.log").exists() and (cfg.workspace_root / "cache.tmp").is_file()
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    (final,) = [e for e in events if e["correlation_id"] == selection["action_id"]
                and e["execution_status"] == "VERIFIED"]
    assert final["metadata"]["action_digest"] == selection["digest"]
    assert final["metadata"]["observed"]["remote_auditor"]["valid"] is True

    # 4. Replaying the click is refused; nothing runs twice.
    text, _ = ask(json.dumps(selection))
    assert "already been approved" in text

    for leaked in (str(tmp_path), WARDEN_SEED, ANALYST_SEED, AUDITOR_SEED, str(REPO_ROOT)):
        assert leaked not in text + json.dumps(review) + json.dumps(result)
    assert offline == [], f"unexpected non-loopback HTTP attempts: {offline}"


def test_unreachable_real_risk_analyst_is_unavailable_and_policy_still_decides(tmp_path, offline):
    warden_id, analyst_id = Identity.from_seed(WARDEN_SEED, 0), Identity.from_seed(ANALYST_SEED, 0)
    dead = f"http://127.0.0.1:{free_port()}/submit"  # nothing listens here
    transport = UAgentRiskTransport(analyst_id.address, warden_id,
                                    resolver=RulesBasedResolver({analyst_id.address: dead}))
    ws = Workspace(tmp_path / "ws")
    ws.create_synthetic_file("old.tmp", "junk")
    warden = WardenAgent(workspace=ws, risk_analyst=RemoteRiskAnalyst(transport, analyst_id.address, 3))
    res = warden.handle_action_request(Action(operation="DELETE", target="old.tmp"))
    assert res["status"].value == "AWAITING_APPROVAL" and res["risk"]["status"] == "UNAVAILABLE"
    assert ws.exists("old.tmp")
