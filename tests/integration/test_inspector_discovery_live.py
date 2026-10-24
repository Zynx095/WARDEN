"""Live loopback run of the mailbox-mode runner: what the Agentverse Inspector and the status check see.

Real HTTP against the WARDEN runner's embedded server (CORS and Private Network Access
headers, origin guard, loopback-only proxy trust) and a real Agent Chat Protocol exchange with
a stand-in client. Mailbox polling and every Agentverse/Almanac call are disabled and any
non-loopback HTTP fails the test, so nothing leaves this machine.
"""

import asyncio
import queue
import socket
import threading
import time
from unittest.mock import AsyncMock, patch
from urllib.parse import urlparse

import aiohttp
import pytest
import requests
from uagents import Agent, Context, Protocol, asgi
from uagents.crypto import Identity
from uagents.mailbox import MailboxClient
from uagents.resolver import RulesBasedResolver
from uagents_core.contrib.protocols.chat import ChatAcknowledgement, ChatMessage, TextContent, chat_protocol_spec

from warden.agents import mailbox
from warden.agents.run_agent import build_warden_agent, enable_inspector_pna_cors, restrict_bind_host
from warden.doctor import FAIL, PASS, WARN

WARDEN_SEED = "inspector-live-test-warden-seed-not-real-01"
CLIENT_SEED = "inspector-live-test-client-seed-not-real-02"
LOOPBACK = {"127.0.0.1", "localhost"}
AGENTVERSE = "https://agentverse.ai"


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
    """Disable SDK publishing and mailbox polling; fail loudly on any non-loopback HTTP."""
    blocked = []
    original_aiohttp = aiohttp.ClientSession._request

    async def guarded_aiohttp(self, method, url, *a, **kw):
        if urlparse(str(url)).hostname not in LOOPBACK:
            blocked.append(str(url))
            raise aiohttp.ClientConnectionError("network disabled in tests")
        return await original_aiohttp(self, method, url, *a, **kw)

    original_requests = requests.Session.request

    def guarded_requests(self, method, url, *a, **kw):
        if urlparse(str(url)).hostname not in LOOPBACK:
            blocked.append(str(url))
            raise requests.ConnectionError("network disabled in tests")
        return original_requests(self, method, url, *a, **kw)

    async def no_op(*args, **kwargs):
        return None

    monkeypatch.setattr(aiohttp.ClientSession, "_request", guarded_aiohttp)
    monkeypatch.setattr(requests.Session, "request", guarded_requests)
    monkeypatch.setattr(Agent, "_update_agent_status", no_op)
    monkeypatch.setattr(Agent, "publish_manifest", no_op)
    monkeypatch.setattr(Agent, "start_registration_loop", lambda self: None)
    monkeypatch.setattr(MailboxClient, "run", no_op)
    # Restore the SDK's module/class state after the runner's process-wide patches.
    monkeypatch.setattr(asgi, "HOST", asgi.HOST)
    monkeypatch.setattr(asgi.ASGIServer, "serve", asgi.ASGIServer.serve)
    monkeypatch.setattr(asgi.ASGIServer, "_pna_cors_enabled", False, raising=False)
    return blocked


def test_mailbox_runner_serves_the_inspector_and_reports_inbound_chat(tmp_path, offline):
    warden_port, client_port = free_port(), free_port()
    warden_url = f"http://127.0.0.1:{warden_port}/submit"
    client_url = f"http://127.0.0.1:{client_port}/submit"
    client_id = Identity.from_seed(CLIENT_SEED, 0)

    assert restrict_bind_host("127.0.0.1") and enable_inspector_pna_cors()
    warden = build_warden_agent(seed=WARDEN_SEED, port=warden_port, mailbox=True, workspace_dir=tmp_path / "ws",
                                resolver=RulesBasedResolver({client_id.address: client_url}),
                                loop=asyncio.new_event_loop())
    warden._report_events = False
    assert warden._use_mailbox

    replies: "queue.Queue[str]" = queue.Queue()
    outbox: "queue.Queue[str]" = queue.Queue()
    client = Agent(name="asi-one-stand-in", seed=CLIENT_SEED, port=client_port, endpoint=[client_url],
                   resolve=RulesBasedResolver({warden.address: warden_url}), loop=asyncio.new_event_loop(),
                   report_events=False, publish_agent_details=False, mark_inactive_on_shutdown=False,
                   enable_agent_inspector=False)
    chat = Protocol(spec=chat_protocol_spec)

    @chat.on_message(model=ChatMessage)
    async def got_reply(ctx: Context, sender: str, msg: ChatMessage):
        replies.put("".join(c.text for c in msg.content if isinstance(c, TextContent)))
        await ctx.send(sender, ChatAcknowledgement(acknowledged_msg_id=msg.msg_id))

    @chat.on_message(model=ChatAcknowledgement)
    async def got_ack(ctx: Context, sender: str, ack: ChatAcknowledgement):
        pass

    client.include(chat)

    @client.on_interval(period=0.3)
    async def pump(ctx: Context):
        while not outbox.empty():
            await ctx.send(warden.address, ChatMessage(content=[TextContent(type="text", text=outbox.get())]))

    for agent in (warden, client):
        threading.Thread(target=agent.run, daemon=True).start()
    wait_for_port(warden_port)
    wait_for_port(client_port)
    base = f"http://127.0.0.1:{warden_port}"

    # What the Inspector's browser fetch gets.
    info = requests.get(f"{base}/agent_info", headers={"Origin": AGENTVERSE}, timeout=5)
    assert info.status_code == 200 and info.json()["address"] == warden.address
    assert info.headers["access-control-allow-origin"] == "*"
    preflight = requests.options(f"{base}/agent_info", timeout=5, headers={
        "Origin": AGENTVERSE, "Access-Control-Request-Method": "GET", "Access-Control-Request-Private-Network": "true"})
    assert preflight.status_code == 204 and preflight.headers["access-control-allow-private-network"] == "true"

    # Other web origins get nothing, and cannot re-register the agent through /connect.
    assert requests.get(f"{base}/agent_info", headers={"Origin": "https://evil.example"}, timeout=5).status_code == 403
    assert requests.get(f"{base}/messages", headers={"Origin": "https://evil.example"}, timeout=5).status_code == 403
    with patch("uagents.agent.register_in_agentverse", new_callable=AsyncMock) as register:
        forged = requests.post(f"{base}/connect", data='{"user_token": "attacker", "agent_type": "mailbox"}',
                               headers={"Origin": "https://evil.example", "Content-Type": "text/plain"}, timeout=5)
        assert forged.status_code == 403
        register.assert_not_called()

    # The status check against the real server: everything the Inspector needs is in place.
    local = mailbox.check_local_agent(warden.address, warden_port)
    assert [c.status for c in local] == [PASS] * 4, local
    stale = mailbox.check_local_agent(client_id.address, warden_port)
    assert stale[0].status == FAIL and "different agent" in stale[0].detail
    assert mailbox.check_inbound(warden.address, warden_port)[0].status == WARN

    # A real Agent Chat Protocol message reaches WARDEN, is answered, and shows up in the check.
    outbox.put("List the files in the WARDEN workspace")
    reply = replies.get(timeout=20)
    assert "WARDEN" in reply or "workspace" in reply.lower()
    (inbound,) = mailbox.check_inbound(warden.address, warden_port)
    assert inbound.status == PASS and inbound.detail.startswith("1 received") and "List the files" not in inbound.detail

    assert offline == [], f"unexpected non-loopback HTTP attempts: {offline}"
