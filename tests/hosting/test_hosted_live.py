"""Live loopback run of the hosted entry point: real HTTP, real uAgents envelopes, no internet.

A client uAgent stands in for ASI:One. Startup calls that would publish the throwaway test
identities (Almanac status/registration, manifest, telemetry) are disabled, and a guard
fails any HTTP request to a non-loopback host, so nothing leaves this machine.
"""

import asyncio
import json
import queue
import re
import socket
import threading
import time
import urllib.error
import urllib.request
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

from warden.hosting.config import HostedConfig
from warden.hosting.server import HEALTH_ROUTE, build_hosted_agent
from warden.integrations.cards import validate_card_metadata

WARDEN_SEED = "hosted-live-test-warden-seed-not-real-01"
CLIENT_SEED = "hosted-live-test-client-seed-not-real-02"
LOOPBACK = {"127.0.0.1", "localhost"}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def offline(monkeypatch):
    """Disable SDK publishing calls and fail loudly on any non-loopback HTTP."""
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

    async def no_status_update(self, active):
        return None

    async def no_manifest(self, manifest):
        return None

    monkeypatch.setattr(aiohttp.ClientSession, "_request", guarded_aiohttp)
    monkeypatch.setattr(requests.Session, "request", guarded_requests)
    monkeypatch.setattr(Agent, "_update_agent_status", no_status_update)
    monkeypatch.setattr(Agent, "publish_manifest", no_manifest)
    monkeypatch.setattr(Agent, "start_registration_loop", lambda self: None)
    return blocked


def wait_for_port(port, deadline=15):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.2)
    pytest.fail(f"nothing listening on {port}")


def test_hosted_agent_serves_health_and_a_full_approval_round_trip(tmp_path, monkeypatch, offline):
    warden_port, client_port = free_port(), free_port()
    warden_id = Identity.from_seed(WARDEN_SEED, 0)
    client_id = Identity.from_seed(CLIENT_SEED, 0)
    warden_url = f"http://127.0.0.1:{warden_port}/submit"
    client_url = f"http://127.0.0.1:{client_port}/submit"

    monkeypatch.setenv("WARDEN_HOSTED_ALLOW_INSECURE_ENDPOINT", "true")
    from uagents import asgi
    monkeypatch.setattr(asgi, "_read_asgi_body", asgi._read_asgi_body)  # restore the SDK reader afterwards
    cfg = HostedConfig(public_endpoint=warden_url, port=warden_port, workspace_root=tmp_path / "hosted")
    warden = build_hosted_agent(
        cfg, seed=WARDEN_SEED, resolver=RulesBasedResolver({client_id.address: client_url}),
        loop=asyncio.new_event_loop(),
    )
    warden._report_events = False

    outbox: "queue.Queue[str]" = queue.Queue()
    inbox: "queue.Queue[str]" = queue.Queue()
    card_inbox: "queue.Queue[list]" = queue.Queue()
    client = Agent(
        name="asi-one-stand-in", seed=CLIENT_SEED, port=client_port, endpoint=[client_url],
        resolve=RulesBasedResolver({warden_id.address: warden_url}), loop=asyncio.new_event_loop(),
        report_events=False, publish_agent_details=False, mark_inactive_on_shutdown=False,
        enable_agent_inspector=False,
    )
    chat = Protocol(spec=chat_protocol_spec)

    @chat.on_message(model=ChatMessage)
    async def got_reply(ctx: Context, sender: str, msg: ChatMessage):
        card_inbox.put([dict(c.metadata) for c in msg.content if isinstance(c, MetadataContent)])
        inbox.put("".join(c.text for c in msg.content if isinstance(c, TextContent)))
        await ctx.send(sender, ChatAcknowledgement(acknowledged_msg_id=msg.msg_id))

    @chat.on_message(model=ChatAcknowledgement)
    async def got_ack(ctx: Context, sender: str, ack: ChatAcknowledgement):
        pass

    client.include(chat)

    @client.on_interval(period=0.3)
    async def pump(ctx: Context):
        while not outbox.empty():
            await ctx.send(warden_id.address, ChatMessage(content=[TextContent(type="text", text=outbox.get())]))

    for agent in (warden, client):
        threading.Thread(target=agent.run, daemon=True).start()
    wait_for_port(warden_port)
    wait_for_port(client_port)

    last_cards: list = []

    def ask(text, timeout=20):
        outbox.put(text)
        reply = inbox.get(timeout=timeout)
        last_cards[:] = card_inbox.get(timeout=timeout)
        return reply

    health = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{warden_port}{HEALTH_ROUTE}", timeout=5).read())
    assert health["status"] == "ok" and health["workspace_ready"] is True
    assert health["agent_address"] == warden_id.address
    assert str(tmp_path) not in json.dumps(health)

    blocked_reply = ask("delete production.env")
    assert "[BLOCKED]" in blocked_reply and (tmp_path / "hosted" / "production.env").is_file()

    pending_reply = ask("delete cache.tmp")
    action_id, digest = re.search(r"APPROVE\s+([a-f0-9\-]+)\s+([a-f0-9]{64})", pending_reply).groups()
    assert (tmp_path / "hosted" / "cache.tmp").is_file()

    final = ask(f"APPROVE {action_id} {digest}")
    assert "VERIFIED" in final and not (tmp_path / "hosted" / "cache.tmp").exists()
    assert str(tmp_path) not in blocked_reply + pending_reply + final

    # Interactive card over the wire: the review card arrives intact and its button selection,
    # sent back as a chat message, goes through the same checks.
    ask("delete debug.log")
    (review,) = last_cards
    validate_card_metadata(review)
    assert review["card_kind"] == "review"
    selection = json.loads(review["card_payload"])["approve_cta"]["selection"]
    clicked = ask(json.dumps(selection))
    (result_card,) = last_cards
    assert result_card["is_terminal"] == "true" and '"label":"VERIFIED"' in result_card["card_payload"]
    assert "VERIFIED" in clicked and not (tmp_path / "hosted" / "debug.log").exists()
    assert str(tmp_path) not in json.dumps(review) + json.dumps(result_card)

    # Endpoint exposure: only /submit and /health. The SDK's inspector routes (/connect could
    # re-register this identity in someone else's Agentverse account) are not served, even to
    # a caller that spoofs a loopback client through proxy headers.
    def http(method, path, body=b"", headers=None):
        req = urllib.request.Request(f"http://127.0.0.1:{warden_port}{path}", data=body or None, method=method,
                                     headers={"content-type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status
        except urllib.error.HTTPError as err:
            return err.code

    spoof = {"x-forwarded-for": "127.0.0.1"}
    connect = json.dumps({"user_token": "x", "agent_type": "mailbox", "endpoint": "https://attacker.example/submit"})
    assert http("POST", "/connect", connect.encode(), spoof) == 404
    assert http("POST", "/disconnect", b"{}", spoof) == 404
    assert http("GET", "/messages", headers=spoof) == 404
    assert http("GET", "/agent_info") == 404
    # Oversized bodies are refused before parsing.
    assert http("POST", "/submit", b'{"pad":"' + b"x" * (cfg.max_request_bytes + 1) + b'"}') == 400

    assert offline == [], f"unexpected non-loopback HTTP attempts: {offline}"
