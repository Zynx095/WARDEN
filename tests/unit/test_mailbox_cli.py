"""Agentverse Mailbox helper: status diagnostics and browser-free provisioning, all offline."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import aiohttp
import pytest
import requests
from uagents.mailbox import AgentverseConnectRequest
from uagents_core.identity import Identity

from warden.agents import mailbox
from warden.agents.run_agent import build_warden_agent
from warden.doctor import FAIL, PASS, WARN
from warden.hosting.config import DEFAULT_DESCRIPTION, DEFAULT_README, LISTING_METADATA, STARTER_PROMPTS

SEED = "mailbox-cli-test-seed-not-a-real-identity-01"
API_KEY = "test-agentverse-key-not-real"
IDENTITY = Identity.from_seed(SEED, 0)
ADDRESS = IDENTITY.address
MAILBOX_URL = "https://agentverse.ai/v2/agents/mailbox/submit"
CHAT = mailbox.CHAT_PROTOCOL_DIGEST


class Resp:
    def __init__(self, status=200, payload=None, headers=None):
        self.status_code = status
        self._payload = payload
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}

    def json(self):
        if self._payload is None:
            raise ValueError("not JSON")
        return self._payload


class FakeHttp:
    """Answers by (method, URL fragment); anything unrouted behaves like a refused connection."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def _answer(self, method, url, **kw):
        self.calls.append((method, url, kw))
        for (m, fragment), answer in self.routes.items():
            if m == method and fragment in url:
                if isinstance(answer, Exception):
                    raise answer
                return answer
        raise requests.ConnectionError("connection refused")

    def get(self, url, **kw):
        return self._answer("GET", url, **kw)

    def options(self, url, **kw):
        return self._answer("OPTIONS", url, **kw)


def agent_info(address=ADDRESS, endpoints=(MAILBOX_URL,), protocols=(CHAT,)):
    return Resp(200, {"address": address, "endpoints": [{"url": u, "weight": 1} for u in endpoints],
                      "protocols": list(protocols), "agent_type": "mailbox", "prefix": "agent", "port": 8000},
                headers={"Access-Control-Allow-Origin": "*"})


PREFLIGHT_OK = Resp(204, headers={"Access-Control-Allow-Private-Network": "true", "Access-Control-Allow-Origin": "*"})
ALMANAC_OK = Resp(200, {"status": "active", "type": "mailbox", "address": ADDRESS,
                        "endpoints": [{"url": MAILBOX_URL, "weight": 1}],
                        "protocols": [CHAT.removeprefix("proto:")], "expiry": "2026-10-31T00:00:00Z"})


def healthy_routes(overrides=None):
    routes = {
        ("GET", "/agent_info"): agent_info(),
        ("OPTIONS", "/agent_info"): PREFLIGHT_OK,
        ("GET", "/v1/almanac/agents/"): ALMANAC_OK,
        ("GET", "/mailbox"): Resp(200, []),
        ("GET", "/messages"): Resp(200, {"envelopes": [
            {"sender": "agent1qasione", "target": ADDRESS, "protocol_digest": CHAT, "timestamp": 1792800000,
             "schema_digest": mailbox.CHAT_MESSAGE_DIGEST, "payload": "please delete my secret notes"},
            {"sender": "agent1qasione", "target": ADDRESS, "protocol_digest": CHAT, "timestamp": 1792800002,
             "schema_digest": "model:acknowledgement", "payload": "ack"},
            {"sender": ADDRESS, "target": "agent1qasione", "protocol_digest": CHAT, "timestamp": 1792800001,
             "schema_digest": mailbox.CHAT_MESSAGE_DIGEST, "payload": "reply"},
        ]}),
    }
    routes.update(overrides or {})
    return routes


def status_output(http):
    lines = []
    code = mailbox.run_status(SEED, 8000, http=http, out=lines.append)
    return code, "\n".join(lines)


def by_name(checks, name):
    return next(c for c in checks if c.name == name)


# --- status -------------------------------------------------------------------------------

def test_status_passes_for_a_connected_mailbox_agent_and_shows_no_secrets_or_content():
    http = FakeHttp(healthy_routes())
    code, out = status_output(http)
    assert code == 0, out
    assert "0 failed" in out and "Inbound chat messages: 1 received" in out
    assert SEED not in out and "secret notes" not in out
    # The Inspector note tells the user that a remaining "Agent Not Found" is the browser's doing.
    assert "Apps on device" in out and "siteDetails?site=https%3A%2F%2Fagentverse.ai" in out


def test_status_when_no_agent_is_running():
    code, out = status_output(FakeHttp({k: v for k, v in healthy_routes().items() if k[1] not in ("/agent_info", "/messages")}))
    assert code == 1
    assert "[FAIL] Local agent: nothing answers at http://127.0.0.1:8000" in out
    assert "--mailbox" in out or "-Mailbox" in out
    assert "Inbound" not in out  # no point reading history from a process that is not there


def test_status_detects_a_stale_agent_holding_the_port():
    checks = mailbox.check_local_agent(ADDRESS, 8000, FakeHttp(healthy_routes({
        ("GET", "/agent_info"): agent_info(address="agent1qsomeoneelse0000000000000000000000000000000000000000")})))
    (local,) = checks
    assert local.status == FAIL and "different agent" in local.detail and "stop it" in local.fix


def test_status_flags_an_agent_without_mailbox_or_chat_protocol():
    checks = mailbox.check_local_agent(ADDRESS, 8000, FakeHttp(healthy_routes({
        ("GET", "/agent_info"): agent_info(endpoints=("http://127.0.0.1:8000/submit",), protocols=())})))
    assert by_name(checks, "Mailbox mode").status == FAIL
    assert by_name(checks, "Agent Chat Protocol").status == FAIL


def test_status_flags_missing_private_network_header():
    checks = mailbox.check_local_agent(ADDRESS, 8000, FakeHttp(healthy_routes({
        ("OPTIONS", "/agent_info"): Resp(204, headers={"Access-Control-Allow-Origin": "*"})})))
    assert by_name(checks, "Browser access headers").status == FAIL


def test_inspector_probe_identifies_itself_as_the_agentverse_origin():
    http = FakeHttp(healthy_routes())
    mailbox.check_local_agent(ADDRESS, 8000, http)
    sent = [kw["headers"] for method, url, kw in http.calls if url.endswith("/agent_info")]
    assert sent and all(h["Origin"] == "https://agentverse.ai" for h in sent)


def test_unprovisioned_mailbox_explains_both_ways_to_connect():
    (check,) = mailbox.check_mailbox(IDENTITY, FakeHttp(healthy_routes({("GET", "/mailbox"): Resp(404, {"detail": "x"})})))
    assert check.status == FAIL and "not provisioned" in check.detail
    assert "Connect -> Mailbox" in check.fix and "connect" in check.fix and "AGENTVERSE_API_KEY" in check.fix


def test_mailbox_check_authenticates_as_the_agent_never_with_the_api_key(monkeypatch):
    monkeypatch.setenv("AGENTVERSE_API_KEY", API_KEY)
    http = FakeHttp(healthy_routes())
    (check,) = mailbox.check_mailbox(IDENTITY, http)
    assert check.status == PASS and check.detail == "provisioned"
    ((method, url, kw),) = [c for c in http.calls if c[1].endswith("/mailbox")]
    assert url == f"https://agentverse.ai/v2/agents/{ADDRESS}/mailbox"
    assert kw["headers"]["Authorization"].startswith("Agent ") and API_KEY not in str(kw)


def test_mailbox_check_reports_refused_attestation_and_network_errors():
    refused = mailbox.check_mailbox(IDENTITY, FakeHttp(healthy_routes({("GET", "/mailbox"): Resp(401, {})})))
    assert refused[0].status == FAIL and "attestation" in refused[0].detail
    offline = mailbox.check_mailbox(IDENTITY, FakeHttp(healthy_routes({("GET", "/mailbox"): requests.Timeout()})))
    assert offline[0].status == WARN and "Timeout" in offline[0].detail


def test_almanac_record_must_route_to_the_mailbox_with_the_chat_protocol():
    proxy = Resp(200, {**ALMANAC_OK.json(), "endpoints": [{"url": "https://agentverse.ai/v2/agents/proxy/submit"}],
                       "protocols": []})
    checks = mailbox.check_almanac(ADDRESS, FakeHttp({("GET", "/v1/almanac/agents/"): proxy}))
    assert by_name(checks, "Almanac endpoint").status == FAIL
    assert by_name(checks, "Almanac protocols").status == FAIL
    missing = mailbox.check_almanac(ADDRESS, FakeHttp({("GET", "/v1/almanac/agents/"): Resp(404, {})}))
    assert missing[0].status == FAIL and "not registered" in missing[0].detail


def test_inbound_check_waits_for_a_first_message():
    (check,) = mailbox.check_inbound(ADDRESS, 8000, FakeHttp({("GET", "/messages"): Resp(200, {"envelopes": []})}))
    assert check.status == WARN and "none received" in check.detail


# --- connect ------------------------------------------------------------------------------

@pytest.fixture
def connect_env(monkeypatch, tmp_path):
    monkeypatch.setenv("WARDEN_WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.setenv("WARDEN_ENV_FILE", str(tmp_path / "absent.env"))
    monkeypatch.delenv("AGENTVERSE_DESCRIPTION", raising=False)
    monkeypatch.delenv("AGENTVERSE_README_PATH", raising=False)
    return tmp_path


def run_connect(confirm, register, http=None):
    lines = []
    code = mailbox.run_connect(SEED, confirm=confirm, http=http or FakeHttp(healthy_routes()),
                               register=register, out=lines.append)
    return code, "\n".join(lines)


def test_connect_dry_run_sends_nothing(connect_env, monkeypatch):
    monkeypatch.setenv("AGENTVERSE_API_KEY", API_KEY)
    register = AsyncMock(return_value=(True, ""))
    code, out = run_connect(False, register)
    assert code == 0 and "Dry run: nothing was sent." in out
    register.assert_not_called()
    assert ADDRESS in out and "Mailbox (endpoint https://agentverse.ai/v2/agents/mailbox/submit)" in out
    assert "AgentChatProtocol 0.3.0 included" in out
    assert SEED not in out and API_KEY not in out


def test_connect_without_api_key_refuses_and_says_where_the_key_goes(connect_env):
    register = AsyncMock(return_value=(True, ""))
    code, out = run_connect(True, register)
    assert code == 1
    register.assert_not_called()
    assert "AGENTVERSE_API_KEY is not set" in out and ".env" in out and "never paste" in out


def test_connect_confirm_registers_and_verifies_the_mailbox(connect_env, monkeypatch):
    monkeypatch.setenv("AGENTVERSE_API_KEY", API_KEY)
    register = AsyncMock(return_value=(True, ""))
    code, out = run_connect(True, register)
    assert code == 0, out
    (agent, key, registration), _ = register.call_args
    assert key == API_KEY and agent.address == ADDRESS
    assert registration.address == ADDRESS and [e.url for e in registration.endpoints] == [MAILBOX_URL]
    assert CHAT in registration.protocols
    assert registration.profile.readme == DEFAULT_README.read_text(encoding="utf-8")
    assert registration.profile.description == DEFAULT_DESCRIPTION
    assert registration.profile.starter_prompts == STARTER_PROMPTS and registration.metadata.model_dump(exclude_none=True) == LISTING_METADATA
    assert "[PASS] Agentverse mailbox: provisioned" in out
    assert API_KEY not in out and SEED not in out


def test_connect_reports_agentverse_refusal(connect_env, monkeypatch):
    monkeypatch.setenv("AGENTVERSE_API_KEY", API_KEY)
    code, out = run_connect(True, AsyncMock(return_value=(False, "Invalid token")))
    assert code == 1
    assert "[CONNECT FAILED] Agentverse: Invalid token" in out and "api-keys" in out
    assert API_KEY not in out
    code, out = run_connect(True, AsyncMock(return_value=(False, "Agent is already registered as proxy agent")))
    assert code == 1 and ("disconnect -Confirm" in out or "disconnect --confirm" in out)


def test_connect_reports_network_errors_without_secrets(connect_env, monkeypatch):
    monkeypatch.setenv("AGENTVERSE_API_KEY", API_KEY)
    code, out = run_connect(True, AsyncMock(side_effect=aiohttp.ClientConnectionError("unreachable")))
    assert code == 1 and "ClientConnectionError" in out and API_KEY not in out


def test_connect_sends_what_the_inspector_connect_button_sends(connect_env):
    """The browser-free path must register the same agent the SDK's /connect handler registers."""
    agent = build_warden_agent(seed=SEED, mailbox=True)
    with patch("uagents.agent.register_in_agentverse", new_callable=AsyncMock) as sdk_register:
        sdk_register.return_value = {"success": True}
        asyncio.run(agent.handle_rest("POST", "/connect", AgentverseConnectRequest(user_token=API_KEY, agent_type="mailbox")))
    inspector = sdk_register.call_args.kwargs

    registration = mailbox.build_mailbox_registration(agent, DEFAULT_README.read_text(encoding="utf-8"))
    with patch("uagents.mailbox.register_in_agentverse", new_callable=AsyncMock) as cli_register:
        cli_register.return_value = type("R", (), {"success": True, "detail": None})()
        assert asyncio.run(mailbox.register_mailbox(agent, API_KEY, registration)) == (True, "")
    cli = cli_register.call_args.kwargs

    assert cli["request"].agent_type == inspector["request"].agent_type == "mailbox"
    assert cli["request"].user_token == API_KEY
    assert cli["identity"].address == inspector["identity"].address == ADDRESS
    assert cli["prefix"] == inspector["prefix"] and cli["agentverse"] == inspector["agentverse"]
    for field in ("address", "name", "endpoints", "protocols", "url"):
        assert getattr(cli["agent_details"], field) == getattr(inspector["agent_details"], field), field
    assert cli["agent_details"].profile.readme == inspector["agent_details"].profile.readme


# --- command line -------------------------------------------------------------------------

def test_cli_requires_a_mode_and_a_seed(connect_env, capsys):
    with pytest.raises(SystemExit):
        mailbox.main(["connect"])
    assert mailbox.main(["connect", "--dry-run"]) == 1  # AGENT_SEED is not set
    assert "CONFIGURATION ERROR" in capsys.readouterr().err


def test_cli_dry_run_and_status_dispatch(connect_env, monkeypatch, capsys):
    monkeypatch.setenv("AGENT_SEED", SEED)
    assert mailbox.main(["connect", "--dry-run"]) == 0
    assert "nothing was sent" in capsys.readouterr().out
    with patch.object(mailbox, "run_status", return_value=1) as status:
        assert mailbox.main(["status", "--port", "8123"]) == 1
    status.assert_called_once_with(SEED, 8123, api_key=None)
    monkeypatch.setenv("AGENTVERSE_API_KEY", API_KEY)
    with patch.object(mailbox, "run_status", return_value=0) as status:
        assert mailbox.main(["status"]) == 0
    status.assert_called_once_with(SEED, 8000, api_key=API_KEY)
    with patch.object(mailbox, "run_disconnect", return_value=0) as disconnect:
        assert mailbox.main(["disconnect", "--dry-run"]) == 0
    disconnect.assert_called_once_with(SEED, confirm=False)


# --- Agentverse registration and disconnect -------------------------------------------------

def registration_routes(answer):
    return healthy_routes({("GET", f"/v2/agents/{ADDRESS}"): answer})


def test_status_with_api_key_shows_the_account_registration_without_printing_the_key():
    http = FakeHttp({**registration_routes(Resp(200, {"agent_type": "mailbox", "pending_messages": 0})),
                     ("GET", "/mailbox"): Resp(200, [])})
    lines = []
    assert mailbox.run_status(SEED, 8000, http=http, out=lines.append, api_key=API_KEY) == 0
    out = "\n".join(lines)
    assert "[PASS] Agentverse registration: registered as a mailbox agent" in out and API_KEY not in out
    (sent,) = [kw for method, url, kw in http.calls if url.endswith(f"/v2/agents/{ADDRESS}")]
    assert sent["headers"]["Authorization"] == f"Bearer {API_KEY}"


def test_registration_of_another_type_must_be_removed_before_the_mailbox_connects():
    (check,) = mailbox.check_registration(ADDRESS, API_KEY, FakeHttp(registration_routes(Resp(200, {"agent_type": "proxy"}))))
    assert check.status == FAIL and "registered as a proxy agent" in check.detail and "disconnect" in check.fix
    (missing,) = mailbox.check_registration(ADDRESS, API_KEY, FakeHttp(registration_routes(Resp(404, {}))))
    assert missing.status == FAIL and "Connect -> Mailbox" in missing.fix
    (refused,) = mailbox.check_registration(ADDRESS, API_KEY, FakeHttp(registration_routes(Resp(401, {}))))
    assert refused.status == WARN and "api-keys" in refused.fix


@pytest.mark.parametrize("detail, hint", [
    ("Agent agent1q... is already registered as proxy agent", "disconnect"),
    ("Agent address is owned by another user", "another Agentverse account"),
    ("Agent quota reached", "agent limit"),
    ("Invalid token", "api-keys"),
])
def test_connect_failures_name_the_next_step(detail, hint):
    assert hint in mailbox.connect_failure_fix(detail)


def test_disconnect_dry_run_and_missing_key_send_nothing(connect_env):
    unregister = AsyncMock(return_value=(True, ""))
    lines = []
    assert mailbox.run_disconnect(SEED, confirm=False, unregister=unregister, out=lines.append) == 0
    assert mailbox.run_disconnect(SEED, confirm=True, unregister=unregister, out=lines.append) == 1
    unregister.assert_not_called()
    assert "Dry run: nothing was sent." in lines and any("AGENTVERSE_API_KEY is not set" in line for line in lines)


def test_disconnect_confirm_uses_the_sdk_unregister_call(connect_env, monkeypatch):
    monkeypatch.setenv("AGENTVERSE_API_KEY", API_KEY)
    lines = []
    with patch("uagents.mailbox.unregister_in_agentverse", new_callable=AsyncMock) as sdk_unregister:
        sdk_unregister.return_value = type("R", (), {"success": True, "detail": None})()
        assert mailbox.run_disconnect(SEED, confirm=True, out=lines.append) == 0
    kwargs = sdk_unregister.call_args.kwargs
    assert kwargs["agent_address"] == ADDRESS and kwargs["request"].user_token == API_KEY
    out = "\n".join(lines)
    assert "[PASS] Removed" in out and "connect" in out and API_KEY not in out
    failing = AsyncMock(return_value=(False, "Agent not found"))
    assert mailbox.run_disconnect(SEED, confirm=True, unregister=failing, out=lines.append) == 1
    assert "[DISCONNECT FAILED] Agentverse: Agent not found" in lines
