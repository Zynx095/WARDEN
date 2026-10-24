"""Agentverse Mailbox for the local WARDEN agent: check it, and connect it without a browser.

    python -m warden.agents.mailbox status                what the Inspector sees, the Almanac record, the mailbox
    python -m warden.agents.mailbox connect --dry-run     show the registration; send nothing
    python -m warden.agents.mailbox connect --confirm     register this agent as an Agentverse Mailbox agent
    python -m warden.agents.mailbox disconnect --confirm  remove its Agentverse registration (to re-connect)

``connect`` sends what the Agentverse Inspector's "Connect -> Mailbox" makes the running agent
send (uAgents' own ``register_in_agentverse``: an identity challenge signed with this agent's
key, then its mailbox endpoint, Agent Chat Protocol digest and public profile). It needs
``AGENTVERSE_API_KEY`` and is the way to connect when a browser may not reach 127.0.0.1. It
creates no identity: the address comes from ``AGENT_SEED``. Secrets are read from the
environment or ``.env`` and never printed; ``status`` never shows message contents.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from secrets import token_bytes
from typing import Callable, List, Optional, Tuple

import requests
from uagents import Agent
from uagents_core.config import AgentverseConfig
from uagents_core.contrib.protocols.chat import ChatMessage, chat_protocol_spec
from uagents_core.identity import Identity
from uagents_core.models import Model
from uagents_core.protocol import ProtocolSpecification
from uagents_core.registration import AgentProfile, RegistrationRequest
from uagents_core.storage import compute_attestation

from warden.agents.run_agent import DEFAULT_PORT, LOOPBACK_HOST, build_warden_agent, inspector_url, mailbox_command
from warden.config import ConfigError, load_environment
from warden.doctor import FAIL, PASS, WARN, Check
from warden.hosting.config import DEFAULT_DESCRIPTION, DEFAULT_README, LISTING_METADATA, STARTER_PROMPTS
from warden.identity import AgentIdentityError, validate_seed

AGENTVERSE = AgentverseConfig()
CHAT_PROTOCOL_DIGEST = ProtocolSpecification.compute_digest(chat_protocol_spec.manifest())
CHAT_MESSAGE_DIGEST = Model.build_schema_digest(ChatMessage)
INSPECTOR_ORIGIN = "https://agentverse.ai"
SITE_SETTINGS_URL = "chrome://settings/content/siteDetails?site=https%3A%2F%2Fagentverse.ai"
HTTP_TIMEOUT = 10.0
LOCAL_TIMEOUT = 3.0
REGISTRATION_TIMEOUT = 60.0


RUN_HINT = (".\\scripts\\run.ps1 -Mailbox -PublishManifest -DemoWorkspace" if os.name == "nt"
            else "python -m warden.agents.run_agent --mailbox --publish-manifest --demo-workspace")
INSPECTOR_HINT = "open the Inspector URL (signed in to Agentverse) -> Connect -> Mailbox"
CONNECT_HINT = (f"{INSPECTOR_HINT}, or put AGENTVERSE_API_KEY in .env and run: "
                f"{mailbox_command('connect -Confirm', 'connect --confirm')}")


def _short(address: str) -> str:
    return f"{address[:14]}...{address[-6:]}" if len(address) > 24 else address or "?"


def _digest_hex(digest: str) -> str:
    return str(digest).removeprefix("proto:")


def check_local_agent(address: str, port: int, http=requests) -> List[Check]:
    """What the Agentverse Inspector sees: the browser at agentverse.ai fetches /agent_info."""
    base = f"http://{LOOPBACK_HOST}:{port}"
    try:
        resp = http.get(f"{base}/agent_info", headers={"Origin": INSPECTOR_ORIGIN}, timeout=LOCAL_TIMEOUT)
    except requests.RequestException:
        return [Check(FAIL, "Local agent", f"nothing answers at {base}", f"start WARDEN in mailbox mode: {RUN_HINT}")]
    if resp.status_code != 200:
        return [Check(FAIL, "Local agent", f"{base}/agent_info answered HTTP {resp.status_code}",
                      f"port {port} is held by another program or an agent without the Inspector routes; "
                      f"stop it and start WARDEN: {RUN_HINT}")]
    try:
        info = resp.json()
    except ValueError:
        return [Check(FAIL, "Local agent", f"{base}/agent_info did not return JSON", f"stop that program; {RUN_HINT}")]
    served = str(info.get("address") or "")
    if served != address:
        return [Check(FAIL, "Local agent", f"port {port} serves a different agent ({_short(served)})",
                      f"a stale or different agent holds port {port} and the Inspector would connect it instead; "
                      f"stop it (owner: Get-NetTCPConnection -LocalPort {port}) and restart WARDEN")]
    checks = [Check(PASS, "Local agent", f"{base}/agent_info answers for {_short(address)}")]

    endpoints = [str(e.get("url")) for e in info.get("endpoints") or [] if isinstance(e, dict)]
    mailbox = AGENTVERSE.mailbox_endpoint in endpoints
    checks.append(Check(PASS if mailbox else FAIL, "Mailbox mode",
                        "advertises the Agentverse mailbox endpoint" if mailbox else f"endpoints: {endpoints or 'none'}",
                        "restart the agent with --mailbox (and without --endpoint)"))

    chat = CHAT_PROTOCOL_DIGEST in [str(p) for p in info.get("protocols") or []]
    checks.append(Check(PASS if chat else FAIL, "Agent Chat Protocol",
                        "AgentChatProtocol 0.3.0 included" if chat else "not included",
                        "run the WARDEN runner (python -m warden.agents.run_agent), which includes it"))

    allow_origin = resp.headers.get("access-control-allow-origin", "")
    try:
        preflight = http.options(f"{base}/agent_info", timeout=LOCAL_TIMEOUT, headers={
            "Origin": INSPECTOR_ORIGIN, "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Private-Network": "true"})
        private_network = (preflight.status_code < 300 and
                           preflight.headers.get("access-control-allow-private-network", "").lower() == "true")
    except requests.RequestException:
        private_network = False
    headers_ok = allow_origin in ("*", INSPECTOR_ORIGIN) and private_network
    checks.append(Check(PASS if headers_ok else FAIL, "Browser access headers",
                        f"CORS and Private Network Access allow {INSPECTOR_ORIGIN}" if headers_ok else
                        f"Access-Control-Allow-Origin={allow_origin or 'missing'}, private-network preflight "
                        f"{'accepted' if private_network else 'not accepted'}",
                        "start the agent with the WARDEN runner, which sends these headers"))
    return checks


def check_almanac(address: str, http=requests) -> List[Check]:
    """The public routing record other agents, Agentverse and ASI:One resolve this address with."""
    try:
        resp = http.get(f"{AGENTVERSE.almanac_api}/agents/{address}", timeout=HTTP_TIMEOUT)
    except requests.RequestException as exc:
        return [Check(WARN, "Almanac record", f"could not reach {AGENTVERSE.url} ({type(exc).__name__})",
                      "check the internet connection and run status again")]
    if resp.status_code == 404:
        return [Check(FAIL, "Almanac record", "this address is not registered",
                      f"start the agent in mailbox mode; it registers itself on startup: {RUN_HINT}")]
    if resp.status_code != 200:
        return [Check(WARN, "Almanac record", f"unexpected HTTP {resp.status_code}", "run status again in a minute")]
    try:
        record = resp.json()
    except ValueError:
        return [Check(WARN, "Almanac record", "response was not JSON", "run status again in a minute")]
    endpoints = [str(e.get("url")) for e in record.get("endpoints") or [] if isinstance(e, dict)]
    mailbox = AGENTVERSE.mailbox_endpoint in endpoints
    chat = _digest_hex(CHAT_PROTOCOL_DIGEST) in [_digest_hex(p) for p in record.get("protocols") or []]
    active = record.get("status") == "active"
    return [
        Check(PASS if mailbox else FAIL, "Almanac endpoint",
              "routes to the Agentverse mailbox" if mailbox else f"routes to {endpoints or 'nothing'}",
              f"restart the agent with --mailbox; it re-registers on startup: {RUN_HINT}"),
        Check(PASS if chat else FAIL, "Almanac protocols",
              "AgentChatProtocol listed" if chat else "AgentChatProtocol missing",
              f"restart the agent with the WARDEN runner: {RUN_HINT}"),
        Check(PASS if active else WARN, "Almanac status",
              f"{record.get('status') or 'unknown'}, registration expires {record.get('expiry') or 'unknown'}",
              f"start the agent; it marks itself active: {RUN_HINT}"),
    ]


def mailbox_attestation(identity: Identity) -> str:
    """Short-lived token, signed by the agent's key, that the Agentverse mailbox API accepts."""
    return compute_attestation(identity=identity, validity_start=datetime.now(timezone.utc),
                               validity_secs=60, nonce=token_bytes(32))


def check_mailbox(identity: Identity, http=requests) -> List[Check]:
    """Whether Agentverse holds a mailbox for this address. Reads only; collects no message."""
    try:
        resp = http.get(f"{AGENTVERSE.agents_api}/{identity.address}/mailbox", timeout=HTTP_TIMEOUT,
                        headers={"Authorization": f"Agent {mailbox_attestation(identity)}"})
    except requests.RequestException as exc:
        return [Check(WARN, "Agentverse mailbox", f"could not reach {AGENTVERSE.url} ({type(exc).__name__})",
                      "check the internet connection and run status again")]
    if resp.status_code == 200:
        try:
            waiting = len(resp.json())
        except (ValueError, TypeError):
            waiting = 0
        detail = "provisioned" + (f"; {waiting} message(s) waiting for the agent to collect" if waiting else "")
        return [Check(PASS, "Agentverse mailbox", detail)]
    if resp.status_code == 404:
        return [Check(FAIL, "Agentverse mailbox", "not provisioned for this address (HTTP 404)", CONNECT_HINT)]
    if resp.status_code in (401, 403):
        return [Check(FAIL, "Agentverse mailbox", f"Agentverse refused the agent's signed attestation "
                      f"(HTTP {resp.status_code})", "check the system clock, then run status again")]
    return [Check(WARN, "Agentverse mailbox", f"unexpected HTTP {resp.status_code}", "run status again in a minute")]


def check_registration(address: str, api_key: str, http=requests) -> List[Check]:
    """The agent's entry in your Agentverse account (the record the Inspector shows), via the API key."""
    try:
        resp = http.get(f"{AGENTVERSE.agents_api}/{address}", timeout=HTTP_TIMEOUT,
                        headers={"Authorization": f"Bearer {api_key}"})
    except requests.RequestException as exc:
        return [Check(WARN, "Agentverse registration", f"could not reach {AGENTVERSE.url} ({type(exc).__name__})",
                      "check the internet connection and run status again")]
    if resp.status_code == 404:
        return [Check(FAIL, "Agentverse registration", "not registered in the account of AGENTVERSE_API_KEY",
                      CONNECT_HINT)]
    if resp.status_code in (401, 403):
        return [Check(WARN, "Agentverse registration", f"AGENTVERSE_API_KEY was refused (HTTP {resp.status_code})",
                      "create a new key at https://agentverse.ai/profile/api-keys and update .env")]
    if resp.status_code != 200:
        return [Check(WARN, "Agentverse registration", f"unexpected HTTP {resp.status_code}", "run status again in a minute")]
    try:
        record = resp.json()
    except ValueError:
        record = {}
    agent_type = str(record.get("agent_type") or "").lower() if isinstance(record, dict) else ""
    if agent_type and agent_type != "mailbox":
        return [Check(FAIL, "Agentverse registration", f"registered as a {agent_type} agent, not a mailbox agent",
                      f"remove that registration ({mailbox_command('disconnect -Confirm', 'disconnect --confirm')}, "
                      "or delete the agent under Agentverse -> My Agents), then connect the mailbox")]
    return [Check(PASS if agent_type else WARN, "Agentverse registration",
                  "registered as a mailbox agent in your account" if agent_type else
                  "registered in your account (type not reported)")]


def check_inbound(address: str, port: int, http=requests) -> List[Check]:
    """Agent Chat Protocol messages the running agent has received (counts only, never content)."""
    try:
        resp = http.get(f"http://{LOOPBACK_HOST}:{port}/messages", timeout=LOCAL_TIMEOUT)
        envelopes = resp.json().get("envelopes") if resp.status_code == 200 else None
    except (requests.RequestException, ValueError, AttributeError):
        envelopes = None
    if not isinstance(envelopes, list):
        return [Check(WARN, "Inbound chat messages", "the agent's message history is not available",
                      "start the agent with the WARDEN runner (the Inspector routes keep the history)")]
    chat = [e for e in envelopes if isinstance(e, dict) and e.get("target") == address
            and e.get("sender") != address and e.get("schema_digest") == CHAT_MESSAGE_DIGEST]
    if not chat:
        return [Check(WARN, "Inbound chat messages", "none received since the agent started",
                      "send one from ASI:One or from the agent's Agentverse page, then run status again")]
    last = max(chat, key=lambda e: e.get("timestamp") or 0)
    when = datetime.fromtimestamp(int(last.get("timestamp") or 0), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return [Check(PASS, "Inbound chat messages",
                  f"{len(chat)} received since the agent started; last at {when} from {_short(str(last.get('sender')))}")]


def run_status(seed: str, port: int, http=requests, out: Callable[[str], None] = print,
               api_key: Optional[str] = None) -> int:
    identity = Identity.from_seed(seed, 0)
    out("WARDEN Agentverse mailbox status")
    out(f"Agent address: {identity.address}")
    out(f"Inspector URL: {inspector_url(identity.address, port, AGENTVERSE.url)}")
    counts = {PASS: 0, WARN: 0, FAIL: 0}

    def section(title: str, checks: List[Check]) -> List[Check]:
        out(f"\n== {title} ==")
        for c in checks:
            counts[c.status] += 1
            out(f"[{c.status}] {c.name}" + (f": {c.detail}" if c.detail else ""))
            if c.status != PASS and c.fix:
                out(f"       fix: {c.fix}")
        return checks

    local = section("Local agent (what the Agentverse Inspector reads)", check_local_agent(identity.address, port, http))
    if all(c.status == PASS for c in local):
        out("note: the agent serves the Inspector correctly. If the Inspector still says 'Agent Not Found',")
        out("      the browser blocked agentverse.ai from reaching 127.0.0.1: allow 'Apps on device' (Local")
        out(f"      Network Access) for https://agentverse.ai at {SITE_SETTINGS_URL}")
        out("      (brave:// or edge:// in those browsers), then reload the Inspector page.")
    section("Almanac (public routing record)", check_almanac(identity.address, http))
    if api_key:
        section("Agentverse registration (account of AGENTVERSE_API_KEY)",
                check_registration(identity.address, api_key, http))
    section("Agentverse mailbox", check_mailbox(identity, http))
    if local and local[0].status == PASS:
        section("Inbound Agent Chat Protocol messages", check_inbound(identity.address, port, http))
    out(f"\nSummary: {counts[PASS]} passed, {counts[WARN]} warnings, {counts[FAIL]} failed.")
    return 1 if counts[FAIL] else 0


def build_mailbox_registration(agent: Agent, readme: str, description: str = DEFAULT_DESCRIPTION) -> RegistrationRequest:
    """What the Inspector's Connect -> Mailbox makes the agent send, with WARDEN's public profile."""
    return RegistrationRequest(
        address=agent.address,
        name=agent.name,
        url=None,
        profile=AgentProfile(description=description, readme=readme, starter_prompts=list(STARTER_PROMPTS)),
        endpoints=agent._endpoints,
        protocols=list(agent.protocols.keys()),
        metadata=dict(LISTING_METADATA),
    )


async def register_mailbox(agent: Agent, api_key: str, registration: RegistrationRequest) -> Tuple[bool, str]:
    """Agentverse identity challenge, signed proof and registration, via the SDK's own code path."""
    from uagents.mailbox import AgentverseConnectRequest, register_in_agentverse

    response = await asyncio.wait_for(
        register_in_agentverse(
            request=AgentverseConnectRequest(user_token=api_key, agent_type="mailbox"),
            identity=agent._identity,
            prefix=agent._prefix,
            agentverse=agent._agentverse,
            agent_details=registration,
        ),
        timeout=REGISTRATION_TIMEOUT,
    )
    return response.success, response.detail or ""


def connect_failure_fix(detail: str) -> str:
    """Next step for the refusals the Agentverse Inspector also distinguishes."""
    text = (detail or "").lower()
    if "already registered as" in text:
        return ("this address is already registered with another connection type (for example the hosted "
                f"registration). Remove it with {mailbox_command('disconnect -Confirm', 'disconnect --confirm')} "
                "or under Agentverse -> My Agents, then connect again.")
    if "owned by another user" in text:
        return ("the address belongs to another Agentverse account: use that account's key, or a different "
                "AGENT_SEED (which is a different agent).")
    if "quota" in text or "limit" in text:
        return "your Agentverse plan's agent limit is reached: remove an agent you no longer use."
    return ("an invalid or expired key needs a new one (https://agentverse.ai/profile/api-keys); an address "
            "registered under another account must be connected with that account's key.")


def run_connect(seed: str, confirm: bool, readme_path: Optional[Path] = None, http=requests,
                register=register_mailbox, out: Callable[[str], None] = print) -> int:
    readme_file = Path(readme_path or os.getenv("AGENTVERSE_README_PATH") or DEFAULT_README)
    try:
        readme = readme_file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise ConfigError(f"Agentverse README not found or not UTF-8 text: {readme_file.name}") from None
    description = (os.getenv("AGENTVERSE_DESCRIPTION") or DEFAULT_DESCRIPTION).strip()
    agent = build_warden_agent(seed=seed, mailbox=True, enable_agent_inspector=False,
                               description=description, readme_path=str(readme_file))
    registration = build_mailbox_registration(agent, readme, description)
    chat = CHAT_PROTOCOL_DIGEST in registration.protocols

    out(f"Agent address: {agent.address}")
    out(f"Name:          {registration.name}")
    out(f"Type:          Mailbox (endpoint {', '.join(e.url for e in registration.endpoints)})")
    out(f"Protocols:     {len(registration.protocols)}{' (AgentChatProtocol 0.3.0 included)' if chat else ''}")
    out(f"README:        {len(readme)} characters; description {len(description)} characters")
    out(f"Prompts:       {len(registration.profile.starter_prompts)}")
    if not confirm:
        out("Dry run: nothing was sent.")
        return 0

    api_key = (os.getenv("AGENTVERSE_API_KEY") or "").strip()
    if not api_key:
        out("[CONFIGURATION ERROR] AGENTVERSE_API_KEY is not set. Create a key at https://agentverse.ai/profile/api-keys,")
        out("                      add a line AGENTVERSE_API_KEY=<key> to .env yourself (never paste it into a chat),")
        out(f"                      then run this again. Or connect in the browser instead: {INSPECTOR_HINT}")
        return 1
    try:
        ok, detail = asyncio.run(register(agent, api_key, registration))
    except asyncio.TimeoutError:
        ok, detail = False, f"no answer from {AGENTVERSE.url} within {int(REGISTRATION_TIMEOUT)} s"
    except Exception as exc:  # network errors and malformed Agentverse answers alike
        ok, detail = False, f"{type(exc).__name__}: {exc}"
    if not ok:
        out(f"[CONNECT FAILED] Agentverse: {detail or 'registration refused without a reason'}")
        out(f"       fix: {connect_failure_fix(detail)} Nothing was changed locally.")
        return 1

    out(f"[PASS] Registered {_short(agent.address)} as a Mailbox agent in your Agentverse account.")
    verified = check_mailbox(agent._identity, http)
    for c in verified:
        out(f"[{c.status}] {c.name}" + (f": {c.detail}" if c.detail else ""))
    out("Next: (re)start the agent so it collects messages from the mailbox and marks itself active:")
    out(f"      {RUN_HINT}")
    out(f"      then run {mailbox_command('status', 'status')} and send it a message from ASI:One or Agentverse.")
    return 0 if verified[0].status != FAIL else 1


async def unregister_agent(address: str, api_key: str) -> Tuple[bool, str]:
    """What the Inspector's Disconnect makes the agent send (uAgents' own unregister_in_agentverse)."""
    from uagents.mailbox import AgentverseDisconnectRequest, unregister_in_agentverse

    response = await asyncio.wait_for(
        unregister_in_agentverse(request=AgentverseDisconnectRequest(user_token=api_key),
                                 agent_address=address, agentverse=AGENTVERSE),
        timeout=REGISTRATION_TIMEOUT,
    )
    return response.success, response.detail or ""


def run_disconnect(seed: str, confirm: bool, unregister=unregister_agent, out: Callable[[str], None] = print) -> int:
    address = Identity.from_seed(seed, 0).address
    out(f"Agent address: {address}")
    out("Removes this agent's Agentverse registration (and its mailbox) from the account of AGENTVERSE_API_KEY.")
    out("The identity, the Almanac record and local state are unchanged; connect again afterwards.")
    if not confirm:
        out("Dry run: nothing was sent.")
        return 0
    api_key = (os.getenv("AGENTVERSE_API_KEY") or "").strip()
    if not api_key:
        out("[CONFIGURATION ERROR] AGENTVERSE_API_KEY is not set (add it to .env yourself), or disconnect in the")
        out("                      Inspector or under Agentverse -> My Agents instead.")
        return 1
    try:
        ok, detail = asyncio.run(unregister(address, api_key))
    except asyncio.TimeoutError:
        ok, detail = False, f"no answer from {AGENTVERSE.url} within {int(REGISTRATION_TIMEOUT)} s"
    except Exception as exc:  # network errors and malformed Agentverse answers alike
        ok, detail = False, f"{type(exc).__name__}: {exc}"
    if not ok:
        out(f"[DISCONNECT FAILED] Agentverse: {detail or 'refused without a reason'}")
        return 1
    out(f"[PASS] Removed {_short(address)} from your Agentverse account.")
    out(f"Next: {mailbox_command('connect -Confirm', 'connect --confirm')} (or the Inspector's Connect -> Mailbox).")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m warden.agents.mailbox",
                                     description="Check or connect the local WARDEN agent's Agentverse Mailbox.")
    commands = parser.add_subparsers(dest="command", required=True)
    status = commands.add_parser("status", help="check what the Inspector sees, the Almanac record and the mailbox")
    status.add_argument("--port", type=int, default=None, help=f"local agent port (default WARDEN_AGENT_PORT or {DEFAULT_PORT})")
    connect = commands.add_parser("connect", help="register this agent as an Agentverse Mailbox agent")
    mode = connect.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="show the registration; send nothing")
    mode.add_argument("--confirm", action="store_true", help="send it (needs AGENTVERSE_API_KEY)")
    connect.add_argument("--readme", type=Path, default=None, help="profile README (default docs/AGENTVERSE_README.md)")
    disconnect = commands.add_parser("disconnect", help="remove this agent's registration from your Agentverse account")
    disconnect_mode = disconnect.add_mutually_exclusive_group(required=True)
    disconnect_mode.add_argument("--dry-run", action="store_true", help="say what would be removed; send nothing")
    disconnect_mode.add_argument("--confirm", action="store_true", help="remove it (needs AGENTVERSE_API_KEY)")
    args = parser.parse_args(argv)

    load_environment()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    # The runner's startup banner describes a process this command does not start.
    logging.getLogger("warden.runner").setLevel(logging.WARNING)
    try:
        seed = validate_seed(os.getenv("AGENT_SEED"))
        if args.command == "status":
            port = args.port or int(os.getenv("WARDEN_AGENT_PORT") or DEFAULT_PORT)
            return run_status(seed, port, api_key=(os.getenv("AGENTVERSE_API_KEY") or "").strip() or None)
        if args.command == "disconnect":
            return run_disconnect(seed, confirm=args.confirm)
        return run_connect(seed, confirm=args.confirm, readme_path=args.readme)
    except (AgentIdentityError, ConfigError, ValueError) as exc:
        print(f"[CONFIGURATION ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
