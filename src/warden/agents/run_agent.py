"""uAgents entry point for WARDEN.

Initializes the uAgents Agent, attaches the Agent Chat Protocol (ACP) and runs it.
By default the agent runs **local-only**: it binds to the loopback interface, has no
registered endpoint or mailbox, and telemetry reporting is disabled. Note that uAgents
0.26.1 still sends one signed, best-effort "active" status update (public agent
identifier only) to the Agentverse Almanac API at startup; that call cannot be disabled
through the Agent constructor and is not registration or mailbox connectivity. Mailbox
mode is opt-in and requires an account-specific provisioning step that this process
cannot perform or verify on its own (see docs/INTEGRATION.md).

Identity comes only from an explicit seed or ``AGENT_SEED``; there is no fallback.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import urllib.parse
from pathlib import Path
from typing import List, Optional, Union

from uagents import Agent
from uagents.resolver import Resolver

from warden.audit.factory import build_remote_auditor_if_enabled
from warden.risk.factory import build_risk_analyst
from warden.agents.warden_agent import WardenAgent
from warden.config import ConfigError, WardenConfig, env_bool, get_config, load_environment, resolve_repo_path
from warden.execution.workspace import Workspace
from warden.identity import AgentIdentityError, derive_agent_address, validate_seed
from warden.integrations.acp_adapter import create_acp_protocol

logger = logging.getLogger("warden.runner")

LOOPBACK_HOST = "127.0.0.1"
DEFAULT_PORT = 8000

__all__ = [
    "AgentIdentityError",
    "build_warden_agent",
    "derive_agent_address",
    "describe_mode",
    "enable_inspector_pna_cors",
    "limit_request_body",
    "restrict_bind_host",
    "main",
]


def describe_mode(use_mailbox: bool, endpoint: Optional[Union[str, List[str]]]) -> str:
    """Name the connectivity mode. This states configuration, not verified connectivity."""
    if endpoint:
        return "external-endpoint (configured, registration not verified)"
    if use_mailbox:
        return "mailbox (configured, Agentverse provisioning not verified)"
    return "local-only"


def restrict_bind_host(host: str = LOOPBACK_HOST) -> bool:
    """Make the SDK's embedded HTTP server bind to ``host`` instead of its hardcoded 0.0.0.0.

    uAgents 0.26.1 exposes the bind address only as the module constant ``uagents.asgi.HOST``.
    Returns True when the restriction was applied; False if the SDK layout differs, in which
    case the caller must not claim the agent is loopback-only.
    """
    try:
        from uagents import asgi
    except ImportError:  # pragma: no cover - uagents is a hard dependency
        return False
    if not hasattr(asgi, "HOST"):
        return False
    asgi.HOST = host
    return True


def limit_request_body(max_bytes: int) -> bool:
    """Cap the request body the SDK's embedded HTTP server will buffer.

    uAgents 0.26.1 reads every request body into memory without a limit. With this cap an
    oversized body is read no further and handed to the SDK as empty, which it answers with
    HTTP 400. Returns False if the SDK layout differs and the cap could not be applied.
    """
    try:
        from uagents import asgi
    except ImportError:  # pragma: no cover - uagents is a hard dependency
        return False
    if not hasattr(asgi, "_read_asgi_body"):
        return False

    async def _bounded_read(receive) -> bytes:
        body = b""
        more_body = True
        while more_body:
            message = await receive()
            body += message.get("body", b"")
            if len(body) > max_bytes:
                return b""
            more_body = message.get("more_body", False)
        return body

    asgi._read_asgi_body = _bounded_read
    return True


def enable_inspector_pna_cors() -> bool:
    """Ensure the embedded ASGI server sends Access-Control-Allow-Private-Network.

    Modern Chromium browsers enforce Private Network Access (PNA) checks when a public
    HTTPS site (agentverse.ai) calls loopback (127.0.0.1). Without this header on OPTIONS
    preflights, the browser blocks the connection before it reaches /agent_info or /connect.
    """
    try:
        from uagents import asgi
        if getattr(asgi.ASGIServer, "_pna_cors_enabled", False):
            return True

        async def _pna_serve(self):
            import contextlib
            import uvicorn
            config = uvicorn.Config(
                self,
                host=asgi.HOST,
                port=self._port,
                log_level="warning",
                forwarded_allow_ips="*",
                headers=[
                    ("Access-Control-Allow-Origin", "*"),
                    ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
                    ("Access-Control-Allow-Headers", "*"),
                    ("Access-Control-Allow-Credentials", "false"),
                    ("Access-Control-Allow-Private-Network", "true"),
                ],
            )
            self._server = uvicorn.Server(config)
            self._logger.info(
                f"Starting server on http://{asgi.HOST}:{self._port} (Press CTRL+C to quit)"
            )
            with contextlib.suppress(asyncio.CancelledError, KeyboardInterrupt):
                await self._server.serve()

        asgi.ASGIServer.serve = _pna_serve
        asgi.ASGIServer._pna_cors_enabled = True
        return True
    except Exception:
        return False


def _sdk_version() -> str:
    try:
        from importlib.metadata import version
        return version("uagents")
    except Exception:  # pragma: no cover
        return "unknown"


def _ensure_event_loop() -> asyncio.AbstractEventLoop:
    """Return a fresh loop for the Agent (the SDK's implicit lookup is deprecated on 3.12)."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return loop


def build_warden_agent(
    name: Optional[str] = None,
    seed: Optional[str] = None,
    port: int = DEFAULT_PORT,
    mailbox: bool = False,
    mailbox_key: Optional[str] = None,
    endpoint: Optional[Union[str, List[str]]] = None,
    workspace_dir: Optional[Path | str] = None,
    publish_manifest: bool = False,
    description: Optional[str] = None,
    readme_path: Optional[str] = None,
    resolver: Optional[Resolver] = None,
    loop: Optional[asyncio.AbstractEventLoop] = None,
    interactive_cards: Optional[bool] = None,
    enable_agent_inspector: bool = True,
    config: Optional[WardenConfig] = None,
) -> Agent:
    """Build and configure a uAgents Agent running WARDEN with native ACP.

    ``resolver`` and ``loop`` default to the SDK's Almanac resolver and the process event
    loop; tests pass explicit ones to run several agents on loopback in one process.
    ``enable_agent_inspector=False`` removes the SDK's /agent_info, /messages, /connect and
    /disconnect routes; hosted mode needs none of them.

    Security invariants:
    - No hardcoded or placeholder seeds; an explicit seed or AGENT_SEED is mandatory.
    - Seeds and keys are never logged or exposed in terminal output.
    - This function does not read ``.env``; entry points call ``load_environment`` first.
    """
    agent_name = name or os.getenv("AGENTVERSE_AGENT_NAME", "warden-verification-agent")
    agent_seed = validate_seed(seed or os.getenv("AGENT_SEED"))

    use_mailbox = mailbox
    if (mailbox_key or os.getenv("AGENTVERSE_MAILBOX_KEY") or "").strip():
        # uAgents 0.26.1 has no mailbox-key parameter: a value here selects mailbox mode only.
        use_mailbox = True
        logger.warning(
            "AGENTVERSE_MAILBOX_KEY is not consumed by uAgents %s; it only selects mailbox mode. "
            "Mailbox provisioning is done by connecting through the local agent inspector.",
            _sdk_version(),
        )

    agent_desc = description if description is not None else os.getenv("AGENTVERSE_DESCRIPTION")
    agent_readme = readme_path if readme_path is not None else os.getenv("AGENTVERSE_README_PATH")

    ws_path = resolve_repo_path(workspace_dir or os.getenv("WARDEN_WORKSPACE_ROOT") or "./temp_workspace")
    workspace = Workspace(ws_path)
    cfg = config or get_config()
    warden_core = WardenAgent(
        workspace=workspace,
        config=cfg,
        audit_log_file=cfg.audit_log,
        auditor=build_remote_auditor_if_enabled(workspace, agent_seed, cfg),
        risk_analyst=build_risk_analyst(agent_seed, cfg),
    )

    agent = Agent(
        name=agent_name,
        seed=agent_seed,
        port=port,
        endpoint=endpoint,
        mailbox=use_mailbox,
        resolve=resolver,
        loop=loop or _ensure_event_loop(),
        # Telemetry is only meaningful once registered on Agentverse; keep local mode quiet.
        report_events=bool(use_mailbox or endpoint),
        description=agent_desc,
        readme_path=agent_readme,
        enable_agent_inspector=enable_agent_inspector,
    )
    agent.include(
        create_acp_protocol(warden=warden_core, interactive_cards=interactive_cards,
                            approval_mode=cfg.approval_mode),
        publish_manifest=publish_manifest,
    )

    logger.info("=" * 60)
    logger.info("[WARDEN] Autonomous Verification Agent Initialized")
    logger.info("Agent Name:    %s", agent.name)
    logger.info("Agent Address: %s", agent.address)
    logger.info("Mode:          %s", describe_mode(agent._use_mailbox, endpoint))
    logger.info("Workspace:     %s", workspace.root_path)
    logger.info("Protocol:      AgentChatProtocol (v0.3.0)")
    if publish_manifest:
        logger.info("Manifest:      Protocol manifest publication enabled")
    logger.info("=" * 60)
    return agent


def main(argv: Optional[List[str]] = None) -> int:
    loaded = load_environment()

    parser = argparse.ArgumentParser(description="Run WARDEN uAgent with Agent Chat Protocol")
    parser.add_argument("--name", type=str, default=None, help="Agent name")
    parser.add_argument("--seed", type=str, default=None,
                        help="Agent seed (discouraged: visible in shell history; prefer AGENT_SEED in .env)")
    parser.add_argument("--port", type=int, default=None,
                        help=f"Local port (default WARDEN_AGENT_PORT or {DEFAULT_PORT})")
    parser.add_argument("--mailbox", action="store_true", help="Opt in to Agentverse mailbox mode")
    parser.add_argument("--mailbox-key", type=str, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--endpoint", type=str, default=None, help="Public HTTP endpoint URL (external endpoint mode)")
    parser.add_argument("--workspace", type=str, default=None, help="Workspace directory")
    parser.add_argument("--bind-all", action="store_true",
                        help="Bind 0.0.0.0 instead of loopback (needed only behind a proxy/tunnel; exposes the agent)")
    parser.add_argument("--show-address", action="store_true",
                        help="Print the derived agent address and exit without starting the server")
    parser.add_argument("--publish-manifest", action="store_true",
                        help="Publish the Agent Chat Protocol manifest to Almanac on startup (for discovery)")
    parser.add_argument("--description", type=str, default=None,
                        help="Agent description for Agentverse profile")
    parser.add_argument("--readme", type=str, default=None,
                        help="Path to README file for Agentverse profile")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, os.getenv("WARDEN_LOG_LEVEL", "INFO").strip().upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    try:
        seed = validate_seed(args.seed or os.getenv("AGENT_SEED"))
        if args.show_address:
            print(f"Agent Address: {derive_agent_address(seed)}")
            return 0

        port = args.port or int(os.getenv("WARDEN_AGENT_PORT") or DEFAULT_PORT)
        use_mailbox = args.mailbox or env_bool("WARDEN_USE_MAILBOX", False)
        publish_manifest = args.publish_manifest or env_bool("AGENTVERSE_PUBLISH_MANIFEST", False)
        agent = build_warden_agent(
            name=args.name,
            seed=seed,
            port=port,
            mailbox=use_mailbox,
            mailbox_key=args.mailbox_key,
            endpoint=args.endpoint,
            workspace_dir=args.workspace,
            publish_manifest=publish_manifest,
            description=args.description,
            readme_path=args.readme,
        )
    except (AgentIdentityError, ConfigError, ValueError) as exc:
        print(f"\n[CONFIGURATION ERROR] {exc}\n", file=sys.stderr)
        return 1

    if args.bind_all:
        restrict_bind_host("0.0.0.0")
        bound = f"0.0.0.0:{port} (--bind-all: reachable from the network)"
    elif restrict_bind_host(LOOPBACK_HOST):
        bound = f"{LOOPBACK_HOST}:{port} (loopback only)"
    else:
        print("[ERROR] Cannot restrict the SDK server to loopback on this uAgents version; "
              "refusing to start. Pass --bind-all to accept network exposure.", file=sys.stderr)
        return 1

    enable_inspector_pna_cors()

    print(f"\n[STARTING] WARDEN agent {agent.address}")
    print(f"  Config file: {loaded if loaded else 'none (.env not found; using process environment)'}")
    print(f"  Mode:        {describe_mode(agent._use_mailbox, args.endpoint)}")
    print(f"  Listening:   {bound}")
    if agent._use_mailbox:
        escaped_uri = urllib.parse.quote(f"http://127.0.0.1:{port}")
        inspector_url = f"{agent._agentverse.url}/inspect/?uri={escaped_uri}&address={agent.address}"
        print(f"  Inspector:   {inspector_url}")
        print("  Note:        If mailbox is not yet provisioned on Agentverse, open the")
        print("               Inspector URL above in your browser to complete connection.")
        print("  Browser tip: If the Inspector shows 'Check your agent' instructions, your")
        print("               browser is blocking mixed-content from HTTPS (agentverse.ai)")
        print("               to local HTTP. In Chrome/Edge: click site settings -> allow")
        print("               'Insecure content' for agentverse.ai and refresh the page.")
        if not (os.getenv("WARDEN_APPROVER_ADDRESSES") or "").strip():
            print("  Advisory:    WARDEN_APPROVER_ADDRESSES is unset. Requesters will be able")
            print("               to approve their own destructive proposals in public chat.")
    if publish_manifest:
        print("  Manifest:    Publishing protocol manifest to Almanac API on startup")
    print("  Stop with Ctrl+C.\n")

    try:
        agent.run()
    except KeyboardInterrupt:
        print("\n[STOPPED] WARDEN agent shut down.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
