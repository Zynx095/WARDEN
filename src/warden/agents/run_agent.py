"""Agentverse and uAgents deployment entry point for WARDEN.

Initializes the uAgents Agent, configures the Agent Chat Protocol (ACP),
and establishes connectivity with Agentverse Mailbox for ASI:One discovery.
Enforces strict agent identity configuration with no hardcoded fallback seeds.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import List, Optional, Union
from uagents import Agent
from uagents.crypto import Identity

from warden.agents.warden_agent import WardenAgent
from warden.execution.workspace import Workspace
from warden.integrations.acp_adapter import create_acp_protocol

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("warden.runner")


class AgentIdentityError(ValueError):
    """Raised when agent identity configuration is missing or insecure."""
    pass


def derive_agent_address(seed: str) -> str:
    """Safely derive the Bech32 agent address from a seed phrase without logging the seed."""
    clean_seed = (seed or "").strip()
    if not clean_seed:
        raise AgentIdentityError("Cannot derive address from an empty or missing seed.")
    identity = Identity.from_seed(clean_seed, 0)
    return identity.address


def build_warden_agent(
    name: Optional[str] = None,
    seed: Optional[str] = None,
    port: int = 8000,
    mailbox: bool = False,
    mailbox_key: Optional[str] = None,
    endpoint: Optional[Union[str, List[str]]] = None,
    workspace_dir: Optional[Path | str] = None,
) -> Agent:
    """Build and configure a uAgents Agent running WARDEN with native ACP.
    
    Security Invariant:
    - Predictable hardcoded fallback seeds are strictly prohibited.
    - An explicit seed or AGENT_SEED environment variable is mandatory.
    - Seeds are never logged or exposed in terminal output.
    """
    agent_name = name or os.getenv("AGENTVERSE_AGENT_NAME", "warden-verification-agent")
    
    # 1. Mandatory seed validation
    agent_seed = (seed or os.getenv("AGENT_SEED") or "").strip()
    if not agent_seed:
        raise AgentIdentityError(
            "Agent seed is not configured. Provide an explicit seed argument or set AGENT_SEED "
            "in your environment. Fallback to predictable hardcoded seeds is prohibited."
        )

    # 2. Mailbox and Agentverse connectivity
    mb_key = mailbox_key or os.getenv("AGENTVERSE_MAILBOX_KEY")
    agentverse_config: Optional[str] = None
    use_mailbox = mailbox

    if mb_key:
        clean_key = mb_key.strip()
        if clean_key:
            agentverse_config = f"{clean_key}@https://agentverse.ai"
            use_mailbox = True

    # 3. Workspace sandbox configuration
    ws_path = Path(workspace_dir or os.getenv("WARDEN_WORKSPACE_ROOT", "./temp_workspace")).resolve()
    workspace = Workspace(ws_path)
    warden_core = WardenAgent(workspace=workspace)

    # 4. Initialize uAgent with verified identity
    agent = Agent(
        name=agent_name,
        seed=agent_seed,
        port=port,
        endpoint=endpoint,
        agentverse=agentverse_config,
        mailbox=use_mailbox,
    )

    # 5. Attach the official Agent Chat Protocol (v0.3.0)
    acp_proto = create_acp_protocol(warden=warden_core)
    agent.include(acp_proto)

    logger.info("=" * 60)
    logger.info("[WARDEN] Autonomous Verification Agent Initialized")
    logger.info(f"Agent Name:    {agent.name}")
    logger.info(f"Agent Address: {agent.address}")
    if agent._use_mailbox:
        masked_key = f"{mb_key[:4]}...{mb_key[-4:]}" if mb_key and len(mb_key) > 8 else "active"
        logger.info(f"Mailbox:       Connected to Agentverse (key: {masked_key})")
    else:
        logger.info("Mailbox:       Disabled (Local standalone mode)")
    logger.info(f"Workspace:     {workspace.root_path}")
    logger.info("Protocol:      AgentChatProtocol (v0.3.0)")
    logger.info("=" * 60)

    return agent


def main():
    parser = argparse.ArgumentParser(description="Run WARDEN uAgent with Agent Chat Protocol")
    parser.add_argument("--name", type=str, default=None, help="Agent name")
    parser.add_argument("--seed", type=str, default=None, help="Agent seed phrase (or set AGENT_SEED)")
    parser.add_argument("--port", type=int, default=8000, help="Local port (default 8000)")
    parser.add_argument("--mailbox", action="store_true", help="Enable Agentverse mailbox polling")
    parser.add_argument("--mailbox-key", type=str, default=None, help="Agentverse mailbox API key")
    parser.add_argument("--endpoint", type=str, default=None, help="Public HTTP endpoint URL")
    parser.add_argument("--workspace", type=str, default=None, help="Workspace directory")
    parser.add_argument(
        "--show-address",
        action="store_true",
        help="Print the derived agent address and exit without starting server",
    )
    args = parser.parse_args()

    # If user requests only public address inspection
    if args.show_address:
        seed = (args.seed or os.getenv("AGENT_SEED") or "").strip()
        if not seed:
            print("Error: Provide --seed or set AGENT_SEED to inspect derived address.", file=sys.stderr)
            sys.exit(1)
        addr = derive_agent_address(seed)
        print(f"Agent Address: {addr}")
        sys.exit(0)

    try:
        agent = build_warden_agent(
            name=args.name,
            seed=args.seed,
            port=args.port,
            mailbox=args.mailbox,
            mailbox_key=args.mailbox_key,
            endpoint=args.endpoint,
            workspace_dir=args.workspace,
        )
    except AgentIdentityError as e:
        print(f"\n[SECURITY CONFIGURATION ERROR] {e}\n", file=sys.stderr)
        sys.exit(1)

    print(f"\n[STARTING] WARDEN Agent is starting on address: {agent.address}")
    print("To discover this agent in ASI:One (https://asi1.ai):")
    print("1. Set AGENT_SEED in .env (keep secret, never commit)")
    print("2. Set AGENTVERSE_MAILBOX_KEY in .env (if connecting via mailbox)")
    print("3. Register agent on Agentverse (https://agentverse.ai)")
    print("4. Query agent in ASI:One chat.\n")

    agent.run()


if __name__ == "__main__":
    main()
