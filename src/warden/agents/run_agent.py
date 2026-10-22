"""Agentverse and uAgents deployment entry point for WARDEN.

Initializes the uAgents Agent, configures the Agent Chat Protocol (ACP),
and establishes connectivity with Agentverse Mailbox for ASI:One discovery.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Optional
from uagents import Agent

from warden.agents.warden_agent import WardenAgent
from warden.execution.workspace import Workspace
from warden.integrations.acp_adapter import create_acp_protocol

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("warden.runner")


def build_warden_agent(
    name: Optional[str] = None,
    seed: Optional[str] = None,
    port: int = 8000,
    mailbox_key: Optional[str] = None,
    workspace_dir: Optional[Path | str] = None,
) -> Agent:
    """Build and configure a uAgents Agent running WARDEN with native ACP."""
    agent_name = name or os.getenv("AGENTVERSE_AGENT_NAME", "warden-verification-agent")
    agent_seed = seed or os.getenv("AGENT_SEED", "warden_fetchathon_recovery_seed_2026")
    mb_key = mailbox_key or os.getenv("AGENTVERSE_MAILBOX_KEY")

    # Mailbox configuration for Agentverse connectivity
    mailbox = f"{mb_key}@https://agentverse.ai" if mb_key else None

    # Workspace configuration
    ws_path = Path(workspace_dir or os.getenv("WARDEN_WORKSPACE_ROOT", "./temp_workspace")).resolve()
    workspace = Workspace(ws_path)
    warden_core = WardenAgent(workspace=workspace)

    agent = Agent(
        name=agent_name,
        seed=agent_seed,
        port=port,
        mailbox=mailbox,
    )

    # Attach the official Agent Chat Protocol
    acp_proto = create_acp_protocol(warden=warden_core)
    agent.include(acp_proto)

    logger.info("=" * 60)
    logger.info("🛡️  WARDEN Autonomous Verification Agent Initialized")
    logger.info(f"Agent Name:    {agent.name}")
    logger.info(f"Agent Address: {agent.address}")
    if mailbox:
        logger.info(f"Mailbox:       Connected to Agentverse ({mb_key[:8]}...)")
    else:
        logger.info("Mailbox:       None (Running in local test mode)")
    logger.info(f"Workspace:     {workspace.root_path}")
    logger.info(f"Protocol:      AgentChatProtocol (v0.3.0)")
    logger.info("=" * 60)

    return agent


def main():
    parser = argparse.ArgumentParser(description="Run WARDEN uAgent with Agent Chat Protocol")
    parser.add_argument("--name", type=str, default=None, help="Agent name")
    parser.add_argument("--seed", type=str, default=None, help="Agent seed phrase")
    parser.add_argument("--port", type=int, default=8000, help="Local port")
    parser.add_argument("--mailbox", type=str, default=None, help="Agentverse mailbox API key")
    parser.add_argument("--workspace", type=str, default=None, help="Workspace directory")
    args = parser.parse_args()

    agent = build_warden_agent(
        name=args.name,
        seed=args.seed,
        port=args.port,
        mailbox_key=args.mailbox,
        workspace_dir=args.workspace,
    )

    print(f"\n🚀 WARDEN Agent is starting on address: {agent.address}")
    print("To discover this agent in ASI:One (https://asi1.ai):")
    print("1. Set AGENTVERSE_MAILBOX_KEY in .env")
    print("2. Ensure agent is registered in Agentverse (https://agentverse.ai)")
    print("3. Query @warden-verification-agent inside ASI:One chat.\n")

    agent.run()


if __name__ == "__main__":
    main()
