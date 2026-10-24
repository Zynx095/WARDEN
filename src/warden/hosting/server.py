"""Hosted entry point: ``python -m warden.hosting.server``.

Runs the unchanged WARDEN pipeline (policy, exact-action approval, restricted executor,
outcome verification) as an externally hosted uAgent with a public endpoint, on a
synthetic demo workspace. The process is meant to run on a container host, not a laptop;
Agentverse registration is a separate, explicit step (``python -m warden.hosting.register``).
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from typing import Optional

from uagents import Agent, Context, Model
from uagents.resolver import Resolver

from warden.agents.run_agent import build_warden_agent, restrict_bind_host
from warden.config import ConfigError, get_config, load_environment
from warden.hosting.config import HostedConfig
from warden.hosting.demo_workspace import DemoWorkspaceError, is_demo_workspace, prepare_demo_workspace
from warden.identity import AgentIdentityError, validate_seed

logger = logging.getLogger("warden.hosting")

HEALTH_ROUTE = "/health"


class HealthResponse(Model):
    """Liveness/readiness summary. Never contains secrets, paths or file contents."""
    status: str
    agent_address: str
    protocol: str
    workspace_ready: bool
    remote_auditor: bool
    endpoint_scheme: str


def build_hosted_agent(
    cfg: HostedConfig,
    seed: Optional[str] = None,
    resolver: Optional[Resolver] = None,
    loop: Optional[asyncio.AbstractEventLoop] = None,
) -> Agent:
    """Prepare the synthetic workspace and build the endpoint-mode agent with a health route."""
    agent_seed = validate_seed(seed or os.getenv("AGENT_SEED"))
    workspace_root = prepare_demo_workspace(cfg.workspace_root)
    agent = build_warden_agent(
        name=cfg.agent_name,
        seed=agent_seed,
        port=cfg.port,
        mailbox=False,
        endpoint=[cfg.public_endpoint],
        workspace_dir=workspace_root,
        publish_manifest=True,
        description=cfg.description,
        readme_path=cfg.readme_path,
        resolver=resolver,
        loop=loop,
    )
    scheme = cfg.public_endpoint.split(":", 1)[0]
    remote_auditor = get_config().remote_auditor

    @agent.on_rest_get(HEALTH_ROUTE, HealthResponse)
    async def health(ctx: Context) -> HealthResponse:
        ready = is_demo_workspace(workspace_root)
        return HealthResponse(
            status="ok" if ready else "degraded",
            agent_address=agent.address,
            protocol="AgentChatProtocol",
            workspace_ready=ready,
            remote_auditor=remote_auditor,
            endpoint_scheme=scheme,
        )

    return agent


def main() -> int:
    load_environment()
    logging.basicConfig(
        level=getattr(logging, os.getenv("WARDEN_LOG_LEVEL", "INFO").strip().upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    try:
        cfg = HostedConfig()
        agent = build_hosted_agent(cfg)
    except (AgentIdentityError, ConfigError, DemoWorkspaceError, ValueError) as exc:
        print(f"[CONFIGURATION ERROR] {exc}", file=sys.stderr)
        return 1

    # A hosted container must accept connections from its platform's proxy.
    if not restrict_bind_host("0.0.0.0"):
        print("[ERROR] Cannot set the uAgents bind address on this SDK version; refusing to start.", file=sys.stderr)
        return 1

    print(f"[STARTING] WARDEN hosted agent {agent.address}")
    print(f"  Endpoint:  {cfg.public_endpoint}")
    print(f"  Listening: 0.0.0.0:{cfg.port}  (health: {HEALTH_ROUTE})")
    print("  Workspace: synthetic demo workspace (fixtures only)")
    agent.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
