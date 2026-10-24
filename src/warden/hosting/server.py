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

from warden.agents.run_agent import build_warden_agent, limit_request_body, restrict_bind_host
from warden.config import ConfigError, get_config, load_environment
from warden.hosting.config import HostedConfig
from warden.hosting.demo_workspace import DemoWorkspaceError, is_demo_workspace, prepare_demo_workspace
from warden.identity import AgentIdentityError, validate_seed
from warden.security.state_store import StateStoreError

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
    approval_mode: str
    durable_state: bool
    risk_analyst: str
    mailbox: bool = False


async def ensure_agentverse_mailbox(agent: Agent, api_key: str) -> bool:
    """Connect and provision the mailbox on Agentverse if an API key is provided."""
    from uagents.mailbox import AgentverseConnectRequest, register_in_agentverse
    from uagents_core.types import AgentType
    from uagents_core.registration import RegistrationRequest

    profile = agent._build_registration_profile()
    reg_data = RegistrationRequest(
        address=agent.address,
        name=agent.name,
        handle=agent._handle,
        url=None,
        profile=profile,
        endpoints=agent._endpoints,
        protocols=list(agent.protocols.keys()),
        metadata=agent.metadata,
    )
    req = AgentverseConnectRequest(user_token=api_key.strip(), agent_type=AgentType.MAILBOX)
    resp = await register_in_agentverse(
        request=req,
        identity=agent._identity,
        prefix=agent._prefix,
        agentverse=agent._agentverse,
        agent_details=reg_data,
    )
    return resp.success


def build_hosted_agent(
    cfg: HostedConfig,
    seed: Optional[str] = None,
    resolver: Optional[Resolver] = None,
    loop: Optional[asyncio.AbstractEventLoop] = None,
) -> Agent:
    """Prepare the synthetic workspace and build the endpoint-mode agent with a health route."""
    agent_seed = validate_seed(seed or os.getenv("AGENT_SEED"))
    workspace_root = prepare_demo_workspace(cfg.workspace_root)
    core = get_config().model_copy(update={"approval_mode": cfg.approval_mode, "state_db": cfg.state_db})
    agent = build_warden_agent(
        config=core,
        name=cfg.agent_name,
        seed=agent_seed,
        port=cfg.port,
        mailbox=cfg.use_mailbox,
        endpoint=None if cfg.use_mailbox else [cfg.public_endpoint],
        workspace_dir=workspace_root,
        publish_manifest=True,
        description=cfg.description,
        readme_path=cfg.readme_path,
        resolver=resolver,
        loop=loop,
        interactive_cards=cfg.interactive_cards,
        # The SDK guards /connect and /disconnect by client IP, which a spoofed X-Forwarded-For
        # header defeats behind its trust-all proxy setting; /connect signs with this identity.
        enable_agent_inspector=False,
    )
    if not limit_request_body(cfg.max_request_bytes):
        raise ConfigError("Cannot cap request body size on this uAgents version; refusing to start.")
    scheme = cfg.public_endpoint.split(":", 1)[0]
    remote_auditor = core.remote_auditor

    api_key = (os.getenv("AGENTVERSE_API_KEY") or os.getenv("AGENTVERSE_MAILBOX_KEY") or "").strip()
    if cfg.use_mailbox and api_key:
        @agent.on_event("startup")
        async def _connect_mailbox_startup(ctx: Context):
            try:
                ok = await ensure_agentverse_mailbox(agent, api_key)
                if ok:
                    ctx.logger.info("Agentverse mailbox provisioned and connected successfully.")
                else:
                    ctx.logger.warning("Agentverse mailbox provisioning returned False; check API key.")
            except Exception as exc:
                ctx.logger.warning("Could not auto-provision mailbox: %s", exc)

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
            approval_mode=core.approval_mode,
            durable_state=core.state_db is not None,
            risk_analyst=core.risk_analyst,
            mailbox=bool(agent._use_mailbox),
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
    except (AgentIdentityError, ConfigError, DemoWorkspaceError, StateStoreError, ValueError) as exc:
        print(f"[CONFIGURATION ERROR] {exc}", file=sys.stderr)
        return 1

    # A hosted container must accept connections from its platform's proxy.
    if not restrict_bind_host("0.0.0.0"):
        print("[ERROR] Cannot set the uAgents bind address on this SDK version; refusing to start.", file=sys.stderr)
        return 1

    print(f"[STARTING] WARDEN hosted agent {agent.address}")
    print(f"  Mode:      {'mailbox (Agentverse Mailman)' if cfg.use_mailbox else 'external-endpoint'}")
    print(f"  Endpoint:  {cfg.public_endpoint}")
    print(f"  Listening: 0.0.0.0:{cfg.port}  (health: {HEALTH_ROUTE})")
    print("  Workspace: synthetic demo workspace (fixtures only)")
    agent.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
