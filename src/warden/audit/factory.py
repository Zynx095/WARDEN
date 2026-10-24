"""Selects the verifier WARDEN uses: local-only by default, remote only when explicitly enabled."""

from __future__ import annotations

from typing import Any, Optional

from uagents.crypto import Identity
from uagents.resolver import RulesBasedResolver

from warden.audit.remote import RemoteAuditVerifier
from warden.audit.transport import UAgentAuditTransport
from warden.config import ConfigError, WardenConfig, get_config
from warden.execution.workspace import Workspace


def build_remote_auditor_if_enabled(
    workspace: Workspace,
    agent_seed: str,
    config: Optional[WardenConfig] = None,
) -> Optional[RemoteAuditVerifier]:
    """Return a RemoteAuditVerifier when WARDEN_REMOTE_AUDITOR is on, else None (local verification only).

    The Auditor must be a distinct identity: the trusted address may not be WARDEN's own.
    This only derives WARDEN's existing signing identity from AGENT_SEED; it creates no identity.
    """
    cfg = config or get_config()
    if not cfg.remote_auditor:
        return None
    sender = Identity.from_seed(agent_seed, 0)
    if cfg.auditor_address == sender.address:
        raise ConfigError("WARDEN_AUDITOR_ADDRESS must be a different identity from WARDEN's own address.")
    resolver = RulesBasedResolver({cfg.auditor_address: cfg.auditor_endpoint}) if cfg.auditor_endpoint else None
    transport: Any = UAgentAuditTransport(cfg.auditor_address, sender, resolver=resolver)
    return RemoteAuditVerifier(
        workspace,
        transport=transport,
        trusted_auditor_address=cfg.auditor_address,
        timeout_seconds=cfg.auditor_timeout_seconds,
    )
