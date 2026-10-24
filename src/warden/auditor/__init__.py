"""Optional independent Auditor agent for WARDEN.

Adapted to the core contracts: schemas and verification live in ``warden.audit.attestation``,
digests in ``warden.security.digest``. This package only holds the read-only service, its
uAgents wiring and its configuration.
"""

from __future__ import annotations

from warden.auditor.agent import (
    AUDITOR_PROTOCOL_NAME,
    AUDITOR_PROTOCOL_VERSION,
    build_auditor_agent,
    create_auditor_protocol,
)
from warden.auditor.config import AuditorConfig
from warden.auditor.service import AuditorService
from warden.auditor.workspace_view import ReadOnlyWorkspaceView

__all__ = [
    "AUDITOR_PROTOCOL_NAME",
    "AUDITOR_PROTOCOL_VERSION",
    "AuditorConfig",
    "AuditorService",
    "ReadOnlyWorkspaceView",
    "build_auditor_agent",
    "create_auditor_protocol",
]
