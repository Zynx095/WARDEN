"""Isolated Multi-Agent Auditor feature for WARDEN.

Provides an optional, independent Auditor uAgent that inspects actual filesystem
ground truth post-execution, verifies action digests, detects collateral damage,
and issues structured attestations without relying on executor claims.
"""

from __future__ import annotations

from warden.auditor.agent import (
    AUDITOR_PROTOCOL_NAME,
    AUDITOR_PROTOCOL_VERSION,
    build_auditor_agent,
    create_auditor_protocol,
)
from warden.auditor.config import (
    AuditorConfig,
    get_auditor_config,
    set_auditor_config,
)
from warden.auditor.digest import compute_action_digest
from warden.auditor.models import (
    AuditAttestation,
    AuditRequest,
    AuditVerdict,
)
from warden.auditor.service import AuditorService
from warden.auditor.verifier import (
    AuditorAttestationError,
    AuditorTimeoutError,
    AuditorUAgentVerifier,
)
from warden.auditor.workspace_view import ReadOnlyWorkspaceView

__all__ = [
    "AUDITOR_PROTOCOL_NAME",
    "AUDITOR_PROTOCOL_VERSION",
    "AuditAttestation",
    "AuditAttestationError",
    "AuditorConfig",
    "AuditorService",
    "AuditorTimeoutError",
    "AuditorUAgentVerifier",
    "AuditRequest",
    "AuditVerdict",
    "ReadOnlyWorkspaceView",
    "build_auditor_agent",
    "compute_action_digest",
    "create_auditor_protocol",
    "get_auditor_config",
    "set_auditor_config",
]
