"""Isolated Multi-Agent Auditor feature for WARDEN.

Provides an optional, independent Auditor uAgent that inspects actual filesystem
ground truth post-execution, verifies action digests, detects collateral damage,
and issues structured attestations without relying on executor claims.
"""

from __future__ import annotations

from warden.auditor.models import (
    AuditAttestation,
    AuditRequest,
    AuditVerdict,
)
from warden.auditor.digest import compute_action_digest

__all__ = [
    "AuditAttestation",
    "AuditRequest",
    "AuditVerdict",
    "compute_action_digest",
]
