"""uAgents wire envelopes for the audit exchange.

The authoritative schemas are the pydantic models in ``warden.audit.attestation``. The
wire layer only carries their canonical JSON as an opaque string, so there is a single
definition of every field and the receiving side always re-validates through it.
"""

from __future__ import annotations

from uagents import Model


class AuditRequestWire(Model):
    payload: str  # AuditRequest.model_dump_json()


class AuditAttestationWire(Model):
    payload: str  # AuditAttestation.model_dump_json()
