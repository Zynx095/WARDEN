"""Verification of signed audit attestations: every failure must be non-VERIFIED."""

from datetime import datetime, timedelta, timezone

import pytest
from uagents.crypto import Identity

from warden.audit.attestation import (
    AuditAttestation,
    AuditRequest,
    check_attestation,
    signing_digest,
)

NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
# Throwaway in-test identities; they are never persisted and are not project identities.
AUDITOR = Identity.from_seed("unit-test-auditor-seed-not-a-real-identity", 0)
OTHER = Identity.from_seed("unit-test-other-seed-not-a-real-identity", 0)


def _iso(dt):
    return dt.isoformat()


@pytest.fixture
def request_():
    return AuditRequest(
        request_id="r1", nonce="n1", action_digest="d" * 64, operation="DELETE",
        target="a.tmp", workspace_id="w" * 64,
        issued_at=_iso(NOW), expires_at=_iso(NOW + timedelta(seconds=60)),
    )


def _att(request, identity=AUDITOR, **overrides):
    fields = dict(
        request_id=request.request_id, nonce=request.nonce, action_digest=request.action_digest,
        workspace_id=request.workspace_id, auditor_address=identity.address,
        verdict="VERIFIED", observed_at=_iso(NOW + timedelta(seconds=5)),
    )
    fields.update(overrides)
    unsigned = AuditAttestation(**fields)
    return unsigned.model_copy(update={"signature": identity.sign_digest(signing_digest(unsigned))})


def _check(request, att, trusted=AUDITOR.address, now=NOW + timedelta(seconds=6)):
    return check_attestation(request, att, trusted, now=now)


def test_valid_attestation_is_accepted(request_):
    res = _check(request_, _att(request_))
    assert res.valid and res.verdict == "VERIFIED"


def test_auditor_failed_verdict_is_propagated_not_upgraded(request_):
    res = _check(request_, _att(request_, verdict="FAILED"))
    assert res.valid and res.verdict == "FAILED"


@pytest.mark.parametrize("att", [None, {}, {"verdict": "VERIFIED"}, "VERIFIED", 42])
def test_missing_or_malformed_is_unverified(request_, att):
    res = _check(request_, att)
    assert not res.valid and res.verdict == "UNVERIFIED"


def test_no_trusted_address_configured_is_unverified(request_):
    for trusted in (None, "", "  "):
        res = _check(request_, _att(request_), trusted=trusted)
        assert not res.valid and res.verdict == "UNVERIFIED"


def test_unsigned_is_unverified(request_):
    att = _att(request_).model_copy(update={"signature": ""})
    assert _check(request_, att).verdict == "UNVERIFIED"


def test_signature_from_wrong_key_is_unverified(request_):
    unsigned = _att(request_)
    forged = unsigned.model_copy(update={"signature": OTHER.sign_digest(signing_digest(unsigned))})
    assert _check(request_, forged).verdict == "UNVERIFIED"


def test_untrusted_signer_is_unverified(request_):
    assert _check(request_, _att(request_, identity=OTHER)).verdict == "UNVERIFIED"


def test_tampered_field_after_signing_is_unverified(request_):
    att = _att(request_, verdict="FAILED").model_copy(update={"verdict": "VERIFIED"})
    assert _check(request_, att).verdict == "UNVERIFIED"


@pytest.mark.parametrize("field", ["request_id", "nonce", "action_digest", "workspace_id"])
def test_binding_mismatch_is_unverified(request_, field):
    res = _check(request_, _att(request_, **{field: "other"}))
    assert not res.valid and res.verdict == "UNVERIFIED"


def test_replay_against_a_different_request_is_unverified(request_):
    att = _att(request_)
    other = request_.model_copy(update={"request_id": "r2", "nonce": "n2"})
    assert _check(other, att).verdict == "UNVERIFIED"


def test_expired_request_is_unverified(request_):
    assert _check(request_, _att(request_), now=NOW + timedelta(minutes=10)).verdict == "UNVERIFIED"


def test_observation_outside_window_is_unverified(request_):
    stale = _att(request_, observed_at=_iso(NOW - timedelta(hours=1)))
    assert _check(request_, stale).verdict == "UNVERIFIED"


def test_verified_with_unexpected_changes_is_failed(request_):
    att = _att(request_, unexpected_changes=["b.tmp modified"])
    res = _check(request_, att)
    assert not res.valid and res.verdict == "FAILED"


def test_verifier_exceptions_fail_closed(request_):
    def boom(*_a):
        raise RuntimeError("x")
    res = check_attestation(request_, _att(request_), AUDITOR.address, now=NOW + timedelta(seconds=6), verify=boom)
    assert res.verdict == "UNVERIFIED"
