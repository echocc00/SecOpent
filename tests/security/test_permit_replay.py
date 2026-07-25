"""TDD tests for ExecutionPermit signing/verification (M5 Task 2, §12)."""
from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from secopent.domain.permits.models import (
    DEFAULT_PERMIT_TTL_SECONDS,
    ExecutionPermit,
    PermitExpired,
    PermitReplayed,
    PermitSignatureInvalid,
    PermitWorkerMismatch,
)
from secopent.infrastructure.permits.permit_signer import PermitSigner, PermitVerifier

_T0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _permit(nonce: str = "nonce-abc") -> ExecutionPermit:
    return ExecutionPermit(
        job_id="job-1",
        worker_id="worker-1",
        scope_digest="sha256:" + "s" * 64,
        plan_digest="sha256:" + "p" * 64,
        capabilities=("passive", "network.connect"),
        budget=100.0,
        issued_at=_T0,
        expires_at=_T0 + timedelta(seconds=DEFAULT_PERMIT_TTL_SECONDS),
        nonce=nonce,
    )


def _signed() -> tuple[ExecutionPermit, PermitVerifier]:
    signer = PermitSigner()
    return signer.issue(_permit()), PermitVerifier(signer.public_key_bytes())


def test_default_ttl_is_fifteen_minutes() -> None:
    assert DEFAULT_PERMIT_TTL_SECONDS == 15 * 60


def test_valid_permit_verifies() -> None:
    permit, verifier = _signed()
    verifier.verify(
        permit,
        now=_T0 + timedelta(minutes=5),
        used_nonces=set(),
        expected_worker="worker-1",
    )


def test_tampered_permit_signature_invalid() -> None:
    permit, verifier = _signed()
    tampered = replace(permit, budget=999999.0)  # change content, keep old signature
    with pytest.raises(PermitSignatureInvalid):
        verifier.verify(tampered, now=_T0, used_nonces=set())


def test_expired_permit_rejected() -> None:
    permit, verifier = _signed()
    with pytest.raises(PermitExpired):
        verifier.verify(permit, now=_T0 + timedelta(minutes=20), used_nonces=set())


def test_replayed_nonce_rejected() -> None:
    permit, verifier = _signed()
    with pytest.raises(PermitReplayed):
        verifier.verify(permit, now=_T0, used_nonces={"nonce-abc"})


def test_cross_worker_rejected() -> None:
    permit, verifier = _signed()
    with pytest.raises(PermitWorkerMismatch):
        verifier.verify(permit, now=_T0, used_nonces=set(), expected_worker="worker-2")


def test_third_party_verifier_with_exported_key() -> None:
    signer = PermitSigner()
    permit = signer.issue(_permit())
    # A third party holding only the public key can verify.
    third_party = PermitVerifier(signer.public_key_bytes())
    third_party.verify(permit, now=_T0, used_nonces=set())


def test_each_permit_gets_unique_nonce_binding() -> None:
    signer = PermitSigner()
    p1 = signer.issue(_permit(nonce="n1"))
    p2 = signer.issue(_permit(nonce="n2"))
    assert p1.nonce != p2.nonce
    assert p1.signature != p2.signature
