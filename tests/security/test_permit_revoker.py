# tests/security/test_permit_revoker.py
"""InMemoryPermitRevoker: real permit revocation store (W2-A Task 1).

Replaces NullPermitRevoker (which returned 0). EmergencyStop.trigger calls
revoke_unused() to invalidate issued-but-unused permits within their TTL
window.
"""
from __future__ import annotations

from secopent.application.emergency_stop import PermitRevoker
from secopent.infrastructure.safety.permit_revoker import InMemoryPermitRevoker


def test_revoke_unused_marks_issued_unused_permits_revoked() -> None:
    revoker = InMemoryPermitRevoker()
    revoker.record_issued("nonce-A", used=False)
    revoker.record_issued("nonce-B", used=True)

    revoked = revoker.revoke_unused()

    assert revoked == 1
    assert revoker.is_revoked("nonce-A")
    assert not revoker.is_revoked("nonce-B")


def test_revoke_unused_returns_zero_when_nothing_pending() -> None:
    assert InMemoryPermitRevoker().revoke_unused() == 0


def test_record_used_marks_issued_permit_used() -> None:
    revoker = InMemoryPermitRevoker()
    revoker.record_issued("nonce-C", used=False)
    revoker.record_used("nonce-C")
    assert revoker.revoke_unused() == 0
    assert not revoker.is_revoked("nonce-C")


def test_satisfies_permit_revoker_protocol() -> None:
    revoker: PermitRevoker = InMemoryPermitRevoker()
    assert isinstance(revoker, PermitRevoker)
