# src/secopent/application/ports/security.py
"""Application-layer ports for permit signing/verification (W2-A).

The concrete ``PermitSigner`` / ``PermitVerifier`` live in infrastructure
(they depend on ``cryptography``, which the application layer must not
import). These Protocols let ``execute_assessment`` depend on the capability
without crossing the architecture boundary.
"""
from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from ...domain.permits.models import ExecutionPermit


@runtime_checkable
class PermitSignerProtocol(Protocol):
    """Issue a signed copy of an ExecutionPermit (Ed25519 in production)."""

    def issue(self, permit: ExecutionPermit) -> ExecutionPermit: ...


@runtime_checkable
class PermitRegistry(Protocol):
    """Tracks issued permit nonces so EmergencyStop can revoke the unused ones.

    The same concrete store (e.g. ``InMemoryPermitRevoker``) satisfies both
    this registry (used by ``execute_assessment`` to record issued nonces) and
    ``PermitRevoker`` (used by ``EmergencyStop`` to revoke them).
    """

    def record_issued(self, nonce: str, *, used: bool = False) -> None: ...

    def record_used(self, nonce: str) -> None: ...


@runtime_checkable
class PermitVerifierProtocol(Protocol):
    """Verify a permit's signature + expiry + nonce-replay + worker binding.

    Raises a ``PermitSignatureInvalid`` / ``PermitExpired`` / ``PermitReplayed``
    / ``PermitWorkerMismatch`` domain error if the permit is not currently
    valid.
    """

    def verify(
        self,
        permit: ExecutionPermit,
        *,
        now: datetime,
        used_nonces: set[str] | frozenset[str],
        expected_worker: str | None = None,
    ) -> None: ...
