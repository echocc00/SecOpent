# src/secopent/application/ports/security.py
"""Application-layer ports for permit signing/verification (W2-A).

The concrete ``PermitSigner`` / ``PermitVerifier`` live in infrastructure
(they depend on ``cryptography``, which the application layer must not
import). These Protocols let ``execute_assessment`` depend on the capability
without crossing the architecture boundary.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from ...domain.permits.models import ExecutionPermit
from ...domain.policy.models import PolicyDecision
from ...domain.scope.models import ScopeSnapshot


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


@runtime_checkable
class EgressGuardProtocol(Protocol):
    """Decide whether a connection to a target is permitted (egress layer).

    Always blocks cloud-metadata / loopback / link-local destinations even if
    the scope mistakenly includes them. Concrete impl (EgressGuard) lives in
    infrastructure; nftables enforcement wraps this in W2-B.
    """

    def check(self, target: str, scope: ScopeSnapshot) -> PolicyDecision: ...


@runtime_checkable
class NftScopeEnforcerProtocol(Protocol):
    """Push a scope's resolved targets into kernel nftables allow/block sets.

    Host-level defence in depth: even if a container's application-layer
    EgressGuard is bypassed, the nft output chain default-drops anything not in
    the allow set. ``apply_scope`` is best-effort (non-Linux dev hosts have no
    nft binary; failures are audited and the run continues on app-layer guard
    alone). Concrete impl (NftScopeEnforcer) lives in infrastructure.
    """

    def apply_scope(
        self, snapshot: ScopeSnapshot, *, session: Any = None
    ) -> object: ...

    def revoke(self) -> None: ...
