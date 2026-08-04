"""SignedAuditEventStore port: persistence for the signed audit chain (W3-C T1).

AuditChain depends on this Optional port so the tamper-evident signed chain
survives process restart (H6). The application layer stays free of SQLAlchemy;
the composition root supplies a SqlAlchemy implementation backed by the Database.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..audit_chain import SignedAuditEvent


@runtime_checkable
class SignedAuditEventStore(Protocol):
    """Append-only store for signed audit events, loadable in chain order."""

    def append(self, signed: SignedAuditEvent) -> None: ...
    def load_all(self) -> tuple[SignedAuditEvent, ...]: ...
