# src/secopent/infrastructure/repositories/sqlalchemy_audit_chain.py
"""SqlAlchemySignedAuditEventStore: persists the signed audit chain (W3-C T3).

Implements the SignedAuditEventStore Protocol over the core_signed_audit_events
table. ``append`` opens a short-lived session per event (correctness over
throughput - audit events are not ultra-high-volume; batching is a follow-up).
``load_all`` returns events in chain order (``seq`` autoincrement).
"""
from __future__ import annotations

from datetime import UTC

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...application.audit_chain import SignedAuditEvent
from ...domain.audit.models import AuditEvent
from ..db.session import Database
from ..db.signed_audit_models import CoreSignedAuditEvent


def _to_row(signed: SignedAuditEvent) -> CoreSignedAuditEvent:
    e = signed.event
    return CoreSignedAuditEvent(
        event_id=e.id,
        actor=e.actor,
        action=e.action,
        resource_type=e.resource_type,
        resource_id=e.resource_id,
        payload=dict(e.payload),
        previous_hash=e.previous_hash,
        event_hash=e.event_hash,
        occurred_at=e.occurred_at,
        signature=signed.signature,
    )


def _to_entity(row: CoreSignedAuditEvent) -> SignedAuditEvent:
    occurred_at = row.occurred_at
    # SQLite stores DateTime(timezone=True) as naive; re-attach UTC.
    if occurred_at.tzinfo is None:
        occurred_at = occurred_at.replace(tzinfo=UTC)
    event = AuditEvent(
        id=row.event_id,
        actor=row.actor,
        action=row.action,
        resource_type=row.resource_type,
        resource_id=row.resource_id,
        payload=dict(row.payload),
        previous_hash=row.previous_hash,
        event_hash=row.event_hash,
        occurred_at=occurred_at,
    )
    return SignedAuditEvent(event=event, signature=row.signature)


class SqlAlchemySignedAuditEventStore:
    """Append-only signed audit event store backed by the Database."""

    def __init__(self, database: Database) -> None:
        self._database = database

    def append(
        self,
        signed: SignedAuditEvent,
        *,
        session: Session | None = None,
    ) -> None:
        """Append a signed event. When ``session`` is provided, use it and do
        NOT commit (the caller owns the transaction - v4 same-tx refactor so
        the signed audit insert joins the caller's business-write transaction,
        eliminating the cross-connection double-write that caused v4). When
        omitted (legacy path), open a short-lived session and commit immediately.
        """
        if session is not None:
            session.add(_to_row(signed))
            return
        with self._database.open_session() as new_session:
            new_session.add(_to_row(signed))
            new_session.commit()

    def load_all(self) -> tuple[SignedAuditEvent, ...]:
        with self._database.open_session() as session:
            stmt = select(CoreSignedAuditEvent).order_by(CoreSignedAuditEvent.seq)
            rows = session.scalars(stmt).all()
            return tuple(_to_entity(r) for r in rows)
