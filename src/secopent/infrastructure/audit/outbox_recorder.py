"""OutboxRecorder: AuditRecorder that writes outbox rows, not audit tables.

The daemon's ``_audit_record`` uses this instead of writing
``core_audit_events`` + ``core_signed_audit_events`` directly: ONE row joins
the caller's business transaction (atomicity - the audit row commits or rolls
back with the business write), and the ``OutboxWorker`` fans it out to both
audit tables asynchronously. Audit leaves the hot path (v0.3.0 T4; the v4
root-cause fix deferred from v0.2.0.x).
"""
from __future__ import annotations

from typing import Any

from ...domain.common.canonical import utc_now
from ..db.outbox_models import CoreAuditOutbox
from ..db.session import Database


class OutboxRecorder:
    """Append-only audit sink via the transactional outbox.

    With ``session`` (the daemon path) the row joins the caller's transaction
    and commits/rolls back with it. Without one, the row is committed in its
    own short transaction.
    """

    def __init__(self, db: Database) -> None:
        self._db = db

    def record(
        self,
        *,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str,
        payload: dict[str, object],
        session: Any = None,
    ) -> None:
        row = CoreAuditOutbox(
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            payload=payload,
            status="pending",
            created_at=utc_now(),
        )
        if session is not None:
            session.add(row)
            return
        with self._db.unit_of_work() as uow:
            uow.session.add(row)
