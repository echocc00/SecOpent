"""OutboxWorker: drain the audit outbox into both audit tables (v0.3.0 T4).

Single background thread, one short transaction PER ROW (an audit insert +
the outbox status flip commit atomically; a failing row can neither poison
its neighbours nor be re-drained into duplicates). Rows drain in id order so
the signed chain's counter/tail advance monotonically. A row that fails is
flagged ``failed`` with the error kept for operator inspection - never
silently dropped.

Startup callers use ``drain_pending()`` synchronously BEFORE the app serves
requests, so rows left pending by a crash/restart reach the signed chain -
and thus the permit-replay detection state - with no gap (design point D4).
"""
from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any

import structlog
from sqlalchemy import select

from ...application.audit import AuditService
from ...domain.common.canonical import utc_now
from ..db.outbox_models import CoreAuditOutbox
from ..db.session import Database
from ..repositories.sqlalchemy_core import SqlAlchemyAuditRepository

if TYPE_CHECKING:
    from ...application.audit_chain import AuditChain

_logger = structlog.get_logger(__name__)

_BATCH_SIZE = 100
_ERROR_TEXT_LIMIT = 1024


class OutboxWorker:
    """Drains ``core_audit_outbox`` -> audit tables off the hot path."""

    def __init__(
        self, db: Database, audit_chain: AuditChain, *, poll_interval: float = 1.0
    ) -> None:
        self._db = db
        self._audit_chain = audit_chain
        self._poll_interval = poll_interval
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run_forever(self) -> None:
        """Poll loop; run in a dedicated daemon thread."""
        while not self._stop.wait(self._poll_interval):
            try:
                self._drain_batch()
            except Exception:  # noqa: BLE001 - the worker must never die
                _logger.exception("outbox drain batch failed; retrying next poll")

    def drain_pending(self) -> int:
        """Drain until the outbox has no pending rows; returns rows drained.

        Used at startup (crash recovery) and shutdown (final flush). Errors
        are logged, not raised - boot/shutdown must not break on a transient
        drain failure; the rows stay pending for the next opportunity.
        """
        total = 0
        while True:
            try:
                drained = self._drain_batch()
            except Exception:  # noqa: BLE001 - see docstring
                _logger.exception("outbox drain_pending batch failed")
                return total
            if drained == 0:
                return total
            total += drained

    def _drain_batch(self) -> int:
        with self._db.unit_of_work() as listing:
            pending_ids = list(
                listing.session.scalars(
                    select(CoreAuditOutbox.id)
                    .where(CoreAuditOutbox.status == "pending")
                    .order_by(CoreAuditOutbox.id)
                    .limit(_BATCH_SIZE)
                )
            )
        for row_id in pending_ids:
            with self._db.unit_of_work() as uow:
                row = uow.session.get(CoreAuditOutbox, row_id)
                if row is None or row.status != "pending":
                    continue
                self._drain_row(uow.session, row)
        return len(pending_ids)

    def _drain_row(self, session: Any, row: CoreAuditOutbox) -> None:
        try:
            AuditService(SqlAlchemyAuditRepository(session)).record(
                actor=row.actor,
                action=row.action,
                resource_type=row.resource_type,
                resource_id=row.resource_id,
                payload=row.payload,
            )
            self._audit_chain.record(
                actor=row.actor,
                action=row.action,
                resource_type=row.resource_type,
                resource_id=row.resource_id,
                payload=row.payload,
                session=session,
            )
            row.status = "done"
            row.processed_at = utc_now()
        except Exception as exc:  # noqa: BLE001 - flag, never drop silently
            session.rollback()
            fresh = session.get(CoreAuditOutbox, row.id)
            if fresh is not None:
                fresh.status = "failed"
                fresh.error = str(exc)[:_ERROR_TEXT_LIMIT]
            _logger.warning(
                "outbox row failed to drain",
                outbox_id=row.id, action=row.action, error=str(exc),
            )
