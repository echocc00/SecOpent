"""DatabaseAuditRecorder: session-factory-backed AuditRecorder (W4-A T5).

For singleton application services (e.g. PeerAgentService on ``app.state``)
that outlive any single request, a session-bound ``SqlAlchemyAuditRepository``
is wrong - it would hold one session open for the app's lifetime. This
recorder opens a fresh session per ``record()`` call and does last_hash +
create + add + commit atomically inside it, so the hash chain stays
consistent under concurrent recorders.

Satisfies the ``AuditRecorder`` Protocol (``record`` only); the full
``AuditService`` (chain HMAC, verify) is still constructed per-request where a
session is naturally scoped.
"""
from __future__ import annotations

from ...domain.audit.models import GENESIS_HASH, AuditEvent
from ..db.session import Database
from ..repositories.sqlalchemy_core import SqlAlchemyAuditRepository


class DatabaseAuditRecorder:
    """Append-only audit sink backed by the shared Database (session per call)."""

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
    ) -> AuditEvent:
        session = self._db.open_session()
        try:
            repo = SqlAlchemyAuditRepository(session)
            previous = repo.last_hash() or GENESIS_HASH
            event = AuditEvent.create(
                event_id=f"evt-{len(repo.list_events()) + 1}",
                actor=actor,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                payload=payload,
                previous_hash=previous,
            )
            repo.add(event)
            session.commit()
            return event
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
