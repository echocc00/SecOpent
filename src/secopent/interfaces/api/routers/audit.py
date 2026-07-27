# src/secopent/interfaces/api/routers/audit.py
"""Audit resource router (Phase A P1, W1): the tamper-evident hash chain.

Read-only surface over ``SqlAlchemyAuditRepository``:
- ``GET /audit/events`` - the ordered audit event log;
- ``GET /audit/verify`` - recompute and verify the whole hash chain.

Audit events are only ever appended by application services (``AuditService``);
there is no POST here because the chain's integrity depends on server-side
append-only writes.
"""
from __future__ import annotations

from fastapi import APIRouter

from ....domain.audit.models import AuditEvent
from ....infrastructure.repositories.sqlalchemy_core import SqlAlchemyAuditRepository
from ..deps import DbSession
from ..schemas import AuditEventOut, AuditVerifyOut

router = APIRouter(prefix="/audit", tags=["audit"])


def _to_out(event: AuditEvent) -> AuditEventOut:
    return AuditEventOut(
        id=event.id,
        actor=event.actor,
        action=event.action,
        resource_type=event.resource_type,
        resource_id=event.resource_id,
        payload=event.payload,
        previous_hash=event.previous_hash,
        event_hash=event.event_hash,
        occurred_at=event.occurred_at,
    )


@router.get("/events", response_model=list[AuditEventOut])
def list_events(session: DbSession) -> list[AuditEventOut]:
    events = SqlAlchemyAuditRepository(session).list_events()
    return [_to_out(e) for e in events]


@router.get("/verify", response_model=AuditVerifyOut)
def verify_chain(session: DbSession) -> AuditVerifyOut:
    events = SqlAlchemyAuditRepository(session).list_events()
    return AuditVerifyOut(
        valid=AuditEvent.verify_chain(events),
        event_count=len(events),
    )
