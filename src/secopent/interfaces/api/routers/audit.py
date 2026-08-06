# src/secopent/interfaces/api/routers/audit.py
"""Audit resource router (Phase A P1, W1): the tamper-evident hash chain.

Query surface over ``SqlAlchemyAuditRepository``:
- ``GET /audit/events`` - the ordered queryable audit event log;
- ``GET /audit/verify`` - recompute and verify the whole hash chain;
- ``GET /audit/chain`` - the SIGNED chain (optionally GDPR-redacted export).

Lifecycle surface over the shared ``AuditChain`` (v0.5.0 Phase 3, 3.6):
- ``POST /audit/rotate`` - rotate the log; the new segment continues from
  the prior tail (human-only);
- ``POST /audit/redact`` - GDPR: mask PII keys on a stored event while
  preserving the hash commitment (human-only).

Audit events are otherwise only ever appended by application services; the
chain's integrity depends on server-side append-only writes, and lifecycle
actions record themselves into the chain.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from ....application.audit_chain import AuditChain, SignedAuditEvent
from ....domain.audit.models import AuditEvent
from ....infrastructure.repositories.sqlalchemy_core import SqlAlchemyAuditRepository
from ..deps import DbSession
from ..schemas import (
    AuditChainEventOut,
    AuditEventOut,
    AuditRedactRequest,
    AuditRotateRequest,
    AuditVerifyOut,
)

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


def _to_chain_out(signed: SignedAuditEvent) -> AuditChainEventOut:
    return AuditChainEventOut(
        event_id=signed.event.id,
        action=signed.event.action,
        event_hash=signed.event.event_hash,
        signature=signed.signature,
    )


def _require_human(actor_role: str) -> None:
    """Audit-chain lifecycle actions are human decisions (LLM boundary)."""
    if actor_role != "human":
        raise HTTPException(
            status_code=403,
            detail="audit chain lifecycle actions are human-only (LLM boundary)",
        )


def _chain(request: Request) -> AuditChain:
    chain = getattr(request.app.state, "audit_chain", None)
    if chain is None:
        raise HTTPException(status_code=503, detail="audit chain not configured")
    return chain  # type: ignore[no-any-return]


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


@router.get("/chain", response_model=list[AuditEventOut])
def export_chain(
    request: Request, session: DbSession, redacted: bool = False
) -> list[AuditEventOut]:
    """Export the SIGNED chain; ``redacted=true`` masks GDPR-redacted keys.

    Every event's hash commitment is preserved either way - redaction only
    masks PII plaintext in the exported payloads.
    """
    del session  # the signed chain lives in app state, not the queryable log
    return [_to_out(e) for e in _chain(request).export(redacted=redacted)]


@router.post("/rotate", status_code=201, response_model=AuditChainEventOut)
def rotate_audit_chain(
    payload: AuditRotateRequest, request: Request, session: DbSession
) -> AuditChainEventOut:
    """Rotate the audit log (§12): the new segment continues from the prior
    tail, so rotation never breaks chain verification.

    Human-only. The rotation event joins the request transaction (3.6): it
    commits or rolls back atomically with the response.
    """
    _require_human(payload.actor_role)
    signed = _chain(request).rotate(actor=payload.actor, session=session)
    return _to_chain_out(signed)


@router.post("/redact", status_code=201, response_model=AuditChainEventOut)
def redact_audit_event(
    payload: AuditRedactRequest, request: Request, session: DbSession
) -> AuditChainEventOut:
    """GDPR: mark PII keys redacted on a stored event; the hash commitment
    is preserved and the deletion is itself recorded in the chain.

    Human-only. The redaction event joins the request transaction (3.6).
    """
    _require_human(payload.actor_role)
    if not payload.event_id.strip():
        raise HTTPException(status_code=422, detail="event_id is required")
    if not payload.keys:
        raise HTTPException(status_code=422, detail="keys must not be empty")
    chain = _chain(request)
    known_ids = {e.id for e in chain.events()}
    if payload.event_id not in known_ids:
        raise HTTPException(status_code=404, detail="audit event not found")
    signed = chain.redact_pii(
        payload.event_id,
        keys=frozenset(payload.keys),
        actor=payload.actor,
        session=session,
    )
    return _to_chain_out(signed)
