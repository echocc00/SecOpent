# src/secopent/interfaces/api/routers/scopes.py
"""Scopes resource router (Phase A P1, W1)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ....application.audit import AuditService
from ....application.scopes import ScopeService
from ....domain.scope.models import ScopeSnapshot
from ....infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAuditRepository,
    SqlAlchemyScopeRepository,
)
from ..deps import DbSession
from ..schemas import ScopeDraftCreate, ScopeSnapshotOut

router = APIRouter(prefix="/scopes", tags=["scopes"])


def _to_out(snapshot: ScopeSnapshot) -> ScopeSnapshotOut:
    return ScopeSnapshotOut(
        id=snapshot.id,
        project_id=snapshot.project_id,
        include=list(snapshot.include),
        exclude=list(snapshot.exclude),
        ports=list(snapshot.ports),
        cloud_accounts=list(snapshot.cloud_accounts),
        approved_by=snapshot.approved_by,
        digest=snapshot.digest,
    )


@router.post("/draft", status_code=201, response_model=ScopeSnapshotOut)
def freeze_scope(payload: ScopeDraftCreate, session: DbSession) -> ScopeSnapshotOut:
    audit = AuditService(SqlAlchemyAuditRepository(session))
    service = ScopeService(SqlAlchemyScopeRepository(session), audit)
    snapshot = service.freeze(
        project_id=payload.project_id,
        include=tuple(payload.include),
        exclude=tuple(payload.exclude),
        ports=tuple(payload.ports),
        approved_by=payload.approved_by,
    )
    return _to_out(snapshot)


@router.get("/{snapshot_id}", response_model=ScopeSnapshotOut)
def get_scope(snapshot_id: str, session: DbSession) -> ScopeSnapshotOut:
    snapshot = SqlAlchemyScopeRepository(session).get_snapshot(snapshot_id)
    if snapshot is None:
        raise HTTPException(status_code=404, detail="scope snapshot not found")
    return _to_out(snapshot)
