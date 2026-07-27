# src/secopent/interfaces/api/routers/updates.py
"""Updates resource router (Phase A P1, W1): knowledge bundle state.

Read-only surface over ``SqlAlchemyUpdateRepository``:
- ``GET /updates/active`` - the currently active bundle id + record;
- ``GET /updates/bundles/{bundle_id}`` - one staged bundle.

Bundle sync/activation (``UpdateManager.sync``) is a signed, audited pipeline
requiring a fetcher + signature verifier + public key; it is orchestrated out
of band, not exposed as a naive POST here (the LLM boundary and signing
constraints keep activation server-side).
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from ....infrastructure.repositories.sqlalchemy_intel import SqlAlchemyUpdateRepository
from ..deps import DbSession
from ..schemas import ActiveBundleOut, UpdateBundleOut

router = APIRouter(prefix="/updates", tags=["updates"])


def _to_out(row: dict[str, Any]) -> UpdateBundleOut:
    return UpdateBundleOut(
        bundle_id=row["bundle_id"],
        version=row["version"],
        digest=row["digest"],
        staged_at=row.get("staged_at"),
    )


@router.get("/active", response_model=ActiveBundleOut)
def get_active_bundle(session: DbSession) -> ActiveBundleOut:
    repo = SqlAlchemyUpdateRepository(session)
    active_id = repo.get_active_bundle_id()
    if active_id is None:
        return ActiveBundleOut(active_bundle_id=None, bundle=None)
    row = repo.get_bundle(active_id)
    return ActiveBundleOut(
        active_bundle_id=active_id,
        bundle=_to_out(row) if row else None,
    )


@router.get("/bundles/{bundle_id}", response_model=UpdateBundleOut)
def get_bundle(bundle_id: str, session: DbSession) -> UpdateBundleOut:
    row = SqlAlchemyUpdateRepository(session).get_bundle(bundle_id)
    if row is None:
        raise HTTPException(status_code=404, detail="bundle not found")
    return _to_out(row)
