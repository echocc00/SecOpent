# src/secopent/interfaces/api/routers/evidence.py
"""Evidence resource router (Phase A P1, W1): three-layer, content-addressed.

Read-only surface over ``SqlAlchemyEvidenceRepository``:
- ``GET /evidence`` - list evidence, optionally filtered to one finding's
  correlated evidence ids (``?finding_id=``);
- ``GET /evidence/{evidence_id}`` - one evidence object.

Evidence is captured by the scan pipeline (``EvidenceService``) and never
mutated - the RAW layer is write-once; REDACTED/SUMMARY are derived objects
linked via ``source_id``. There is no POST here.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ....domain.evidence.models import Evidence
from ....infrastructure.repositories.sqlalchemy_evidence import (
    SqlAlchemyEvidenceRepository,
)
from ....infrastructure.repositories.sqlalchemy_findings import (
    SqlAlchemyFindingRepository,
)
from ..deps import DbSession
from ..schemas import EvidenceOut

router = APIRouter(prefix="/evidence", tags=["evidence"])


def _to_out(evidence: Evidence) -> EvidenceOut:
    return EvidenceOut(
        id=evidence.id,
        layer=evidence.layer.value,
        sha256=evidence.sha256,
        storage_uri=evidence.storage_uri,
        source_id=evidence.source_id,
        signature=evidence.signature,
    )


@router.get("", response_model=list[EvidenceOut])
def list_evidence(
    session: DbSession, finding_id: str | None = None
) -> list[EvidenceOut]:
    repo = SqlAlchemyEvidenceRepository(session)
    if finding_id is None:
        return [_to_out(e) for e in repo.all()]
    finding = SqlAlchemyFindingRepository(session).get(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    result: list[EvidenceOut] = []
    for evidence_id in finding.evidence_ids:
        evidence = repo.get(evidence_id)
        if evidence is not None:
            result.append(_to_out(evidence))
    return result


@router.get("/{evidence_id}", response_model=EvidenceOut)
def get_evidence(evidence_id: str, session: DbSession) -> EvidenceOut:
    evidence = SqlAlchemyEvidenceRepository(session).get(evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="evidence not found")
    return _to_out(evidence)
