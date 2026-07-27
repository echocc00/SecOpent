# src/secopent/infrastructure/repositories/sqlalchemy_evidence.py
"""SqlAlchemy repository for content-addressed evidence (§13, three-layer)."""
from __future__ import annotations

from sqlalchemy.orm import Session

from ...domain.evidence.models import Evidence, EvidenceLayer
from ..db.evidence_models import CoreEvidence


def _to_evidence(row: CoreEvidence) -> Evidence:
    return Evidence(
        id=row.id,
        layer=EvidenceLayer(row.layer),
        sha256=row.sha256,
        storage_uri=row.storage_uri,
        source_id=row.source_id,
        signature=row.signature,
    )


def _from_evidence(evidence: Evidence) -> CoreEvidence:
    return CoreEvidence(
        id=evidence.id,
        layer=evidence.layer.value,
        sha256=evidence.sha256,
        storage_uri=evidence.storage_uri,
        source_id=evidence.source_id,
        signature=evidence.signature,
    )


class SqlAlchemyEvidenceRepository:
    """Persisted Evidence store (content-addressed, three-layer)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, evidence: Evidence) -> None:
        self._session.merge(_from_evidence(evidence))

    def get(self, evidence_id: str) -> Evidence | None:
        row = self._session.get(CoreEvidence, evidence_id)
        return _to_evidence(row) if row else None

    def all(self) -> list[Evidence]:
        return [_to_evidence(row) for row in self._session.query(CoreEvidence).all()]
