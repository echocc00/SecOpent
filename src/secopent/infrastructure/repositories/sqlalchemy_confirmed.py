# src/secopent/infrastructure/repositories/sqlalchemy_confirmed.py
"""SqlAlchemy ConfirmedFindingRepository (W3-A T3)."""
from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...domain.verification.models import ConfirmedFinding, VulnType
from ..db.confirmed_finding_models import CoreConfirmedFinding


def _to_row(c: ConfirmedFinding) -> CoreConfirmedFinding:
    return CoreConfirmedFinding(
        candidate_id=c.candidate_id,
        vuln_type=c.vuln_type.value,
        evidence_ids=list(c.evidence_ids),
        verified_at=c.verified_at,
        successes=c.successes,
        attempts=c.attempts,
    )


def _to_entity(row: CoreConfirmedFinding) -> ConfirmedFinding:
    verified_at = row.verified_at
    # SQLite stores DateTime(timezone=True) as naive; re-attach UTC.
    if verified_at.tzinfo is None:
        verified_at = verified_at.replace(tzinfo=UTC)
    return ConfirmedFinding(
        candidate_id=row.candidate_id,
        vuln_type=VulnType(row.vuln_type),
        evidence_ids=tuple(row.evidence_ids),
        verified_at=verified_at,
        successes=row.successes,
        attempts=row.attempts,
    )


class SqlAlchemyConfirmedFindingRepository:
    """Persisted ConfirmedFinding store."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, confirmed: ConfirmedFinding) -> None:
        self._session.merge(_to_row(confirmed))

    def get(self, candidate_id: str) -> ConfirmedFinding | None:
        row = self._session.get(CoreConfirmedFinding, candidate_id)
        return _to_entity(row) if row is not None else None

    def list_for_candidates(
        self, candidate_ids: Sequence[str]
    ) -> tuple[ConfirmedFinding, ...]:
        if not candidate_ids:
            return ()
        stmt = select(CoreConfirmedFinding).where(
            CoreConfirmedFinding.candidate_id.in_(tuple(candidate_ids))
        )
        return tuple(_to_entity(r) for r in self._session.scalars(stmt))
