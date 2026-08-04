"""SqlAlchemyConfirmedFindingRepository round-trip (W3-A T3)."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from secopent.domain.verification.models import ConfirmedFinding, VulnType
from secopent.infrastructure.db import confirmed_finding_models  # noqa: F401
from secopent.infrastructure.db.core_models import CoreBase
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_confirmed import (
    SqlAlchemyConfirmedFindingRepository,
)


def _confirmed(candidate_id: str = "finding:abc") -> ConfirmedFinding:
    return ConfirmedFinding(
        candidate_id=candidate_id,
        vuln_type=VulnType.SQLI,
        evidence_ids=("ev-1", "ev-2"),
        verified_at=datetime(2026, 1, 1, tzinfo=UTC),
        successes=5,
        attempts=5,
    )


@pytest.fixture
def session(tmp_path):  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(tmp_path / "confirmed.db")
    CoreBase.metadata.create_all(engine)
    return Session(engine)


def test_add_and_get_round_trip(session: Session) -> None:
    repo = SqlAlchemyConfirmedFindingRepository(session)
    repo.add(_confirmed("finding:1"))
    session.commit()
    got = repo.get("finding:1")
    assert got is not None
    assert got.candidate_id == "finding:1"
    assert got.vuln_type is VulnType.SQLI
    assert got.successes == 5
    assert got.attempts == 5
    assert got.evidence_ids == ("ev-1", "ev-2")
    assert got.verified_at == datetime(2026, 1, 1, tzinfo=UTC)


def test_get_missing_returns_none(session: Session) -> None:
    assert SqlAlchemyConfirmedFindingRepository(session).get("nope") is None


def test_add_upserts_on_same_candidate_id(session: Session) -> None:
    """Re-confirming a finding updates the row (merge semantics)."""
    repo = SqlAlchemyConfirmedFindingRepository(session)
    repo.add(_confirmed("finding:1"))
    session.commit()
    # Re-add with different counts -> the row is replaced, not duplicated.
    repo.add(ConfirmedFinding(
        candidate_id="finding:1",
        vuln_type=VulnType.SQLI,
        evidence_ids=(),
        verified_at=datetime(2026, 1, 2, tzinfo=UTC),
        successes=3,
        attempts=3,
    ))
    session.commit()
    got = repo.get("finding:1")
    assert got is not None
    assert got.successes == 3
    assert got.attempts == 3


def test_list_for_candidates(session: Session) -> None:
    repo = SqlAlchemyConfirmedFindingRepository(session)
    repo.add(_confirmed("finding:1"))
    repo.add(_confirmed("finding:2"))
    session.commit()
    rows = repo.list_for_candidates(("finding:1", "finding:2", "finding:3"))
    ids = {r.candidate_id for r in rows}
    assert ids == {"finding:1", "finding:2"}


def test_list_for_empty_candidates_returns_empty(session: Session) -> None:
    assert SqlAlchemyConfirmedFindingRepository(session).list_for_candidates(()) == ()
