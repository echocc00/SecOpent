"""Tests for SqlAlchemyCaseRegistry: durable CaseDefinition round-trip (P1 W1d)."""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace

import pytest
from sqlalchemy.orm import Session

from secopent.domain.cases.models import (
    CaseAssertion,
    CaseDefinition,
    CaseOrigin,
    CaseStatus,
    CaseStep,
    CaseVerification,
)
from secopent.domain.policy.models import RiskClass
from secopent.infrastructure.db.session import init_db
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_cases import (
    SqlAlchemyCaseRegistry,
)


@pytest.fixture
def session(tmp_path) -> Iterator[Session]:  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(tmp_path / "cases.db")
    init_db(engine)
    with Session(engine) as s:
        yield s


def _full_case() -> CaseDefinition:
    return CaseDefinition(
        id="case-full",
        version="1.2.0",
        author="analyst",
        risk=RiskClass.ACTIVE,
        target_type="web_app",
        schema="secopent-case/v1",
        steps=(
            CaseStep(id="s1", action="http.request", spec={"method": "POST", "path": "/login"}),
            CaseStep(id="s2", action="assert.status", spec={"expect": 200}),
        ),
        preconditions=("authenticated",),
        assertions=(CaseAssertion(id="a1", expression="status == 200"),),
        evidence_req=("response_body",),
        cwe=("CWE-89",),
        cve=("CVE-2024-1234",),
        owasp=("A03:2021",),
        verification=CaseVerification(method="sql_injection", reproduce=2),
        signature="sig:abc",
        min_engine_version="1.0.0",
        origin=CaseOrigin.MANUAL,
        status=CaseStatus.VALIDATED,
    )


def test_case_round_trip_preserves_all_fields(session: Session) -> None:
    repo = SqlAlchemyCaseRegistry(session)
    original = _full_case()
    repo.put(original)
    session.commit()

    fetched = repo.get("case-full")
    assert fetched == original
    assert fetched is not None
    assert fetched.verification is not None
    assert fetched.verification.method == "sql_injection"
    assert fetched.verification.reproduce == 2
    assert fetched.steps[0].spec == {"method": "POST", "path": "/login"}
    assert fetched.assertions[0].expression == "status == 200"


def test_case_list_ordered_by_id(session: Session) -> None:
    repo = SqlAlchemyCaseRegistry(session)
    for case_id in ("case-b", "case-a"):
        repo.put(
            CaseDefinition(
                id=case_id, version="1.0.0", author="x", risk=RiskClass.LOW,
                target_type="http", schema="s",
                steps=(CaseStep(id="s", action="http.request", spec={}),),
            )
        )
    session.commit()
    assert [c.id for c in repo.list()] == ["case-a", "case-b"]


def test_case_put_is_idempotent_upsert(session: Session) -> None:
    repo = SqlAlchemyCaseRegistry(session)
    repo.put(_full_case())
    session.commit()
    # Re-putting the same id updates (merge) rather than duplicating.
    updated = replace(_full_case(), status=CaseStatus.REVIEWED)
    repo.put(updated)
    session.commit()
    assert len(repo.list()) == 1
    fetched = repo.get("case-full")
    assert fetched is not None
    assert fetched.status is CaseStatus.REVIEWED


def test_case_get_missing_returns_none(session: Session) -> None:
    assert SqlAlchemyCaseRegistry(session).get("nope") is None
