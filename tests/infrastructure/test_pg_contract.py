"""Repository contract portability test (M5 Task 9, §13 SQLite<->PG).

The same repository code must run unchanged on SQLite and PostgreSQL (M0's
Repository abstraction). The SQLite run always executes; the PostgreSQL run
executes only when ``SECOPENT_PG_URL`` is set (skipped otherwise), proving the
switch needs no domain/application refactor.
"""
from __future__ import annotations

import os

import pytest
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from secopent.domain.adapters.contracts import Severity
from secopent.domain.findings.models import Finding, FindingStatus

# Register all ORM tables on CoreBase.metadata.
from secopent.infrastructure.db import (  # noqa: F401
    asset_models,
    finding_models,
    job_models,
    report_models,
)
from secopent.infrastructure.db.core_models import CoreBase
from secopent.infrastructure.db.postgres import create_postgres_engine
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_findings import (
    SqlAlchemyFindingRepository,
)


def _finding_round_trip(engine: Engine) -> None:
    CoreBase.metadata.create_all(engine)
    session = Session(engine)
    finding = Finding(
        id="f-contract",
        fingerprint="sha256:" + "c" * 64,
        title="contract finding",
        asset="https://x.test/",
        severity=Severity.HIGH,
        cwe=("CWE-89",),
        status=FindingStatus.VALIDATED,
    )
    repo = SqlAlchemyFindingRepository(session)
    repo.add(finding)
    session.commit()
    loaded = SqlAlchemyFindingRepository(session).get("f-contract")
    assert loaded == finding


@pytest.fixture
def sqlite_engine(tmp_path):  # type: ignore[no-untyped-def]
    return create_sqlite_engine(tmp_path / "contract.db")


def test_finding_contract_on_sqlite(sqlite_engine: Engine) -> None:
    _finding_round_trip(sqlite_engine)


def test_finding_contract_on_postgres() -> None:
    dsn = os.environ.get("SECOPENT_PG_URL")
    if not dsn:
        pytest.skip("SECOPENT_PG_URL not set; PostgreSQL contract run skipped")
    _finding_round_trip(create_postgres_engine(dsn))
