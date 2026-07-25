"""Round-trip tests for the M4 persistence repositories (Task 11)."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secopent.domain.adapters.contracts import Severity
from secopent.domain.assets.graph import AssetGraph
from secopent.domain.assets.models import AssetEdge, AssetNode, AssetRelation, AssetType
from secopent.domain.findings.models import Finding, FindingStatus
from secopent.domain.jobs.models import Job, JobStatus
from secopent.domain.reports.models import Report, ReportSection, ReportStatus

# Importing the model modules registers their tables on CoreBase.metadata.
from secopent.infrastructure.db import (  # noqa: F401
    asset_models,
    finding_models,
    job_models,
    report_models,
)
from secopent.infrastructure.db.core_models import CoreBase
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_assets import (
    SqlAlchemyAssetRepository,
)
from secopent.infrastructure.repositories.sqlalchemy_findings import (
    SqlAlchemyFindingRepository,
)
from secopent.infrastructure.repositories.sqlalchemy_jobs import SqlAlchemyJobRepository
from secopent.infrastructure.repositories.sqlalchemy_reports import (
    SqlAlchemyReportRepository,
)


@pytest.fixture
def session(tmp_path):  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(tmp_path / "m4.db")
    CoreBase.metadata.create_all(engine)
    return Session(engine)


def test_asset_graph_round_trip(session: Session) -> None:
    domain = AssetNode(type=AssetType.DOMAIN, value="example.com")
    ip = AssetNode(type=AssetType.IP, value="192.0.2.1")
    graph = AssetGraph().add_edge(
        AssetEdge(src=domain, dst=ip, rel=AssetRelation.RESOLVES_TO)
    )
    repo = SqlAlchemyAssetRepository(session)
    repo.save_graph(graph)
    session.commit()

    loaded = SqlAlchemyAssetRepository(session).load_graph()
    assert set(loaded.nodes) == {domain, ip}
    assert loaded.neighbors(domain) == (ip,)


def test_finding_round_trip(session: Session) -> None:
    finding = Finding(
        id="f1",
        fingerprint="sha256:" + "a" * 64,
        title="SQLi",
        asset="https://x.test/login",
        severity=Severity.HIGH,
        cwe=("CWE-89",),
        observation_ids=("obs-1",),
        evidence_ids=("ev-1",),
        status=FindingStatus.VALIDATED,
    )
    repo = SqlAlchemyFindingRepository(session)
    repo.add(finding)
    session.commit()
    assert SqlAlchemyFindingRepository(session).get("f1") == finding


def test_report_round_trip(session: Session) -> None:
    report = Report(
        id="rep-1",
        assessment_id="assess-1",
        title="Report",
        sections=(ReportSection(name="findings", content="## Findings"),),
        finding_count=1,
        coverage_rate=1.0,
        completeness_ok=True,
        status=ReportStatus.RENDERED,
        digest="sha256:" + "d" * 64,
    )
    repo = SqlAlchemyReportRepository(session)
    repo.add(report)
    session.commit()
    loaded = SqlAlchemyReportRepository(session).get("rep-1")
    assert loaded == report
    assert loaded.section("findings").content == "## Findings"


def test_job_round_trip_preserves_lease(session: Session) -> None:
    expires = datetime(2026, 1, 1, 0, 5, tzinfo=UTC)
    job = Job(
        id="job-1",
        plan_step_key="recon",
        idempotency_key="digest:recon",
        status=JobStatus.LEASED,
        attempt=1,
        lease_owner="worker-1",
        lease_expires_at=expires,
        dependencies=("a", "b"),
    )
    repo = SqlAlchemyJobRepository(session)
    repo.add(job)
    session.commit()
    loaded = SqlAlchemyJobRepository(session).get("job-1")
    assert loaded == job
    assert loaded.lease_expires_at == expires
    assert loaded.dependencies == ("a", "b")


def test_job_idempotency_key_unique(session: Session) -> None:
    repo = SqlAlchemyJobRepository(session)
    repo.add(Job(id="j1", plan_step_key="k", idempotency_key="same"))
    session.commit()
    repo.add(Job(id="j2", plan_step_key="k2", idempotency_key="same"))
    with pytest.raises(IntegrityError):  # duplicate idempotency_key
        session.commit()
