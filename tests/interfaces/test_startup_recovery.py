"""Startup recovery: leftover RUNNING/QUEUED assessments -> FAILED.

Covers integration-graph edge 20: an assessment left mid-flight by a crash,
restart, or deploy must not spin forever in the UI - create_app transitions
stale RUNNING/QUEUED rows to FAILED at boot (the operator re-starts it
explicitly). Terminal statuses are untouched.
"""
from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from secopent.domain.assessments.models import AssessmentStatus
from secopent.domain.common.canonical import utc_now
from secopent.infrastructure.db.core_models import (
    CoreAssessment,
    CoreProject,
    CoreScopeSnapshot,
)
from secopent.infrastructure.db.session import init_db
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAssessmentRepository,
)
from secopent.interfaces.api.main import create_app


def _assessment(aid: str, status: str) -> CoreAssessment:
    return CoreAssessment(
        id=aid, project_id="p1", scope_snapshot_id="s1", mode="approval",
        status=status, active_plan_id=None, approval_id=None,
    )


def test_startup_recovery_marks_stale_running_and_queued_failed(
    tmp_path: Path,
) -> None:
    engine = create_sqlite_engine(tmp_path / "recovery.db")
    # Simulate a crash: seed mid-flight rows BEFORE the app boots. Parents
    # are committed first (they predate the crash), then the assessments.
    init_db(engine, mode="always")
    with Session(engine) as session:
        session.add(CoreProject(id="p1", name="t", status="active", created_at=utc_now()))
        session.add(
            CoreScopeSnapshot(
                id="s1", project_id="p1", include=[], exclude=[], ports=[],
                limits={}, approved_by="a", approved_at=utc_now(),
                digest="sha256:x",
            )
        )
        session.commit()
    with Session(engine) as session:
        session.add(_assessment("a-run", "running"))
        session.add(_assessment("a-queued", "queued"))
        session.add(_assessment("a-done", "completed"))
        session.commit()

    create_app(engine=engine)  # recovery runs during construction

    with Session(engine) as session:
        repo = SqlAlchemyAssessmentRepository(session)
        running = repo.get("a-run")
        queued = repo.get("a-queued")
        done = repo.get("a-done")
    assert running is not None and running.status is AssessmentStatus.FAILED
    assert queued is not None and queued.status is AssessmentStatus.FAILED
    assert done is not None and done.status is AssessmentStatus.COMPLETED
