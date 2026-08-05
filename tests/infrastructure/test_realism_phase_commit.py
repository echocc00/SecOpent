"""Production-realism regression: per-phase commits release the WAL write lock
during long scan phases (v0.3.0 T3; v4 root cause).

The pre-T3 daemon held ONE transaction (and thus SQLite's single WAL write
lock) for the entire assessment - an 8-15 minute scan blocked every other
writer until busy_timeout expired. This test proves the lock is released
during the scan phase: while the step runner blocks, a second connection with
a deliberately tiny busy timeout can INSERT immediately. Pre-T3 this INSERT
raised ``database is locked``.
"""
from __future__ import annotations

import threading
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from secopent.application.assessments import AssessmentService
from secopent.application.execution import execute_assessment
from secopent.application.orchestrator import StepResult
from secopent.domain.adapters.contracts import Observation
from secopent.domain.assessments.models import AssessmentStatus, PlanStep
from secopent.domain.policy.models import ExecutionMode, RiskClass
from secopent.domain.projects.models import Project
from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot
from secopent.infrastructure.db.session import Database
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAssessmentRepository,
    SqlAlchemyAuditRepository,
    SqlAlchemyProjectRepository,
    SqlAlchemyScopeRepository,
)
from secopent.infrastructure.repositories.sqlalchemy_findings import (
    SqlAlchemyFindingRepository,
)


class _BlockingStepRunner:
    """Blocks in run() until released - simulates a multi-minute scan."""

    def __init__(self, entered: threading.Event, released: threading.Event) -> None:
        self._entered = entered
        self._released = released

    def run(self, step: PlanStep) -> StepResult:
        self._entered.set()
        assert self._released.wait(30), "test never released the scan phase"
        return StepResult(result_digest="sha256:fake")

    def all_observations(self) -> tuple[Observation, ...]:
        return ()


def _seed_queued(db: Database) -> str:
    """project -> scope -> assessment -> plan -> approval -> start (QUEUED)."""
    from secopent.domain.common.canonical import utc_now

    with db.unit_of_work() as uow:
        SqlAlchemyProjectRepository(uow.session).add(
            Project.create(project_id="p1", name="t")
        )
        SqlAlchemyScopeRepository(uow.session).add_snapshot(
            ScopeSnapshot(
                id="s1", project_id="p1", include=("http://target",), exclude=(),
                ports=(80,),
                limits=ScopeLimits(
                    requests_per_second=10, concurrency=2, max_requests=100
                ),
                approved_by="a", approved_at=utc_now(), digest="sha256:scope",
            )
        )
        service = AssessmentService(SqlAlchemyAssessmentRepository(uow.session))
        assessment = service.create(
            project_id="p1", scope_snapshot_id="s1", mode=ExecutionMode.APPROVAL
        )
        service.attach_plan(
            assessment.id,
            steps=(
                PlanStep(
                    key="nuclei-sqli", runner="nuclei", risk=RiskClass.LOW,
                    parameters={"target": "http://target"}, dependencies=(),
                ),
            ),
        )
        service.approve(
            assessment_id=assessment.id, approved_by="analyst",
            approved_risks=frozenset({RiskClass.LOW}),
            approved_capabilities=frozenset(), scope_digest="sha256:scope",
        )
        service.start(assessment.id)
        return assessment.id


@pytest.mark.realism
def test_scan_phase_releases_wal_write_lock(tmp_path: Path) -> None:
    db_path = tmp_path / "phase.db"
    db = Database(create_sqlite_engine(db_path))
    assessment_id = _seed_queued(db)

    entered = threading.Event()
    released = threading.Event()
    errors: list[Exception] = []

    def daemon() -> None:
        try:
            with db.unit_of_work() as uow:
                execute_assessment(
                    assessment_id=assessment_id,
                    assessment_repo=SqlAlchemyAssessmentRepository(uow.session),
                    scope_repo=SqlAlchemyScopeRepository(uow.session),
                    finding_repo=SqlAlchemyFindingRepository(uow.session),
                    audit_repo=SqlAlchemyAuditRepository(uow.session),
                    step_runner_factory=lambda _scope: _BlockingStepRunner(
                        entered, released
                    ),
                )
        except Exception as exc:  # noqa: BLE001 - surface any daemon failure
            errors.append(exc)

    thread = threading.Thread(target=daemon)
    thread.start()
    assert entered.wait(15), "scan phase never started"

    # While the scan "runs": a second connection with a 1s busy timeout must
    # be able to write immediately. Pre-T3 the daemon's open transaction held
    # the WAL write lock for the whole assessment -> OperationalError here.
    probe = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False, "timeout": 1.0},
    )
    with probe.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO core_projects (id, name, status, created_at) "
                "VALUES ('probe', 'probe', 'active', '2026-01-01 00:00:00')"
            )
        )
    probe.dispose()

    released.set()
    thread.join(timeout=60)
    assert not thread.is_alive(), "daemon did not finish"
    assert not errors, f"daemon failed: {errors[:3]}"

    with db.unit_of_work() as check:
        assessment = SqlAlchemyAssessmentRepository(check.session).get(assessment_id)
        assert assessment is not None
        assert assessment.status is AssessmentStatus.COMPLETED
        actions = {
            e.action for e in SqlAlchemyAuditRepository(check.session).list_events()
        }
    assert {"assessment.started", "assessment.completed"} <= actions
