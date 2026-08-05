"""Production-realism: outbox end-to-end + crash-restart drain (v0.3.0 T4).

Part 1: a full daemon run with the outbox wired completes; draining moves
every pending row into BOTH audit tables (done + processed_at).
Part 2 (D4): rows left pending by a crash are drained synchronously by a
FRESH chain/worker before serving, and the rebuilt chain verifies - no gap
in the permit-replay detection state after crash+restart.
"""
from __future__ import annotations

import threading
from pathlib import Path

import pytest
from sqlalchemy import select

from secopent.application.audit_chain import AuditChain
from secopent.application.execution import execute_assessment
from secopent.domain.assessments.models import AssessmentStatus
from secopent.infrastructure.audit.key_manager import AuditKeyManager
from secopent.infrastructure.audit.outbox_recorder import OutboxRecorder
from secopent.infrastructure.audit.outbox_worker import OutboxWorker
from secopent.infrastructure.db.outbox_models import CoreAuditOutbox
from secopent.infrastructure.db.session import Database
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_audit_chain import (
    SqlAlchemySignedAuditEventStore,
)
from secopent.infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAssessmentRepository,
    SqlAlchemyAuditRepository,
    SqlAlchemyScopeRepository,
)
from secopent.infrastructure.repositories.sqlalchemy_findings import (
    SqlAlchemyFindingRepository,
)


class _NoopRunner:
    """Step runner that returns instantly with no observations."""

    def run(self, step):  # type: ignore[no-untyped-def]
        from secopent.application.orchestrator import StepResult

        return StepResult(result_digest="sha256:noop")

    def all_observations(self):  # type: ignore[no-untyped-def]
        return ()


def _seed_queued(db: Database) -> str:
    """project -> scope -> assessment -> plan -> approval -> start (QUEUED)."""
    from secopent.application.assessments import AssessmentService
    from secopent.domain.assessments.models import PlanStep
    from secopent.domain.common.canonical import utc_now
    from secopent.domain.policy.models import ExecutionMode, RiskClass
    from secopent.domain.projects.models import Project
    from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot
    from secopent.infrastructure.repositories.sqlalchemy_core import (
        SqlAlchemyProjectRepository,
    )

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
def test_outbox_end_to_end_and_crash_restart(tmp_path: Path) -> None:
    db = Database(create_sqlite_engine(tmp_path / "outbox_real.db"))
    keys = AuditKeyManager()
    chain = AuditChain(keys, store=SqlAlchemySignedAuditEventStore(db))
    outbox = OutboxRecorder(db)
    worker = OutboxWorker(db, chain, poll_interval=0.05)
    assessment_id = _seed_queued(db)

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
                    step_runner_factory=lambda _scope: _NoopRunner(),
                    audit_chain=chain,
                    audit_outbox=outbox,
                )
        except Exception as exc:  # noqa: BLE001 - surface daemon failures
            errors.append(exc)

    thread = threading.Thread(target=daemon)
    thread.start()
    thread.join(timeout=60)
    assert not errors, f"daemon failed: {errors[:3]}"

    with db.unit_of_work() as check:
        assessment = SqlAlchemyAssessmentRepository(check.session).get(assessment_id)
        assert assessment is not None
        assert assessment.status is AssessmentStatus.COMPLETED
        # The daemon wrote outbox rows; nothing went to core_audit_events yet
        # (the worker has not run) - audit is off the hot path.
        pending = check.session.scalars(
            select(CoreAuditOutbox).where(CoreAuditOutbox.status == "pending")
        ).all()
    assert len(pending) >= 2
    assert {r.action for r in pending} >= {
        "assessment.started", "assessment.completed",
    }

    # Drain (what the worker thread does continuously in production).
    drained = worker.drain_pending()
    assert drained == len(pending)
    with db.unit_of_work() as check:
        rows = check.session.scalars(select(CoreAuditOutbox)).all()
    assert {r.status for r in rows} == {"done"}
    chain_actions = {e.action for e in chain.events()}
    assert {"assessment.started", "assessment.completed"} <= chain_actions
    assert chain.verify() is True

    # --- Part 2: crash-restart (D4) ---------------------------------------
    # A row lands in the outbox, then the process dies before the worker
    # drains it. A fresh chain + worker must pick it up with no gap.
    outbox.record(
        actor="system", action="post.crash.event",
        resource_type="assessment", resource_id=assessment_id, payload={},
    )
    fresh_chain = AuditChain(keys, store=SqlAlchemySignedAuditEventStore(db))
    assert "post.crash.event" not in {e.action for e in fresh_chain.events()}
    fresh_worker = OutboxWorker(db, fresh_chain, poll_interval=0.05)
    assert fresh_worker.drain_pending() == 1
    assert "post.crash.event" in {e.action for e in fresh_chain.events()}
    assert fresh_chain.verify() is True
