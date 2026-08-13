"""M4 integration: control-plane pause/resume/cancel through the real layers.

Drives the execution layer (Orchestrator + gate) over the in-memory repos
with a counting fake runner, exercising the exact machine the MCP tools drive:

- a CANCEL_REQUESTED signal blocks the run before the first step, invokes the
  cancel terminator, marks remaining jobs SKIPPED, and the CANCELLED terminal
  status is never overwritten by the executor;
- a PAUSE_REQUESTED signal stops the executor at the next step boundary
  (a step that was executing completes first; remaining jobs stay READY);
- resume_assessment() drains exactly the remaining READY jobs (dispatch is
  idempotent over the durable job store) and completes the assessment.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from test_execution import _MemoryFindingRepo  # type: ignore[import-not-found]

from secopent.application.assessments import AssessmentService
from secopent.application.execution import (
    _make_control_gate,
    resume_assessment,
)
from secopent.application.jobs import JobService, MemoryJobStore
from secopent.application.orchestrator import Orchestrator, StepResult
from secopent.domain.assessments.models import (
    Assessment,
    AssessmentStatus,
    ControlState,
    PlanStep,
)
from secopent.domain.jobs.models import JobStatus
from secopent.domain.policy.models import ExecutionMode, RiskClass
from secopent.domain.projects.models import Project
from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot


@dataclass
class _CountingRunner:
    """Fake StepRunner that counts every execution (no observations)."""

    calls: int = 0

    def run(self, step: PlanStep) -> StepResult:
        self.calls += 1
        return StepResult(result_digest="sha256:fake")

    def all_observations(self) -> tuple[object, ...]:
        return ()


def _two_step_assessment(repos):  # noqa: ANN001
    """Seed an APPROVED assessment with two independent plan steps."""
    repos.projects.add(Project.create(project_id="p1", name="t"))
    repos.scopes.add_snapshot(ScopeSnapshot(
        id="s1", project_id="p1", include=("http://target",), exclude=(),
        ports=(80,), limits=ScopeLimits(10.0, 2, 100),
        approved_by="a", approved_at=datetime.now(UTC), digest="sha256:scope",
    ))
    service = AssessmentService(repos.assessments)
    assessment = service.create(
        project_id="p1", scope_snapshot_id="s1", mode=ExecutionMode.APPROVAL
    )
    steps = tuple(
        PlanStep(
            key=key, runner="nuclei", risk=RiskClass.LOW,
            parameters={"target": "http://target"}, dependencies=(),
        )
        for key in ("s1", "s2")
    )
    service.attach_plan(assessment.id, steps=steps)
    service.approve(
        assessment_id=assessment.id, approved_by="analyst",
        approved_risks=frozenset({RiskClass.LOW}),
        approved_capabilities=frozenset(), scope_digest="sha256:scope",
    )
    # Re-read: the returned entity carries the plan + approval attachments.
    latest = repos.assessments.get(assessment.id)
    assert latest is not None
    return latest, service


def _gate_for(repos, assessment_id: str):  # noqa: ANN001
    return _make_control_gate(repos.assessments, assessment_id)


def _plan(repos, assessment: Assessment):  # noqa: ANN001
    plan = repos.assessments.get_plan(assessment.active_plan_id or "")
    assert plan is not None
    return plan


def test_cancel_blocks_first_step_skips_jobs_and_terminates(
    memory_repositories,
) -> None:  # noqa: ANN001
    assessment, service = _two_step_assessment(memory_repositories)
    service.start(assessment.id)
    service.mark_running(assessment.id)

    cancelled = service.cancel(assessment.id)
    assert cancelled.control is ControlState.CANCEL_REQUESTED

    terminated: list[str] = []

    def _terminator(aid: str) -> int:
        terminated.append(aid)
        return 2

    runner = _CountingRunner()
    jobs = JobService()
    orchestrator = Orchestrator(
        jobs, runner, max_workers=1,
        step_gate=_gate_for(memory_repositories, assessment.id),
    )
    orchestrator.dispatch(_plan(memory_repositories, assessment))
    status = orchestrator.run_to_completion(owner="w", now=datetime.now(UTC))
    assert status == "cancelled"
    assert runner.calls == 0  # blocked before any step

    # The executor's cancel branch (the exact code execute_assessment calls):
    # abandon remaining jobs + invoke the per-assessment terminator.
    from secopent.application.execution import _handle_cancelled

    _handle_cancelled(
        assessment_id=assessment.id, jobs=jobs,
        audit_repo=memory_repositories.audit, audit_chain=None,
        audit_outbox=None, cancel_terminator=_terminator,
    )
    assert terminated == [assessment.id]  # terminator invoked
    # Remaining jobs were abandoned (SKIPPED) by the executor.
    assert {j.status for j in jobs.all()} == {JobStatus.SKIPPED}
    assert "assessment.cancelled" in {
        e.action for e in memory_repositories.audit.events
    }
    # CANCELLED terminal survives the executor (never overwritten).
    persisted = memory_repositories.assessments.get(assessment.id)
    assert persisted is not None
    assert persisted.status is AssessmentStatus.CANCELLED


def test_pause_blocks_before_first_step_leaves_jobs_ready(
    memory_repositories,
) -> None:  # noqa: ANN001
    assessment, service = _two_step_assessment(memory_repositories)
    service.start(assessment.id)
    service.mark_running(assessment.id)

    paused = service.pause(assessment.id)
    assert paused.control is ControlState.PAUSE_REQUESTED

    runner = _CountingRunner()
    jobs = JobService()
    orchestrator = Orchestrator(
        jobs, runner, max_workers=1,
        step_gate=_gate_for(memory_repositories, assessment.id),
    )
    orchestrator.dispatch(_plan(memory_repositories, assessment))
    status = orchestrator.run_to_completion(owner="w", now=datetime.now(UTC))

    assert status == "paused"
    assert runner.calls == 0  # a pending pause issues no new work
    # Pause leaves the jobs READY for a later resume (NOT skipped).
    assert {j.status for j in jobs.all()} == {JobStatus.READY}
    # The signal was consumed: a fresh read shows NONE.
    persisted = memory_repositories.assessments.get(assessment.id)
    assert persisted is not None
    assert persisted.control is ControlState.NONE


def test_pause_finishes_current_step_then_resume_drains_remaining(
    memory_repositories,
) -> None:  # noqa: ANN001
    """Pause at the second step boundary; resume drains the remaining job."""
    assessment, service = _two_step_assessment(memory_repositories)
    service.start(assessment.id)
    service.mark_running(assessment.id)

    runner = _CountingRunner()
    shared_store = MemoryJobStore()
    jobs = JobService(shared_store)
    gate = _gate_for(memory_repositories, assessment.id)
    gate_calls = {"seen": 0}

    def _pausing_gate() -> str | None:
        gate_calls["seen"] += 1
        if gate_calls["seen"] == 2:  # right after the first step completes
            service.pause(assessment.id)
        return gate()

    orchestrator = Orchestrator(
        jobs, runner, max_workers=1, step_gate=_pausing_gate,
    )
    orchestrator.dispatch(_plan(memory_repositories, assessment))
    status = orchestrator.run_to_completion(owner="w", now=datetime.now(UTC))

    # The in-flight first step completed; no second step was issued.
    assert status == "paused"
    assert runner.calls == 1
    assert {j.status for j in jobs.all()} == {JobStatus.SUCCEEDED, JobStatus.READY}

    # Control plane resumes: signal + RUNNING, then a light drain of READY jobs.
    resumed = service.resume(assessment.id)
    assert resumed.control is ControlState.RESUME_REQUESTED

    resume_assessment(
        assessment_id=assessment.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: runner,
        max_workers=1,
        jobs_store=shared_store,  # durable store: dispatch re-uses existing jobs
    )
    # Idempotent re-dispatch re-uses the existing jobs: only the READY one ran.
    assert runner.calls == 2
    assert {j.status for j in jobs.all()} == {JobStatus.SUCCEEDED}
    persisted = memory_repositories.assessments.get(assessment.id)
    assert persisted is not None
    assert persisted.status is AssessmentStatus.COMPLETED
    assert {e.action for e in memory_repositories.audit.events} >= {
        "assessment.resumed",
        "assessment.completed",
    }