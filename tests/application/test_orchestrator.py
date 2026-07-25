"""TDD tests for the Orchestrator + JobService (M4 Task 4, §13 V1 + §7.3)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from secopent.application.jobs import JobLeaseError, JobService
from secopent.application.orchestrator import (
    Orchestrator,
    StepFailure,
    StepResult,
)
from secopent.domain.assessments.models import ExecutionPlan, PlanStep
from secopent.domain.jobs.models import FailureClass, Job, JobStatus
from secopent.domain.policy.models import RiskClass

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _plan() -> ExecutionPlan:
    recon = PlanStep(
        key="recon", runner="nmap", risk=RiskClass.PASSIVE, parameters={}, dependencies=()
    )
    active = PlanStep(
        key="active",
        runner="nuclei",
        risk=RiskClass.ACTIVE,
        parameters={},
        dependencies=("recon",),
    )
    return ExecutionPlan.create(
        plan_id="p", assessment_id="a", version=1, steps=(recon, active)
    )


class ScriptedRunner:
    """Returns scripted outcomes per step key ('ok' or a FailureClass, in order)."""

    def __init__(self, script: dict[str, list[object]]) -> None:
        self._script = {key: list(outcomes) for key, outcomes in script.items()}
        self.calls: list[str] = []

    def run(self, step: PlanStep) -> StepResult:
        self.calls.append(step.key)
        outcomes = self._script.get(step.key, ["ok"])
        outcome = outcomes.pop(0) if outcomes else "ok"
        if isinstance(outcome, FailureClass):
            raise StepFailure(outcome)
        return StepResult(result_digest="sha256:" + "d" * 64)


def _orchestrator(
    script: dict[str, list[object]],
) -> tuple[Orchestrator, JobService, ScriptedRunner]:
    jobs = JobService()
    runner = ScriptedRunner(script)
    return Orchestrator(jobs, runner), jobs, runner


def test_dispatch_creates_jobs_with_dependency_status() -> None:
    orchestrator, jobs, _ = _orchestrator({})
    created = orchestrator.dispatch(_plan())
    assert len(created) == 2
    by_key = {j.plan_step_key: j for j in created}
    assert by_key["recon"].status is JobStatus.READY  # no deps
    assert by_key["active"].status is JobStatus.BLOCKED  # depends on recon


def test_dispatch_is_idempotent() -> None:
    orchestrator, jobs, _ = _orchestrator({})
    plan = _plan()
    orchestrator.dispatch(plan)
    orchestrator.dispatch(plan)  # same plan again
    assert len(jobs.all()) == 2  # no duplicate jobs


def test_run_to_completion_executes_in_dependency_order() -> None:
    orchestrator, jobs, runner = _orchestrator({"recon": ["ok"], "active": ["ok"]})
    orchestrator.dispatch(_plan())
    orchestrator.run_to_completion(owner="worker-1", now=_T0)
    by_key = {j.plan_step_key: j for j in jobs.all()}
    assert by_key["recon"].status is JobStatus.SUCCEEDED
    assert by_key["active"].status is JobStatus.SUCCEEDED
    assert by_key["recon"].result_digest.startswith("sha256:")
    # recon executed before active.
    assert runner.calls.index("recon") < runner.calls.index("active")


def test_retryable_failure_retries_then_succeeds() -> None:
    script = {"recon": [FailureClass.WORKER_UNAVAILABLE, FailureClass.TIMEOUT, "ok"]}
    orchestrator, jobs, _ = _orchestrator(script)
    orchestrator.dispatch(_plan())
    orchestrator.run_to_completion(owner="w", now=_T0)
    recon = next(j for j in jobs.all() if j.plan_step_key == "recon")
    assert recon.status is JobStatus.SUCCEEDED
    assert recon.attempt == 3


def test_retryable_failure_exhausts_to_failed() -> None:
    script = {"recon": [FailureClass.WORKER_UNAVAILABLE] * 10}
    orchestrator, jobs, _ = _orchestrator(script)
    orchestrator.dispatch(_plan())
    orchestrator.run_to_completion(owner="w", now=_T0)
    recon = next(j for j in jobs.all() if j.plan_step_key == "recon")
    assert recon.status is JobStatus.FAILED
    assert recon.attempt == 3  # bounded by max_attempts


def test_policy_failure_denied_without_retry() -> None:
    script = {"recon": [FailureClass.OUT_OF_SCOPE, "ok", "ok"]}
    orchestrator, jobs, _ = _orchestrator(script)
    orchestrator.dispatch(_plan())
    orchestrator.run_to_completion(owner="w", now=_T0)
    recon = next(j for j in jobs.all() if j.plan_step_key == "recon")
    assert recon.status is JobStatus.POLICY_DENIED
    assert recon.attempt == 1  # no retry for policy failures


def test_lease_blocks_other_owner_until_expiry() -> None:
    jobs = JobService(lease_ttl_seconds=60)
    jobs.add(Job(id="j", plan_step_key="k", idempotency_key="idem", status=JobStatus.READY))
    jobs.lease("j", owner="w1", now=_T0)
    # Another owner cannot lease a live (unexpired) lease.
    with pytest.raises(JobLeaseError):
        jobs.lease("j", owner="w2", now=_T0 + timedelta(seconds=10))
    # After the lease expires, another owner can re-lease (stale takeover).
    reclaimed = jobs.lease("j", owner="w2", now=_T0 + timedelta(seconds=120))
    assert reclaimed.lease_owner == "w2"


def test_renew_requires_ownership() -> None:
    jobs = JobService(lease_ttl_seconds=60)
    jobs.add(Job(id="j", plan_step_key="k", idempotency_key="idem", status=JobStatus.READY))
    jobs.lease("j", owner="w1", now=_T0)
    with pytest.raises(JobLeaseError):
        jobs.renew("j", owner="w2", now=_T0)
    renewed = jobs.renew("j", owner="w1", now=_T0)
    assert renewed.lease_expires_at == _T0 + timedelta(seconds=60)
