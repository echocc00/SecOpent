# src/secopent/application/orchestrator.py
"""Orchestrator: V1 single-machine plan execution with leased jobs (§13, O1=B).

Dispatches an ExecutionPlan into leased jobs (one per step, idempotent on
plan-digest+step-key), executes READY jobs through an injected StepRunner, and
classifies failures: transient failures (worker_unavailable/timeout) are retried
up to ``max_attempts``; policy failures (out_of_scope/not_approved) are denied
outright. When a step succeeds, dependent steps unblock (READY). No remote
workers in V1 (O1=B); the lease machinery is in place for the V2 distributed
worker.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from ..domain.assessments.models import ExecutionPlan, PlanStep
from ..domain.common.errors import DomainError
from ..domain.jobs.models import (
    POLICY_FAILURES,
    RETRYABLE_FAILURES,
    FailureClass,
    Job,
    JobStatus,
)
from .jobs import JobService


class StepFailure(DomainError):
    """A step execution failed; ``failure_class`` drives retry vs deny."""

    def __init__(self, failure_class: FailureClass, message: str = "") -> None:
        super().__init__(message or failure_class.value)
        self.failure_class = failure_class


@dataclass(frozen=True, slots=True)
class StepResult:
    """Successful step output (a content digest of the produced observations)."""

    result_digest: str


@runtime_checkable
class StepRunner(Protocol):
    """Executes one plan step; raises StepFailure on failure."""

    def run(self, step: PlanStep) -> StepResult: ...


class Orchestrator:
    """Dispatch and execute plan steps as leased jobs."""

    def __init__(self, jobs: JobService, runner: StepRunner) -> None:
        self._jobs = jobs
        self._runner = runner
        self._steps: dict[str, PlanStep] = {}

    def dispatch(self, plan: ExecutionPlan) -> tuple[Job, ...]:
        """Create one job per step (idempotent); steps with deps start BLOCKED."""
        created: list[Job] = []
        for step in plan.steps:
            idempotency_key = f"{plan.digest}:{step.key}"
            job = Job(
                id=f"job:{step.key}",
                plan_step_key=step.key,
                idempotency_key=idempotency_key,
                dependencies=step.dependencies,
                status=JobStatus.BLOCKED if step.dependencies else JobStatus.READY,
            )
            created.append(self._jobs.add(job))
            self._steps[step.key] = step
        return tuple(created)

    def execute_ready(self, *, owner: str, now: datetime) -> tuple[Job, ...]:
        """Lease + execute every currently-leaseable job once; then unblock deps."""
        results: list[Job] = []
        for job in self._jobs.leaseable(now):
            step = self._steps.get(job.plan_step_key)
            if step is None:
                continue
            results.append(self._execute(job, step, owner=owner, now=now))
        self._resolve_dependencies()
        return tuple(results)

    def run_to_completion(self, *, owner: str, now: datetime, max_rounds: int = 100) -> None:
        """Repeatedly execute ready jobs until none remain (V1 drain loop)."""
        for _ in range(max_rounds):
            executed = self.execute_ready(owner=owner, now=now)
            if not executed:
                break

    def _execute(self, job: Job, step: PlanStep, *, owner: str, now: datetime) -> Job:
        leased = self._jobs.lease(job.id, owner=owner, now=now)
        try:
            result = self._runner.run(step)
        except StepFailure as failure:
            return self._handle_failure(leased, failure)
        return self._jobs.complete(job.id, result_digest=result.result_digest)

    def _handle_failure(self, job: Job, failure: StepFailure) -> Job:
        if failure.failure_class in POLICY_FAILURES:
            return self._jobs.fail(job.id, failure_class=failure.failure_class)
        if failure.failure_class in RETRYABLE_FAILURES and job.attempt < job.max_attempts:
            return self._jobs.requeue(job.id)
        return self._jobs.fail(job.id, failure_class=failure.failure_class)

    def _resolve_dependencies(self) -> None:
        """Mark BLOCKED jobs READY once all their dependency steps succeeded."""
        succeeded = {
            job.plan_step_key
            for job in self._jobs.all()
            if job.status is JobStatus.SUCCEEDED
        }
        for job in self._jobs.all():
            if job.status is JobStatus.BLOCKED and set(job.dependencies) <= succeeded:
                self._jobs.mark_ready(job.id)
