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

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
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


class StepPaused(DomainError):
    """Internal signal: the step boundary requested a pause (no new work)."""


class StepCancelled(DomainError):
    """Internal signal: the step boundary requested a cancel (terminate)."""


# Step-boundary gate: called before every job execution; returns None to
# continue, "paused" to stop issuing work (leave remaining jobs READY), or
# "cancelled" to abort the whole run.
StepGate = Callable[[], str | None]


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

    def __init__(
        self,
        jobs: JobService,
        runner: StepRunner,
        *,
        max_workers: int = 1,
        step_gate: StepGate | None = None,
    ) -> None:
        if max_workers < 1:
            raise ValueError(f"max_workers must be >= 1, got {max_workers}")
        self._jobs = jobs
        self._runner = runner
        self._max_workers = max_workers
        self._step_gate = step_gate
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

    def _check_gate(self) -> None:
        """Consult the step-boundary gate; raise on a pause/cancel request."""
        if self._step_gate is None:
            return
        decision = self._step_gate()
        if decision == "paused":
            raise StepPaused("step boundary pause requested")
        if decision == "cancelled":
            raise StepCancelled("step boundary cancel requested")

    def execute_ready(self, *, owner: str, now: datetime) -> tuple[Job, ...]:
        """Lease + execute every currently-leaseable job once; then unblock deps.

        With ``max_workers > 1`` the per-step executions run concurrently on a
        thread pool (P3 §3.5 / T4). The JobService lease is atomic, so distinct
        jobs are processed in parallel without double-leasing (no race/deadlock);
        the slow ``runner.run`` calls overlap instead of running serially.

        The step gate is consulted BEFORE every job is leased: a paused run
        finishes its in-flight step and issues no new work; a cancelled run
        stops likewise (the caller terminates containers / marks jobs SKIPPED).
        """
        targets: list[tuple[Job, PlanStep]] = []
        for job in self._jobs.leaseable(now):
            step = self._steps.get(job.plan_step_key)
            if step is not None:
                targets.append((job, step))

        if self._max_workers <= 1 or len(targets) <= 1:
            results: list[Job] = []
            for job, step in targets:
                self._check_gate()
                results.append(self._execute(job, step, owner=owner, now=now))
        else:
            with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
                futures = []
                for job, step in targets:
                    self._check_gate()
                    futures.append(
                        pool.submit(self._execute, job, step, owner=owner, now=now)
                    )
                results = [future.result() for future in futures]
        self._resolve_dependencies()
        return tuple(results)

    def run_to_completion(self, *, owner: str, now: datetime, max_rounds: int = 100) -> str:
        """Repeatedly execute ready jobs until none remain (V1 drain loop).

        Returns "completed" when every dependency-visible job finished,
        "paused" when the step gate stopped issuing work, or "cancelled" when
        the gate aborted the run.
        """
        for _ in range(max_rounds):
            try:
                executed = self.execute_ready(owner=owner, now=now)
            except StepPaused:
                return "paused"
            except StepCancelled:
                return "cancelled"
            if not executed:
                break
        return "completed"

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
