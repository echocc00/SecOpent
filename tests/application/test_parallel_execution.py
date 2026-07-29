# tests/application/test_parallel_execution.py
"""TDD tests for adapter --parallel N (P3 §3.5 / T4).

Proves the two §3.5 acceptance properties without Docker:

* **JobService lease is race-free**: N threads racing to lease the *same* READY
  job yield exactly one winner (the atomic check-then-set under the RLock);
  distinct jobs lease concurrently, each exactly once.
* **Orchestrator runs steps concurrently**: a ``threading.Barrier(3)`` inside
  the step runner only releases when all three steps are in flight at once - so
  a serial scheduler would deadlock/timeout the barrier and fail the test,
  while ``max_workers=3`` overlaps them (no deadlock, all SUCCEEDED).
"""
from __future__ import annotations

import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

from secopent.application.jobs import JobLeaseError, JobService
from secopent.application.orchestrator import Orchestrator, StepFailure, StepResult
from secopent.domain.assessments.models import ExecutionPlan, PlanStep
from secopent.domain.jobs.models import FailureClass, Job, JobStatus
from secopent.domain.policy.models import RiskClass
from secopent.infrastructure.adapters.base import ContainerResult
from secopent.infrastructure.adapters.subprocess_executor import (
    SubprocessContainerExecutor,
)

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _independent_plan(n: int = 3) -> ExecutionPlan:
    steps = tuple(
        PlanStep(
            key=f"s{i}",
            runner="nuclei",
            risk=RiskClass.ACTIVE,
            parameters={},
            dependencies=(),
        )
        for i in range(n)
    )
    return ExecutionPlan.create(plan_id="p", assessment_id="a", version=1, steps=steps)


class _OkRunner:
    def run(self, step: PlanStep) -> StepResult:
        return StepResult(result_digest="sha256:" + "d" * 64)


class _BarrierRunner:
    """Requires ``n`` concurrent ``run`` calls; serial execution times out."""

    def __init__(self, n: int) -> None:
        self._barrier = threading.Barrier(n)
        self._lock = threading.Lock()
        self._inflight = 0
        self.max_inflight = 0

    def run(self, step: PlanStep) -> StepResult:
        with self._lock:
            self._inflight += 1
            self.max_inflight = max(self.max_inflight, self._inflight)
        try:
            self._barrier.wait(timeout=10)
        except threading.BrokenBarrierError as exc:
            raise StepFailure(
                FailureClass.TIMEOUT, "steps did not run concurrently"
            ) from exc
        finally:
            with self._lock:
                self._inflight -= 1
        return StepResult(result_digest="sha256:" + "d" * 64)


# --- JobService lease race-freedom ------------------------------------------


def test_concurrent_lease_of_same_job_has_single_winner() -> None:
    jobs = JobService()
    jobs.add(Job(id="j", plan_step_key="k", idempotency_key="idem", status=JobStatus.READY))
    n = 8
    barrier = threading.Barrier(n)
    wins: list[int] = []
    losses: list[int] = []
    lock = threading.Lock()

    def try_lease(i: int) -> None:
        barrier.wait(timeout=5)
        try:
            jobs.lease("j", owner=f"w{i}", now=_T0)
            with lock:
                wins.append(i)
        except JobLeaseError:
            with lock:
                losses.append(i)

    threads = [threading.Thread(target=try_lease, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(wins) == 1  # atomic lease: no double-lease
    assert len(losses) == n - 1
    assert jobs.get("j").attempt == 1  # leased exactly once


def test_concurrent_lease_of_distinct_jobs_each_once() -> None:
    jobs = JobService()
    for i in range(3):
        jobs.add(
            Job(id=f"j{i}", plan_step_key=f"k{i}", idempotency_key=f"idem{i}",
                status=JobStatus.READY)
        )
    barrier = threading.Barrier(3)
    leased: list[str] = []
    lock = threading.Lock()

    def lease_one(i: int) -> None:
        barrier.wait(timeout=5)
        jobs.lease(f"j{i}", owner=f"w{i}", now=_T0)
        with lock:
            leased.append(f"j{i}")

    threads = [threading.Thread(target=lease_one, args=(i,)) for i in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(leased) == ["j0", "j1", "j2"]
    assert all(jobs.get(f"j{i}").status is JobStatus.LEASED for i in range(3))
    assert all(jobs.get(f"j{i}").attempt == 1 for i in range(3))


# --- Orchestrator parallel execution ----------------------------------------


def test_orchestrator_parallel_overlaps_steps() -> None:
    jobs = JobService()
    runner = _BarrierRunner(3)
    orchestrator = Orchestrator(jobs, runner, max_workers=3)
    orchestrator.dispatch(_independent_plan(3))

    orchestrator.execute_ready(owner="w", now=_T0)

    statuses = {j.plan_step_key: j.status for j in jobs.all()}
    assert all(status is JobStatus.SUCCEEDED for status in statuses.values())
    assert runner.max_inflight == 3  # all three overlapped (barrier released)


def test_orchestrator_serial_default_still_works() -> None:
    jobs = JobService()
    orchestrator = Orchestrator(jobs, _OkRunner())  # max_workers defaults to 1
    orchestrator.dispatch(_independent_plan(3))
    orchestrator.run_to_completion(owner="w", now=_T0)
    assert all(j.status is JobStatus.SUCCEEDED for j in jobs.all())


def test_orchestrator_rejects_bad_max_workers() -> None:
    with pytest.raises(ValueError):
        Orchestrator(JobService(), _OkRunner(), max_workers=0)


# --- Executor run_many -------------------------------------------------------


def test_executor_run_many_runs_concurrently_and_preserves_order() -> None:
    executor = SubprocessContainerExecutor(max_workers=3)
    barrier = threading.Barrier(3)

    def fake_run(**kwargs: object) -> ContainerResult:
        # All three must be in flight at once; serial would time out the barrier.
        barrier.wait(timeout=10)
        return ContainerResult(
            stdout=str(kwargs["image_digest"]),
            stderr="",
            exit_code=0,
            artifacts_dir=Path("."),
        )

    executor.run = fake_run  # type: ignore[method-assign]
    invocations = [
        {
            "image_digest": f"digest-{i}",
            "command": [],
            "mounts": {},
            "network_policy": "scoped-egress",
            "resource_limits": {},
        }
        for i in range(3)
    ]
    results = executor.run_many(invocations)
    assert [r.stdout for r in results] == ["digest-0", "digest-1", "digest-2"]


def test_executor_run_many_serial_when_single_worker() -> None:
    executor = SubprocessContainerExecutor(max_workers=1)
    seen: list[str] = []

    def fake_run(**kwargs: object) -> ContainerResult:
        seen.append(str(kwargs["image_digest"]))
        return ContainerResult(
            stdout=str(kwargs["image_digest"]), stderr="", exit_code=0,
            artifacts_dir=Path("."),
        )

    executor.run = fake_run  # type: ignore[method-assign]
    invocations = [
        {"image_digest": f"d{i}", "command": [], "mounts": {},
         "network_policy": "scoped-egress", "resource_limits": {}}
        for i in range(3)
    ]
    results = executor.run_many(invocations)
    assert seen == ["d0", "d1", "d2"]  # serial, in order
    assert len(results) == 3


def test_executor_rejects_bad_max_workers() -> None:
    with pytest.raises(ValueError):
        SubprocessContainerExecutor(max_workers=0)
