# src/secopent/application/jobs.py
"""JobService facade + the in-memory JobStore (M4 §13, §7.3).

``JobService`` is the backward-compatible surface the orchestrator and tests
already use; by default it wraps an in-memory store. Production wiring passes
the SQLAlchemy-backed store (``SqlAlchemyJobRepository`` over ``core_jobs``)
so leases survive restarts and the Web /jobs view shows real execution state
(design: sepcs/2026-08-13-mcp-job-lease-cancellation-design.md, M1).

Lease semantics (identical across stores):

- ``lease``: READY (or LEASED with an expired lease - stale takeover) ->
  LEASED, stamped with the owner + expiry, attempt incremented. The
  check-then-set is atomic (RLock here; a conditional UPDATE in SQL), so
  concurrent workers cannot double-lease the same job.
- ``renew``: only the current owner may extend the lease.
- ``add``: idempotent on ``idempotency_key`` - re-dispatching a plan does not
  duplicate jobs.
"""
from __future__ import annotations

import threading
from dataclasses import replace
from datetime import datetime, timedelta

from ..domain.common.errors import DomainError
from ..domain.jobs.models import (
    POLICY_FAILURES,
    FailureClass,
    Job,
    JobStatus,
)
from .ports.jobs import JobStore


class JobNotFoundError(DomainError):
    """Raised when a job id is unknown."""


class JobLeaseError(DomainError):
    """Raised on an invalid lease transition (wrong owner / not leaseable)."""


class MemoryJobStore:
    """In-memory JobStore implementation (thread-safe, RLock)."""

    def __init__(self, *, lease_ttl_seconds: int = 300) -> None:
        self._jobs: dict[str, Job] = {}
        self._ttl = lease_ttl_seconds
        # RLock: public methods lock, and they call each other (e.g. lease ->
        # get / _set), so the lock must be re-entrant within a thread.
        self._lock = threading.RLock()

    def add(self, job: Job) -> Job:
        """Store a job, idempotent on idempotency_key (returns the existing one)."""
        with self._lock:
            for existing in self._jobs.values():
                if existing.idempotency_key == job.idempotency_key:
                    return existing
            self._jobs[job.id] = job
            return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def all(self) -> tuple[Job, ...]:
        with self._lock:
            return tuple(self._jobs.values())

    def mark_ready(self, job_id: str) -> Job:
        return self._set(job_id, status=JobStatus.READY)

    def lease(self, job_id: str, *, owner: str, now: datetime) -> Job:
        """Lease a READY (or stale-LEASED) job to ``owner``; increments attempt.

        Atomic under the lock: the READY/stale check and the LEASED write happen
        together, so two concurrent workers cannot both lease the same job.
        """
        with self._lock:
            job = self._require(job_id)
            stale = (
                job.status is JobStatus.LEASED
                and job.lease_expires_at is not None
                and job.lease_expires_at <= now
            )
            if job.status is not JobStatus.READY and not stale:
                raise JobLeaseError(f"cannot lease job in status {job.status.value}")
            return self._set(
                job_id,
                status=JobStatus.LEASED,
                lease_owner=owner,
                lease_expires_at=now + timedelta(seconds=self._ttl),
                attempt=job.attempt + 1,
            )

    def renew(self, job_id: str, *, owner: str, now: datetime) -> Job:
        """Extend the lease; only the current owner may renew."""
        with self._lock:
            job = self._require(job_id)
            if job.lease_owner != owner:
                raise JobLeaseError("only the lease owner may renew")
            return self._set(job_id, lease_expires_at=now + timedelta(seconds=self._ttl))

    def complete(self, job_id: str, *, result_digest: str) -> Job:
        return self._set(job_id, status=JobStatus.SUCCEEDED, result_digest=result_digest)

    def fail(self, job_id: str, *, failure_class: FailureClass) -> Job:
        status = (
            JobStatus.POLICY_DENIED
            if failure_class in POLICY_FAILURES
            else JobStatus.FAILED
        )
        return self._set(job_id, status=status, failure_class=failure_class.value)

    def requeue(self, job_id: str) -> Job:
        """Return a job to READY (released lease, cleared failure) for a retry."""
        return self._set(
            job_id,
            status=JobStatus.READY,
            lease_owner=None,
            lease_expires_at=None,
            failure_class="",
        )

    def skip(self, job_id: str) -> Job:
        """Mark a job SKIPPED (a cancelled/paused run abandons it)."""
        return self._set(
            job_id, status=JobStatus.SKIPPED, lease_owner=None, lease_expires_at=None
        )

    def leaseable(self, now: datetime) -> tuple[Job, ...]:
        """Jobs that can be leased now: READY, or LEASED with an expired lease.

        Reasoning-loop jobs (``plan_step_key`` starting with ``loop:``) are
        ordered first so loop steps don't starve behind ordinary work; within
        each group the insertion order is preserved (a stable partition).
        """
        with self._lock:
            loop_jobs: list[Job] = []
            ordinary: list[Job] = []
            for job in self._jobs.values():
                stale_lease = (
                    job.status is JobStatus.LEASED
                    and job.lease_expires_at is not None
                    and job.lease_expires_at <= now
                )
                if job.status is JobStatus.READY or stale_lease:
                    if job.plan_step_key.startswith("loop:"):
                        loop_jobs.append(job)
                    else:
                        ordinary.append(job)
            return tuple(loop_jobs + ordinary)

    def _require(self, job_id: str) -> Job:
        """Internal lookup: raise JobNotFoundError on a missing job."""
        job = self.get(job_id)
        if job is None:
            raise JobNotFoundError(f"job not found: {job_id}")
        return job

    def _set(self, job_id: str, **changes: object) -> Job:
        # Callers hold the (re-entrant) lock; get() re-acquires it safely.
        with self._lock:
            job = self._require(job_id)
            updated = replace(job, **changes)  # type: ignore[arg-type]
            self._jobs[job_id] = updated
            return updated


class JobService:
    """Backward-compatible facade over a ``JobStore`` (memory by default)."""

    def __init__(
        self,
        store: JobStore | None = None,
        *,
        lease_ttl_seconds: int = 300,
    ) -> None:
        self._store = store or MemoryJobStore(lease_ttl_seconds=lease_ttl_seconds)

    def add(self, job: Job) -> Job:
        return self._store.add(job)

    def get(self, job_id: str) -> Job:
        """Facade contract (unchanged): raise on a missing job."""
        job = self._store.get(job_id)
        if job is None:
            raise JobNotFoundError(f"job not found: {job_id}")
        return job

    def all(self) -> tuple[Job, ...]:
        return self._store.all()

    def mark_ready(self, job_id: str) -> Job:
        return self._store.mark_ready(job_id)

    def lease(self, job_id: str, *, owner: str, now: datetime) -> Job:
        return self._store.lease(job_id, owner=owner, now=now)

    def renew(self, job_id: str, *, owner: str, now: datetime) -> Job:
        return self._store.renew(job_id, owner=owner, now=now)

    def complete(self, job_id: str, *, result_digest: str) -> Job:
        return self._store.complete(job_id, result_digest=result_digest)

    def fail(self, job_id: str, *, failure_class: FailureClass) -> Job:
        return self._store.fail(job_id, failure_class=failure_class)

    def requeue(self, job_id: str) -> Job:
        return self._store.requeue(job_id)

    def skip(self, job_id: str) -> Job:
        return self._store.skip(job_id)

    def leaseable(self, now: datetime) -> tuple[Job, ...]:
        return self._store.leaseable(now)