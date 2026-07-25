# src/secopent/application/jobs.py
"""JobService: job lifecycle + DB-lease semantics (§13 V1, §7.3).

Manages jobs in a lease-based store. A worker leases a READY (or stale-leased)
job, which stamps it with an owner + expiry; if the worker stalls, the lease
expires and another worker can re-lease. ``add`` is idempotent on the
``idempotency_key`` so re-dispatching the same plan does not duplicate work.
The in-memory store is M4 scope; the SQLite-backed lease lands behind the same
surface (Task 11).
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta

from ..domain.common.errors import DomainError
from ..domain.jobs.models import (
    POLICY_FAILURES,
    FailureClass,
    Job,
    JobStatus,
)


class JobNotFoundError(DomainError):
    """Raised when a job id is unknown."""


class JobLeaseError(DomainError):
    """Raised on an invalid lease transition (wrong owner / not leaseable)."""


class JobService:
    """Lease-based job store (single-machine V1)."""

    def __init__(self, *, lease_ttl_seconds: int = 300) -> None:
        self._jobs: dict[str, Job] = {}
        self._ttl = lease_ttl_seconds

    def add(self, job: Job) -> Job:
        """Store a job, idempotent on idempotency_key (returns the existing one)."""
        for existing in self._jobs.values():
            if existing.idempotency_key == job.idempotency_key:
                return existing
        self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Job:
        job = self._jobs.get(job_id)
        if job is None:
            raise JobNotFoundError(f"job not found: {job_id}")
        return job

    def all(self) -> tuple[Job, ...]:
        return tuple(self._jobs.values())

    def mark_ready(self, job_id: str) -> Job:
        return self._set(job_id, status=JobStatus.READY)

    def lease(self, job_id: str, *, owner: str, now: datetime) -> Job:
        """Lease a READY (or stale-LEASED) job to ``owner``; increments attempt."""
        job = self.get(job_id)
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
        job = self.get(job_id)
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
        """Return a job to READY (released lease) for a retry."""
        return self._set(job_id, status=JobStatus.READY, lease_owner=None, lease_expires_at=None)

    def leaseable(self, now: datetime) -> tuple[Job, ...]:
        """Jobs that can be leased now: READY, or LEASED with an expired lease."""
        result = []
        for job in self._jobs.values():
            stale_lease = (
                job.status is JobStatus.LEASED
                and job.lease_expires_at is not None
                and job.lease_expires_at <= now
            )
            if job.status is JobStatus.READY or stale_lease:
                result.append(job)
        return tuple(result)

    def _set(self, job_id: str, **changes: object) -> Job:
        job = self.get(job_id)
        updated = replace(job, **changes)  # type: ignore[arg-type]
        self._jobs[job_id] = updated
        return updated
