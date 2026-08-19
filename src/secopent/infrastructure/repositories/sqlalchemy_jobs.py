# src/secopent/infrastructure/repositories/sqlalchemy_jobs.py
"""SQLAlchemy JobStore over ``core_jobs``: a durable, atomic lease (§13).

Implements the full ``JobStore`` protocol (application/ports/jobs.py) against
the existing ``core_jobs`` table so orchestrator leases survive restarts and
the Web /jobs view reads real execution state. The check-then-set of ``lease``
is a single conditional UPDATE (``WHERE status='ready' OR stale-LEASED``), so
two workers - even in different processes - can never double-lease the same
job: the database write lock adjudicates the race instead of an in-process
lock (the V2 distributed-worker enabler).

Timezone convention: ``core_jobs.lease_expires_at`` is stored as **naive UTC**
(SQLite stores naive datetimes as plain ISO strings, so string comparison in
the UPDATE stays consistent). ``now`` is converted with ``_naive_utc`` before
binding, and ``_to_job`` restores the UTC timezone on read so Python-side
comparisons (``leaseable``) see aware datetimes.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, or_, update
from sqlalchemy.orm import Session

from ...application.jobs import JobLeaseError, JobNotFoundError
from ...domain.jobs.models import (
    POLICY_FAILURES,
    FailureClass,
    Job,
    JobStatus,
)
from ..db.job_models import CoreJob

_DEFAULT_LEASE_TTL_SECONDS = 300


def _naive_utc(now: datetime) -> datetime:
    """Normalize to a naive-UTC datetime for the SQLite/PG DateTime columns."""
    if now.tzinfo is None:
        return now
    return now.astimezone(UTC).replace(tzinfo=None)


def _to_job(row: CoreJob) -> Job:
    expires = row.lease_expires_at
    if expires is not None and expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return Job(
        id=row.id,
        plan_step_key=row.plan_step_key,
        idempotency_key=row.idempotency_key,
        status=JobStatus(row.status),
        attempt=row.attempt,
        max_attempts=row.max_attempts,
        lease_owner=row.lease_owner,
        lease_expires_at=expires,
        result_digest=row.result_digest,
        failure_class=row.failure_class,
        dependencies=tuple(row.dependencies),
    )


def _from_job(job: Job) -> CoreJob:
    return CoreJob(
        id=job.id,
        plan_step_key=job.plan_step_key,
        idempotency_key=job.idempotency_key,
        status=job.status.value,
        attempt=job.attempt,
        max_attempts=job.max_attempts,
        lease_owner=job.lease_owner,
        lease_expires_at=_naive_utc(job.lease_expires_at) if job.lease_expires_at else None,
        result_digest=job.result_digest,
        failure_class=job.failure_class,
        dependencies=list(job.dependencies),
    )


class SqlAlchemyJobRepository:
    """Persisted Job store (durable lease) implementing the JobStore protocol."""

    def __init__(
        self, session: Session, *, lease_ttl_seconds: int = _DEFAULT_LEASE_TTL_SECONDS
    ) -> None:
        self._session = session
        self._ttl = lease_ttl_seconds

    # --- reads -------------------------------------------------------------

    def get(self, job_id: str) -> Job | None:
        row = self._session.get(CoreJob, job_id)
        return _to_job(row) if row else None

    def all(self) -> tuple[Job, ...]:
        return tuple(_to_job(row) for row in self._session.query(CoreJob).all())

    def leaseable(self, now: datetime) -> tuple[Job, ...]:
        """Jobs leaseable now: READY, or LEASED with an expired lease.

        Reasoning-loop jobs (``plan_step_key`` starting with ``loop:``) are
        ordered first so loop steps don't starve behind ordinary work; within
        each group the query order is preserved (a stable partition). Mirrors
        ``MemoryJobStore`` so the two stores stay behaviorally equivalent
        (test_job_store equivalence matrix).
        """
        loop_jobs: list[Job] = []
        ordinary: list[Job] = []
        for job in self.all():
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

    # --- writes ------------------------------------------------------------

    def add(self, job: Job) -> Job:
        """Store a job; idempotent on idempotency_key (returns the existing one)."""
        existing = self._session.query(CoreJob).filter_by(
            idempotency_key=job.idempotency_key
        ).first()
        if existing is not None:
            return _to_job(existing)
        self._session.merge(_from_job(job))
        return job

    def mark_ready(self, job_id: str) -> Job:
        self._update(
            job_id,
            status=JobStatus.READY.value,
            lease_owner=None,
            lease_expires_at=None,
        )
        return self._require(job_id)

    def lease(self, job_id: str, *, owner: str, now: datetime) -> Job:
        """Atomic READY | stale-LEASED -> LEASED with attempt+1.

        One conditional UPDATE decides the outcome; when no row matched
        (wrong status / still-held lease) the current state is read back and a
        ``JobLeaseError`` raised. Concurrent workers see a compare-and-set: the
        database write lock picks exactly one winner, so two processes can
        never double-lease.
        """
        naive_now = _naive_utc(now)
        result = self._session.execute(
            update(CoreJob)
            .where(
                CoreJob.id == job_id,
                or_(
                    CoreJob.status == JobStatus.READY.value,
                    and_(
                        CoreJob.status == JobStatus.LEASED.value,
                        CoreJob.lease_expires_at.is_not(None),
                        CoreJob.lease_expires_at <= naive_now,
                    ),
                ),
            )
            .values(
                status=JobStatus.LEASED.value,
                lease_owner=owner,
                lease_expires_at=naive_now + timedelta(seconds=self._ttl),
                attempt=CoreJob.attempt + 1,
            )
        )
        if result.rowcount == 1:
            return self._require(job_id)
        current = self.get(job_id)
        if current is None:
            raise JobNotFoundError(f"job not found: {job_id}")
        raise JobLeaseError(f"cannot lease job in status {current.status.value}")

    def renew(self, job_id: str, *, owner: str, now: datetime) -> Job:
        """Extend the lease; only the current owner may renew (conditional)."""
        naive_now = _naive_utc(now)
        result = self._session.execute(
            update(CoreJob)
            .where(CoreJob.id == job_id, CoreJob.lease_owner == owner)
            .values(lease_expires_at=naive_now + timedelta(seconds=self._ttl))
        )
        if result.rowcount != 1:
            raise JobLeaseError("only the lease owner may renew")
        return self._require(job_id)

    def complete(self, job_id: str, *, result_digest: str) -> Job:
        self._update(job_id, status=JobStatus.SUCCEEDED.value, result_digest=result_digest)
        return self._require(job_id)

    def fail(self, job_id: str, *, failure_class: FailureClass) -> Job:
        status = (
            JobStatus.POLICY_DENIED
            if failure_class in POLICY_FAILURES
            else JobStatus.FAILED
        )
        self._update(job_id, status=status.value, failure_class=failure_class.value)
        return self._require(job_id)

    def requeue(self, job_id: str) -> Job:
        """Return a job to READY (released lease, cleared failure) for a retry."""
        self._update(
            job_id,
            status=JobStatus.READY.value,
            lease_owner=None,
            lease_expires_at=None,
            failure_class="",
        )
        return self._require(job_id)

    def skip(self, job_id: str) -> Job:
        """Mark a job SKIPPED (a cancelled/paused run abandons it)."""
        self._update(
            job_id,
            status=JobStatus.SKIPPED.value,
            lease_owner=None,
            lease_expires_at=None,
        )
        return self._require(job_id)

    # --- helpers -----------------------------------------------------------

    def _require(self, job_id: str) -> Job:
        """Internal lookup after a successful write (row must exist)."""
        job = self.get(job_id)
        if job is None:
            raise JobNotFoundError(f"job not found: {job_id}")
        return job

    def _update(self, job_id: str, **values: object) -> None:
        result = self._session.execute(
            update(CoreJob).where(CoreJob.id == job_id).values(**values)
        )
        if result.rowcount != 1:
            raise JobNotFoundError(f"job not found: {job_id}")