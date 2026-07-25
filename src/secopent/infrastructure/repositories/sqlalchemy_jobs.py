# src/secopent/infrastructure/repositories/sqlalchemy_jobs.py
"""SqlAlchemy repository for orchestrator jobs with a durable lease (§13)."""
from __future__ import annotations

from datetime import UTC

from sqlalchemy.orm import Session

from ...domain.jobs.models import Job, JobStatus
from ..db.job_models import CoreJob


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
        lease_expires_at=job.lease_expires_at,
        result_digest=job.result_digest,
        failure_class=job.failure_class,
        dependencies=list(job.dependencies),
    )


class SqlAlchemyJobRepository:
    """Persisted Job store (durable lease)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, job: Job) -> None:
        self._session.merge(_from_job(job))

    def get(self, job_id: str) -> Job | None:
        row = self._session.get(CoreJob, job_id)
        return _to_job(row) if row else None

    def all(self) -> list[Job]:
        return [_to_job(row) for row in self._session.query(CoreJob).all()]
