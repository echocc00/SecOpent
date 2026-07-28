# src/secopent/interfaces/api/routers/jobs.py
"""Jobs resource router (Phase A P1, W1): orchestrator job view + retry.

Lists the persisted jobs (``SqlAlchemyJobRepository``) so the Web UI's
assessment-detail view can render per-step status, and exposes a retry for
FAILED jobs (reset to READY so a worker can re-lease them). Only retryable
FAILED jobs may be retried; a live/leased job is left to the worker lifecycle.
"""
from __future__ import annotations

from dataclasses import replace

from fastapi import APIRouter, HTTPException

from ....domain.jobs.models import Job, JobStatus
from ....infrastructure.repositories.sqlalchemy_jobs import SqlAlchemyJobRepository
from ..deps import DbSession
from ..schemas import JobOut

router = APIRouter(prefix="/jobs", tags=["jobs"])


def _to_out(job: Job) -> JobOut:
    return JobOut(
        id=job.id,
        plan_step_key=job.plan_step_key,
        idempotency_key=job.idempotency_key,
        status=job.status.value,
        attempt=job.attempt,
        max_attempts=job.max_attempts,
        lease_owner=job.lease_owner,
        result_digest=job.result_digest,
        failure_class=job.failure_class,
        dependencies=list(job.dependencies),
    )


@router.get("", response_model=list[JobOut])
def list_jobs(session: DbSession) -> list[JobOut]:
    return [_to_out(j) for j in SqlAlchemyJobRepository(session).all()]


@router.get("/{job_id}", response_model=JobOut)
def get_job(job_id: str, session: DbSession) -> JobOut:
    job = SqlAlchemyJobRepository(session).get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return _to_out(job)


@router.post("/{job_id}/retry", response_model=JobOut)
def retry_job(job_id: str, session: DbSession) -> JobOut:
    """Retry a FAILED job: reset it to READY (clears the lease) for re-leasing."""
    repo = SqlAlchemyJobRepository(session)
    job = repo.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    if job.status is not JobStatus.FAILED:
        raise HTTPException(
            status_code=409,
            detail=f"only failed jobs can be retried (status={job.status.value})",
        )
    retried = replace(
        job,
        status=JobStatus.READY,
        lease_owner=None,
        lease_expires_at=None,
        failure_class="",
    )
    repo.add(retried)
    return _to_out(retried)
