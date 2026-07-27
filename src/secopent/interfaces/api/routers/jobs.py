# src/secopent/interfaces/api/routers/jobs.py
"""Jobs resource router (Phase A P1, W1): read-only view of orchestrator jobs.

Lists the persisted jobs (``SqlAlchemyJobRepository``) so the Web UI's
assessment-detail view can render per-step status. Job dispatch, leasing, and
retry are orchestrated by the worker lifecycle (application/jobs.py +
orchestrator) and are intentionally NOT exposed here - a bare status flip
without the worker would create an inconsistent lease state.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ....domain.jobs.models import Job
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
