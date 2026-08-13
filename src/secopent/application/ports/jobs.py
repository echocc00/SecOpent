# src/secopent/application/ports/jobs.py
"""JobStore protocol: the durable job + lease surface (§13 V1 + DB lease).

Separated from the implementations so the orchestrator's lease machinery can
run against either ``MemoryJobStore`` (tests / single-process) or the
SQLAlchemy-backed store over ``core_jobs`` (production, durable across
processes and visible to the Web /jobs view). The lease rules are the
contract each implementation enforces with its own concurrency mechanism:

- ``lease``: READY, or LEASED with an expired lease (stale takeover) -> LEASED
  with ``lease_owner`` stamped and ``attempt`` incremented; anything else is a
  ``JobLeaseError``. The check-then-set must be atomic (a re-entrant lock in
  memory; a conditional UPDATE in SQL), so concurrent workers can never
  double-lease the same job.
- ``renew``: only the current owner may extend the lease.
- ``add``: idempotent on ``idempotency_key`` - re-dispatching the same plan
  returns the already-stored job (no duplicate work).
"""
from __future__ import annotations

from datetime import datetime
from typing import Protocol

from ...domain.jobs.models import FailureClass, Job


class JobStore(Protocol):
    """Persistent-ish job store with lease semantics (thread/process safe)."""

    def add(self, job: Job) -> Job:
        """Store a job; idempotent on ``idempotency_key`` (returns existing)."""
        ...

    def get(self, job_id: str) -> Job | None:
        """Return the job or None (repository convention; facades may raise)."""
        ...

    def all(self) -> tuple[Job, ...]:
        """Return every job currently in the store."""
        ...

    def mark_ready(self, job_id: str) -> Job:
        """Move a job to READY (dependencies met / retry reset)."""
        ...

    def lease(self, job_id: str, *, owner: str, now: datetime) -> Job:
        """Lease a READY (or stale-LEASED) job to ``owner``; increments attempt.

        Raises ``JobLeaseError`` on any other status. Atomic: two concurrent
        workers cannot both lease the same job.
        """
        ...

    def renew(self, job_id: str, *, owner: str, now: datetime) -> Job:
        """Extend the lease; only the current ``lease_owner`` may renew."""
        ...

    def complete(self, job_id: str, *, result_digest: str) -> Job:
        """Mark the job SUCCEEDED with its result digest."""
        ...

    def fail(self, job_id: str, *, failure_class: FailureClass) -> Job:
        """Mark FAILED (or POLICY_DENIED for policy failures)."""
        ...

    def requeue(self, job_id: str) -> Job:
        """Return a job to READY (lease released) for a retry."""
        ...

    def skip(self, job_id: str) -> Job:
        """Mark a job SKIPPED (a cancelled/paused run abandons it)."""
        ...

    def leaseable(self, now: datetime) -> tuple[Job, ...]:
        """Jobs leaseable now: READY, or LEASED with an expired lease."""
        ...