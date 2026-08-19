# src/secopent/domain/jobs/models.py
"""Job domain models for the orchestrator (§13 V1 single-machine + DB lease).

A Job is one executable unit of an ExecutionPlan step. It moves through
PENDING -> BLOCKED/READY -> LEASED -> RUNNING -> SUCCEEDED/FAILED/SKIPPED/
POLICY_DENIED. The lease (owner + expiry) lets a stalled worker's job be
re-leased. Failures are classified so the orchestrator knows what to retry
(transient: worker_unavailable/timeout) versus what to deny outright (policy:
out_of_scope/not_approved).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class JobStatus(StrEnum):
    """Job lifecycle states."""

    PENDING = "pending"
    BLOCKED = "blocked"  # waiting on dependency steps
    READY = "ready"  # dependencies met, can be leased
    LEASED = "leased"  # a worker holds the lease
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    POLICY_DENIED = "policy_denied"


class FailureClass(StrEnum):
    """Why a job failed (drives retry vs deny)."""

    INPUT_INVALID = "input_invalid"
    OUT_OF_SCOPE = "out_of_scope"
    NOT_APPROVED = "not_approved"
    WORKER_UNAVAILABLE = "worker_unavailable"
    TIMEOUT = "timeout"
    PARSE_FAILED = "parse_failed"


# Transient failures worth retrying (with bounded backoff).
RETRYABLE_FAILURES: frozenset[FailureClass] = frozenset(
    {FailureClass.WORKER_UNAVAILABLE, FailureClass.TIMEOUT}
)

# Policy failures: never retried; the job is denied.
POLICY_FAILURES: frozenset[FailureClass] = frozenset(
    {FailureClass.OUT_OF_SCOPE, FailureClass.NOT_APPROVED}
)


@dataclass(frozen=True, slots=True)
class Job:
    """One executable unit of a plan step."""

    id: str
    plan_step_key: str
    idempotency_key: str
    status: JobStatus = JobStatus.PENDING
    attempt: int = 0
    max_attempts: int = 3
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    result_digest: str = ""
    failure_class: str = ""
    dependencies: tuple[str, ...] = ()
    # Optional per-job payload (e.g. loop step metadata); deliberately NOT
    # persisted by the SQLAlchemy store until a schema column exists. Added
    # backward-compatibly (default-only) so existing Job constructions and DB
    # mappings are unaffected.
    parameters: dict[str, Any] = field(default_factory=dict)
