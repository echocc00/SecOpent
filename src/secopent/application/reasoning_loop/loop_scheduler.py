"""LoopJobScheduler — scheduling a permitted loop step onto JobService (v0.7.2 Task 3).

A thin JobService-facing seam used by the orchestrator to run a reasoning-loop
step that already holds a signed ``ExecutionPermit`` through the standard
execution plane. Crucially it schedules the step as a **plain Job** (via
``job_builder.build_job``) — never a LoopJob subclass — so the sandbox /
seccomp / netns / lease machinery treats it exactly like any other job and
cannot tell (let alone bypass) that it came from a reasoning loop.

Guarantees (each is enforced before a step reaches ``JobService``):

- **Permit pre-check**: ``PermitVerifierProtocol.verify`` runs first (signature
  + expiry + worker binding for the job's ``worker_id``). A permit that does
  not verify is rejected and nothing is enqueued. This is deliberately the
  narrow ``verify`` seam: the scheduler has no ``LoopContext``, so the richer
  ``PermitGate.check`` (which needs one) does not apply here.
- **Idempotency**: scheduling the same ``loop_id:step_id`` twice is a no-op.
  We scan ``JobService`` for an existing job with the same ``idempotency_key``
  before calling ``add`` (which itself is idempotent) and return ``False`` on
  a collision so the caller knows no new work was enqueued.

The scheduler reads loop metadata only from **stable, persisted fields**
(``idempotency_key`` / ``plan_step_key``), never from ``Job.parameters`` —
which the SQLAlchemy store deliberately does not map to a column.
"""

from __future__ import annotations

from typing import Any

from ...domain.common.canonical import utc_now
from ...domain.permits.models import ExecutionPermit
from ...domain.reasoning_loop.models import LoopId
from ..jobs import JobService
from ..ports.security import PermitVerifierProtocol
from .job_builder import build_job


class LoopJobScheduler:
    """Enqueue permitted reasoning-loop steps onto ``JobService``.

    ``verifier`` is the permit-checking port (signature + expiry + worker);
    production wires the Ed25519 ``PermitVerifier`` from infrastructure.
    """

    def __init__(self, jobs: JobService, verifier: PermitVerifierProtocol) -> None:
        self._jobs = jobs
        self._verifier = verifier

    def schedule(
        self,
        loop_id: LoopId,
        step_id: str,
        tool_or_case_id: str,
        parameters: dict[str, Any],
        permit: ExecutionPermit,
        worker_id: str,
    ) -> bool:
        """Verify the permit, then idempotently enqueue the step as a plain Job.

        Returns ``True`` when new work was enqueued and ``False`` when the
        permit failed verification or the step was already scheduled.
        """
        if not self._permit_valid(permit, worker_id=worker_id):
            return False
        if self._already_scheduled(loop_id, step_id):
            return False
        job = build_job(
            loop_id,
            int(step_id),
            permit=permit,
            tool_or_case_id=tool_or_case_id,
            parameters=parameters,
        )
        self._jobs.add(job)
        return True

    def _permit_valid(self, permit: ExecutionPermit, *, worker_id: str) -> bool:
        try:
            self._verifier.verify(
                permit,
                now=utc_now(),
                used_nonces=frozenset(),
                expected_worker=worker_id,
            )
            return True
        except Exception:
            # Invalid signature / expired / replayed / worker mismatch all
            # collapse to "not schedulable"; nothing is enqueued.
            return False

    def _already_scheduled(self, loop_id: LoopId, step_id: str) -> bool:
        """True if a job for this loop_step is already in the store.

        Uses only the stable ``idempotency_key`` (== ``loop_id:step_id``),
        which ``JobService`` dedups on; ``Job.parameters`` is not relied on
        here because the SQLAlchemy store does not persist it.
        """
        key = f"{loop_id.value}:{step_id}"
        return any(j.idempotency_key == key for j in self._jobs.all())
