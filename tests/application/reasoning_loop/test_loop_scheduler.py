"""LoopJobScheduler — JobService scheduling with permit pre-check (v0.7.2 Task 3).

A ``LoopJobScheduler`` is the thin JobService-facing seam for a reasoning-loop
step that already holds a signed ``ExecutionPermit``. Scheduling is gated
ahead of enqueue by ``PermitVerifierProtocol.verify`` (signature + expiry +
worker binding for the ``worker_id`` the job will run under); the step is then
enqueued as a **plain Job** via ``build_job`` + ``JobService.add``. A repeated
schedule of the same loop_step is a no-op (idempotency_key collision) and a
permit that does not verify is rejected before anything is enqueued.
"""

from __future__ import annotations

from datetime import timedelta

from secopent.application.jobs import JobService
from secopent.application.reasoning_loop.loop_scheduler import LoopJobScheduler
from secopent.domain.common.canonical import utc_now
from secopent.domain.jobs.models import JobStatus
from secopent.domain.permits.models import ExecutionPermit
from secopent.domain.reasoning_loop.models import LoopId
from secopent.infrastructure.permits.permit_signer import (
    PermitSigner,
    PermitVerifier,
)

_WORKER = "worker-1"


def _loop_id() -> LoopId:
    return LoopId(value="abcd1234")


def _unsigned_permit(loop_id: LoopId, step_id: str, *, worker_id: str = _WORKER) -> ExecutionPermit:
    """A permit whose content fields are filled but signature is empty/unsigned."""
    now = utc_now()
    return ExecutionPermit(
        job_id=f"loop:{loop_id.value}:{step_id}",
        worker_id=worker_id,
        scope_digest="sha256:" + "a" * 64,
        plan_digest="sha256:" + "b" * 64,
        capabilities=("nuclei",),
        budget=0.0,
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
        nonce=f"nonce-{step_id}",
        signature="",  # never signed
    )


def _signed_permit(
    signer: PermitSigner,
    loop_id: LoopId,
    step_id: str,
    *,
    worker_id: str = _WORKER,
) -> ExecutionPermit:
    """A permit signed by ``signer`` (the SAME signer whose public key backs the
    scheduler under test, so the signature actually verifies)."""
    permit = _unsigned_permit(loop_id, step_id, worker_id=worker_id)
    return signer.issue(permit)


def _scheduler(signer: PermitSigner) -> tuple[LoopJobScheduler, JobService]:
    """A scheduler + JobService whose verifier is bound to the signer's public key."""
    verifier = PermitVerifier(signer.public_key_bytes())
    jobs = JobService()
    scheduler = LoopJobScheduler(jobs=jobs, verifier=verifier)
    return scheduler, jobs


def test_schedule_enqueues_job_and_is_leaseable() -> None:
    """A validly-permitted step is enqueued; JobService.add puts it in READY so
    ``leaseable`` immediately hits it."""
    signer = PermitSigner()
    scheduler, jobs = _scheduler(signer)
    permit = _signed_permit(signer, _loop_id(), "7")

    ok = scheduler.schedule(_loop_id(), "7", "nuclei", {"tags": ["xss"]}, permit, _WORKER)

    assert ok is True
    leaseable = jobs.leaseable(now=utc_now())
    assert len(leaseable) == 1
    job = leaseable[0]
    assert job.idempotency_key == "abcd1234:7"
    assert job.status is JobStatus.READY
    # loop metadata rides on stable fields (not the non-persisted parameters).
    assert job.plan_step_key == "loop:abcd1234:7"


def test_repeated_schedule_of_same_step_is_idempotent_noop() -> None:
    """Scheduling the same loop_step twice enqueues it exactly once; the second
    call returns False and does not re-insert (idempotency_key collision)."""
    signer = PermitSigner()
    scheduler, jobs = _scheduler(signer)
    permit = _signed_permit(signer, _loop_id(), "3")

    first = scheduler.schedule(_loop_id(), "3", "nuclei", {}, permit, _WORKER)
    second = scheduler.schedule(_loop_id(), "3", "nuclei", {}, permit, _WORKER)

    assert first is True
    assert second is False  # idempotent rejection, no duplicate enqueue
    matching = [j for j in jobs.all() if j.idempotency_key == "abcd1234:3"]
    assert len(matching) == 1


def test_schedule_rejects_permit_not_signed() -> None:
    """A loop_step carrying an unsigned permit is rejected (verifier.verify
    raises PermitSignatureInvalid) before anything is enqueued."""
    scheduler, jobs = _scheduler(PermitSigner())
    permit = _unsigned_permit(_loop_id(), "5")

    ok = scheduler.schedule(_loop_id(), "5", "nuclei", {}, permit, _WORKER)

    assert ok is False
    assert jobs.all() == ()


def test_schedule_rejects_permit_for_different_worker() -> None:
    """The permit is bound to a specific worker; scheduling for another worker
    fails verification (PermitWorkerMismatch) and nothing is enqueued."""
    signer = PermitSigner()
    scheduler, jobs = _scheduler(signer)
    # Correctly signed, but bound to a DIFFERENT worker than the one the job
    # is scheduled for -> verifier raises PermitWorkerMismatch.
    permit = _signed_permit(signer, _loop_id(), "9", worker_id="someone-else")

    ok = scheduler.schedule(_loop_id(), "9", "nuclei", {}, permit, _WORKER)

    assert ok is False
    assert jobs.all() == ()


def test_schedule_verifies_permit_before_enqueue() -> None:
    """Permit pre-check happens ahead of enqueue: even a tampered permit is
    rejected and never reaches the store."""
    signer = PermitSigner()
    scheduler, jobs = _scheduler(signer)
    permit = _signed_permit(signer, _loop_id(), "11")
    # Tamper the content the signature no longer covers (scope_digest changed
    # after signing) -> the signature must no longer verify.
    tampered = ExecutionPermit(
        job_id=permit.job_id,
        worker_id=permit.worker_id,
        scope_digest="sha256:" + "f" * 64,
        plan_digest=permit.plan_digest,
        capabilities=permit.capabilities,
        budget=permit.budget,
        issued_at=permit.issued_at,
        expires_at=permit.expires_at,
        nonce=permit.nonce,
        signature=permit.signature,
    )

    ok = scheduler.schedule(_loop_id(), "11", "nuclei", {}, tampered, _WORKER)

    assert ok is False
    assert jobs.all() == ()

    # Sanity: the same signature over untouched content WOULD verify, proving
    # the rejection was the content-mismatch, not the verifier being broken.
    ok_clean = scheduler.schedule(_loop_id(), "12", "nuclei", {}, permit, _WORKER)
    assert ok_clean is True
