# tests/application/reasoning_loop/test_job_builder.py
"""LoopStep -> Job builder (spec §6.3, §7, v0.7.2 Task 2).

A scheduled loop step is converted into a plain ``Job`` (never a ``LoopJob``
subclass). The conversion is pure/incremental: it carries the loop + step
metadata on the Job's ``idempotency_key``/``plan_step_key``/``parameters``
without touching the ``Job`` class hierarchy.
"""
from __future__ import annotations

from datetime import UTC, datetime

from secopent.application.reasoning_loop.job_builder import build_job
from secopent.domain.jobs.models import Job, JobStatus
from secopent.domain.permits.models import ExecutionPermit
from secopent.domain.reasoning_loop.models import (
    LoopActionType,
    LoopId,
    LoopStep,
    PolicyDecision,
    ProposeAction,
)

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _permit(loop_id: LoopId, step_id: str) -> ExecutionPermit:
    """A signed-style permit carrying the loop's proposed-action digest."""
    return ExecutionPermit(
        job_id=f"loop:{loop_id.value}:{step_id}",
        worker_id="reasoning-loop",
        scope_digest="sha256:" + "a" * 64,
        plan_digest="sha256:" + "b" * 64,
        capabilities=("nuclei",),
        budget=0.0,
        issued_at=_T0,
        expires_at=datetime(2026, 1, 1, 1, 0, tzinfo=UTC),
        nonce="nonce-abc123",
        signature="",  # domain layer does not verify signatures here
    )


def _action() -> ProposeAction:
    return ProposeAction(
        action_type=LoopActionType.RUN_TOOL,
        payload={"tool_id": "nuclei", "parameters": {"tags": ["xss"]}},
        rationale="s" * 80,
        confidence=0.5,
    )


def _step(loop_id: LoopId, step_number: int) -> LoopStep:
    return LoopStep(
        step_id=str(step_number),
        loop_id=loop_id,
        step_number=step_number,
        timestamp=_T0,
        context_hash_before="sha256:" + "0" * 64,
        proposed_action=_action(),
        propose_tokens_used=0,
        propose_latency_ms=0,
        propose_rationale=_action().rationale,
        schema_check_passed=True,
        policy_decision=PolicyDecision(verdict="allow", reason="ok"),
        permit_id="permit-nonce",  # a real signed permit would be present here
        tool_or_case_id="nuclei",
        execution_result_digest="sha256:" + "1" * 64,
        evidence_refs=(),
        observation_signals=(),
        catalog_class_matched=frozenset(),
        oracle_progressed=False,
        correlation_id="corr-1",
    )


def test_build_job_returns_plain_job_for_signed_permit_loop_step() -> None:
    loop_id = LoopId(value="abcd1234")
    step = _step(loop_id, step_number=7)
    permit = _permit(loop_id, step_id=str(step.step_number))

    job = build_job(
        loop_id,
        step.step_number,
        permit=permit,
        tool_or_case_id=step.tool_or_case_id or "",
        parameters={"tags": ["xss"]},
    )

    # A plain Job, exactly -- never a LoopJob (or any subclass) instance.
    assert type(job) is Job

    step_id = str(step.step_number)
    assert job.idempotency_key == f"{loop_id.value}:{step_id}"
    assert job.plan_step_key == f"loop:{loop_id.value}:{step_id}"
    assert job.status is JobStatus.READY
    assert job.dependencies == ()

    assert job.parameters["loop_id"] == loop_id.value
    assert job.parameters["step_id"] == step_id
    assert job.parameters["step_number"] == step.step_number
    assert job.parameters["proposed_action_digest"] == permit.scope_digest
    assert job.parameters["permit_id"] == permit.job_id
    assert job.parameters["tool_or_case_id"] == "nuclei"
    assert job.parameters["parameters"] == {"tags": ["xss"]}