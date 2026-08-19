# src/secopent/application/reasoning_loop/job_builder.py
"""LoopStep -> Job conversion (spec §6.3, §7; v0.7.2 Task 2).

A loop step that has passed PermitGate (i.e. holds a signed ``ExecutionPermit``)
is scheduled as a **plain ``Job``** — never a ``LoopJob`` subclass. The loop
+ step metadata ride on the standard ``Job`` fields so the execution plane
(sandbox / seccomp / netns / JobService lease) treats it like any other job
and cannot tell — let alone bypass — that it came from a reasoning loop.

Mapping:
- ``idempotency_key`` = ``<loop_id>:<step_id>`` (JobService dedups on this)
- ``plan_step_key``   = ``loop:<loop_id>:<step_id>`` (the ``loop:`` prefix lets
  the orchestrator order/serialize loop jobs ahead of other work)
- ``parameters``      = loop metadata carried verbatim for the worker
- ``status``          = ``READY`` (dependencies are always empty for a step)
"""
from __future__ import annotations

from typing import Any

from ...domain.jobs.models import Job, JobStatus
from ...domain.permits.models import ExecutionPermit
from ...domain.reasoning_loop.models import LoopId


def build_job(
    loop_id: LoopId,
    step_number: int,
    *,
    permit: ExecutionPermit,
    tool_or_case_id: str,
    parameters: dict[str, Any],
) -> Job:
    """Build a plain READY ``Job`` for one permitted reasoning-loop step.

    ``step_id`` is derived deterministically from ``step_number`` (stringified)
    so the builder needs no separate identifier field and the resulting
    idempotency/plan keys stay stable across re-scheduling of the same step.
    """
    step_id = str(step_number)
    idempotency_key = f"{loop_id.value}:{step_id}"
    plan_step_key = f"loop:{loop_id.value}:{step_id}"
    payload = {
        "loop_id": loop_id.value,
        "step_id": step_id,
        "step_number": step_number,
        # The permit binds the step to its proposed action via scope_digest.
        "proposed_action_digest": permit.scope_digest,
        "permit_id": permit.job_id,
        "tool_or_case_id": tool_or_case_id,
        "parameters": parameters,
    }
    return Job(
        id=f"job:loop:{loop_id.value}:{step_id}",
        plan_step_key=plan_step_key,
        idempotency_key=idempotency_key,
        status=JobStatus.READY,
        dependencies=(),
        parameters=payload,
        result_digest="",
        failure_class="",
    )