# src/secopent/interfaces/api/routers/loops.py
"""ReasoningLoop control plane REST surface (spec §6.3; v0.7.7 + v0.7.8).

- ``POST /loops/{loop_id}/pause``  - freeze a running loop (human only);
- ``POST /loops/{loop_id}/resume`` - resume under a human-signed approval;
- ``GET  /loops/{loop_id}``        - read-only status (agent + human callable);
- ``POST /loops/{loop_id}/stop``   - kill into EMERGENCY_STOPPED (human only);
- ``POST /loops``                  - create a loop (human only, 201).

Pause/resume are enforced human-only *in the service* (agent -> ApprovalRejected);
stop/create gate ``actor_role`` at the router boundary (mirroring signing-keys /
assessments emergency-stop). The router maps service errors onto HTTP and reaches
the composed services through ``request.app.state`` (mirroring how
``emergency_stop`` reads ``app.state.emergency_stop``).
"""
from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from ....application.audit_chain import AuditChain
from ....application.ports.loop_approval import (
    ApprovalRejected,
    ApprovalRequired,
)
from ....application.ports.loop_state import LoopStateRepository
from ....application.ports.loop_step import LoopStepRepository
from ....application.reasoning_loop.audit import (
    LOOP_CREATED,
    LOOP_RESOURCE_TYPE,
    LOOP_TERMINATED,
)
from ....application.reasoning_loop.pause_control import (
    PauseBudgetExceeded,
    PauseControlService,
)
from ....domain.common.canonical import utc_now
from ....domain.common.errors import DomainError
from ....domain.reasoning_loop.models import (
    LoopBudget,
    LoopId,
    LoopPhase,
    LoopPlan,
    LoopState,
    LoopTerminationPolicy,
)
from ....infrastructure.db.session import Database
from ....infrastructure.reasoning_loop.sqlalchemy_state import (
    SqlAlchemyLoopStateRepository,
    SqlAlchemyLoopStepRepository,
)
from ..schemas import (
    LoopCreateBody,
    LoopOut,
    LoopStopBody,
)

router = APIRouter(prefix="/loops", tags=["loops"])


class LoopPauseRequest(BaseModel):
    """Body for POST /loops/{id}/pause (human actor required)."""

    model_config = ConfigDict(extra="forbid")

    actor: str
    reason: str
    actor_role: str = "human"


class LoopResumeRequest(BaseModel):
    """Body for POST /loops/{id}/resume (human actor + signed approval)."""

    model_config = ConfigDict(extra="forbid")

    actor: str
    actor_role: str = "human"
    approved_by: str | None = None
    signature: str | None = None
    nonce: str | None = None
    expires_at: datetime | None = None
    modified_context: object | None = None


def _control(request: Request) -> PauseControlService:
    """The composed PauseControlService, or a loud 503 when unconfigured.

    The composition root (``create_app``) is mandatory since the loop service
    is wired onto ``app.state.loop_control``; an unconfigured app fails loudly
    rather than silently reporting a false pause/resume.
    """
    control = getattr(request.app.state, "loop_control", None)
    if not isinstance(control, PauseControlService):
        raise HTTPException(status_code=503, detail="loop control not configured")
    return control


def _loops(
    request: Request,
    *,
    session: Session | None = None,
) -> tuple[LoopStateRepository, LoopStepRepository, AuditChain]:
    """The loop state/step repos + signed audit chain, or a loud 503.

    Write handlers pass a UoW ``session`` so a fresh ``SqlAlchemyLoop*Repository``
    is built on that session — the save then commits with the caller's
    transaction (v0.7.2 hotfix for issue v10: the pre-bound singleton repo
    only ``merge``-ed, never committed, so loop rows vanished on session close).

    Read-only handlers omit ``session`` and use the repos wired onto
    ``app.state`` (in-memory singletons or a pre-bound SQL repo). An
    unconfigured app fails loudly rather than reporting a false status/stop.
    """
    if session is not None:
        audit = getattr(request.app.state, "audit_chain", None)
        if not isinstance(audit, AuditChain):
            raise HTTPException(status_code=503, detail="audit chain not configured")
        return (
            SqlAlchemyLoopStateRepository(session),
            SqlAlchemyLoopStepRepository(session),
            audit,
        )
    state_repo = getattr(request.app.state, "loop_state_repo", None)
    step_repo = getattr(request.app.state, "loop_step_repo", None)
    audit = getattr(request.app.state, "audit_chain", None)
    if not isinstance(state_repo, LoopStateRepository) or not isinstance(
        step_repo, LoopStepRepository
    ):
        raise HTTPException(status_code=503, detail="loop state not configured")
    if not isinstance(audit, AuditChain):
        raise HTTPException(status_code=503, detail="audit chain not configured")
    return state_repo, step_repo, audit


def _loop_out(state: LoopState, step_count: int) -> dict[str, object]:
    """Project a LoopState (plus executed step count) into the response."""
    budget = state.budget.snapshot()
    return {
        "loop_id": state.loop_id.value,
        "assessment_id": state.assessment_id,
        "phase": state.phase.value,
        "budget_remaining": {
            "steps": budget.steps_remaining,
            "tokens": budget.tokens_remaining,
            "wall_seconds": budget.wall_seconds_remaining,
        },
        "step_count": step_count,
        "context_hash": state.context_hash,
    }


@contextmanager
def _loop_write_ctx(request: Request) -> Iterator[Session | None]:
    """Transaction context for a loop write (v0.7.2 hotfix for issue v10).

    When the wired loop state repo is SQL-backed (production), yields a UoW
    session so the save + signed audit record commit atomically (the
    pre-bound SQL repo only merge-ed, never committed). When the wired repo
    is InMemory (dev/test wiring), yields ``None`` so ``_loops`` falls back
    to the pre-bound in-memory repos — in-memory saves need no commit.
    """
    from ....application.reasoning_loop.in_memory_state import (
        InMemoryLoopStateRepository,
    )

    state_repo = getattr(request.app.state, "loop_state_repo", None)
    db = getattr(request.app.state, "db", None)
    if (
        isinstance(db, Database)
        and not isinstance(state_repo, InMemoryLoopStateRepository)
    ):
        with db.unit_of_work() as uow:
            yield uow.session
    else:
        yield None


@router.get("/{loop_id}", response_model=LoopOut)
def get_loop(loop_id: str, request: Request) -> dict[str, object]:
    """Read-only status of a loop (agent + human callable; no actor gating).

    Returns the phase, remaining budget snapshot, executed step count and
    context hash. Unknown loop -> 404; unconfigured app -> 503.
    """
    state_repo, step_repo, _audit = _loops(request)
    state = state_repo.get(LoopId(loop_id))
    if state is None:
        raise HTTPException(status_code=404, detail=f"no loop state for {loop_id}")
    steps = step_repo.list_for_loop(state.loop_id)
    return _loop_out(state, len(steps))


@router.post("/{loop_id}/stop")
def stop_loop(loop_id: str, payload: LoopStopBody, request: Request) -> dict[str, str]:
    """Stop a loop into EMERGENCY_STOPPED (human only; agent -> 403).

    Mirrors the orchestrator's ``emergency_stop`` semantics (direct transition,
    NOT via ``run_step`` so a PAUSED loop is still killable) and the MCP
    ``loop_stop`` handler. Idempotent for an already-stopped loop (200).
    Unknown loop -> 404; unconfigured app -> 503.
    """
    if payload.actor_role != "human":
        raise HTTPException(
            status_code=403,
            detail="loop stop is human-only (agents cannot stop a loop)",
        )
    try:
        lid = LoopId(loop_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    with _loop_write_ctx(request) as session:
        state_repo, _step_repo, audit = _loops(request, session=session)
        state = state_repo.get(lid)
        if state is None:
            raise HTTPException(
                status_code=404, detail=f"no loop state for {loop_id}",
            )
        if state.phase is not LoopPhase.EMERGENCY_STOPPED:
            now = utc_now()
            stopped = replace(
                state, phase=LoopPhase.EMERGENCY_STOPPED, last_step_at=now,
            )
            state_repo.save(stopped)
            audit.record(
                actor=payload.actor,
                action=LOOP_TERMINATED,
                resource_type=LOOP_RESOURCE_TYPE,
                resource_id=loop_id,
                payload={
                    "final_phase": LoopPhase.EMERGENCY_STOPPED.value,
                    "reason": "emergency_stop",
                    "human_reason": payload.reason
                    or "stopped via REST /loops/{id}/stop",
                    "from_phase": state.phase.value,
                },
                session=session,
            )
            state = stopped
        return {"loop_id": state.loop_id.value, "phase": state.phase.value}


@router.post("", status_code=201)
def create_loop(payload: LoopCreateBody, request: Request) -> dict[str, str]:
    """Create a loop in INITIALIZING (human only; agent -> 403).

    Builds a fresh LoopState via the domain models (default budget unless
    overridden) and records a signed ``loop.created`` event. Returns 201 with
    the new loop id + phase.
    """
    if payload.actor_role != "human":
        raise HTTPException(
            status_code=403,
            detail="loop creation is human-only (agents cannot create a loop)",
        )
    with _loop_write_ctx(request) as session:
        state_repo, _step_repo, audit = _loops(request, session=session)
        now = utc_now()
        loop_id = LoopId.new()
        base = LoopBudget.default()
        budget = LoopBudget(
            max_steps=payload.max_steps
            if payload.max_steps is not None
            else base.max_steps,
            max_total_tokens=(
                payload.max_total_tokens
                if payload.max_total_tokens is not None
                else base.max_total_tokens
            ),
            max_wall_seconds=(
                payload.max_wall_seconds
                if payload.max_wall_seconds is not None
                else base.max_wall_seconds
            ),
        )
        plan = LoopPlan(
            plan_id=f"plan-{uuid.uuid4().hex[:12]}",
            loop_id=loop_id,
            assessment_id=payload.assessment_id,
            termination_policy=LoopTerminationPolicy.default(),
            policy_snapshot="rest:loop:default",
            created_at=now,
        )
        state = LoopState(
            loop_id=plan.loop_id,
            assessment_id=plan.assessment_id,
            phase=LoopPhase.INITIALIZING,
            policy_snapshot=plan.policy_snapshot,
            budget=budget,
            context_hash="0" * 64,
            catalog_required_remaining=frozenset(),
            catalog_required_executed=frozenset(),
            consecutive_no_signal=0,
            consecutive_policy_rejected=0,
            started_at=now,
            last_step_at=None,
        )
        state_repo.save(state)
        audit.record(
            actor=payload.actor,
            action=LOOP_CREATED,
            resource_type=LOOP_RESOURCE_TYPE,
            resource_id=loop_id.value,
            payload={
                "assessment_id": payload.assessment_id,
                "budget": {
                    "max_steps": budget.max_steps,
                    "max_total_tokens": budget.max_total_tokens,
                    "max_wall_seconds": budget.max_wall_seconds,
                },
            },
            session=session,
        )
        return {"loop_id": loop_id.value, "phase": state.phase.value}


@router.post("/{loop_id}/pause")
def pause_loop(loop_id: str, payload: LoopPauseRequest, request: Request) -> dict[str, str]:
    """Pause a loop (human only; agent -> 403).

    Returns the loop id + phase. Already-paused loops are idempotent (200).
    """
    service = _control(request)
    try:
        with _loop_write_ctx(request) as session:
            state = service.pause(
                loop_id=LoopId(loop_id),
                actor=payload.actor,
                reason=payload.reason,
                actor_role=payload.actor_role,
                session=session,
            )
        return {"loop_id": state.loop_id.value, "phase": state.phase.value}
    except ApprovalRejected as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DomainError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{loop_id}/resume")
def resume_loop(
    loop_id: str, payload: LoopResumeRequest, request: Request
) -> dict[str, object]:
    """Resume a paused loop under a human-signed approval (agent -> 403).

    Missing/empty signature -> 401 (ApprovalRequired); expired pause budget ->
    409; a stopped/terminal loop cannot resume -> 409; unknown loop -> 404.
    """
    service = _control(request)
    try:
        with _loop_write_ctx(request) as session:
            state = service.resume(
                loop_id=LoopId(loop_id),
                actor=payload.actor,
                actor_role=payload.actor_role,
                approved_by=payload.approved_by,
                signature=payload.signature,
                nonce=payload.nonce,
                expires_at=payload.expires_at,
                modified_context=payload.modified_context,
                session=session,
            )
    except ApprovalRejected as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ApprovalRequired as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except PauseBudgetExceeded as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except DomainError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        "loop_id": state.loop_id.value,
        "phase": state.phase.value,
        "pause_attempts": state.pause_attempts,
    }
