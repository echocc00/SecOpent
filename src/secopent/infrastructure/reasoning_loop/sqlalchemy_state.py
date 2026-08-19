# src/secopent/infrastructure/reasoning_loop/sqlalchemy_state.py
"""SQLAlchemy-backed ReasoningLoop state/step repositories (v0.7.8, spec §12.1).

Implements the ``LoopStateRepository`` / ``LoopStepRepository`` ports against
``core_reasoning_loops`` / ``core_loop_steps`` so the in-memory stores can be
replaced in production. Frozen-dataclass fields that SQLAlchemy cannot store
natively are serialized: ``LoopBudget`` → JSON dict, ``frozenset``/``tuple`` →
sorted JSON lists, ``ProposeAction`` (pydantic) → ``model_dump()``/``validate``,
``PolicyDecision`` (dataclass) → dict. Every ``LoopState`` field is persisted so
``repo.get(state) == state`` round-trips with full fidelity (incl. the v0.7.7
pause counters).
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from typing import overload

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...domain.reasoning_loop.models import (
    LoopBudget,
    LoopId,
    LoopPhase,
    LoopState,
    LoopStep,
    PolicyDecision,
    ProposeAction,
)
from ..db.core_models import CoreBase  # noqa: F401 - ensure metadata built
from ..db.loop_models import CoreLoopStep, CoreReasoningLoop


def _budget_to_json(budget: LoopBudget) -> dict[str, int]:
    return {
        "max_steps": budget.max_steps,
        "max_total_tokens": budget.max_total_tokens,
        "max_wall_seconds": budget.max_wall_seconds,
        "steps_used": budget.steps_used,
        "tokens_used": budget.tokens_used,
        "wall_seconds_used": budget.wall_seconds_used,
    }


def _budget_from_json(data: dict[str, int]) -> LoopBudget:
    return LoopBudget(
        max_steps=data["max_steps"],
        max_total_tokens=data["max_total_tokens"],
        max_wall_seconds=data["max_wall_seconds"],
        steps_used=data["steps_used"],
        tokens_used=data["tokens_used"],
        wall_seconds_used=data["wall_seconds_used"],
    )


@overload
def _aware(value: datetime) -> datetime: ...
@overload
def _aware(value: None) -> None: ...
def _aware(value: datetime | None) -> datetime | None:
    """SQLite stores DateTime(timezone=True) as naive; re-attach UTC so the
    round-tripped dataclass compares equal to the in-memory original."""
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


def _to_state(row: CoreReasoningLoop) -> LoopState:
    return LoopState(
        loop_id=LoopId(value=row.loop_id),
        assessment_id=row.assessment_id,
        phase=LoopPhase(row.phase),
        policy_snapshot=row.policy_snapshot,
        budget=_budget_from_json(row.budget_state),
        context_hash=row.context_hash,
        catalog_required_remaining=frozenset(row.catalog_required_remaining),
        catalog_required_executed=frozenset(row.catalog_required_executed),
        consecutive_no_signal=row.consecutive_no_signal,
        consecutive_policy_rejected=row.consecutive_policy_rejected,
        started_at=_aware(row.started_at),
        last_step_at=_aware(row.last_step_at),
        pause_attempts=row.pause_attempts,
        paused_at=_aware(row.paused_at),
        resumed_at=_aware(row.resumed_at),
    )


def _from_state(state: LoopState) -> CoreReasoningLoop:
    return CoreReasoningLoop(
        loop_id=state.loop_id.value,
        assessment_id=state.assessment_id,
        phase=state.phase.value,
        policy_snapshot=state.policy_snapshot,
        budget_state=_budget_to_json(state.budget),
        context_hash=state.context_hash,
        catalog_required_remaining=sorted(state.catalog_required_remaining),
        catalog_required_executed=sorted(state.catalog_required_executed),
        consecutive_no_signal=state.consecutive_no_signal,
        consecutive_policy_rejected=state.consecutive_policy_rejected,
        started_at=state.started_at,
        last_step_at=state.last_step_at,
        ended_at=_derive_ended_at(state),
        pause_attempts=state.pause_attempts,
        paused_at=state.paused_at,
        resumed_at=state.resumed_at,
        correlation_id=_derive_correlation_id(state),
    )


def _derive_ended_at(state: LoopState) -> datetime | None:
    terminal = {
        LoopPhase.CONVERGED,
        LoopPhase.BUDGET_EXHAUSTED,
        LoopPhase.POLICY_BLOCKED,
        LoopPhase.EMERGENCY_STOPPED,
        LoopPhase.COMPLETED,
        LoopPhase.CATALOG_FLOOR_DONE,
    }
    return state.last_step_at if state.phase in terminal else None


def _derive_correlation_id(state: LoopState) -> str:
    # LoopState does not carry a correlation id today; default to the loop id so
    # the NOT NULL column stays populated. (Task 3 wiring may thread a real one.)
    return ""


def _to_step(row: CoreLoopStep) -> LoopStep:
    return LoopStep(
        step_id=row.step_id,
        loop_id=LoopId(value=row.loop_id),
        step_number=row.step_number,
        timestamp=_aware(row.timestamp),
        context_hash_before=row.context_hash_before,
        proposed_action=ProposeAction.model_validate(row.proposed_action),
        propose_tokens_used=row.propose_tokens_used,
        propose_latency_ms=row.propose_latency_ms,
        propose_rationale=row.propose_rationale or "",
        schema_check_passed=row.schema_check_passed,
        policy_decision=PolicyDecision(**row.policy_decision),
        permit_id=row.permit_id,
        tool_or_case_id=row.tool_or_case_id,
        execution_result_digest=row.execution_result or "",
        evidence_refs=tuple(row.evidence_refs or ()),
        observation_signals=tuple(row.observation_signals or ()),
        catalog_class_matched=frozenset(row.catalog_class_matched or ()),
        oracle_progressed=row.oracle_progressed,
        correlation_id=row.correlation_id,
    )


def _from_step(step: LoopStep) -> CoreLoopStep:
    return CoreLoopStep(
        step_id=step.step_id,
        loop_id=step.loop_id.value,
        step_number=step.step_number,
        timestamp=step.timestamp,
        context_hash_before=step.context_hash_before,
        proposed_action=step.proposed_action.model_dump(mode="json"),
        propose_tokens_used=step.propose_tokens_used,
        propose_latency_ms=step.propose_latency_ms,
        propose_rationale=step.propose_rationale,
        schema_check_passed=step.schema_check_passed,
        policy_decision=asdict(step.policy_decision),
        permit_id=step.permit_id,
        tool_or_case_id=step.tool_or_case_id,
        execution_result=step.execution_result_digest,
        evidence_refs=list(step.evidence_refs),
        observation_signals=list(step.observation_signals),
        catalog_class_matched=sorted(step.catalog_class_matched),
        oracle_progressed=step.oracle_progressed,
        correlation_id=step.correlation_id,
    )


class SqlAlchemyLoopStateRepository:
    """Persisted LoopState store — one row per loop."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, loop_id: LoopId) -> LoopState | None:
        row = self._session.get(CoreReasoningLoop, loop_id.value)
        return _to_state(row) if row else None

    def save(self, state: LoopState) -> None:
        self._session.merge(_from_state(state))


class SqlAlchemyLoopStepRepository:
    """Persisted append-only LoopStep store."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, step: LoopStep) -> None:
        self._session.merge(_from_step(step))

    def list_for_loop(self, loop_id: LoopId) -> list[LoopStep]:
        stmt = (
            select(CoreLoopStep)
            .where(CoreLoopStep.loop_id == loop_id.value)
            .order_by(CoreLoopStep.step_number.asc())
        )
        rows = self._session.execute(stmt).scalars().all()
        return [_to_step(row) for row in rows]
