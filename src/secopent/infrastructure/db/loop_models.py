"""ORM for ReasoningLoop persistence (v0.7.8, spec §12.1).

Maps the frozen ``LoopState`` / ``LoopStep`` domain dataclasses to the
``core_reasoning_loops`` / ``core_loop_steps`` tables created by the
``d3f4a5b6c7d8`` migration. Every ``LoopState`` field (incl. the v0.7.7 pause
counters) is persisted so ``repo.get(state) == state`` round-trips with full
fidelity. JSON columns carry frozen-dataclass set/tuple fields as lists and the
``LoopBudget`` as a dict; the repositories serialize/deserialize both ways.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .core_models import CoreBase


class CoreReasoningLoop(CoreBase):
    __tablename__ = "core_reasoning_loops"

    loop_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("core_assessments.id"), nullable=False
    )
    phase: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_snapshot: Mapped[str] = mapped_column(String(64), nullable=False)
    budget_state: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    context_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    catalog_required_remaining: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    catalog_required_executed: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    consecutive_no_signal: Mapped[int] = mapped_column(Integer, nullable=False)
    consecutive_policy_rejected: Mapped[int] = mapped_column(Integer, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_step_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    pause_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    paused_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False)


class CoreLoopStep(CoreBase):
    __tablename__ = "core_loop_steps"

    step_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    loop_id: Mapped[str] = mapped_column(
        ForeignKey("core_reasoning_loops.loop_id"), nullable=False
    )
    step_number: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    context_hash_before: Mapped[str] = mapped_column(String(64), nullable=False)
    proposed_action: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    propose_tokens_used: Mapped[int] = mapped_column(Integer, nullable=False)
    propose_latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    propose_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    schema_check_passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    policy_decision: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    permit_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tool_or_case_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    execution_result: Mapped[str | None] = mapped_column(JSON, nullable=True)
    evidence_refs: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    observation_signals: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    catalog_class_matched: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    oracle_progressed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False)
