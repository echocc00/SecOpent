"""Frozen dataclasses for ReasoningLoop state and data (spec §3)."""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from enum import Enum

_LOOP_ID_RE = re.compile(r"^[0-9a-f]{8}$")


@dataclass(frozen=True, slots=True)
class LoopId:
    """Value object identifying one ReasoningLoop instance."""

    value: str

    def __post_init__(self) -> None:
        if not _LOOP_ID_RE.fullmatch(self.value):
            raise ValueError(
                f"LoopId must be 8 lowercase hex chars, got: {self.value!r}"
            )

    @classmethod
    def new(cls) -> LoopId:
        return cls(value=secrets.token_hex(4))


class LoopPhase(str, Enum):
    """Deterministic loop lifecycle states. LLM MUST NOT write this value."""

    INITIALIZING = "initializing"
    RUNNING = "running"
    CONVERGED = "converged"  # no new signals for N steps
    CATALOG_FLOOR_DONE = "catalog_floor_done"  # audit milestone: floor green (NOT a terminator)
    PAUSED = "paused"  # human-paused; resumable (spec §6.3; full pause/resume API lands in v0.7.7)
    RESUMED = "resumed"  # transient: recorded after a pause→resume transition
    BUDGET_EXHAUSTED = "budget_exhausted"  # any of steps/tokens/wall hit 0
    POLICY_BLOCKED = "policy_blocked"  # 3-strike gate rejection
    EMERGENCY_STOPPED = "emergency_stopped"
    COMPLETED = "completed"  # terminal happy path (converged / target met)


@dataclass(frozen=True, slots=True)
class LoopBudget:
    """Trackable budget for a ReasoningLoop instance.

    Immutable; ``consume`` returns a new instance. ``exhausted`` is true when
    any of the three limits is reached. These are HARD limits — once hit, the
    orchestrator MUST transition to ``BUDGET_EXHAUSTED`` and stop issuing work.
    """

    max_steps: int
    max_total_tokens: int
    max_wall_seconds: int
    steps_used: int = 0
    tokens_used: int = 0
    wall_seconds_used: int = 0

    @classmethod
    def default(cls) -> LoopBudget:
        return cls(
            max_steps=50,
            max_total_tokens=200_000,
            max_wall_seconds=1800,
        )

    def consume(self, *, steps: int = 0, tokens: int = 0, wall_seconds: int = 0) -> LoopBudget:
        return LoopBudget(
            max_steps=self.max_steps,
            max_total_tokens=self.max_total_tokens,
            max_wall_seconds=self.max_wall_seconds,
            steps_used=self.steps_used + steps,
            tokens_used=self.tokens_used + tokens,
            wall_seconds_used=self.wall_seconds_used + wall_seconds,
        )

    def snapshot(self) -> LoopBudgetSnapshot:
        return LoopBudgetSnapshot(
            steps_remaining=max(0, self.max_steps - self.steps_used),
            tokens_remaining=max(0, self.max_total_tokens - self.tokens_used),
            wall_seconds_remaining=max(0, self.max_wall_seconds - self.wall_seconds_used),
        )

    def exhausted(self) -> bool:
        return (
            self.steps_used >= self.max_steps
            or self.tokens_used >= self.max_total_tokens
            or self.wall_seconds_used >= self.max_wall_seconds
        )


@dataclass(frozen=True, slots=True)
class LoopBudgetSnapshot:
    """Read-only view of remaining budget, safe to embed in audit payloads."""

    steps_remaining: int
    tokens_remaining: int
    wall_seconds_remaining: int
