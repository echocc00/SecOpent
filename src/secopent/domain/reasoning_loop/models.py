"""Frozen dataclasses for ReasoningLoop state and data (spec §3)."""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

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


class LoopActionType(str, Enum):
    """Closed set of action kinds the LLM/Mock proposer may emit."""

    RUN_TOOL = "run_tool"
    RUN_CASE = "run_case"
    REQUEST_PEER = "request_peer"
    REQUEST_ORACLE = "request_oracle"
    REQUEST_CHAIN = "request_chain"
    ABORT_STEP = "abort_step"


class _ProposeActionPayload(BaseModel):
    """Per-action-type payload validator.

    Each action type requires its own keys; missing keys fail validation.
    Unknown keys (i.e. anything not in the per-type schema) are rejected
    via ``extra='forbid'`` to harden against prompt-injection overflow.
    """

    model_config = ConfigDict(extra="forbid")

    # run_tool / run_case / request_peer
    tool_id: str | None = None
    case_id: str | None = None
    peer_name: str | None = None
    instruction: str | None = None
    # run_tool / run_case
    parameters: dict[str, Any] | None = None
    # request_oracle / request_chain
    candidate_id: str | None = None
    hypothesis_id: str | None = None


class ProposeAction(BaseModel):
    """LLM/Mock proposer output. Strict schema; never bypasses Schema Gate."""

    model_config = ConfigDict(extra="forbid")

    action_type: LoopActionType
    payload: dict[str, Any]
    rationale: str = Field(min_length=50, max_length=500)
    confidence: float = Field(ge=0.0, le=1.0)
    hypothesis_id: str | None = None
    catalog_class_targeted: str | None = None

    @field_validator("payload")
    @classmethod
    def _validate_payload(cls, v: dict[str, Any], info: Any) -> dict[str, Any]:
        action_type = info.data.get("action_type")
        required: dict[str, list[str]] = {
            "run_tool": ["tool_id", "parameters"],
            "run_case": ["case_id", "parameters"],
            "request_peer": ["peer_name", "instruction"],
            "request_oracle": ["candidate_id"],
            "request_chain": ["hypothesis_id"],
            "abort_step": [],
        }
        missing = [k for k in required.get(action_type, []) if k not in v]
        if missing:
            raise ValueError(
                f"action_type={action_type!r} requires payload keys {missing!r}"
            )
        # Also enforce forbidden keys per action type via _ProposeActionPayload.
        _ProposeActionPayload.model_validate({k: v.get(k) for k in v if v.get(k) is not None})
        return v

    @property
    def tool_id(self) -> str | None:
        return self.payload.get("tool_id")
