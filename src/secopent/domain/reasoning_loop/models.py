"""Frozen dataclasses for ReasoningLoop state and data (spec §3)."""
from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..common.canonical import canonical_json

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


@dataclass(frozen=True, slots=True)
class ObservationSummary:
    """Compact summary of one Observation, used inside LoopContext.

    ``token_estimate`` is the LLM-side cost of including this summary
    verbatim in a prompt — the context builder uses it to budget the
    observation budget of ``LoopContext``.
    """

    observation_id: str
    tool_or_case_id: str
    target_digest: str
    key_signals: tuple[str, ...]
    confidence: float
    has_full_text: bool
    full_text_ref: str | None
    token_estimate: int


@dataclass(frozen=True, slots=True)
class AvailableCapability:
    """Lightweight pointer to a registered tool/case the proposer may choose."""

    capability_id: str
    kind: str  # "tool" | "case"
    summary: str
    risk_class: str
    cwe: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PendingHypothesis:
    """Pointer to an AttackChain hypothesis awaiting verification."""

    hypothesis_id: str
    description: str
    needed_cwe: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class HandbookSummary:
    """Lightweight, token-bounded distillation of a Handbook for the proposer.

    Carries only the curated, LLM-consumed hints (attack_surface /
    recon_endpoints / payload_classes / verification_hint) — never provenance
    or CWE/OWASP metadata. Frozen + slots for stable hashing; set-like fields
    are stored sorted so ``context_hash()`` is deterministic.
    """

    id: str
    title: str
    attack_surface: tuple[str, ...]
    recon_endpoints: tuple[str, ...]
    payload_classes: tuple[str, ...]
    verification_hint: str


@dataclass(frozen=True, slots=True)
class LoopContext:
    """Structured input the proposer consumes. Immutable; content-addressed."""

    asset_subgraph: tuple[str, ...]
    recent_observations: tuple[ObservationSummary, ...]
    observation_token_count: int
    catalog_already_executed: frozenset[str]
    catalog_still_required: frozenset[str]
    catalog_floor_progress: float
    unconfirmed_candidates: tuple[str, ...]
    confirmed_findings_recent: tuple[str, ...]
    chain_hypotheses_pending: tuple[PendingHypothesis, ...]
    available_tools: tuple[AvailableCapability, ...]
    available_cases: tuple[AvailableCapability, ...]
    available_peers: tuple[str, ...]
    budget_remaining: LoopBudgetSnapshot
    loop_step: int
    max_steps: int
    elapsed_seconds: int
    # v0.7.4 Task 2: curated per-vuln-class handbooks surfaced to the proposer
    # as context hints. Empty by default (no handbook injection). Deliberately
    # NOT fed into available_tools — that field feeds the SchemaGate's
    # SCHEMA_UNKNOWN_TOOL check, so handbook entries must never pollute it.
    handbook_hints: tuple[HandbookSummary, ...] = ()

    def context_hash(self) -> str:
        body = {
            "asset_subgraph": list(self.asset_subgraph),
            "recent_observations": [
                {
                    "observation_id": o.observation_id,
                    "tool_or_case_id": o.tool_or_case_id,
                    "target_digest": o.target_digest,
                    "key_signals": list(o.key_signals),
                    "confidence": o.confidence,
                    "has_full_text": o.has_full_text,
                    "full_text_ref": o.full_text_ref,
                    "token_estimate": o.token_estimate,
                }
                for o in self.recent_observations
            ],
            "observation_token_count": self.observation_token_count,
            "catalog_already_executed": sorted(self.catalog_already_executed),
            "catalog_still_required": sorted(self.catalog_still_required),
            "catalog_floor_progress": self.catalog_floor_progress,
            "unconfirmed_candidates": list(self.unconfirmed_candidates),
            "confirmed_findings_recent": list(self.confirmed_findings_recent),
            "chain_hypotheses_pending": [
                {"hypothesis_id": h.hypothesis_id, "description": h.description,
                 "needed_cwe": list(h.needed_cwe)}
                for h in self.chain_hypotheses_pending
            ],
            "available_tools": [
                {"capability_id": t.capability_id, "kind": t.kind, "summary": t.summary,
                 "risk_class": t.risk_class, "cwe": list(t.cwe)}
                for t in self.available_tools
            ],
            "available_cases": [
                {"capability_id": c.capability_id, "kind": c.kind, "summary": c.summary,
                 "risk_class": c.risk_class, "cwe": list(c.cwe)}
                for c in self.available_cases
            ],
            "available_peers": list(self.available_peers),
            "handbook_hints": [
                {
                    "id": h.id,
                    "title": h.title,
                    "attack_surface": list(h.attack_surface),
                    "recon_endpoints": list(h.recon_endpoints),
                    "payload_classes": list(h.payload_classes),
                    "verification_hint": h.verification_hint,
                }
                for h in self.handbook_hints
            ],
            "budget_remaining": {
                "steps_remaining": self.budget_remaining.steps_remaining,
                "tokens_remaining": self.budget_remaining.tokens_remaining,
                "wall_seconds_remaining": self.budget_remaining.wall_seconds_remaining,
            },
            "loop_step": self.loop_step,
            "max_steps": self.max_steps,
            "elapsed_seconds": self.elapsed_seconds,
        }
        return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Output of PolicyGate; ``verdict`` is deterministic."""

    verdict: Literal["allow", "deny"]
    reason: str
    deny_code: str | None = None


@dataclass(frozen=True, slots=True)
class GateVerdict:
    """Output of a single gate (Schema / Policy / Permit).

    Exactly one of ``passed=True`` (with optional ``permit_id``) or
    ``passed=False`` (with ``deny_code``) is set per call.
    """

    passed: bool
    reason: str
    deny_code: str | None = None
    permit_id: str | None = None
    permit_ttl_seconds: int | None = None


@dataclass(frozen=True, slots=True)
class LoopState:
    """Snapshot of one ReasoningLoop instance.

    The orchestrator produces a new ``LoopState`` per ``step``; nothing
    here is mutable, so audit/replay stays trivial.
    """

    loop_id: LoopId
    assessment_id: str
    phase: LoopPhase
    policy_snapshot: str
    budget: LoopBudget
    context_hash: str
    catalog_required_remaining: frozenset[str]
    catalog_required_executed: frozenset[str]
    consecutive_no_signal: int
    consecutive_policy_rejected: int
    started_at: datetime
    last_step_at: datetime | None


@dataclass(frozen=True, slots=True)
class LoopStep:
    """Per-step audit record (replayable, signed via AuditChain)."""

    step_id: str
    loop_id: LoopId
    step_number: int
    timestamp: datetime
    context_hash_before: str
    proposed_action: ProposeAction
    propose_tokens_used: int
    propose_latency_ms: int
    propose_rationale: str
    schema_check_passed: bool
    policy_decision: PolicyDecision
    permit_id: str | None
    tool_or_case_id: str | None
    execution_result_digest: str
    evidence_refs: tuple[str, ...]
    observation_signals: tuple[str, ...]
    catalog_class_matched: frozenset[str]
    oracle_progressed: bool
    correlation_id: str


@dataclass(frozen=True, slots=True)
class LoopTerminationPolicy:
    """All-deterministic termination configuration. LLM MUST NOT write this."""

    max_steps: int
    max_wall_clock_seconds: int
    max_total_tokens: int
    no_signal_streak_to_converge: int
    policy_rejected_streak_to_stop: int
    # NOTE (spec §6.1): `require_catalog_floor_green` was REMOVED. Catalog
    # floor is the Assessment's gate (CoverageService), NOT a loop termination
    # condition. The loop runs ON TOP of the floor; termination is decided by
    # budget / no-signal / policy-rejection / emergency only. Floor progress is
    # surfaced to the LLM via LoopContext.catalog_* as informational input.
    require_min_confirmed: int

    @classmethod
    def default(cls) -> LoopTerminationPolicy:
        return cls(
            max_steps=50,
            max_wall_clock_seconds=1800,
            max_total_tokens=200_000,
            no_signal_streak_to_converge=5,
            policy_rejected_streak_to_stop=3,
            require_min_confirmed=0,
        )


@dataclass(frozen=True, slots=True)
class LoopPlan:
    """The plan a ReasoningLoop follows — its termination policy + audit anchor."""

    plan_id: str
    loop_id: LoopId
    assessment_id: str
    termination_policy: LoopTerminationPolicy
    policy_snapshot: str
    created_at: datetime
