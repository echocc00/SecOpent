"""Audit-event action vocabulary for ReasoningLoop (spec §12.3)."""
from __future__ import annotations

# Resource type
LOOP_RESOURCE_TYPE = "reasoning_loop"

# Actions emitted by ReasoningLoopOrchestrator (NOT free-form — extend here)
LOOP_CREATED = "loop.created"
LOOP_STEP_PROPOSED = "loop.step_proposed"
LOOP_GATE_REJECTED = "loop.gate_rejected"
LOOP_STEP_EXECUTED = "loop.step_executed"
LOOP_TERMINATED = "loop.terminated"
LOOP_FALLBACK_USED = "loop.fallback_used"
LOOP_BACKEND_UNAVAILABLE = "loop.backend_unavailable"

ALL_LOOP_ACTIONS: tuple[str, ...] = (
    LOOP_CREATED,
    LOOP_STEP_PROPOSED,
    LOOP_GATE_REJECTED,
    LOOP_STEP_EXECUTED,
    LOOP_TERMINATED,
    LOOP_FALLBACK_USED,
    LOOP_BACKEND_UNAVAILABLE,
)
