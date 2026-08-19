# src/secopent/application/reasoning_loop/degradation.py
"""DegradationPolicy — real→mock→catalog fallback chain, all audited (spec §10).

The loop's proposer depends on an LLM backend; when that backend fails the
policy decides, from a failure streak + backend availability, how the loop may
continue:

- ``PROPOSE_AGAIN``: backend healthy, keep proposing (session-level transient
  resume, streak < 3).
- ``POLICY_BLOCKED``: three consecutive schema failures — stop the real
  proposer; write a ``loop.fallback_used`` audit event.
- ``USE_MOCK``: backend unavailable (no key / down) — degrade immediately to a
  Mock proposer; audited.
- ``CATALOG_ONLY``: nothing left to propose but the catalog floor — the loop
  terminates; the Assessment gate (CoverageService) enforces the gate, so a
  catalog-only degradation never fabricates a message.

Every degraded transition MUST be audited via ``record_fallback`` (nothing is
silent). ``record_fallback`` emits the same ``loop.fallback_used`` action the
v0.7.1 composition already uses for proposer-level mock fallback, keeping one
event vocabulary (spec §12.3).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ...application.ports.audit import AuditRecorder
from ..reasoning_loop.audit import LOOP_FALLBACK_USED, LOOP_RESOURCE_TYPE

# Consecutive schema failures before the real proposer is stopped.
FALLBACK_STREAK_THRESHOLD = 3


class BackendState(Enum):
    """Availability of the real LLM backend, from the loop's perspective."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"     # no key / unreachable — mock fallback now
    CATALOG_ONLY = "catalog_only"   # only the catalog floor remains — terminate


class DegradeAction(Enum):
    """The policy's decision after evaluating a failure streak + backend state."""

    PROPOSE_AGAIN = "propose_again"
    USE_MOCK = "use_mock"
    POLICY_BLOCKED = "policy_blocked"
    CATALOG_ONLY = "catalog_only"

    @property
    def is_terminal(self) -> bool:
        return self in (DegradeAction.POLICY_BLOCKED, DegradeAction.CATALOG_ONLY)


@dataclass(frozen=True)
class DegradationPolicy:
    """Pure decision table mapping (streak, backend) -> DegradeAction.

    Stateless and side-effect free: it only *decides*. The caller is
    responsible for acting on the decision AND for calling ``record_fallback``
    on every non-``PROPOSE_AGAIN`` transition so the move is audited.
    """

    streak_threshold: int = FALLBACK_STREAK_THRESHOLD

    def evaluate(
        self,
        *,
        failure_streak: int,
        backend_state: BackendState,
    ) -> DegradeAction:
        """Return the degradation decision for the current loop conditions."""
        if backend_state is BackendState.UNAVAILABLE:
            # Backend down wins over everything: fall back to Mock immediately.
            return DegradeAction.USE_MOCK
        if backend_state is BackendState.CATALOG_ONLY:
            # Nothing left to propose — terminate (gate enforced upstream).
            return DegradeAction.CATALOG_ONLY
        if failure_streak >= self.streak_threshold:
            # Repeated schema failure: stop the real proposer (audited).
            return DegradeAction.POLICY_BLOCKED
        return DegradeAction.PROPOSE_AGAIN

    def record_fallback(
        self,
        audit: AuditRecorder,
        *,
        reason: str,
        degraded_to: DegradeAction,
        resource_id: str = "proposer",
        actor: str = "reasoning_loop",
    ) -> None:
        """Audit a degradation transition (never silent, spec §10).

        Emits the shared ``loop.fallback_used`` event with the reason and the
        degraded-to action so the trace is tamper-evident and inspectable.
        """
        audit.record(
            actor=actor,
            action=LOOP_FALLBACK_USED,
            resource_type=LOOP_RESOURCE_TYPE,
            resource_id=resource_id,
            payload={
                "reason": reason,
                "degraded_to": degraded_to.value,
            },
        )