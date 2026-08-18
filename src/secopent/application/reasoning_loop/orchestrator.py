"""ReasoningLoopOrchestrator — drives the loop one step at a time (spec §3 + §5).

v0.7.0 tracer bullet: the 'execute step' stage is a MOCK recorder (no real
tool/container call); v0.7.2 wires this to JobService + SubprocessExecutor.

The orchestrator composes existing services via injected ports:
- build a ``LoopContext`` for the loop (``LoopContextBuilder``)
- ask the ``LoopActionProposer`` for the next action
- run the three gates (Schema / Policy / Permit)
- MOCK-execute the step (record only)
- apply ``LoopFeedback`` to produce the next ``LoopState``
- call ``evaluate_termination`` and persist the new state

Domain/application layers stay framework-free; concrete repos / permit
signing are injected at the composition root.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from ...domain.common.canonical import canonical_json
from ...domain.common.errors import DomainError
from ...domain.reasoning_loop.models import (
    LoopActionType,
    LoopBudget,
    LoopContext,
    LoopId,
    LoopPhase,
    LoopPlan,
    LoopState,
    LoopStep,
    LoopTerminationPolicy,
    PolicyDecision,
    ProposeAction,
)
from ...domain.reasoning_loop.policies import evaluate_termination
from ..ports.audit import AuditRecorder
from ..ports.loop_context import LoopContextBuilder
from ..ports.loop_gates import PermitGate, PolicyGate, SchemaGate
from ..ports.loop_proposer import LoopActionProposer
from ..ports.loop_state import LoopStateRepository
from ..ports.loop_step import LoopStepRepository
from .audit import (
    LOOP_BACKEND_UNAVAILABLE,
    LOOP_CREATED,
    LOOP_GATE_REJECTED,
    LOOP_STEP_EXECUTED,
    LOOP_STEP_PROPOSED,
    LOOP_TERMINATED,
)
from .feedback import LoopFeedback


class LoopNotFoundError(DomainError):
    """The requested loop_id has no persisted state."""


class LoopAlreadyTerminalError(DomainError):
    """run_step was called on a loop that already reached a terminal phase."""


_TERMINAL_PHASES = frozenset({
    LoopPhase.COMPLETED,
    LoopPhase.BUDGET_EXHAUSTED,
    LoopPhase.POLICY_BLOCKED,
    LoopPhase.CONVERGED,
    LoopPhase.EMERGENCY_STOPPED,
})

# Phases where the loop is NOT auto-stepping but is not terminal:
# - PAUSED: human-paused, waits for explicit resume (spec §6.3; API in v0.7.7)
# - CATALOG_FLOOR_DONE: audit milestone only (spec §6.1) — NOT a terminator; a
#   loop whose floor just turned green keeps running for incremental discovery.
_NON_AUTO_STEP_PHASES = frozenset({
    LoopPhase.PAUSED,
    LoopPhase.CATALOG_FLOOR_DONE,
})

# v0.7.0: each mock-executed step spends a fixed nominal token budget.
_MOCK_STEP_TOKENS = 100


@dataclass(frozen=True, slots=True)
class StepResult:
    """Public result of one orchestrator step."""

    loop_id: LoopId
    phase: LoopPhase
    # None if step was not executed (gate rejected, backend unavailable)
    step_recorded: LoopStep | None
    signals_count: int


class ReasoningLoopOrchestrator:
    """State-machine driver for one ReasoningLoop instance."""

    def __init__(
        self,
        *,
        state_repo: LoopStateRepository,
        step_repo: LoopStepRepository,
        context_builder: LoopContextBuilder,
        proposer: LoopActionProposer,
        schema_gate: SchemaGate,
        policy_gate: PolicyGate,
        permit_gate: PermitGate,
        feedback: LoopFeedback,
        audit: AuditRecorder,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.state_repo = state_repo
        self.step_repo = step_repo
        self.context_builder = context_builder
        self.proposer = proposer
        self.schema_gate = schema_gate
        self.policy_gate = policy_gate
        self.permit_gate = permit_gate
        self.feedback = feedback
        self._audit = audit
        self._clock = clock or (lambda: datetime.now(UTC))

    # ------------------------------------------------------------------ create
    def create_loop(
        self, plan: LoopPlan, *, catalog_required_remaining: frozenset[str]
    ) -> LoopState:
        """Instantiate a loop in INITIALIZING and audit the creation."""
        state = LoopState(
            loop_id=plan.loop_id,
            assessment_id=plan.assessment_id,
            phase=LoopPhase.INITIALIZING,
            policy_snapshot=plan.policy_snapshot,
            budget=LoopBudget.default(),  # v0.7.0: derive from policy
            context_hash="0" * 64,
            catalog_required_remaining=catalog_required_remaining,
            catalog_required_executed=frozenset(),
            consecutive_no_signal=0,
            consecutive_policy_rejected=0,
            started_at=self._clock(),
            last_step_at=None,
        )
        self.state_repo.save(state)
        self._audit.record(
            actor="reasoning_loop",
            action=LOOP_CREATED,
            resource_type="reasoning_loop",
            resource_id=plan.loop_id.value,
            payload={
                "assessment_id": plan.assessment_id,
                "policy_snapshot": plan.policy_snapshot,
                "catalog_required_remaining": sorted(catalog_required_remaining),
            },
        )
        return state

    # ----------------------------------------------------------------- run_step
    def run_step(self, *, loop_id: LoopId) -> StepResult:
        """Advance the loop by one step and return the resulting phase."""
        state = self.state_repo.get(loop_id)
        if state is None:
            raise LoopNotFoundError(f"loop_id {loop_id.value!r} not found")
        if state.phase in _TERMINAL_PHASES:
            raise LoopAlreadyTerminalError(
                f"loop_id {loop_id.value!r} already terminal in phase {state.phase}"
            )
        if state.phase in _NON_AUTO_STEP_PHASES:
            # PAUSED (spec §6.3, full API in v0.7.7) and CATALOG_FLOOR_DONE
            # (audit milestone, spec §6.1) are not terminal but must not
            # auto-step. Return a no-op step result.
            return StepResult(
                loop_id=loop_id, phase=state.phase,
                step_recorded=None, signals_count=0,
            )

        # 1. Build context.
        context = self.context_builder.build(loop_id)

        # 2. Propose.
        proposed = self.proposer.propose(context)
        if proposed is None:
            return self._record_backend_unavailable(loop_id, state, context)

        # 3. Schema gate.
        sv = self.schema_gate.check(proposed, context)
        if not sv.passed:
            return self._record_gate_rejected(
                loop_id, state, context, proposed,
                gate_name="schema", deny_code=sv.deny_code or "SCHEMA_DENIED",
                reason=sv.reason,
            )

        # 4. Policy gate.
        pv = self.policy_gate.check(proposed, context)
        if not pv.passed:
            return self._record_gate_rejected(
                loop_id, state, context, proposed,
                gate_name="policy", deny_code=pv.deny_code or "POLICY_DENIED",
                reason=pv.reason,
            )

        # 5. Permit gate.
        permit_v = self.permit_gate.check(proposed, context)
        if not permit_v.passed:
            return self._record_gate_rejected(
                loop_id, state, context, proposed,
                gate_name="permit", deny_code=permit_v.deny_code or "PERMIT_DENIED",
                reason=permit_v.reason,
            )

        # 6. MOCK execute (v0.7.0 — no real tool/container call).
        step = self._mock_execute(loop_id, context, proposed, permit_v.permit_id or "")
        self.step_repo.add(step)
        self._audit.record(
            actor="reasoning_loop",
            action=LOOP_STEP_PROPOSED,
            resource_type="reasoning_loop",
            resource_id=loop_id.value,
            payload={
                "step_id": step.step_id,
                "action_type": step.proposed_action.action_type.value,
                "permit_id": step.permit_id,
                "tokens_used": step.propose_tokens_used,
            },
        )
        self._audit.record(
            actor="reasoning_loop",
            action=LOOP_STEP_EXECUTED,
            resource_type="reasoning_loop",
            resource_id=loop_id.value,
            payload={
                "step_id": step.step_id,
                "tool_or_case_id": step.tool_or_case_id,
                "result_digest": step.execution_result_digest,
                "signals": list(step.observation_signals),
            },
        )

        # 7. Feedback -> next state.
        new_state = self.feedback.apply(
            current=state,
            step=step,
            policy_decision_passed=True,
            signal_count=len(step.observation_signals),
            now=self._clock(),
        )
        new_phase = evaluate_termination(new_state, LoopTerminationPolicy.default())
        new_state = replace(new_state, phase=new_phase)
        self.state_repo.save(new_state)

        if new_phase in _TERMINAL_PHASES:
            self._audit.record(
                actor="reasoning_loop",
                action=LOOP_TERMINATED,
                resource_type="reasoning_loop",
                resource_id=loop_id.value,
                payload={"final_phase": new_phase.value, "step_id": step.step_id},
            )

        return StepResult(
            loop_id, new_phase, step_recorded=step,
            signals_count=len(step.observation_signals),
        )

    # ------------------------------------------------------------- internal
    def _record_backend_unavailable(
        self, loop_id: LoopId, state: LoopState, context: LoopContext
    ) -> StepResult:
        """Proposer returned None: one transient, budget-consuming no-op step."""
        audit = self._audit
        audit.record(
            actor="reasoning_loop",
            action=LOOP_BACKEND_UNAVAILABLE,
            resource_type="reasoning_loop",
            resource_id=loop_id.value,
            payload={"context_hash": context.context_hash()},
        )
        new_state = self.feedback.apply(
            current=state,
            step=self._placeholder_step(
                loop_id, context, action=None,
                schema_passed=False, policy_passed=True,
                signals=0, tokens=0,
            ),
            # Backend unavailability is a transient 1-step failure, NOT a policy
            # rejection: no LLM punishment (policy streak stays put), but the
            # step counter still advances and the no-signal streak increments.
            policy_decision_passed=True,
            signal_count=0,
            now=self._clock(),
        )
        new_phase = evaluate_termination(new_state, LoopTerminationPolicy.default())
        new_state = replace(new_state, phase=new_phase)
        self.state_repo.save(new_state)
        if new_phase in _TERMINAL_PHASES:
            audit.record(
                actor="reasoning_loop",
                action=LOOP_TERMINATED,
                resource_type="reasoning_loop",
                resource_id=loop_id.value,
                payload={"final_phase": new_phase.value, "via": "backend_unavailable"},
            )
        return StepResult(loop_id, new_phase, step_recorded=None, signals_count=0)

    def _record_gate_rejected(
        self,
        loop_id: LoopId,
        state: LoopState,
        context: LoopContext,
        proposed: ProposeAction,
        *,
        gate_name: str,
        deny_code: str,
        reason: str,
    ) -> StepResult:
        audit = self._audit
        audit.record(
            actor="reasoning_loop",
            action=LOOP_GATE_REJECTED,
            resource_type="reasoning_loop",
            resource_id=loop_id.value,
            payload={
                "gate": gate_name,
                "deny_code": deny_code,
                "reason": reason,
                "action_type": proposed.action_type.value,
            },
        )
        placeholder = self._placeholder_step(
            loop_id, context, action=proposed,
            schema_passed=(gate_name != "schema"),
            policy_passed=(gate_name == "permit"),
            signals=0,
            tokens=0,  # no token spend on rejection
        )
        new_state = self.feedback.apply(
            current=state, step=placeholder,
            policy_decision_passed=(gate_name != "policy"),
            signal_count=0, now=self._clock(),
        )
        new_phase = evaluate_termination(new_state, LoopTerminationPolicy.default())
        new_state = replace(new_state, phase=new_phase)
        self.state_repo.save(new_state)
        if new_phase in _TERMINAL_PHASES:
            audit.record(
                actor="reasoning_loop",
                action=LOOP_TERMINATED,
                resource_type="reasoning_loop",
                resource_id=loop_id.value,
                payload={"final_phase": new_phase.value, "via": "gate_rejected"},
            )
        return StepResult(loop_id, new_phase, step_recorded=None, signals_count=0)

    def _mock_execute(
        self,
        loop_id: LoopId,
        context: LoopContext,
        action: ProposeAction,
        permit_id: str,
    ) -> LoopStep:
        """v0.7.0 mock: produce a no-observation step (catalog_class_matched empty)."""
        result_digest = "sha256:" + hashlib.sha256(
            canonical_json({"mock": True, "loop_id": loop_id.value}).encode("utf-8")
        ).hexdigest()
        return LoopStep(
            step_id=f"step-{secrets.token_hex(4)}",
            loop_id=loop_id,
            step_number=int(uuid.uuid4().int & 0xFFFFFFFF),  # unique per step
            timestamp=self._clock(),
            context_hash_before=context.context_hash(),
            proposed_action=action,
            propose_tokens_used=_MOCK_STEP_TOKENS,
            propose_latency_ms=50,
            propose_rationale=action.rationale,
            schema_check_passed=True,
            policy_decision=PolicyDecision(verdict="allow", reason="ok"),
            permit_id=permit_id,
            tool_or_case_id=action.tool_id or action.payload.get("case_id"),
            execution_result_digest=result_digest,
            evidence_refs=(),
            observation_signals=(),  # mock: no real signal; real impl populates from Observation
            catalog_class_matched=frozenset(),
            oracle_progressed=False,
            correlation_id=f"corr-{secrets.token_hex(4)}",
        )

    def _placeholder_step(
        self,
        loop_id: LoopId,
        context: LoopContext,
        *,
        action: ProposeAction | None,
        schema_passed: bool,
        policy_passed: bool,
        signals: int,
        tokens: int,
    ) -> LoopStep:
        if action is None:
            action = ProposeAction(
                action_type=LoopActionType.ABORT_STEP,
                payload={},
                rationale="(no proposer output)" + " " * 60,
                confidence=0.0,
            )
        return LoopStep(
            step_id=f"step-{secrets.token_hex(4)}",
            loop_id=loop_id,
            step_number=int(uuid.uuid4().int & 0xFFFFFFFF),
            timestamp=self._clock(),
            context_hash_before=context.context_hash(),
            proposed_action=action,
            propose_tokens_used=tokens,
            propose_latency_ms=0,
            propose_rationale=action.rationale,
            schema_check_passed=schema_passed,
            policy_decision=PolicyDecision(
                verdict="allow" if policy_passed else "deny",
                reason="mock",
                deny_code=None if policy_passed else "MOCK_DENIED",
            ),
            permit_id=None,
            tool_or_case_id=None,
            execution_result_digest="",
            evidence_refs=(),
            observation_signals=(),
            catalog_class_matched=frozenset(),
            oracle_progressed=False,
            correlation_id=f"corr-{secrets.token_hex(4)}",
        )
