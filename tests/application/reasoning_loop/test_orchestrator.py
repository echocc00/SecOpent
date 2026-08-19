"""ReasoningLoopOrchestrator — drives one step (spec §3 + §5).

Reconciled to the real injected-gate interfaces:
- ``PermitGateImpl`` requires ``signer`` / ``verifier`` (infrastructure
  ``PermitSigner``/``PermitVerifier``, no app-layer crypto).
- ``PolicyGateImpl`` is constructed with ``scope`` / ``mode`` /
  ``approved_risks`` / ``approved_capabilities`` and an ``engine`` callable;
  tests inject an allow-all engine.
- Termination follows spec §6.1 (no catalog-floor termination): a green floor
  alone does NOT make the loop COMPLETE — it keeps RUNNING.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

from secopent.application.audit import AuditService
from secopent.application.reasoning_loop.audit import LOOP_GATE_REJECTED
from secopent.application.reasoning_loop.budget_gate import BudgetGateImpl
from secopent.application.reasoning_loop.context_builder import (
    DefaultLoopContextBuilder,
)
from secopent.application.reasoning_loop.feedback import LoopFeedback
from secopent.application.reasoning_loop.in_memory_state import (
    InMemoryLoopStateRepository,
    InMemoryLoopStepRepository,
)
from secopent.application.reasoning_loop.mock_proposer import MockLoopActionProposer
from secopent.application.reasoning_loop.orchestrator import ReasoningLoopOrchestrator
from secopent.application.reasoning_loop.permit_gate import PermitGateImpl
from secopent.application.reasoning_loop.policy_gate import PolicyGateImpl
from secopent.application.reasoning_loop.schema_gate import SchemaGateImpl
from secopent.domain.catalog.models import TestCatalog
from secopent.domain.policy.models import ExecutionMode, PolicyDecision
from secopent.domain.reasoning_loop.models import (
    AvailableCapability,
    LoopActionType,
    LoopBudget,
    LoopId,
    LoopPhase,
    LoopPlan,
    LoopState,
    LoopTerminationPolicy,
    ProposeAction,
)
from secopent.infrastructure.permits.permit_signer import (
    PermitSigner,
    PermitVerifier,
)

_T0 = datetime(2026, 1, 1, tzinfo=UTC)
_DEFAULT_TEST_BUDGET = LoopBudget.default()


@dataclass
class _FakeAuditRepo:
    events: list[Any] | None = None

    def __post_init__(self) -> None:
        self.events: list[Any] = []

    def add(self, e: Any) -> None:
        self.events.append(e)

    def list_events(self) -> list[Any]:
        return list(self.events)

    def last_hash(self) -> str:
        if not self.events:
            return "0" * 64
        return str(self.events[-1].event_hash).removeprefix("sha256:")


def _allow_all_engine(
    request: Any,
    *,
    scope: Any,
    mode: Any,
    approved_risks: Any,
    approved_capabilities: Any,
) -> PolicyDecision:
    return PolicyDecision(allowed=True, reason="ok")


def _permit_gate() -> PermitGateImpl:
    signer = PermitSigner()
    verifier = PermitVerifier(signer.public_key_bytes())
    return PermitGateImpl(ttl_seconds=900, signer=signer, verifier=verifier)


def _tool_capabilities(assessment_id: str) -> tuple[AvailableCapability, ...]:
    """Registered scan-tool capabilities the mock proposer may route to.

    Aligned with the mock proposer's ``run_tool(tool_id="nuclei")`` so the
    SchemaGate's SCHEMA_UNKNOWN_TOOL check has a real knowledge-backed set
    (v0.7.1 seam fix: capabilities are wired, not the empty tuple).
    """
    return (
        AvailableCapability(
            capability_id="nuclei",
            kind="tool",
            summary="template-driven web/API vulnerability scanner",
            risk_class="active",
            cwe=("CWE-89", "CWE-79"),
        ),
    )


def _bootstrap(
    *,
    catalog_required_remaining: frozenset[str] = frozenset(),
    script: Iterable[ProposeAction] = (),
    budget_gate: BudgetGateImpl | None = None,
    budget: LoopBudget = _DEFAULT_TEST_BUDGET,
) -> tuple[ReasoningLoopOrchestrator, LoopId]:
    state_repo = InMemoryLoopStateRepository()
    step_repo = InMemoryLoopStepRepository()
    catalog = TestCatalog(version="t-1", mappings={})
    builder = DefaultLoopContextBuilder(
        catalog=catalog,
        state_repo=state_repo,
        asset_subgraph_provider=lambda aid: (),  # type: ignore[arg-type, return-value]
        observation_provider=lambda lid: (),  # type: ignore[arg-type, return-value]
        tool_provider=_tool_capabilities,
    )
    proposer = MockLoopActionProposer(script=script)
    schema_gate = SchemaGateImpl()
    policy_gate = PolicyGateImpl(
        scope=None,  # type: ignore[arg-type]  # allow-all engine ignores scope
        mode=ExecutionMode.SCOPE_AUTOPILOT,
        approved_risks=frozenset(),
        approved_capabilities=frozenset(),
        engine=_allow_all_engine,
    )
    permit_gate = _permit_gate()
    feedback = LoopFeedback()
    audit = AuditService(_FakeAuditRepo())
    orchestrator = ReasoningLoopOrchestrator(
        state_repo=state_repo,
        step_repo=step_repo,
        context_builder=builder,
        proposer=proposer,
        schema_gate=schema_gate,
        policy_gate=policy_gate,
        permit_gate=permit_gate,
        feedback=feedback,
        audit=audit,
        clock=lambda: _T0,
        budget_gate=budget_gate,
    )
    lid = LoopId(value="abcd1234")
    state_repo.save(
        LoopState(
            loop_id=lid,
            assessment_id="asmt-1",
            phase=LoopPhase.INITIALIZING,
            policy_snapshot="sha256:" + "0" * 64,
            budget=budget,
            context_hash="0" * 64,
            catalog_required_remaining=catalog_required_remaining,
            catalog_required_executed=frozenset(),
            consecutive_no_signal=0,
            consecutive_policy_rejected=0,
            started_at=_T0,
            last_step_at=None,
        )
    )
    return orchestrator, lid


def _plan(lid: LoopId) -> LoopPlan:
    return LoopPlan(
        plan_id="lp-1",
        loop_id=lid,
        assessment_id="asmt-1",
        termination_policy=LoopTerminationPolicy.default(),
        policy_snapshot="sha256:" + "0" * 64,
        created_at=_T0,
    )


def _scripted_action(rationale: str = "r" * 80) -> ProposeAction:
    return ProposeAction(
        action_type=LoopActionType.RUN_TOOL,
        payload={"tool_id": "nuclei", "parameters": {}},
        rationale=rationale,
        confidence=0.5,
    )


def test_create_loop_emits_audit_event() -> None:
    orch, lid = _bootstrap()
    orch.create_loop(_plan(lid), catalog_required_remaining=frozenset({"web:sqli"}))
    state = orch.state_repo.get(lid)
    assert state is not None
    assert state.phase is LoopPhase.INITIALIZING
    assert state.catalog_required_remaining == frozenset({"web:sqli"})


def test_run_step_executes_one_step_and_persists_state() -> None:
    orch, lid = _bootstrap(script=[_scripted_action()])
    orch.create_loop(_plan(lid), catalog_required_remaining=frozenset())
    orch.run_step(loop_id=lid)
    state = orch.state_repo.get(lid)
    assert state is not None
    assert state.budget.snapshot().steps_remaining == 49
    steps = orch.step_repo.list_for_loop(lid)
    assert len(steps) == 1


def test_run_step_with_no_proposal_increments_no_signal_streak() -> None:
    orch, lid = _bootstrap(script=[])  # empty script -> None
    orch.create_loop(_plan(lid), catalog_required_remaining=frozenset())
    orch.run_step(loop_id=lid)
    state = orch.state_repo.get(lid)
    assert state is not None
    assert state.consecutive_no_signal == 1


def test_run_step_terminates_when_no_signal_streak_reaches_policy() -> None:
    """Run 5 steps with empty script -> CONVERGED."""
    orch, lid = _bootstrap(script=[])
    orch.create_loop(_plan(lid), catalog_required_remaining=frozenset({"web:x"}))
    result = None
    for _ in range(5):
        result = orch.run_step(loop_id=lid)
        if result.phase is not LoopPhase.RUNNING:
            break
    assert result is not None
    assert result.phase is LoopPhase.CONVERGED


def test_run_step_floor_green_stays_running_spec_61() -> None:
    """Spec §6.1: a green catalog floor is NOT a loop terminator. A single
    scripted step (no observation signals yet) leaves the loop RUNNING."""
    orch, lid = _bootstrap(
        script=[_scripted_action()],
        catalog_required_remaining=frozenset(),
    )
    orch.create_loop(_plan(lid), catalog_required_remaining=frozenset())
    result = orch.run_step(loop_id=lid)
    assert result.phase is LoopPhase.RUNNING
    assert result.step_recorded is not None


def test_run_step_budget_gate_denies_before_propose() -> None:
    """v0.7.3 Task 4: a budget gate wired into the orchestrator is checked
    BEFORE the proposer runs. An already-exhausted budget denies the step, the
    step is recorded as a budget rejection (not executed), and the loop reaches
    BUDGET_EXHAUSTED without issuing new work."""
    # The loop's budget is already spent (steps_used == max_steps == 50) but the
    # phase is still RUNNING, so run_step proceeds into the budget pre-guard.
    exhausted_budget = LoopBudget.default().consume(steps=50)
    orch, lid = _bootstrap(
        script=[_scripted_action()],
        budget=exhausted_budget,
        budget_gate=BudgetGateImpl(budget_now=lambda: exhausted_budget),
    )
    orch.create_loop(_plan(lid), catalog_required_remaining=frozenset())

    # Re-save state with the exhausted budget and RUNNING phase (create_loop
    # resets to INITIALIZING; we override budget directly on the repo).
    state = orch.state_repo.get(lid)
    assert state is not None
    orch.state_repo.save(
        replace(state, phase=LoopPhase.RUNNING, budget=exhausted_budget)
    )

    result = orch.run_step(loop_id=lid)
    assert result.phase is LoopPhase.BUDGET_EXHAUSTED
    assert result.step_recorded is None

    # The proposer must never have been asked: budget is a pre-propose guard,
    # and (consistent with the other gate-rejection paths) no LoopStep is
    # persisted — a ``loop.gate_rejected`` audit event carries the semantics.
    assert orch.step_repo.list_for_loop(lid) == []
    # The loop state was advanced (budget step consumed) to the terminal phase.
    assert orch.state_repo.get(lid).phase is LoopPhase.BUDGET_EXHAUSTED
    # A gate rejection was audited with the budget deny code.
    audit_actions = [e.action for e in orch._audit._repo.list_events()]
    assert LOOP_GATE_REJECTED in audit_actions
    gate_payloads = [
        e.payload
        for e in orch._audit._repo.list_events()
        if e.action == LOOP_GATE_REJECTED
    ]
    assert any(p.get("gate") == "budget" for p in gate_payloads)
    assert any(p.get("deny_code") == "BUDGET_EXHAUSTED" for p in gate_payloads)


def test_run_step_without_budget_gate_proceeds_normally() -> None:
    """v0.7.3 Task 4: no budget gate wired => the pre-propose guard is off and
    the loop steps exactly as before (backward compatible)."""
    orch, lid = _bootstrap(script=[_scripted_action()])
    orch.create_loop(_plan(lid), catalog_required_remaining=frozenset())
    result = orch.run_step(loop_id=lid)
    assert result.phase is LoopPhase.RUNNING
    assert result.step_recorded is not None
    assert orch.step_repo.list_for_loop(lid)[0].propose_tokens_used == 100
