"""End-to-end vertical slice: create loop -> drive steps -> verify phase + audit.

Reconciled to spec §6.1: a green catalog floor does NOT terminate the loop.
The first scripted step (a mock execute with no observation signals) leaves a
green-floor loop RUNNING — it does not jump to COMPLETED. The e2e test asserts
the audit ordering (created < step_executed < terminated) on a loop that DOES
converge after its no-signal streak is reached.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from secopent.application.audit import AuditService
from secopent.application.reasoning_loop.audit import (
    LOOP_CREATED,
    LOOP_STEP_EXECUTED,
    LOOP_TERMINATED,
)
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
    LoopActionType,
    LoopId,
    LoopPhase,
    LoopPlan,
    LoopTerminationPolicy,
    ProposeAction,
)
from secopent.infrastructure.permits.permit_signer import (
    PermitSigner,
    PermitVerifier,
)

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


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


def _action(rationale: str = "rationale " * 12) -> ProposeAction:
    return ProposeAction(
        action_type=LoopActionType.RUN_TOOL,
        payload={"tool_id": "nuclei", "parameters": {}},
        rationale=rationale,
        confidence=0.5,
    )


def _make_orchestrator(
    script: list[ProposeAction],
) -> tuple[ReasoningLoopOrchestrator, _FakeAuditRepo]:
    catalog = TestCatalog(version="t-1", mappings={})
    state_repo = InMemoryLoopStateRepository()
    step_repo = InMemoryLoopStepRepository()
    builder = DefaultLoopContextBuilder(
        catalog=catalog,
        state_repo=state_repo,
        asset_subgraph_provider=lambda aid: (),  # type: ignore[arg-type, return-value]
        observation_provider=lambda lid: (),  # type: ignore[arg-type, return-value]
    )
    proposer = MockLoopActionProposer(script=script)
    signer = PermitSigner()
    verifier = PermitVerifier(signer.public_key_bytes())
    audit_repo = _FakeAuditRepo()
    audit = AuditService(audit_repo)
    orchestrator = ReasoningLoopOrchestrator(
        state_repo=state_repo,
        step_repo=step_repo,
        context_builder=builder,
        proposer=proposer,
        schema_gate=SchemaGateImpl(),
        policy_gate=PolicyGateImpl(
            scope=None,  # type: ignore[arg-type]  # allow-all engine ignores scope
            mode=ExecutionMode.SCOPE_AUTOPILOT,
            approved_risks=frozenset(),
            approved_capabilities=frozenset(),
            engine=_allow_all_engine,
        ),
        permit_gate=PermitGateImpl(
            ttl_seconds=900, signer=signer, verifier=verifier
        ),
        feedback=LoopFeedback(),
        audit=audit,
        clock=lambda: _T0,
    )
    return orchestrator, audit_repo


def test_e2e_create_run_terminate_records_audit_chain() -> None:
    """Drive executed steps to CONVERGENCE and assert created < step_executed < terminated.

    Uses a 5-action script: each scripted action passes the three gates and is
    mock-executed (no observation signals), so the no-signal streak climbs to
    the policy's converge threshold (5) -> CONVERGED.
    """
    orchestrator, audit_repo = _make_orchestrator(
        script=[_action() for _ in range(5)]
    )

    lid = LoopId(value="abcd1234")
    plan = LoopPlan(
        plan_id="lp-1", loop_id=lid, assessment_id="asmt-1",
        termination_policy=LoopTerminationPolicy.default(),
        policy_snapshot="sha256:" + "0" * 64,
        created_at=_T0,
    )
    state = orchestrator.create_loop(
        plan, catalog_required_remaining=frozenset({"web:x"})
    )
    assert state.phase is LoopPhase.INITIALIZING

    # Drive until the loop escapes RUNNING (mock steps are signal-free -> CONVERGED).
    final_phase = None
    for _ in range(10):
        result = orchestrator.run_step(loop_id=lid)
        final_phase = result.phase
        if result.phase is not LoopPhase.RUNNING:
            break
    assert final_phase is LoopPhase.CONVERGED

    # Audit chain must record loop.created + loop.step_executed + loop.terminated.
    actions = [e.action for e in audit_repo.list_events()]
    assert LOOP_CREATED in actions
    assert LOOP_STEP_EXECUTED in actions
    assert LOOP_TERMINATED in actions
    # Order matters: created before step_executed before terminated.
    assert actions.index(LOOP_CREATED) < actions.index(LOOP_STEP_EXECUTED)
    assert actions.index(LOOP_STEP_EXECUTED) < actions.index(LOOP_TERMINATED)


def test_e2e_green_floor_does_not_terminate_spec_61() -> None:
    """Spec §6.1: a single scripted step on a green floor leaves the loop RUNNING."""
    orchestrator, _ = _make_orchestrator(script=[_action()])

    lid = LoopId(value="abcd1234")
    plan = LoopPlan(
        plan_id="lp-1", loop_id=lid, assessment_id="asmt-1",
        termination_policy=LoopTerminationPolicy.default(),
        policy_snapshot="sha256:" + "0" * 64,
        created_at=_T0,
    )
    orchestrator.create_loop(plan, catalog_required_remaining=frozenset())
    result = orchestrator.run_step(loop_id=lid)
    assert result.phase is LoopPhase.RUNNING
    assert result.step_recorded is not None
    # The step went through all three gates and was recorded as executed.
    assert result.signals_count == 0  # mock execute produces no observation signals
