# tests/application/reasoning_loop/test_orchestrator_pause.py
"""Milestone v0.7.7 closer — orchestrator-level pause/resume invariants.

Covers the closed loop that Tasks 3-5 established at the service level but
did NOT yet guarantee through the *orchestrator*:

1. EmergencyStop takes priority over PAUSED: a loop that is PAUSED, when
   emergency-stopped, lands in the terminal EMERGENCY_STOPPED phase — it must
   not stay PAUSED (a paused loop is still a *live* loop and must be killable).
2. resume is rejected after EMERGENCY_STOPPED (the loop is dead).
3. an over-budget pause (pause_attempts reaches max_pauses) forces a terminal
   transition via ``loop.terminated`` with reason="pause_budget" — the
   orchestrator translates PauseBudgetExceeded into a terminal phase rather
   than leaking the domain exception.
4. the audit vocabulary is complete: loop.paused / loop.resumed / loop.terminated
   are all in ALL_LOOP_ACTIONS.

These are end-to-end-style: they drive the orchestrator (with a real
PauseControlService sharing the same state repo) the way the API/CLI/MCP
composition root would.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest

from secopent.application.audit import AuditService
from secopent.application.reasoning_loop.audit import (
    ALL_LOOP_ACTIONS,
    LOOP_PAUSED,
    LOOP_RESUMED,
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
from secopent.application.reasoning_loop.pause_control import PauseControlService
from secopent.application.reasoning_loop.permit_gate import PermitGateImpl
from secopent.application.reasoning_loop.policy_gate import PolicyGateImpl
from secopent.application.reasoning_loop.schema_gate import SchemaGateImpl
from secopent.domain.catalog.models import TestCatalog
from secopent.domain.common.errors import DomainError
from secopent.domain.policy.models import ExecutionMode, PolicyDecision
from secopent.domain.reasoning_loop.models import (
    AvailableCapability,
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

_T0 = datetime(2026, 8, 19, 12, 0, 0, tzinfo=UTC)


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


class _FakeLoopApproval:
    """Human-signed approval port: accepts any non-empty approved_by/signature."""

    def require_resume_approval(
        self,
        *,
        loop_id: object,
        actor: str,
        actor_role: str,
        approved_by: str | None = None,
        signature: str | None = None,
        nonce: str | None = None,
        expires_at: object | None = None,
    ) -> None:
        if actor_role == "agent":
            raise DomainError("agents are rejected")
        if not approved_by or not signature:
            raise DomainError("human approval requires approved_by + signature")


def _allow_all_engine(
    request: Any,
    *,
    scope: Any,
    mode: Any,
    approved_risks: Any,
    approved_capabilities: Any,
) -> PolicyDecision:
    return PolicyDecision(allowed=True, reason="ok")


def _tool_capabilities(assessment_id: str) -> tuple[AvailableCapability, ...]:
    return (
        AvailableCapability(
            capability_id="nuclei",
            kind="tool",
            summary="template-driven web/API vulnerability scanner",
            risk_class="active",
            cwe=("CWE-89", "CWE-79"),
        ),
    )


def _make_orchestrator(
    *,
    script: Iterable[ProposeAction] = (),
    policy: LoopTerminationPolicy | None = None,
) -> tuple[ReasoningLoopOrchestrator, PauseControlService, LoopId, _FakeAuditRepo]:
    """Compose an orchestrator + PauseControlService over ONE shared state repo.

    This mirrors the composition root (app.state.loop_control shares the state
    repo with the orchestrator) so pause/resume transitions are visible to both.
    """
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
    signer = PermitSigner()
    verifier = PermitVerifier(signer.public_key_bytes())
    audit_repo = _FakeAuditRepo()
    audit = AuditService(audit_repo)
    policy = policy or LoopTerminationPolicy.default()
    control = PauseControlService(
        state_repo=state_repo,
        audit=audit,
        approval=_FakeLoopApproval(),
        policy=policy,
        now_fn=lambda: _T0,
    )
    orchestrator = ReasoningLoopOrchestrator(
        state_repo=state_repo,
        step_repo=step_repo,
        context_builder=builder,
        proposer=MockLoopActionProposer(script=list(script)),
        schema_gate=SchemaGateImpl(),
        policy_gate=PolicyGateImpl(
            scope=None,  # type: ignore[arg-type]  # allow-all engine ignores scope
            mode=ExecutionMode.SCOPE_AUTOPILOT,
            approved_risks=frozenset(),
            approved_capabilities=frozenset(),
            engine=_allow_all_engine,
        ),
        permit_gate=PermitGateImpl(ttl_seconds=900, signer=signer, verifier=verifier),
        feedback=LoopFeedback(),
        audit=audit,
        clock=lambda: _T0,
        pause_control=control,
    )
    lid = LoopId(value="abcd1234")
    return orchestrator, control, lid, audit_repo


def _plan(
    lid: LoopId,
    *,
    policy: LoopTerminationPolicy | None = None,
) -> LoopPlan:
    return LoopPlan(
        plan_id="lp-1",
        loop_id=lid,
        assessment_id="asmt-1",
        termination_policy=policy or LoopTerminationPolicy.default(),
        policy_snapshot="sha256:" + "0" * 64,
        created_at=_T0,
    )


def _paused_state(lid: LoopId, *, pause_attempts: int = 0) -> LoopState:
    return LoopState(
        loop_id=lid,
        assessment_id="asmt-1",
        phase=LoopPhase.PAUSED,
        policy_snapshot="sha256:" + "0" * 64,
        budget=LoopBudget.default(),
        context_hash="0" * 64,
        catalog_required_remaining=frozenset(),
        catalog_required_executed=frozenset(),
        consecutive_no_signal=0,
        consecutive_policy_rejected=0,
        started_at=_T0,
        last_step_at=None,
        pause_attempts=pause_attempts,
        paused_at=_T0,
    )


# ---------------------------------------------------------------------------
# 6.1 EmergencyStop priority over PAUSED
# ---------------------------------------------------------------------------
def test_emergency_stop_overrides_paused_loop() -> None:
    """A PAUSED loop, when emergency-stopped, ends terminal EMERGENCY_STOPPED.

    The orchestrator must offer a kill entry point that works even while the
    loop is paused (run_step no-ops on PAUSED, so the emergency stop cannot
    ride on run_step). EmergencyStop takes priority over PAUSED.
    """
    orch, _control, lid, _audit_repo = _make_orchestrator()
    orch.state_repo.save(_paused_state(lid))

    result = orch.emergency_stop(lid, actor="alice", reason="compromise")

    assert result.phase is LoopPhase.EMERGENCY_STOPPED
    # The paused loop must NOT remain PAUSED — it is now terminal and dead.
    persisted = orch.state_repo.get(lid)
    assert persisted is not None
    assert persisted.phase is LoopPhase.EMERGENCY_STOPPED


def test_emergency_stop_then_resume_rejected() -> None:
    """After EMERGENCY_STOPPED, resume is rejected (the loop is dead)."""
    orch, _control, lid, _audit_repo = _make_orchestrator()
    orch.state_repo.save(_paused_state(lid))
    orch.emergency_stop(lid, actor="alice", reason="compromise")

    with pytest.raises(DomainError):
        orch.resume_loop(
            loop_id=lid,
            actor="bob",
            approved_by="bob",
            signature="sig-1",
        )


def test_emergency_stop_records_loop_terminated_audit() -> None:
    """Emergency-stop lands a deterministic loop.terminated audit event."""
    orch, _control, lid, audit_repo = _make_orchestrator()
    orch.state_repo.save(_paused_state(lid))

    orch.emergency_stop(lid, actor="alice", reason="compromise")

    terminated = [
        e for e in audit_repo.list_events() if getattr(e, "action", None) == LOOP_TERMINATED
    ]
    assert terminated, "expected a loop.terminated event"
    payload = terminated[-1].payload
    assert payload["final_phase"] == LoopPhase.EMERGENCY_STOPPED.value
    assert payload["reason"] == "emergency_stop"


def test_run_step_on_emergency_stopped_is_rejected() -> None:
    """An EMERGENCY_STOPPED loop refuses further run_step (terminal)."""
    from secopent.application.reasoning_loop.orchestrator import (
        LoopAlreadyTerminalError,
    )

    orch, _control, lid, _audit_repo = _make_orchestrator()
    orch.state_repo.save(_paused_state(lid))
    orch.emergency_stop(lid, actor="alice", reason="compromise")

    with pytest.raises(LoopAlreadyTerminalError):
        orch.run_step(loop_id=lid)


# ---------------------------------------------------------------------------
# 6.1 over-budget pause forces a terminal transition
# ---------------------------------------------------------------------------
def _max_pauses_3_policy() -> LoopTerminationPolicy:
    return LoopTerminationPolicy(
        max_steps=50,
        max_wall_clock_seconds=1800,
        max_total_tokens=200_000,
        no_signal_streak_to_converge=5,
        policy_rejected_streak_to_stop=3,
        require_min_confirmed=0,
        max_pauses=3,
    )


@pytest.mark.parametrize(
    "pause_attempts",
    [3, 4],
)
def test_over_budget_pause_resume_forces_terminal_transition(
    pause_attempts: int,
) -> None:
    """When pause_attempts already meets/exceeds max_pauses, resume_loop forces
    the loop into a terminal phase and records loop.terminated(reason=pause_budget)
    instead of leaking PauseBudgetExceeded to the caller.
    """
    orch, _control, lid, audit_repo = _make_orchestrator(
        policy=_max_pauses_3_policy()
    )
    orch.state_repo.save(_paused_state(lid, pause_attempts=pause_attempts))

    result = orch.resume_loop(
        loop_id=lid,
        actor="bob",
        approved_by="bob",
        signature="sig-1",
    )

    # The loop is forced terminal (not left PAUSED, not RESUMED).
    assert result.phase in {
        LoopPhase.COMPLETED,
        LoopPhase.BUDGET_EXHAUSTED,
        LoopPhase.POLICY_BLOCKED,
        LoopPhase.CONVERGED,
        LoopPhase.EMERGENCY_STOPPED,
    }
    persisted = orch.state_repo.get(lid)
    assert persisted is not None
    assert persisted.phase is result.phase

    terminated = [
        e for e in audit_repo.list_events() if getattr(e, "action", None) == LOOP_TERMINATED
    ]
    assert terminated, "expected a loop.terminated event for the forced termination"
    assert terminated[-1].payload.get("reason") == "pause_budget"


def test_over_budget_pause_leaves_loop_terminal_for_resume() -> None:
    """After a forced pause-budget termination, a later resume is rejected."""
    orch, _control, lid, _audit_repo = _make_orchestrator(
        policy=_max_pauses_3_policy()
    )
    orch.state_repo.save(_paused_state(lid, pause_attempts=3))

    orch.resume_loop(loop_id=lid, actor="bob", approved_by="bob", signature="sig-1")

    with pytest.raises(DomainError):
        orch.resume_loop(loop_id=lid, actor="bob", approved_by="bob", signature="sig-2")


# ---------------------------------------------------------------------------
# 6.1 audit vocabulary is complete
# ---------------------------------------------------------------------------
def test_audit_action_vocabulary_is_complete() -> None:
    """loop.paused / loop.resumed / loop.terminated are all in ALL_LOOP_ACTIONS."""
    assert LOOP_PAUSED in ALL_LOOP_ACTIONS
    assert LOOP_RESUMED in ALL_LOOP_ACTIONS
    assert LOOP_TERMINATED in ALL_LOOP_ACTIONS


# ---------------------------------------------------------------------------
# 6.1 happy path through the orchestrator wiring still works
# ---------------------------------------------------------------------------
def test_resume_via_orchestrator_wiring_records_resumed_audit() -> None:
    """A normal (under-budget) resume via the orchestrator reaches RESUMED and
    records loop.resumed — proving the orchestrator path drives the service."""
    orch, _control, lid, audit_repo = _make_orchestrator()
    orch.state_repo.save(_paused_state(lid, pause_attempts=1))

    result = orch.resume_loop(
        loop_id=lid,
        actor="bob",
        approved_by="bob",
        signature="sig-1",
    )

    assert result.phase is LoopPhase.RESUMED
    assert result.pause_attempts == 2
    actions = [getattr(e, "action", None) for e in audit_repo.list_events()]
    assert LOOP_RESUMED in actions


def test_pause_via_wiring_records_paused_audit() -> None:
    """PauseControlService.pause records loop.paused (wired through the control
    service used by the orchestrator composition)."""
    orch, control, lid, audit_repo = _make_orchestrator()
    orch.create_loop(_plan(lid), catalog_required_remaining=frozenset())

    control.pause(loop_id=lid, actor="alice", reason="review")

    actions = [getattr(e, "action", None) for e in audit_repo.list_events()]
    assert LOOP_PAUSED in actions
