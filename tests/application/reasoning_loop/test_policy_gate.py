"""PolicyGate — delegates to existing PolicyEngine (spec §6.2).

Reconciled to the real ``domain.policy.engine.evaluate`` signature:
``evaluate(request, *, scope, mode, approved_risks, approved_capabilities)
-> PolicyDecision(allowed, reason)``. There is no ``ScopeDecision`` type in
this codebase; the real decision model has only ``allowed`` + ``reason`` (no
``deny_code``), so the gate maps the denial reason into ``deny_code``.
"""
from __future__ import annotations

from datetime import UTC, datetime

from secopent.application.reasoning_loop.policy_gate import PolicyGateImpl
from secopent.domain.policy.engine import evaluate as engine_evaluate
from secopent.domain.policy.models import ExecutionMode, RiskClass
from secopent.domain.reasoning_loop.models import (
    LoopActionType,
    LoopBudgetSnapshot,
    LoopContext,
    ProposeAction,
)
from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot


def _ctx() -> LoopContext:
    return LoopContext(
        asset_subgraph=(),
        recent_observations=(),
        observation_token_count=0,
        catalog_already_executed=frozenset(),
        catalog_still_required=frozenset(),
        catalog_floor_progress=0.0,
        unconfirmed_candidates=(),
        confirmed_findings_recent=(),
        chain_hypotheses_pending=(),
        available_tools=(),
        available_cases=(),
        available_peers=(),
        budget_remaining=LoopBudgetSnapshot(50, 200_000, 1800),
        loop_step=0,
        max_steps=50,
        elapsed_seconds=0,
    )


def _in_scope() -> ScopeSnapshot:
    return ScopeSnapshot(
        id="scope-1",
        project_id="p-1",
        include=("example.com",),
        exclude=(),
        ports=(80, 443),
        limits=ScopeLimits(requests_per_second=10, concurrency=5, max_requests=1000),
        approved_by="admin",
        approved_at=datetime(2026, 1, 1, tzinfo=UTC),
        digest="sha256:" + "0" * 64,
    )


def _action(*, host: str, risk: str = "low") -> ProposeAction:
    return ProposeAction(
        action_type=LoopActionType.RUN_TOOL,
        payload={
            "tool_id": "nuclei",
            "parameters": {"host": host, "port": 443, "risk": risk},
        },
        rationale="x" * 80,
        confidence=0.5,
    )


def _gate(scope: ScopeSnapshot) -> PolicyGateImpl:
    return PolicyGateImpl(
        scope=scope,
        mode=ExecutionMode.SCOPE_AUTOPILOT,
        approved_risks=frozenset({RiskClass.LOW}),
        approved_capabilities=frozenset({"nuclei"}),
        engine=engine_evaluate,
    )


def test_policy_gate_allows_in_scope_approved_action() -> None:
    gate = _gate(_in_scope())
    verdict = gate.check(_action(host="http://example.com"), _ctx())
    assert verdict.passed is True


def test_policy_gate_denies_out_of_scope_action() -> None:
    gate = _gate(_in_scope())
    verdict = gate.check(_action(host="http://evil.com"), _ctx())
    assert verdict.passed is False
    # Real engine's reason string doubles as the stable deny_code.
    assert verdict.deny_code == "SCOPE_DENIED"
    assert "SCOPE_DENIED" in verdict.reason
