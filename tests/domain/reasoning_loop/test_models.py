"""Tests for ReasoningLoop domain models (v0.7.0 tracer bullet)."""
from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from secopent.domain.reasoning_loop.models import (
    GateVerdict,
    HandbookSummary,
    LoopActionType,
    LoopBudget,
    LoopContext,
    LoopId,
    LoopPhase,
    LoopPlan,
    LoopState,
    LoopStep,
    LoopTerminationPolicy,
    ObservationSummary,
    PolicyDecision,
    ProposeAction,
)


def test_loop_id_is_8_char_hex() -> None:
    lid = LoopId.new()
    assert isinstance(lid.value, str)
    assert re.fullmatch(r"[0-9a-f]{8}", lid.value), lid.value


def test_loop_id_new_is_unique() -> None:
    ids = {LoopId.new() for _ in range(1000)}
    assert len(ids) == 1000


def test_loop_id_value_object_is_immutable() -> None:
    lid = LoopId(value="abcd1234")
    with pytest.raises((AttributeError, TypeError)):
        lid.value = "deadbeef"  # type: ignore[misc]


def test_loop_id_equality_on_value() -> None:
    a = LoopId(value="abcd1234")
    b = LoopId(value="abcd1234")
    c = LoopId(value="00000000")
    assert a == b
    assert a != c
    assert hash(a) == hash(b)


def test_loop_id_rejects_invalid_value() -> None:
    with pytest.raises(ValueError):
        LoopId(value="not-hex!")
    with pytest.raises(ValueError):
        LoopId(value="abcdef")  # too short


def test_loop_phase_is_string_enum() -> None:
    assert LoopPhase.RUNNING.value == "running"
    assert str(LoopPhase.RUNNING) == "LoopPhase.RUNNING"
    # JSON-serializable (used in audit)
    import json

    assert json.loads(json.dumps(LoopPhase.RUNNING.value)) == "running"


def test_loop_phase_includes_required_states() -> None:
    required = {
        "INITIALIZING",
        "RUNNING",
        "CONVERGED",
        "CATALOG_FLOOR_DONE",
        "PAUSED",  # spec §6.3 skeleton
        "RESUMED",  # spec §6.3 skeleton
        "BUDGET_EXHAUSTED",
        "POLICY_BLOCKED",
        "EMERGENCY_STOPPED",
        "COMPLETED",
    }
    assert {p.name for p in LoopPhase} >= required


def test_loop_budget_defaults() -> None:
    b = LoopBudget.default()
    snap = b.snapshot()
    assert snap.steps_remaining == 50
    assert snap.tokens_remaining == 200_000
    assert snap.wall_seconds_remaining == 1800


def test_loop_budget_consume_decrements() -> None:
    b = LoopBudget.default()
    b2 = b.consume(steps=3, tokens=1000, wall_seconds=30)
    snap = b2.snapshot()
    assert snap.steps_remaining == 47
    assert snap.tokens_remaining == 199_000
    assert snap.wall_seconds_remaining == 1770


def test_loop_budget_consume_returns_new_instance() -> None:
    """Budget must be immutable (frozen dataclass)."""
    b = LoopBudget.default()
    b.consume(steps=1)
    # Original unchanged.
    assert b.snapshot().steps_remaining == 50


def test_loop_budget_exhaustion_predicates() -> None:
    b = LoopBudget.default()
    assert not b.exhausted()
    # Drain all three budgets.
    drained = LoopBudget(
        max_steps=50,
        max_total_tokens=200_000,
        max_wall_seconds=1800,
        steps_used=50,
        tokens_used=200_000,
        wall_seconds_used=1800,
    )
    assert drained.exhausted()


def test_action_type_is_closed_enum() -> None:
    assert LoopActionType.RUN_TOOL.value == "run_tool"
    # Literal-ish: rejected at Pydantic layer when we use it as a field type.


def test_propose_action_run_tool_minimal() -> None:
    pa = ProposeAction(
        action_type=LoopActionType.RUN_TOOL,
        payload={"tool_id": "nuclei", "parameters": {"tags": ["sql-injection"]}},
        rationale="Catalog floor for SQLi not yet run on /api/users endpoint.",
        confidence=0.7,
    )
    assert pa.action_type is LoopActionType.RUN_TOOL
    assert pa.tool_id == "nuclei"  # convenience accessor


def test_propose_action_rejects_extra_fields_strict() -> None:
    with pytest.raises(ValidationError):
        ProposeAction.model_validate(
            {
                "action_type": "run_tool",
                "payload": {"tool_id": "nuclei", "parameters": {}},
                "rationale": "x" * 80,
                "confidence": 0.5,
                "rogue_field": "should not be accepted",
            }
        )


def test_propose_action_rationale_length_window() -> None:
    base = {
        "action_type": "run_tool",
        "payload": {"tool_id": "nuclei", "parameters": {}},
        "confidence": 0.5,
    }
    # Too short (<50 chars after stripping).
    with pytest.raises(ValidationError):
        ProposeAction.model_validate({**base, "rationale": "short"})
    # Too long (>500 chars).
    with pytest.raises(ValidationError):
        ProposeAction.model_validate({**base, "rationale": "a" * 501})
    # Just right.
    pa = ProposeAction.model_validate({**base, "rationale": "x" * 80})
    assert len(pa.rationale) == 80


def test_propose_action_confidence_window() -> None:
    base = {
        "action_type": "run_tool",
        "payload": {"tool_id": "nuclei", "parameters": {}},
        "rationale": "x" * 80,
    }
    with pytest.raises(ValidationError):
        ProposeAction.model_validate({**base, "confidence": -0.1})
    with pytest.raises(ValidationError):
        ProposeAction.model_validate({**base, "confidence": 1.1})
    ProposeAction.model_validate({**base, "confidence": 0.0})
    ProposeAction.model_validate({**base, "confidence": 1.0})


def test_propose_action_payload_required_keys_per_action_type() -> None:
    base = {"rationale": "x" * 80, "confidence": 0.5}
    # run_tool requires tool_id + parameters
    with pytest.raises(ValidationError):
        ProposeAction.model_validate(
            {**base, "action_type": "run_tool", "payload": {}}
        )
    # request_oracle requires candidate_id
    with pytest.raises(ValidationError):
        ProposeAction.model_validate(
            {**base, "action_type": "request_oracle", "payload": {}}
        )


def test_observation_summary_token_count_present() -> None:
    s = ObservationSummary(
        observation_id="obs-1",
        tool_or_case_id="nuclei",
        target_digest="sha256:" + "a" * 64,
        key_signals=("new_endpoint:/api/users",),
        confidence=0.6,
        has_full_text=False,
        full_text_ref=None,
        token_estimate=120,
    )
    assert s.token_estimate == 120
    assert s.has_full_text is False


def test_loop_context_context_hash_deterministic() -> None:
    ctx_a = LoopContext(
        asset_subgraph=(),
        recent_observations=(),
        observation_token_count=0,
        catalog_already_executed=frozenset({"web:sql-injection"}),
        catalog_still_required=frozenset({"web:xss"}),
        catalog_floor_progress=0.5,
        unconfirmed_candidates=(),
        confirmed_findings_recent=(),
        chain_hypotheses_pending=(),
        available_tools=(),
        available_cases=(),
        available_peers=(),
        budget_remaining=LoopBudget.default().snapshot(),
        loop_step=3,
        max_steps=50,
        elapsed_seconds=42,
    )
    ctx_b = LoopContext(
        asset_subgraph=(),
        recent_observations=(),
        observation_token_count=0,
        catalog_already_executed=frozenset({"web:sql-injection"}),
        catalog_still_required=frozenset({"web:xss"}),
        catalog_floor_progress=0.5,
        unconfirmed_candidates=(),
        confirmed_findings_recent=(),
        chain_hypotheses_pending=(),
        available_tools=(),
        available_cases=(),
        available_peers=(),
        budget_remaining=LoopBudget.default().snapshot(),
        loop_step=3,
        max_steps=50,
        elapsed_seconds=42,
    )
    assert ctx_a.context_hash() == ctx_b.context_hash()


def test_loop_context_context_hash_changes_on_field_change() -> None:
    base = dict(
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
        budget_remaining=LoopBudget.default().snapshot(),
        loop_step=0,
        max_steps=50,
        elapsed_seconds=0,
    )
    h0 = LoopContext(**base).context_hash()
    h1 = LoopContext(**{**base, "loop_step": 1}).context_hash()
    assert h0 != h1
    # v0.7.4: handbook_hints participates in content-addressing. Isolate the
    # field (same key_signals) so a regression where the hash omits it fails.
    handbook = (HandbookSummary(id="h1", title="t", attack_surface=("as",),
                                recon_endpoints=("re",), payload_classes=("pc",),
                                verification_hint="vh"),)
    h2 = LoopContext(**{**base, "handbook_hints": handbook}).context_hash()
    assert h0 != h2
    assert h1 != h2
    # Hash must be 64 hex chars (sha256).
    import re
    assert re.fullmatch(r"[0-9a-f]{64}", h0)


def test_loop_context_is_frozen() -> None:
    ctx = LoopContext(
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
        budget_remaining=LoopBudget.default().snapshot(),
        loop_step=0,
        max_steps=50,
        elapsed_seconds=0,
    )
    with pytest.raises((AttributeError, TypeError)):
        ctx.loop_step = 99  # type: ignore[misc]


def test_loop_state_initial_phase() -> None:
    s = LoopState(
        loop_id=LoopId(value="abcd1234"),
        assessment_id="asmt-1",
        phase=LoopPhase.INITIALIZING,
        policy_snapshot="sha256:" + "0" * 64,
        budget=LoopBudget.default(),
        context_hash="0" * 64,
        catalog_required_remaining=frozenset(),
        catalog_required_executed=frozenset(),
        consecutive_no_signal=0,
        consecutive_policy_rejected=0,
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        last_step_at=None,
    )
    assert s.phase is LoopPhase.INITIALIZING
    assert s.budget.snapshot().steps_remaining == 50


def test_loop_step_stores_full_proposal_and_outcome() -> None:
    pa = ProposeAction(
        action_type=LoopActionType.RUN_TOOL,
        payload={"tool_id": "nuclei", "parameters": {}},
        rationale="x" * 80,
        confidence=0.6,
    )
    verdict = GateVerdict(
        passed=True,
        reason="ok",
        deny_code=None,
        permit_id="permit-1",
        permit_ttl_seconds=900,
    )
    assert verdict.passed is True
    step = LoopStep(
        step_id="step-1",
        loop_id=LoopId(value="abcd1234"),
        step_number=1,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        context_hash_before="0" * 64,
        proposed_action=pa,
        propose_tokens_used=120,
        propose_latency_ms=200,
        propose_rationale=pa.rationale,
        schema_check_passed=True,
        policy_decision=PolicyDecision(verdict="allow", reason="in scope"),
        permit_id="permit-1",
        tool_or_case_id="nuclei",
        execution_result_digest="sha256:" + "a" * 64,
        evidence_refs=(),
        observation_signals=("new_endpoint:/api/users",),
        catalog_class_matched=frozenset(),
        oracle_progressed=False,
        correlation_id="corr-1",
    )
    assert step.tool_or_case_id == "nuclei"
    assert step.proposed_action.action_type is LoopActionType.RUN_TOOL


def test_loop_plan_carries_termination_policy_snapshot() -> None:
    policy = LoopTerminationPolicy.default()
    plan = LoopPlan(
        plan_id="lp-1",
        loop_id=LoopId(value="abcd1234"),
        assessment_id="asmt-1",
        termination_policy=policy,
        policy_snapshot="sha256:" + "f" * 64,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert plan.termination_policy.max_steps == 50


class TestLoopStatePauseFields:
    """v0.7.7: pause/resume tracking fields on LoopState."""

    def test_defaults(self) -> None:
        # Backward-compatible defaults: existing constructions (that stop at
        # last_step_at) must still compile and get sensible pause defaults.
        s = LoopState(
            loop_id=LoopId(value="abcd1234"),
            assessment_id="asmt-1",
            phase=LoopPhase.RUNNING,
            policy_snapshot="sha256:" + "0" * 64,
            budget=LoopBudget.default(),
            context_hash="0" * 64,
            catalog_required_remaining=frozenset(),
            catalog_required_executed=frozenset(),
            consecutive_no_signal=0,
            consecutive_policy_rejected=0,
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            last_step_at=None,
        )
        assert s.pause_attempts == 0
        assert s.paused_at is None
        assert s.resumed_at is None

    def test_with_pause(self) -> None:
        paused = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
        resumed = datetime(2026, 1, 1, 10, 30, tzinfo=UTC)
        s = LoopState(
            loop_id=LoopId(value="abcd1234"),
            assessment_id="asmt-1",
            phase=LoopPhase.PAUSED,
            policy_snapshot="sha256:" + "0" * 64,
            budget=LoopBudget.default(),
            context_hash="0" * 64,
            catalog_required_remaining=frozenset(),
            catalog_required_executed=frozenset(),
            consecutive_no_signal=0,
            consecutive_policy_rejected=0,
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            last_step_at=None,
            pause_attempts=2,
            paused_at=paused,
            resumed_at=resumed,
        )
        assert s.pause_attempts == 2
        assert s.paused_at == paused
        assert s.resumed_at == resumed


class TestLoopTerminationPolicyMaxPauses:
    """v0.7.7: max-pauses termination policy."""

    def test_default_three(self) -> None:
        assert LoopTerminationPolicy.default().max_pauses == 3

    def test_pause_budget_exceeded(self) -> None:
        policy = LoopTerminationPolicy.default()
        assert policy.pause_budget_exceeded(3) is True
        assert policy.pause_budget_exceeded(2) is False
