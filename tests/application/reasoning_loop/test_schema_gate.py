# tests/application/reasoning_loop/test_schema_gate.py
"""SchemaGate — Pydantic strict validation + payload key check + capability
existence (spec §6.1, v0.7.1 Task 3).

Deny codes:
- SCHEMA_INVALID_ACTION_TYPE      action_type outside LoopActionType enum
- SCHEMA_MISSING_PAYLOAD_KEYS     action_type requires a payload key that's absent
- SCHEMA_UNKNOWN_TOOL             run_tool references a tool_id not in available_tools
- SCHEMA_EXTRA_FIELDS             payload carries a key the per-type schema forbids
- SCHEMA_RATIONALE_TOO_SHORT      rationale shorter than the 50-char minimum
- SCHEMA_UNKNOWN_HYPOTHESIS       request_chain references an unknown hypothesis_id
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from secopent.application.reasoning_loop.schema_gate import SchemaGateImpl
from secopent.domain.reasoning_loop.models import (
    AvailableCapability,
    LoopActionType,
    LoopBudgetSnapshot,
    LoopContext,
    PendingHypothesis,
    ProposeAction,
)

_RATIONALE = "x" * 80


def _capability(capability_id: str) -> AvailableCapability:
    return AvailableCapability(
        capability_id=capability_id,
        kind="tool",
        summary=f"{capability_id} scanner",
        risk_class="low",
        cwe=("CWE-79",),
    )


def _hypothesis(hypothesis_id: str) -> PendingHypothesis:
    return PendingHypothesis(
        hypothesis_id=hypothesis_id,
        description="auth bypass on admin surface",
        needed_cwe=("CWE-287",),
    )


def _ctx(
    *,
    available_tools: tuple[AvailableCapability, ...] = (_capability("nuclei"),),
    chain_hypotheses_pending: tuple[PendingHypothesis, ...] = (_hypothesis("hyp-A"),),
) -> LoopContext:
    return LoopContext(
        asset_subgraph=(),
        recent_observations=(),
        observation_token_count=0,
        catalog_already_executed=frozenset(),
        catalog_still_required=frozenset(),
        catalog_floor_progress=0.0,
        unconfirmed_candidates=(),
        confirmed_findings_recent=(),
        chain_hypotheses_pending=chain_hypotheses_pending,
        available_tools=available_tools,
        available_cases=(),
        available_peers=(),
        budget_remaining=LoopBudgetSnapshot(50, 200_000, 1800),
        loop_step=0,
        max_steps=50,
        elapsed_seconds=0,
    )


class _UnvalidatedStub(BaseModel):
    """A Pydantic model with the same field shape as ProposeAction but without
    the enum/strict validators, so tests can feed deliberate-invalid inputs
    straight through to the gate's dict-path."""

    model_config = ConfigDict(extra="forbid")

    action_type: str
    payload: dict
    rationale: str
    confidence: float


def test_schema_gate_accepts_valid_propose_action() -> None:
    gate = SchemaGateImpl()
    pa = ProposeAction(
        action_type=LoopActionType.RUN_TOOL,
        payload={"tool_id": "nuclei", "parameters": {"tags": ["xss"]}},
        rationale=_RATIONALE,
        confidence=0.5,
    )
    verdict = gate.check(pa, _ctx())
    assert verdict.passed is True
    assert verdict.reason == "schema_ok"


def test_schema_gate_accepts_valid_run_tool_with_known_tool() -> None:
    gate = SchemaGateImpl()
    pa = ProposeAction(
        action_type=LoopActionType.RUN_TOOL,
        payload={"tool_id": "nuclei", "parameters": {"tags": ["xss"]}},
        rationale=_RATIONALE,
        confidence=0.5,
    )
    # tool_id "nuclei" IS present in _ctx().available_tools.
    assert gate.check(pa, _ctx()).passed is True


def test_schema_gate_rejects_unknown_action_type() -> None:
    """Reject an action_type outside the closed enum, even before Pydantic
    validates it (what a real LLM might emit)."""
    gate = SchemaGateImpl()
    stub = _UnvalidatedStub(
        action_type="explode_target",  # not in LoopActionType
        payload={},
        rationale=_RATIONALE,
        confidence=0.5,
    )
    verdict = gate.check(stub, _ctx())
    assert verdict.passed is False
    assert verdict.deny_code == "SCHEMA_INVALID_ACTION_TYPE"


def test_schema_gate_rejects_missing_payload_keys() -> None:
    gate = SchemaGateImpl()
    stub = _UnvalidatedStub(
        action_type="run_tool",
        payload={"tool_id": "nuclei"},  # missing "parameters"
        rationale=_RATIONALE,
        confidence=0.5,
    )
    verdict = gate.check(stub, _ctx())
    assert verdict.passed is False
    assert verdict.deny_code == "SCHEMA_MISSING_PAYLOAD_KEYS"


def test_schema_gate_rejects_rationale_too_short() -> None:
    gate = SchemaGateImpl()
    stub = _UnvalidatedStub(
        action_type="run_tool",
        payload={"tool_id": "nuclei", "parameters": {}},
        rationale="short",  # < 50 chars
        confidence=0.5,
    )
    verdict = gate.check(stub, _ctx())
    assert verdict.passed is False
    assert verdict.deny_code == "SCHEMA_RATIONALE_TOO_SHORT"


def test_schema_gate_rejects_unknown_tool() -> None:
    """run_tool referencing a tool_id not present in context.available_tools."""
    gate = SchemaGateImpl()
    stub = _UnvalidatedStub(
        action_type="run_tool",
        payload={"tool_id": "not-a-real-tool", "parameters": {}},
        rationale=_RATIONALE,
        confidence=0.5,
    )
    verdict = gate.check(stub, _ctx())
    assert verdict.passed is False
    assert verdict.deny_code == "SCHEMA_UNKNOWN_TOOL"


def test_schema_gate_rejects_extra_payload_fields() -> None:
    """payload carrying a key the per-type schema forbids (extra='forbid')."""
    gate = SchemaGateImpl()
    stub = _UnvalidatedStub(
        action_type="run_tool",
        payload={"tool_id": "nuclei", "parameters": {}, "bogus_key": 1},
        rationale=_RATIONALE,
        confidence=0.5,
    )
    verdict = gate.check(stub, _ctx())
    assert verdict.passed is False
    assert verdict.deny_code == "SCHEMA_EXTRA_FIELDS"


def test_schema_gate_rejects_unknown_hypothesis() -> None:
    """request_chain referencing a hypothesis_id not in chain_hypotheses_pending."""
    gate = SchemaGateImpl()
    stub = _UnvalidatedStub(
        action_type="request_chain",
        payload={"hypothesis_id": "hyp-NOPE"},
        rationale=_RATIONALE,
        confidence=0.5,
    )
    verdict = gate.check(stub, _ctx())
    assert verdict.passed is False
    assert verdict.deny_code == "SCHEMA_UNKNOWN_HYPOTHESIS"


def test_schema_gate_accepts_valid_request_chain_with_known_hypothesis() -> None:
    """request_chain referencing a hypothesis_id that IS pending passes."""
    gate = SchemaGateImpl()
    stub = _UnvalidatedStub(
        action_type="request_chain",
        payload={"hypothesis_id": "hyp-A"},
        rationale=_RATIONALE,
        confidence=0.5,
    )
    assert gate.check(stub, _ctx()).passed is True