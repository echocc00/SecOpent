"""SchemaGate — Pydantic strict validation + payload key check (spec §6.1)."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from secopent.application.reasoning_loop.schema_gate import SchemaGateImpl
from secopent.domain.reasoning_loop.models import (
    LoopActionType,
    LoopBudgetSnapshot,
    LoopContext,
    ProposeAction,
)


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


def test_schema_gate_accepts_valid_propose_action() -> None:
    gate = SchemaGateImpl()
    pa = ProposeAction(
        action_type=LoopActionType.RUN_TOOL,
        payload={"tool_id": "nuclei", "parameters": {"tags": ["xss"]}},
        rationale="x" * 80,
        confidence=0.5,
    )
    verdict = gate.check(pa, _ctx())
    assert verdict.passed is True
    assert verdict.reason == "schema_ok"


def test_schema_gate_rejects_unknown_action_type() -> None:
    """Reject an action_type outside the closed enum, even before Pydantic
    validates it (what a real LLM might emit)."""
    gate = SchemaGateImpl()

    class _Stub(BaseModel):
        model_config = ConfigDict(extra="forbid")
        action_type: str = "explode_target"  # not in LoopActionType
        payload: dict = {}
        rationale: str = "x" * 80
        confidence: float = 0.5

    verdict = gate.check(_Stub(), _ctx())
    assert verdict.passed is False
    assert verdict.deny_code == "SCHEMA_INVALID_ACTION_TYPE"


def test_schema_gate_rejects_missing_payload_keys() -> None:
    gate = SchemaGateImpl()

    class _Stub(BaseModel):
        model_config = ConfigDict(extra="forbid")
        action_type: str = "run_tool"
        payload: dict = {"tool_id": "nuclei"}  # missing "parameters"
        rationale: str = "x" * 80
        confidence: float = 0.5

    verdict = gate.check(_Stub(), _ctx())
    assert verdict.passed is False
    assert verdict.deny_code == "SCHEMA_MISSING_PAYLOAD_KEYS"


def test_schema_gate_rejects_rationale_too_short() -> None:
    gate = SchemaGateImpl()

    class _Stub(BaseModel):
        model_config = ConfigDict(extra="forbid")
        action_type: str = "run_tool"
        payload: dict = {"tool_id": "nuclei", "parameters": {}}
        rationale: str = "short"
        confidence: float = 0.5

    verdict = gate.check(_Stub(), _ctx())
    assert verdict.passed is False
    assert verdict.deny_code == "SCHEMA_RATIONALE_OUT_OF_RANGE"
