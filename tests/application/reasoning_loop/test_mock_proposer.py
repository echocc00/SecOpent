# tests/application/reasoning_loop/test_mock_proposer.py
"""MockLoopActionProposer — scripted ProposeAction queue (dev + tests)."""
from __future__ import annotations

from secopent.application.reasoning_loop.mock_proposer import MockLoopActionProposer
from secopent.domain.reasoning_loop.models import (
    LoopActionType,
    LoopBudgetSnapshot,
    LoopContext,
    ProposeAction,
)


def _ctx(step: int = 0) -> LoopContext:
    return LoopContext(
        asset_subgraph=(), recent_observations=(), observation_token_count=0,
        catalog_already_executed=frozenset(), catalog_still_required=frozenset(),
        catalog_floor_progress=0.0, unconfirmed_candidates=(),
        confirmed_findings_recent=(), chain_hypotheses_pending=(),
        available_tools=(), available_cases=(), available_peers=(),
        budget_remaining=LoopBudgetSnapshot(50, 200_000, 1800),
        loop_step=step, max_steps=50, elapsed_seconds=0,
    )


def _action(rationale: str = "rationale " * 10) -> ProposeAction:
    return ProposeAction(
        action_type=LoopActionType.RUN_TOOL,
        payload={"tool_id": "nuclei", "parameters": {}},
        rationale=rationale,
        confidence=0.5,
    )


def test_mock_returns_scripted_action_per_call() -> None:
    script = [_action("a " * 30), _action("b " * 30), _action("c " * 30)]
    mp = MockLoopActionProposer(script=script)
    assert mp.propose(_ctx(0)) == script[0]
    assert mp.propose(_ctx(1)) == script[1]
    assert mp.propose(_ctx(2)) == script[2]


def test_mock_returns_None_when_script_exhausted() -> None:
    mp = MockLoopActionProposer(script=[_action("a " * 30)])
    assert mp.propose(_ctx(0)) is not None
    assert mp.propose(_ctx(1)) is None  # backend "unavailable"


def test_mock_records_proposal_history() -> None:
    mp = MockLoopActionProposer(script=[_action("a " * 30), _action("b " * 30)])
    mp.propose(_ctx(0))
    mp.propose(_ctx(1))
    mp.propose(_ctx(2))  # returns None
    history = mp.history
    assert len(history) == 3
    assert history[0].action is not None
    assert history[1].action is not None
    assert history[2].action is None


def test_mock_can_replay_with_reset() -> None:
    mp = MockLoopActionProposer(script=[_action("a " * 30)])
    assert mp.propose(_ctx(0)) is not None
    assert mp.propose(_ctx(1)) is None
    mp.reset()
    assert mp.propose(_ctx(0)) is not None
