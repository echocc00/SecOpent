# tests/infrastructure/reasoning_loop/test_composition.py
"""create_loop_proposer (v0.7.1 Task 4) — env selection + fallback + audit.

Asserts the composition factory:
- ``SECOPENT_LOOP_PROPOSER=mock`` (default) -> a Mock proposer, no audit.
- ``=real`` with a usable LLM backend -> a proposer that routes the LLM's
  strict-JSON output to the orchestrator port (ProposeAction).
- ``=real`` with an unavailable backend / no LLM key -> degrades to Mock AND
  records a ``loop.fallback_used`` audit event (never weakens the gate).
"""
from __future__ import annotations

from typing import Any

from secopent.application.audit import AuditService
from secopent.application.reasoning_loop.audit import LOOP_FALLBACK_USED
from secopent.application.reasoning_loop.llm_backend import LoopLLMBackend
from secopent.application.reasoning_loop.mock_proposer import MockLoopActionProposer
from secopent.domain.reasoning_loop.models import (
    LoopActionType,
    LoopBudgetSnapshot,
    LoopContext,
    ProposeAction,
)
from secopent.infrastructure.reasoning_loop.composition import (
    LOOP_PROPOSER_ENV,
    create_loop_proposer,
)

_PROPOSE_JSON = (
    '{"action_type":"run_tool",'
    '"payload":{"tool_id":"nuclei","parameters":{}},'
    '"rationale":"probe the adjacent endpoint for a local file disclosure to '
    'confirm scope inclusion and validate the perimeter","confidence":0.7}'
)


class _FakeBackend(LoopLLMBackend):
    """Canned JSON backend; reports availability so the factory can decide."""

    def __init__(self, responses: list[str], available: bool = True) -> None:
        self._responses = list(responses)
        self._available = available

    def complete(self, prompt: str) -> str:
        return self._responses.pop(0)

    def is_available(self) -> bool:
        return self._available


class _FakeAuditRepo:
    """Minimal audit repo for the real AuditService (like peer composition tests)."""

    def __init__(self) -> None:
        self._events: list[Any] = []

    def add(self, event: Any) -> None:
        self._events.append(event)

    def list_events(self) -> list[Any]:
        return list(self._events)

    def last_hash(self) -> str:
        from secopent.domain.audit.models import GENESIS_HASH

        return GENESIS_HASH


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


def _audit() -> tuple[AuditService, _FakeAuditRepo]:
    repo = _FakeAuditRepo()
    return AuditService(repo), repo


def _actions(repo: _FakeAuditRepo) -> list[str]:
    return [getattr(e, "action", "") for e in repo.list_events()]


class TestDefaultIsMock:
    def test_mock_env_returns_mock_with_no_audit(self) -> None:
        audit, repo = _audit()
        proposer = create_loop_proposer(audit=audit, env={LOOP_PROPOSER_ENV: "mock"})
        assert isinstance(proposer, MockLoopActionProposer)
        assert proposer.propose(_ctx()) is None
        assert _actions(repo) == []

    def test_unset_env_defaults_to_mock(self) -> None:
        audit, repo = _audit()
        proposer = create_loop_proposer(audit=audit, env={})
        assert isinstance(proposer, MockLoopActionProposer)
        assert _actions(repo) == []


class TestRealSelection:
    def test_real_with_usable_backend_routes_llm_action(self) -> None:
        audit, repo = _audit()
        backend = _FakeBackend([_PROPOSE_JSON], available=True)
        proposer = create_loop_proposer(
            audit=audit,
            env={LOOP_PROPOSER_ENV: "real"},
            backend=backend,
        )
        assert not isinstance(proposer, MockLoopActionProposer)
        action = proposer.propose(_ctx())
        assert isinstance(action, ProposeAction)
        assert action.action_type is LoopActionType.RUN_TOOL
        # No fallback took place: mock selection would have recorded it.
        assert _actions(repo) == []

    def test_real_with_unavailable_backend_falls_back_to_mock(self) -> None:
        audit, repo = _audit()
        backend = _FakeBackend([_PROPOSE_JSON], available=False)
        proposer = create_loop_proposer(
            audit=audit,
            env={LOOP_PROPOSER_ENV: "real"},
            backend=backend,
        )
        assert isinstance(proposer, MockLoopActionProposer)
        assert proposer.propose(_ctx()) is None
        assert LOOP_FALLBACK_USED in _actions(repo)

    def test_real_without_backend_and_no_config_falls_back(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        audit, repo = _audit()
        missing_config = tmp_path / "no-llm.yaml"
        proposer = create_loop_proposer(
            audit=audit,
            env={LOOP_PROPOSER_ENV: "real"},
            backend=None,
            config_path=missing_config,
        )
        assert isinstance(proposer, MockLoopActionProposer)
        assert LOOP_FALLBACK_USED in _actions(repo)