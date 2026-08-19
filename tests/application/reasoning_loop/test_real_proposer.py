# tests/application/reasoning_loop/test_real_proposer.py
"""Task 1 (v0.7.1): LoopLLMBackend port + result types.

Scope note: Task 1 tests ONLY the ``llm_backend`` port surface — the
``LoopLLMBackend`` Protocol, the ``ProposalOutcome`` enum, the frozen
``LLMProposalResult`` dtype, and the typed error classes. The
``RealLoopActionProposer`` behavior (calling the backend, JSON retry,
degradation policy) is asserted in Task 4, where the proposer lands.

The ``FakeLLMBackend`` / ``_prompt_ok()`` / ``_ctx()`` scaffolding is kept
here so downstream tasks can reuse it without duplication.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from secopent.application.reasoning_loop.llm_backend import (
    LLMBackendProtocolError,
    LLMBackendUnavailable,
    LLMProposalResult,
    LoopLLMBackend,
    ProposalOutcome,
)
from secopent.application.reasoning_loop.proposer import RealLoopActionProposer
from secopent.domain.common.errors import DomainError
from secopent.domain.reasoning_loop.models import (
    LoopActionType,
    LoopBudgetSnapshot,
    LoopContext,
    ProposeAction,
)


class FakeLLMBackend(LoopLLMBackend):
    """Returns canned JSON; records calls."""

    def __init__(self, responses: list[str | Exception]) -> None:
        self._responses = list(responses)
        self.calls: list[str] = []

    def complete(self, prompt: str) -> str:
        self.calls.append(prompt)
        resp = self._responses.pop(0)
        if isinstance(resp, Exception):
            raise resp
        return resp


def _prompt_ok() -> str:
    return '{"action_type":"run_tool","payload":{"tool_id":"nuclei","parameters":{"template":"x"}},"rationale":"probe adjacent endpoint for auth bypass","confidence":0.7}'  # noqa: E501


# A strict-schema-valid prompt for the proposer behavior tests (Task 4). The
# T1 ``_prompt_ok`` fixture above intentionally carries a <50-char rationale,
# which the strict ProposeAction schema (min_length=50) rejects — the proposer
# MUST treat it as bad output, so these tests use a fully-valid prompt whose
# rationale satisfies the schema.
_VALID_PROMPT = (
    '{"action_type":"run_tool",'
    '"payload":{"tool_id":"nuclei","parameters":{"template":"x"}},'
    '"rationale":"probe the adjacent endpoint for a local file disclosure to '
    'confirm scope inclusion and validate the perimeter","confidence":0.7}'
)


def _ctx() -> LoopContext:
    # Minimal valid LoopContext (fields mirror v0.7.0 domain models).
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


class TestLoopLLMBackendPort:
    def test_protocol_is_runtime_checkable(self) -> None:
        assert isinstance(FakeLLMBackend([]), LoopLLMBackend)

    def test_protocol_declares_single_complete_call(self) -> None:
        sig = LoopLLMBackend.__protocol_attrs__
        assert "complete" in sig

    def test_fake_backend_records_prompts(self) -> None:
        backend = FakeLLMBackend([_prompt_ok()])
        backend.complete("hello")
        assert backend.calls == ["hello"]


class TestProposalOutcome:
    def test_four_enum_members(self) -> None:
        members = {m.name for m in ProposalOutcome}
        assert members == {
            "OK",
            "RETRYABLE",
            "POLICY_BLOCKED",
            "BACKEND_UNAVAILABLE",
        }

    def test_values_are_stable(self) -> None:
        assert ProposalOutcome.OK.value == "ok"
        assert ProposalOutcome.RETRYABLE.value == "retryable"
        assert ProposalOutcome.POLICY_BLOCKED.value == "policy_blocked"
        assert ProposalOutcome.BACKEND_UNAVAILABLE.value == "backend_unavailable"


class TestLLMProposalResult:
    def test_is_frozen_dataclass(self) -> None:
        res = LLMProposalResult(outcome=ProposalOutcome.OK)
        with pytest.raises(FrozenInstanceError):
            res.outcome = ProposalOutcome.RETRYABLE  # type: ignore[misc]

    def test_default_fields(self) -> None:
        res = LLMProposalResult(outcome=ProposalOutcome.OK)
        assert res.action is None
        assert res.error == ""
        assert res.attempts == 0


class TestLLMBackendErrors:
    def test_unavailable_is_domain_error(self) -> None:
        assert issubclass(LLMBackendUnavailable, DomainError)

    def test_protocol_error_is_domain_error(self) -> None:
        assert issubclass(LLMBackendProtocolError, DomainError)


class TestFixtures:
    def test_prompt_ok_is_json_with_expected_action_type(self) -> None:
        import json

        data = json.loads(_prompt_ok())
        assert data["action_type"] == LoopActionType.RUN_TOOL.value
        assert data["payload"]["tool_id"] == "nuclei"

    def test_ctx_is_minimal_valid_loop_context(self) -> None:
        ctx = _ctx()
        assert isinstance(ctx, LoopContext)
        assert ctx.context_hash()


class TestRealProposer:
    """RealLoopActionProposer behavior (Task 4): LLM call -> strict ProposeAction.

    ``propose`` returns a typed ``LLMProposalResult``; the composition adapter
    maps non-OK outcomes onto the orchestrator's ``LoopActionProposer`` port
    (None). These tests assert the proposer's own degradation vocabulary.
    """

    def test_valid_json_yields_ProposeAction(self) -> None:
        backend = FakeLLMBackend([_VALID_PROMPT])
        proposer = RealLoopActionProposer(backend=backend)
        res = proposer.propose(_ctx())
        assert res.outcome is ProposalOutcome.OK
        assert isinstance(res.action, ProposeAction)
        assert res.action.action_type is LoopActionType.RUN_TOOL
        assert res.action.tool_id == "nuclei"

    def test_bad_json_retries_once_then_ok(self) -> None:
        backend = FakeLLMBackend(["{not json", _VALID_PROMPT])
        proposer = RealLoopActionProposer(backend=backend, max_retries=1)
        res = proposer.propose(_ctx())
        assert res.outcome is ProposalOutcome.OK
        assert isinstance(res.action, ProposeAction)
        assert len(backend.calls) == 2

    def test_bad_json_exhausts_retries_is_retryable(self) -> None:
        backend = FakeLLMBackend(["{not json", "still not json"])
        proposer = RealLoopActionProposer(backend=backend, max_retries=1)
        res = proposer.propose(_ctx())
        assert res.outcome is ProposalOutcome.RETRYABLE
        assert res.action is None
        assert len(backend.calls) == 2

    def test_backend_unavailable_is_hard_error(self) -> None:
        backend = FakeLLMBackend([LLMBackendUnavailable("down")])
        proposer = RealLoopActionProposer(backend=backend)
        res = proposer.propose(_ctx())
        assert res.outcome is ProposalOutcome.BACKEND_UNAVAILABLE
        assert res.action is None