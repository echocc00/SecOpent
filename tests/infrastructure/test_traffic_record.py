"""TDD tests for the traffic-recording draft path (M3 Task 3, §11.9).

Recorded traffic is clustered into transitions; an injected LLM gateway proposes
states. The result is LLM_PROPOSED - the LLM only drafts, a human validates/
signs (LLM边界). The LLM gateway is a mock here (RemoteModelGateway is M5).
"""
from __future__ import annotations

from collections.abc import Sequence

from secopent.domain.appmodel.lifecycle import AppModelStatus
from secopent.infrastructure.model_sources.traffic_record import (
    ModelDraftGateway,
    RecordedRequest,
    TrafficRecorder,
)


class FakeLLM:
    def __init__(self, states: tuple[str, ...]) -> None:
        self._states = states
        self.seen_endpoints: list[Sequence[str]] = []

    def draft_states(self, endpoints: Sequence[str]) -> tuple[str, ...]:
        self.seen_endpoints.append(list(endpoints))
        return self._states


def _traffic() -> list[RecordedRequest]:
    return [
        RecordedRequest(method="POST", path="/login"),
        RecordedRequest(method="GET", path="/pets"),
        RecordedRequest(method="GET", path="/pets"),  # duplicate -> clustered
        RecordedRequest(method="POST", path="/checkout"),
    ]


def test_cluster_dedups_repeated_requests() -> None:
    transitions = TrafficRecorder().cluster(_traffic())
    endpoints = {t.endpoint for t in transitions}
    assert endpoints == {"POST /login", "GET /pets", "POST /checkout"}


def test_to_draft_without_llm_uses_default_state() -> None:
    model = TrafficRecorder().to_draft("Shop", _traffic())
    assert model.states == ("default",)
    assert model.status is AppModelStatus.LLM_PROPOSED
    assert len(model.transitions) == 3


def test_to_draft_with_llm_uses_proposed_states() -> None:
    llm = FakeLLM(states=("anonymous", "logged_in", "cart"))
    model = TrafficRecorder(llm=llm).to_draft("Shop", _traffic())
    assert model.states == ("anonymous", "logged_in", "cart")
    assert model.status is AppModelStatus.LLM_PROPOSED  # proposed, NOT validated


def test_llm_receives_clustered_endpoints() -> None:
    llm = FakeLLM(states=("a", "b"))
    TrafficRecorder(llm=llm).to_draft("Shop", _traffic())
    assert set(llm.seen_endpoints[0]) == {"POST /login", "GET /pets", "POST /checkout"}


def test_llm_gateway_satisfies_protocol() -> None:
    assert isinstance(FakeLLM(states=("a",)), ModelDraftGateway)
