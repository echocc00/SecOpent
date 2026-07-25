"""TDD tests for RemoteModelGateway (M5 Task 6, §12.11 LLM ops constraints)."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from secopent.application.remote_model import (
    DataClassification,
    ModelBudget,
    PromptTooLarge,
    RemoteModelGateway,
    RestrictedDenied,
    SecretNeverSent,
)
from secopent.infrastructure.evidence_store.redaction import RedactionEngine

_T0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


class RecordingBackend:
    def __init__(self, reply: str = "model-reply") -> None:
        self.received: list[str] = []
        self._reply = reply

    def complete(self, prompt: str) -> str:
        self.received.append(prompt)
        return self._reply


def _gateway(
    *,
    remote: RecordingBackend | None = None,
    budget: ModelBudget | None = None,
) -> tuple[RemoteModelGateway, RecordingBackend, RecordingBackend | None]:
    local = RecordingBackend(reply="local-reply")
    gw = RemoteModelGateway(
        local_backend=local,
        remote_backend=remote,
        redactor=RedactionEngine(),
        budget=budget or ModelBudget(),
    )
    return gw, local, remote


def test_secret_never_sent() -> None:
    gw, local, _ = _gateway()
    with pytest.raises(SecretNeverSent):
        gw.call("apikey " + _AWS_KEY, classification=DataClassification.SECRET, now=_T0)
    assert local.received == []


def test_restricted_default_deny() -> None:
    gw, _, _ = _gateway()
    with pytest.raises(RestrictedDenied):
        gw.call("restricted data", classification=DataClassification.RESTRICTED, now=_T0)


def test_sensitive_is_redacted_before_send() -> None:
    remote = RecordingBackend()
    gw, _, _ = _gateway(remote=remote)
    gw.call(
        "leaked " + _AWS_KEY + " here",
        classification=DataClassification.SENSITIVE,
        now=_T0,
        prefer_remote=True,
    )
    sent = remote.received[0]
    assert _AWS_KEY not in sent
    assert "[REDACTED:aws_access_key]" in sent


def test_prompt_size_cap_enforced() -> None:
    gw, _, _ = _gateway(budget=ModelBudget(prompt_size_cap=100))
    with pytest.raises(PromptTooLarge):
        gw.call("x" * 200, classification=DataClassification.PUBLIC, now=_T0)


def test_local_first_by_default() -> None:
    remote = RecordingBackend()
    gw, local, _ = _gateway(remote=remote)
    response = gw.call("hello", classification=DataClassification.PUBLIC, now=_T0)
    assert response.backend == "local"
    assert local.received == ["hello"]
    assert remote.received == []


def test_remote_used_when_preferred_and_within_budget() -> None:
    remote = RecordingBackend()
    gw, _, _ = _gateway(remote=remote)
    response = gw.call(
        "hello", classification=DataClassification.PUBLIC, now=_T0, prefer_remote=True
    )
    assert response.backend == "remote"
    assert response.degraded is False


def test_budget_exhaustion_degrades_to_local() -> None:
    remote = RecordingBackend()
    # Tiny budget; a prompt whose token estimate exceeds it must degrade.
    gw, local, _ = _gateway(remote=remote, budget=ModelBudget(daily_token_budget=10))
    response = gw.call(
        "x" * 100,  # estimate ~25 tokens > 10
        classification=DataClassification.PUBLIC,
        now=_T0,
        prefer_remote=True,
    )
    assert response.backend == "local"
    assert response.degraded is True
    assert remote.received == []


def test_rate_limit_degrades_to_local() -> None:
    remote = RecordingBackend()
    gw, local, _ = _gateway(
        remote=remote, budget=ModelBudget(rate_limit_per_min=1)
    )
    first = gw.call("a", classification=DataClassification.PUBLIC, now=_T0, prefer_remote=True)
    second = gw.call("b", classification=DataClassification.PUBLIC, now=_T0, prefer_remote=True)
    assert first.backend == "remote"
    assert second.backend == "local"  # rate-limited -> degraded
    assert second.degraded is True


def test_alert_at_80_percent_budget() -> None:
    gw, _, _ = _gateway(budget=ModelBudget(daily_token_budget=100))
    # estimate ~ len/4; 360 chars -> ~90 tokens -> 90% -> warn.
    response = gw.call("x" * 360, classification=DataClassification.PUBLIC, now=_T0)
    assert response.alert == "budget_80_warn"


def test_local_mode_needs_no_remote() -> None:
    # No remote backend at all; local still serves (scanning works LLM-free).
    gw, local, remote = _gateway(remote=None)
    assert remote is None
    response = gw.call("scan", classification=DataClassification.PUBLIC, now=_T0)
    assert response.backend == "local"
    assert response.text == "local-reply"
