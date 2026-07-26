"""Real LLM gateway integration tests (Phase A Task A6).

Exercise the RemoteModelGateway against the REAL configured model (MiniMax via
config/llm.yaml). Verify a real call works, SENSITIVE data is redacted BEFORE it
is sent to the model, and RESTRICTED data is default-denied.

Marked ``integration``; skipped automatically when the LLM key/config is absent
or the API is unreachable.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from secopent.application.remote_model import (
    DataClassification,
    RemoteModelGateway,
    RestrictedDenied,
)
from secopent.infrastructure.evidence_store.redaction import RedactionEngine
from secopent.infrastructure.llm.config import load_backend_from_config
from secopent.infrastructure.llm.remote_openai_backend import (
    RemoteOpenAICompatibleBackend,
)

_NOW = datetime(2026, 1, 1, tzinfo=UTC)
_CONFIG = Path(__file__).resolve().parents[2] / "config" / "llm.yaml"


class _StubBackend:
    """Local fallback backend (not used for the real-call assertions)."""

    def complete(self, prompt: str) -> str:
        return "local-stub"


@pytest.fixture
def real_backend() -> RemoteOpenAICompatibleBackend:  # type: ignore[no-untyped-def]
    if not _CONFIG.is_file():
        pytest.skip("config/llm.yaml missing")
    try:
        return load_backend_from_config(_CONFIG)
    except Exception as exc:  # noqa: BLE001 - skip when key/config unavailable
        pytest.skip(f"LLM backend unavailable: {exc}")


def _gateway(backend: RemoteOpenAICompatibleBackend) -> RemoteModelGateway:
    return RemoteModelGateway(
        local_backend=_StubBackend(),
        redactor=RedactionEngine(),
        remote_backend=backend,
    )


@pytest.mark.integration
def test_real_llm_public_call(real_backend) -> None:  # type: ignore[no-untyped-def]
    gateway = _gateway(real_backend)
    response = gateway.call(
        "Reply with exactly one word: PONG",
        classification=DataClassification.PUBLIC,
        now=_NOW,
        prefer_remote=True,
    )
    assert response.backend == "remote"
    assert response.text.strip()  # a real non-empty completion


@pytest.mark.integration
def test_real_llm_redacts_sensitive_before_send(real_backend) -> None:  # type: ignore[no-untyped-def]
    gateway = _gateway(real_backend)
    secret_prompt = (
        "Summarize this contact info: admin@example.com and key "
        "AKIAIOSFODNN7EXAMPLE. Keep it short."
    )
    response = gateway.call(
        secret_prompt,
        classification=DataClassification.SENSITIVE,
        now=_NOW,
        prefer_remote=True,
    )
    assert response.redacted is True
    sent = real_backend.last_sent_prompt
    assert sent is not None
    # The email and AWS key must be redacted BEFORE reaching the model.
    assert "admin@example.com" not in sent
    assert "AKIAIOSFODNN7EXAMPLE" not in sent
    assert "[REDACTED:" in sent


@pytest.mark.integration
def test_real_llm_restricted_denied(real_backend) -> None:  # type: ignore[no-untyped-def]
    gateway = _gateway(real_backend)
    with pytest.raises(RestrictedDenied):
        gateway.call(
            "restricted internal data",
            classification=DataClassification.RESTRICTED,
            now=_NOW,
            prefer_remote=True,
        )
