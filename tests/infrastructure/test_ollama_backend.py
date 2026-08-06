"""OllamaBackend: local Ollama over /api/generate (v0.5.0 Phase 3, 3.4)."""
from __future__ import annotations

from typing import Any

import httpx
import pytest

from secopent.infrastructure.llm import LLMError
from secopent.infrastructure.llm.ollama_backend import OllamaBackend


class _FakeResponse:
    def __init__(self, payload: dict[str, Any], status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("POST", "http://fake")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError(
                f"status {self.status_code}", request=request, response=response
            )

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeClient:
    """Stands in for httpx.Client; records the last request it saw."""

    last_url: str = ""
    last_json: dict[str, Any] = {}

    def __init__(self, response: _FakeResponse, *, raise_on_send: Exception | None = None) -> None:
        self._response = response
        self._raise_on_send = raise_on_send

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *args: object) -> bool:
        return False

    def post(self, url: str, json: dict[str, Any] | None = None, **kwargs: Any) -> _FakeResponse:
        _FakeClient.last_url = url
        _FakeClient.last_json = json or {}
        if self._raise_on_send is not None:
            raise self._raise_on_send
        return self._response

    def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        _FakeClient.last_url = url
        if self._raise_on_send is not None:
            raise self._raise_on_send
        return self._response


@pytest.fixture()
def patch_httpx(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """Return a helper that swaps httpx.Client for the recording fake."""

    def _patch(response: _FakeResponse, raise_on_send: Exception | None = None) -> None:
        monkeypatch.setattr(
            httpx, "Client",
            lambda timeout=None: _FakeClient(response, raise_on_send=raise_on_send),
        )

    return _patch


def test_complete_returns_response_text(patch_httpx) -> None:  # type: ignore[no-untyped-def]
    patch_httpx(_FakeResponse({"response": "hello from llama", "model": "llama3.1:8b"}))
    backend = OllamaBackend(endpoint="http://ollama.test:11434/", model="llama3.1:8b")
    assert backend.complete("say hi") == "hello from llama"
    assert backend.last_sent_prompt == "say hi"
    # The endpoint rides /api/generate, non-streaming, with model + prompt.
    assert _FakeClient.last_url == "http://ollama.test:11434/api/generate"
    assert _FakeClient.last_json["model"] == "llama3.1:8b"
    assert _FakeClient.last_json["prompt"] == "say hi"
    assert _FakeClient.last_json["stream"] is False


def test_generate_flattens_messages_into_prompt(patch_httpx) -> None:  # type: ignore[no-untyped-def]
    patch_httpx(_FakeResponse({"response": "ok"}))
    backend = OllamaBackend()
    resp = backend.generate(
        messages=[{"role": "system", "content": "be brief"}, {"role": "user", "content": "hi"}]
    )
    assert resp.text == "ok"
    assert "system: be brief" in _FakeClient.last_json["prompt"]
    assert "user: hi" in _FakeClient.last_json["prompt"]


def test_http_error_status_raises_llmerror(patch_httpx) -> None:  # type: ignore[no-untyped-def]
    patch_httpx(_FakeResponse({}, status_code=500))
    with pytest.raises(LLMError, match="Ollama status 500"):
        OllamaBackend().complete("boom")


def test_network_error_raises_llmerror(patch_httpx) -> None:  # type: ignore[no-untyped-def]
    patch_httpx(_FakeResponse({}), raise_on_send=httpx.ConnectError("connection refused"))
    with pytest.raises(LLMError, match="network error"):
        OllamaBackend().complete("boom")


def test_is_available_when_tags_endpoint_answers(patch_httpx) -> None:  # type: ignore[no-untyped-def]
    patch_httpx(_FakeResponse({"models": []}))
    assert OllamaBackend().is_available() is True
    assert _FakeClient.last_url.endswith("/api/tags")


def test_is_available_false_on_network_error(patch_httpx) -> None:  # type: ignore[no-untyped-def]
    patch_httpx(_FakeResponse({}), raise_on_send=httpx.ConnectError("down"))
    assert OllamaBackend().is_available() is False
