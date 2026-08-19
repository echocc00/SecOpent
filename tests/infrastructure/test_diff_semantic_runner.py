# tests/infrastructure/test_diff_semantic_runner.py
"""TDD tests for DiffSemanticRunner / HttpDiffSemanticRunner (v0.7.6).

The DIFF_SEMANTIC oracle executes a baseline request and an assertion request
over HTTP(S) and compares them. This runner is the pure infrastructure
transport: it executes ONE request dict and returns a normalized
DiffSemanticResponse. It decides nothing - the domain decide_diff_outcome does.
These tests use a duck-typed fake session, no external network.
"""
from __future__ import annotations

from typing import Any

from secopent.infrastructure.oracle.diff_semantic_runner import HttpDiffSemanticRunner


class _FakeResponse:
    def __init__(self, status: int, json_data: object | None = None) -> None:
        self.status_code = status
        self._json = json_data

    @property
    def text(self) -> str:
        # The runner reads body text only when content-type says JSON; the fake
        # always claims JSON so text is the JSON rendering path.
        return self._json if isinstance(self._json, str) else ""

    @property
    def headers(self) -> dict[str, str]:
        return {"content-type": "application/json"}

    def json(self) -> object:
        return self._json


class _FakeSession:
    """Duck-typed session; each call pops the next canned response."""

    def __init__(self, responses: list[_FakeResponse]) -> None:
        self._responses = responses
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def get(self, url: str, **kw: Any) -> _FakeResponse:
        self.calls.append(("GET", url, kw))
        return self._responses.pop(0)

    def request(self, method: str, url: str, **kw: Any) -> _FakeResponse:
        self.calls.append((method, url, kw))
        return self._responses.pop(0)


class _RaisingSession:
    """Session whose request raises a transport error."""

    def request(self, method: str, url: str, **kw: Any) -> Any:
        raise ConnectionError("boom")


def test_executes_baseline_and_assertion() -> None:
    session = _FakeSession(
        [_FakeResponse(200, {"id": 1002}), _FakeResponse(403, None)]
    )
    runner = HttpDiffSemanticRunner(session=session)

    first = runner.execute({"method": "GET", "url": "/a"})
    assert first.status == 200
    assert first.body == {"id": 1002}
    assert first.error == ""

    second = runner.execute({"method": "GET", "url": "/b"})
    assert second.status == 403
    assert second.body is None

    # The runner passed method + url correctly on both calls.
    assert [c[0] for c in session.calls] == ["GET", "GET"]
    assert [c[1] for c in session.calls] == ["/a", "/b"]


def test_transport_error_maps_status_zero() -> None:
    runner = HttpDiffSemanticRunner(session=_RaisingSession())
    result = runner.execute({"method": "GET", "url": "/x"})
    assert result.status == 0
    assert result.body is None
    assert "boom" in result.error


def test_body_json_content_json() -> None:
    # JSON-serializable dict body is sent as json=...
    session_json = _FakeSession([_FakeResponse(200, {})])
    runner_json = HttpDiffSemanticRunner(session=session_json)
    runner_json.execute({"method": "POST", "url": "/a", "body": {"q": 1}})
    call_json = session_json.calls[0][2]
    assert call_json.get("json") == {"q": 1}
    assert "content" not in call_json

    # str body is sent as content=..., not json.
    session_str = _FakeSession([_FakeResponse(200, {})])
    runner_str = HttpDiffSemanticRunner(session=session_str)
    runner_str.execute({"method": "POST", "url": "/b", "body": "raw=data"})
    call_str = session_str.calls[0][2]
    assert call_str.get("content") == "raw=data"
    assert "json" not in call_str


def test_with_session_swaps_runner() -> None:
    session = _FakeSession([_FakeResponse(201, {"ok": True})])
    runner = HttpDiffSemanticRunner(session=_FakeSession([])).with_session(session)
    result = runner.execute({"method": "GET", "url": "/s"})
    assert result.status == 201
    assert result.body == {"ok": True}
