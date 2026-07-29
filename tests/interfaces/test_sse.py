# tests/interfaces/test_sse.py
"""TDD tests for the SSE backpressure stream (P3 §3.5 / T2).

The mechanism is exercised directly via ``event_stream`` with injected async
snapshots (no database, no real client); each test drives the async generator
with ``asyncio.run`` so no pytest-asyncio dependency is required. The endpoint
test streams a real (non-existent) assessment, which terminates on the
``not_found`` stop condition so the test cannot hang.
"""
from __future__ import annotations

import asyncio
from typing import Any

from fastapi.testclient import TestClient

from secopent.interfaces.api.main import create_app
from secopent.interfaces.api.sse import event_stream, sse_frame, state_signature


def _collect(aiter) -> list[str]:
    async def run() -> list[str]:
        return [frame async for frame in aiter]

    return asyncio.run(run())


def test_sse_frame_format() -> None:
    assert sse_frame({"status": "running"}) == 'data: {"status": "running"}\n\n'


def test_signature_is_stable_and_change_sensitive() -> None:
    a = [{"assessment_id": "x", "status": "running"}]
    assert state_signature(a) == state_signature(list(a))
    assert state_signature(a) != state_signature(
        [{"assessment_id": "x", "status": "completed"}]
    )


def test_dedup_emits_only_on_change() -> None:
    async def snapshot() -> list[dict[str, Any]]:
        return [{"assessment_id": "x", "status": "running"}]

    frames = _collect(event_stream(snapshot, poll_interval=0, max_iterations=3))
    # Three polls of unchanged state emit exactly one batch.
    assert frames == ['data: {"assessment_id": "x", "status": "running"}\n\n']


def test_backpressure_bounds_the_queue() -> None:
    async def snapshot() -> list[dict[str, Any]]:
        return [{"i": i} for i in range(100)]

    # One tick with 100 events through a 64-slot queue: the excess is dropped
    # (no unbounded growth / OOM), exactly 64 frames are yielded.
    frames = _collect(
        event_stream(snapshot, queue_size=64, poll_interval=0, max_iterations=1)
    )
    assert len(frames) == 64


def test_queue_size_must_be_positive() -> None:
    async def snapshot() -> list[dict[str, Any]]:
        return []

    try:
        _collect(event_stream(snapshot, queue_size=0, max_iterations=1))
    except ValueError:
        pass
    else:  # pragma: no cover - guard for clarity
        raise AssertionError("queue_size=0 should raise ValueError")


def test_disconnect_cleanup_terminates_the_stream() -> None:
    calls = {"n": 0}

    async def disconnected() -> bool:
        calls["n"] += 1
        return calls["n"] > 2  # disconnect on the 3rd check

    state = {"i": 0}

    async def snapshot() -> list[dict[str, Any]]:
        state["i"] += 1
        return [{"n": state["i"]}]

    frames = _collect(event_stream(snapshot, poll_interval=0, is_disconnected=disconnected))
    # Two polls emit before the disconnect is observed; then the loop stops
    # (this test would hang if disconnect cleanup were broken).
    assert len(frames) == 2


def test_stop_when_terminates_after_terminal_snapshot() -> None:
    states = iter(
        [
            [{"assessment_id": "x", "status": "running"}],
            [{"assessment_id": "x", "status": "completed"}],
        ]
    )

    async def snapshot() -> list[dict[str, Any]]:
        return next(states)

    def stop_when(events: list[dict[str, Any]]) -> bool:
        return bool(events) and events[0]["status"] == "completed"

    frames = _collect(
        event_stream(snapshot, poll_interval=0, stop_when=stop_when, max_iterations=10)
    )
    assert len(frames) == 2
    assert "completed" in frames[-1]


def test_endpoint_streams_not_found_and_terminates() -> None:
    client = TestClient(create_app())
    with client.stream("GET", "/assessments/does-not-exist/events") as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        body = "".join(response.iter_text())
    # Unknown assessment -> "not_found" snapshot -> stop condition closes stream.
    assert "not_found" in body
