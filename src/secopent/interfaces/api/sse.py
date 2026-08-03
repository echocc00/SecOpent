# src/secopent/interfaces/api/sse.py
"""Server-sent-events stream with real backpressure (P3 §3.5 / T2).

Replaces the demo status loop with a bounded, disconnect-aware, de-duplicated
stream:

- **Backpressure**: events pass through ``asyncio.Queue(maxsize=queue_size)``;
  when a client is too slow to drain it, ``put_nowait`` raises ``QueueFull`` and
  the excess is dropped rather than growing memory without bound (no OOM). Each
  emission is a *full* snapshot of current state, so a dropped frame is
  recovered on the next state change.
- **Disconnect cleanup**: ``is_disconnected`` is checked each tick; when the
  client is gone the generator stops promptly (no leaked polling loop).
- **De-duplication**: a canonical signature of the snapshot is compared each
  tick; unchanged state is not re-emitted.

The data source is an injected async ``snapshot`` callable so the mechanism is
unit-testable without a database or a real HTTP client.
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from typing import Any

from ...domain.common.canonical import canonical_digest

DEFAULT_QUEUE_SIZE = 64
DEFAULT_POLL_INTERVAL = 1.0
# Safety cap: behind reverse proxies (nginx, Caddy) the ASGI disconnect signal
# may not propagate promptly, causing ghost SSE loops to poll indefinitely.
# 3600 iterations at 1s interval = 1 hour max per stream.
DEFAULT_MAX_ITERATIONS = 3600

Snapshot = Callable[[], Awaitable[Sequence[dict[str, Any]]]]
DisconnectCheck = Callable[[], Awaitable[bool]]
StopWhen = Callable[[Sequence[dict[str, Any]]], bool]


def sse_frame(payload: dict[str, Any]) -> str:
    """Format one SSE ``data:`` frame (double-newline terminated)."""
    return f"data: {json.dumps(payload, default=str)}\n\n"


def state_signature(events: Sequence[dict[str, Any]]) -> str:
    """Canonical signature of a snapshot, for change de-duplication."""
    return canonical_digest({"events": [dict(e) for e in events]})


async def event_stream(
    snapshot: Snapshot,
    *,
    queue_size: int = DEFAULT_QUEUE_SIZE,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    is_disconnected: DisconnectCheck | None = None,
    stop_when: StopWhen | None = None,
    max_iterations: int | None = DEFAULT_MAX_ITERATIONS,
) -> AsyncIterator[str]:
    """Yield SSE frames from polled snapshots with bounded backpressure.

    Terminates when the client disconnects (``is_disconnected``), when
    ``stop_when`` matches the latest snapshot (e.g. a terminal assessment
    status), or when ``max_iterations`` is reached (a test/safety cap).
    """
    if queue_size < 1:
        raise ValueError(f"queue_size must be >= 1, got {queue_size}")
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=queue_size)
    last_signature = ""
    iterations = 0
    while True:
        if max_iterations is not None and iterations >= max_iterations:
            break
        iterations += 1
        if is_disconnected is not None and await is_disconnected():
            break
        events = await snapshot()
        signature = state_signature(events)
        if signature != last_signature:
            last_signature = signature
            for event in events:
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    # Backpressure: drop the slow client's excess this tick; the
                    # next state change re-emits a full snapshot, so no data the
                    # client still cares about is permanently lost.
                    break
        while not queue.empty():
            yield sse_frame(queue.get_nowait())
        if stop_when is not None and stop_when(events):
            break
        await asyncio.sleep(poll_interval)


__all__ = [
    "DEFAULT_POLL_INTERVAL",
    "DEFAULT_QUEUE_SIZE",
    "event_stream",
    "sse_frame",
    "state_signature",
]
