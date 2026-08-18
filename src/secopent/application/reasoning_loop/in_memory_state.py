"""In-memory LoopState + LoopStep repositories (dev + tests).

Production wiring (v0.7.6) will add SQLAlchemy-backed repos in
``infrastructure/reasoning_loop/``. The orchestrator depends only on the
Protocols, not these classes.
"""
from __future__ import annotations

import threading

from ...domain.reasoning_loop.models import LoopId, LoopState, LoopStep
from ..ports.loop_state import LoopStateRepository
from ..ports.loop_step import LoopStepRepository


class InMemoryLoopStateRepository(LoopStateRepository):
    def __init__(self) -> None:
        self._states: dict[str, LoopState] = {}
        self._lock = threading.RLock()

    def get(self, loop_id: LoopId) -> LoopState | None:
        with self._lock:
            return self._states.get(loop_id.value)

    def save(self, state: LoopState) -> None:
        with self._lock:
            self._states[state.loop_id.value] = state


class InMemoryLoopStepRepository(LoopStepRepository):
    def __init__(self) -> None:
        self._steps: list[LoopStep] = []
        self._lock = threading.RLock()

    def add(self, step: LoopStep) -> None:
        with self._lock:
            self._steps.append(step)

    def list_for_loop(self, loop_id: LoopId) -> list[LoopStep]:
        with self._lock:
            return [s for s in self._steps if s.loop_id == loop_id]
