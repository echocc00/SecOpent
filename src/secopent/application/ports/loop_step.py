"""LoopStepRepository port — append-only step records."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ...domain.reasoning_loop.models import LoopId, LoopStep


@runtime_checkable
class LoopStepRepository(Protocol):
    def add(self, step: LoopStep) -> None: ...
    def list_for_loop(self, loop_id: LoopId) -> list[LoopStep]: ...
