"""LoopStateRepository port — one row per loop."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ...domain.reasoning_loop.models import LoopId, LoopState


@runtime_checkable
class LoopStateRepository(Protocol):
    def get(self, loop_id: LoopId) -> LoopState | None: ...
    def save(self, state: LoopState) -> None: ...
