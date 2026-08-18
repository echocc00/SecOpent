"""LoopContextBuilder port — assembles the LoopContext for a given loop."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ...domain.reasoning_loop.models import LoopContext, LoopId


@runtime_checkable
class LoopContextBuilder(Protocol):
    def build(self, loop_id: LoopId) -> LoopContext: ...
