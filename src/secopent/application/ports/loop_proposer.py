"""Proposer port (spec §4) — anything that returns a ProposeAction given a LoopContext."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ...domain.reasoning_loop.models import LoopContext, ProposeAction


@runtime_checkable
class LoopActionProposer(Protocol):
    """Returns a ProposeAction or None when the backend is unavailable.

    The orchestrator treats ``None`` as a 1-step transient failure (no LLM
    punishment, but the step counter still advances). Throwing is reserved
    for unrecoverable errors.
    """

    def propose(self, context: LoopContext) -> ProposeAction | None: ...
