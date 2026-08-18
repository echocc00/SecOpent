"""LoopBudgetGate port — single-step budget cap enforcement (spec §6.1)."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ...domain.reasoning_loop.models import GateVerdict, ProposeAction


@runtime_checkable
class LoopBudgetGate(Protocol):
    def check(self, action: ProposeAction, proposed_tokens: int) -> GateVerdict: ...
