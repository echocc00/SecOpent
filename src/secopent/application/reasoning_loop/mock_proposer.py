# src/secopent/application/reasoning_loop/mock_proposer.py
"""MockLoopActionProposer — scripted ProposeAction queue (spec §4.4).

Used in tests + dev mode. The orchestrator treats ``None`` return as a
transient backend-unavailable step (1 step consumed, no progress).
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ...domain.reasoning_loop.models import LoopContext, ProposeAction
from ..ports.loop_proposer import LoopActionProposer


@dataclass(frozen=True, slots=True)
class ProposerCall:
    """Audit record of one Mock proposer call."""

    call_index: int
    context_hash: str
    action: ProposeAction | None


class MockLoopActionProposer(LoopActionProposer):
    def __init__(self, script: Iterable[ProposeAction]) -> None:
        self._script: list[ProposeAction] = list(script)
        self._index = 0
        self._history: list[ProposerCall] = []

    def propose(self, context: LoopContext) -> ProposeAction | None:
        action = (
            self._script[self._index]
            if self._index < len(self._script)
            else None
        )
        self._history.append(
            ProposerCall(
                call_index=self._index,
                context_hash=context.context_hash(),
                action=action,
            )
        )
        self._index += 1
        return action

    @property
    def history(self) -> list[ProposerCall]:
        return list(self._history)

    def reset(self) -> None:
        self._index = 0
        self._history.clear()
