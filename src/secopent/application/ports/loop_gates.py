"""Three-gate ports (spec §6)."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ...domain.reasoning_loop.models import (
    GateVerdict,
    LoopContext,
    ProposeAction,
)


@runtime_checkable
class SchemaGate(Protocol):
    def check(self, action: ProposeAction, context: LoopContext) -> GateVerdict: ...


@runtime_checkable
class PolicyGate(Protocol):
    def check(self, action: ProposeAction, context: LoopContext) -> GateVerdict: ...


@runtime_checkable
class PermitGate(Protocol):
    def check(self, action: ProposeAction, context: LoopContext) -> GateVerdict: ...
