"""Smoke tests — ports are runtime_checkable Protocols (no behavior yet)."""
from __future__ import annotations

from secopent.application.ports.loop_context import LoopContextBuilder
from secopent.application.ports.loop_gates import (
    PermitGate,
    PolicyGate,
    SchemaGate,
)
from secopent.application.ports.loop_proposer import LoopActionProposer
from secopent.application.ports.loop_state import LoopStateRepository
from secopent.application.ports.loop_step import LoopStepRepository


def test_all_loop_ports_are_runtime_checkable() -> None:
    """Any class with the right method signatures satisfies the Protocol."""
    class FakeProposer:
        def propose(self, ctx):  # type: ignore[no-untyped-def]
            return None

    class FakeStateRepo:
        def get(self, loop_id): return None  # type: ignore[no-untyped-def]
        def save(self, state): pass  # type: ignore[no-untyped-def]

    class FakeStepRepo:
        def add(self, step): pass  # type: ignore[no-untyped-def]
        def list_for_loop(self, loop_id): return []  # type: ignore[no-untyped-def]

    class FakeContextBuilder:
        def build(self, loop_id):  # type: ignore[no-untyped-def]
            return None

    class FakeSchemaGate:
        def check(self, action, context):  # type: ignore[no-untyped-def]
            return None

    class FakePolicyGate:
        def check(self, action, context):  # type: ignore[no-untyped-def]
            return None

    class FakePermitGate:
        def check(self, action, context):  # type: ignore[no-untyped-def]
            return None

    assert isinstance(FakeProposer(), LoopActionProposer)
    assert isinstance(FakeStateRepo(), LoopStateRepository)
    assert isinstance(FakeStepRepo(), LoopStepRepository)
    assert isinstance(FakeContextBuilder(), LoopContextBuilder)
    assert isinstance(FakeSchemaGate(), SchemaGate)
    assert isinstance(FakePolicyGate(), PolicyGate)
    assert isinstance(FakePermitGate(), PermitGate)
