"""TDD tests for LogicTestGenerator orchestration (M3 Task 5, §11.10 + ADR-012).

The generator runs the registered strategies over a signed AppModel and produces
all five logic test classes. Generation is a pure function of the model: same
model -> same signatures (idempotent), and generate_incremental regenerates only
cases whose signature changed after a model micro-edit.
"""
from __future__ import annotations

import pytest

from secopent.application.logic_generator import LogicTestGenerator
from secopent.domain.appmodel.logic import LogicTestClass
from secopent.domain.appmodel.models import AppModel, Field, Invariant, Transition
from secopent.infrastructure.logic_strategies.invariant_strategy import InvariantStrategy
from secopent.infrastructure.logic_strategies.restler_strategy import RestlerStrategy
from secopent.infrastructure.logic_strategies.schemathesis_strategy import (
    SchemathesisStrategy,
)


def _model() -> AppModel:
    return AppModel(
        app_id="shop",
        version="1.0.0",
        states=("anonymous", "cart", "paid"),
        transitions=(
            Transition(
                id="add",
                from_state="anonymous",
                to_state="cart",
                endpoint="POST /add",
                idempotent=True,
            ),
            Transition(
                id="checkout",
                from_state="cart",
                to_state="paid",
                endpoint="POST /checkout",
                idempotent=False,
            ),
        ),
        invariants=(Invariant(id="i1", expr="cart.total >= 0"),),
        fields=(Field(name="qty", type="int", range=(0, 100), trusted_source="client"),),
    )


@pytest.fixture
def generator() -> LogicTestGenerator:
    return LogicTestGenerator(
        [RestlerStrategy(), SchemathesisStrategy(), InvariantStrategy()]
    )


def test_generates_all_five_test_classes(generator: LogicTestGenerator) -> None:
    cases = generator.generate(_model())
    classes = {c.test_class for c in cases}
    assert classes == {
        LogicTestClass.REPLAY,
        LogicTestClass.SKIP_STEP,
        LogicTestClass.OUT_OF_ORDER,
        LogicTestClass.BOUNDARY,
        LogicTestClass.INVARIANT_VIOLATION,
    }


def test_generation_is_idempotent(generator: LogicTestGenerator) -> None:
    a = generator.generate(_model())
    b = generator.generate(_model())
    assert [c.signature for c in a] == [c.signature for c in b]


def test_all_cases_carry_model_digest(generator: LogicTestGenerator) -> None:
    model = _model()
    cases = generator.generate(model)
    assert all(c.app_model_digest == model.digest for c in cases)


def test_signatures_globally_unique(generator: LogicTestGenerator) -> None:
    signatures = [c.signature for c in generator.generate(_model())]
    assert len(signatures) == len(set(signatures))


def test_incremental_skips_known_signatures(generator: LogicTestGenerator) -> None:
    model = _model()
    all_cases = generator.generate(model)
    known = {all_cases[0].signature, all_cases[1].signature}
    fresh = generator.generate_incremental(model, known)
    fresh_signatures = {c.signature for c in fresh}
    assert known.isdisjoint(fresh_signatures)
    assert len(fresh) == len(all_cases) - 2


def test_incremental_regenerates_changed_model(generator: LogicTestGenerator) -> None:
    model = _model()
    original = {c.signature for c in generator.generate(model)}
    # Micro-edit: tighten the qty range -> boundary signatures change.
    edited = AppModel(
        app_id="shop",
        version="1.0.0",
        states=("anonymous", "cart", "paid"),
        transitions=model.transitions,
        invariants=model.invariants,
        fields=(Field(name="qty", type="int", range=(0, 50), trusted_source="client"),),
    )
    fresh = generator.generate_incremental(edited, original)
    # At least the boundary cases changed; unchanged cases are skipped.
    assert fresh, "a model micro-edit must regenerate the affected cases"
    assert all(c.signature not in original for c in fresh)
