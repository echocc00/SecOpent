"""TDD tests for SchemathesisStrategy (M3 Task 7, §11.10 boundary tests).

For each AppModel field with a valid range, the strategy generates out-of-bounds
probes (just below low, just above high). Schemathesis engine is M5; the
deterministic boundary derivation from field ranges is tested.
"""
from __future__ import annotations

from secopent.domain.appmodel.logic import LogicTestClass
from secopent.domain.appmodel.models import AppModel, Field
from secopent.infrastructure.logic_strategies.schemathesis_strategy import (
    SchemathesisStrategy,
)


def _model(*fields: Field) -> AppModel:
    return AppModel(
        app_id="shop",
        version="1.0.0",
        states=("cart",),
        fields=tuple(fields),
    )


def test_boundary_probes_below_and_above() -> None:
    model = _model(Field(name="qty", type="int", range=(0, 100), trusted_source="client"))
    cases = SchemathesisStrategy().generate(model)
    values = {dict(c.inputs)["qty"] for c in cases}
    assert values == {-1, 101}
    assert all(c.test_class is LogicTestClass.BOUNDARY for c in cases)


def test_field_without_range_yields_nothing() -> None:
    model = _model(Field(name="note", type="str", range=None, trusted_source="client"))
    assert SchemathesisStrategy().generate(model) == ()


def test_multiple_fields() -> None:
    model = _model(
        Field(name="qty", type="int", range=(0, 100), trusted_source="client"),
        Field(name="price", type="int", range=(1, 9999), trusted_source="client"),
    )
    cases = SchemathesisStrategy().generate(model)
    # 2 probes each for 2 fields.
    assert len(cases) == 4


def test_signatures_idempotent_and_unique() -> None:
    model = _model(Field(name="qty", type="int", range=(0, 100), trusted_source="client"))
    a = SchemathesisStrategy().generate(model)
    b = SchemathesisStrategy().generate(model)
    assert [c.signature for c in a] == [c.signature for c in b]
    signatures = [c.signature for c in a]
    assert len(signatures) == len(set(signatures))
