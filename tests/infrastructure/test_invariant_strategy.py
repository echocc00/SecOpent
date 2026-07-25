"""TDD tests for InvariantStrategy (M3 Task 8, §11.10 self-built).

The invariant strategy turns AppModel invariants (e.g. ``cart.total >= 0``) into
violation tests: it parses the invariant, finds the referenced field, and
constructs an input that breaks the rule (total=-1). There is no open-source
equivalent for business-invariant violation, so this is built in-house. Each
generated case carries an idempotent signature (same model -> same signature).
"""
from __future__ import annotations

from secopent.domain.appmodel.logic import LogicTestCase, LogicTestClass, compute_signature
from secopent.domain.appmodel.models import AppModel, Field, Invariant
from secopent.infrastructure.logic_strategies.invariant_strategy import InvariantStrategy


def _model(*invariants: Invariant, fields: tuple[Field, ...] = ()) -> AppModel:
    if not fields:
        fields = (
            Field(name="total", type="int", range=(-100, 10000), trusted_source="server"),
            Field(name="qty", type="int", range=(0, 100), trusted_source="client"),
        )
    return AppModel(
        app_id="shop",
        version="1.0.0",
        states=("cart", "paid"),
        invariants=tuple(invariants),
        fields=fields,
    )


def test_generates_violation_for_lower_bound() -> None:
    model = _model(Invariant(id="i1", expr="cart.total >= 0"))
    cases = InvariantStrategy().generate(model)
    assert len(cases) == 1
    case = cases[0]
    assert case.test_class is LogicTestClass.INVARIANT_VIOLATION
    assert dict(case.inputs)["total"] == -1  # breaks total >= 0


def test_generates_violation_for_upper_bound() -> None:
    model = _model(Invariant(id="i1", expr="qty <= 100"))
    cases = InvariantStrategy().generate(model)
    assert dict(cases[0].inputs)["qty"] == 101  # breaks qty <= 100


def test_one_case_per_invariant() -> None:
    model = _model(
        Invariant(id="i1", expr="cart.total >= 0"),
        Invariant(id="i2", expr="qty <= 100"),
    )
    cases = InvariantStrategy().generate(model)
    assert len(cases) == 2
    assert {c.target for c in cases} == {"i1", "i2"}


def test_case_carries_app_model_digest() -> None:
    model = _model(Invariant(id="i1", expr="cart.total >= 0"))
    case = InvariantStrategy().generate(model)[0]
    assert case.app_model_digest == model.digest


def test_signature_is_idempotent() -> None:
    model = _model(Invariant(id="i1", expr="cart.total >= 0"))
    cases_a = InvariantStrategy().generate(model)
    cases_b = InvariantStrategy().generate(model)
    assert cases_a[0].signature == cases_b[0].signature
    assert cases_a[0].signature.startswith("sha256:")


def test_signature_differs_per_invariant() -> None:
    model = _model(
        Invariant(id="i1", expr="cart.total >= 0"),
        Invariant(id="i2", expr="qty <= 100"),
    )
    cases = InvariantStrategy().generate(model)
    assert cases[0].signature != cases[1].signature


def test_compute_signature_deterministic() -> None:
    sig1 = compute_signature(
        app_model_digest="sha256:abc",
        test_class=LogicTestClass.INVARIANT_VIOLATION,
        strategy_version="1.0.0",
        target="i1",
    )
    sig2 = compute_signature(
        app_model_digest="sha256:abc",
        test_class=LogicTestClass.INVARIANT_VIOLATION,
        strategy_version="1.0.0",
        target="i1",
    )
    assert sig1 == sig2


def test_no_invariants_yields_no_cases() -> None:
    model = _model()
    assert InvariantStrategy().generate(model) == ()


def test_returns_logic_test_cases() -> None:
    model = _model(Invariant(id="i1", expr="cart.total >= 0"))
    assert all(isinstance(c, LogicTestCase) for c in InvariantStrategy().generate(model))
