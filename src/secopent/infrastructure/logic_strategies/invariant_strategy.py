# src/secopent/infrastructure/logic_strategies/invariant_strategy.py
"""InvariantStrategy: business-invariant violation tests (§11.10, self-built).

There is no open-source equivalent for business-logic invariant violation, so
this strategy is built in-house. It parses each AppModel invariant of the form
``<field> <op> <number>`` (e.g. ``cart.total >= 0``), locates the referenced
field, and constructs an input that breaks the rule (``total = -1``). The
resulting LogicTestCase carries an idempotent signature so the same model always
regenerates the same test (CoverageMatrix dedupes on signature).
"""
from __future__ import annotations

import re

from secopent.domain.appmodel.logic import (
    LogicTestCase,
    LogicTestClass,
    compute_signature,
)
from secopent.domain.appmodel.models import AppModel, Field

# Independently versioned so a strategy change reshuffles signatures deliberately.
STRATEGY_VERSION = "1.0.0"

# ``<dotted.field> <op> <number>`` - the invariant shapes we can violate.
_INVARIANT_RE = re.compile(
    r"^\s*([\w.]+)\s*(>=|<=|==|>|<)\s*(-?\d+(?:\.\d+)?)\s*$"
)


def _violating_value(op: str, bound: float, field: Field | None) -> object:
    """Return a value that violates ``field <op> bound``."""
    is_int = field is not None and field.type.lower() == "int"

    def _num(value: float) -> object:
        return int(value) if is_int and float(value).is_integer() else value

    if op == ">=":  # must be >= bound -> go below
        return _num(bound - 1)
    if op == ">":  # must be > bound -> equal violates
        return _num(bound)
    if op == "<=":  # must be <= bound -> go above
        return _num(bound + 1)
    if op == "<":  # must be < bound -> equal violates
        return _num(bound)
    if op == "==":  # must equal bound -> differ
        return _num(bound + 1)
    return _num(bound)


class InvariantStrategy:
    """Generate invariant-violation logic tests from an AppModel."""

    strategy_version = STRATEGY_VERSION

    def generate(self, app_model: AppModel) -> tuple[LogicTestCase, ...]:
        """One LogicTestCase per violable invariant (empty if none)."""
        fields_by_name = {field.name: field for field in app_model.fields}
        cases: list[LogicTestCase] = []
        for invariant in app_model.invariants:
            match = _INVARIANT_RE.match(invariant.expr)
            if match is None:
                continue  # non-numeric invariant - cannot construct a violation
            lhs, op, number_str = match.groups()
            field_name = lhs.rsplit(".", 1)[-1]
            field = fields_by_name.get(field_name)
            bound = float(number_str)
            value = _violating_value(op, bound, field)
            signature = compute_signature(
                app_model_digest=app_model.digest,
                test_class=LogicTestClass.INVARIANT_VIOLATION,
                strategy_version=self.strategy_version,
                target=invariant.id,
            )
            cases.append(
                LogicTestCase(
                    test_class=LogicTestClass.INVARIANT_VIOLATION,
                    app_model_digest=app_model.digest,
                    target=invariant.id,
                    description=(
                        f"violate invariant {invariant.id} ({invariant.expr}): "
                        f"set {field_name}={value}"
                    ),
                    inputs=((field_name, value),),
                    signature=signature,
                )
            )
        return tuple(cases)
