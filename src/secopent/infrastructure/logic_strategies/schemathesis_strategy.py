# src/secopent/infrastructure/logic_strategies/schemathesis_strategy.py
"""SchemathesisStrategy: boundary tests from AppModel field ranges (§11.10).

Adopts the Schemathesis approach (ADR-012): for each AppModel field with a valid
range it generates out-of-bounds inputs (just below the low bound and just above
the high bound - e.g. qty=-1, qty=101) as property-style boundary tests. Each
case carries an idempotent signature.
"""
from __future__ import annotations

from secopent.domain.appmodel.logic import (
    LogicTestCase,
    LogicTestClass,
    compute_signature,
)
from secopent.domain.appmodel.models import AppModel, Field

STRATEGY_VERSION = "1.0.0"


def _boundary_values(field: Field) -> list[tuple[str, object]]:
    """Return (label, value) out-of-bounds probes for a ranged field."""
    if field.range is None or len(field.range) != 2:
        return []
    low, high = field.range
    is_int = field.type.lower() == "int"
    probes: list[tuple[str, object]] = []
    if isinstance(low, int | float) and not isinstance(low, bool):
        below = low - 1
        probes.append(("below_low", int(below) if is_int else below))
    if isinstance(high, int | float) and not isinstance(high, bool):
        above = high + 1
        probes.append(("above_high", int(above) if is_int else above))
    return probes


class SchemathesisStrategy:
    """Generate boundary-violation tests from AppModel field ranges."""

    strategy_version = STRATEGY_VERSION

    def generate(self, app_model: AppModel) -> tuple[LogicTestCase, ...]:
        cases: list[LogicTestCase] = []
        for field in app_model.fields:
            for label, value in _boundary_values(field):
                target = f"{field.name}:{label}"
                cases.append(
                    LogicTestCase(
                        test_class=LogicTestClass.BOUNDARY,
                        app_model_digest=app_model.digest,
                        target=target,
                        description=(
                            f"boundary probe {field.name}={value} ({label}) "
                            f"outside range {field.range}"
                        ),
                        inputs=((field.name, value),),
                        signature=compute_signature(
                            app_model_digest=app_model.digest,
                            test_class=LogicTestClass.BOUNDARY,
                            strategy_version=self.strategy_version,
                            target=target,
                        ),
                    )
                )
        return tuple(cases)
