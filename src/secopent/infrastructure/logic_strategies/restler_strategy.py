# src/secopent/infrastructure/logic_strategies/restler_strategy.py
"""RestlerStrategy: sequence tests - skip-step / out-of-order / replay (§11.10).

Adopts the RESTler approach (ADR-012): from the AppModel state machine it derives
three classes of sequence-logic tests.

- **replay**: call a non-idempotent transition twice (e.g. charge twice);
- **skip_step**: for a chain A->B->C, call the later transition without the
  required earlier one (skip B);
- **out_of_order**: call a later transition before its prerequisite.

Production delegates sequence generation to the RESTler engine via the M1
adapter; the deterministic derivation from transitions is what is unit-tested
here (RESTler binary is M5). Each case carries an idempotent signature.
"""
from __future__ import annotations

from secopent.domain.appmodel.logic import (
    LogicTestCase,
    LogicTestClass,
    compute_signature,
)
from secopent.domain.appmodel.models import AppModel

STRATEGY_VERSION = "1.0.0"


class RestlerStrategy:
    """Generate skip-step / out-of-order / replay tests from an AppModel."""

    strategy_version = STRATEGY_VERSION

    def generate(self, app_model: AppModel) -> tuple[LogicTestCase, ...]:
        cases: list[LogicTestCase] = []
        cases.extend(self._replay(app_model))
        cases.extend(self._skip_step(app_model))
        cases.extend(self._out_of_order(app_model))
        return tuple(cases)

    def _case(
        self,
        app_model: AppModel,
        test_class: LogicTestClass,
        target: str,
        description: str,
        inputs: tuple[tuple[str, object], ...] = (),
    ) -> LogicTestCase:
        return LogicTestCase(
            test_class=test_class,
            app_model_digest=app_model.digest,
            target=target,
            description=description,
            inputs=inputs,
            signature=compute_signature(
                app_model_digest=app_model.digest,
                test_class=test_class,
                strategy_version=self.strategy_version,
                target=target,
            ),
        )

    def _replay(self, app_model: AppModel) -> list[LogicTestCase]:
        """Replay each non-idempotent transition (double-submit)."""
        cases = []
        for t in app_model.transitions:
            if t.idempotent:
                continue
            cases.append(
                self._case(
                    app_model,
                    LogicTestClass.REPLAY,
                    t.id,
                    f"replay non-idempotent transition {t.endpoint} twice",
                    (("repeat_endpoint", t.endpoint), ("times", 2)),
                )
            )
        return cases

    def _adjacent_pairs(self, app_model: AppModel) -> list[tuple]:
        """Transition pairs where t1 feeds t2 (t1.to_state == t2.from_state)."""
        pairs = []
        for t1 in app_model.transitions:
            for t2 in app_model.transitions:
                if t1.id != t2.id and t1.to_state == t2.from_state:
                    pairs.append((t1, t2))
        return pairs

    def _skip_step(self, app_model: AppModel) -> list[LogicTestCase]:
        """For each chain t1->t2, call t2 without the prerequisite t1."""
        cases = []
        for t1, t2 in self._adjacent_pairs(app_model):
            cases.append(
                self._case(
                    app_model,
                    LogicTestClass.SKIP_STEP,
                    f"{t1.id}->{t2.id}",
                    f"skip {t1.endpoint}: call {t2.endpoint} directly",
                    (("call", t2.endpoint), ("skip", t1.endpoint)),
                )
            )
        return cases

    def _out_of_order(self, app_model: AppModel) -> list[LogicTestCase]:
        """For each chain t1->t2, call t2 before t1."""
        cases = []
        for t1, t2 in self._adjacent_pairs(app_model):
            cases.append(
                self._case(
                    app_model,
                    LogicTestClass.OUT_OF_ORDER,
                    f"{t2.id}->{t1.id}",
                    f"call {t2.endpoint} before prerequisite {t1.endpoint}",
                    (("order", (t2.endpoint, t1.endpoint)),),
                )
            )
        return cases
