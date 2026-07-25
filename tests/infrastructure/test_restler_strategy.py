"""TDD tests for RestlerStrategy (M3 Task 6, §11.10 sequence tests).

From the AppModel state machine the strategy derives replay (double-submit a
non-idempotent transition), skip-step (call a transition without its
prerequisite), and out-of-order (call a transition before its prerequisite).
RESTler binary is M5; the deterministic derivation from transitions is tested.
"""
from __future__ import annotations

from secopent.domain.appmodel.logic import LogicTestClass
from secopent.domain.appmodel.models import AppModel, Transition
from secopent.infrastructure.logic_strategies.restler_strategy import RestlerStrategy


def _model() -> AppModel:
    # Chain: add(idempotent) anonymous->cart, then checkout(non-idempotent) cart->paid.
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
    )


def test_replay_targets_non_idempotent_only() -> None:
    cases = RestlerStrategy().generate(_model())
    replays = [c for c in cases if c.test_class is LogicTestClass.REPLAY]
    assert len(replays) == 1
    assert replays[0].target == "checkout"  # 'add' is idempotent -> not replayed


def test_skip_step_for_adjacent_chain() -> None:
    cases = RestlerStrategy().generate(_model())
    skips = [c for c in cases if c.test_class is LogicTestClass.SKIP_STEP]
    assert len(skips) == 1
    assert skips[0].target == "add->checkout"


def test_out_of_order_for_adjacent_chain() -> None:
    cases = RestlerStrategy().generate(_model())
    ooo = [c for c in cases if c.test_class is LogicTestClass.OUT_OF_ORDER]
    assert len(ooo) == 1
    assert ooo[0].target == "checkout->add"


def test_signatures_are_idempotent() -> None:
    a = RestlerStrategy().generate(_model())
    b = RestlerStrategy().generate(_model())
    assert [c.signature for c in a] == [c.signature for c in b]


def test_signatures_unique_across_cases() -> None:
    cases = RestlerStrategy().generate(_model())
    signatures = [c.signature for c in cases]
    assert len(signatures) == len(set(signatures))
