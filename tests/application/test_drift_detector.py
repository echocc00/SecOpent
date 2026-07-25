"""TDD tests for DriftDetector (M3 Task 10, §11.9 re-import diff)."""
from __future__ import annotations

from secopent.application.drift_detector import DriftDetector
from secopent.domain.appmodel.models import AppModel, Transition


def _model(*transitions: Transition) -> AppModel:
    return AppModel(
        app_id="shop",
        version="1.0.0",
        states=("cart", "paid"),
        transitions=tuple(transitions),
    )


def _t(endpoint: str, params: tuple[str, ...] = ()) -> Transition:
    op_id = endpoint.replace(" ", "_").replace("/", "-").strip("-")
    return Transition(
        id=op_id, from_state="cart", to_state="paid", endpoint=endpoint, params=params
    )


def test_no_change_no_drift() -> None:
    current = _model(_t("GET /pets"), _t("POST /checkout"))
    report = DriftDetector().check(current, _model(_t("GET /pets"), _t("POST /checkout")))
    assert report.has_drift is False
    assert report.added == report.removed == report.changed == ()


def test_added_endpoint_detected() -> None:
    current = _model(_t("GET /pets"))
    reimported = _model(_t("GET /pets"), _t("DELETE /pets"))
    report = DriftDetector().check(current, reimported)
    assert report.has_drift is True
    assert report.added == ("DELETE /pets",)
    assert report.removed == ()


def test_removed_endpoint_detected() -> None:
    current = _model(_t("GET /pets"), _t("POST /checkout"))
    reimported = _model(_t("GET /pets"))
    report = DriftDetector().check(current, reimported)
    assert report.removed == ("POST /checkout",)


def test_changed_params_detected() -> None:
    current = _model(_t("GET /pets", params=("limit",)))
    reimported = _model(_t("GET /pets", params=("limit", "offset")))
    report = DriftDetector().check(current, reimported)
    assert report.changed == ("GET /pets",)
    assert report.added == () and report.removed == ()
