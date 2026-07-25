"""TDD tests for ModelRegistry (M3 Task 9, §11.9 versioned publish + snapshots)."""
from __future__ import annotations

import pytest

from secopent.application.model_registry import (
    ModelNotFoundError,
    ModelNotSignedError,
    ModelRegistry,
)
from secopent.domain.appmodel.lifecycle import AppModelStatus
from secopent.domain.appmodel.models import AppModel, Transition


def _signed(version: str = "1.0.0", app_id: str = "shop") -> AppModel:
    return AppModel(
        app_id=app_id,
        version=version,
        states=("cart", "paid"),
        transitions=(
            Transition(
                id="checkout",
                from_state="cart",
                to_state="paid",
                endpoint="POST /checkout",
            ),
        ),
        status=AppModelStatus.SIGNED,
        signature="sig-abc",
    )


def test_publish_signed_model() -> None:
    registry = ModelRegistry()
    published = registry.publish(_signed())
    assert published.status is AppModelStatus.PUBLISHED


def test_publish_rejects_unsigned() -> None:
    registry = ModelRegistry()
    draft = AppModel(app_id="shop", version="1.0.0", states=("cart",))
    with pytest.raises(ModelNotSignedError):
        registry.publish(draft)


def test_supersede_retains_old_version() -> None:
    registry = ModelRegistry()
    registry.publish(_signed(version="1.0.0"))
    registry.publish(_signed(version="2.0.0"))
    versions = registry.versions("shop")
    assert [v.version for v in versions] == ["1.0.0", "2.0.0"]
    # Old version is SUPERSEDED but NOT deleted.
    assert versions[0].status is AppModelStatus.SUPERSEDED
    assert versions[1].status is AppModelStatus.PUBLISHED


def test_current_returns_latest_published() -> None:
    registry = ModelRegistry()
    registry.publish(_signed(version="1.0.0"))
    registry.publish(_signed(version="2.0.0"))
    assert registry.current("shop").version == "2.0.0"


def test_snapshot_pins_version_for_assessment() -> None:
    registry = ModelRegistry()
    registry.publish(_signed(version="1.0.0"))
    snap_id = registry.snapshot_for_assessment("assess-1", "shop")
    snapshot = registry.get_snapshot(snap_id)
    assert snapshot.version == "1.0.0"
    # Publishing a new version does not move the existing snapshot.
    registry.publish(_signed(version="2.0.0"))
    assert registry.get_snapshot(snap_id).version == "1.0.0"


def test_cross_assessment_reuse_same_snapshot() -> None:
    registry = ModelRegistry()
    registry.publish(_signed(version="1.0.0"))
    snap_a = registry.snapshot_for_assessment("assess-1", "shop")
    snap_b = registry.snapshot_for_assessment("assess-2", "shop")
    assert registry.get_snapshot(snap_a).digest == registry.get_snapshot(snap_b).digest


def test_unknown_app_and_snapshot_raise() -> None:
    registry = ModelRegistry()
    with pytest.raises(ModelNotFoundError):
        registry.current("missing")
    with pytest.raises(ModelNotFoundError):
        registry.get_snapshot("nope")
