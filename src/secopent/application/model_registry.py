# src/secopent/application/model_registry.py
"""ModelRegistry: versioned AppModel publish + per-assessment snapshots (§11.9).

Publishes signed AppModels, keeps full version history (a new version SUPERSEDES
the old one - old versions are never deleted, for audit/replay), and pins a
published version per Assessment via a snapshot id so an Assessment's logic tests
stay reproducible even as the model evolves. Cross-assessment reuse is just
snapshotting the same published version into another Assessment.
"""
from __future__ import annotations

from dataclasses import replace

from ..domain.appmodel.lifecycle import AppModelStatus
from ..domain.appmodel.models import AppModel
from ..domain.common.errors import DomainError


class ModelNotSignedError(DomainError):
    """Raised when publishing a model that is not SIGNED."""


class ModelNotFoundError(DomainError):
    """Raised when an app_id / snapshot is unknown."""


class ModelRegistry:
    """Versioned registry of published AppModels + per-assessment snapshots."""

    def __init__(self) -> None:
        self._history: dict[str, list[AppModel]] = {}
        self._snapshots: dict[str, AppModel] = {}

    def publish(self, model: AppModel) -> AppModel:
        """Publish a SIGNED model; supersede any currently-published version."""
        if model.status is not AppModelStatus.SIGNED:
            raise ModelNotSignedError(
                f"model {model.app_id} must be SIGNED to publish (is {model.status.value})"
            )
        # Supersede the currently published version (keep it in history).
        superseded_history = [
            replace(m, status=AppModelStatus.SUPERSEDED)
            if m.status is AppModelStatus.PUBLISHED
            else m
            for m in self._history.get(model.app_id, [])
        ]
        published = replace(model, status=AppModelStatus.PUBLISHED)
        superseded_history.append(published)
        self._history[model.app_id] = superseded_history
        return published

    def versions(self, app_id: str) -> tuple[AppModel, ...]:
        """Full version history for an app (oldest first; superseded retained)."""
        history = self._history.get(app_id)
        if not history:
            raise ModelNotFoundError(f"no published model for app_id={app_id}")
        return tuple(history)

    def current(self, app_id: str) -> AppModel:
        """The currently-published version for an app."""
        for model in reversed(self._history.get(app_id, [])):
            if model.status is AppModelStatus.PUBLISHED:
                return model
        raise ModelNotFoundError(f"no published model for app_id={app_id}")

    def snapshot_for_assessment(self, assessment_id: str, app_id: str) -> str:
        """Pin the current published version for an Assessment; return the snapshot id."""
        published = self.current(app_id)
        snapshot_id = f"appmodel-snap:{assessment_id}:{app_id}:{published.version}"
        self._snapshots[snapshot_id] = published
        return snapshot_id

    def get_snapshot(self, snapshot_id: str) -> AppModel:
        snapshot = self._snapshots.get(snapshot_id)
        if snapshot is None:
            raise ModelNotFoundError(f"unknown snapshot: {snapshot_id}")
        return snapshot
