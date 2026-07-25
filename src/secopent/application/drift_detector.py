# src/secopent/application/drift_detector.py
"""DriftDetector: detect AppModel drift on re-import (§11.9, ADR-005).

When an API spec / traffic is re-imported, the detector diffs the new model
against the current one and reports added / removed / changed endpoints. Drift
means the model is stale: the LogicTestGenerator should regenerate (only the
changed signatures, via the idempotent signature scheme) and the changed model
goes back to DRAFT for re-validation. CI can run this on a schedule.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..domain.appmodel.models import AppModel


@dataclass(frozen=True, slots=True)
class DriftReport:
    """The endpoint-level diff between the current and a re-imported model."""

    app_id: str
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    changed: tuple[str, ...] = ()

    @property
    def has_drift(self) -> bool:
        return bool(self.added or self.removed or self.changed)


class DriftDetector:
    """Diff a re-imported model against the current one."""

    def check(self, current: AppModel, reimported: AppModel) -> DriftReport:
        """Compare transitions by endpoint; flag added/removed/changed (params)."""
        current_eps = {t.endpoint: t for t in current.transitions}
        new_eps = {t.endpoint: t for t in reimported.transitions}

        added = tuple(sorted(set(new_eps) - set(current_eps)))
        removed = tuple(sorted(set(current_eps) - set(new_eps)))
        changed = tuple(
            sorted(
                endpoint
                for endpoint in set(current_eps) & set(new_eps)
                if current_eps[endpoint].params != new_eps[endpoint].params
                or current_eps[endpoint].idempotent != new_eps[endpoint].idempotent
            )
        )
        return DriftReport(
            app_id=current.app_id, added=added, removed=removed, changed=changed
        )
