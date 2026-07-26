# src/secopent/infrastructure/db/update_models.py
"""SQLAlchemy ORM models for the UpdateManager bundle + activation pointer.

``CoreUpdateBundle`` stores one downloaded knowledge-layer bundle (catalog +
intel snapshot) staged for activation. ``CoreBundleActivation`` is the
single-row "active version" pointer table - the row is updated atomically by
``UpdateManager.activate()`` (Task 6) to switch the active bundle. Keeping
the pointer in its own table (rather than a boolean column on bundles) lets
us enforce the single-active invariant via primary-key uniqueness.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from .core_models import CoreBase


class CoreUpdateBundle(CoreBase):
    """Persisted knowledge-layer update bundle."""

    __tablename__ = "core_update_bundles"

    bundle_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    digest: Mapped[str] = mapped_column(String(80), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    staged_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CoreBundleActivation(CoreBase):
    """Single-row table recording the currently active bundle id.

    The ``singleton`` column is fixed to ``1`` and serves as the primary key
    so the table can never hold more than one row. ``UpdateManager`` updates
    the ``active_bundle_id`` column atomically to switch the active bundle.
    """

    __tablename__ = "core_bundle_activations"

    singleton: Mapped[int] = mapped_column(primary_key=True, autoincrement=False)
    active_bundle_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
