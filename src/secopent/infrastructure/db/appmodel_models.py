# src/secopent/infrastructure/db/appmodel_models.py
"""ORM table for versioned, signed AppModels (§4.6/§11.9).

An AppModel's identity is the composite (app_id, version); multiple versions of
an app coexist (a new version supersedes the old, which is retained for
audit/replay). Nested parts (transitions, invariants, fields, roles,
idempotency) are stored as JSON.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from .core_models import CoreBase


class CoreAppModel(CoreBase):
    __tablename__ = "core_appmodels"
    app_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[str] = mapped_column(String(32), primary_key=True)
    states: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    transitions: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    invariants: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    fields: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    roles: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    idempotency: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    out_of_scope_rules: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    digest: Mapped[str] = mapped_column(String(80), nullable=False)
    signature: Mapped[str | None] = mapped_column(String(256), nullable=True)
