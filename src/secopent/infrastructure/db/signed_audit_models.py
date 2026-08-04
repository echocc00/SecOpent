# src/secopent/infrastructure/db/signed_audit_models.py
"""ORM table for the signed audit chain (W3-C T2, H6).

Distinct from core_audit_events (the M0 queryable audit log, no signature):
core_signed_audit_events stores the Ed25519-signed hash chain so tamper-evidence
survives process restart. ``seq`` autoincrement preserves chain order on load.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from .core_models import CoreBase


class CoreSignedAuditEvent(CoreBase):
    __tablename__ = "core_signed_audit_events"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    signature: Mapped[str] = mapped_column(String(256), nullable=False)
