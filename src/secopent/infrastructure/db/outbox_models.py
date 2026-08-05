"""CoreAuditOutbox: transactional outbox rows for audit events (v0.3.0 T4).

Business writes and their audit events must be atomic, but the audit fan-out
(queryable log + signed chain) must not extend the business transaction -
that coupling is what produced the v4 lock contention. The daemon writes ONE
outbox row inside its short business transaction; the OutboxWorker drains
pending rows to ``core_audit_events`` + ``core_signed_audit_events``
asynchronously (default poll 1s). The queryable audit API is therefore
eventually consistent (delay <= poll interval); the signed chain stays
complete and ordered. Failed rows are flagged, never silently dropped.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .core_models import CoreBase


class CoreAuditOutbox(CoreBase):
    __tablename__ = "core_audit_outbox"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending", index=True
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    processed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
