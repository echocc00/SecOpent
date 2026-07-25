# src/secopent/infrastructure/db/job_models.py
"""ORM table for orchestrator jobs with a durable lease (§13, §7.3)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from .core_models import CoreBase


class CoreJob(CoreBase):
    __tablename__ = "core_jobs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    plan_step_key: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(
        String(160), nullable=False, unique=True, index=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    attempt: Mapped[int] = mapped_column(nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(nullable=False, default=3)
    lease_owner: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    result_digest: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    failure_class: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    dependencies: Mapped[list] = mapped_column(JSON, nullable=False)
