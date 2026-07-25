# src/secopent/infrastructure/db/report_models.py
"""ORM table for rendered reports (§13)."""
from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, String
from sqlalchemy.orm import Mapped, mapped_column

from .core_models import CoreBase


class CoreReport(CoreBase):
    __tablename__ = "core_reports"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    sections: Mapped[list] = mapped_column(JSON, nullable=False)
    finding_count: Mapped[int] = mapped_column(nullable=False)
    coverage_rate: Mapped[float] = mapped_column(Float, nullable=False)
    completeness_ok: Mapped[bool] = mapped_column(Boolean, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    digest: Mapped[str] = mapped_column(String(80), nullable=False)
