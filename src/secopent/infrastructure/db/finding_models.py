# src/secopent/infrastructure/db/finding_models.py
"""ORM table for correlated findings (§13)."""
from __future__ import annotations

from sqlalchemy import JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from .core_models import CoreBase


class CoreFinding(CoreBase):
    __tablename__ = "core_findings"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    asset: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    cwe: Mapped[list] = mapped_column(JSON, nullable=False)
    cve: Mapped[list] = mapped_column(JSON, nullable=False)
    owasp: Mapped[list] = mapped_column(JSON, nullable=False)
    observation_ids: Mapped[list] = mapped_column(JSON, nullable=False)
    evidence_ids: Mapped[list] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
