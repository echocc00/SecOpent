# src/secopent/infrastructure/db/confirmed_finding_models.py
"""ORM table for oracle-confirmed findings (W3-A T3).

A ConfirmedFinding is the oracle-verified promotion of a Finding: the
candidate_id is the source Finding's id. Stored separately from
core_findings so the domain's Finding (low-trust, correlated) and
ConfirmedFinding (oracle-verified) stay distinct.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .core_models import CoreBase


class CoreConfirmedFinding(CoreBase):
    __tablename__ = "core_confirmed_findings"

    candidate_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    vuln_type: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_ids: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    successes: Mapped[int] = mapped_column(Integer, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)
