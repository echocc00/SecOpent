"""ORM for grants (v0.6.0 spec §3.6).

The grant's embedded ScopeSnapshot lives in ``core_scope_snapshots`` (the SAME
store assessments use - one matcher, one store). The grant row references it by
``scope_snapshot_id`` (the snapshot's ORM primary key is ``id``, not digest).
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .core_models import CoreBase


class CoreEngagementGrant(CoreBase):
    __tablename__ = "core_grants"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("core_projects.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    scope_snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("core_scope_snapshots.id"), nullable=False
    )
    # JSON list of RiskClass values (e.g. ["passive","low","active"]).
    risk_caps: Mapped[str] = mapped_column(Text, nullable=False)
    valid_from: Mapped[datetime] = mapped_column(nullable=False)
    valid_to: Mapped[datetime] = mapped_column(nullable=False)
    created_by: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    status: Mapped[str] = mapped_column(String(12), nullable=False)
    digest: Mapped[str] = mapped_column(String(80), nullable=False, index=True)