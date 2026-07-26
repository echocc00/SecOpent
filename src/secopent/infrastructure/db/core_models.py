from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class CoreBase(DeclarativeBase):
    pass


class CoreProject(CoreBase):
    __tablename__ = "core_projects"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CoreScopeSnapshot(CoreBase):
    __tablename__ = "core_scope_snapshots"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("core_projects.id"), nullable=False)
    include: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    exclude: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    ports: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    limits: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    approved_by: Mapped[str] = mapped_column(String(64), nullable=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    digest: Mapped[str] = mapped_column(String(80), nullable=False, index=True)


class CoreAssessment(CoreBase):
    __tablename__ = "core_assessments"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("core_projects.id"), nullable=False)
    scope_snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("core_scope_snapshots.id"), nullable=False
    )
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    active_plan_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approval_id: Mapped[str | None] = mapped_column(String(64), nullable=True)


class CoreExecutionPlan(CoreBase):
    __tablename__ = "core_execution_plans"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("core_assessments.id"), nullable=False)
    version: Mapped[int] = mapped_column(nullable=False)
    steps: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    digest: Mapped[str] = mapped_column(String(80), nullable=False, index=True)


class CoreApproval(CoreBase):
    __tablename__ = "core_approvals"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("core_assessments.id"), nullable=False)
    plan_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    scope_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    approved_risks: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    approved_capabilities: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    approved_by: Mapped[str] = mapped_column(String(64), nullable=False)
    digest: Mapped[str] = mapped_column(String(80), nullable=False, index=True)


class CoreAuditEvent(CoreBase):
    __tablename__ = "core_audit_events"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
