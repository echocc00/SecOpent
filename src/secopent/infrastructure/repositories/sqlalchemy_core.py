from __future__ import annotations

from datetime import UTC

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...domain.assessments.models import Approval, Assessment, AssessmentStatus, ExecutionPlan
from ...domain.audit.models import GENESIS_HASH, AuditEvent
from ...domain.policy.models import ExecutionMode, RiskClass
from ...domain.projects.models import Project, ProjectStatus
from ...domain.scope.models import ScopeLimits, ScopeSnapshot
from ..db.core_models import (
    CoreApproval,
    CoreAssessment,
    CoreAuditEvent,
    CoreExecutionPlan,
    CoreProject,
    CoreScopeSnapshot,
)


class SqlAlchemyProjectRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, project: Project) -> None:
        self._session.add(
            CoreProject(
                id=project.id,
                name=project.name,
                status=project.status.value,
                created_at=project.created_at,
            )
        )

    def get(self, project_id: str) -> Project | None:
        row = self._session.get(CoreProject, project_id)
        if row is None:
            return None
        return Project(
            id=row.id,
            name=row.name,
            status=ProjectStatus(row.status),
            created_at=row.created_at,
        )

    def list(self) -> list[Project]:
        rows = self._session.execute(
            select(CoreProject).order_by(CoreProject.created_at)
        ).scalars().all()
        return [
            Project(
                id=row.id,
                name=row.name,
                status=ProjectStatus(row.status),
                created_at=row.created_at,
            )
            for row in rows
        ]


def _to_snapshot(row: CoreScopeSnapshot) -> ScopeSnapshot:
    approved_at = row.approved_at
    if approved_at.tzinfo is None:
        # SQLite stores DateTime(timezone=True) as naive; re-attach UTC so the
        # round-tripped ScopeSnapshot compares equal to the in-memory original.
        approved_at = approved_at.replace(tzinfo=UTC)
    return ScopeSnapshot(
        id=row.id, project_id=row.project_id,
        include=tuple(row.include), exclude=tuple(row.exclude),
        ports=tuple(row.ports),
        limits=ScopeLimits(**row.limits),
        approved_by=row.approved_by, approved_at=approved_at, digest=row.digest,
    )


def _from_snapshot(snapshot: ScopeSnapshot) -> CoreScopeSnapshot:
    return CoreScopeSnapshot(
        id=snapshot.id, project_id=snapshot.project_id,
        include=list(snapshot.include), exclude=list(snapshot.exclude),
        ports=list(snapshot.ports),
        limits={
            "requests_per_second": snapshot.limits.requests_per_second,
            "concurrency": snapshot.limits.concurrency,
            "max_requests": snapshot.limits.max_requests,
        },
        approved_by=snapshot.approved_by, approved_at=snapshot.approved_at, digest=snapshot.digest,
    )


class SqlAlchemyScopeRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add_snapshot(self, snapshot: ScopeSnapshot) -> None:
        self._session.add(_from_snapshot(snapshot))

    def get_snapshot(self, snapshot_id: str) -> ScopeSnapshot | None:
        row = self._session.get(CoreScopeSnapshot, snapshot_id)
        return _to_snapshot(row) if row else None


class SqlAlchemyAuditRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    @property
    def session(self) -> Session:
        """The bound session (exposed for same-transaction merges - v4 refactor:
        lets ``_audit_record`` pass this session to the signed audit store so
        both audit tables are written in ONE transaction)."""
        return self._session

    def add(self, event: AuditEvent) -> None:
        self._session.add(CoreAuditEvent(
            id=event.id, actor=event.actor, action=event.action,
            resource_type=event.resource_type, resource_id=event.resource_id,
            payload=event.payload, previous_hash=event.previous_hash,
            event_hash=event.event_hash, occurred_at=event.occurred_at,
        ))

    def list_events(self) -> list[AuditEvent]:
        rows = self._session.execute(
            select(CoreAuditEvent).order_by(CoreAuditEvent.occurred_at)
        ).scalars().all()
        events: list[AuditEvent] = []
        for r in rows:
            occurred_at = r.occurred_at
            if occurred_at.tzinfo is None:
                # SQLite stores DateTime(timezone=True) as naive; re-attach UTC
                # so the round-tripped event hashes identically to the original
                # (verify_chain recomputes the canonical digest over occurred_at).
                occurred_at = occurred_at.replace(tzinfo=UTC)
            events.append(
                AuditEvent(
                    id=r.id, actor=r.actor, action=r.action, resource_type=r.resource_type,
                    resource_id=r.resource_id, payload=r.payload, previous_hash=r.previous_hash,
                    event_hash=r.event_hash, occurred_at=occurred_at,
                )
            )
        return events

    def last_hash(self) -> str:
        rows = self._session.execute(
            select(CoreAuditEvent).order_by(CoreAuditEvent.occurred_at.desc()).limit(1)
        ).scalars().all()
        return rows[0].event_hash.removeprefix("sha256:") if rows else GENESIS_HASH


class SqlAlchemyAssessmentRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, assessment: Assessment) -> None:
        self._session.merge(CoreAssessment(
            id=assessment.id, project_id=assessment.project_id,
            scope_snapshot_id=assessment.scope_snapshot_id,
            mode=assessment.mode.value, status=assessment.status.value,
            active_plan_id=assessment.active_plan_id, approval_id=assessment.approval_id,
            control=assessment.control.value,
        ))

    def get(self, assessment_id: str) -> Assessment | None:
        row = self._session.get(CoreAssessment, assessment_id)
        if not row:
            return None
        from ...domain.assessments.models import ControlState

        return Assessment(
            id=row.id, project_id=row.project_id, scope_snapshot_id=row.scope_snapshot_id,
            mode=ExecutionMode(row.mode), status=AssessmentStatus(row.status),
            active_plan_id=row.active_plan_id, approval_id=row.approval_id,
            control=ControlState(row.control),
        )

    def list_all(self, project_id: str | None = None) -> list[Assessment]:
        stmt = select(CoreAssessment)
        if project_id is not None:
            stmt = stmt.where(CoreAssessment.project_id == project_id)
        rows = self._session.execute(stmt).scalars().all()
        from ...domain.assessments.models import ControlState

        return [
            Assessment(
                id=row.id, project_id=row.project_id,
                scope_snapshot_id=row.scope_snapshot_id,
                mode=ExecutionMode(row.mode), status=AssessmentStatus(row.status),
                active_plan_id=row.active_plan_id, approval_id=row.approval_id,
                control=ControlState(row.control),
            )
            for row in rows
        ]

    def save_plan(self, plan: ExecutionPlan) -> None:
        self._session.add(CoreExecutionPlan(
            id=plan.id, assessment_id=plan.assessment_id, version=plan.version,
            steps=[{"key": s.key, "runner": s.runner, "risk": s.risk.value,
                     "parameters": s.parameters, "dependencies": list(s.dependencies)}
                   for s in plan.steps],
            digest=plan.digest,
        ))

    def get_plan(self, plan_id: str) -> ExecutionPlan | None:
        row = self._session.get(CoreExecutionPlan, plan_id)
        if not row:
            return None
        from ...domain.assessments.models import PlanStep
        steps = tuple(PlanStep(
            key=s["key"], runner=s["runner"], risk=RiskClass(s["risk"]),
            parameters=s["parameters"], dependencies=tuple(s["dependencies"]),
        ) for s in row.steps)
        return ExecutionPlan(
            id=row.id, assessment_id=row.assessment_id, version=row.version,
            steps=steps, digest=row.digest,
        )

    def save_approval(self, approval: Approval) -> None:
        self._session.add(CoreApproval(
            id=approval.id, assessment_id=approval.assessment_id,
            plan_digest=approval.plan_digest, scope_digest=approval.scope_digest,
            mode=approval.mode.value,
            approved_risks=[r.value for r in approval.approved_risks],
            approved_capabilities=list(approval.approved_capabilities),
            approved_by=approval.approved_by, digest=approval.digest,
        ))

    def get_approval(self, approval_id: str) -> Approval | None:
        row = self._session.get(CoreApproval, approval_id)
        if row is None:
            return None
        return Approval(
            id=row.id, assessment_id=row.assessment_id,
            plan_digest=row.plan_digest, scope_digest=row.scope_digest,
            mode=ExecutionMode(row.mode),
            approved_risks=frozenset(RiskClass(r) for r in row.approved_risks),
            approved_capabilities=frozenset(row.approved_capabilities),
            approved_by=row.approved_by, digest=row.digest,
        )
