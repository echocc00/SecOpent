# src/secopent/domain/assessments/models.py
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from ..common.canonical import canonical_digest
from ..common.errors import DomainValidationError
from ..policy.models import ExecutionMode, RiskClass


class AssessmentStatus(StrEnum):
    DRAFT = "draft"
    PLANNED = "planned"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ControlState(StrEnum):
    """Runtime-control signal for a live assessment (MCP pause/resume/cancel).

    Written by the control-plane tools (``AssessmentService.pause/resume/
    cancel``) and consumed (then cleared to NONE) by the executor thread at
    step boundaries. The signal is durable (a column on ``core_assessments``)
    so an executor in a different process sees the request; M4 wires the
    actual consumption.
    """

    NONE = "none"
    PAUSE_REQUESTED = "pause_requested"
    RESUME_REQUESTED = "resume_requested"
    CANCEL_REQUESTED = "cancel_requested"


@dataclass(frozen=True, slots=True)
class PlanStep:
    key: str
    runner: str
    risk: RiskClass
    parameters: dict[str, object]
    dependencies: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    id: str
    assessment_id: str
    version: int
    steps: tuple[PlanStep, ...]
    digest: str

    @classmethod
    def create(cls, *, plan_id: str, assessment_id: str, version: int,
               steps: tuple[PlanStep, ...]) -> ExecutionPlan:
        if version < 1:
            raise DomainValidationError("plan version must be positive")
        keys = [s.key for s in steps]
        if len(keys) != len(set(keys)):
            raise DomainValidationError("plan step keys must be unique")
        known = set(keys)
        if any(set(s.dependencies) - known for s in steps):
            raise DomainValidationError("plan dependency does not exist")
        graph = {s.key: s.dependencies for s in steps}
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(key: str) -> None:
            if key in visiting:
                raise DomainValidationError("plan dependency cycle")
            if key in visited:
                return
            visiting.add(key)
            for dep in graph[key]:
                visit(dep)
            visiting.remove(key)
            visited.add(key)

        for key in keys:
            visit(key)
        payload = {"assessment_id": assessment_id, "version": version, "steps": steps}
        return cls(plan_id, assessment_id, version, tuple(steps), canonical_digest(payload))


@dataclass(frozen=True, slots=True)
class Approval:
    id: str
    assessment_id: str
    plan_digest: str
    scope_digest: str
    mode: ExecutionMode
    approved_risks: frozenset[RiskClass]
    approved_capabilities: frozenset[str]
    approved_by: str
    digest: str

    @classmethod
    def create(cls, *, approval_id: str, assessment_id: str, plan_digest: str,
               scope_digest: str, mode: ExecutionMode,
               approved_risks: frozenset[RiskClass], approved_capabilities: frozenset[str],
               approved_by: str) -> Approval:
        if not plan_digest or not scope_digest:
            raise DomainValidationError("approval requires plan and scope digest")
        payload = {
            "assessment_id": assessment_id,
            "plan_digest": plan_digest,
            "scope_digest": scope_digest,
            "mode": mode,
            "approved_risks": approved_risks,
            "approved_capabilities": approved_capabilities,
            "approved_by": approved_by,
        }
        return cls(approval_id, assessment_id, plan_digest, scope_digest, mode,
                   frozenset(approved_risks), frozenset(approved_capabilities),
                   approved_by, canonical_digest(payload))


@dataclass(frozen=True, slots=True)
class Assessment:
    id: str
    project_id: str
    scope_snapshot_id: str
    mode: ExecutionMode
    status: AssessmentStatus
    active_plan_id: str | None = None
    approval_id: str | None = None
    # Runtime-control signal for a live execution (ControlState); consumed by
    # the executor at step boundaries (M4). Default NONE keeps every existing
    # construction site compatible.
    control: ControlState = ControlState.NONE

    @classmethod
    def create(cls, *, assessment_id: str, project_id: str, scope_snapshot_id: str,
               mode: ExecutionMode) -> Assessment:
        if not all((assessment_id, project_id, scope_snapshot_id)):
            raise DomainValidationError("assessment identifiers are required")
        return cls(assessment_id, project_id, scope_snapshot_id, mode, AssessmentStatus.DRAFT)

    def start(self, *, plan_id: str, approval_id: str | None) -> Assessment:
        if not approval_id:
            raise DomainValidationError("assessment requires approval")
        if self.status not in {AssessmentStatus.DRAFT, AssessmentStatus.APPROVED}:
            raise DomainValidationError("assessment cannot start from current status")
        return replace(self, status=AssessmentStatus.QUEUED,
                       active_plan_id=plan_id, approval_id=approval_id)
