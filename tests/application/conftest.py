from __future__ import annotations
from dataclasses import dataclass, field
import pytest
from secopent.domain.assessments.models import Assessment, ExecutionPlan, Approval
from secopent.domain.audit.models import AuditEvent, GENESIS_HASH
from secopent.domain.projects.models import Project
from secopent.domain.scope.models import ScopeSnapshot


@dataclass
class MemoryProjectRepo:
    items: dict[str, Project] = field(default_factory=dict)
    def add(self, p: Project) -> None: self.items[p.id] = p
    def get(self, pid: str) -> Project | None: return self.items.get(pid)


@dataclass
class MemoryScopeRepo:
    items: dict[str, ScopeSnapshot] = field(default_factory=dict)
    def add_snapshot(self, s: ScopeSnapshot) -> None: self.items[s.id] = s
    def get_snapshot(self, sid: str) -> ScopeSnapshot | None: return self.items.get(sid)


@dataclass
class MemoryAssessmentRepo:
    items: dict[str, Assessment] = field(default_factory=dict)
    plans: dict[str, ExecutionPlan] = field(default_factory=dict)
    def add(self, a: Assessment) -> None: self.items[a.id] = a
    def get(self, aid: str) -> Assessment | None: return self.items.get(aid)
    def save_plan(self, p: ExecutionPlan) -> None: self.plans[p.id] = p
    def get_plan(self, pid: str) -> ExecutionPlan | None: return self.plans.get(pid)
    def save_approval(self, a: Approval) -> None: ...


@dataclass
class MemoryAuditRepo:
    events: list[AuditEvent] = field(default_factory=list)
    def add(self, e: AuditEvent) -> None: self.events.append(e)
    def list_events(self) -> list[AuditEvent]: return list(self.events)
    def last_hash(self) -> str:
        return self.events[-1].event_hash.removeprefix("sha256:") if self.events else GENESIS_HASH


@dataclass
class MemoryRepos:
    projects: MemoryProjectRepo = field(default_factory=MemoryProjectRepo)
    scopes: MemoryScopeRepo = field(default_factory=MemoryScopeRepo)
    assessments: MemoryAssessmentRepo = field(default_factory=MemoryAssessmentRepo)
    audit: MemoryAuditRepo = field(default_factory=MemoryAuditRepo)


@pytest.fixture
def memory_repositories() -> MemoryRepos:
    return MemoryRepos()
