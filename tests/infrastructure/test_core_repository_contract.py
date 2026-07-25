from __future__ import annotations
from datetime import datetime
import pytest
from sqlalchemy.orm import Session
from secopent.domain.assessments.models import Assessment
from secopent.domain.policy.models import ExecutionMode
from secopent.domain.scope.models import ScopeDraft
from secopent.infrastructure.db.core_models import CoreBase
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAuditRepository, SqlAlchemyScopeRepository, SqlAlchemyAssessmentRepository,
)


@pytest.fixture
def sqlite_session(tmp_path):
    engine = create_sqlite_engine(tmp_path / "secopent.db")
    CoreBase.metadata.create_all(engine)
    session = Session(engine)
    # Seed parent rows so FK constraints (PRAGMA foreign_keys=ON from Task 10)
    # are satisfied for scope_snapshot.project_id='p' and
    # assessment.{project_id='p', scope_snapshot_id='s'} references.
    from secopent.domain.common.canonical import utc_now
    from secopent.domain.projects.models import Project, ProjectStatus
    from secopent.infrastructure.db.core_models import CoreProject, CoreScopeSnapshot
    project = Project.create(project_id="p", name="Lab")
    session.add(CoreProject(
        id=project.id, name=project.name,
        status=project.status.value, created_at=project.created_at,
    ))
    snapshot_row = CoreScopeSnapshot(
        id="s", project_id="p", include=[], exclude=[], ports=[],
        limits={"requests_per_second": 5.0, "concurrency": 3, "max_requests": 50000},
        approved_by="u", approved_at=utc_now(), digest="sha256:" + "0" * 64,
    )
    session.add(snapshot_row)
    session.commit()
    yield session
    session.close()


def test_scope_repository_round_trip(sqlite_session):
    draft = ScopeDraft(project_id="p", include=("https://example.test",))
    snapshot = draft.freeze(snapshot_id="scope-1", approved_by="u")
    repo = SqlAlchemyScopeRepository(sqlite_session)
    repo.add_snapshot(snapshot)
    sqlite_session.commit()
    assert repo.get_snapshot("scope-1") == snapshot


def test_scope_repository_returns_none_for_missing(sqlite_session):
    repo = SqlAlchemyScopeRepository(sqlite_session)
    assert repo.get_snapshot("missing") is None


def test_audit_repository_chains(sqlite_session):
    repo = SqlAlchemyAuditRepository(sqlite_session)
    repo.add(_make_event(repo, "e1", "a"))
    repo.add(_make_event(repo, "e2", "b"))
    sqlite_session.commit()
    events = repo.list_events()
    assert len(events) == 2
    assert repo.last_hash() == events[-1].event_hash.removeprefix("sha256:")


def test_assessment_repository_round_trip(sqlite_session):
    repo = SqlAlchemyAssessmentRepository(sqlite_session)
    assessment = Assessment.create(assessment_id="a1", project_id="p",
        scope_snapshot_id="s", mode=ExecutionMode.APPROVAL)
    repo.add(assessment)
    sqlite_session.commit()
    assert repo.get("a1") == assessment


def _make_event(repo, event_id, action):
    from secopent.domain.audit.models import AuditEvent
    previous = repo.last_hash() or "0" * 64
    return AuditEvent.create(
        event_id=event_id, actor="u", action=action, resource_type="r",
        resource_id="r1", payload={}, previous_hash=previous,
    )
