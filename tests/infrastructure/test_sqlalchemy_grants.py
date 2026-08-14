"""SqlAlchemyGrantRepository round-trip (v0.6.0 spec §3.2/§3.6).

The grant embeds a ScopeSnapshot; persistence must write the snapshot to
core_scope_snapshots (via SqlAlchemyScopeRepository) and the grant row to
core_grants keyed by scope_snapshot_id, then reassemble the domain object.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy.orm import Session

from secopent.domain.grants.models import EngagementGrant, GrantStatus
from secopent.domain.policy.models import RiskClass
from secopent.domain.scope.models import ScopeDraft, ScopeLimits
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyScopeRepository,
)
from secopent.infrastructure.repositories.sqlalchemy_grants import (
    SqlAlchemyGrantRepository,
)

_NOW = datetime(2026, 8, 8, tzinfo=UTC)


def _make_grant(*, snapshot_id: str = "grant-scope-1") -> EngagementGrant:
    scope = ScopeDraft(
        project_id="proj-1",
        include=("http://8.133.200.235/", "internal.example.com"),
        exclude=(), ports=(80, 443),
        limits=ScopeLimits(5.0, 3, 50_000),
    ).freeze(snapshot_id=snapshot_id, approved_by="operator-1")
    return EngagementGrant.create(
        project_id="proj-1", name="ECS prod scan", scope=scope,
        risk_caps=frozenset({RiskClass.PASSIVE, RiskClass.LOW, RiskClass.ACTIVE}),
        valid_from=_NOW - timedelta(days=1),
        valid_to=_NOW + timedelta(days=7),
        created_by="operator-1",
        created_at=_NOW,
    )


def _engine(tmp_path: Path):
    from secopent.infrastructure.db.session import init_db

    engine = create_sqlite_engine(tmp_path / "grants.db")
    init_db(engine, mode="auto")
    return engine


def _seed_project(session) -> None:
    """grant.scope and core_grants both FK to core_projects - seed it first."""
    from secopent.domain.projects.models import Project
    from secopent.infrastructure.repositories.sqlalchemy_core import (
        SqlAlchemyProjectRepository,
    )

    SqlAlchemyProjectRepository(session).add(Project.create(project_id="proj-1", name="t"))


def test_grant_round_trip_preserves_embedded_scope(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    grant = _make_grant()
    with Session(engine) as s:
        _seed_project(s)
        SqlAlchemyGrantRepository(s).add(grant)
        s.commit()

    with Session(engine) as s:
        loaded = SqlAlchemyGrantRepository(s).get(grant.id)
    assert loaded is not None
    assert loaded.id == grant.id
    assert loaded.project_id == "proj-1"
    assert loaded.name == grant.name
    assert loaded.digest == grant.digest
    assert loaded.status is GrantStatus.ACTIVE
    assert loaded.risk_caps == grant.risk_caps
    assert loaded.valid_to == grant.valid_to
    # embedded scope reassembled exactly
    assert loaded.scope.digest == grant.scope.digest
    assert loaded.scope.include == grant.scope.include
    assert loaded.scope.ports == grant.scope.ports


def test_scope_persisted_in_core_scope_snapshots(tmp_path: Path) -> None:
    """The embedded scope lives in core_scope_snapshots (one store, one matcher)."""
    engine = _engine(tmp_path)
    grant = _make_grant()
    with Session(engine) as s:
        _seed_project(s)
        SqlAlchemyGrantRepository(s).add(grant)
        s.commit()

    with Session(engine) as s:
        restored = SqlAlchemyScopeRepository(s).get_snapshot(grant.scope.id)
    assert restored is not None
    assert restored.digest == grant.scope.digest


def test_list_for_project(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    with Session(engine) as s:
        _seed_project(s)
        SqlAlchemyGrantRepository(s).add(_make_grant(snapshot_id="scope-a"))
        SqlAlchemyGrantRepository(s).add(
            _make_grant(snapshot_id="scope-b").__class__.create(  # second grant
                project_id="proj-1", name="app B",
                scope=ScopeDraft(
                    project_id="proj-1", include=("app-b.example.com",),
                    exclude=(), ports=(443,), limits=ScopeLimits(5.0, 3, 50_000),
                ).freeze(snapshot_id="scope-b", approved_by="operator-1"),
                risk_caps=frozenset({RiskClass.LOW}),
                valid_from=_NOW - timedelta(days=1),
                valid_to=_NOW + timedelta(days=7),
                created_by="operator-1", created_at=_NOW,
            )
        )
        s.commit()

    with Session(engine) as s:
        listings = SqlAlchemyGrantRepository(s).list_for_project("proj-1")
    assert len(listings) == 2
    assert {g.name for g in listings} == {"ECS prod scan", "app B"}

    with Session(engine) as s:
        assert SqlAlchemyGrantRepository(s).list_for_project("proj-2") == ()


def test_get_missing_returns_none(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    with Session(engine) as s:
        assert SqlAlchemyGrantRepository(s).get("grant-missing") is None