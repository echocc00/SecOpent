"""secopent grant CLI (v0.6.5 C1) - the HUMAN entry point for grant lifecycle.

The CLI is how an operator creates/revokes grants (create_human is
agent-DENIED at the service layer; the CLI passes actor_role="human" by
construction). List is read-only (agent-discoverable via MCP grant_list;
here for operators).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from secopent.domain.grants.models import GrantStatus
from secopent.domain.policy.models import RiskClass
from secopent.infrastructure.db.session import init_db
from secopent.infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyScopeRepository,
)
from secopent.infrastructure.repositories.sqlalchemy_grants import (
    SqlAlchemyGrantRepository,
)
from secopent.interfaces.cli.main import main


def _window() -> tuple[str, str]:
    """A grant window covering NOW (window start is in the past) so list_active
    (which checks against the real clock) always sees the grant as active."""
    now = datetime.now(UTC)
    start = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = (now + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return start, end


def _url(tmp_path, name: str = "t.db") -> str:
    return f"sqlite:///{(tmp_path / name).as_posix()}"


def _seed_project(engine, project_id: str = "proj-1") -> None:
    from secopent.domain.projects.models import Project

    with Session(engine) as s:
        from secopent.infrastructure.repositories.sqlalchemy_core import (
            SqlAlchemyProjectRepository,
        )

        SqlAlchemyProjectRepository(s).add(Project.create(project_id=project_id, name="t"))
        s.commit()


def test_grant_create_list_revoke_round_trip(tmp_path, capsys) -> None:
    url = _url(tmp_path)
    eng = create_engine(url)
    init_db(eng, mode="auto")
    _seed_project(eng)

    rc = main([
        "grant", "create",
        "--db", url,
        "--project", "proj-1",
        "--name", "ECS prod scan",
        "--include", "http://8.133.200.235/",
        "--risk-caps", "passive,low,active",
        "--from", _window()[0], "--to", _window()[1],
    ])
    assert rc == 0
    out = capsys.readouterr()
    assert "grant-" in out.out

    rc = main(["grant", "list", "--db", url, "--project", "proj-1"])
    assert rc == 0
    out = capsys.readouterr()
    assert "ECS prod scan" in out.out
    assert "8.133.200.235" in out.out

    # The grant row exists and persists its embedded scope.
    with Session(eng) as s:
        grants = SqlAlchemyGrantRepository(s).list_for_project("proj-1")
    assert len(grants) == 1
    grant = grants[0]
    assert grant.risk_caps == frozenset(
        {RiskClass.LOW, RiskClass.ACTIVE, RiskClass.PASSIVE}
    )
    assert grant.scope.include == ("http://8.133.200.235/",)

    rc = main(["grant", "revoke", "--db", url, "--grant", grant.id])
    assert rc == 0
    with Session(eng) as s:
        revoked = SqlAlchemyGrantRepository(s).get(grant.id)
    assert revoked is not None
    assert revoked.status is GrantStatus.REVOKED


def test_grant_create_requires_project(tmp_path, capsys) -> None:
    """A grant against a missing project must fail (FK integrity)."""
    url = _url(tmp_path)
    eng = create_engine(url)
    init_db(eng, mode="auto")

    rc = main([
        "grant", "create",
        "--db", url,
        "--project", "proj-missing",
        "--name", "g",
        "--include", "http://8.133.200.235/",
        "--risk-caps", "low",
        "--from", _window()[0], "--to", _window()[1],
    ])
    assert rc != 0
    err = capsys.readouterr()
    assert "error" in (err.out + err.err).lower()


def test_grant_create_rejects_invalid_window(tmp_path, capsys) -> None:
    url = _url(tmp_path)
    eng = create_engine(url)
    init_db(eng, mode="auto")
    _seed_project(eng)

    rc = main([
        "grant", "create",
        "--db", url,
        "--project", "proj-1",
        "--name", "g",
        "--include", "http://8.133.200.235/",
        "--risk-caps", "low",
        "--from", "2026-08-17T00:00:00Z", "--to", "2026-08-16T00:00:00Z",
    ])
    assert rc != 0
    err = capsys.readouterr()
    assert "error" in (err.out + err.err).lower()


def test_grant_list_empty_when_none(tmp_path, capsys) -> None:
    url = _url(tmp_path)
    eng = create_engine(url)
    init_db(eng, mode="auto")
    _seed_project(eng)

    rc = main(["grant", "list", "--db", url, "--project", "proj-1"])
    assert rc == 0
    out = capsys.readouterr()
    assert "no active grants" in (out.out + out.err).lower()


def test_grant_scope_frozen_into_snapshot_table(tmp_path) -> None:
    """The grant's embedded scope must land in core_scope_snapshots (one store
    - the same store assessments use; never a shadow copy)."""
    url = _url(tmp_path)
    eng = create_engine(url)
    init_db(eng, mode="auto")
    _seed_project(eng)

    rc = main([
        "grant", "create",
        "--db", url,
        "--project", "proj-1",
        "--name", "g",
        "--include", "http://8.133.200.235/",
        "--risk-caps", "low",
        "--from", _window()[0], "--to", _window()[1],
    ])
    assert rc == 0
    with Session(eng) as s:
        grants = SqlAlchemyGrantRepository(s).list_for_project("proj-1")
        assert len(grants) == 1
        restored = SqlAlchemyScopeRepository(s).get_snapshot(grants[0].scope.id)
    assert restored is not None
    assert restored.digest == grants[0].scope.digest