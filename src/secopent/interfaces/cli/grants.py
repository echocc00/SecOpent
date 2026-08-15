"""secopent grant CLI - the HUMAN entry point for grant lifecycle (v0.6.5 C1).

Grant creation/revocation is human-only at the service layer
(``GrantService.create_human``/``revoke`` reject ``actor_role="agent"``); the
CLI is one of the sanctioned human surfaces, so it always passes
``actor_role="human"``. Operator flow:

    secopent grant create --db <url> --project <id> --name "desc" \\
        --include http://target/ --risk-caps passive,low --from <iso> --to <iso>
    secopent grant list --db <url> --project <id>
    secopent grant revoke --db <url> --grant <grant_id>

``list`` is read-only and shows ACTIVE grants only (an operator may want to
verify what an agent can currently run against a project).
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from ...domain.scope.models import ScopeDraft, ScopeLimits


def _parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 timestamp (Z suffix -> UTC) into an aware datetime."""
    normalized = value.strip().rstrip("Z")
    return datetime.fromisoformat(normalized).replace(tzinfo=UTC)


def _build_url(db: str) -> str:
    return db if "://" in db else f"sqlite:///{db}"


@contextmanager
def _grant_service(db: str) -> Iterator[Any]:
    """A grant service over a short-lived session; commits on success exit."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from secopent.application.grants import GrantService
    from secopent.infrastructure.repositories.sqlalchemy_grants import (
        SqlAlchemyGrantRepository,
    )

    engine = create_engine(_build_url(db))
    session = Session(engine)
    try:
        yield GrantService(SqlAlchemyGrantRepository(session))
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
        engine.dispose()


def cmd_grant_create(
    *,
    db: str,
    project: str,
    name: str,
    include: list[str],
    risk_caps: str,
    from_iso: str,
    to_iso: str,
    ports: str = "80,443",
) -> int:
    from sqlalchemy import create_engine, select

    from secopent.domain.policy.models import RiskClass
    from secopent.infrastructure.db.core_models import CoreProject

    # SQLite does not enforce FKs by default - check the project row exists so
    # a grant can never be created against a missing project (like the service
    # would if FKs were enforced).
    engine = create_engine(_build_url(db))
    try:
        with engine.connect() as conn:
            exists = conn.execute(
                select(CoreProject.id).where(CoreProject.id == project)
            ).first() is not None
    finally:
        engine.dispose()
    if not exists:
        print(f"error: project not found: {project}")
        return 1

    try:
        caps = frozenset(
            RiskClass(r.strip()) for r in risk_caps.split(",") if r.strip()
        )
    except ValueError as exc:
        print(f"error: invalid --risk-caps: {exc}")
        return 1
    if not caps:
        print("error: --risk-caps must name at least one risk")
        return 1
    try:
        parsed_ports = tuple(int(p) for p in ports.split(",") if p.strip())
    except ValueError as exc:
        print(f"error: invalid --ports: {exc}")
        return 1
    scope = ScopeDraft(
        project_id=project,
        include=tuple(include),
        exclude=(),
        ports=parsed_ports,
        limits=ScopeLimits(5.0, 3, 50_000),
    ).freeze(snapshot_id=f"cli-scope-{project}", approved_by="cli")

    try:
        with _grant_service(db) as service:
            grant = service.create_human(
                project_id=project,
                name=name,
                scope=scope,
                risk_caps=caps,
                valid_from=_parse_iso(from_iso),
                valid_to=_parse_iso(to_iso),
                actor_role="human",  # the CLI IS a human surface - never agent
            )
    except LookupError as exc:
        print(f"error: {exc}")
        return 1
    except Exception as exc:  # noqa: BLE001 - CLI surfaces the domain error
        print(f"error: grant create failed: {exc}")
        return 1
    print(f"created grant {grant.id} for project {project}")
    print(
        f"  scope: {', '.join(include)}; risk caps: {risk_caps}; "
        f"valid {from_iso} -> {to_iso}"
    )
    return 0


def cmd_grant_list(*, db: str, project: str) -> int:
    from secopent.domain.common.canonical import utc_now

    try:
        with _grant_service(db) as service:
            grants = service.list_active(project, now=utc_now())
    except Exception as exc:  # noqa: BLE001 - CLI surfaces the domain error
        print(f"error: grant list failed: {exc}")
        return 1
    if not grants:
        print(f"no active grants for project {project}")
        return 0
    for g in grants:
        print(
            f"{g.id}\t{g.name}\tscope={', '.join(g.scope.include)}\t"
            f"risk={','.join(sorted(r.value for r in g.risk_caps))}\t"
            f"until={g.valid_to.isoformat()}"
        )
    return 0


def cmd_grant_revoke(*, db: str, grant: str) -> int:
    try:
        with _grant_service(db) as service:
            service.revoke(grant, actor_role="human")
    except Exception as exc:  # noqa: BLE001 - CLI surfaces the domain error
        print(f"error: grant revoke failed: {exc}")
        return 1
    print(f"revoked grant {grant}")
    return 0