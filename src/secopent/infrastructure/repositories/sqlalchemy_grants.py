"""SqlAlchemyGrantRepository (v0.6.0 spec §3.2/§3.6).

Persists the grant row in ``core_grants`` and the embedded ScopeSnapshot in
``core_scope_snapshots`` (via SqlAlchemyScopeRepository - the same store the
assessments use, so the authorization boundary and the scannable scope share
one persistence + one matcher). Reassembles the frozen domain object on read.
"""
from __future__ import annotations

import json
from datetime import UTC as _UTC
from typing import Any

from sqlalchemy import select

from ...domain.grants.models import EngagementGrant, GrantStatus
from ...domain.policy.models import RiskClass
from ...domain.scope.models import ScopeSnapshot
from ..db.grants_models import CoreEngagementGrant


class SqlAlchemyGrantRepository:
    def __init__(self, session: Any, scope_repo: Any = None) -> None:
        self._session = session
        if scope_repo is None:
            from .sqlalchemy_core import SqlAlchemyScopeRepository

            scope_repo = SqlAlchemyScopeRepository(session)
        self._scopes = scope_repo

    def add(self, grant: EngagementGrant) -> None:
        # The embedded boundary MUST live in the same scope store assessments
        # use - persisting it anywhere else would split the matcher (v8 lesson).
        self._scopes.add_snapshot(grant.scope)
        self._session.merge(
            CoreEngagementGrant(
                id=grant.id,
                project_id=grant.project_id,
                name=grant.name,
                scope_snapshot_id=grant.scope.id,
                risk_caps=json.dumps(sorted(r.value for r in grant.risk_caps)),
                valid_from=grant.valid_from,
                valid_to=grant.valid_to,
                created_by=grant.created_by,
                created_at=grant.created_at,
                status=grant.status.value,
                digest=grant.digest,
            )
        )

    def get(self, grant_id: str) -> EngagementGrant | None:
        row = self._session.execute(
            select(CoreEngagementGrant).where(CoreEngagementGrant.id == grant_id)
        ).scalar_one_or_none()
        if row is None:
            return None
        scope = self._scopes.get_snapshot(row.scope_snapshot_id)
        if scope is None:  # pragma: no cover - FK guarantees presence
            return None
        return self._from_row(row, scope)

    def list_for_project(self, project_id: str) -> tuple[EngagementGrant, ...]:
        rows = (
            self._session.execute(
                select(CoreEngagementGrant)
                .where(CoreEngagementGrant.project_id == project_id)
                .order_by(CoreEngagementGrant.created_at.desc())
            )
            .scalars()
            .all()
        )
        result: list[EngagementGrant] = []
        for row in rows:
            scope = self._scopes.get_snapshot(row.scope_snapshot_id)
            if scope is not None:
                result.append(self._from_row(row, scope))
        return tuple(result)

    def _from_row(self, row: CoreEngagementGrant, scope: ScopeSnapshot) -> EngagementGrant:
        # SQLite stores DateTime(timezone=True) as naive; re-attach UTC so the
        # round-tripped grant compares equal to the in-memory original (same
        # convention as sqlalchemy_core._to_snapshot).
        def _utc(value: Any) -> Any:
            if value.tzinfo is None:
                return value.replace(tzinfo=_UTC)
            return value

        return EngagementGrant(
            id=row.id,
            project_id=row.project_id,
            name=row.name,
            scope=scope,
            risk_caps=frozenset(RiskClass(v) for v in json.loads(row.risk_caps)),
            valid_from=_utc(row.valid_from),
            valid_to=_utc(row.valid_to),
            created_by=row.created_by,
            created_at=_utc(row.created_at),
            status=GrantStatus(row.status),
            digest=row.digest,
        )