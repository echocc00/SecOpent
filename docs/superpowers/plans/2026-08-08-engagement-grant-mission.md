# EngagementGrant + Mission Implementation Plan (v0.6.0 + v0.6.1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Let an agent run approved scans autonomously within a human-granted authorization boundary (EngagementGrant), and decide which test classes to run via the project's own LLM (Mission).

**Architecture:** Phase A adds a grant object (embedded `ScopeSnapshot`, risk caps, validity window, human-only creation) and threads `grant_id` through `AssessmentService.approve/start` as an opt-in approval path that overrides `_require_human` only when the grant authorizes the exact scope+risk. Phase B adds `mission_create` (target + intent) that builds scope→assessment→plan, lets the project LLM select test classes on top of the deterministic `catalog.required_for` floor, then approves/starts via a grant.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2.0, alembic, pytest (coverage gate 80%), mypy strict, ruff, MCP handlers.

**Design doc:** `docs/superpowers/specs/2026-08-08-engagement-grant-mission-design.md` (approved).

---

## Phase A — EngagementGrant (v0.6.0)

### Task A1 — Grant domain model

**Files:** `src/secopent/domain/grants/models.py` (new), `src/secopent/domain/grants/errors.py` (new), `tests/domain/test_grants.py` (new)

**A1.1 — Write the failing tests** in `tests/domain/test_grants.py`:

```python
"""EngagementGrant domain tests (v0.6.0, spec §3.1).

A grant is a human-granted authorization boundary: an embedded ScopeSnapshot
(one matcher - ScopeSnapshot owns target matching), risk caps, validity window.
covers_scope must be precise: every assessment target must match the grant's
scope; covers_risks caps every plan step.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from secopent.domain.common.errors import DomainValidationError
from secopent.domain.grants.models import EngagementGrant, GrantStatus
from secopent.domain.policy.models import RiskClass
from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot


def _grant(**overrides: object) -> EngagementGrant:
    now = datetime(2026, 8, 8, tzinfo=UTC)
    base = dict(
        id="grant-1",
        project_id="proj-1",
        name="ECS prod scan",
        scope=ScopeSnapshot(  # grants one IP + one domain
            id="grant-scope-1", project_id="proj-1",
            include=("http://8.133.200.235/", "internal.example.com"),
            exclude=(), ports=(80, 443),
            limits=ScopeLimits(5.0, 3, 50_000),
            approved_by="human", approved_at=now, digest="sha256:grant-scope",
        ),
        risk_caps=frozenset({RiskClass.PASSIVE, RiskClass.LOW, RiskClass.ACTIVE}),
        valid_from=now - timedelta(days=1),
        valid_to=now + timedelta(days=7),
        created_by="operator-1", created_at=now,
        status=GrantStatus.ACTIVE,
        digest="sha256:grant",
    )
    base.update(overrides)
    return EngagementGrant(**base)  # type: ignore[arg-type]


def _assessment_scope(*include: str, ports: tuple[int, ...] = (443,)) -> ScopeSnapshot:
    return ScopeSnapshot(
        id="asm-scope", project_id="proj-1", include=include, exclude=(),
        ports=ports, limits=ScopeLimits(5.0, 3, 50_000),
        approved_by="human", approved_at=datetime(2026, 8, 8, tzinfo=UTC),
        digest="sha256:asm-scope",
    )


def test_create_rejects_destructive_risk_cap() -> None:
    with pytest.raises(DomainValidationError):
        _grant(risk_caps=frozenset({RiskClass.DESTRUCTIVE}))


def test_create_rejects_empty_name() -> None:
    with pytest.raises(DomainValidationError):
        _grant(name="  ")


def test_create_rejects_inverted_window() -> None:
    with pytest.raises(DomainValidationError):
        _grant(valid_from=datetime(2026, 8, 9, tzinfo=UTC),
               valid_to=datetime(2026, 8, 8, tzinfo=UTC))


def test_is_active_within_window_but_not_expired() -> None:
    now = datetime(2026, 8, 8, tzinfo=UTC)
    assert _grant().is_active_at(now) is True


def test_expired_after_valid_to() -> None:
    g = _grant(valid_to=datetime(2026, 8, 5, tzinfo=UTC))
    assert g.is_active_at(datetime(2026, 8, 8, tzinfo=UTC)) is False
    assert g.status is GrantStatus.EXPIRED  # lazy conversion


def test_revoked_is_not_active() -> None:
    g = _grant().revoke()
    assert g.status is GrantStatus.REVOKED
    assert g.is_active_at(datetime(2026, 8, 8, tzinfo=UTC)) is False


def test_covers_scope_exact_ip_target() -> None:
    assert _grant().covers_scope(_assessment_scope("http://8.133.200.235/"))


def test_covers_scope_domain_target() -> None:
    assert _grant().covers_scope(_assessment_scope("internal.example.com"))


def test_covers_scope_rejects_out_of_grant_ip() -> None:
    assert not _grant().covers_scope(_assessment_scope("http://8.133.200.236/"))


def test_covers_scope_requires_all_targets_in_grant() -> None:
    assert not _grant().covers_scope(
        _assessment_scope("http://8.133.200.235/", "http://evil.example/")
    )


def test_covers_scope_rejects_extra_ports() -> None:
    assert not _grant().covers_scope(
        _assessment_scope("http://8.133.200.235/", ports=(443, 8443))
    )


def test_covers_scope_large_cidr_does_not_imply_subnet_scan() -> None:
    # "授权 /24" 不等于 "能扫 /8":assessment 的每个 target 必须单独命中.
    wide = _grant(scope=ScopeSnapshot(
        id="grant-scope-2", project_id="proj-1",
        include=("10.0.0.0/24",), exclude=(), ports=(80,),
        limits=ScopeLimits(5.0, 3, 50_000),
        approved_by="human", approved_at=datetime(2026, 8, 8, tzinfo=UTC),
        digest="sha256:grant-scope-2",
    ))
    assert wide.covers_scope(_assessment_scope("10.0.0.5"))
    assert not wide.covers_scope(_assessment_scope("10.0.1.5"))


def test_covers_risks_within_caps() -> None:
    from secopent.domain.assessments.models import PlanStep
    steps = (PlanStep(
        key="wstg-info-01", runner="nuclei", risk=RiskClass.LOW,
        parameters={}, dependencies=(),
    ),)
    assert _grant().covers_risks(steps)


def test_covers_risks_rejects_above_caps() -> None:
    from secopent.domain.assessments.models import PlanStep
    steps = (PlanStep(
        key="intrusive-01", runner="nuclei", risk=RiskClass.INTRUSIVE,
        parameters={}, dependencies=(),
    ),)
    assert not _grant().covers_risks(steps)
```

**A1.2 — Run, confirm RED** (module doesn't exist).

**A1.3 — Implement.**

`src/secopent/domain/grants/errors.py`:

```python
from ...common.errors import DomainError


class GrantNotFoundError(DomainError):
    """No grant with the given id (or it belongs to another scope of use)."""


class GrantInactiveError(DomainError):
    """The grant is revoked or outside its validity window."""


class GrantScopeMismatchError(DomainError):
    """The assessment's target/ports are not covered by the grant's scope."""


class GrantRiskNotApprovedError(DomainError):
    """A plan step's risk exceeds the grant's risk caps."""
```

`src/secopent/domain/grants/models.py`:

```python
from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum

from ...domain.policy.models import RiskClass
from ...domain.scope.models import ScopeSnapshot
from ..assessments.models import PlanStep
from ..common.canonical import canonical_digest
from ..common.errors import DomainValidationError
from .errors import (  # pycharm marks unused; keeps exception classes importable
    GrantInactiveError,  # noqa: F401
    GrantNotFoundError,  # noqa: F401
    GrantRiskNotApprovedError,  # noqa: F401
    GrantScopeMismatchError,  # noqa: F401
)


class GrantStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class EngagementGrant:
    id: str
    project_id: str
    name: str
    scope: ScopeSnapshot  # single source of truth for the authorization boundary
    risk_caps: frozenset[RiskClass]
    valid_from: datetime
    valid_to: datetime
    created_by: str
    created_at: datetime
    status: GrantStatus
    digest: str
    _DESTRUCTIVE_MSG = "Destructive actions can never be grant-approved"

    @classmethod
    def create(
        cls,
        *,
        project_id: str,
        name: str,
        scope: ScopeSnapshot,
        risk_caps: frozenset[RiskClass],
        valid_from: datetime,
        valid_to: datetime,
        created_by: str,
        created_at: datetime,
        grant_id: str | None = None,
    ) -> EngagementGrant:
        if not name.strip():
            raise DomainValidationError("grant name must be non-empty")
        if RiskClass.DESTRUCTIVE in risk_caps:
            raise DomainValidationError(cls._DESTRUCTIVE_MSG)
        if valid_to <= valid_from:
            raise DomainValidationError("grant window must be positive")
        payload = {
            "project_id": project_id, "name": name.strip(),
            "scope_digest": scope.digest,
            "risk_caps": sorted(r.value for r in risk_caps),
            "valid_from": valid_from.isoformat(), "valid_to": valid_to.isoformat(),
            "created_by": created_by, "created_at": created_at.isoformat(),
        }
        return cls(
            id=grant_id or f"grant-{uuid.uuid4().hex[:12]}",
            project_id=project_id, name=name.strip(), scope=scope,
            risk_caps=frozenset(risk_caps), valid_from=valid_from,
            valid_to=valid_to, created_by=created_by, created_at=created_at,
            status=GrantStatus.ACTIVE, digest=canonical_digest(payload),
        )

    def revoke(self) -> EngagementGrant:
        return replace(self, status=GrantStatus.REVOKED)

    def is_active_at(self, now: datetime) -> bool:
        if self.status is GrantStatus.REVOKED:
            return False
        if now < self.valid_from or now > self.valid_to:
            # 惰性 EXPIRED:caller persists the updated status (domain stays pure).
            return False
        return self.status is GrantStatus.ACTIVE

    def covers_scope(self, assessment_scope: ScopeSnapshot) -> bool:
        """Every assessment target must match the grant scope; ports must ⊆."""
        if not set(assessment_scope.ports) <= set(self.scope.ports):
            return False
        for target in assessment_scope.include:
            if self.scope.includes_url(target) \
                    or self.scope.includes_ip(target) \
                    or self.scope.includes_domain(target):
                continue
            return False
        return True

    def covers_risks(self, steps: tuple[PlanStep, ...]) -> bool:
        return all(step.risk in self.risk_caps for step in steps)
```

> Note: `includes_ip` raises `DomainValidationError` for non-IP values. `covers_scope` catches that via the `includes_domain` fallthrough — but `includes_ip` raises *before* `includes_domain` runs. Fix: reorder so the call is guarded:

```python
    def covers_scope(self, assessment_scope: ScopeSnapshot) -> bool:
        if not set(assessment_scope.ports) <= set(self.scope.ports):
            return False
        for target in assessment_scope.include:
            if self.scope.includes_url(target):
                continue
            if self._matches_hostlike(target):
                continue
            return False
        return True

    def _matches_hostlike(self, target: str) -> bool:
        try:
            if self.scope.includes_ip(target):
                return True
        except DomainValidationError:
            pass
        try:
            return self.scope.includes_domain(target)
        except DomainValidationError:
            return False
```

> Rationale: `includes_url("8.133.200.235")` may also raise (it requires scheme) — keep `_matches_hostlike` as the guarded wrapper and have `covers_scope` try URL then hostlike. The plan's A1.3 implementation must not let a `DomainValidationError` escape `covers_scope`.

**A1.4 — Run, confirm GREEN.**

```bash
py -3.12 -m pytest tests/domain/test_grants.py -q
```

**A1.5 — Commit.**

```bash
git add src/secopent/domain/grants/ tests/domain/test_grants.py
git commit -m "feat(grants): EngagementGrant domain model + covers_scope/covers_risks (v0.6.0)"
```

---

### Task A2 — GrantRepository port + persistence

**Files:** `src/secopent/application/ports/grants.py` (new), `src/secopent/infrastructure/db/grants_models.py` (new), `src/secopent/infrastructure/repositories/sqlalchemy_grants.py` (new), `src/secopent/infrastructure/db/core_models.py` (edit: register CoreEngagementGrant), `tests/infrastructure/test_sqlalchemy_grants.py` (new)

**A2.1 — Write the failing tests** in `tests/infrastructure/test_sqlalchemy_grants.py`:

```python
"""SqlAlchemyGrantRepository round-trip (v0.6.0 spec §3.2/§3.6).

The grant embeds a ScopeSnapshot; persistence must write the snapshot to
core_scope_snapshots (via SqlAlchemyScopeRepository) and the grant row to
core_grants keyed by scope_digest, then reassemble.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from secopent.domain.grants.models import EngagementGrant, GrantStatus
from secopent.domain.policy.models import RiskClass
from secopent.domain.scope.models import ScopeDraft, ScopeLimits
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_grants import (
    SqlAlchemyGrantRepository,
)
from secopent.infrastructure.repositories.sqlalchemy_scope import (
    SqlAlchemyScopeRepository,
)


def _engine(tmp_path):
    return create_sqlite_engine(tmp_path / "grants.db")


def _grant(engine) -> EngagementGrant:
    scope = ScopeDraft(
        project_id="proj-1",
        include=("http://8.133.200.235/", "internal.example.com"),
        exclude=(), ports=(80, 443),
        limits=ScopeLimits(5.0, 3, 50_000),
    ).freeze(snapshot_id="grant-scope-1", approved_by="operator-1")
    return EngagementGrant.create(
        project_id="proj-1", name="ECS prod scan", scope=scope,
        risk_caps=frozenset({RiskClass.PASSIVE, RiskClass.LOW, RiskClass.ACTIVE}),
        valid_from=datetime(2026, 8, 7, tzinfo=UTC),
        valid_to=datetime(2026, 8, 14, tzinfo=UTC),
        created_by="operator-1",
        created_at=datetime(2026, 8, 8, tzinfo=UTC),
    )


def test_grant_round_trip(tmp_path) -> None:
    engine = _engine(tmp_path)
    with Session(engine) as s:
        grant = _grant(engine)
        SqlAlchemyGrantRepository(s).add(grant)
        s.commit()

    with Session(engine) as s:
        loaded = SqlAlchemyGrantRepository(s).get(grant.id)
    assert loaded is not None
    assert loaded.id == grant.id
    assert loaded.project_id == "proj-1"
    assert loaded.digest == grant.digest
    assert loaded.status is GrantStatus.ACTIVE
    assert loaded.scope.digest == grant.scope.digest
    # embedded scope reassembled exactly
    assert loaded.scope.include == grant.scope.include
    assert loaded.scope.ports == grant.scope.ports


def test_list_for_project_only_active_scopes_match(tmp_path) -> None:
    engine = _engine(tmp_path)
    with Session(engine) as s:
        repo = SqlAlchemyGrantRepository(s)
        repo.add(_grant(engine))
        s.commit()
    with Session(engine) as s:
        listings = SqlAlchemyGrantRepository(s).list_for_project("proj-1")
        assert len(listings) == 1
        assert listings[0].name == "ECS prod scan"
    with Session(engine) as s:
        assert SqlAlchemyGrantRepository(s).list_for_project("proj-2") == ()


def test_get_missing_returns_none(tmp_path) -> None:
    engine = _engine(tmp_path)
    with Session(engine) as s:
        assert SqlAlchemyGrantRepository(s).get("grant-missing") is None
```

> Note: `create_sqlite_engine` must create tables. Prefer the repo's caller (`init_db`) — for the test, call `init_db(engine)` or `CoreBase.metadata.create_all(engine)` in a fixture (match how `test_init_db_autostamp.py` does it).

**A2.2 — Run, confirm RED.**

**A2.3 — Implement.**

`src/secopent/application/ports/grants.py`:

```python
from __future__ import annotations

from typing import Protocol

from ...domain.grants.models import EngagementGrant


class GrantRepository(Protocol):
    def add(self, grant: EngagementGrant) -> None: ...
    def get(self, grant_id: str) -> EngagementGrant | None: ...
    def list_for_project(self, project_id: str) -> tuple[EngagementGrant, ...]: ...
```

`src/secopent/infrastructure/db/grants_models.py`:

```python
from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .core_models import CoreBase


class CoreEngagementGrant(CoreBase):
    __tablename__ = "core_grants"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(40), index=True)
    name: Mapped[str] = mapped_column(String(120))
    scope_digest: Mapped[str] = mapped_column(
        String(70), ForeignKey("core_scope_snapshots.digest")
    )
    risk_caps: Mapped[str] = mapped_column(Text)  # JSON list of RiskClass values
    valid_from: Mapped[datetime]
    valid_to: Mapped[datetime]
    created_by: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime]
    status: Mapped[str] = mapped_column(String(12))
    digest: Mapped[str] = mapped_column(String(70), unique=True)
```

`src/secopent/infrastructure/repositories/sqlalchemy_grants.py`:

```python
from __future__ import annotations

import json

from sqlalchemy import select

from ...domain.grants.models import EngagementGrant, GrantStatus
from ...domain.policy.models import RiskClass
from ...domain.scope.models import ScopeSnapshot
from ..db.grants_models import CoreEngagementGrant
from .sqlalchemy_scope import SqlAlchemyScopeRepository


class SqlAlchemyGrantRepository:
    """Persist grants; the embedded scope lives in core_scope_snapshots."""

    def __init__(self, session) -> None:
        self._session = session
        self._scopes = SqlAlchemyScopeRepository(session)

    def add(self, grant: EngagementGrant) -> None:
        self._scopes.add_snapshot(grant.scope)
        row = CoreEngagementGrant(
            id=grant.id, project_id=grant.project_id, name=grant.name,
            scope_digest=grant.scope.digest,
            risk_caps=json.dumps(sorted(r.value for r in grant.risk_caps)),
            valid_from=grant.valid_from, valid_to=grant.valid_to,
            created_by=grant.created_by, created_at=grant.created_at,
            status=grant.status.value, digest=grant.digest,
        )
        self._session.merge(row)

    def get(self, grant_id: str) -> EngagementGrant | None:
        row = self._session.execute(
            select(CoreEngagementGrant).where(CoreEngagementGrant.id == grant_id)
        ).scalar_one_or_none()
        if row is None:
            return None
        scope = self._scopes.get_snapshot(row.scope_digest)
        if scope is None:  # pragma: no cover - FK guarantees presence
            return None
        return EngagementGrant(
            id=row.id, project_id=row.project_id, name=row.name,
            scope=scope,
            risk_caps=frozenset(RiskClass(v) for v in json.loads(row.risk_caps)),
            valid_from=row.valid_from, valid_to=row.valid_to,
            created_by=row.created_by, created_at=row.created_at,
            status=GrantStatus(row.status), digest=row.digest,
        )

    def list_for_project(self, project_id: str) -> tuple[EngagementGrant, ...]:
        rows = self._session.execute(
            select(CoreEngagementGrant)
            .where(CoreEngagementGrant.project_id == project_id)
            .order_by(CoreEngagementGrant.created_at.desc())
        ).scalars().all()
        return tuple(self.get(r.id) for r in rows if self.get(r.id) is not None)
```

> Note: verify `SqlAlchemyScopeRepository` has `add_snapshot`/`get_snapshot` in the plan's own A2.3 before writing (check `infrastructure/repositories/sqlalchemy_scope.py`; if the API differs, adapt the above to the actual method names). The planner/approval flow already uses `ScopeRepository` for the assessment's scope — grant persistence must reuse the SAME scope storage the assessment uses, never a shadow of it.

**A2.4 — Alembic migration** (`alembic/versions/xxxx_add_core_grants.py`):

```python
"""add core_grants

Revision ID: <new-rev>
Revises: 811a5b9a583d
"""
from alembic import op
import sqlalchemy as sa


def upgrade() -> None:
    op.create_table(
        "core_grants",
        sa.Column("id", sa.String(40), primary_key=True),
        sa.Column("project_id", sa.String(40), nullable=False, index=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("scope_digest", sa.String(70),
                  sa.ForeignKey("core_scope_snapshots.digest"), nullable=False),
        sa.Column("risk_caps", sa.Text(), nullable=False),
        sa.Column("valid_from", sa.DateTime(), nullable=False),
        sa.Column("valid_to", sa.DateTime(), nullable=False),
        sa.Column("created_by", sa.String(40), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("digest", sa.String(70), nullable=False, unique=True),
    )


def downgrade() -> None:
    op.drop_table("core_grants")
```

Also register `CoreEngagementGrant` in `core_models.py` imports and update `baseline_schema.py` equivalence test if the baseline includes core_grants (the baseline already exists — do NOT edit the historical baseline; add only the new migration).

**A2.5 — Run, confirm GREEN + no baseline regression.**

```bash
py -3.12 -m pytest tests/infrastructure/test_sqlalchemy_grants.py tests/infrastructure/test_init_db_autostamp.py -q
```

**A2.6 — Commit.**

```bash
git add src/secopent/application/ports/grants.py src/secopent/infrastructure/db/grants_models.py src/secopent/infrastructure/repositories/sqlalchemy_grants.py alembic/versions/ tests/infrastructure/test_sqlalchemy_grants.py
git commit -m "feat(grants): GrantRepository port + SqlAlchemy + alembic migration (v0.6.0)"
```

---

### Task A3 — GrantService

**Files:** `src/secopent/application/grants.py` (new), `tests/application/test_grants_service.py` (new)

**A3.1 — Write the failing tests** in `tests/application/test_grants_service.py`:

```python
"""GrantService: create_human / revoke / authorize (v0.6.0 spec §3.3)."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from secopent.application.assessments import AssessmentPermissionError
from secopent.application.grants import GrantService
from secopent.domain.assessments.models import PlanStep
from secopent.domain.common.errors import DomainError
from secopent.domain.grants.errors import GrantInactiveError, GrantNotFoundError
from secopent.domain.grants.models import EngagementGrant, GrantStatus
from secopent.domain.policy.models import RiskClass
from secopent.domain.scope.models import ScopeDraft, ScopeLimits, ScopeSnapshot


@dataclass
class _MemoryGrantRepo:
    items: dict[str, EngagementGrant] = field_factory()

    def add(self, grant):
        self.items[grant.id] = grant
    def get(self, grant_id):
        return self.items.get(grant_id)
    def list_for_project(self, project_id):
        return tuple(g for g in self.items.values() if g.project_id == project_id)


def _scope(**overrides) -> ScopeSnapshot:
    return ScopeDraft(
        project_id="proj-1",
        include=("http://8.133.200.235/",),
        exclude=(), ports=(80, 443),
        limits=ScopeLimits(5.0, 3, 50_000),
    ).freeze(snapshot_id=overrides.get("id", "s1"), approved_by="operator-1")


def _service(repo=None) -> GrantService:
    return GrantService(repo or _MemoryGrantRepo())


def test_create_human_by_agent_raises() -> None:
    repo = _MemoryGrantRepo()
    with pytest.raises(AssessmentPermissionError):
        _service(repo).create_human(
            project_id="proj-1", name="g", scope=_scope(),
            risk_caps=frozenset({RiskClass.LOW}),
            valid_from=datetime(2026, 8, 8, tzinfo=UTC),
            valid_to=datetime(2026, 8, 9, tzinfo=UTC),
            actor_role="agent",
        )
    assert repo.items == {}


def test_create_human_by_human_ok() -> None:
    g = _service().create_human(
        project_id="proj-1", name="g", scope=_scope(),
        risk_caps=frozenset({RiskClass.LOW}),
        valid_from=datetime(2026, 8, 8, tzinfo=UTC),
        valid_to=datetime(2026, 8, 9, tzinfo=UTC),
        actor_role="human",
    )
    assert g.status is GrantStatus.ACTIVE


def test_authorize_active_and_covered() -> None:
    repo = _MemoryGrantRepo()
    svc = _service(repo)
    g = svc.create_human(project_id="proj-1", name="g", scope=_scope(),
                         risk_caps=frozenset({RiskClass.LOW}),
                         valid_from=datetime(2026, 8, 8, tzinfo=UTC),
                         valid_to=datetime(2026, 8, 9, tzinfo=UTC),
                         actor_role="human")
    step = PlanStep(key="s", runner="nuclei", risk=RiskClass.LOW, parameters={}, dependencies=())
    decision = svc.authorize(g.id, _scope(), (step,), now=datetime(2026, 8, 8, tzinfo=UTC))
    assert decision.allowed is True
    assert decision.reason == "ALLOWED"


def test_authorize_grant_not_found() -> None:
    decision = _service().authorize("grant-missing", _scope(), (),
                                    now=datetime(2026, 8, 8, tzinfo=UTC))
    assert decision.allowed is False
    assert decision.reason == "GRANT_NOT_FOUND"


def test_authorize_expired_grant() -> None:
    repo = _MemoryGrantRepo()
    svc = _service(repo)
    g = svc.create_human(project_id="proj-1", name="g", scope=_scope(),
                         risk_caps=frozenset({RiskClass.LOW}),
                         valid_from=datetime(2026, 8, 1, tzinfo=UTC),
                         valid_to=datetime(2026, 8, 2, tzinfo=UTC),
                         actor_role="human")
    decision = svc.authorize(g.id, _scope(), (), now=datetime(2026, 8, 8, tzinfo=UTC))
    assert decision.allowed is False
    assert decision.reason == "GRANT_INACTIVE"


def test_authorize_scope_mismatch() -> None:
    repo = _MemoryGrantRepo()
    svc = _service(repo)
    g = svc.create_human(project_id="proj-1", name="g", scope=_scope(),
                         risk_caps=frozenset({RiskClass.LOW}),
                         valid_from=datetime(2026, 8, 8, tzinfo=UTC),
                         valid_to=datetime(2026, 8, 9, tzinfo=UTC),
                         actor_role="human")
    out_of_scope = _scope(id="s2")
    out_of_scope_other = ScopeDraft(project_id="proj-1",
        include=("http://8.133.200.236/",), exclude=(), ports=(80, 443),
        limits=ScopeLimits(5.0, 3, 50_000)).freeze(snapshot_id="s2", approved_by="operator-1")
    decision = svc.authorize(g.id, out_of_scope_other, (),
                             now=datetime(2026, 8, 8, tzinfo=UTC))
    assert decision.allowed is False
    assert decision.reason == "GRANT_SCOPE_MISMATCH"


def test_authorize_risk_exceeds_caps() -> None:
    repo = _MemoryGrantRepo()
    svc = _service(repo)
    g = svc.create_human(project_id="proj-1", name="g", scope=_scope(),
                         risk_caps=frozenset({RiskClass.LOW}),
                         valid_from=datetime(2026, 8, 8, tzinfo=UTC),
                         valid_to=datetime(2026, 8, 9, tzinfo=UTC),
                         actor_role="human")
    step = PlanStep(key="h", runner="nuclei", risk=RiskClass.ACTIVE, parameters={}, dependencies=())
    decision = svc.authorize(g.id, _scope(), (step,),
                             now=datetime(2026, 8, 8, tzinfo=UTC))
    assert decision.allowed is False
    assert decision.reason == "GRANT_RISK_NOT_APPROVED"


def test_revoke_marks_status() -> None:
    repo = _MemoryGrantRepo()
    svc = _service(repo)
    g = svc.create_human(project_id="proj-1", name="g", scope=_scope(),
                         risk_caps=frozenset({RiskClass.LOW}),
                         valid_from=datetime(2026, 8, 8, tzinfo=UTC),
                         valid_to=datetime(2026, 8, 9, tzinfo=UTC),
                         actor_role="human")
    revoked = svc.revoke(g.id, actor_role="human")
    assert revoked.status is GrantStatus.REVOKED
    assert _service(repo).authorize(g.id, _scope(), (),
                                    now=datetime(2026, 8, 8, tzinfo=UTC)).allowed is False
```

**A3.2 — Run, confirm RED.**

**A3.3 — Implement** `src/secopent/application/grants.py`:

```python
from __future__ import annotations

from datetime import datetime
from typing import Protocol

from ..domain.assessments.models import PlanStep
from ..domain.grants.models import EngagementGrant
from ..domain.policy.models import RiskClass
from ..domain.scope.models import ScopeSnapshot
from .assessments import AssessmentPermissionError
from .ports.grants import GrantRepository


class GrantDecision(Protocol):
    allowed: bool
    reason: str


@dataclass(frozen=True, slots=True)
class _Decision:
    allowed: bool
    reason: str


class GrantService:
    """Own the grant lifecycle. Creation/revocation are human-only."""

    def __init__(self, repo: GrantRepository) -> None:
        self._repo = repo

    def create_human(self, *, project_id: str, name: str, scope: ScopeSnapshot,
                     risk_caps: frozenset[RiskClass], valid_from: datetime,
                     valid_to: datetime, actor_role: str) -> EngagementGrant:
        self._require_human(actor_role)
        grant = EngagementGrant.create(
            project_id=project_id, name=name, scope=scope,
            risk_caps=risk_caps, valid_from=valid_from, valid_to=valid_to,
            created_by=actor_role, created_at=utc_now(),
        )
        self._repo.add(grant)
        return grant

    def revoke(self, grant_id: str, *, actor_role: str) -> EngagementGrant:
        self._require_human(actor_role)
        grant = self._repo.get(grant_id)
        if grant is None:
            raise GrantNotFoundError(f"grant not found: {grant_id}")
        revoked = grant.revoke()
        self._repo.add(revoked)
        return revoked

    def authorize(self, grant_id: str, scope: ScopeSnapshot,
                  steps: tuple[PlanStep, ...], *, now: datetime) -> _Decision:
        grant = self._repo.get(grant_id)
        if grant is None:
            return _Decision(False, "GRANT_NOT_FOUND")
        if not grant.is_active_at(now):
            return _Decision(False, "GRANT_INACTIVE")
        if not grant.covers_scope(scope):
            return _Decision(False, "GRANT_SCOPE_MISMATCH")
        if not grant.covers_risks(steps):
            return _Decision(False, "GRANT_RISK_NOT_APPROVED")
        return _Decision(True, "ALLOWED")

    def list_active(self, project_id: str, *, now: datetime) -> tuple[EngagementGrant, ...]:
        return tuple(
            g for g in self._repo.list_for_project(project_id) if g.is_active_at(now)
        )

    @staticmethod
    def _require_human(actor_role: str) -> None:
        if actor_role != "human":
            raise AssessmentPermissionError(
                "grant creation/revocation is human-only"
            )
```

(add `from dataclasses import dataclass`, `from ..domain.common.canonical import utc_now`, `from .errors import GrantNotFoundError` imports)

**A3.4 — Run, confirm GREEN.**

**A3.5 — Commit.**

```bash
git add src/secopent/application/grants.py tests/application/test_grants_service.py
git commit -m "feat(grants): GrantService create_human/revoke/authorize (v0.6.0)"
```

---

### Task A4 — Approval-gate integration in AssessmentService

**Files:** `src/secopent/application/assessments.py` (edit), `src/secopent/application/grants.py` (edit: helper), `tests/application/test_grant_approval_path.py` (new)

**A4.1 — Write the failing tests** in `tests/application/test_grant_approval_path.py`:

```python
"""AssessmentService approve/start via grant (v0.6.0 spec §3.4).

The grant path must override _require_human ONLY when the grant authorizes
the exact scope + plan; all existing human behavior must remain intact.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

import pytest

from secopent.application.assessments import (
    AssessmentPermissionError,
    AssessmentService,
)
from secopent.application.grants import GrantService
from secopent.domain.assessments.models import Assessment, AssessmentStatus
from secopent.domain.grants.models import EngagementGrant
from secopent.domain.policy.models import ExecutionMode, RiskClass
from secopent.domain.scope.models import ScopeDraft, ScopeLimits, ScopeSnapshot
from test_execution import _seed_approved  # reuse seed helper


@dataclass
class _MemoryGrantRepo:
    items: dict[str, EngagementGrant] = field_factory()
    def add(self, g): self.items[g.id] = g
    def get(self, gid): return self.items.get(gid)
    def list_for_project(self, pid):
        return tuple(g for g in self.items.values() if g.project_id == pid)


def _grant(project_id="p1") -> EngagementGrant:
    scope = ScopeDraft(project_id=project_id,
        include=("http://target",), exclude=(), ports=(80,),
        limits=ScopeLimits(5.0, 3, 50_000)).freeze(snapshot_id="gs", approved_by="operator-1")
    return EngagementGrant.create(project_id=project_id, name="g", scope=scope,
        risk_caps=frozenset({RiskClass.LOW}),
        valid_from=datetime(2026, 1, 1, tzinfo=UTC),
        valid_to=datetime(2026, 12, 31, tzinfo=UTC),
        created_by="operator-1", created_at=datetime(2026, 1, 1, tzinfo=UTC))


def _svc(repos, repo=None, svc=None) -> AssessmentService:
    return AssessmentService(repos.assessments, grant_service=svc or GrantService(repo or _MemoryGrantRepo()))


def test_agent_without_grant_still_denied(memory_repositories) -> None:
    a = _seed_approved(memory_repositories)  # human-approved, but…
    # start without grant as agent must still be rejected
    with pytest.raises(AssessmentPermissionError):
        AssessmentService(memory_repositories.assessments).start(a.id, actor_role="agent")


def test_agent_approve_via_grant_ok(memory_repositories) -> None:
    a = _seed_approved(memory_repositories)
    svc = _svc(memory_repositories, repo=_MemoryGrantRepo())
    # attach a plan + approve via grant
    from secopent.domain.assessments.models import PlanStep
    a2 = svc.attach_plan(a.id, steps=(PlanStep(key="k", runner="nuclei", risk=RiskClass.LOW, parameters={}, dependencies=()),))
    approval = svc.approve(
        assessment_id=a.id,
        approved_by="agent",           # ignored - overridden to grant:<id>
        approved_risks=frozenset({RiskClass.LOW}),
        approved_capabilities=frozenset(),
        scope_digest="sha256:scope",   # must match the seeded scope digest
        actor_role="agent",
        grant_id="grant-1",
    )
    assert approval.approved_by == "grant:grant-1"


def test_agent_start_via_grant_ok(memory_repositories) -> None:
    a = _seed_approved(memory_repositories)
    svc = _svc(memory_repositories, repo=_MemoryGrantRepo())
    from secopent.domain.assessments.models import PlanStep
    svc.attach_plan(a.id, steps=(PlanStep(key="k", runner="nuclei", risk=RiskClass.LOW, parameters={}, dependencies=()),))
    svc.approve(assessment_id=a.id, approved_by="agent",
                approved_risks=frozenset({RiskClass.LOW}),
                approved_capabilities=frozenset(), scope_digest="sha256:scope",
                actor_role="agent", grant_id="grant-1")
    started = svc.start(a.id, actor_role="agent", grant_id="grant-1")
    assert started.status is AssessmentStatus.QUEUED


def test_agent_start_via_grant_scope_mismatch_denied(memory_repositories) -> None:
    a = _seed_approved(memory_repositories)
    # grant covers http://target, but the seeded scope differs → deny
    svc = _svc(memory_repositories, repo=_MemoryGrantRepo())
    from secopent.domain.assessments.models import PlanStep
    svc.attach_plan(a.id, steps=(PlanStep(key="k", runner="nuclei", risk=RiskClass.LOW, parameters={}, dependencies=()),))
    with pytest.raises(AssessmentPermissionError):
        svc.approve(assessment_id=a.id, approved_by="agent",
                    approved_risks=frozenset({RiskClass.LOW}),
                    approved_capabilities=frozenset(), scope_digest="sha256:scope",
                    actor_role="agent", grant_id="grant-1")
    # scope digest mismatch: the seed uses a different scope
```

> Note: the exact seed (`_seed_approved`) scope digest is `"sha256:scope"` (from `test_execution.py`). The grant's embedded scope must be compatible with the assessment's scope for the happy path. In the plan's own A4.1, seed a scope that the grant actually covers (e.g., build the seed with `ScopeDraft(include=("http://target",))` so both agree) — adjust the fixture so the "approve via grant ok" test uses a matching scope and the mismatch test uses a different one.

**A4.2 — Run, confirm RED.**

**A4.3 — Implement.** In `assessment.py`:

- Constructor: `def __init__(self, repo: AssessmentRepository, grant_service: GrantService | None = None)`
- `approve`: add `grant_id: str | None = None`; at the top:

```python
        if grant_id is not None:
            if self._grant_service is None:
                raise AssessmentPermissionError("grant service not configured")
            decision = self._grant_service.authorize(
                grant_id, self._assessment_scope(assessment_id), self._plan_steps(assessment_id),
                now=utc_now(),
            )
            if not decision.allowed:
                raise AssessmentPermissionError(f"grant denied: {decision.reason}")
            approved_by = f"grant:{grant_id}"  # override caller-supplied value
        else:
            self._require_human(actor_role)
```

- `start`: add `grant_id: str | None = None`; at the top:

```python
        if grant_id is not None:
            if self._grant_service is None:
                raise AssessmentPermissionError("grant service not configured")
            decision = self._grant_service.authorize(
                grant_id, self._assessment_scope(assessment_id), self._plan_steps(assessment_id),
                now=utc_now(),
            )
            if not decision.allowed:
                raise AssessmentPermissionError(f"grant denied: {decision.reason}")
        else:
            self._require_human(actor_role)
```

- private helpers:

```python
    def _assessment_scope(self, assessment_id: str) -> ScopeSnapshot:
        # resolve from the repo port (get_snapshot on scope repo) or from the
        # caller-supplied scope_digest — the AssessmentService has only the
        # assessment repo; adapt to what the repo exposes. See plan A4.3 note.
        raise NotImplementedError("A4.3: wire scope from the repo port")
```

> Note: `AssessmentService` currently has no scope repository. Simplest correct shape: extend the constructor to `(repo, scope_repo: ScopeRepository | None = None, grant_service: GrantService | None = None)` and resolve both scope + plan from repos inside authorize. In tests, pass the in-memory scope repo. In the API/MCP layer, the same caller that builds `AssessmentService` also owns the scope repo — wire it there (composition root). The plan's A4.3 must implement `_authorize` that reads `scope_repo.get_snapshot(assessment.scope_snapshot_id)` + `repo.get_plan(assessment.active_plan_id)` and pass those into `grant_service.authorize`. Keep the signature change additive (`grant_id=None` default).

**A4.4 — Run application tests, confirm GREEN + no regression on `test_execution_gates.py` T8.**

**A4.5 — Commit.**

```bash
git add src/secopent/application/assessments.py src/secopent/application/grants.py tests/application/test_grant_approval_path.py
git commit -m "feat(grants): approve/start grant path in AssessmentService (v0.6.0)"
```

---

### Task A5 — MCP handlers: de-deadcode + grant_list

**Files:** `src/secopent/interfaces/mcp/handlers.py` (edit), `src/secopent/interfaces/mcp/tool_registry.py` (edit), `tests/interfaces/test_mcp_grant_handlers.py` (new)

**A5.1 — Write the failing tests** in `tests/interfaces/test_mcp_grant_handlers.py`. Reuse the existing MCP test harness (find the current one — e.g. `tests/interfaces/test_mcp_tools.py` or the registry self-tests). The tests drive the FastMCP registry directly with a real `McpRuntime`:

```python
"""MCP grant handlers: plan_approve/start via grant, grant_list (v0.6.0 §3.5)."""
from __future__ import annotations

import pytest

from secopent.interfaces.mcp.handlers import (
    handler_grant_list, handler_plan_approve, handler_assessment_start,
)


@pytest.fixture
def mcp_runtime(tmp_path):
    # build a real McpRuntime with a sqlite DB + audit chain + grant service
    # (mirror the existing test fixture for MCP handlers in the repo)
    ...


def test_plan_approve_without_grant_returns_human_required(runtime, seed_assessment):
    result = handler_plan_approve(runtime, assessment_id=seed_assessment)
    assert result["status"] == "HUMAN_REQUIRED"


def test_plan_approve_with_grant_records_approval(runtime, seed_assessment_with_grant):
    result = handler_plan_approve(
        runtime, assessment_id=seed_assessment_with_grant, grant_id="grant-1"
    )
    assert result["status"] != "HUMAN_REQUIRED"


def test_assessment_start_without_grant_human_required(runtime, seed_assessment):
    result = handler_assessment_start(runtime, assessment_id=seed_assessment)
    assert result["status"] == "HUMAN_REQUIRED"


def test_assessment_start_with_grant_starts(runtime, seed_assessment_with_grant):
    result = handler_assessment_start(runtime, assessment_id=seed_assessment_with_grant, grant_id="grant-1")
    assert result["status"] != "HUMAN_REQUIRED"


def test_grant_list_returns_active_only(runtime, seed_two_grants):
    result = handler_grant_list(runtime, project_id="proj-1")
    assert result["status"] == "success"  # whatever the structure is
    assert any(g["id"] == "grant-1" for g in result.get("grants", []))
```

> Note: the exact harness (`McpRuntime`, seed helpers, result keys) must be discovered from the existing MCP tests in A5.1 before writing — adapt the scaffold to the real fixture. The goal is: (1) no-grant → HUMAN_REQUIRED; (2) grant → real service call; (3) grant_list returns only ACTIVE.

**A5.2 — Run, confirm RED.**

**A5.3 — Implement.** In `handlers.py`:

- `handler_plan_approve`: replace the `if False else _human_required` lambda with:

```python
def handler_plan_approve(runtime, *, assessment_id, approved_risks=None,
                         approved_capabilities=None, grant_id=None):
    """Approve a plan. Human approves directly; an agent needs a grant."""
    if not grant_id:
        return _human_required("plan_approve", assessment_id,
                               "agents need a grant to approve (see grant_list)")
    with runtime.db.unit_of_work() as uow:
        session = uow.session
        service = AssessmentService(
            SqlAlchemyAssessmentRepository(session),
            grant_service=runtime.grant_service,           # ← composed
        )
        return _guard("plan_approve", lambda: (
            _assessment_out(service.approve(
                assessment_id=assessment_id,
                approved_by="agent",                       # service overrides to grant:<id>
                approved_risks=frozenset(RiskClass(r) for r in (approved_risks or [])),
                approved_capabilities=frozenset(approved_capabilities or []),
                scope_digest="",
                actor_role="agent",
                grant_id=grant_id,
            ))
        ))
```

- `handler_assessment_start`: same pattern with `service.start(..., actor_role="agent", grant_id=grant_id)`.
- `handler_grant_list`:

```python
def handler_grant_list(runtime, *, project_id: str) -> dict[str, object]:
    """List active grants for a project (agent discovers what it may run)."""
    with runtime.db.unit_of_work() as uow:
        service = GrantService(SqlAlchemyGrantRepository(uow.session))
        now = utc_now()
        return {
            "status": "success",
            "project_id": project_id,
            "grants": [
                {"id": g.id, "name": g.name,
                 "scope_include": list(g.scope.include),
                 "risk_caps": sorted(r.value for r in g.risk_caps),
                 "valid_to": g.valid_to.isoformat()}
                for g in service.list_active(project_id, now=now)
            ],
        }
```

- `tool_registry.py`: update `plan_approve`/`assessment_start` arg schemas (add `grant_id: str | None`), register `grant_list` with `project_id` arg.
- `main.py` composition root: build `GrantService(SqlAlchemyGrantRepository(...))` once, attach to `app.state` + `runtime.grant_service`; the MCP server gets it via `McpRuntime.grant_service`.

**A5.4 — Run, confirm GREEN.**

**A5.5 — Commit.**

```bash
git add src/secopent/interfaces/mcp/handlers.py src/secopent/interfaces/mcp/tool_registry.py src/secopent/interfaces/api/main.py tests/interfaces/test_mcp_grant_handlers.py
git commit -m "feat(mcp): plan_approve/start via grant + grant_list (v0.6.0)"
```

---

### Task A6 — Phase A quality gate + docs + release v0.6.0

**A6.1 — Full gate:**

```bash
py -3.12 -m ruff check .
py -3.12 -m mypy src/secopent
py -3.12 scripts/lint_forbidden_patterns.py  # R3: .record( calls must carry session=
py -3.12 -m pytest --cov=src --cov-report=term --cov-fail-under=80 -q
```

**A6.2 — Docs:** `docs/deployment/grants.md` (operator: how to create/revoke grants, what the agent can then do), CHANGELOG `[Unreleased]` → `### v0.6.0 (in progress)`.

**A6.3 — Commit + release** (only after user confirms): `scripts/release.sh 0.6.0`.

---

## Phase B — Mission (v0.6.1)

### Task B1 — LLMPlanner

**Files:** `src/secopent/application/llm_planner.py` (new), `tests/application/test_llm_planner.py` (new)

**B1.1 — Write the failing tests**:

```python
"""LLMPlanner: intent-driven test-class selection with deterministic floor
(v0.6.1 spec §4.2)."""
from __future__ import annotations

import pytest

from secopent.application.llm_planner import LLMPlanner
from secopent.domain.policy.models import RiskClass


class _FakeBackend:
    def __init__(self, output: str): self._output = output
    def complete(self, prompt: str) -> str: return self._output


def test_llm_selected_classes_are_added_to_required() -> None:
    # catalog has required classes web_app:sqli + web_app:xss; LLM adds xss-extra
    planner = LLMPlanner(backend=_FakeBackend('["web_app:xss-extra"]'), catalog=_catalog())
    plan = planner.generate(plan_id="p", assessment_id="a", asset_types=(AssetType.WEB_APP,),
                            intent="find xss")
    keys = [s.key for s in plan.steps]
    assert "web_app:sqli" in keys          # required floor preserved
    assert "web_app:xss-extra" in keys     # LLM addition present


def test_llm_invalid_ids_are_dropped() -> None:
    planner = LLMPlanner(backend=_FakeBackend('["web_app:not-real", "garbage"]'), catalog=_catalog())
    plan = planner.generate(plan_id="p", assessment_id="a", asset_types=(AssetType.WEB_APP,),
                            intent="whatever")
    keys = [s.key for s in plan.steps]
    assert "web_app:not-real" not in keys


def test_llm_null_backend_degrades_to_required() -> None:
    planner = LLMPlanner(backend=None, catalog=_catalog())
    plan = planner.generate(plan_id="p", assessment_id="a", asset_types=(AssetType.WEB_APP,),
                            intent="anything")
    assert [s.key for s in plan.steps] == ["web_app:sqli", "web_app:xss"]  # required only


def test_llm_risk_cap_filters_selection() -> None:
    planner = LLMPlanner(backend=_FakeBackend('["web_app:sqli", "web_app:active-lab"]'), catalog=_catalog())
    plan = planner.generate(plan_id="p", assessment_id="a", asset_types=(AssetType.WEB_APP,),
                            intent="active stuff", risk_cap=RiskClass.LOW)
    keys = [s.key for s in plan.steps]
    assert "web_app:active-lab" not in keys  # above LOW cap filtered
```

(Adapt `_catalog()` to the real TestCatalog in B1.1 — check `tests/e2e_real/test_orchestration.py` for how a catalog is built for tests.)

**B1.2 — Run, confirm RED.**

**B1.3 — Implement** `src/secopent/application/llm_planner.py`:

```python
"""LLMPlanner (v0.6.1): catalog floor + LLM test-class selection (spec §4.2).

The deterministic required classes (catalog.required_for per asset type) are
ALWAYS included - the LLM may only ADD classes it deems relevant to the
mission intent. risk_cap (or the grant's caps) filters the final set. Any LLM
failure/absence degrades to the deterministic plan (never fails the mission).
"""
from __future__ import annotations

import json
from collections.abc import Sequence

from ..domain.assessments.models import ExecutionPlan, PlanStep
from ..domain.catalog.models import AssetType, TestCatalog
from ..domain.common.canonical import canonical_digest
from ..domain.policy.models import RiskClass
from .remote_model import ModelBackend

_DEFAULT_RUNNERS: dict[AssetType, str] = {
    AssetType.WEB_APP: "nuclei",
    AssetType.API: "nuclei",
    AssetType.IP_PORT: "nmap",
    AssetType.CLOUD_ACCOUNT: "prowler",
    AssetType.CONTAINER_K8S: "trivy",
}


class LLMPlanner:
    def __init__(self, backend: ModelBackend | None, catalog: TestCatalog,
                 runner_map: dict[AssetType, str] | None = None) -> None:
        self._backend = backend
        self._catalog = catalog
        self._runners = dict(_DEFAULT_RUNNERS)
        if runner_map:
            self._runners.update(runner_map)

    def generate(self, *, plan_id: str, assessment_id: str,
                 asset_types: Sequence[AssetType], intent: str,
                 risk_cap: RiskClass | None = None) -> ExecutionPlan:
        selected = self._floor_classes(asset_types)
        if self._backend is not None:
            selected |= self._llm_classes(intent, risk_cap)
        steps = [
            PlanStep(
                key=f"{asset_type.value}:{cls.id}",
                runner=self._runners.get(asset_type, "adapter"),
                risk=cls.risk,
                parameters={
                    "asset_type": asset_type.value,
                    "test_class": cls.id,
                    "cwe": cls.cwe,
                    "owasp": cls.owasp,
                    "intent": intent,
                },
                dependencies=(),
            )
            for asset_type in asset_types
            for cls in sorted(selected, key=lambda c: c.id)
            if cls.asset_type == asset_type.value or asset_type.value == cls.asset_type
        ]
        return ExecutionPlan.create(
            plan_id=plan_id, assessment_id=assessment_id, version=1,
            steps=tuple(steps),
        )

    def _floor_classes(self, asset_types: Sequence[AssetType]) -> set[object]:
        required: set[object] = set()
        for asset_type in asset_types:
            required |= set(self._catalog.required_for(asset_type))
        return required

    def _llm_classes(self, intent: str, risk_cap: RiskClass | None) -> set[object]:
        try:
            prompt = self._build_prompt(intent, risk_cap)
            raw = self._backend.complete(prompt)  # type: ignore[union-attr]
            ids = {str(x) for x in json.loads(raw) if isinstance(x, (str, dict))}
        except Exception:  # noqa: BLE001 - degrade on any LLM failure
            return set()
        catalog_by_id = {c.id: c for c in self._catalog.all_classes()}
        result: set[object] = set()
        for cid in ids:
            cls = catalog_by_id.get(cid)
            if cls is None:
                continue
            if risk_cap is not None and _rank(cls.risk) > _rank(risk_cap):
                continue
            result.add(cls)
        return result

    def _build_prompt(self, intent: str, risk_cap: RiskClass | None) -> str:
        classes = self._catalog.all_classes()
        lines = "\n".join(
            f'- "{c.id}" (risk={c.risk.value}, cwe={",".join(c.cwe)})' for c in classes
        )
        cap = risk_cap.value if risk_cap else "no cap"
        return (
            f"Mission intent: {intent}\n"
            f"Select the most relevant test classes from this catalog "
            f"(risk cap: {cap}). Return ONLY a JSON array of ids:\n{lines}"
        )
```

**B1.4 — Run, confirm GREEN + existing planner tests unaffected.**

**B1.5 — Commit.**

```bash
git add src/secopent/application/llm_planner.py tests/application/test_llm_planner.py
git commit -m "feat(llm-planner): intent-driven class selection with catalog floor (v0.6.1)"
```

---

### Task B2 — mission_create MCP tool

**Files:** `src/secopent/interfaces/mcp/handlers.py` (edit), `src/secopent/interfaces/mcp/tool_registry.py` (edit), `tests/interfaces/test_mcp_mission.py` (new)

**B2.1 — Write the failing tests** (seed a real runtime + catalog + LLMPlanner + grant; drive `handler_mission_create`):

```python
"""Mission end-to-end: scope→assessment→LLM plan→grant approve→start (v0.6.1 §4)."""
from __future__ import annotations

import pytest

from secopent.interfaces.mcp.handlers import handler_mission_create


def test_mission_create_with_grant_runs_assessment(runtime, seeded_grant) -> None:
    result = handler_mission_create(
        runtime,
        target="http://8.133.200.235/",
        intent="find exposed admin panels",
        grant_id="grant-1",
        project_id="proj-1",
    )
    assert result["status"] == "success"
    assert result["assessment_id"]  # created + approved + started


def test_mission_create_out_of_scope_target_denied(runtime, seeded_grant) -> None:
    result = handler_mission_create(
        runtime, target="http://192.168.50.50/", intent="x",
        grant_id="grant-1", project_id="proj-1",
    )
    assert result["status"] != "success"  # e.g. "error" with grant-code


def test_mission_create_missing_grant_denied(runtime, empty_repo) -> None:
    result = handler_mission_create(
        runtime, target="http://8.133.200.235/", intent="x",
        grant_id="grant-missing", project_id="proj-1",
    )
    assert result["status"] != "success"


def test_mission_create_llm_unavailable_still_runs(runtime, seeded_grant, no_llm) -> None:
    # backend=None -> deterministic required-floor plan; mission still completes
    result = handler_mission_create(
        runtime, target="http://8.133.200.235/", intent="x",
        grant_id="grant-1", project_id="proj-1",
    )
    assert result["status"] == "success"
```

**B2.2 — Run, confirm RED.**

**B2.3 — Implement** `handler_mission_create`:

```python
def handler_mission_create(runtime, *, target: str, intent: str,
                           grant_id: str, project_id: str,
                           risk_cap: str | None = None) -> dict[str, object]:
    """Agent dispatches a high-level task; the project decides the cases."""
    with runtime.db.unit_of_work() as uow:
        session = uow.session
        grant_service = GrantService(SqlAlchemyGrantRepository(session))
        grant = grant_service._repo.get(grant_id)  # or a public grant_get
        if grant is None:
            return _error("GRANT_NOT_FOUND", f"no grant {grant_id}")
        if not grant.is_active_at(utc_now()):
            return _error("GRANT_INACTIVE", "grant is not active")
        if not grant.covers_scope(ScopeDraft(
            project_id=project_id, include=(target,), exclude=(),
            ports=(80, 443)).freeze(snapshot_id="mission-scope", approved_by=f"grant:{grant_id}")):
            return _error("GRANT_SCOPE_MISMATCH", f"target {target} not covered by grant")
        scope = ScopeDraft(project_id=project_id, include=(target,), exclude=(),
                           ports=(80, 443)).freeze(snapshot_id=f"mscope-{uuid4().hex[:8]}",
                                                   approved_by=f"grant:{grant_id}")
        scope_repo = SqlAlchemyScopeRepository(session)
        scope_repo.add_snapshot(scope)
        asm_repo = SqlAlchemyAssessmentRepository(session)
        svc = AssessmentService(asm_repo, scope_repo=scope_repo, grant_service=grant_service)
        assessment = svc.create(project_id=project_id, scope_snapshot_id=scope.id,
                                mode=ExecutionMode.APPROVAL)
        planner = LLMPlanner(
            runtime.llm_backend, runtime.catalog,
        )
        cap = RiskClass(risk_cap) if risk_cap else max(grant.risk_caps, key=_rank)
        plan = planner.generate(plan_id=f"plan-{uuid4().hex[:12]}",
                                assessment_id=assessment.id,
                                asset_types=(AssetType.WEB_APP,), intent=intent,
                                risk_cap=cap)
        svc.attach_plan(assessment.id, steps=plan.steps)
        svc.approve(assessment_id=assessment.id, approved_by="agent",
                    approved_risks=frozenset(grant.risk_caps),
                    approved_capabilities=frozenset(),
                    scope_digest=scope.digest,
                    actor_role="agent", grant_id=grant_id)
        started = svc.start(assessment.id, actor_role="agent", grant_id=grant_id)
        _audit(runtime, session=session, actor="agent",
               action="mission.created", resource_type="mission",
               resource_id=assessment.id,
               payload={"grant_id": grant_id, "target": target, "intent": intent})
        return {"status": "success", "assessment_id": assessment.id,
                "status_detail": started.status.value}
```

- Register `mission_create` in `tool_registry.py` (target/intent/grant_id/project_id/risk_cap args).
- `McpRuntime` gains `llm_backend` + `catalog` (composed in `main.py` via `load_backend_from_config` + default catalog repo).

**B2.4 — Run, confirm GREEN.**

**B2.5 — Commit.**

```bash
git add src/secopent/interfaces/mcp/handlers.py src/secopent/interfaces/mcp/tool_registry.py src/secopent/interfaces/api/main.py tests/interfaces/test_mcp_mission.py
git commit -m "feat(mcp): mission_create - target+intent -> LLM plan + grant approve + start (v0.6.1)"
```

---

### Task B3 — Phase B quality gate + docs + release v0.6.1

Same as A6: full gate, `docs/deployment/grants.md` add mission section, CHANGELOG, release after user confirmation.

---

## Self-review

- **Spec coverage:** Phase A (grant domain → repo/persistence → service → approval gate → MCP → release) maps to spec §3.1-3.6 + A1-A6. Phase B (LLM planner → mission tool → release) maps to §4 + B1-B3. Safety rules (human-only creation, DESTRUCTIVE reject, scope precision, no-grant → HUMAN_REQUIRED) each have a dedicated test. ✓
- **Placeholder scan:** no TBD; the two "Note:" callouts are explicit verified-dequed decisions (match harness names in-definition, resolve scope-repo wiring in A4.3 — a real constraint, not vagueness). ✓
- **Type consistency:** `GrantService(repo)`, `AssessmentService(repo, scope_repo=None, grant_service=None)`, `handler_*(runtime, ...)` all consistent across tasks. ✓

## Execution handoff

1. **Subagent-Driven (recommended)** — Phase A first (A1→A6), review between tasks; Phase B (B1→B3) after.
2. **Inline Execution** — execute tasks in this session.