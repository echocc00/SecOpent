"""JobStore equivalence matrix: Memory vs SQLAlchemy behave identically.

The orchestrator's lease machinery must run against either store without
semantic changes (sepcs/2026-08-13-mcp-job-lease-cancellation-design.md, M2).
Every lease lifecycle rule is exercised against BOTH implementations with the
same assertions: idempotent add, lease READY, stale-LEASED takeover, illegal
transition refusal, owner-only renew, complete/fail/requeue/mark_ready, and
leaseable filtering. Times are aware-UTC (the project's ``utc_now`` contract).
"""
from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from secopent.application.jobs import (
    JobLeaseError,
    JobNotFoundError,
    MemoryJobStore,
)
from secopent.domain.jobs.models import FailureClass, Job, JobStatus
from secopent.infrastructure.db.core_models import CoreBase
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_jobs import (
    SqlAlchemyJobRepository,
)

_T0 = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)


@pytest.fixture
def session(tmp_path) -> Iterator[Session]:  # type: ignore[no-untyped-def] # noqa: ANN001
    engine = create_sqlite_engine(tmp_path / "jobs.db")
    CoreBase.metadata.create_all(engine)
    yield Session(engine)
    engine.dispose()


def _ready(id: str = "j1", key: str = "digest:k", status: JobStatus = JobStatus.READY) -> Job:
    return Job(id=id, plan_step_key=key, idempotency_key=key, status=status)


def _memory_store() -> MemoryJobStore:
    return MemoryJobStore(lease_ttl_seconds=60)


@pytest.fixture
def sql_store(session):  # noqa: ANN001
    return SqlAlchemyJobRepository(session, lease_ttl_seconds=60)


@pytest.mark.parametrize("factory", [_memory_store, "sql"], ids=["memory", "sql"])
def test_add_is_idempotent(factory, sql_store) -> None:  # noqa: ANN001
    store = sql_store if factory == "sql" else factory()
    store.add(_ready())
    repeated = store.add(_ready(id="j2", key="digest:k"))
    assert repeated.id == "j1"  # existing job wins on same idempotency_key
    assert len(store.all()) == 1


@pytest.mark.parametrize("factory", [_memory_store, "sql"], ids=["memory", "sql"])
def test_lease_reads_lease_owner_and_bumps_attempt(factory, sql_store) -> None:  # noqa: ANN001
    store = sql_store if factory == "sql" else factory()
    store.add(_ready())
    leased = store.lease("j1", owner="w1", now=_T0)
    assert leased.status is JobStatus.LEASED
    assert leased.lease_owner == "w1"
    assert leased.attempt == 1
    assert leased.lease_expires_at == _T0 + timedelta(seconds=60)


@pytest.mark.parametrize("factory", [_memory_store, "sql"], ids=["memory", "sql"])
def test_live_lease_blocks_other_owner_until_expiry(factory, sql_store) -> None:  # noqa: ANN001
    store = sql_store if factory == "sql" else factory()
    store.add(_ready())
    store.lease("j1", owner="w1", now=_T0)
    with pytest.raises(JobLeaseError):
        store.lease("j1", owner="w2", now=_T0 + timedelta(seconds=10))
    reclaimed = store.lease("j1", owner="w2", now=_T0 + timedelta(seconds=120))
    assert reclaimed.lease_owner == "w2"
    assert reclaimed.attempt == 2  # stale takeover still increments


@pytest.mark.parametrize("factory", [_memory_store, "sql"], ids=["memory", "sql"])
def test_lease_refuses_non_ready_statuses(factory, sql_store) -> None:  # noqa: ANN001
    store = sql_store if factory == "sql" else factory()
    for status in (JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.BLOCKED, JobStatus.SKIPPED):
        store.add(_ready(id=f"j-{status.value}", key=f"k-{status.value}", status=status))
        with pytest.raises(JobLeaseError):
            store.lease(f"j-{status.value}", owner="w", now=_T0)


@pytest.mark.parametrize("factory", [_memory_store, "sql"], ids=["memory", "sql"])
def test_lease_missing_job_raises_not_found(factory, sql_store) -> None:  # noqa: ANN001
    store = sql_store if factory == "sql" else factory()
    with pytest.raises(JobNotFoundError):
        store.lease("nope", owner="w", now=_T0)


@pytest.mark.parametrize("factory", [_memory_store, "sql"], ids=["memory", "sql"])
def test_renew_requires_ownership(factory, sql_store) -> None:  # noqa: ANN001
    store = sql_store if factory == "sql" else factory()
    store.add(_ready())
    store.lease("j1", owner="w1", now=_T0)
    with pytest.raises(JobLeaseError):
        store.renew("j1", owner="w2", now=_T0 + timedelta(seconds=10))
    renewed = store.renew("j1", owner="w1", now=_T0 + timedelta(seconds=10))
    assert renewed.lease_expires_at == _T0 + timedelta(seconds=70)


@pytest.mark.parametrize("factory", [_memory_store, "sql"], ids=["memory", "sql"])
def test_complete_fail_policy_denied_requeue(factory, sql_store) -> None:  # noqa: ANN001
    store = sql_store if factory == "sql" else factory()
    store.add(_ready())
    done = store.complete("j1", result_digest="d1")
    assert done.status is JobStatus.SUCCEEDED and done.result_digest == "d1"

    store.add(_ready(id="j2", key="k2"))
    failed = store.fail("j2", failure_class=FailureClass.TIMEOUT)
    assert failed.status is JobStatus.FAILED and failed.failure_class == "timeout"

    store.add(_ready(id="j3", key="k3"))
    denied = store.fail("j3", failure_class=FailureClass.NOT_APPROVED)
    assert denied.status is JobStatus.POLICY_DENIED and denied.failure_class == "not_approved"

    store.add(_ready(id="j4", key="k4"))
    store.lease("j4", owner="w", now=_T0)
    store.renew("j4", owner="w", now=_T0 + timedelta(seconds=10))
    requeued = store.requeue("j4")
    assert requeued.status is JobStatus.READY
    assert requeued.lease_owner is None and requeued.lease_expires_at is None
    assert requeued.failure_class == ""  # retry clears the previous failure
    # A requeued job is leaseable again (retry semantics).
    assert {j.id for j in store.leaseable(_T0 + timedelta(seconds=20))} == {"j4"}


@pytest.mark.parametrize("factory", [_memory_store, "sql"], ids=["memory", "sql"])
def test_mark_ready_and_leaseable_filters(factory, sql_store) -> None:  # noqa: ANN001
    store = sql_store if factory == "sql" else factory()
    store.add(_ready(id="ready-1", key="k1"))
    store.add(_ready(id="done-1", key="k2", status=JobStatus.SUCCEEDED))
    store.add(_ready(id="leased-1", key="k3"))
    store.lease("leased-1", owner="w", now=_T0)

    leaseable_now = {j.id for j in store.leaseable(_T0)}
    assert leaseable_now == {"ready-1"}  # LEASED not stale yet

    stale_incl = {j.id for j in store.leaseable(_T0 + timedelta(seconds=120))}
    assert stale_incl == {"ready-1", "leased-1"}

    blocked = _ready(id="blocked-1", key="k4", status=JobStatus.BLOCKED)
    store.add(blocked)
    marked = store.mark_ready("blocked-1")
    assert marked.status is JobStatus.READY
    assert "blocked-1" in {j.id for j in store.leaseable(_T0)}


@pytest.mark.parametrize("factory", [_memory_store, "sql"], ids=["memory", "sql"])
def test_skip_marks_abandoned_job(factory, sql_store) -> None:  # noqa: ANN001
    store = sql_store if factory == "sql" else factory()
    store.add(_ready())
    store.lease("j1", owner="w", now=_T0)
    skipped = store.skip("j1")
    assert skipped.status is JobStatus.SKIPPED
    assert skipped.lease_owner is None and skipped.lease_expires_at is None
    # A skipped job is never leaseable again.
    assert store.leaseable(_T0 + timedelta(seconds=120)) == ()


@pytest.mark.parametrize("factory", [_memory_store, "sql"], ids=["memory", "sql"])
def test_writes_survive_store_recreation(factory, sql_store) -> None:  # noqa: ANN001
    """Persisted stores keep state across instances (the durable-lease point).

    Memory is excluded by design (its whole point is ephemeral) - this pins the
    SQLAlchemy store's restart-survival contract.
    """
    if factory == "memory":
        pytest.skip("memory store is intentionally ephemeral")
    store = sql_store
    store.add(_ready())
    store.lease("j1", owner="w", now=_T0)
    # A fresh repository over the same session/DB sees the leased state.
    fresh = SqlAlchemyJobRepository(store._session, lease_ttl_seconds=60)  # noqa: SLF001
    reloaded = fresh.get("j1")
    assert reloaded is not None
    assert reloaded.status is JobStatus.LEASED
    assert reloaded.lease_owner == "w"
    assert reloaded.lease_expires_at == _T0 + timedelta(seconds=60)