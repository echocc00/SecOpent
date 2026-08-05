"""execute_assessment wires OracleService (W3-A T5).

Reuses the seed/step-runner helpers from test_execution.py. The oracle runs
after correlation; with no oracle param the flow is unchanged (backward compat).
"""
from __future__ import annotations

from dataclasses import replace

from test_execution import (  # type: ignore[import-not-found]
    _FakeStepRunner,
    _MemoryFindingRepo,
    _observation,
    _seed_approved,
)

from secopent.application.assessments import AssessmentService
from secopent.application.execution import execute_assessment
from secopent.application.oracle_service import OracleSummary
from secopent.domain.assessments.models import AssessmentStatus
from secopent.domain.verification.models import VerificationStatus


class _StubOracle:
    """Records calls; simulates confirmation for every finding it sees."""

    def __init__(self) -> None:
        self.calls: list = []  # type: ignore[type-arg]

    def verify_findings(  # type: ignore[no-untyped-def]
        self,
        findings,
        *,
        finding_repo,
        confirmed_repo,
        audit,
        audit_chain,
        actor,
        verified_at=None,
        session=None,
    ) -> OracleSummary:
        confirmed = 0
        for f in findings:
            self.calls.append(f)

            class _Confirmed:
                candidate_id = f.id

            confirmed_repo.add(_Confirmed())
            finding_repo.add(replace(f, oracle_verdict=VerificationStatus.CONFIRMED))
            confirmed += 1
        return OracleSummary(confirmed=confirmed)


class _MemoryConfirmedRepo:
    def __init__(self) -> None:
        self.rows: list = []  # type: ignore[type-arg]

    def add(self, confirmed: object) -> None:
        self.rows.append(confirmed)

    def get(self, candidate_id: str) -> object | None:
        return next(
            (r for r in self.rows if getattr(r, "candidate_id", None) == candidate_id),
            None,
        )

    def list_for_candidates(self, ids):  # type: ignore[no-untyped-def]
        return tuple(self.rows)


def test_oracle_runs_after_correlation_and_confirms(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)  # -> QUEUED
    finding_repo = _MemoryFindingRepo()
    confirmed_repo = _MemoryConfirmedRepo()
    oracle = _StubOracle()

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=finding_repo,
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda _scope: _FakeStepRunner((_observation(),)),
        oracle=oracle,  # type: ignore[arg-type]
        confirmed_finding_repo=confirmed_repo,  # type: ignore[arg-type]
    )

    assert memory_repositories.assessments.get(a.id).status is AssessmentStatus.COMPLETED
    # Oracle was called with the correlated finding.
    assert len(oracle.calls) == 1
    # ConfirmedFinding persisted.
    assert len(confirmed_repo.rows) == 1
    # Finding's oracle_verdict updated to CONFIRMED (last add wins in _MemoryFindingRepo).
    assert finding_repo.items[-1].oracle_verdict is VerificationStatus.CONFIRMED
    # The batch-verified audit event landed.
    actions = [e.action for e in memory_repositories.audit.events]
    assert "oracle.batch_verified" in actions


def test_without_oracle_backward_compatible(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    """No oracle param -> findings persist, verdict stays PENDING (W2 behavior)."""
    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)
    finding_repo = _MemoryFindingRepo()

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=finding_repo,
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda _scope: _FakeStepRunner((_observation(),)),
        # no oracle, no confirmed_finding_repo
    )

    assert memory_repositories.assessments.get(a.id).status is AssessmentStatus.COMPLETED
    assert len(finding_repo.items) == 1
    assert finding_repo.items[0].oracle_verdict is VerificationStatus.PENDING


def test_oracle_failure_does_not_fail_assessment(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    """If the oracle batch raises, the assessment still completes (best-effort)."""

    class _BoomOracle:
        def verify_findings(self, *a, **kw):  # type: ignore[no-untyped-def]
            raise RuntimeError("oracle infra down")

    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)
    finding_repo = _MemoryFindingRepo()

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=finding_repo,
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda _scope: _FakeStepRunner((_observation(),)),
        oracle=_BoomOracle(),  # type: ignore[arg-type]
        confirmed_finding_repo=_MemoryConfirmedRepo(),  # type: ignore[arg-type]
    )

    # Assessment completed despite the oracle raising.
    assert memory_repositories.assessments.get(a.id).status is AssessmentStatus.COMPLETED
    # Findings still persisted (oracle is best-effort).
    assert len(finding_repo.items) == 1
    actions = [e.action for e in memory_repositories.audit.events]
    assert "oracle.batch_failed" in actions
