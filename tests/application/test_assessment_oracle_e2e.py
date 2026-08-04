"""E2E: assessment -> correlation -> oracle -> ConfirmedFinding (W3-A T8).

Drives execute_assessment with a real OracleService (real RescanVerifierFactory
+ real canary + real AuditChain) over a fake scan runner whose observations
reproduce, asserting a ConfirmedFinding is persisted and the Finding's
oracle_verdict flips to CONFIRMED. Proves the W3-A wiring closes the
"built but not wired" oracle gap end-to-end.
"""
from __future__ import annotations

from typing import Any

from test_execution import (  # type: ignore[import-not-found]
    _FakeStepRunner,
    _MemoryFindingRepo,
    _seed_approved,
)

from secopent.application.assessments import AssessmentService
from secopent.application.audit_chain import AuditChain
from secopent.application.canary import CanaryTokenManager
from secopent.application.execution import execute_assessment
from secopent.application.oracle_service import OracleService
from secopent.domain.adapters.contracts import (
    AdapterSource,
    CoverageDomain,
    Observation,
    Severity,
)
from secopent.domain.assessments.models import AssessmentStatus
from secopent.domain.verification.registry import default_registry
from secopent.infrastructure.audit.key_manager import AuditKeyManager
from secopent.infrastructure.oracle.verifier_factory import RescanVerifierFactory


class _ReproRunner:
    """Fake RealScanRunner: returns an observation whose asset_identity matches
    the finding's asset, so RescanVerifier's legacy substring path sees a
    reproduction (SUCCESS)."""

    def __init__(self, target: str) -> None:
        self._target = target

    def scan(self, adapter_key: str, *, args: Any, **kwargs: Any) -> Any:
        class _Obs:
            asset_identity = self._target

        class _Result:
            observations = (_Obs(),)
            stdout = ""

        return _Result()


class _MemoryConfirmedRepo:
    def __init__(self) -> None:
        self.rows: list[Any] = []

    def add(self, confirmed: Any) -> None:
        self.rows = [r for r in self.rows if r.candidate_id != confirmed.candidate_id]
        self.rows.append(confirmed)

    def get(self, candidate_id: str) -> Any:
        return next((r for r in self.rows if r.candidate_id == candidate_id), None)

    def list_for_candidates(self, ids: Any) -> tuple:
        return tuple(r for r in self.rows if r.candidate_id in set(ids))


def _sqli_observation() -> Observation:
    return Observation(
        external_id="o1",
        asset_identity="http://target",
        source=AdapterSource(name="nuclei", version="1", template_version="1"),
        rule_id="sqli",
        rule_version="1",
        coverage_domain=CoverageDomain.WEB,
        title="SQL Injection",
        severity=Severity.HIGH,
        confidence=0.9,
        cwe=("CWE-89",),
    )


def test_assessment_confirms_finding_end_to_end(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)  # -> QUEUED
    finding_repo = _MemoryFindingRepo()
    confirmed_repo = _MemoryConfirmedRepo()

    chain = AuditChain(AuditKeyManager())
    canary = CanaryTokenManager(chain)
    oracle = OracleService(
        registry=default_registry(),
        canary=canary,
        verifier_factory=RescanVerifierFactory(
            _ReproRunner("http://target"),  # type: ignore[arg-type]
            "/templates",
            canary,
        ),
    )

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=finding_repo,
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda _scope: _FakeStepRunner((_sqli_observation(),)),
        oracle=oracle,
        confirmed_finding_repo=confirmed_repo,  # type: ignore[arg-type]
        audit_chain=chain,
    )

    # Assessment completed despite the oracle rescan work.
    assert (
        memory_repositories.assessments.get(a.id).status is AssessmentStatus.COMPLETED
    )
    # A ConfirmedFinding was persisted for the SQLi finding.
    assert len(confirmed_repo.rows) == 1
    confirmed = confirmed_repo.rows[0]
    assert confirmed.vuln_type.value == "sqli"
    assert confirmed.successes == 5  # SQLi N=5, all reproduced
    assert confirmed.attempts == 5
    # The candidate_id is the source Finding's id.
    assert confirmed.candidate_id == finding_repo.items[0].id
    # The finding's oracle_verdict was updated to CONFIRMED.
    assert finding_repo.items[-1].oracle_verdict.value == "confirmed"
    # The verification was audited into the signed chain.
    assert any(e.action == "oracle.verified" for e in chain.events())
    assert any(e.action == "oracle.batch_verified" for e in chain.events())
    assert chain.verify() is True


def test_assessment_without_oracle_leaves_finding_unconfirmed(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    """Without the oracle wired, the finding stays PENDING (W2 behavior)."""
    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)
    finding_repo = _MemoryFindingRepo()

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=finding_repo,
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda _scope: _FakeStepRunner((_sqli_observation(),)),
        # no oracle, no confirmed_finding_repo
    )

    assert (
        memory_repositories.assessments.get(a.id).status is AssessmentStatus.COMPLETED
    )
    assert finding_repo.items
    assert finding_repo.items[-1].oracle_verdict.value == "pending"
