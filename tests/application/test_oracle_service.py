"""OracleService: verify findings -> persist ConfirmedFindings (W3-A T4)."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from secopent.application.audit import AuditService
from secopent.application.audit_chain import AuditChain
from secopent.application.canary import CanaryTokenManager
from secopent.application.oracle import OracleVerifier
from secopent.application.oracle_service import OracleService, OracleSummary
from secopent.domain.adapters.contracts import Severity
from secopent.domain.findings.models import Finding, FindingStatus
from secopent.domain.verification.models import (
    CandidateFinding,
    ReproductionStatus,
    VerificationMethod,
    VerificationStatus,
)
from secopent.domain.verification.registry import default_registry
from secopent.infrastructure.audit.key_manager import AuditKeyManager


class _FakeVerifier:
    """Fake OracleVerifier returning a fixed reproduction outcome."""

    def __init__(self, *, reproduce: bool = True) -> None:
        self._reproduce = reproduce
        self.calls: list[str] = []  # canary tokens seen

    def reproduce(
        self,
        candidate: CandidateFinding,
        method: VerificationMethod,
        *,
        canary_token: str,
    session=None,
    ) -> ReproductionStatus:
        self.calls.append(canary_token)
        return ReproductionStatus.SUCCESS if self._reproduce else ReproductionStatus.FAILURE


class _FakeFactory:
    """Builds a per-finding verifier with a controlled reproduce flag."""

    def __init__(self, *, reproduce: bool = True) -> None:
        self._reproduce = reproduce
        self.verifiers: list[_FakeVerifier] = []

    def for_finding(self, finding: Finding) -> OracleVerifier:
        v = _FakeVerifier(reproduce=self._reproduce)
        self.verifiers.append(v)
        return v  # type: ignore[return-value]


class _BoomFactory:
    def for_finding(self, finding: Finding) -> OracleVerifier:
        class _Boom:
            def reproduce(
                self, c: CandidateFinding, m: VerificationMethod, *, canary_token: str, session=None
            ) -> ReproductionStatus:
                raise RuntimeError("scan blew up")
        return _Boom()  # type: ignore[return-value]


class _FakeFindingRepo:
    def __init__(self) -> None:
        self._by_id: dict[str, Finding] = {}

    def add(self, finding: Finding) -> None:
        self._by_id[finding.id] = finding

    def get(self, fid: str) -> Finding | None:
        return self._by_id.get(fid)


class _InMemoryConfirmedRepo:
    def __init__(self) -> None:
        self.rows: list[Any] = []

    def add(self, confirmed: Any) -> None:
        # Replace on same candidate_id (merge semantics).
        self.rows = [r for r in self.rows if r.candidate_id != confirmed.candidate_id]
        self.rows.append(confirmed)

    def get(self, candidate_id: str) -> Any:
        return next((r for r in self.rows if r.candidate_id == candidate_id), None)

    def list_for_candidates(self, ids: Any) -> tuple:
        return tuple(r for r in self.rows if r.candidate_id in set(ids))


def _finding(fid: str, cwe: str, asset: str = "http://t/") -> Finding:
    return Finding(
        id=fid,
        fingerprint=f"sha256:{fid}",
        title=fid,
        asset=asset,
        severity=Severity.HIGH,
        cwe=(cwe,),
        observation_ids=("obs-1",),
        status=FindingStatus.CANDIDATE,
    )


def _make_service(
    reproduce: bool = True,
) -> tuple[OracleService, AuditChain, CanaryTokenManager, _FakeFactory]:
    chain = AuditChain(AuditKeyManager())
    canary = CanaryTokenManager(chain)
    factory = _FakeFactory(reproduce=reproduce)
    service = OracleService(
        registry=default_registry(),
        canary=canary,
        verifier_factory=factory,
    )
    return service, chain, canary, factory


def _verify(
    service: OracleService, chain: AuditChain, findings, audit: AuditService  # type: ignore[no-untyped-def]
) -> OracleSummary:
    return service.verify_findings(
        findings,
        finding_repo=_FakeFindingRepo(),  # type: ignore[arg-type]
        confirmed_repo=_InMemoryConfirmedRepo(),  # type: ignore[arg-type]
        audit=audit,
        audit_chain=chain,
        actor="oracle",
        verified_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def test_confirmed_finding_persisted_when_reproduces(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    service, chain, _, factory = _make_service(reproduce=True)
    audit = AuditService(memory_repositories.audit)
    finding_repo = _FakeFindingRepo()
    confirmed_repo = _InMemoryConfirmedRepo()
    findings = [_finding("finding:1", "CWE-89")]

    summary = service.verify_findings(
        findings,
        finding_repo=finding_repo,  # type: ignore[arg-type]
        confirmed_repo=confirmed_repo,  # type: ignore[arg-type]
        audit=audit,
        audit_chain=chain,
        actor="oracle",
        verified_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert summary.confirmed == 1
    assert summary.refuted == 0
    assert confirmed_repo.get("finding:1") is not None
    assert confirmed_repo.get("finding:1").vuln_type.value == "sqli"
    assert confirmed_repo.get("finding:1").successes == 5  # SQLi N=5
    # Finding.oracle_verdict updated to CONFIRMED.
    assert finding_repo.get("finding:1").oracle_verdict is VerificationStatus.CONFIRMED
    # Each reproduction used a fresh canary token (N=5 for SQLi).
    assert len(factory.verifiers[0].calls) == 5
    assert len(set(factory.verifiers[0].calls)) == 5


def test_refuted_finding_not_confirmed_but_verdict_set(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    service, chain, _, _ = _make_service(reproduce=False)
    audit = AuditService(memory_repositories.audit)
    finding_repo = _FakeFindingRepo()
    confirmed_repo = _InMemoryConfirmedRepo()
    findings = [_finding("finding:2", "CWE-79")]  # XSS N=3

    summary = service.verify_findings(
        findings,
        finding_repo=finding_repo,  # type: ignore[arg-type]
        confirmed_repo=confirmed_repo,  # type: ignore[arg-type]
        audit=audit,
        audit_chain=chain,
        actor="oracle",
        verified_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert summary.confirmed == 0
    assert summary.refuted == 1
    assert confirmed_repo.get("finding:2") is None
    assert finding_repo.get("finding:2").oracle_verdict is VerificationStatus.REFUTED


def test_unmappable_cwe_skipped(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    service, chain, _, factory = _make_service(reproduce=True)
    audit = AuditService(memory_repositories.audit)
    finding_repo = _FakeFindingRepo()
    confirmed_repo = _InMemoryConfirmedRepo()
    skipped = _finding("finding:3", "CWE-999")  # no VulnType mapping
    finding_repo.add(skipped)  # caller already persisted it before oracle ran

    summary = service.verify_findings(
        [skipped],
        finding_repo=finding_repo,  # type: ignore[arg-type]
        confirmed_repo=confirmed_repo,  # type: ignore[arg-type]
        audit=audit,
        audit_chain=chain,
        actor="oracle",
        verified_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert summary.confirmed == 0
    assert summary.skipped == 1
    assert confirmed_repo.get("finding:3") is None
    # Skipped finding is untouched: verdict stays PENDING (oracle did not run).
    assert finding_repo.get("finding:3").oracle_verdict is VerificationStatus.PENDING
    # No verifier was built for the skipped finding.
    assert factory.verifiers == []


def test_verification_audited_to_signed_chain(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    service, chain, _, _ = _make_service(reproduce=True)
    audit = AuditService(memory_repositories.audit)
    summary = _verify(service, chain, [_finding("finding:4", "CWE-89")], audit)
    assert summary.confirmed == 1
    events = chain.events()
    assert any(e.action == "oracle.verified" for e in events)
    assert chain.verify() is True  # signed chain intact


def test_single_finding_failure_does_not_abort_others(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    chain = AuditChain(AuditKeyManager())
    canary = CanaryTokenManager(chain)
    service = OracleService(
        registry=default_registry(),
        canary=canary,
        verifier_factory=_BoomFactory(),
    )
    audit = AuditService(memory_repositories.audit)
    summary = service.verify_findings(
        [_finding("finding:5", "CWE-89"), _finding("finding:6", "CWE-79")],
        finding_repo=_FakeFindingRepo(),  # type: ignore[arg-type]
        confirmed_repo=_InMemoryConfirmedRepo(),  # type: ignore[arg-type]
        audit=audit,
        audit_chain=chain,
        actor="oracle",
        verified_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert summary.failed == 2
    assert summary.confirmed == 0
    # The failure was audited.
    events = chain.events()
    assert any(e.action == "oracle.verification_failed" for e in events)
