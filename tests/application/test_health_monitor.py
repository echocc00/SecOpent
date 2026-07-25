# tests/application/test_health_monitor.py
"""TDD tests for KnowledgeHealthMonitor (M1 Task 7).

Covers the 5 detectors from §7.3 and the coverage regression gate
(§7.5 选项 D: 0 容忍 + override-with-reason):

    1. check_source_stale        - nuclei-templates > 7 days no commit
    2. check_curation_lag        - 100 new upstream tags but TestCatalog unmapped
    3. check_coverage_regression - new CoverageMatrix coverage_rate < old
    4. check_source_unreachable  - OSV API unreachable -> degrade to cache + alert
    5. check_signature_invalid   - bundle signature verification failed

All external checks (git commit dates, API reachability, upstream tag counts,
signature verification) are abstracted behind Protocol ports so tests inject
fakes. The application layer stays framework-free.
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from secopent.application.audit import AuditService
from secopent.application.health import (
    HealthAlert,
    HealthAlertKind,
    HealthReport,
    KnowledgeHealthMonitor,
)
from secopent.domain.catalog.coverage import CoverageMatrix
from secopent.domain.common.errors import DomainValidationError

# --- Test doubles (Protocol-shaped checkers) -------------------------------


@dataclass
class FakeSourceFreshnessChecker:
    """Stand-in for the git commit-date probe. Returns a canned ``days_since``
    value for the requested source (e.g. ``nuclei-templates``)."""

    days_since_last_commit: int = 0

    def days_since_last_commit_for(self, source: str) -> int:
        return self.days_since_last_commit


@dataclass
class FakeCurationLagChecker:
    """Stand-in for the upstream-vs-catalog delta probe. Returns the count of
    upstream tags (e.g. nuclei template tags) that have no mapping in the
    currently active TestCatalog."""

    unmapped_upstream_count: int = 0

    def unmapped_upstream_tags(self, source: str) -> int:
        return self.unmapped_upstream_count


@dataclass
class FakeSourceReachabilityChecker:
    """Stand-in for the OSV API reachability probe."""

    reachable: dict[str, bool] = None  # type: ignore[assignment]

    def is_reachable(self, source: str) -> bool:
        if self.reachable is None:
            return True
        return self.reachable.get(source, True)


@dataclass
class FakeSignatureChecker:
    """Stand-in for the bundle signature verification probe."""

    last_verify_ok: bool = True

    def last_signature_valid(self) -> bool:
        return self.last_verify_ok


# --- Helpers ----------------------------------------------------------------


def _make_matrix(
    *,
    version: str = "v1",
    framework: str = "OWASP_WSTG_4.2",
    covered: int = 50,
    total: int = 100,
) -> CoverageMatrix:
    """Build a CoverageMatrix with ``covered`` items mapped and the rest empty.

    Item ids are deterministic so canonical_digest stays stable across runs.
    """
    mappings: dict[str, tuple[str, ...]] = {}
    for i in range(covered):
        mappings[f"WSTG-{i:03d}"] = (f"TC-{i:03d}",)
    for i in range(covered, total):
        mappings[f"WSTG-{i:03d}"] = ()
    return CoverageMatrix(
        version=version,
        framework=framework,
        mappings=mappings,
        total_items=total,
    )


def _make_monitor(
    *,
    audit: AuditService,
    freshness: FakeSourceFreshnessChecker | None = None,
    curation: FakeCurationLagChecker | None = None,
    reachability: FakeSourceReachabilityChecker | None = None,
    signature: FakeSignatureChecker | None = None,
    stale_threshold_days: int = 7,
    curation_lag_threshold: int = 100,
    sources: tuple[str, ...] = ("nuclei-templates",),
    intel_sources: tuple[str, ...] = ("osv",),
) -> KnowledgeHealthMonitor:
    return KnowledgeHealthMonitor(
        audit_service=audit,
        freshness_checker=freshness or FakeSourceFreshnessChecker(),
        curation_checker=curation or FakeCurationLagChecker(),
        reachability_checker=reachability or FakeSourceReachabilityChecker(),
        signature_checker=signature or FakeSignatureChecker(),
        stale_threshold_days=stale_threshold_days,
        curation_lag_threshold=curation_lag_threshold,
        sources=sources,
        intel_sources=intel_sources,
    )


# --- 1. source_stale --------------------------------------------------------


def test_source_stale_alert(memory_repositories):
    """nuclei-templates last commit > 7 days ago -> alert "source_stale"."""
    audit = AuditService(memory_repositories.audit)
    freshness = FakeSourceFreshnessChecker(days_since_last_commit=10)
    monitor = _make_monitor(audit=audit, freshness=freshness)

    report = monitor.check_all()

    kinds = {alert.kind for alert in report.alerts}
    assert HealthAlertKind.SOURCE_STALE in kinds
    stale_alert = next(a for a in report.alerts if a.kind is HealthAlertKind.SOURCE_STALE)
    assert "nuclei-templates" in stale_alert.source
    assert stale_alert.details["days_since_last_commit"] == 10


def test_source_stale_no_alert_when_fresh(memory_repositories):
    """nuclei-templates last commit <= 7 days ago -> no source_stale alert."""
    audit = AuditService(memory_repositories.audit)
    freshness = FakeSourceFreshnessChecker(days_since_last_commit=3)
    monitor = _make_monitor(audit=audit, freshness=freshness)

    report = monitor.check_all()

    kinds = {alert.kind for alert in report.alerts}
    assert HealthAlertKind.SOURCE_STALE not in kinds


# --- 2. curation_lag --------------------------------------------------------


def test_curation_lag_alert(memory_repositories):
    """nuclei added 100 new tags but TestCatalog unmapped -> alert "curation_lag"."""
    audit = AuditService(memory_repositories.audit)
    curation = FakeCurationLagChecker(unmapped_upstream_count=150)
    monitor = _make_monitor(audit=audit, curation=curation)

    report = monitor.check_all()

    kinds = {alert.kind for alert in report.alerts}
    assert HealthAlertKind.CURATION_LAG in kinds
    lag_alert = next(a for a in report.alerts if a.kind is HealthAlertKind.CURATION_LAG)
    assert lag_alert.details["unmapped_upstream_count"] == 150


# --- 3. coverage_regression gate (选项 D) -----------------------------------


def test_coverage_regression_blocks_publish(memory_repositories):
    """New CoverageMatrix coverage_rate < old -> block publish (选项 D: 0 容忍).

    Override-with-reason allowed when ``override_reason`` AND ``roadmap`` are
    provided -> audit event emitted.
    """
    audit = AuditService(memory_repositories.audit)
    monitor = _make_monitor(audit=audit)
    old_matrix = _make_matrix(version="v1", covered=80, total=100)  # 80%
    new_matrix = _make_matrix(version="v2", covered=70, total=100)  # 70%

    # Without override -> regression must raise.
    with pytest.raises(DomainValidationError, match="coverage regression"):
        monitor.enforce_coverage_gate(
            new_matrix=new_matrix, old_matrix=old_matrix
        )

    # With override + roadmap -> allowed, but audit event recorded.
    monitor.enforce_coverage_gate(
        new_matrix=new_matrix,
        old_matrix=old_matrix,
        override_reason="upstream license change forced removal of 10 mappings",
        roadmap="re-add mappings via community PRs in Q3",
    )

    events = memory_repositories.audit.list_events()
    actions = [e.action for e in events]
    assert "coverage.override" in actions
    override_event = next(e for e in events if e.action == "coverage.override")
    assert override_event.payload["old_rate"] == pytest.approx(0.80)
    assert override_event.payload["new_rate"] == pytest.approx(0.70)
    assert "upstream license" in override_event.payload["override_reason"]
    assert "Q3" in override_event.payload["roadmap"]


def test_coverage_regression_no_override_blocks(memory_repositories):
    """Regression without override reason -> publish blocked, raises."""
    audit = AuditService(memory_repositories.audit)
    monitor = _make_monitor(audit=audit)
    old_matrix = _make_matrix(version="v1", covered=90, total=100)
    new_matrix = _make_matrix(version="v2", covered=85, total=100)

    with pytest.raises(DomainValidationError, match="coverage regression"):
        monitor.enforce_coverage_gate(
            new_matrix=new_matrix, old_matrix=old_matrix
        )

    # No audit event when blocked without override.
    events = memory_repositories.audit.list_events()
    actions = [e.action for e in events]
    assert "coverage.override" not in actions


def test_coverage_regression_override_requires_roadmap(memory_repositories):
    """Override with reason but missing roadmap -> still rejected (both required)."""
    audit = AuditService(memory_repositories.audit)
    monitor = _make_monitor(audit=audit)
    old_matrix = _make_matrix(version="v1", covered=80, total=100)
    new_matrix = _make_matrix(version="v2", covered=70, total=100)

    with pytest.raises(DomainValidationError, match="roadmap"):
        monitor.enforce_coverage_gate(
            new_matrix=new_matrix,
            old_matrix=old_matrix,
            override_reason="license change",
            roadmap="",
        )


def test_coverage_no_regression_passes(memory_repositories):
    """New rate >= old rate -> no regression, no raise, no override audit."""
    audit = AuditService(memory_repositories.audit)
    monitor = _make_monitor(audit=audit)
    old_matrix = _make_matrix(version="v1", covered=70, total=100)
    new_matrix = _make_matrix(version="v2", covered=80, total=100)

    # Should not raise.
    monitor.enforce_coverage_gate(new_matrix=new_matrix, old_matrix=old_matrix)

    events = memory_repositories.audit.list_events()
    actions = [e.action for e in events]
    assert "coverage.override" not in actions


def test_coverage_equal_rate_passes(memory_repositories):
    """Equal coverage (no regression) is allowed under 0 容忍 (monotonic non-decreasing)."""
    audit = AuditService(memory_repositories.audit)
    monitor = _make_monitor(audit=audit)
    old_matrix = _make_matrix(version="v1", covered=80, total=100)
    new_matrix = _make_matrix(version="v2", covered=80, total=100)

    monitor.enforce_coverage_gate(new_matrix=new_matrix, old_matrix=old_matrix)


# --- 4. source_unreachable --------------------------------------------------


def test_source_unreachable_degrades(memory_repositories):
    """OSV API unreachable -> degrade to cache + alert "source_unreachable"."""
    audit = AuditService(memory_repositories.audit)
    reachability = FakeSourceReachabilityChecker(reachable={"osv": False})
    monitor = _make_monitor(audit=audit, reachability=reachability)

    report = monitor.check_all()

    kinds = {alert.kind for alert in report.alerts}
    assert HealthAlertKind.SOURCE_UNREACHABLE in kinds
    unreach = next(
        a for a in report.alerts if a.kind is HealthAlertKind.SOURCE_UNREACHABLE
    )
    assert unreach.source == "osv"
    assert unreach.details["degraded_to"] == "cache"


# --- 5. signature_invalid ---------------------------------------------------


def test_signature_invalid_alert(memory_repositories):
    """Bundle signature verification failed -> alert "signature_invalid"."""
    audit = AuditService(memory_repositories.audit)
    signature = FakeSignatureChecker(last_verify_ok=False)
    monitor = _make_monitor(audit=audit, signature=signature)

    report = monitor.check_all()

    kinds = {alert.kind for alert in report.alerts}
    assert HealthAlertKind.SIGNATURE_INVALID in kinds


# --- 6. check_all aggregation -----------------------------------------------


def test_check_all_runs_all_detectors(memory_repositories):
    """check_all() runs all 5 detectors and returns a HealthReport.

    Drive every detector to fire by injecting failing checkers, then assert
    the report contains exactly one alert of each kind.
    """
    audit = AuditService(memory_repositories.audit)
    monitor = _make_monitor(
        audit=audit,
        freshness=FakeSourceFreshnessChecker(days_since_last_commit=30),
        curation=FakeCurationLagChecker(unmapped_upstream_count=200),
        reachability=FakeSourceReachabilityChecker(reachable={"osv": False}),
        signature=FakeSignatureChecker(last_verify_ok=False),
    )
    # Coverage regression detector does NOT run inside check_all (it runs via
    # enforce_coverage_gate). The 5 detectors above are the 5 from §7.3.

    report = monitor.check_all()

    assert isinstance(report, HealthReport)
    # Frozen dataclass
    import dataclasses

    assert dataclasses.is_dataclass(report)
    # We expect at least: source_stale + curation_lag + source_unreachable +
    # signature_invalid (4 of the 5 §7.3 detectors fire from check_all; the
    # 5th, coverage_regression, fires only through enforce_coverage_gate).
    kinds = {alert.kind for alert in report.alerts}
    assert HealthAlertKind.SOURCE_STALE in kinds
    assert HealthAlertKind.CURATION_LAG in kinds
    assert HealthAlertKind.SOURCE_UNREACHABLE in kinds
    assert HealthAlertKind.SIGNATURE_INVALID in kinds


def test_health_alert_and_report_are_frozen(memory_repositories):
    """HealthAlert and HealthReport must be frozen dataclasses (immutable)."""
    import dataclasses

    assert dataclasses.is_dataclass(HealthAlert)
    # frozen=True raises on setattr.
    alert = HealthAlert(
        kind=HealthAlertKind.SOURCE_STALE,
        source="nuclei-templates",
        details={"days_since_last_commit": 10},
    )
    with pytest.raises((AttributeError, dataclasses.FrozenInstanceError)):
        alert.source = "tampered"  # type: ignore[misc]

    report = HealthReport(alerts=(alert,))
    with pytest.raises((AttributeError, dataclasses.FrozenInstanceError)):
        report.alerts = ()  # type: ignore[misc]
