# src/secopent/application/health.py
"""KnowledgeHealthMonitor (M1 Task 7).

Implements the §7.3 knowledge-layer health monitoring table and the §7.5
coverage regression gate (选项 D: 0 容忍 + override-with-reason).

§7.3 detector table
-------------------
| 检测         | 告警条件                                       |
|--------------|------------------------------------------------|
| 源停更       | nuclei-templates 超 7 天无新 commit            |
| 策展滞后     | nuclei 新增 100 tag 但 TestCatalog 未映射      |
| 覆盖率退化   | 新版覆盖率 < 旧版                              |
| 源失效       | OSV API 不可达 -> 降级缓存 + 告警              |
| 签名失效     | bundle 签名校验失败                            |

§7.5 选项 D
-----------
0 容忍为默认 (coverage_rate 单调非降)；override 逃生口需 ``override_reason``
+ 补救 ``roadmap`` + 审计留痕 (AuditService hash chain)。

Architecture
------------
* **Framework-free**: imports only stdlib + ``secopent.domain.*`` +
  ``secopent.application.audit`` (M0 AuditService). The architecture
  boundary test enforces this.
* **Injectable checkers**: each external probe (git commit date, API
  reachability, upstream tag count, signature status) is a Protocol so
  tests inject fakes; production wires real infrastructure adapters at
  composition root.
* **Frozen dataclasses**: ``HealthReport`` and ``HealthAlert`` are
  immutable so callers can safely cache / log them.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from ..domain.catalog.coverage import CoverageMatrix
from ..domain.common.errors import DomainValidationError
from .audit import AuditService


class HealthAlertKind(StrEnum):
    """The 5 §7.3 alert kinds. Mirrors the table verbatim."""

    SOURCE_STALE = "source_stale"
    CURATION_LAG = "curation_lag"
    COVERAGE_REGRESSION = "coverage_regression"
    SOURCE_UNREACHABLE = "source_unreachable"
    SIGNATURE_INVALID = "signature_invalid"


@dataclass(frozen=True, slots=True)
class HealthAlert:
    """A single health alert emitted by a detector.

    ``source`` identifies the upstream or component the alert is about
    (e.g. ``"nuclei-templates"``, ``"osv"``). ``details`` carries the
    detector-specific payload (counts, thresholds, etc.) for the audit
    trail and operator UI.
    """

    kind: HealthAlertKind
    source: str
    details: dict[str, object]


@dataclass(frozen=True, slots=True)
class HealthReport:
    """Aggregated result of ``KnowledgeHealthMonitor.check_all()``.

    ``alerts`` is a tuple so the report is hashable and immutable; the
    ordering matches the detector execution order in ``check_all``.
    """

    alerts: tuple[HealthAlert, ...]


# --- Injectable checker Protocols ------------------------------------------


class SourceFreshnessChecker(Protocol):
    """Probe days-since-last-commit for an upstream source (e.g. git)."""

    def days_since_last_commit_for(self, source: str) -> int:
        """Return days since the last commit on ``source``'s default branch."""
        ...


class CurationLagChecker(Protocol):
    """Probe the count of upstream tags not yet mapped in TestCatalog."""

    def unmapped_upstream_tags(self, source: str) -> int:
        """Return the number of upstream tags with no TestCatalog mapping."""
        ...


class SourceReachabilityChecker(Protocol):
    """Probe whether a remote source (e.g. OSV REST API) is reachable."""

    def is_reachable(self, source: str) -> bool:
        """Return True iff ``source`` answers a health-check request."""
        ...


class SignatureChecker(Protocol):
    """Probe the result of the most recent bundle signature verification.

    The detector reports on the *last* verification rather than re-running
    one: UpdateManager already verifies signatures on sync
    (``application/updates.py``); the health monitor surfaces a failed
    verification as an alert so operators see the cumulative state.
    """

    def last_signature_valid(self) -> bool:
        """Return True iff the most recent bundle signature verification passed."""
        ...


# --- Monitor ----------------------------------------------------------------


class KnowledgeHealthMonitor:
    """Run the 5 §7.3 detectors and enforce the §7.5 coverage regression gate.

    The monitor is stateless between calls; persistent state lives in the
    injected ``AuditService`` (override audit events) and the injected
    checkers (which encapsulate whatever caching/health they need).

    Construction
    ------------
    Production wires concrete infrastructure adapters
    (``infrastructure/intel_sources/*`` for reachability,
    ``infrastructure/signing/*`` for signature status, a git adapter for
    freshness). Tests inject fakes that satisfy the Protocols.
    """

    def __init__(
        self,
        *,
        audit_service: AuditService,
        freshness_checker: SourceFreshnessChecker,
        curation_checker: CurationLagChecker,
        reachability_checker: SourceReachabilityChecker,
        signature_checker: SignatureChecker,
        stale_threshold_days: int = 7,
        curation_lag_threshold: int = 100,
        sources: tuple[str, ...] = ("nuclei-templates",),
        intel_sources: tuple[str, ...] = ("osv",),
    ) -> None:
        if stale_threshold_days < 1:
            raise DomainValidationError(
                f"stale_threshold_days must be >= 1, got {stale_threshold_days}"
            )
        if curation_lag_threshold < 1:
            raise DomainValidationError(
                f"curation_lag_threshold must be >= 1, got {curation_lag_threshold}"
            )
        self._audit = audit_service
        self._freshness = freshness_checker
        self._curation = curation_checker
        self._reachability = reachability_checker
        self._signature = signature_checker
        self._stale_threshold_days = stale_threshold_days
        self._curation_lag_threshold = curation_lag_threshold
        self._sources = sources
        self._intel_sources = intel_sources

    # --- §7.3 detectors ---------------------------------------------------

    def check_source_stale(self) -> tuple[HealthAlert, ...]:
        """Detector 1: nuclei-templates 超 7 天无新 commit."""
        alerts: list[HealthAlert] = []
        for source in self._sources:
            days = self._freshness.days_since_last_commit_for(source)
            if days > self._stale_threshold_days:
                alerts.append(
                    HealthAlert(
                        kind=HealthAlertKind.SOURCE_STALE,
                        source=source,
                        details={
                            "days_since_last_commit": days,
                            "threshold_days": self._stale_threshold_days,
                        },
                    )
                )
        return tuple(alerts)

    def check_curation_lag(self) -> tuple[HealthAlert, ...]:
        """Detector 2: nuclei 新增 >= 100 tag 但 TestCatalog 未映射."""
        alerts: list[HealthAlert] = []
        for source in self._sources:
            unmapped = self._curation.unmapped_upstream_tags(source)
            if unmapped >= self._curation_lag_threshold:
                alerts.append(
                    HealthAlert(
                        kind=HealthAlertKind.CURATION_LAG,
                        source=source,
                        details={
                            "unmapped_upstream_count": unmapped,
                            "threshold": self._curation_lag_threshold,
                        },
                    )
                )
        return tuple(alerts)

    def check_source_unreachable(self) -> tuple[HealthAlert, ...]:
        """Detector 4: OSV API 不可达 -> 降级缓存 + 告警.

        The detector emits an alert naming the unreachable source and
        records that the system has degraded to the local cache. The
        actual cache fallback is the responsibility of ``IntelService``
        (M1 Task 5 / application/intel.py); this monitor only reports.
        """
        alerts: list[HealthAlert] = []
        for source in self._intel_sources:
            if not self._reachability.is_reachable(source):
                alerts.append(
                    HealthAlert(
                        kind=HealthAlertKind.SOURCE_UNREACHABLE,
                        source=source,
                        details={"degraded_to": "cache"},
                    )
                )
        return tuple(alerts)

    def check_signature_invalid(self) -> tuple[HealthAlert, ...]:
        """Detector 5: bundle 签名校验失败.

        Reports on the most recent signature verification result. The
        verification itself happens in ``UpdateManager.sync`` (M1 Task 6);
        the monitor surfaces failures here so an operator running
        ``check_all`` sees the cumulative state.
        """
        if not self._signature.last_signature_valid():
            return (
                HealthAlert(
                    kind=HealthAlertKind.SIGNATURE_INVALID,
                    source="update_bundle",
                    details={"last_verify_ok": False},
                ),
            )
        return ()

    # --- Aggregation ------------------------------------------------------

    def check_all(self) -> HealthReport:
        """Run every detector that needs no extra arguments and aggregate.

        The coverage regression detector (§7.3 row 3) is intentionally NOT
        run from ``check_all`` because it requires the old+new CoverageMatrix
        pair that only the publish flow has. Use ``enforce_coverage_gate``
        for that detector.

        Returns a frozen ``HealthReport`` whose ``alerts`` tuple preserves
        detector execution order.
        """
        alerts: list[HealthAlert] = []
        alerts.extend(self.check_source_stale())
        alerts.extend(self.check_curation_lag())
        alerts.extend(self.check_source_unreachable())
        alerts.extend(self.check_signature_invalid())
        return HealthReport(alerts=tuple(alerts))

    # --- §7.5 选项 D gate -------------------------------------------------

    def enforce_coverage_gate(
        self,
        *,
        new_matrix: CoverageMatrix,
        old_matrix: CoverageMatrix,
        override_reason: str | None = None,
        roadmap: str | None = None,
    ) -> None:
        """选项 D: 0 容忍 coverage regression gate (§7.5).

        Rules (verbatim from §7.5):

        * Default: 0 容忍 (coverage_rate monotonic non-decreasing). New
          ``coverage_rate() < old`` -> block publish by raising
          ``DomainValidationError``.
        * Override escape hatch: allowed when ``override_reason`` AND
          ``roadmap`` are both non-empty. Each override is audited
          (``coverage.override`` action) with old/new rate, reason, and
          roadmap so the chain of custody is preserved.
        * Override with reason but missing roadmap -> still rejected
          (both required by §7.5).
        * Equal or higher rate -> no regression, no raise, no audit.

        Raises
        ------
        DomainValidationError
            On regression without a valid override, or with reason but
            missing roadmap.
        """
        old_rate = old_matrix.coverage_rate()
        new_rate = new_matrix.coverage_rate()

        # No regression -> pass through.
        if new_rate >= old_rate:
            return

        # Regression detected -> require a full override (reason + roadmap).
        reason_provided = bool(override_reason and override_reason.strip())
        roadmap_provided = bool(roadmap and roadmap.strip())

        if not reason_provided and not roadmap_provided:
            raise DomainValidationError(
                f"coverage regression blocked publish: "
                f"old_rate={old_rate:.4f} new_rate={new_rate:.4f}; "
                f"provide override_reason + roadmap to override (§7.5 选项 D)"
            )
        if reason_provided and not roadmap_provided:
            raise DomainValidationError(
                "coverage regression override requires both override_reason "
                "AND roadmap (§7.5 选项 D); roadmap is missing"
            )
        if not reason_provided and roadmap_provided:
            raise DomainValidationError(
                "coverage regression override requires both override_reason "
                "AND roadmap (§7.5 选项 D); override_reason is missing"
            )

        # Full override provided -> audit and allow.
        self._audit.record(
            actor="health-monitor",
            action="coverage.override",
            resource_type="coverage_matrix",
            resource_id=new_matrix.version,
            payload={
                "old_version": old_matrix.version,
                "new_version": new_matrix.version,
                "old_rate": old_rate,
                "new_rate": new_rate,
                "override_reason": override_reason,
                "roadmap": roadmap,
            },
        )


__all__ = [
    "HealthAlert",
    "HealthAlertKind",
    "HealthReport",
    "KnowledgeHealthMonitor",
    "SignatureChecker",
    "SourceFreshnessChecker",
    "SourceReachabilityChecker",
    "CurationLagChecker",
]
