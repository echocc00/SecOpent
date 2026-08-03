# src/secopent/application/execution.py
"""Background assessment execution: wire API -> Orchestrator (v0.1.2 P0).

The execution layer components (Orchestrator, AdapterStepRunner, JobService,
RealScanRunner) were proven end-to-end by T5's ``tests/e2e_real``. This module
is the missing bridge from the REST API to those components: it runs the
Orchestrator in a daemon thread so ``POST /assessments/{id}/start`` returns
immediately, streams progress via the existing SSE endpoint (which polls
``assessment.status``), and persists correlated findings with ``assessment_id``.

Emergency stop works through container termination: ``POST /assessments/{id}/stop``
kills active adapter containers via ``DockerContainerTerminator``; the step's
subprocess then fails, ``run_to_completion`` raises, and this module records
``FAILED``. No separate stop-flag polling is needed for the P0 fix.
"""
from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import replace
from typing import Protocol

import structlog

from ..domain.common.canonical import utc_now
from ..domain.findings.models import Finding
from ..domain.scope.models import ScopeSnapshot
from .assessments import AssessmentService
from .audit import AuditService
from .finding_correlation import FindingCorrelation
from .jobs import JobService
from .orchestrator import Orchestrator, StepRunner
from .ports.repositories import AssessmentRepository, ScopeRepository

_logger = structlog.get_logger(__name__)


class _FindingRepository(Protocol):
    """Minimal write-port for persisting findings during execution."""
    def add(self, finding: Finding) -> None: ...


def _compute_coverage(
    catalog: object | None, asset_types: tuple[object, ...], observations: object
) -> tuple[float, tuple[str, ...]]:
    """Best-effort coverage rate from the run's observations.

    Returns (0.0, ()) when catalog/asset_types are unavailable (e.g. tests),
    so the report endpoint can fall back to 0.0 without crashing. Uses the
    first asset type; multi-type assessments take the conservative rate.
    """
    if catalog is None or not asset_types or not observations:
        return 0.0, ()
    try:
        from .coverage import CoverageService
        report = CoverageService().compute(asset_types[0], observations, catalog)  # type: ignore[arg-type]
        return report.coverage_rate, report.uncovered_classes
    except Exception:  # noqa: BLE001 - coverage is best-effort, never fail execution
        return 0.0, ()


def execute_assessment(
    *,
    assessment_id: str,
    assessment_repo: AssessmentRepository,
    scope_repo: ScopeRepository,
    finding_repo: _FindingRepository,
    audit_repo: object,
    step_runner_factory: Callable[[ScopeSnapshot], StepRunner],
    catalog: object | None = None,
    asset_types: tuple[object, ...] = (),
    max_workers: int = 1,
) -> None:
    """Run one assessment to completion in a background thread.

    Constructs the Orchestrator with the injected ``step_runner_factory`` (so
    tests can inject a fake; production wires ``AdapterStepRunner`` over
    ``RealScanRunner``), dispatches the plan, runs to completion, correlates
    observations into findings (tagged with ``assessment_id``), and updates
    status. Any exception -> ``FAILED`` with the reason audited.

    When ``catalog`` + ``asset_types`` are supplied, a coverage report is
    computed from the run's observations and the rate is recorded in the
    ``assessment.completed`` audit payload (so the report endpoint can surface
    a real number instead of a hardcoded 0.0).
    """
    service = AssessmentService(assessment_repo)
    audit = AuditService(audit_repo)  # type: ignore[arg-type]

    try:
        service.mark_running(assessment_id)  # QUEUED -> RUNNING
        audit.record(
            actor="system", action="assessment.started",
            resource_type="assessment", resource_id=assessment_id, payload={},
        )
        _logger.info("assessment started", assessment_id=assessment_id)

        assessment = assessment_repo.get(assessment_id)
        assert assessment is not None and assessment.active_plan_id is not None
        plan = assessment_repo.get_plan(assessment.active_plan_id)
        assert plan is not None
        scope = scope_repo.get_snapshot(assessment.scope_snapshot_id)
        assert scope is not None

        step_runner = step_runner_factory(scope)
        jobs = JobService()
        orchestrator = Orchestrator(jobs, step_runner, max_workers=max_workers)
        orchestrator.dispatch(plan)
        orchestrator.run_to_completion(owner="system", now=utc_now())

        observations = step_runner.all_observations()  # type: ignore[attr-defined]
        findings = FindingCorrelation().correlate(observations)
        for finding in findings:
            finding_repo.add(replace(finding, assessment_id=assessment_id))

        service.complete(assessment_id)  # RUNNING -> COMPLETED
        coverage_rate, uncovered = _compute_coverage(catalog, asset_types, observations)
        audit.record(
            actor="system", action="assessment.completed",
            resource_type="assessment", resource_id=assessment_id,
            payload={
                "findings": len(findings),
                "coverage_rate": coverage_rate,
                "uncovered_classes": list(uncovered),
            },
        )
        _logger.info(
            "assessment completed",
            assessment_id=assessment_id, findings=len(findings),
            coverage_rate=coverage_rate,
        )
    except Exception as exc:  # noqa: BLE001 - executor must never leak
        _logger.warning(
            "assessment failed", assessment_id=assessment_id,
            error=str(exc), exc_info=True,
        )
        with contextlib.suppress(Exception):
            service.fail(assessment_id, str(exc))
        audit.record(
            actor="system", action="assessment.failed",
            resource_type="assessment", resource_id=assessment_id,
            payload={"reason": str(exc)},
        )
