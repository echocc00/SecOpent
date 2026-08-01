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

from ..domain.common.canonical import utc_now
from ..domain.findings.models import Finding
from ..domain.scope.models import ScopeSnapshot
from .assessments import AssessmentService
from .audit import AuditService
from .finding_correlation import FindingCorrelation
from .jobs import JobService
from .orchestrator import Orchestrator, StepRunner
from .ports.repositories import AssessmentRepository, ScopeRepository


class _FindingRepository(Protocol):
    """Minimal write-port for persisting findings during execution."""
    def add(self, finding: Finding) -> None: ...


def execute_assessment(
    *,
    assessment_id: str,
    assessment_repo: AssessmentRepository,
    scope_repo: ScopeRepository,
    finding_repo: _FindingRepository,
    audit_repo: object,
    step_runner_factory: Callable[[ScopeSnapshot], StepRunner],
) -> None:
    """Run one assessment to completion in a background thread.

    Constructs the Orchestrator with the injected ``step_runner_factory`` (so
    tests can inject a fake; production wires ``AdapterStepRunner`` over
    ``RealScanRunner``), dispatches the plan, runs to completion, correlates
    observations into findings (tagged with ``assessment_id``), and updates
    status. Any exception -> ``FAILED`` with the reason audited.
    """
    service = AssessmentService(assessment_repo)
    audit = AuditService(audit_repo)  # type: ignore[arg-type]

    try:
        service.mark_running(assessment_id)  # QUEUED -> RUNNING
        audit.record(
            actor="system", action="assessment.started",
            resource_type="assessment", resource_id=assessment_id, payload={},
        )

        assessment = assessment_repo.get(assessment_id)
        assert assessment is not None and assessment.active_plan_id is not None
        plan = assessment_repo.get_plan(assessment.active_plan_id)
        assert plan is not None
        scope = scope_repo.get_snapshot(assessment.scope_snapshot_id)
        assert scope is not None

        step_runner = step_runner_factory(scope)
        jobs = JobService()
        orchestrator = Orchestrator(jobs, step_runner)
        orchestrator.dispatch(plan)
        orchestrator.run_to_completion(owner="system", now=utc_now())

        observations = step_runner.all_observations()  # type: ignore[attr-defined]
        findings = FindingCorrelation().correlate(observations)
        for finding in findings:
            finding_repo.add(replace(finding, assessment_id=assessment_id))

        service.complete(assessment_id)  # RUNNING -> COMPLETED
        audit.record(
            actor="system", action="assessment.completed",
            resource_type="assessment", resource_id=assessment_id,
            payload={"findings": len(findings)},
        )
    except Exception as exc:  # noqa: BLE001 - executor must never leak
        with contextlib.suppress(Exception):
            service.fail(assessment_id, str(exc))
        audit.record(
            actor="system", action="assessment.failed",
            resource_type="assessment", resource_id=assessment_id,
            payload={"reason": str(exc)},
        )
