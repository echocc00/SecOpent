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
import secrets
from collections.abc import Callable
from dataclasses import replace
from datetime import timedelta
from typing import Protocol

import structlog

from ..domain.common.canonical import utc_now
from ..domain.common.errors import DomainError
from ..domain.findings.models import Finding
from ..domain.permits.models import DEFAULT_PERMIT_TTL_SECONDS, ExecutionPermit
from ..domain.scope.models import ScopeSnapshot
from .assessments import AssessmentService
from .audit import AuditService
from .audit_chain import AuditChain
from .emergency_stop import EmergencyStop
from .finding_correlation import FindingCorrelation
from .jobs import JobService
from .oracle_service import OracleService
from .orchestrator import Orchestrator, StepRunner
from .ports.repositories import AssessmentRepository, ScopeRepository
from .ports.security import (
    EgressGuardProtocol,
    NftScopeEnforcerProtocol,
    PermitRegistry,
    PermitSignerProtocol,
    PermitVerifierProtocol,
)
from .scope_enforcer import EnforcementContext, ScopeEnforcer

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


def _issue_permit(
    signer: PermitSignerProtocol | None,
    registry: PermitRegistry | None,
    *,
    assessment_id: str,
    scope_digest: str,
    plan_digest: str,
) -> ExecutionPermit | None:
    """Sign an ExecutionPermit binding this run to its scope + plan (W2-A T3).

    Returns None when no signer is wired (e.g. tests that don't exercise the
    permit chain). The signed permit's nonce is registered with the registry so
    EmergencyStop can invalidate it before it's used.
    """
    if signer is None:
        return None
    now = utc_now()
    permit = signer.issue(ExecutionPermit(
        job_id=assessment_id,
        worker_id="adapter-executor",
        scope_digest=scope_digest,
        plan_digest=plan_digest,
        capabilities=(),
        budget=0.0,
        issued_at=now,
        expires_at=now + timedelta(seconds=DEFAULT_PERMIT_TTL_SECONDS),
        nonce=secrets.token_urlsafe(16),
    ))
    if registry is not None:
        registry.record_issued(permit.nonce, used=False)
    _logger.info(
        "permit issued", assessment_id=assessment_id, permit_nonce=permit.nonce,
    )
    return permit


def _audit_record(
    audit_repo: object,
    audit_chain: AuditChain | None,
    *,
    actor: str,
    action: str,
    resource_type: str,
    resource_id: str,
    payload: dict[str, object],
    permit_nonce: str | None = None,
) -> None:
    """Record to the DB-backed queryable audit log AND the signed AuditChain in
    the SAME transaction (v4 refactor). The queryable log uses the repo's bound
    session; the signed chain is passed that same session so both INSERTs join
    one transaction, one WAL frame, one commit (caller commits). This eliminates
    the cross-connection double-write that caused v4's SQLite lock contention.
    """
    AuditService(audit_repo).record(  # type: ignore[arg-type]
        actor=actor, action=action, resource_type=resource_type,
        resource_id=resource_id, payload=payload,
    )
    if audit_chain is not None:
        session = getattr(audit_repo, "session", None)
        audit_chain.record(
            actor=actor, action=action, resource_type=resource_type,
            resource_id=resource_id, payload=payload,
            permit_nonce=permit_nonce, session=session,
        )


def _phase_commit(audit_repo: object) -> None:
    """Commit the caller-owned session at a phase boundary (v0.3.0 T3).

    No-ops for in-memory repos (no bound session). In production this ends
    the current short transaction, releasing the SQLite WAL write lock, and
    the next write implicitly opens a fresh transaction. Called around the
    long-running phases (scan, oracle) so emergency stops and other writers
    are never blocked for the duration of an assessment (v4 root cause).
    """
    session = getattr(audit_repo, "session", None)
    if session is not None:
        session.commit()


def _verify_permit(
    permit: ExecutionPermit | None,
    verifier: PermitVerifierProtocol | None,
    registry: PermitRegistry | None,
    audit_chain: AuditChain | None,
    assessment_id: str,
    service: AssessmentService,
    audit_repo: object,
) -> bool | None:
    """Verify the signed permit (signature + expiry + replay + worker).

    Returns True if the permit is valid (or no verifier is wired). Returns
    None if verification failed (the assessment is already FAILED + audited).
    On success the nonce is marked used so it cannot be replayed. Replay set
    comes from the AuditChain's recorded nonces (T5).
    """
    if verifier is None or permit is None:
        return True
    used_nonces: frozenset[str] = (
        frozenset(audit_chain.permit_nonces()) if audit_chain is not None else frozenset()
    )
    try:
        verifier.verify(
            permit, now=utc_now(), used_nonces=used_nonces,
            expected_worker="adapter-executor",
        )
    except DomainError as exc:
        service.fail(assessment_id, f"PERMIT_INVALID:{exc}")
        _audit_record(
            audit_repo, audit_chain, actor="system",
            action="assessment.blocked.permit_invalid",
            resource_type="assessment", resource_id=assessment_id,
            payload={"reason": str(exc)},
        )
        _logger.warning(
            "permit verification failed", assessment_id=assessment_id, error=str(exc),
        )
        return None
    if registry is not None:
        registry.record_used(permit.nonce)
    return True


def _check_plan_scope(
    enforcer: ScopeEnforcer | None,
    egress_guard: EgressGuardProtocol | None,
    plan: object,
    scope: ScopeSnapshot,
    permit_valid: bool,
    audit_chain: AuditChain | None,
    assessment_id: str,
    service: AssessmentService,
    audit_repo: object,
) -> bool:
    """Pre-check every plan target against the scope + egress before dispatch.

    Returns True if all targets are in scope (or no enforcer is wired).
    Returns False (and FAILS + audits the assessment) on the first denial.
    """
    if enforcer is None and egress_guard is None:
        return True
    steps = getattr(plan, "steps", ())
    for step in steps:
        target = step.parameters.get("target") if hasattr(step, "parameters") else None
        if not target:
            continue
        if egress_guard is not None:
            egress_decision = egress_guard.check(target, scope)
            if not egress_decision.allowed:
                service.fail(assessment_id, f"EGRESS_DENIED:{egress_decision.reason}")
                _audit_record(
                    audit_repo, audit_chain, actor="system",
                    action="assessment.blocked.egress_denied",
                    resource_type="assessment", resource_id=assessment_id,
                    payload={"target": target, "reason": egress_decision.reason},
                )
                _logger.warning(
                    "egress denied", assessment_id=assessment_id,
                    target=target, reason=egress_decision.reason,
                )
                return False
        if enforcer is not None:
            context = EnforcementContext(
                risk=step.risk,
                approved_risks=frozenset({step.risk}),
                approved=True,
                budget_remaining=1.0,
                now=utc_now(),
                permit_valid=permit_valid,
            )
            decision = enforcer.check(target, scope, context)
            if not decision.allowed:
                service.fail(assessment_id, f"SCOPE_VIOLATION:{decision.reason}")
                _audit_record(
                    audit_repo, audit_chain, actor="system",
                    action="assessment.blocked.scope_violation",
                    resource_type="assessment", resource_id=assessment_id,
                    payload={"target": target, "reason": decision.reason},
                )
                _logger.warning(
                    "scope violation", assessment_id=assessment_id,
                    target=target, reason=decision.reason,
                )
                return False
    return True


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
    emergency_stop: EmergencyStop | None = None,
    permit_signer: PermitSignerProtocol | None = None,
    permit_registry: PermitRegistry | None = None,
    permit_verifier: PermitVerifierProtocol | None = None,
    scope_enforcer: ScopeEnforcer | None = None,
    egress_guard: EgressGuardProtocol | None = None,
    nft_scope_enforcer: NftScopeEnforcerProtocol | None = None,
    audit_chain: AuditChain | None = None,
    oracle: OracleService | None = None,
    confirmed_finding_repo: object | None = None,
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

    nft_applied = False
    try:
        service.mark_running(assessment_id)  # QUEUED -> RUNNING

        if emergency_stop is not None and emergency_stop.is_triggered:
            service.fail(assessment_id, "EMERGENCY_STOP_TRIGGERED")
            _audit_record(
                audit_repo, audit_chain, actor="system",
                action="assessment.blocked.emergency_stop",
                resource_type="assessment", resource_id=assessment_id,
                payload={"reason": "emergency_stop_triggered"},
            )
            _logger.warning(
                "assessment blocked by emergency stop", assessment_id=assessment_id,
            )
            return

        assessment = assessment_repo.get(assessment_id)
        assert assessment is not None and assessment.active_plan_id is not None
        plan = assessment_repo.get_plan(assessment.active_plan_id)
        assert plan is not None
        scope = scope_repo.get_snapshot(assessment.scope_snapshot_id)
        assert scope is not None

        permit = _issue_permit(
            permit_signer, permit_registry,
            assessment_id=assessment_id, scope_digest=scope.digest,
            plan_digest=plan.digest,
        )

        permit_valid = _verify_permit(
            permit, permit_verifier, permit_registry, audit_chain,
            assessment_id, service, audit_repo,
        )
        if permit_valid is None:
            return  # verification failed: assessment already FAILED + audited

        if audit_chain is not None and permit is not None:
            audit_chain.record_permit_nonce(
                actor="system", job_id=assessment_id, permit_nonce=permit.nonce,
                session=getattr(audit_repo, "session", None),
            )

        _audit_record(
            audit_repo, audit_chain, actor="system", action="assessment.started",
            resource_type="assessment", resource_id=assessment_id,
            payload={"permit_nonce": permit.nonce} if permit is not None else {},
        )
        _logger.info("assessment started", assessment_id=assessment_id)

        if not _check_plan_scope(
            scope_enforcer, egress_guard, plan, scope, permit_valid, audit_chain,
            assessment_id, service, audit_repo,
        ):
            return  # out-of-scope/egress-denied target: assessment already FAILED + audited

        # Push the scope into kernel nftables (host-level defence in depth,
        # W2-B). Best-effort: non-Linux dev hosts have no nft binary; failures
        # are audited and the run continues on the app-layer EgressGuard alone.
        if nft_scope_enforcer is not None:
            try:
                nft_scope_enforcer.apply_scope(
                    scope, session=getattr(audit_repo, "session", None)
                )
                nft_applied = True
            except Exception as exc:  # noqa: BLE001 - nft is defence-in-depth
                _logger.warning(
                    "nft apply_scope failed (continuing on app-layer guard)",
                    assessment_id=assessment_id, error=str(exc),
                )

        # v0.3.0 T3: release the WAL write lock before the long scan phase -
        # everything up to here (RUNNING + permit + scope audits) is durable.
        _phase_commit(audit_repo)

        step_runner = step_runner_factory(scope)
        jobs = JobService()
        orchestrator = Orchestrator(jobs, step_runner, max_workers=max_workers)
        orchestrator.dispatch(plan)
        orchestrator.run_to_completion(owner="system", now=utc_now())

        observations = step_runner.all_observations()  # type: ignore[attr-defined]
        findings = FindingCorrelation().correlate(observations)
        for finding in findings:
            finding_repo.add(replace(finding, assessment_id=assessment_id))
        # v0.3.0 T3: findings durable before the (minutes-long) oracle phase.
        _phase_commit(audit_repo)

        if oracle is not None and confirmed_finding_repo is not None and findings:
            try:
                summary = oracle.verify_findings(
                    findings,
                    finding_repo=finding_repo,
                    confirmed_repo=confirmed_finding_repo,
                    audit=AuditService(audit_repo),  # type: ignore[arg-type]
                    audit_chain=audit_chain,
                    actor="system",
                    verified_at=utc_now(),
                    session=getattr(audit_repo, "session", None),
                )
                _audit_record(
                    audit_repo, audit_chain, actor="system", action="oracle.batch_verified",
                    resource_type="assessment", resource_id=assessment_id,
                    payload={
                        "confirmed": summary.confirmed,
                        "refuted": summary.refuted,
                        "inconclusive": summary.inconclusive,
                        "skipped": summary.skipped,
                        "failed": summary.failed,
                    },
                )
            except Exception as exc:  # noqa: BLE001 - oracle is best-effort
                _logger.warning(
                    "oracle batch verification failed (findings remain unconfirmed)",
                    assessment_id=assessment_id, error=str(exc), exc_info=True,
                )
                _audit_record(
                    audit_repo, audit_chain, actor="system", action="oracle.batch_failed",
                    resource_type="assessment", resource_id=assessment_id,
                    payload={"reason": str(exc)},
                )
        # v0.3.0 T3: oracle-phase writes durable before completion bookkeeping.
        _phase_commit(audit_repo)

        service.complete(assessment_id)  # RUNNING -> COMPLETED
        coverage_rate, uncovered = _compute_coverage(catalog, asset_types, observations)
        _audit_record(
            audit_repo, audit_chain, actor="system", action="assessment.completed",
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
        _audit_record(
            audit_repo, audit_chain, actor="system", action="assessment.failed",
            resource_type="assessment", resource_id=assessment_id,
            payload={"reason": str(exc)},
        )
    finally:
        # Flush the nft allow/block sets so the next assessment starts clean
        # (W2-B). Best-effort: revoke must never mask a real failure.
        if nft_applied and nft_scope_enforcer is not None:
            with contextlib.suppress(Exception):
                nft_scope_enforcer.revoke()
