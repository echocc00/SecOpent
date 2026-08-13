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

from ..domain.assessments.models import ControlState
from ..domain.common.canonical import utc_now
from ..domain.common.errors import DomainError
from ..domain.findings.models import Finding
from ..domain.jobs.models import JobStatus
from ..domain.permits.models import DEFAULT_PERMIT_TTL_SECONDS, ExecutionPermit
from ..domain.policy.models import RiskClass
from ..domain.scope.models import ScopeSnapshot
from .assessments import AssessmentService
from .audit import AuditService
from .audit_chain import AuditChain
from .emergency_stop import EmergencyStop
from .finding_correlation import FindingCorrelation
from .jobs import JobService
from .oracle_service import OracleService
from .orchestrator import (
    Orchestrator,
    StepGate,
    StepRunner,
)
from .ports.jobs import JobStore
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
    outbox: object | None = None,
) -> None:
    """Record an audit event for the execution.

    With ``outbox`` wired (production, v0.3.0 T4) ONE outbox row is written
    in the caller's transaction and the OutboxWorker fans it out to both
    audit tables asynchronously - audit is off the hot path. Events carrying
    a ``permit_nonce`` always take the direct path so replay-detection state
    is never async. Without an outbox (tests) the event is recorded to the
    DB-backed queryable audit log AND the signed AuditChain in the SAME
    transaction (v4 refactor): the queryable log uses the repo's bound
    session; the signed chain is passed that same session so both INSERTs
    join one transaction, one WAL frame, one commit (caller commits).
    """
    session = getattr(audit_repo, "session", None)
    if outbox is not None and permit_nonce is None:
        outbox.record(  # type: ignore[attr-defined]
            actor=actor, action=action, resource_type=resource_type,
            resource_id=resource_id, payload=payload, session=session,
        )
        return
    AuditService(audit_repo).record(  # type: ignore[arg-type]
        actor=actor, action=action, resource_type=resource_type,
        resource_id=resource_id, payload=payload,
    )
    if audit_chain is not None:
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
    audit_outbox: object | None = None,
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
            outbox=audit_outbox,
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
    audit_outbox: object | None = None,
) -> bool:
    """Pre-check every target that will be scanned against scope + egress.

    Returns True if all targets are in scope (or no enforcer is wired).
    Returns False (and FAILS + audits the assessment) on the first denial.

    The targets checked are: (1) any ``target`` a plan step carries explicitly,
    plus (2) every ``scope.include`` entry - because the production
    ``_production_step_runner`` uses ``scope.include`` as the ScanContext
    targets, so those are the actual addresses the tool containers will hit.
    Relying on ``step.parameters["target"]`` alone was dead code: real
    catalog-generated plans never populate it (v8 scope/egress bug B - the
    check silently skipped every step).
    """
    if enforcer is None and egress_guard is None:
        return True
    steps = getattr(plan, "steps", ())
    targets: list[str] = []
    for step in steps:
        target = step.parameters.get("target") if hasattr(step, "parameters") else None
        if target:
            targets.append(target)
    # Also check concrete-host scope.include entries (URLs/IPs/domains): the
    # production _production_step_runner uses scope.include as ScanContext
    # targets, so those are the actual addresses tool containers hit. CIDR
    # networks (e.g. "10.0.0.0/30") are authorization boundaries, not direct
    # egress targets - they are skipped (the plan's explicit target is checked
    # instead). This closes the v8 bug B dead-code gap: a catalog plan with no
    # `target` field still has every concrete scan destination checked.
    for target in scope.include:
        if "/" in target and not target.startswith(("http://", "https://")):
            continue  # CIDR network, not a direct egress target
        if target not in targets:
            targets.append(target)
    if not targets:
        return True
    for target in targets:
        if egress_guard is not None:
            egress_decision = egress_guard.check(target, scope)
            if not egress_decision.allowed:
                service.fail(assessment_id, f"EGRESS_DENIED:{egress_decision.reason}")
                _audit_record(
                    audit_repo, audit_chain, actor="system",
                    action="assessment.blocked.egress_denied",
                    resource_type="assessment", resource_id=assessment_id,
                    payload={"target": target, "reason": egress_decision.reason},
                    outbox=audit_outbox,
                )
                _logger.warning(
                    "egress denied", assessment_id=assessment_id,
                    target=target, reason=egress_decision.reason,
                )
                return False
        if enforcer is not None:
            # Target-driven (scope.include), not step-driven: use a fixed,
            # already-approved risk context so the enforcer's scope/rebinding
            # checks run while its risk/approval steps pass trivially (the
            # assessment was approved upstream before dispatch).
            context = EnforcementContext(
                risk=RiskClass.PASSIVE,
                approved_risks=frozenset({RiskClass.PASSIVE}),
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
                    outbox=audit_outbox,
                )
                _logger.warning(
                    "scope violation", assessment_id=assessment_id,
                    target=target, reason=decision.reason,
                )
                return False
    return True


def _make_control_gate(
    assessment_repo: AssessmentRepository, assessment_id: str
) -> StepGate:
    """Build the step-boundary gate: reads + consumes the control signal.

    Called by the Orchestrator before every job lease. Returns None to keep
    executing, "paused" to stop issuing work (remaining jobs stay READY for a
    resume drain), or "cancelled" to abort the run. The signal is CONSUMED
    (cleared to NONE) on read, in the same repository transaction, so a
    restarted drain never double-applies it.
    """
    def gate() -> str | None:
        current = assessment_repo.get(assessment_id)
        if current is None:
            return "cancelled"  # assessment vanished -> stop the run
        signal = current.control
        if signal is ControlState.NONE:
            return None
        assessment_repo.add(replace(current, control=ControlState.NONE))
        if signal is ControlState.PAUSE_REQUESTED:
            return "paused"
        if signal is ControlState.CANCEL_REQUESTED:
            return "cancelled"
        return None  # RESUME_REQUESTED mid-run: we are already executing

    return gate


def _handle_cancelled(
    *,
    assessment_id: str,
    jobs: JobService,
    audit_repo: object,
    audit_chain: AuditChain | None,
    audit_outbox: object | None,
    cancel_terminator: Callable[[str], int] | None,
) -> None:
    """Abandon a cancelled run: skip remaining jobs, terminate containers.

    Best-effort: remaining READY/BLOCKED/PENDING/LEASED jobs become SKIPPED so
    a later resume cannot pick them up; the optional ``cancel_terminator``
    (per-assessment container kill) is attempted and its outcome audited. The
    assessment status is already CANCELLED (the service wrote it with the
    signal) - this function never touches it.
    """
    for job in jobs.all():
        if job.status in {
            JobStatus.READY, JobStatus.BLOCKED, JobStatus.PENDING, JobStatus.LEASED,
        }:
            jobs.skip(job.id)
    terminated = 0
    if cancel_terminator is not None:
        try:
            terminated = cancel_terminator(assessment_id)
        except Exception as exc:  # noqa: BLE001 - cancellation must not crash
            _audit_record(
                audit_repo, audit_chain, actor="system",
                action="assessment.cancel.termination_failed",
                resource_type="assessment", resource_id=assessment_id,
                payload={"reason": str(exc)},
                outbox=audit_outbox,
            )
    _audit_record(
        audit_repo, audit_chain, actor="system", action="assessment.cancelled",
        resource_type="assessment", resource_id=assessment_id,
        payload={"actual": True, "terminated_containers": terminated},
        outbox=audit_outbox,
    )
    _logger.info("assessment cancelled", assessment_id=assessment_id)


def _finalize_execution(
    *,
    assessment_id: str,
    step_runner: StepRunner,
    jobs: JobService,
    service: AssessmentService,
    finding_repo: _FindingRepository,
    audit_repo: object,
    audit_chain: AuditChain | None,
    audit_outbox: object | None,
    catalog: object | None,
    asset_types: tuple[object, ...],
    oracle: OracleService | None,
    confirmed_finding_repo: object | None,
) -> None:
    """Correlate observations -> findings -> oracle -> COMPLETED + coverage.

    The shared tail of ``execute_assessment`` and ``resume_assessment``: turns
    the run's observations into persisted findings (tagged with
    ``assessment_id``), runs the best-effort oracle pass, and marks the
    assessment COMPLETED with its coverage rate. An execution where no step
    succeeded and nothing was produced is FAILED (EMPTY_EXECUTION), never a
    clean scan (v8 NAS-incident lesson).
    """
    observations = step_runner.all_observations()  # type: ignore[attr-defined]
    findings = FindingCorrelation().correlate(observations)
    succeeded_steps = sum(
        1 for job in jobs.all() if job.status is JobStatus.SUCCEEDED
    )
    # v0.5.2 (v8): an execution where EVERY step failed and nothing was
    # produced is an EMPTY execution, not a clean scan. Mark FAILED so
    # coverage_rate=0.0 never masquerades as "target is clean" (the NAS
    # incident: 9 nuclei steps all failed to launch, the run still
    # completed). A plan where >=1 step succeeded with 0 findings stays
    # COMPLETED - that is a legitimately clean (or partial-coverage) scan.
    if not findings and succeeded_steps == 0:
        service.fail(assessment_id, "EMPTY_EXECUTION:no plan step succeeded, 0 findings")
        _audit_record(
            audit_repo, audit_chain, actor="system",
            action="assessment.completed.empty_execution",
            resource_type="assessment", resource_id=assessment_id,
            payload={
                "coverage_rate": 0.0,
                "reason": "zero successful plan steps, zero findings",
            },
            outbox=audit_outbox,
        )
        _logger.warning("assessment empty execution", assessment_id=assessment_id)
        return
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
                outbox=audit_outbox,
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
                outbox=audit_outbox,
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
            # v8 scenario #3: steps succeeded but produced zero observations
            # (e.g. every probe failed on a throttling ISP). This is
            # ambiguous with a clean target, so the assessment stays
            # COMPLETED - but the flag makes the anomaly queryable in the
            # audit log instead of being indistinguishable from "clean".
            "no_observations": True if not observations else None,
        },
        outbox=audit_outbox,
    )
    _logger.info(
        "assessment completed",
        assessment_id=assessment_id, findings=len(findings),
        coverage_rate=coverage_rate,
    )


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
    audit_outbox: object | None = None,
    oracle: OracleService | None = None,
    confirmed_finding_repo: object | None = None,
    jobs_store: JobStore | None = None,
    cancel_terminator: Callable[[str], int] | None = None,
) -> None:
    """Run one assessment to completion in a background thread.

    Constructs the Orchestrator with the injected ``step_runner_factory`` (so
    tests can inject a fake; production wires ``AdapterStepRunner`` over
    ``RealScanRunner``), dispatches the plan, runs to completion, correlates
    observations into findings (tagged with ``assessment_id``), and updates
    status. Any exception -> ``FAILED`` with the reason audited.

    Control plane (M4): the Orchestrator's step gate reads the durable
    ``assessment.control`` signal at every step boundary. A pause request
    stops issuing work (status PAUSED, remaining jobs stay READY for a
    resume drain); a cancel request skips the remaining jobs and calls
    ``cancel_terminator(assessment_id)`` when supplied (per-assessment
    container kill; None today - wiring is deployment-level). The job
    resolution is observed through ``jobs_store`` when provided (the
    SQLAlchemy-backed store over ``core_jobs``), else in-memory.

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
                outbox=audit_outbox,
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
            assessment_id, service, audit_repo, audit_outbox,
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
            outbox=audit_outbox,
        )
        _logger.info("assessment started", assessment_id=assessment_id)

        if not _check_plan_scope(
            scope_enforcer, egress_guard, plan, scope, permit_valid, audit_chain,
            assessment_id, service, audit_repo, audit_outbox,
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
                # v8 §3.1: a hardening-feature downgrade must be audited, not
                # silent - the app-layer EgressGuard cannot block a container on
                # the bridge network, so losing nftables is a real egress-isolation
                # regression the operator needs to see in the audit log.
                _audit_record(
                    audit_repo, audit_chain, actor="system",
                    action="egress.hardening_unavailable",
                    resource_type="assessment", resource_id=assessment_id,
                    payload={"reason": str(exc)},
                    outbox=audit_outbox,
                )

        # v0.3.0 T3: release the WAL write lock before the long scan phase -
        # everything up to here (RUNNING + permit + scope audits) is durable.
        _phase_commit(audit_repo)

        step_runner = step_runner_factory(scope)
        jobs = JobService(jobs_store) if jobs_store is not None else JobService()
        orchestrator = Orchestrator(
            jobs, step_runner, max_workers=max_workers,
            step_gate=_make_control_gate(assessment_repo, assessment_id),
        )
        orchestrator.dispatch(plan)
        run_status = orchestrator.run_to_completion(owner="system", now=utc_now())
        if run_status == "cancelled":
            _handle_cancelled(
                assessment_id=assessment_id, jobs=jobs,
                audit_repo=audit_repo, audit_chain=audit_chain,
                audit_outbox=audit_outbox, cancel_terminator=cancel_terminator,
            )
            return  # status is already CANCELLED (the service wrote it)
        if run_status == "paused":
            _audit_record(
                audit_repo, audit_chain, actor="system",
                action="assessment.paused",
                resource_type="assessment", resource_id=assessment_id,
                payload={"actual": True},
                outbox=audit_outbox,
            )
            _logger.info(
                "assessment paused at step boundary", assessment_id=assessment_id
            )
            return  # status is already PAUSED; jobs stay READY for resume

        _finalize_execution(
            assessment_id=assessment_id, step_runner=step_runner, jobs=jobs,
            service=service, finding_repo=finding_repo, audit_repo=audit_repo,
            audit_chain=audit_chain, audit_outbox=audit_outbox,
            catalog=catalog, asset_types=asset_types,
            oracle=oracle, confirmed_finding_repo=confirmed_finding_repo,
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
            outbox=audit_outbox,
        )
    finally:
        # Flush the nft allow/block sets so the next assessment starts clean
        # (W2-B). Best-effort: revoke must never mask a real failure.
        if nft_applied and nft_scope_enforcer is not None:
            with contextlib.suppress(Exception):
                nft_scope_enforcer.revoke()


def resume_assessment(
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
    audit_chain: AuditChain | None = None,
    audit_outbox: object | None = None,
    oracle: OracleService | None = None,
    confirmed_finding_repo: object | None = None,
    jobs_store: JobStore | None = None,
    cancel_terminator: Callable[[str], int] | None = None,
) -> None:
    """Resume a PAUSED assessment: light drain of the remaining jobs.

    The heavy start path (permit re-issue, nft re-apply, assessment.started
    audit) is NOT repeated - the resume is a continuation of the original
    execution. ``dispatch`` is idempotent (core_jobs idempotency_key), so
    re-dispatching the plan only re-uses existing jobs and the drain executes
    exactly the remaining READY ones. The assessment status was already set to
    RUNNING by ``AssessmentService.resume`` (same transaction as the
    RESUME_REQUESTED signal the drain consumes first). Runs from an executor
    thread (the caller schedules it like the initial daemon).
    """
    service = AssessmentService(assessment_repo)
    assessment = assessment_repo.get(assessment_id)
    assert assessment is not None and assessment.active_plan_id is not None
    plan = assessment_repo.get_plan(assessment.active_plan_id)
    assert plan is not None
    scope = scope_repo.get_snapshot(assessment.scope_snapshot_id)
    assert scope is not None

    step_runner = step_runner_factory(scope)
    jobs = JobService(jobs_store) if jobs_store is not None else JobService()
    orchestrator = Orchestrator(
        jobs, step_runner, max_workers=max_workers,
        step_gate=_make_control_gate(assessment_repo, assessment_id),
    )
    orchestrator.dispatch(plan)  # idempotent: existing jobs are re-used
    run_status = orchestrator.run_to_completion(owner="system", now=utc_now())
    if run_status == "cancelled":
        _handle_cancelled(
            assessment_id=assessment_id, jobs=jobs,
            audit_repo=audit_repo, audit_chain=audit_chain,
            audit_outbox=audit_outbox, cancel_terminator=cancel_terminator,
        )
        return
    if run_status == "paused":
        _audit_record(
            audit_repo, audit_chain, actor="system",
            action="assessment.paused",
            resource_type="assessment", resource_id=assessment_id,
            payload={"actual": True},
            outbox=audit_outbox,
        )
        return
    _audit_record(
        audit_repo, audit_chain, actor="system", action="assessment.resumed",
        resource_type="assessment", resource_id=assessment_id,
        payload={"actual": True},
        outbox=audit_outbox,
    )
    _finalize_execution(
        assessment_id=assessment_id, step_runner=step_runner, jobs=jobs,
        service=service, finding_repo=finding_repo, audit_repo=audit_repo,
        audit_chain=audit_chain, audit_outbox=audit_outbox,
        catalog=catalog, asset_types=asset_types,
        oracle=oracle, confirmed_finding_repo=confirmed_finding_repo,
    )
