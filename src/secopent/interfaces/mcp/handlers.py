# src/secopent/interfaces/mcp/handlers.py
"""MCP tool handlers bound to Application Services + SqlAlchemy repositories.

Each handler mirrors the corresponding FastAPI router's body (the router is the
transport-agnostic reference implementation): open a short-lived session from
``McpRuntime.db``, build repo/service, call, return a JSON-able dict. Mutating
actions record on the signed ``AuditChain`` inside the same transaction - never
the plain ``AuditService`` (security-relevant events must be signed).

Safety invariants (M4 §13 / ADR-007):

- ``plan_approve`` / ``assessment_start`` run with ``actor_role="agent"`` and
  translate ``AssessmentPermissionError`` into a structured ``HUMAN_REQUIRED``
  result: the agent learns a human must act and NEVER triggers a scan.
- ``assessment_pause`` / ``resume`` / ``cancel`` are real control-plane moves
  (M4): the durable control signal is consumed by the executor at step
  boundaries, so a pause stops issuing new work (a step already executing
  finishes first), resume re-drains the remaining READY jobs (idempotent over
  the durable core_jobs store), and cancel abandons the remaining jobs. A
  cancel does NOT forcefully kill a container in every deployment: the
  per-assessment container terminator is wired per deployment (the callers
  should state "jobs stopped at the next step; container kill best-effort").
- ``finding_validate`` is a read-only evidence/verdict check - the agent never
  sets a finding verdict (oracle/human only).
- ``report_render`` never LLM-polishes (``polish`` is forced False).
"""
from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

from sqlalchemy.orm import Session

from ...application.assessments import (
    AssessmentPermissionError,
    AssessmentService,
)
from ...application.audit import AuditService
from ...application.audit_chain import AuditChain
from ...application.planner import Planner
from ...application.projects import ProjectService
from ...application.report_renderer import ReportData, ReportRenderer
from ...application.scopes import ScopeService
from ...domain.assessments.models import Assessment
from ...domain.assets.graph import AssetGraph
from ...domain.common.canonical import utc_now
from ...domain.findings.models import Finding
from ...domain.intel.models import Vulnerability
from ...domain.policy.models import ExecutionMode, RiskClass
from ...domain.projects.models import Project
from ...domain.reports.models import Report
from ...domain.scope.models import ScopeSnapshot
from ...domain.verification.models import VerificationStatus
from ...infrastructure.db.session import Database
from ...infrastructure.evidence_store.redaction import RedactionEngine
from ...infrastructure.report_templates.renderer import Jinja2TemplateRenderer
from ...infrastructure.repositories.sqlalchemy_assets import SqlAlchemyAssetRepository
from ...infrastructure.repositories.sqlalchemy_catalog import SqlAlchemyCatalogRepository
from ...infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAssessmentRepository,
    SqlAlchemyAuditRepository,
    SqlAlchemyProjectRepository,
    SqlAlchemyScopeRepository,
)
from ...infrastructure.repositories.sqlalchemy_findings import SqlAlchemyFindingRepository
from ...infrastructure.repositories.sqlalchemy_intel import SqlAlchemyIntelRepository
from ...infrastructure.repositories.sqlalchemy_reports import SqlAlchemyReportRepository

_T = TypeVar("_T")


@dataclass(frozen=True, slots=True)
class McpRuntime:
    """Shared singletons an MCP tool handler needs (mirrors app.state)."""

    db: Database
    audit_chain: AuditChain
    scope_enforcer: object | None = None
    resume_scheduler: Callable[[str], None] | None = None
    start_scheduler: Callable[[str], None] | None = None


def _audit(
    runtime: McpRuntime,
    *,
    session: Session,
    actor: str,
    action: str,
    resource_type: str,
    resource_id: str,
    payload: dict[str, object],
) -> None:
    """Record a signed audit event in the caller's transaction."""
    runtime.audit_chain.record(
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        payload=payload,
        session=session,
    )


def _human_required(action: str, assessment_id: str, message: str) -> dict[str, object]:
    return {
        "status": "HUMAN_REQUIRED",
        "action": action,
        "assessment_id": assessment_id,
        "message": message,
        "next_step": "a human must approve/start this assessment via the SecOpent UI",
    }


def _error(code: str, message: str, **extra: object) -> dict[str, object]:
    return {"status": "error", "code": code, "message": message, **extra}


def _guard(action: str, fn: Callable[[], _T]) -> dict[str, object]:
    """Translate service errors into structured results (never a bare raise).

    The registry's framework-free handlers may still raise, but the FastMCP
    transport layer wraps every registered tool with this guard so the agent
    always sees a structured dict: HUMAN_REQUIRED for the human boundary,
    NOT_FOUND for missing resources, INVALID_STATE for illegal transitions,
    INVALID_ARGUMENT for bad tool arguments.
    """
    try:
        return fn()  # type: ignore[return-value]
    except AssessmentPermissionError as exc:
        return _human_required(action, "", str(exc))
    except LookupError as exc:
        return _error("NOT_FOUND", str(exc))
    except ValueError as exc:
        return _error("INVALID_ARGUMENT", str(exc))
    except Exception as exc:  # noqa: BLE001 - structured result, never a crash
        return _error("INTERNAL", str(exc))


# --- serialization helpers (mirror the API routers' _to_out) ---------------


def _project_out(project: Project) -> dict[str, object]:
    return {
        "id": project.id,
        "name": project.name,
        "status": project.status.value,
        "created_at": project.created_at.isoformat(),
    }


def _scope_out(snapshot: ScopeSnapshot) -> dict[str, object]:
    return {
        "id": snapshot.id,
        "project_id": snapshot.project_id,
        "include": list(snapshot.include),
        "exclude": list(snapshot.exclude),
        "ports": list(snapshot.ports),
        "cloud_accounts": list(snapshot.cloud_accounts),
        "limits": {
            "requests_per_second": snapshot.limits.requests_per_second,
            "concurrency": snapshot.limits.concurrency,
            "max_requests": snapshot.limits.max_requests,
        },
        "approved_by": snapshot.approved_by,
        "approved_at": snapshot.approved_at.isoformat(),
        "digest": snapshot.digest,
    }


def _assessment_out(assessment) -> dict[str, object]:  # type: ignore[no-untyped-def]
    return {
        "id": assessment.id,
        "project_id": assessment.project_id,
        "scope_snapshot_id": assessment.scope_snapshot_id,
        "mode": assessment.mode.value,
        "status": assessment.status.value,
        "control": assessment.control.value,
        "active_plan_id": assessment.active_plan_id,
        "approval_id": assessment.approval_id,
    }


def _plan_out(plan) -> dict[str, object]:  # type: ignore[no-untyped-def]
    return {
        "id": plan.id,
        "assessment_id": plan.assessment_id,
        "version": plan.version,
        "digest": plan.digest,
        "steps": [
            {
                "key": s.key,
                "runner": s.runner,
                "risk": s.risk.value,
                "parameters": s.parameters,
                "dependencies": list(s.dependencies),
            }
            for s in plan.steps
        ],
    }


def _finding_out(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.id,
        "fingerprint": finding.fingerprint,
        "title": finding.title,
        "asset": finding.asset,
        "severity": finding.severity.value,
        "cwe": list(finding.cwe),
        "cve": list(finding.cve),
        "owasp": list(finding.owasp),
        "status": finding.status.value,
        "assessment_id": finding.assessment_id,
        "oracle_verdict": finding.oracle_verdict.value,
    }


def _vuln_out(vuln: Vulnerability) -> dict[str, object]:
    signal = vuln.exploitation_signal
    return {
        "canonical_id": vuln.canonical_id,
        "aliases": list(vuln.aliases),
        "description": vuln.description,
        "cvss": {source: score for source, (score, _prov) in vuln.cvss.items()},
        "cwe": list(vuln.cwe),
        "references": list(vuln.references),
        "published_at": vuln.published_at.isoformat() if vuln.published_at else None,
        "affected_products": [
            {
                "vendor": p.vendor,
                "product": p.product,
                "cpe": p.cpe,
                "package": p.package,
                "version_range": p.version_range,
                "fixed_versions": list(p.fixed_versions),
            }
            for p in vuln.affected_products
        ],
        "exploitation_signal": {
            "kev": signal.kev,
            "epss_score": signal.epss_score,
            "public_exploit": signal.public_exploit,
            "ransomware": signal.ransomware,
            "active_exploitation": signal.active_exploitation,
        },
        "digest": vuln.digest,
    }


def _report_out(report: Report) -> dict[str, object]:
    return {
        "id": report.id,
        "assessment_id": report.assessment_id,
        "title": report.title,
        "sections": [{"name": s.name, "content": s.content} for s in report.sections],
        "finding_count": report.finding_count,
        "coverage_rate": report.coverage_rate,
        "completeness_ok": report.completeness_ok,
        "status": report.status.value,
        "digest": report.digest,
    }


def _asset_graph_out(graph: AssetGraph) -> dict[str, object]:
    return {
        "nodes": [{"type": n.type.value, "value": n.value} for n in graph.nodes],
        "edges": [
            {
                "src": {"type": e.src.type.value, "value": e.src.value},
                "dst": {"type": e.dst.type.value, "value": e.dst.value},
                "rel": e.rel.value,
            }
            for e in graph.edges
        ],
    }


def _coverage_from_audit(
    runtime: McpRuntime, session: Session, assessment_id: str
) -> tuple[float, tuple[str, ...]]:
    """Read the coverage rate the execution layer recorded (mirror reports.py)."""
    events = SqlAlchemyAuditRepository(session).list_events()
    for event in reversed(events):
        if (
            event.action == "assessment.completed"
            and event.resource_id == assessment_id
            and "coverage_rate" in event.payload
        ):
            rate_raw = event.payload.get("coverage_rate", 0.0)
            uncovered_raw = event.payload.get("uncovered_classes", ())
            rate = float(rate_raw) if isinstance(rate_raw, int | float) else 0.0
            uncovered: tuple[str, ...] = (
                tuple(uncovered_raw) if isinstance(uncovered_raw, list | tuple) else ()
            )
            return rate, uncovered
    return 0.0, ()


# --- tools (the 17 STANDARD_ORCHESTRATION_TOOLS) ---------------------------


def handler_project_create(
    runtime: McpRuntime, *, name: str
) -> dict[str, object]:
    """Create a project (agent-callable: proposal, no approval needed)."""
    with runtime.db.unit_of_work() as uow:
        session = uow.session
        return _guard(
            "project_create",
            lambda: _project_out(
                ProjectService(SqlAlchemyProjectRepository(session)).create(name=name)
            ),
        )


def _scope_validate_result(runtime: McpRuntime, *, include: list[str],
                           exclude: list[str], ports: list[int],
                           cloud_accounts: list[str]) -> dict[str, object]:
    with runtime.db.unit_of_work() as uow:
        session = uow.session
        service = ScopeService(
            SqlAlchemyScopeRepository(session),
            AuditService(SqlAlchemyAuditRepository(session)),
        )
        result = service.validate(
            include=tuple(include),
            exclude=tuple(exclude),
            ports=tuple(ports),
            cloud_accounts=tuple(cloud_accounts),
        )
        return {
            "status": "ok" if result.ok else "invalid",
            "include": list(result.include),
            "exclude": list(result.exclude),
            "ports": list(result.ports),
            "cloud_accounts": list(result.cloud_accounts),
            "errors": [
                {"field": field, "index": index, "raw": raw, "error": error}
                for field, index, raw, error in result.errors
            ],
        }


def handler_scope_draft(
    runtime: McpRuntime,
    *,
    include: list[str],
    exclude: list[str] | None = None,
    ports: list[int] | None = None,
    cloud_accounts: list[str] | None = None,
) -> dict[str, object]:
    """Draft preview: normalize a scope WITHOUT persisting (no DB write)."""
    return _scope_validate_result(
        runtime,
        include=include,
        exclude=exclude or [],
        ports=ports or [443],
        cloud_accounts=cloud_accounts or [],
    )


def handler_scope_validate(
    runtime: McpRuntime,
    *,
    include: list[str],
    exclude: list[str] | None = None,
    ports: list[int] | None = None,
    cloud_accounts: list[str] | None = None,
) -> dict[str, object]:
    """Validate a scope draft: per-target normalization errors, no persistence."""
    return _scope_validate_result(
        runtime,
        include=include,
        exclude=exclude or [],
        ports=ports or [443],
        cloud_accounts=cloud_accounts or [],
    )


def handler_scope_freeze(
    runtime: McpRuntime,
    *,
    project_id: str,
    include: list[str],
    exclude: list[str] | None = None,
    ports: list[int] | None = None,
    approved_by: str,
    requests_per_second: float = 5.0,
    concurrency: int = 3,
    max_requests: int = 50_000,
    cloud_accounts: list[str] | None = None,
) -> dict[str, object]:
    """Freeze a scope snapshot (persists; records scope.frozen on the signed chain)."""
    with runtime.db.unit_of_work() as uow:
        session = uow.session
        def _freeze() -> dict[str, object]:
            service = ScopeService(
                SqlAlchemyScopeRepository(session),
                AuditService(SqlAlchemyAuditRepository(session)),
            )
            snapshot = service.freeze(
                project_id=project_id,
                include=tuple(include),
                exclude=tuple(exclude or []),
                ports=tuple(ports or [443]),
                approved_by=approved_by,
                requests_per_second=requests_per_second,
                concurrency=concurrency,
                max_requests=max_requests,
                cloud_accounts=tuple(cloud_accounts or []),
            )
            _audit(
                runtime,
                session=session,
                actor=approved_by,
                action="scope.frozen",
                resource_type="scope_snapshot",
                resource_id=snapshot.id,
                payload={"project_id": project_id, "digest": snapshot.digest},
            )
            return _scope_out(snapshot)

        return _guard("scope_freeze", _freeze)


def handler_assessment_create(
    runtime: McpRuntime, *, project_id: str, scope_snapshot_id: str,
    mode: str = "approval",
) -> dict[str, object]:
    """Create a draft assessment (agent-callable: proposal, no approval needed).

    The assessment enters DRAFT; a plan must be generated and a HUMAN must
    approve before any execution may start.
    """
    with runtime.db.unit_of_work() as uow:
        session = uow.session
        return _guard(
            "assessment_create",
            lambda: _assessment_out(
                AssessmentService(SqlAlchemyAssessmentRepository(session)).create(
                    project_id=project_id,
                    scope_snapshot_id=scope_snapshot_id,
                    mode=ExecutionMode(mode),
                )
            ),
        )


def handler_plan_generate(
    runtime: McpRuntime, *, assessment_id: str, catalog_version: str | None = None
) -> dict[str, object]:
    """Deterministic plan generation (catalog + scope, never the LLM)."""
    with runtime.db.unit_of_work() as uow:
        session = uow.session
        def _generate() -> dict[str, object]:
            assessment_repo = SqlAlchemyAssessmentRepository(session)
            assessment = assessment_repo.get(assessment_id)
            if assessment is None:
                raise LookupError(f"assessment {assessment_id} not found")
            snapshot = SqlAlchemyScopeRepository(session).get_snapshot(
                assessment.scope_snapshot_id
            )
            if snapshot is None:
                raise LookupError("scope snapshot not found")
            catalog_repo = SqlAlchemyCatalogRepository(session)
            catalog = (
                catalog_repo.get_catalog_by_version(catalog_version)
                if catalog_version
                else catalog_repo.latest_catalog()
            )
            if catalog is None:
                raise ValueError("no test catalog available")
            from ..api.routers.assessments import _classify_asset_types

            asset_types = _classify_asset_types(snapshot)
            plan = Planner(catalog).generate(
                plan_id=f"plan-{uuid.uuid4().hex[:12]}",
                assessment_id=assessment_id,
                asset_types=asset_types,
            )
            if not plan.steps:
                raise ValueError("no required test classes for the scope's asset types")
            service = AssessmentService(assessment_repo)
            updated = service.attach_plan(assessment_id, plan.steps)
            created = assessment_repo.get_plan(updated.active_plan_id or "")
            if created is None:  # pragma: no cover - attach_plan always sets it
                raise RuntimeError("plan was not persisted")
            return _plan_out(created)

        return _guard("plan_generate", _generate)


def _scope_digest(asm_repo: object, scope_repo: object, assessment_id: str) -> str:
    """Resolve the assessment's scope digest (approve pins it in the Approval).

    Mirrors interfaces/api/routers/approvals.py: it looks up the snapshot from
    the scope repo and passes its digest. The agent path MUST pin the real
    digest too - the Approval binds plan + scope digests so the approved
    execution is exactly what was reviewed.
    """
    assessment = asm_repo.get(assessment_id)  # type: ignore[attr-defined]
    snapshot = (
        scope_repo.get_snapshot(assessment.scope_snapshot_id)  # type: ignore[attr-defined]
        if assessment is not None
        else None
    )
    if assessment is None or snapshot is None:
        raise LookupError(f"assessment {assessment_id} or its scope not found")
    digest = snapshot.digest
    if not isinstance(digest, str):  # pragma: no cover - schema guarantees str
        raise LookupError(f"assessment {assessment_id} scope digest invalid")
    return digest


def _approve_via_grant(
    service: AssessmentService,
    asm_repo: object,
    assessment_id: str,
    *,
    approved_risks: list[str] | None,
    approved_capabilities: list[str] | None,
    grant_id: str,
    scope_repo: object,
) -> dict[str, object]:
    """Approve then respond with the assessment (approve returns an Approval;
    the agent-facing shape is the refreshed assessment)."""
    service.approve(
        assessment_id=assessment_id,
        approved_by="agent",  # overridden to grant:<id>
        approved_risks=frozenset(RiskClass(r) for r in (approved_risks or [])),
        approved_capabilities=frozenset(approved_capabilities or []),
        scope_digest=_scope_digest(asm_repo, scope_repo, assessment_id),
        actor_role="agent",
        grant_id=grant_id,
    )
    refreshed = asm_repo.get(assessment_id)  # type: ignore[attr-defined]
    if refreshed is None:  # pragma: no cover - just persisted
        raise LookupError(f"assessment {assessment_id} vanished after approval")
    return _assessment_out(refreshed)


def handler_plan_approve(
    runtime: McpRuntime,
    *,
    assessment_id: str,
    approved_risks: list[str] | None = None,
    approved_capabilities: list[str] | None = None,
    grant_id: str | None = None,
) -> dict[str, object]:
    """Approve a plan. A human approves directly; an agent needs a grant.

    Without a grant the agent receives structured HUMAN_REQUIRED (unchanged);
    with a grant the approval is authorized against the grant's scope+risk
    boundary and recorded as ``grant:<id>`` (v0.6.0).
    """
    if not grant_id:
        return _human_required(
            "plan_approve",
            assessment_id,
            "agents need a grant to approve (see grant_list)",
        )
    from secopent.application.grants import GrantService
    from secopent.infrastructure.repositories.sqlalchemy_core import (
        SqlAlchemyAssessmentRepository,
        SqlAlchemyScopeRepository,
    )
    from secopent.infrastructure.repositories.sqlalchemy_grants import (
        SqlAlchemyGrantRepository,
    )

    with runtime.db.unit_of_work() as uow:
        session = uow.session
        asm_repo = SqlAlchemyAssessmentRepository(session)
        scope_repo = SqlAlchemyScopeRepository(session)
        service = AssessmentService(
            asm_repo,
            scope_repo=scope_repo,
            grant_service=GrantService(SqlAlchemyGrantRepository(session)),
        )
        return _guard(
            "plan_approve",
            lambda: _approve_via_grant(
                service, asm_repo, assessment_id,
                approved_risks=approved_risks,
                approved_capabilities=approved_capabilities,
                grant_id=grant_id,
                scope_repo=scope_repo,
            ),
        )


def handler_assessment_start(
    runtime: McpRuntime, *, assessment_id: str, grant_id: str | None = None
) -> dict[str, object]:
    """Start an assessment. A human starts directly; an agent needs a grant.

    Starting triggers real scanning - the grant must still authorize at start
    time (a revoked/expired grant cannot start). Without a grant the agent
    receives structured HUMAN_REQUIRED (unchanged).
    """
    if not grant_id:
        return _human_required(
            "assessment_start",
            assessment_id,
            "agents need a grant to start (see grant_list)",
        )
    from secopent.application.grants import GrantService
    from secopent.infrastructure.repositories.sqlalchemy_core import (
        SqlAlchemyAssessmentRepository,
        SqlAlchemyScopeRepository,
    )
    from secopent.infrastructure.repositories.sqlalchemy_grants import (
        SqlAlchemyGrantRepository,
    )

    with runtime.db.unit_of_work() as uow:
        session = uow.session
        service = AssessmentService(
            SqlAlchemyAssessmentRepository(session),
            scope_repo=SqlAlchemyScopeRepository(session),
            grant_service=GrantService(SqlAlchemyGrantRepository(session)),
        )
        result = _guard(
            "assessment_start",
            lambda: (
                _assessment_out(
                    service.start(assessment_id, actor_role="agent",
                                  grant_id=grant_id)
                )
            ),
        )
        if result.get("status") == "success":
            scheduler = runtime.start_scheduler
            if scheduler is not None:
                # A started assessment must actually run, not stall in QUEUED
                # (the v0.4.0 incident shape). Spawn the executor thread like
                # the API /start background task (mirrors handler_assessment_resume).
                import threading

                threading.Thread(
                    target=scheduler, args=(assessment_id,), daemon=True,
                    name=f"mcp-start-{assessment_id}",
                ).start()
        return result


def handler_grant_list(
    runtime: McpRuntime, *, project_id: str
) -> dict[str, object]:
    """List ACTIVE grants for a project (agent discovers what it may run).

    Read-only: exposes the grant's boundary (targets, risk caps, window end)
    so an agent can decide whether to propose an assessment under a grant -
    it never exposes the grant lifecycle controls, which are human-only.
    """
    from secopent.application.grants import GrantService
    from secopent.infrastructure.repositories.sqlalchemy_grants import (
        SqlAlchemyGrantRepository,
    )

    with runtime.db.unit_of_work() as uow:
        session = uow.session
        service = GrantService(SqlAlchemyGrantRepository(session))
        grants = service.list_active(project_id, now=utc_now())
        return {
            "status": "success",
            "project_id": project_id,
            "grants": [
                {
                    "id": g.id,
                    "name": g.name,
                    "scope_include": list(g.scope.include),
                    "risk_caps": sorted(r.value for r in g.risk_caps),
                    "valid_to": g.valid_to.isoformat(),
                }
                for g in grants
            ],
        }


def _assessment_control(
    runtime: McpRuntime,
    *,
    assessment_id: str,
    action: str,
    service_call: Callable[[AssessmentService], Assessment],
) -> dict[str, object]:
    with runtime.db.unit_of_work() as uow:
        session = uow.session
        def _run() -> dict[str, object]:
            service = AssessmentService(SqlAlchemyAssessmentRepository(session))
            updated = service_call(service)
            _audit(
                runtime,
                session=session,
                actor="agent",
                action=f"assessment.{action}",
                resource_type="assessment",
                resource_id=updated.id,
                payload={
                    "assessment_id": assessment_id,
                    "status": updated.status.value,
                },
            )
            return _assessment_out(updated)

        return _guard(f"assessment_{action}", _run)


def handler_assessment_status(
    runtime: McpRuntime, *, assessment_id: str
) -> dict[str, object]:
    """Read-only status probe for an assessment."""
    with runtime.db.unit_of_work() as uow:
        session = uow.session
        return _guard(
            "assessment_status",
            lambda: _assessment_out(
                AssessmentService(SqlAlchemyAssessmentRepository(session)).status(
                    assessment_id
                )
            ),
        )


def handler_assessment_pause(
    runtime: McpRuntime, *, assessment_id: str
) -> dict[str, object]:
    """Pause a RUNNING assessment: the executor stops at the next step
    boundary (a step already executing completes first; remaining jobs stay
    READY for a resume). Returns the updated status + control signal."""
    return _assessment_control(
        runtime,
        assessment_id=assessment_id,
        action="pause",
        service_call=lambda s: s.pause(assessment_id),
    )


def handler_assessment_resume(
    runtime: McpRuntime, *, assessment_id: str
) -> dict[str, object]:
    """Resume a PAUSED assessment: restarts the drain of remaining jobs
    (durable core_jobs makes re-dispatch idempotent - only READY jobs run)."""
    with runtime.db.unit_of_work() as uow:
        session = uow.session
        def _run() -> dict[str, object]:
            service = AssessmentService(SqlAlchemyAssessmentRepository(session))
            updated = service.resume(assessment_id)
            _audit(
                runtime,
                session=session,
                actor="agent",
                action="assessment.resumed",
                resource_type="assessment",
                resource_id=updated.id,
                payload={"assessment_id": assessment_id, "status": updated.status.value},
            )
            scheduler = runtime.resume_scheduler
            if scheduler is not None:
                # Outside the request context: spawn the drain thread ourselves
                # (mirrors the FastAPI /resume background task).
                import threading

                threading.Thread(
                    target=scheduler, args=(assessment_id,), daemon=True,
                    name=f"mcp-resume-{assessment_id}",
                ).start()
            return _assessment_out(updated)

        return _guard("assessment_resume", _run)


def handler_assessment_cancel(
    runtime: McpRuntime, *, assessment_id: str
) -> dict[str, object]:
    """Cancel a QUEUED/RUNNING/PAUSED assessment (terminal): remaining jobs
    are abandoned (SKIPPED) and new work stops at the next step boundary.
    Container termination is best-effort (deployment-wired terminator)."""
    return _assessment_control(
        runtime,
        assessment_id=assessment_id,
        action="cancel",
        service_call=lambda s: s.cancel(assessment_id),
    )


def handler_asset_list(runtime: McpRuntime) -> dict[str, object]:
    """Read-only: the discovered asset graph (nodes + directed edges)."""
    with runtime.db.unit_of_work() as uow:
        session = uow.session
        return _guard(
            "asset_list",
            lambda: _asset_graph_out(SqlAlchemyAssetRepository(session).load_graph()),
        )


def handler_finding_list(
    runtime: McpRuntime,
    *,
    assessment_id: str | None = None,
    severity: str | None = None,
    oracle_verdict: str | None = None,
) -> dict[str, object]:
    """Read-only: list findings, optionally filtered."""
    with runtime.db.unit_of_work() as uow:
        session = uow.session
        return _guard(
            "finding_list",
            lambda: {
                "findings": [
                    _finding_out(f)
                    for f in SqlAlchemyFindingRepository(session).all(
                        assessment_id=assessment_id,
                        severity=severity,
                        oracle_verdict=oracle_verdict,
                    )
                ]
            },
        )


def handler_finding_validate(
    runtime: McpRuntime, *, finding_id: str
) -> dict[str, object]:
    """Read-only evidence/verdict check (the agent never SETS a verdict).

    A finding counts as validated only when the deterministic oracle has
    CONFIRMED it (N/N reproduction) AND evidence is attached.
    """
    with runtime.db.unit_of_work() as uow:
        session = uow.session
        finding = SqlAlchemyFindingRepository(session).get(finding_id)
        if finding is None:
            return _error("NOT_FOUND", f"finding {finding_id} not found",
                          finding_id=finding_id)
        confirmed = (
            finding.oracle_verdict is VerificationStatus.CONFIRMED
            and bool(finding.evidence_ids)
        )
        return {
            "status": "validated" if confirmed else "not_validated",
            "finding": _finding_out(finding),
            "evidence_ids": list(finding.evidence_ids),
            "validated": confirmed,
            "reason": (
                "oracle confirmed (N/N reproduction) with evidence attached"
                if confirmed
                else "not confirmed: needs oracle N/N reproduction or human "
                "evidence review (agent may not set verdicts)"
            ),
        }


def handler_intel_search(
    runtime: McpRuntime,
    *,
    keyword: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
) -> dict[str, object]:
    """Read-only: FTS vulnerability search (keyword / CVE / CWE)."""
    with runtime.db.unit_of_work() as uow:
        session = uow.session
        return _guard(
            "intel_search",
            lambda: {
                "results": [
                    _vuln_out(v)
                    for v in SqlAlchemyIntelRepository(session).search_fts(
                        keyword=keyword, cve=cve, cwe=cwe
                    )
                ]
            },
        )


def handler_report_render(
    runtime: McpRuntime,
    *,
    assessment_id: str,
    title: str = "Assessment report",
) -> dict[str, object]:
    """Render + persist a data-driven report (deterministic; never LLM-polished)."""
    with runtime.db.unit_of_work() as uow:
        session = uow.session
        def _render() -> dict[str, object]:
            assessment_repo = SqlAlchemyAssessmentRepository(session)
            assessment = assessment_repo.get(assessment_id)
            if assessment is None:
                raise LookupError(f"assessment {assessment_id} not found")
            findings = SqlAlchemyFindingRepository(session).all(
                assessment_id=assessment_id
            )
            snapshot = SqlAlchemyScopeRepository(session).get_snapshot(
                assessment.scope_snapshot_id
            )
            scope_summary = (
                "In scope: " + ", ".join(snapshot.include) if snapshot else "n/a"
            )
            coverage_rate, uncovered_classes = _coverage_from_audit(
                runtime, session, assessment_id
            )
            data = ReportData(
                assessment_id=assessment_id,
                title=title,
                scope_summary=scope_summary,
                method="Catalog-driven authorized assessment with oracle N/N verification.",
                findings=tuple(findings),
                coverage_rate=coverage_rate,
                uncovered_classes=uncovered_classes,
                evidence_digests=tuple(eid for f in findings for eid in f.evidence_ids),
                assets=tuple(sorted({f.asset for f in findings})),
            )
            renderer = ReportRenderer(Jinja2TemplateRenderer(), RedactionEngine())
            report = renderer.render(
                data, report_id=f"rep-{uuid.uuid4().hex[:12]}"
            )
            SqlAlchemyReportRepository(session).add(report)
            return _report_out(report)

        return _guard("report_render", _render)


# Registry of every standard orchestration tool -> its handler (used by
# build_default_registry when a runtime is wired).
TOOL_HANDLERS: dict[str, Callable[..., object]] = {
    "project_create": handler_project_create,
    "scope_draft": handler_scope_draft,
    "scope_validate": handler_scope_validate,
    "scope_freeze": handler_scope_freeze,
    "assessment_create": handler_assessment_create,
    "plan_generate": handler_plan_generate,
    "plan_approve": handler_plan_approve,
    "assessment_start": handler_assessment_start,
    "grant_list": handler_grant_list,
    "assessment_pause": handler_assessment_pause,
    "assessment_resume": handler_assessment_resume,
    "assessment_cancel": handler_assessment_cancel,
    "assessment_status": handler_assessment_status,
    "asset_list": handler_asset_list,
    "finding_list": handler_finding_list,
    "finding_validate": handler_finding_validate,
    "intel_search": handler_intel_search,
    "report_render": handler_report_render,
}