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
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from typing import TypeVar

from sqlalchemy.orm import Session

from ...application.assessments import (
    AssessmentPermissionError,
    AssessmentService,
)
from ...application.audit import AuditService
from ...application.audit_chain import AuditChain
from ...application.planner import Planner
from ...application.ports.loop_approval import ApprovalRejected
from ...application.ports.loop_state import LoopStateRepository
from ...application.ports.loop_step import LoopStepRepository
from ...application.projects import ProjectService
from ...application.reasoning_loop.audit import (
    LOOP_CREATED,
    LOOP_RESOURCE_TYPE,
    LOOP_TERMINATED,
)
from ...application.reasoning_loop.pause_control import PauseControlService
from ...application.report_renderer import ReportData, ReportRenderer
from ...application.scopes import ScopeService
from ...domain.assessments.models import Assessment
from ...domain.assets.graph import AssetGraph
from ...domain.catalog.models import AssetType
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
from ...infrastructure.reasoning_loop.sqlalchemy_state import (
    SqlAlchemyLoopStateRepository,
    SqlAlchemyLoopStepRepository,
)
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
    llm_backend: object | None = None
    loop_control: PauseControlService | None = None
    # ReasoningLoop state/step repos (v0.7.8 Task 4). ``loop_status``/``history``
    # read them; ``loop_create``/``stop`` write state. Wired to the same
    # in-memory stores the /loops control plane uses (see server.py), so the
    # agent and the human control surface observe the same loops.
    loop_state_repo: LoopStateRepository | None = None
    loop_step_repo: LoopStepRepository | None = None


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
    except ApprovalRejected as exc:
        # Loop pause/resume is human-only: the service rejects the agent, and
        # the agent must learn a human must act (structured, never a raw 403).
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


def handler_mission_create(
    runtime: McpRuntime,
    *,
    project_id: str,
    target: str,
    intent: str,
    grant_id: str,
    risk_cap: str | None = None,
) -> dict[str, object]:
    """Dispatch a high-level mission: the project decides what to run.

    One call completes the whole chain inside the caller's transaction:
    validate the grant covers the target -> create scope + assessment -> plan
    via the LLM planner (deterministic floor when no backend) -> approve via
    grant -> start via grant -> schedule the executor thread. The agent only
    declares WHAT (target + intent); HOW (which test classes) is decided here.
    """
    from ...application.grants import GrantService
    from ...application.llm_planner import LLMPlanner
    from ...domain.common.canonical import utc_now
    from ...domain.policy.models import RiskClass
    from ...domain.scope.models import ScopeDraft, ScopeLimits
    from ...infrastructure.repositories.sqlalchemy_core import (
        SqlAlchemyAssessmentRepository,
        SqlAlchemyScopeRepository,
    )
    from ...infrastructure.repositories.sqlalchemy_grants import (
        SqlAlchemyGrantRepository,
    )

    if risk_cap is not None:
        try:
            requested_cap = RiskClass(risk_cap)
        except ValueError:
            return _error("INVALID_ARGUMENT", f"invalid risk_cap: {risk_cap!r}")

    with runtime.db.unit_of_work() as uow:
        session = uow.session
        grants = GrantService(SqlAlchemyGrantRepository(session))
        grant = grants.get_active(grant_id, now=utc_now())
        if grant is None:
            return _error("GRANT_NOT_FOUND", f"grant {grant_id} is not active")
        if grant.project_id != project_id:
            return _error("GRANT_NOT_FOUND", "grant does not belong to this project")

        scope = ScopeDraft(
            project_id=project_id,
            include=(target,),
            exclude=(),
            ports=(80, 443),
            limits=ScopeLimits(5.0, 3, 50_000),
        ).freeze(snapshot_id=f"mscope-{uuid.uuid4().hex[:8]}",
                 approved_by=f"grant:{grant_id}")
        if not grant.covers_scope(scope):
            return _error(
                "GRANT_SCOPE_MISMATCH",
                f"target {target} not covered by grant {grant_id}",
            )
        # The mission's effective risk ceiling: the grant's MAX cap by default
        # (a broad grant may use its full authorized range), or the requested
        # cap which must NOT exceed the grant (the agent cannot escalate).
        grant_cap = max(grant.risk_caps, key=_risk_rank)
        if risk_cap is None:
            effective_cap = grant_cap
        else:
            if _risk_rank(requested_cap) > _risk_rank(grant_cap):
                return _error(
                    "GRANT_RISK_NOT_APPROVED",
                    f"risk_cap {risk_cap!r} exceeds grant caps "
                    f"({','.join(sorted(r.value for r in grant.risk_caps))})",
                )
            effective_cap = requested_cap

        scope_repo = SqlAlchemyScopeRepository(session)
        scope_repo.add_snapshot(scope)
        asm_repo = SqlAlchemyAssessmentRepository(session)
        service = AssessmentService(
            asm_repo,
            scope_repo=scope_repo,
            grant_service=grants,
        )
        assessment = service.create(
            project_id=project_id, scope_snapshot_id=scope.id,
            mode=ExecutionMode.APPROVAL,
        )

        catalog = SqlAlchemyCatalogRepository(session).latest_catalog()
        backend = runtime.llm_backend
        planner = LLMPlanner(backend=backend, catalog=catalog)  # type: ignore[arg-type]
        plan = planner.generate(
            plan_id=f"plan-{uuid.uuid4().hex[:12]}",
            assessment_id=assessment.id,
            asset_types=(_asset_type_for_target(target),),
            intent=intent,
            risk_cap=effective_cap,
        )
        service.attach_plan(assessment.id, steps=plan.steps)

        service.approve(
            assessment_id=assessment.id,
            approved_by="agent",  # overridden to grant:<id>
            approved_risks=frozenset(grant.risk_caps),
            approved_capabilities=frozenset(),
            scope_digest=scope.digest,
            actor_role="agent",
            grant_id=grant_id,
        )
        started = service.start(assessment.id, actor_role="agent", grant_id=grant_id)
        _audit(
            runtime,
            session=session,
            actor="agent",
            action="mission.created",
            resource_type="mission",
            resource_id=assessment.id,
            payload={
                "grant_id": grant_id, "target": target, "intent": intent,
                "plan_steps": len(plan.steps),
                "llm_backend": type(backend).__name__ if backend is not None else "none",
            },
        )
        result = _assessment_out(started)
        # result["status"] is the assessment status; add mission context
        result["assessment_id"] = assessment.id
        # The UoW's __exit__ commits on clean exit (v0.7.2: removed a manual
        # session.commit() here that defeated the UoW's rollback safety net —
        # a raise after this line would have rolled back an already-committed
        # transaction, silently masking the error).

    scheduler = runtime.start_scheduler
    if scheduler is not None:
        import threading

        threading.Thread(
            target=scheduler, args=(assessment.id,), daemon=True,
            name=f"mcp-mission-{assessment.id}",
        ).start()
    return result


def _asset_type_for_target(target: str) -> AssetType:
    """Sniff an asset type from a mission target (URL/IP/domain/cloud account)."""
    import ipaddress

    if target.startswith(("http://", "https://")):
        return AssetType.WEB_APP
    if ":" in target and "/" not in target:
        # host:port -> IP_PORT; provider:account -> CLOUD_ACCOUNT (no scheme)
        return AssetType.IP_PORT
    try:
        ipaddress.ip_network(target, strict=False)
        return AssetType.IP_PORT
    except ValueError:
        return AssetType.WEB_APP


# Risk ladder for effective-cap comparison (mission cannot exceed its grant).
_RISK_RANK: dict[RiskClass, int] = {
    RiskClass.PASSIVE: 0,
    RiskClass.LOW: 1,
    RiskClass.ACTIVE: 2,
    RiskClass.INTRUSIVE: 3,
    RiskClass.DESTRUCTIVE: 4,
}


def _risk_rank(risk: RiskClass) -> int:
    return _RISK_RANK[risk]


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


def handler_loop_pause(
    runtime: McpRuntime, *, loop_id: str, reason: str
) -> dict[str, object]:
    """Pause a ReasoningLoop.

    Loop pause/resume is a HUMAN action (spec §6.3): the caller here is the
    AGENT, so PauseControlService raises ApprovalRejected, which ``_guard``
    maps to structured HUMAN_REQUIRED - the loop is not controllable by the
    agent at the MCP layer.
    """
    from ...domain.reasoning_loop.models import LoopId

    def _run() -> dict[str, object]:
        service = runtime.loop_control
        if service is None:
            raise LookupError("loop control not configured")
        with _loop_write_ctx(runtime) as session:
            state = service.pause(
                loop_id=LoopId(loop_id),
                actor="agent",
                reason=reason,
                actor_role="agent",
                session=session,
            )
            return {
                "status": "ok",
                "loop_id": state.loop_id.value,
                "phase": state.phase.value,
            }

    return _guard("loop_pause", _run)


def handler_loop_resume(
    runtime: McpRuntime,
    *,
    loop_id: str,
    approved_by: str | None = None,
    signature: str | None = None,
) -> dict[str, object]:
    """Resume a paused ReasoningLoop.

    Human-only (spec §6.3): the agent caller is rejected by the service
    (ApprovalRejected) -> structured HUMAN_REQUIRED.
    """
    from ...domain.reasoning_loop.models import LoopId

    def _run() -> dict[str, object]:
        service = runtime.loop_control
        if service is None:
            raise LookupError("loop control not configured")
        with _loop_write_ctx(runtime) as session:
            state = service.resume(
                loop_id=LoopId(loop_id),
                actor="agent",
                actor_role="agent",
                approved_by=approved_by,
                signature=signature,
                session=session,
            )
            return {
                "status": "ok",
                "loop_id": state.loop_id.value,
                "phase": state.phase.value,
                "pause_attempts": state.pause_attempts,
            }

    return _guard("loop_resume", _run)


def _loop_repos(
    runtime: McpRuntime,
    *,
    session: Session | None = None,
) -> tuple[LoopStateRepository, LoopStepRepository]:
    """The loop state/step repos, or a loud config error when not wired.

    Write handlers pass a UoW ``session`` so a fresh ``SqlAlchemyLoop*Repository``
    is built on that session — the save then commits with the caller's
    transaction (v0.7.2 hotfix for issue v10: the pre-bound singleton repo
    only ``merge``-ed, never committed, so loop rows vanished on session close).

    Read-only handlers and InMemory tests omit ``session`` and use the repos
    wired onto the runtime (the in-memory singletons or a pre-bound SQL repo).
    """
    if session is not None:
        return (
            SqlAlchemyLoopStateRepository(session),
            SqlAlchemyLoopStepRepository(session),
        )
    state_repo = runtime.loop_state_repo
    step_repo = runtime.loop_step_repo
    if state_repo is None or step_repo is None:
        raise LookupError("loop repos not configured")
    return state_repo, step_repo


@contextmanager
def _loop_write_ctx(
    runtime: McpRuntime,
) -> Iterator[Session | None]:
    """Transaction context for a loop write handler.

    When ``runtime.db`` is a real Database AND the wired loop state repo is
    SQL-backed (production), yields a UoW session so the save + signed audit
    record commit atomically (v0.7.2 hotfix for issue v10). When the repo is
    InMemory (dev/test wiring), yields ``None`` so ``_loop_repos`` falls back
    to the pre-bound in-memory repos — in-memory saves need no commit.
    """
    from ...application.reasoning_loop.in_memory_state import (
        InMemoryLoopStateRepository,
    )

    state_repo = runtime.loop_state_repo
    if (
        isinstance(runtime.db, Database)
        and not isinstance(state_repo, InMemoryLoopStateRepository)
    ):
        with runtime.db.unit_of_work() as uow:
            yield uow.session
    else:
        yield None


def handler_loop_status(
    runtime: McpRuntime, *, loop_id: str
) -> dict[str, object]:
    """Read-only status probe for a ReasoningLoop (agent + human callable).

    Returns the loop's phase, executed step count, remaining budget snapshot
    and context hash. Unknown loop -> structured NOT_FOUND via ``_guard``.
    """
    from ...domain.reasoning_loop.models import LoopId

    def _run() -> dict[str, object]:
        state_repo, step_repo = _loop_repos(runtime)
        state = state_repo.get(LoopId(loop_id))
        if state is None:
            raise LookupError(f"loop {loop_id!r} not found")
        steps = step_repo.list_for_loop(state.loop_id)
        budget = state.budget.snapshot()
        return {
            "status": "success",
            "loop_id": state.loop_id.value,
            "assessment_id": state.assessment_id,
            "phase": state.phase.value,
            "step_count": len(steps),
            "budget_remaining": {
                "steps": budget.steps_remaining,
                "tokens": budget.tokens_remaining,
                "wall_seconds": budget.wall_seconds_remaining,
            },
            "context_hash": state.context_hash,
        }

    return _guard("loop_status", _run)


def handler_loop_history(
    runtime: McpRuntime, *, loop_id: str
) -> dict[str, object]:
    """Read-only step history for a ReasoningLoop (agent + human callable).

    Returns every recorded step (step_id / step_number / action_type /
    tool_or_case_id / oracle_progressed). Unknown loop -> NOT_FOUND.
    """
    from ...domain.reasoning_loop.models import LoopId

    def _run() -> dict[str, object]:
        state_repo, step_repo = _loop_repos(runtime)
        state = state_repo.get(LoopId(loop_id))
        if state is None:
            raise LookupError(f"loop {loop_id!r} not found")
        steps = step_repo.list_for_loop(state.loop_id)
        return {
            "status": "success",
            "loop_id": loop_id,
            "steps": [
                {
                    "step_id": step.step_id,
                    "step_number": step.step_number,
                    "action_type": step.proposed_action.action_type.value,
                    "tool_or_case_id": step.tool_or_case_id,
                    "oracle_progressed": step.oracle_progressed,
                }
                for step in steps
            ],
        }

    return _guard("loop_history", _run)


def handler_loop_create(
    runtime: McpRuntime,
    *,
    assessment_id: str,
    grant_id: str | None = None,
    max_steps: int | None = None,
    max_wall_seconds: int | None = None,
    max_total_tokens: int | None = None,
) -> dict[str, object]:
    """Create a ReasoningLoop for an assessment. HUMAN only (grant required).

    A grant authorizes a human to start the loop; an agent without a grant
    receives structured HUMAN_REQUIRED. Builds a fresh INITIALIZING loop state
    (default budget derived from ``LoopBudget.default`` unless overridden) and
    records a signed ``loop.created`` audit event.
    """
    if not grant_id:
        return _human_required(
            "loop_create",
            assessment_id,
            "humans need a grant to create a loop (see grant_list)",
        )
    from ...domain.common.canonical import utc_now
    from ...domain.reasoning_loop.models import (
        LoopBudget,
        LoopId,
        LoopPhase,
        LoopPlan,
        LoopState,
        LoopTerminationPolicy,
    )

    def _run() -> dict[str, object]:
        with _loop_write_ctx(runtime) as session:
            state_repo, _step_repo = _loop_repos(runtime, session=session)
            now = utc_now()
            loop_id = LoopId.new()
            base = LoopBudget.default()
            budget = LoopBudget(
                max_steps=max_steps if max_steps is not None else base.max_steps,
                max_total_tokens=(
                    max_total_tokens if max_total_tokens is not None
                    else base.max_total_tokens
                ),
                max_wall_seconds=(
                    max_wall_seconds if max_wall_seconds is not None
                    else base.max_wall_seconds
                ),
            )
            plan = LoopPlan(
                plan_id=f"plan-{uuid.uuid4().hex[:12]}",
                loop_id=loop_id,
                assessment_id=assessment_id,
                termination_policy=LoopTerminationPolicy.default(),
                policy_snapshot="mcp:loop:default",
                created_at=now,
            )
            state = LoopState(
                loop_id=plan.loop_id,
                assessment_id=plan.assessment_id,
                phase=LoopPhase.INITIALIZING,
                policy_snapshot=plan.policy_snapshot,
                budget=budget,
                context_hash="0" * 64,
                catalog_required_remaining=frozenset(),
                catalog_required_executed=frozenset(),
                consecutive_no_signal=0,
                consecutive_policy_rejected=0,
                started_at=now,
                last_step_at=None,
            )
            state_repo.save(state)
            runtime.audit_chain.record(
                actor="human",
                action=LOOP_CREATED,
                resource_type=LOOP_RESOURCE_TYPE,
                resource_id=loop_id.value,
                payload={
                    "assessment_id": assessment_id,
                    "grant_id": grant_id,
                    "budget": {
                        "max_steps": budget.max_steps,
                        "max_total_tokens": budget.max_total_tokens,
                        "max_wall_seconds": budget.max_wall_seconds,
                    },
                },
                session=session,
            )
            return {
                "status": "success",
                "loop_id": loop_id.value,
                "phase": state.phase.value,
            }

    return _guard("loop_create", _run)


def handler_loop_stop(
    runtime: McpRuntime, *, loop_id: str, grant_id: str | None = None,
    actor: str = "human",
) -> dict[str, object]:
    """Stop a ReasoningLoop. HUMAN only (grant required).

    A grant authorizes a human to stop the loop; an agent without a grant
    receives structured HUMAN_REQUIRED. Transitions the loop to the terminal
    ``EMERGENCY_STOPPED`` phase (the orchestrator's emergency-stop semantics)
    and records a signed ``loop.terminated`` audit event. Idempotent for an
    already-stopped loop.
    """
    if not grant_id:
        return _human_required(
            "loop_stop",
            loop_id,
            "humans need a grant to stop a loop (see grant_list)",
        )
    from ...domain.common.canonical import utc_now
    from ...domain.reasoning_loop.models import LoopId, LoopPhase

    def _run() -> dict[str, object]:
        with _loop_write_ctx(runtime) as session:
            state_repo, _step_repo = _loop_repos(runtime, session=session)
            lid = LoopId(loop_id)
            state = state_repo.get(lid)
            if state is None:
                raise LookupError(f"loop {loop_id!r} not found")
            if state.phase is not LoopPhase.EMERGENCY_STOPPED:
                now = utc_now()
                stopped = replace(state, phase=LoopPhase.EMERGENCY_STOPPED,
                                  last_step_at=now)
                state_repo.save(stopped)
                runtime.audit_chain.record(
                    actor=actor or "human",
                    action=LOOP_TERMINATED,
                    resource_type=LOOP_RESOURCE_TYPE,
                    resource_id=loop_id,
                    payload={
                        "final_phase": LoopPhase.EMERGENCY_STOPPED.value,
                        "reason": "emergency_stop",
                        "human_reason": "stopped via MCP loop_stop (grant)",
                        "from_phase": state.phase.value,
                    },
                    session=session,
                )
                return {
                    "status": "success",
                    "loop_id": loop_id,
                    "phase": LoopPhase.EMERGENCY_STOPPED.value,
                }
            return {
                "status": "success",
                "loop_id": loop_id,
                "phase": state.phase.value,
            }

    return _guard("loop_stop", _run)


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
    "mission_create": handler_mission_create,
    "assessment_pause": handler_assessment_pause,
    "assessment_resume": handler_assessment_resume,
    "assessment_cancel": handler_assessment_cancel,
    "assessment_status": handler_assessment_status,
    "loop_pause": handler_loop_pause,
    "loop_resume": handler_loop_resume,
    "loop_status": handler_loop_status,
    "loop_history": handler_loop_history,
    "loop_create": handler_loop_create,
    "loop_stop": handler_loop_stop,
    "asset_list": handler_asset_list,
    "finding_list": handler_finding_list,
    "finding_validate": handler_finding_validate,
    "intel_search": handler_intel_search,
    "report_render": handler_report_render,
}