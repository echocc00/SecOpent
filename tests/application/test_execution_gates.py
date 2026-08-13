# tests/application/test_execution_gates.py
"""execute_assessment security gates (W2-A Tasks 2-5).

Tests the wiring of EmergencyStop, PermitSigner/Verifier, ScopeEnforcer, and
AuditChain into the execution path. Reuses the seed/step-runner helpers from
test_execution.py to avoid duplication.
"""
from __future__ import annotations

# Reuse the seed/fake helpers defined in the sibling execution test module.
from test_execution import (  # type: ignore[import-not-found]
    _FakeStepRunner,
    _MemoryFindingRepo,
    _observation,
    _seed_approved,
)

from secopent.application.assessments import AssessmentService
from secopent.application.audit import AuditService
from secopent.application.emergency_stop import EmergencyStop
from secopent.application.execution import execute_assessment
from secopent.domain.assessments.models import AssessmentStatus
from secopent.infrastructure.safety.emergency_infra import NullContainerTerminator
from secopent.infrastructure.safety.permit_revoker import InMemoryPermitRevoker

# --- T2: EmergencyStop gate -------------------------------------------------


def test_execute_refuses_when_emergency_stop_triggered(memory_repositories) -> None:
    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)  # -> QUEUED

    stop = EmergencyStop(
        permit_revoker=InMemoryPermitRevoker(),
        container_terminator=NullContainerTerminator(),
        audit=AuditService(memory_repositories.audit),
    )
    stop.trigger(actor="ops", reason="manual kill switch")

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
        emergency_stop=stop,
    )

    assessment = memory_repositories.assessments.get(a.id)
    assert assessment is not None
    assert assessment.status is AssessmentStatus.FAILED
    actions = [e.action for e in memory_repositories.audit.events]
    assert "assessment.blocked.emergency_stop" in actions
    assert "assessment.completed" not in actions


# --- T3: Permit signing -----------------------------------------------------


def test_start_assessment_signs_permit_bound_to_scope_and_plan(
    memory_repositories,
) -> None:
    from secopent.domain.permits.models import ExecutionPermit
    from secopent.infrastructure.permits.permit_signer import PermitSigner

    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)  # -> QUEUED

    real_signer = PermitSigner()
    captured: list[ExecutionPermit] = []

    class _CapturingSigner:
        def issue(self, permit: ExecutionPermit) -> ExecutionPermit:
            signed = real_signer.issue(permit)
            captured.append(signed)
            return signed

    revoker = InMemoryPermitRevoker()

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
        permit_signer=_CapturingSigner(),
        permit_registry=revoker,
    )

    assert len(captured) == 1
    permit = captured[0]
    assert permit.signature  # non-empty Ed25519 signature
    assert permit.worker_id == "adapter-executor"
    assert permit.job_id == a.id

    assessment = memory_repositories.assessments.get(a.id)
    assert assessment is not None
    plan = memory_repositories.assessments.get_plan(assessment.active_plan_id)
    scope = memory_repositories.scopes.get_snapshot(assessment.scope_snapshot_id)
    assert plan is not None and scope is not None
    assert permit.scope_digest == scope.digest
    assert permit.plan_digest == plan.digest

    # nonce registered with the revoker so EmergencyStop can revoke it
    assert revoker.revoke_unused() == 1


# --- T4: Permit verification + ScopeEnforcer --------------------------------


def test_permit_verification_failure_fails_assessment(memory_repositories) -> None:
    """A permit signed by key A but verified with key B -> FAILED."""
    from secopent.infrastructure.permits.permit_signer import PermitSigner, PermitVerifier

    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)

    signer = PermitSigner()  # key A
    wrong_verifier = PermitVerifier(PermitSigner().public_key_bytes())  # key B

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
        permit_signer=signer,
        permit_registry=InMemoryPermitRevoker(),
        permit_verifier=wrong_verifier,
    )

    assessment = memory_repositories.assessments.get(a.id)
    assert assessment is not None
    assert assessment.status is AssessmentStatus.FAILED
    actions = [e.action for e in memory_repositories.audit.events]
    assert "assessment.blocked.permit_invalid" in actions


def test_permit_verification_success_proceeds_to_completion(memory_repositories) -> None:
    """A permit signed + verified with the same key -> COMPLETED."""
    from secopent.infrastructure.permits.permit_signer import PermitSigner, PermitVerifier

    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)

    signer = PermitSigner()
    verifier = PermitVerifier(signer.public_key_bytes())

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
        permit_signer=signer,
        permit_registry=InMemoryPermitRevoker(),
        permit_verifier=verifier,
    )

    assessment = memory_repositories.assessments.get(a.id)
    assert assessment is not None
    assert assessment.status is AssessmentStatus.COMPLETED


def _seed_approved_ip_scope(repos, *, target: str) -> None:
    """Seed an assessment whose scope is an IP network (enforcer-friendly)."""
    from datetime import UTC, datetime

    from secopent.domain.policy.models import ExecutionMode, RiskClass
    from secopent.domain.projects.models import Project
    from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot

    repos.projects.add(Project.create(project_id="p1", name="t"))
    repos.scopes.add_snapshot(ScopeSnapshot(
        id="s1", project_id="p1", include=("10.0.0.0/30",), exclude=(),
        ports=(80,),
        limits=ScopeLimits(requests_per_second=10, concurrency=2, max_requests=100),
        approved_by="a", approved_at=datetime.now(UTC), digest="sha256:scope-ip",
    ))
    service = AssessmentService(repos.assessments)
    assessment = service.create(
        project_id="p1", scope_snapshot_id="s1", mode=ExecutionMode.APPROVAL,
    )
    from secopent.domain.assessments.models import PlanStep
    service.attach_plan(assessment.id, steps=(
        PlanStep(
            key="nuclei-sqli", runner="nuclei", risk=RiskClass.LOW,
            parameters={"target": target}, dependencies=(),
        ),
    ))
    service.approve(
        assessment_id=assessment.id, approved_by="analyst",
        approved_risks=frozenset({RiskClass.LOW}),
        approved_capabilities=frozenset(), scope_digest="sha256:scope-ip",
    )
    return repos.assessments.get(assessment.id)


class _NullDnsResolver:
    def resolve(self, host: str) -> tuple[str, ...]:
        return ()


def test_scope_enforcer_denies_out_of_scope_target(memory_repositories) -> None:
    from secopent.application.scope_enforcer import ScopeEnforcer

    _seed_approved_ip_scope(memory_repositories, target="http://192.168.50.50")
    assessment = memory_repositories.assessments.items[
        next(iter(memory_repositories.assessments.items))
    ]
    AssessmentService(memory_repositories.assessments).start(assessment.id)

    execute_assessment(
        assessment_id=assessment.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
        scope_enforcer=ScopeEnforcer(_NullDnsResolver()),
    )

    assessment = memory_repositories.assessments.get(assessment.id)
    assert assessment is not None
    assert assessment.status is AssessmentStatus.FAILED
    actions = [e.action for e in memory_repositories.audit.events]
    assert "assessment.blocked.scope_violation" in actions


def test_scope_enforcer_allows_in_scope_target(memory_repositories) -> None:
    from secopent.application.scope_enforcer import ScopeEnforcer

    _seed_approved_ip_scope(memory_repositories, target="http://10.0.0.1")
    assessment = memory_repositories.assessments.items[
        next(iter(memory_repositories.assessments.items))
    ]
    AssessmentService(memory_repositories.assessments).start(assessment.id)

    execute_assessment(
        assessment_id=assessment.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
        scope_enforcer=ScopeEnforcer(_NullDnsResolver()),
    )

    assessment = memory_repositories.assessments.get(assessment.id)
    assert assessment is not None
    assert assessment.status is AssessmentStatus.COMPLETED


def _seed_http_prefixed_scope(repos) -> None:  # noqa: ANN001
    """Seed an assessment whose scope rule is the documented HTTP form (v9)."""
    from datetime import UTC, datetime

    from secopent.domain.assessments.models import PlanStep
    from secopent.domain.policy.models import ExecutionMode, RiskClass
    from secopent.domain.projects.models import Project
    from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot

    repos.projects.add(Project.create(project_id="p1", name="t"))
    repos.scopes.add_snapshot(ScopeSnapshot(
        id="s1", project_id="p1",
        include=("http://192.168.2.18:3000/",),  # the standard operator form
        exclude=(), ports=(3000,),
        limits=ScopeLimits(requests_per_second=10, concurrency=2, max_requests=100),
        approved_by="a", approved_at=datetime.now(UTC), digest="sha256:scope-url",
    ))
    service = AssessmentService(repos.assessments)
    assessment = service.create(
        project_id="p1", scope_snapshot_id="s1", mode=ExecutionMode.APPROVAL,
    )
    # No explicit `target` on the step (v8 bug B): _check_plan_scope enforces
    # the scope.include entries themselves - exactly the production shape.
    service.attach_plan(assessment.id, steps=(
        PlanStep(
            key="nuclei-sqli", runner="nuclei", risk=RiskClass.LOW,
            parameters={}, dependencies=(),
        ),
    ))
    service.approve(
        assessment_id=assessment.id, approved_by="analyst",
        approved_risks=frozenset({RiskClass.LOW}),
        approved_capabilities=frozenset(), scope_digest="sha256:scope-url",
    )


def test_http_prefixed_scope_runs_through_executor(memory_repositories) -> None:
    """v9 at the executor level: the documented URL-form scope must NOT fail.

    Before v0.6.1, ScopeEnforcer's private matcher rejected every http(s)://
    rule with NOT_INCLUDED, so `_check_plan_scope` failed the assessment
    before any scan container launched (issue v9 + v9.5 deployment).
    """
    from secopent.application.scope_enforcer import ScopeEnforcer

    _seed_http_prefixed_scope(memory_repositories)
    assessment = memory_repositories.assessments.items[
        next(iter(memory_repositories.assessments.items))
    ]
    AssessmentService(memory_repositories.assessments).start(assessment.id)

    execute_assessment(
        assessment_id=assessment.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
        scope_enforcer=ScopeEnforcer(_NullDnsResolver()),
    )

    assessment = memory_repositories.assessments.get(assessment.id)
    assert assessment is not None
    assert assessment.status is AssessmentStatus.COMPLETED
    assert "assessment.blocked.scope_violation" not in {
        e.action for e in memory_repositories.audit.events
    }


# --- T5: AuditChain signed events + permit nonce ----------------------------


def test_audit_chain_records_signed_events_and_permit_nonce(memory_repositories) -> None:
    from secopent.application.audit_chain import AuditChain
    from secopent.infrastructure.audit.key_manager import AuditKeyManager
    from secopent.infrastructure.permits.permit_signer import PermitSigner, PermitVerifier

    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)

    signer = PermitSigner()
    chain = AuditChain(AuditKeyManager())

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
        permit_signer=signer,
        permit_registry=InMemoryPermitRevoker(),
        permit_verifier=PermitVerifier(signer.public_key_bytes()),
        audit_chain=chain,
    )

    actions = [e.action for e in chain.events()]
    assert "assessment.started" in actions
    assert "assessment.completed" in actions
    assert "permit.used" in actions  # record_permit_nonce
    assert chain.permit_nonces()  # non-empty
    assert chain.verify() is True  # hash chain + every signature valid


# --- T7: EgressGuard app-layer pre-check ------------------------------------


def test_egress_guard_denies_cloud_metadata_target(memory_repositories) -> None:
    """169.254.169.254 is always blocked even if scope mistakenly includes it."""
    from secopent.infrastructure.egress.egress_guard import EgressGuard
    from secopent.infrastructure.egress.nft_scope import SocketDnsResolver

    _seed_approved_ip_scope(memory_repositories, target="http://169.254.169.254")
    assessment = memory_repositories.assessments.items[
        next(iter(memory_repositories.assessments.items))
    ]
    AssessmentService(memory_repositories.assessments).start(assessment.id)

    execute_assessment(
        assessment_id=assessment.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
        egress_guard=EgressGuard(SocketDnsResolver()),
    )

    assessment = memory_repositories.assessments.get(assessment.id)
    assert assessment is not None
    assert assessment.status is AssessmentStatus.FAILED
    actions = [e.action for e in memory_repositories.audit.events]
    assert "assessment.blocked.egress_denied" in actions


# --- T8: End-to-end auth chain integration ----------------------------------


def test_full_auth_chain_integration_and_emergency_stop(memory_repositories) -> None:
    """All W2-A components wired together: permit signed + verified, scope +
    egress enforced, signed audit chain valid, then emergency stop blocks the
    next assessment."""
    from secopent.application.audit_chain import AuditChain
    from secopent.application.emergency_stop import EmergencyStop
    from secopent.application.scope_enforcer import ScopeEnforcer
    from secopent.infrastructure.audit.key_manager import AuditKeyManager
    from secopent.infrastructure.egress.egress_guard import EgressGuard
    from secopent.infrastructure.egress.nft_scope import SocketDnsResolver
    from secopent.infrastructure.permits.permit_signer import PermitSigner, PermitVerifier
    from secopent.infrastructure.safety.emergency_infra import NullContainerTerminator

    signer = PermitSigner()
    registry = InMemoryPermitRevoker()
    chain = AuditChain(AuditKeyManager())
    stop = EmergencyStop(
        permit_revoker=registry,
        container_terminator=NullContainerTerminator(),
        audit=AuditService(memory_repositories.audit),
    )

    # Assessment 1: full chain -> COMPLETED with signed audit + permit nonce.
    a1 = _seed_approved_ip_scope(memory_repositories, target="http://10.0.0.1")
    assert a1 is not None
    AssessmentService(memory_repositories.assessments).start(a1.id)
    execute_assessment(
        assessment_id=a1.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
        emergency_stop=stop,
        permit_signer=signer,
        permit_registry=registry,
        permit_verifier=PermitVerifier(signer.public_key_bytes()),
        scope_enforcer=ScopeEnforcer(_NullDnsResolver()),
        egress_guard=EgressGuard(SocketDnsResolver()),
        audit_chain=chain,
    )
    a1 = memory_repositories.assessments.get(a1.id)
    assert a1 is not None
    assert a1.status is AssessmentStatus.COMPLETED
    assert chain.verify() is True
    assert chain.permit_nonces()  # permit nonce recorded in signed chain

    # Trigger the kill switch.
    stop.trigger(actor="ops", reason="incident response")
    assert stop.is_triggered

    # Assessment 2: refused at the emergency-stop gate (before any dispatch).
    a2 = _seed_approved_ip_scope(memory_repositories, target="http://10.0.0.1")
    assert a2 is not None and a2.id != a1.id
    AssessmentService(memory_repositories.assessments).start(a2.id)
    execute_assessment(
        assessment_id=a2.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
        emergency_stop=stop,
        permit_signer=signer,
        permit_registry=registry,
        permit_verifier=PermitVerifier(signer.public_key_bytes()),
        audit_chain=chain,
    )
    a2 = memory_repositories.assessments.get(a2.id)
    assert a2 is not None
    assert a2.status is AssessmentStatus.FAILED
    actions = [e.action for e in chain.events()]
    assert "assessment.blocked.emergency_stop" in actions


# --- W2-B: nftables scope enforcement ---------------------------------------


def test_nft_scope_enforcer_applied_and_revoked_around_execution(
    memory_repositories,
) -> None:
    """apply_scope(scope) runs before dispatch; revoke() runs after (finally)."""

    class _CapturingNft:
        def __init__(self) -> None:
            self.applied: list[object] = []
            self.revoked = 0

        def apply_scope(self, snapshot: object, *, session=None) -> object:
            self.applied.append(snapshot)
            return None

        def revoke(self) -> None:
            self.revoked += 1

    nft = _CapturingNft()
    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
        nft_scope_enforcer=nft,
    )

    assert len(nft.applied) == 1
    assert nft.applied[0] is memory_repositories.scopes.get_snapshot(
        memory_repositories.assessments.get(a.id).scope_snapshot_id
    )
    assert nft.revoked == 1  # revoke ran in finally
    assert memory_repositories.assessments.get(a.id).status is AssessmentStatus.COMPLETED


def test_nft_scope_enforcer_revoked_even_on_failure(memory_repositories) -> None:
    """revoke() runs in finally even when the assessment fails."""

    class _CapturingNft:
        def __init__(self) -> None:
            self.applied: list[object] = []
            self.revoked = 0

        def apply_scope(self, snapshot: object, *, session=None) -> object:
            self.applied.append(snapshot)
            return None

        def revoke(self) -> None:
            self.revoked += 1

    nft = _CapturingNft()
    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)

    def _boom(_scope):  # noqa: ANN001
        raise RuntimeError("adapter exploded")

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=_boom,
        nft_scope_enforcer=nft,
    )

    assert nft.applied  # apply ran before the boom
    assert nft.revoked == 1  # revoke still ran in finally
    assert memory_repositories.assessments.get(a.id).status is AssessmentStatus.FAILED
