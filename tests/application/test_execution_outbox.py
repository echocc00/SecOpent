"""execute_assessment routes audit through the outbox when wired (v0.3.0 T4).

With an outbox, every _audit_record event becomes ONE outbox row (the worker
fans out later) and nothing is written to the direct audit sinks - EXCEPT
permit nonces, which stay synchronous so replay detection never lags (D3).
Without an outbox the v0.2.0.2 direct same-transaction path is unchanged.
"""
from __future__ import annotations

from test_execution import (  # type: ignore[import-not-found]
    _FakeStepRunner,
    _MemoryFindingRepo,
    _observation,
    _seed_approved,
)

from secopent.application.assessments import AssessmentService
from secopent.application.audit_chain import AuditChain
from secopent.application.execution import execute_assessment
from secopent.infrastructure.audit.key_manager import AuditKeyManager
from secopent.infrastructure.permits.permit_signer import PermitSigner


class _FakeOutbox:
    def __init__(self) -> None:
        self.rows: list[tuple[str, object]] = []  # (action, session)

    def record(
        self, *, actor: str, action: str, resource_type: str,
        resource_id: str, payload: dict[str, object], session: object = None,
    ) -> None:
        self.rows.append((action, session))


def test_outbox_receives_all_audit_events_and_direct_sinks_stay_empty(
    memory_repositories,  # type: ignore[no-untyped-def]
) -> None:
    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)
    outbox = _FakeOutbox()

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda _scope: _FakeStepRunner((_observation(),)),
        audit_outbox=outbox,
    )

    actions = [action for action, _ in outbox.rows]
    assert "assessment.started" in actions
    assert "assessment.completed" in actions
    # Nothing reached the direct queryable audit sink.
    assert memory_repositories.audit.events == []


def test_without_outbox_direct_path_unchanged(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda _scope: _FakeStepRunner((_observation(),)),
    )

    actions = [e.action for e in memory_repositories.audit.events]
    assert "assessment.started" in actions
    assert "assessment.completed" in actions


def test_permit_nonce_stays_direct_even_with_outbox(
    memory_repositories,  # type: ignore[no-untyped-def]
) -> None:
    """D3: replay-detection state must never be async."""
    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)
    outbox = _FakeOutbox()
    chain = AuditChain(AuditKeyManager())  # in-memory chain, no store
    signer = PermitSigner()

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda _scope: _FakeStepRunner((_observation(),)),
        permit_signer=signer,
        audit_chain=chain,
        audit_outbox=outbox,
    )

    # The nonce went DIRECTLY to the signed chain (permit.used)...
    chain_actions = [e.action for e in chain.events()]
    assert "permit.used" in chain_actions
    assert len(chain.permit_nonces()) == 1
    # ...and never through the outbox.
    assert "permit.used" not in [action for action, _ in outbox.rows]
