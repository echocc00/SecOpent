"""TDD tests for CaseService lifecycle (M2 Task 10, §11.5/§11.8).

YAML cases move DRAFT -> VALIDATED -> REVIEWED -> SIGNED -> PUBLISHED. validate
runs the static RiskAnalyzer gate. Per §11.8 / LLM边界, an AGENT may create and
validate but can NEVER review, sign, or publish - those are human-only. State
transitions must follow the lifecycle order.
"""
from __future__ import annotations

import pytest

from secopent.application.cases import (
    CaseNotFoundError,
    CasePermissionError,
    CaseService,
    CaseTransitionError,
)
from secopent.application.risk_analyzer import RiskAnalyzer
from secopent.domain.cases.models import CaseDefinition, CaseStatus, CaseStep
from secopent.domain.cases.risk import RiskPublishDenied, RiskUndeclared
from secopent.domain.policy.models import RiskClass


def _case(
    case_id: str = "c1", *steps: CaseStep, risk: RiskClass = RiskClass.ACTIVE
) -> CaseDefinition:
    if not steps:
        steps = (CaseStep(id="s", action="crawl", spec={}),)  # computed Active
    return CaseDefinition(
        id=case_id,
        version="1.0.0",
        author="analyst",
        risk=risk,
        target_type="http",
        schema="s",
        steps=tuple(steps),
    )


@pytest.fixture
def service() -> CaseService:
    return CaseService(RiskAnalyzer())


def _signer(payload: bytes) -> str:
    return "sig:" + payload.hex()[:8]


def test_create_draft_stores_as_draft(service: CaseService) -> None:
    case = service.create_draft(_case())
    assert case.status is CaseStatus.DRAFT
    assert service.get("c1").status is CaseStatus.DRAFT


def test_validate_passes_risk_gate(service: CaseService) -> None:
    service.create_draft(_case())  # crawl, computed Active, declared Active
    validated = service.validate("c1")
    assert validated.status is CaseStatus.VALIDATED


def test_validate_rejects_deny_pattern(service: CaseService) -> None:
    shell_step = CaseStep(id="s", action="shell.exec", spec={"cmd": "id"})
    service.create_draft(_case("c-shell", shell_step))
    with pytest.raises(RiskPublishDenied):
        service.validate("c-shell")


def test_validate_rejects_undeclared_risk(service: CaseService) -> None:
    # oast computes Intrusive but declared Low -> undeclared.
    oast_step = CaseStep(id="s", action="oast.wait", spec={"window": 30})
    service.create_draft(_case("c-oast", oast_step, risk=RiskClass.LOW))
    with pytest.raises(RiskUndeclared):
        service.validate("c-oast")


def test_full_lifecycle_to_published(service: CaseService) -> None:
    service.create_draft(_case())
    service.validate("c1")
    service.review("c1", actor_role="human")
    signed = service.sign("c1", signer=_signer, actor_role="human")
    assert signed.status is CaseStatus.SIGNED
    assert signed.signature.startswith("sig:")
    published = service.publish("c1", actor_role="human")
    assert published.status is CaseStatus.PUBLISHED


def test_agent_cannot_review(service: CaseService) -> None:
    service.create_draft(_case())
    service.validate("c1")
    with pytest.raises(CasePermissionError):
        service.review("c1", actor_role="agent")


def test_agent_cannot_sign(service: CaseService) -> None:
    service.create_draft(_case())
    service.validate("c1")
    service.review("c1", actor_role="human")
    with pytest.raises(CasePermissionError):
        service.sign("c1", signer=_signer, actor_role="agent")


def test_agent_cannot_publish(service: CaseService) -> None:
    service.create_draft(_case())
    service.validate("c1")
    service.review("c1", actor_role="human")
    service.sign("c1", signer=_signer, actor_role="human")
    with pytest.raises(CasePermissionError):
        service.publish("c1", actor_role="agent")


def test_cannot_publish_from_draft(service: CaseService) -> None:
    service.create_draft(_case())
    with pytest.raises(CaseTransitionError):
        service.publish("c1", actor_role="human")


def test_cannot_sign_before_review(service: CaseService) -> None:
    service.create_draft(_case())
    service.validate("c1")  # VALIDATED, not REVIEWED
    with pytest.raises(CaseTransitionError):
        service.sign("c1", signer=_signer, actor_role="human")


def test_get_unknown_raises(service: CaseService) -> None:
    with pytest.raises(CaseNotFoundError):
        service.get("missing")
