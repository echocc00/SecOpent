"""TDD tests for the Case domain + YAML schema (M2 Task 6, §11.2/§11.5).

A Case is a versioned, signed verification recipe in Nuclei-compatible YAML
plus three SecOpent extension hooks: a ``{{canary_token}}`` placeholder, a
``verification`` block (links the VerificationMethodRegistry + reproduce count),
and a ``classification`` block (CWE/CVE/OWASP feeding CoverageMatrix). The YAML
*string -> dict* step lives in infrastructure (case_engine); the domain owns the
pure *dict -> CaseDefinition* schema validation so it stays framework-free.
"""
from __future__ import annotations

import pytest

from secopent.domain.cases.models import (
    CaseAssertion,
    CaseDefinition,
    CaseOrigin,
    CaseStatus,
    CaseStep,
    CaseVerification,
)
from secopent.domain.cases.yaml_schema import (
    case_from_mapping,
    uses_canary_token,
)
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.policy.models import RiskClass


def _minimal_steps() -> tuple[CaseStep, ...]:
    return (CaseStep(id="req1", action="http.request", spec={"method": "GET"}),)


def test_case_status_progression() -> None:
    # The YAML-case lifecycle states (DRAFT -> ... -> PUBLISHED + terminal).
    assert CaseStatus.DRAFT.value == "draft"
    assert CaseStatus.PUBLISHED.value == "published"
    for state in ("draft", "validated", "reviewed", "signed", "published"):
        assert state in {s.value for s in CaseStatus}


def test_case_origin_has_three_sources() -> None:
    assert {o.value for o in CaseOrigin} == {"manual", "model_generated", "community"}


def test_case_definition_defaults_to_draft_manual() -> None:
    case = CaseDefinition(
        id="case-1",
        version="1.0.0",
        author="analyst",
        risk=RiskClass.LOW,
        target_type="http",
        schema="nuclei+secopent/1",
        steps=_minimal_steps(),
    )
    assert case.status is CaseStatus.DRAFT
    assert case.origin is CaseOrigin.MANUAL
    assert case.signature == ""
    assert case.assertions == ()
    assert case.cwe == ()


def test_case_definition_requires_core_fields() -> None:
    with pytest.raises(DomainValidationError):
        CaseDefinition(
            id="",
            version="1.0.0",
            author="a",
            risk=RiskClass.LOW,
            target_type="http",
            schema="s",
            steps=_minimal_steps(),
        )


def test_case_definition_requires_at_least_one_step() -> None:
    with pytest.raises(DomainValidationError):
        CaseDefinition(
            id="case-1",
            version="1.0.0",
            author="a",
            risk=RiskClass.LOW,
            target_type="http",
            schema="s",
            steps=(),
        )


def test_case_step_requires_id_and_action() -> None:
    with pytest.raises(DomainValidationError):
        CaseStep(id="", action="http.request")
    with pytest.raises(DomainValidationError):
        CaseStep(id="s1", action="")


def test_case_assertion_requires_expression() -> None:
    with pytest.raises(DomainValidationError):
        CaseAssertion(id="a1", expression="")


def test_case_verification_requires_positive_reproduce() -> None:
    with pytest.raises(DomainValidationError):
        CaseVerification(method="sqli", reproduce=0)


# ---------------------------------------------------------------------------
# case_from_mapping: pure dict -> CaseDefinition schema parsing
# ---------------------------------------------------------------------------


def _full_mapping() -> dict[str, object]:
    return {
        "id": "sqli-time-based",
        "version": "1.0.0",
        "author": "analyst",
        "schema": "nuclei+secopent/1",
        "risk": "active",
        "target_type": "http",
        "origin": "manual",
        "min_engine_version": "1.0.0",
        "preconditions": ["target responds to /login"],
        "classification": {
            "cwe": ["CWE-89"],
            "cve": ["CVE-2021-1234"],
            "owasp": ["A03:2021"],
        },
        "evidence_req": ["raw", "redacted"],
        "verification": {"method": "sqli", "reproduce": 5},
        "steps": [
            {
                "id": "req1",
                "action": "http.request",
                "spec": {"method": "GET", "path": "/?id={{canary_token}}"},
            },
            {"id": "oob", "action": "oast.wait", "spec": {"window": 30}},
        ],
        "assertions": [
            {"id": "a1", "expression": "contains(body, canary_token)"},
        ],
    }


def test_case_from_mapping_parses_full_case() -> None:
    case = case_from_mapping(_full_mapping())
    assert case.id == "sqli-time-based"
    assert case.version == "1.0.0"
    assert case.risk is RiskClass.ACTIVE
    assert case.target_type == "http"
    assert case.schema == "nuclei+secopent/1"
    assert case.origin is CaseOrigin.MANUAL
    assert case.min_engine_version == "1.0.0"
    assert case.preconditions == ("target responds to /login",)
    assert len(case.steps) == 2
    assert case.steps[0].action == "http.request"
    assert case.assertions[0].expression == "contains(body, canary_token)"


def test_case_from_mapping_parses_classification() -> None:
    case = case_from_mapping(_full_mapping())
    assert case.cwe == ("CWE-89",)
    assert case.cve == ("CVE-2021-1234",)
    assert case.owasp == ("A03:2021",)


def test_case_from_mapping_parses_verification_block() -> None:
    case = case_from_mapping(_full_mapping())
    assert case.verification is not None
    assert case.verification.method == "sqli"
    assert case.verification.reproduce == 5


def test_case_from_mapping_parses_evidence_req() -> None:
    case = case_from_mapping(_full_mapping())
    assert case.evidence_req == ("raw", "redacted")


def test_case_from_mapping_rejects_missing_id() -> None:
    mapping = _full_mapping()
    del mapping["id"]
    with pytest.raises(DomainValidationError):
        case_from_mapping(mapping)


def test_case_from_mapping_rejects_unknown_risk() -> None:
    mapping = _full_mapping()
    mapping["risk"] = "catastrophic"
    with pytest.raises(DomainValidationError):
        case_from_mapping(mapping)


def test_uses_canary_token_detects_placeholder() -> None:
    case = case_from_mapping(_full_mapping())
    assert uses_canary_token(case) is True


def test_uses_canary_token_false_without_placeholder() -> None:
    mapping = _full_mapping()
    mapping["steps"] = [{"id": "req1", "action": "http.request", "spec": {"path": "/static"}}]
    case = case_from_mapping(mapping)
    assert uses_canary_token(case) is False
