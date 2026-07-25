"""TDD tests for FixtureRunner (M2 Task 11, §11.7 five fixture classes).

Every case must ship five fixture classes - positive (detects), negative (does
not), timeout, scope_deny, malformed (the last three handled gracefully, i.e.
not detected and no crash). Intrusive cases additionally require range /
before-after / cleanup / max-impact fixtures. All required fixtures must be
present AND behave as expected before a case may publish.
"""
from __future__ import annotations

from secopent.application.fixture_runner import (
    INTRUSIVE_EXTRA_KINDS,
    REQUIRED_FIXTURE_KINDS,
    CaseFixture,
    FixtureRunner,
)
from secopent.domain.cases.models import CaseDefinition, CaseStep
from secopent.domain.policy.models import RiskClass


def _case(risk: RiskClass = RiskClass.ACTIVE) -> CaseDefinition:
    return CaseDefinition(
        id="c",
        version="1.0.0",
        author="a",
        risk=risk,
        target_type="http",
        schema="s",
        steps=(CaseStep(id="s", action="crawl", spec={}),),
    )


def _five_fixtures() -> list[CaseFixture]:
    return [
        CaseFixture(kind="positive", detected=True),
        CaseFixture(kind="negative", detected=False),
        CaseFixture(kind="timeout", detected=False),
        CaseFixture(kind="scope_deny", detected=False),
        CaseFixture(kind="malformed", detected=False),
    ]


def test_required_kinds_are_the_five_classes() -> None:
    assert set(REQUIRED_FIXTURE_KINDS) == {
        "positive",
        "negative",
        "timeout",
        "scope_deny",
        "malformed",
    }


def test_all_five_fixtures_pass() -> None:
    result = FixtureRunner().run(_case(), _five_fixtures())
    assert result.passed is True
    assert result.missing_kinds == ()
    assert result.failures == ()


def test_missing_fixture_kind_fails() -> None:
    fixtures = [f for f in _five_fixtures() if f.kind != "malformed"]
    result = FixtureRunner().run(_case(), fixtures)
    assert result.passed is False
    assert "malformed" in result.missing_kinds


def test_positive_must_detect() -> None:
    fixtures = _five_fixtures()
    fixtures[0] = CaseFixture(kind="positive", detected=False)  # missed the vuln
    result = FixtureRunner().run(_case(), fixtures)
    assert result.passed is False
    assert any("positive" in failure for failure in result.failures)


def test_negative_must_not_detect() -> None:
    fixtures = _five_fixtures()
    fixtures[1] = CaseFixture(kind="negative", detected=True)  # false positive
    result = FixtureRunner().run(_case(), fixtures)
    assert result.passed is False
    assert any("negative" in failure for failure in result.failures)


def test_intrusive_case_requires_extra_fixtures() -> None:
    result = FixtureRunner().run(_case(risk=RiskClass.INTRUSIVE), _five_fixtures())
    assert result.passed is False
    assert set(result.missing_kinds) == set(INTRUSIVE_EXTRA_KINDS)


def test_intrusive_case_passes_with_extra_fixtures() -> None:
    fixtures = _five_fixtures() + [
        CaseFixture(kind=kind, detected=False) for kind in INTRUSIVE_EXTRA_KINDS
    ]
    result = FixtureRunner().run(_case(risk=RiskClass.INTRUSIVE), fixtures)
    assert result.passed is True


def test_non_intrusive_case_does_not_need_extra_fixtures() -> None:
    result = FixtureRunner().run(_case(risk=RiskClass.LOW), _five_fixtures())
    assert result.passed is True
