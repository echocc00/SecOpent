# tests/domain/test_policy.py
from __future__ import annotations
import pytest
from secopent.domain.policy.engine import ActionRequest, evaluate
from secopent.domain.policy.models import ExecutionMode, RiskClass
from secopent.domain.scope.models import ScopeDraft


@pytest.fixture
def scope_snapshot():
    draft = ScopeDraft(
        project_id="p",
        include=("https://example.test", "192.0.2.0/28"),
        ports=(443,),
    )
    return draft.freeze(snapshot_id="s", approved_by="u")


def test_policy_denies_scope_outside_target(scope_snapshot) -> None:
    decision = evaluate(
        ActionRequest(target="https://outside.test/", port=443, risk=RiskClass.LOW, capability="scoped_http"),
        scope=scope_snapshot,
        mode=ExecutionMode.SCOPE_AUTOPILOT,
        approved_risks=frozenset(RiskClass),
        approved_capabilities=frozenset({"scoped_http"}),
    )
    assert (decision.allowed, decision.reason) == (False, "SCOPE_DENIED")


def test_policy_denies_destructive_even_if_in_scope(scope_snapshot) -> None:
    decision = evaluate(
        ActionRequest(target="https://example.test/", port=443, risk=RiskClass.DESTRUCTIVE, capability="delete_data"),
        scope=scope_snapshot,
        mode=ExecutionMode.SCOPE_AUTOPILOT,
        approved_risks=frozenset(RiskClass),
        approved_capabilities=frozenset({"delete_data"}),
    )
    assert decision.reason == "DESTRUCTIVE_ACTION_DENIED"


def test_policy_active_requires_capability(scope_snapshot) -> None:
    decision = evaluate(
        ActionRequest(target="https://example.test/", port=443, risk=RiskClass.ACTIVE, capability="web_crawl"),
        scope=scope_snapshot,
        mode=ExecutionMode.APPROVAL,
        approved_risks=frozenset({RiskClass.LOW, RiskClass.ACTIVE}),
        approved_capabilities=frozenset(),
    )
    assert decision.reason == "CAPABILITY_NOT_APPROVED"


def test_policy_risk_not_approved(scope_snapshot) -> None:
    decision = evaluate(
        ActionRequest(target="https://example.test/", port=443, risk=RiskClass.ACTIVE, capability="web_crawl"),
        scope=scope_snapshot,
        mode=ExecutionMode.APPROVAL,
        approved_risks=frozenset({RiskClass.LOW}),
        approved_capabilities=frozenset({"web_crawl"}),
    )
    assert decision.reason == "RISK_NOT_APPROVED"


def test_policy_allows_low_in_scope(scope_snapshot) -> None:
    decision = evaluate(
        ActionRequest(target="https://example.test/", port=443, risk=RiskClass.LOW, capability="scoped_http"),
        scope=scope_snapshot,
        mode=ExecutionMode.APPROVAL,
        approved_risks=frozenset({RiskClass.LOW}),
        approved_capabilities=frozenset({"scoped_http"}),
    )
    assert (decision.allowed, decision.reason) == (True, "ALLOWED")
