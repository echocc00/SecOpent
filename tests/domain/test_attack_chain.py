# tests/domain/test_attack_chain.py
"""AttackChain domain (spec §9): links, state machine, composite severity."""
from __future__ import annotations

import pytest

from secopent.domain.adapters.contracts import Severity
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.findings.attack_chain import (
    AttackChain,
    ChainLink,
    ChainStatus,
    composite_severity,
)


def _link(finding_id: str = "", pending: bool = False) -> ChainLink:
    if pending:
        return ChainLink(
            confirmed_finding_id="",
            pending_verification_key=f"pv-{finding_id or 'x'}",
        )
    return ChainLink(confirmed_finding_id=finding_id or "finding:abc123")


class TestChainLink:
    def test_link_needs_confirmed_or_pending(self) -> None:
        with pytest.raises(DomainValidationError):
            ChainLink(confirmed_finding_id="", pending_verification_key="")

    def test_confirmed_link(self) -> None:
        link = _link("finding:xyz")
        assert link.is_confirmed


class TestAttackChain:
    def test_requires_at_least_two_links(self) -> None:
        with pytest.raises(DomainValidationError):
            AttackChain(
                id="chain-1", template_id="t", hypothesis_source="template",
                links=(_link("finding:a"),),
            )

    def test_initial_status_is_hypothesis(self) -> None:
        chain = AttackChain(
            id="chain-1", template_id="auth-bypass-plus-idor",
            hypothesis_source="template",
            links=(_link("finding:a"), _link("finding:b")),
        )
        assert chain.status is ChainStatus.HYPOTHESIS

    def test_status_transition_confirmed_requires_all_links_confirmed(self) -> None:
        chain = AttackChain(
            id="chain-1", template_id="t", hypothesis_source="template",
            links=(_link("finding:a"), _link(pending=True)),
        )
        assert chain.all_links_confirmed is False
        assert chain.status is ChainStatus.HYPOTHESIS


class TestCompositeSeverity:
    def test_chain_severity_is_max_of_links(self) -> None:
        assert composite_severity(
            (Severity.LOW, Severity.HIGH), asset_critical=False,
        ) is Severity.HIGH

    def test_escalates_one_level_when_reaching_critical_asset(self) -> None:
        assert composite_severity(
            (Severity.MEDIUM, Severity.MEDIUM), asset_critical=True,
        ) is Severity.HIGH

    def test_never_exceeds_critical(self) -> None:
        assert composite_severity(
            (Severity.CRITICAL,), asset_critical=True,
        ) is Severity.CRITICAL
