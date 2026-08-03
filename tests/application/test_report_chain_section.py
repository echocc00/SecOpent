# tests/application/test_report_chain_section.py
"""Report chain section rendering (P2b Task 4)."""
from __future__ import annotations

from secopent.application.report_renderer import render_chain_section
from secopent.domain.adapters.contracts import Severity
from secopent.domain.findings.attack_chain import (
    AttackChain,
    ChainLink,
    ChainStatus,
)


def _chain(
    *,
    status: ChainStatus,
    links: tuple[ChainLink, ...],
    severity: Severity = Severity.HIGH,
    template_id: str = "auth-bypass-plus-idor",
) -> AttackChain:
    return AttackChain(
        id="chain-test-1",
        template_id=template_id,
        hypothesis_source="template",
        links=links,
        status=status,
        severity=severity,
    )


class TestRenderChainSection:
    def test_empty_chains_returns_not_found_message(self) -> None:
        result = render_chain_section(())
        assert "本次评估未发现可验证攻击链" in result

    def test_confirmed_chain_renders_verified_section(self) -> None:
        chain = _chain(
            status=ChainStatus.CONFIRMED,
            links=(
                ChainLink(confirmed_finding_id="finding:a"),
                ChainLink(confirmed_finding_id="finding:b"),
            ),
            severity=Severity.CRITICAL,
        )
        result = render_chain_section((chain,))
        assert "已验证攻击链" in result
        assert "finding:a" in result
        assert "finding:b" in result
        assert "critical" in result.lower()

    def test_hypothesis_chain_goes_to_suggested_section(self) -> None:
        chain = _chain(
            status=ChainStatus.HYPOTHESIS,
            links=(
                ChainLink(confirmed_finding_id="finding:x"),
                ChainLink(pending_verification_key="pv-abc"),
            ),
        )
        result = render_chain_section((chain,))
        assert "建议优先修复路径" in result
        assert "finding:x" in result

    def test_partially_verified_chain_in_suggested_section(self) -> None:
        chain = _chain(
            status=ChainStatus.PARTIALLY_VERIFIED,
            links=(
                ChainLink(confirmed_finding_id="finding:p"),
                ChainLink(pending_verification_key="pv-def"),
            ),
        )
        result = render_chain_section((chain,))
        assert "建议优先修复路径" in result
        assert "finding:p" in result
