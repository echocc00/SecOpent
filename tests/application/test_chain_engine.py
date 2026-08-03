# tests/application/test_chain_engine.py
"""ChainEngine: hypothesis generation + verification projection (P2b)."""
from __future__ import annotations

from secopent.application.chain_engine import ChainEngine
from secopent.domain.adapters.contracts import Severity
from secopent.domain.findings.attack_chain import ChainStatus
from secopent.domain.findings.chain_templates import default_chain_templates
from secopent.domain.findings.models import Finding, FindingStatus


def _confirmed(
    finding_id: str,
    cwe: str,
    asset: str,
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        id=finding_id,
        fingerprint=f"fp-{finding_id}",
        title=f"t-{cwe}",
        asset=asset,
        severity=severity,
        cwe=(cwe,),
        status=FindingStatus.VALIDATED,
    )


class TestTemplateHypotheses:
    def test_matching_confirmed_findings_yield_confirmed_chain(self) -> None:
        engine = ChainEngine(templates=default_chain_templates())
        findings = (
            _confirmed("finding:a", "CWE-287", "http://app/login"),
            _confirmed("finding:b", "CWE-639", "http://app/api/profile"),
        )
        chains = engine.hypothesize_from_findings(findings)
        matched = [c for c in chains if c.template_id == "auth-bypass-plus-idor"]
        assert len(matched) == 1
        chain = matched[0]
        assert chain.all_links_confirmed
        assert chain.status is ChainStatus.CONFIRMED
        assert chain.severity in (Severity.HIGH, Severity.CRITICAL)

    def test_partial_match_yields_partially_verified_with_pending_links(self) -> None:
        engine = ChainEngine(templates=default_chain_templates())
        findings = (_confirmed("finding:a", "CWE-287", "http://app/login"),)
        chains = engine.hypothesize_from_findings(findings)
        matched = [c for c in chains if c.template_id == "auth-bypass-plus-idor"]
        assert len(matched) == 1
        chain = matched[0]
        # First link confirmed, rest pending → PARTIALLY_VERIFIED (DoD)
        assert chain.status is ChainStatus.PARTIALLY_VERIFIED
        pending = [lk for lk in chain.links if not lk.is_confirmed]
        assert len(pending) == 1  # IDOR 环待补证

    def test_verification_projection_lists_pending_keys(self) -> None:
        engine = ChainEngine(templates=default_chain_templates())
        findings = (_confirmed("finding:a", "CWE-287", "http://app/login"),)
        chains = engine.hypothesize_from_findings(findings)
        # Filter tasks for the specific chain we care about
        auth_chains = [c for c in chains if c.template_id == "auth-bypass-plus-idor"]
        tasks = engine.pending_verification_tasks(auth_chains)
        assert len(tasks) == 1
        assert tasks[0].required_cwe == ("CWE-639", "CWE-284")

    def test_only_validated_findings_feed_chains(self) -> None:
        engine = ChainEngine(templates=default_chain_templates())
        draft = Finding(
            id="finding:draft",
            fingerprint="fp-d",
            title="t",
            asset="http://app",
            severity=Severity.HIGH,
            cwe=("CWE-287",),
            status=FindingStatus.CANDIDATE,  # 未 oracle 确认
        )
        confirmed = _confirmed("finding:b", "CWE-639", "http://app/api")
        chains = engine.hypothesize_from_findings((draft, confirmed))
        assert all(
            c.template_id != "auth-bypass-plus-idor" or not c.all_links_confirmed
            for c in chains
        )
