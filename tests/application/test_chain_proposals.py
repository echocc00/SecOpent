# tests/application/test_chain_proposals.py
"""Chain proposal ports: llm/peer sources PROPOSE only (P2b Task 3)."""
from __future__ import annotations

from secopent.application.chain_engine import ChainEngine
from secopent.application.ports.chain_proposals import ChainProposal
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


class TestProposalHypotheses:
    def test_proposal_binds_validated_findings_and_pends_missing(self) -> None:
        engine = ChainEngine(templates=default_chain_templates())
        confirmed = _confirmed("finding:a", "CWE-287", "http://app/login")
        proposal = ChainProposal(
            proposer="llm:test-model",
            template_hint="auth-bypass-plus-idor",
            finding_ids=("finding:a", "finding:does-not-exist"),
        )
        chains = engine.hypothesize_from_proposals((proposal,), (confirmed,))
        assert len(chains) == 1
        chain = chains[0]
        assert chain.hypothesis_source == "llm_proposal"
        assert chain.status is not ChainStatus.CONFIRMED
        assert chain.links[0].is_confirmed
        assert not chain.links[1].is_confirmed  # 未确认引用 → pending

    def test_peer_claim_marked_as_peer_source(self) -> None:
        engine = ChainEngine(templates=default_chain_templates())
        confirmed_a = _confirmed("finding:a", "CWE-287", "http://app/login")
        confirmed_b = _confirmed("finding:b", "CWE-639", "http://app/api")
        proposal = ChainProposal(
            proposer="peer:strix",
            template_hint="auth-bypass-plus-idor",
            finding_ids=("finding:a", "finding:b"),
        )
        chains = engine.hypothesize_from_proposals(
            (proposal,), (confirmed_a, confirmed_b)
        )
        assert chains[0].hypothesis_source == "peer_claim"
        assert chains[0].status is ChainStatus.CONFIRMED

    def test_llm_claim_of_confirmation_not_honored(self) -> None:
        # LLM 声称 finding 已确认，但该 finding 仅是 CANDIDATE → 保持 pending
        candidate = Finding(
            id="finding:cand",
            fingerprint="fp-c",
            title="t",
            asset="http://app",
            severity=Severity.HIGH,
            cwe=("CWE-639",),
            status=FindingStatus.CANDIDATE,
        )
        confirmed = _confirmed("finding:a", "CWE-287", "http://app/login")
        engine = ChainEngine(templates=default_chain_templates())
        proposal = ChainProposal(
            proposer="llm:m",
            template_hint="auth-bypass-plus-idor",
            finding_ids=("finding:a", "finding:cand"),
        )
        chains = engine.hypothesize_from_proposals((proposal,), (confirmed, candidate))
        assert not chains[0].all_links_confirmed
