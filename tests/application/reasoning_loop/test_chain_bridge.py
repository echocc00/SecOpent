# tests/application/reasoning_loop/test_chain_bridge.py
"""ChainBridge — attack-chain pending hypotheses into LoopContext (v0.7.5).

The bridge closes the AttackChain hypothesis loop: confirmed findings feed the
ChainEngine, whose un-verified pending links are surfaced to the LLM as
LoopContext.chain_hypotheses_pending. This fixes the seam where the context
builder hardcoded `()` — the SchemaGate's SCHEMA_UNKNOWN_HYPOTHESIS check then
denied every request_chain.
"""
from __future__ import annotations

from secopent.application.chain_engine import ChainEngine
from secopent.application.reasoning_loop.chain_bridge import ChainBridge
from secopent.domain.adapters.contracts import Severity
from secopent.domain.findings.chain_templates import default_chain_templates
from secopent.domain.findings.models import Finding, FindingStatus
from secopent.domain.reasoning_loop.models import PendingHypothesis


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


def test_sync_populates_pending_hypotheses() -> None:
    """Confirmed findings matching a template's first link leave later links
    un-confirmed; the bridge surfaces them as PendingHypothesis with the
    un-bound CWE (e.g. CWE-639, the IDOR escalation link)."""
    engine = ChainEngine(templates=default_chain_templates())
    bridge = ChainBridge(
        engine=engine,
        finding_provider=lambda: (
            _confirmed("finding:a", "CWE-287", "http://app/login"),
        ),
    )
    pending = bridge.sync()
    assert isinstance(pending, tuple)
    assert len(pending) >= 1
    assert all(isinstance(h, PendingHypothesis) for h in pending)
    # The auth-bypass template's second (IDOR) link is un-bound.
    idor = [h for h in pending if set(h.needed_cwe) & {"CWE-639", "CWE-284"}]
    assert len(idor) >= 1
    assert idor[0].description


def test_valid_hypothesis_rejects_unknown() -> None:
    engine = ChainEngine(templates=default_chain_templates())
    bridge = ChainBridge(
        engine=engine,
        finding_provider=lambda: (
            _confirmed("finding:a", "CWE-287", "http://app/login"),
        ),
    )
    pending = bridge.sync()
    real_id = pending[0].hypothesis_id
    assert bridge.valid_hypothesis(real_id, pending) is True
    assert bridge.valid_hypothesis("nope", pending) is False


def test_engine_with_no_matching_findings_yields_empty() -> None:
    engine = ChainEngine(templates=default_chain_templates())
    bridge = ChainBridge(engine=engine, finding_provider=lambda: ())
    pending = bridge.sync()
    assert pending == ()
