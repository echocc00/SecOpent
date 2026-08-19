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
from secopent.application.reasoning_loop.chain_bridge import (
    ChainBridge,
    PendingPriority,
)
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


def test_request_chain_targets_stable_hypothesis() -> None:
    """v0.7.5 Task 2: the SAME logical pending link must yield the SAME
    hypothesis_id across repeated sync() calls (two loop builds over the same
    findings). Falls GREEN only once the bridge owns a deterministic identity
    scheme — the Task-1 volatile `pv-{uuid}` keys change every build, so this
    is the RED that motivates Task 2."""
    engine = ChainEngine(templates=default_chain_templates())
    bridge = ChainBridge(
        engine=engine,
        finding_provider=lambda: (
            _confirmed("finding:a", "CWE-287", "http://app/login"),
        ),
    )
    first = bridge.sync()
    second = bridge.sync()

    assert len(first) >= 1
    assert first == second
    # The SAME link (by required_cwe) keeps its id across builds.
    first_idor = {h.hypothesis_id for h in first if set(h.needed_cwe) & {"CWE-639", "CWE-284"}}
    second_idor = {h.hypothesis_id for h in second if set(h.needed_cwe) & {"CWE-639", "CWE-284"}}
    assert len(first_idor) == 1
    assert first_idor == second_idor


def test_next_priorities_orders_pending() -> None:
    """v0.7.5 Task 2: next_priorities returns PendingPriority ordered with the
    most urgent first — the earlier (first un-resolved) link outranks later
    links deterministically."""
    # ssrf-to-cloud-creds (3 links): CWE-918 confirms link 0, links 1 & 2 pend.
    engine = ChainEngine(templates=default_chain_templates())
    bridge = ChainBridge(
        engine=engine,
        finding_provider=lambda: (
            _confirmed("finding:ssrf", "CWE-918", "http://app/fetch"),
        ),
    )
    pending = bridge.sync()
    assert len(pending) >= 2

    priorities = bridge.next_priorities(pending)
    assert isinstance(priorities, tuple)
    assert all(isinstance(p, PendingPriority) for p in priorities)
    assert len(priorities) == len(pending)
    # Sorted descending by priority_score.
    scores = [p.priority_score for p in priorities]
    assert scores == sorted(scores, reverse=True)
    # IDs are stable & unique across the tuple.
    assert len({p.hypothesis_id for p in priorities}) == len(priorities)
    # The first un-resolved link (metadata, index 1) outranks the later one.
    assert priorities[0].priority_score > priorities[1].priority_score


def test_mark_progress_removes_from_pending() -> None:
    """v0.7.5 Task 2: once a pending link's hypothesis is marked progressed the
    bridge stops surfacing it in subsequent sync() calls, so next_priorities
    drops it — closing the loop on the targeted hypothesis."""
    engine = ChainEngine(templates=default_chain_templates())
    bridge = ChainBridge(
        engine=engine,
        finding_provider=lambda: (
            _confirmed("finding:a", "CWE-287", "http://app/login"),
        ),
    )
    pending = bridge.sync()
    assert pending
    target = pending[0].hypothesis_id

    bridge.mark_pending_progress(target)
    after = bridge.sync()
    after_ids = {h.hypothesis_id for h in after}
    assert target not in after_ids

    # And next_priorities no longer ranks the resolved hypothesis.
    ranked = {p.hypothesis_id for p in bridge.next_priorities(after)}
    assert target not in ranked
