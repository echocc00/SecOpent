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
    ConcludedChain,
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


class GrowingFindingProvider:
    """Returns the findings recorded so far, so one bridge reflects growing
    evidence across sync() calls — the closed-loop re-verification driver."""

    def __init__(self) -> None:
        self._findings: list[Finding] = []

    def add(self, finding: Finding) -> None:
        self._findings.append(finding)

    def __call__(self) -> tuple[Finding, ...]:
        return tuple(self._findings)


def test_reverification_moves_chain_to_confirmed_and_clears_pending() -> None:
    """Task 3 closed loop: as more findings get VALIDATED, re-running the engine
    moves a hypothesis's chain to CONFIRMED and its pending link disappears."""
    provider = GrowingFindingProvider()
    bridge = ChainBridge(
        engine=ChainEngine(templates=default_chain_templates()),
        finding_provider=provider,
    )
    # Stage 1: only the EARLY auth-bypass link is confirmed; the later IDOR
    # link (CWE-639/284) is still missing → it surfaces as pending.
    provider.add(_confirmed("finding:a", "CWE-287", "http://app/login"))
    first_pending = bridge.sync()
    idor = [h for h in first_pending if set(h.needed_cwe) & {"CWE-639", "CWE-284"}]
    assert len(idor) >= 1
    idor_id = idor[0].hypothesis_id

    # Stage 2: the completing finding (CWE-639 in a VALIDATED finding) arrives.
    provider.add(_confirmed("finding:b", "CWE-639", "http://app/account"))
    second_pending = bridge.sync()
    # The chain is now CONFIRMED; the engine emits no pending task for it, so
    # the earlier IDOR hypothesis is gone from the pending set.
    assert all(h.hypothesis_id != idor_id for h in second_pending)
    assert second_pending != first_pending
    # And the loop has a chain it may stop proposing work on.
    concluded_ids = {c.template_id for c in bridge.concluded_chains()}
    assert "auth-bypass-plus-idor" in concluded_ids


def test_broken_link_keeps_pending() -> None:
    """A template link whose CWE is NEVER provided stays pending across repeated
    sync() — the chain stays HYPOTHESIS and the pending set is retained."""
    provider = GrowingFindingProvider()
    bridge = ChainBridge(
        engine=ChainEngine(templates=default_chain_templates()),
        finding_provider=provider,
    )
    provider.add(_confirmed("finding:a", "CWE-287", "http://app/login"))
    first = bridge.sync()
    idor = [h for h in first if set(h.needed_cwe) & {"CWE-639", "CWE-284"}]
    assert len(idor) == 1
    idor_id = idor[0].hypothesis_id

    second = bridge.sync()
    second_ids = {h.hypothesis_id for h in second}
    assert idor_id in second_ids
    # No evidence changed → the pending set is identical (same id + set).
    assert first == second
    assert "auth-bypass-plus-idor" not in {
        c.template_id for c in bridge.concluded_chains()
    }


def test_sync_idempotent() -> None:
    """Two consecutive sync() calls over identical findings are a no-op: the
    SAME tuple (same ids + order) is returned each time."""
    provider = GrowingFindingProvider()
    bridge = ChainBridge(
        engine=ChainEngine(templates=default_chain_templates()),
        finding_provider=provider,
    )
    provider.add(_confirmed("finding:a", "CWE-287", "http://app/login"))
    provider.add(_confirmed("finding:ssrf", "CWE-918", "http://app/fetch"))
    first = bridge.sync()
    second = bridge.sync()
    assert len(first) >= 1
    assert first == second


def test_concluded_chains_filters() -> None:
    """concluded_chains() returns the CONFIRMED chain and excludes the still-
    HYPOTHESIS one, deterministically."""
    provider = GrowingFindingProvider()
    bridge = ChainBridge(
        engine=ChainEngine(templates=default_chain_templates()),
        finding_provider=provider,
    )
    # auth: both links confirmed → CONFIRMED. ssrf: only link 1 matches
    # (no CWE-918), so it stays HYPOTHESIS.
    provider.add(_confirmed("finding:auth", "CWE-287", "http://app/login"))
    provider.add(_confirmed("finding:idor", "CWE-639", "http://app/account"))
    provider.add(_confirmed("finding:ssrf", "CWE-200", "http://169.254.169.254/meta"))
    bridge.sync()

    concluded = bridge.concluded_chains()
    assert isinstance(concluded, tuple)
    assert all(isinstance(c, ConcludedChain) for c in concluded)
    concluded_ids = {c.template_id for c in concluded}
    assert "auth-bypass-plus-idor" in concluded_ids
    assert "ssrf-to-cloud-creds" not in concluded_ids
