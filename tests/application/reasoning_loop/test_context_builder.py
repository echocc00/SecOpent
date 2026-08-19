# tests/application/reasoning_loop/test_context_builder.py
"""DefaultLoopContextBuilder — assembles LoopContext (spec §3.4)."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from secopent.application.reasoning_loop.context_builder import (
    DefaultLoopContextBuilder,
)
from secopent.application.reasoning_loop.in_memory_state import (
    InMemoryLoopStateRepository,
)
from secopent.application.reasoning_loop.summarizer import ObservationSummarizer
from secopent.domain.catalog.models import AssetType, RequiredTestClass, TestCatalog
from secopent.domain.policy.models import RiskClass
from secopent.domain.reasoning_loop.models import (
    LoopBudget,
    LoopId,
    LoopPhase,
    LoopState,
    ObservationSummary,
)

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _state(loop_id: LoopId, required_remaining: frozenset[str]) -> LoopState:
    return LoopState(
        loop_id=loop_id,
        assessment_id="asmt-1",
        phase=LoopPhase.RUNNING,
        policy_snapshot="sha256:" + "0" * 64,
        budget=LoopBudget.default(),
        context_hash="0" * 64,
        catalog_required_remaining=required_remaining,
        catalog_required_executed=frozenset(),
        consecutive_no_signal=0,
        consecutive_policy_rejected=0,
        started_at=_T0,
        last_step_at=None,
    )


def test_context_builder_builds_empty_observations_for_new_loop() -> None:
    catalog = TestCatalog(version="t-1", mappings={})
    state_repo = InMemoryLoopStateRepository()
    builder = DefaultLoopContextBuilder(
        catalog=catalog,
        state_repo=state_repo,
        asset_subgraph_provider=lambda aid: (),
        observation_provider=lambda lid: (),
    )
    lid = LoopId(value="abcd1234")
    state_repo.save(_state(lid, frozenset()))
    ctx = builder.build(lid)
    assert ctx.loop_step == 0
    assert ctx.catalog_already_executed == frozenset()
    assert ctx.catalog_still_required == frozenset()
    assert ctx.catalog_floor_progress == 0.0
    assert ctx.recent_observations == ()


def test_context_builder_reflects_catalog_remaining_classes() -> None:
    catalog = TestCatalog(
        version="t-1",
        mappings={
            AssetType.WEB_APP: (
                RequiredTestClass(
                    id="web:xss",
                    cwe=("CWE-79",),
                    owasp=("WSTG-INPV-01",),
                    risk=RiskClass.PASSIVE,
                ),
                RequiredTestClass(
                    id="web:sqli",
                    cwe=("CWE-89",),
                    owasp=("WSTG-INPV-05",),
                    risk=RiskClass.ACTIVE,
                ),
            ),
        },
    )
    state_repo = InMemoryLoopStateRepository()
    builder = DefaultLoopContextBuilder(
        catalog=catalog,
        state_repo=state_repo,
        asset_subgraph_provider=lambda aid: (),
        observation_provider=lambda lid: (),
    )
    lid = LoopId(value="abcd1234")
    # State already executed web:xss but not web:sqli.
    state_repo.save(
        _state(lid, frozenset({"web:sqli"}))
    )
    ctx = builder.build(lid)
    assert ctx.catalog_still_required == frozenset({"web:sqli"})
    assert ctx.catalog_floor_progress == pytest.approx(0.5)
    # builder reads catalog_still_required from state only
    assert ctx.catalog_already_executed == frozenset()


def test_context_builder_with_summarizer_compresses_observations() -> None:
    """v0.7.3 Task 4: when a summarizer is injected, the raw observation window
    is compressed via ObservationSummarizer.summarize() and the compressed
    token count feeds LoopContext.observation_token_count."""
    catalog = TestCatalog(version="t-1", mappings={})
    state_repo = InMemoryLoopStateRepository()
    observations = tuple(
        ObservationSummary(
            observation_id=f"obs-{i}",
            tool_or_case_id=f"tool-{i}",
            target_digest=f"digest-{i}",
            key_signals=("s1", "s2", "s3"),
            confidence=0.7,
            has_full_text=True,
            full_text_ref=f"ref-{i}",
            token_estimate=200,
        )
        for i in range(8)
    )
    builder = DefaultLoopContextBuilder(
        catalog=catalog,
        state_repo=state_repo,
        asset_subgraph_provider=lambda aid: (),
        observation_provider=lambda lid: observations,
        summarizer=ObservationSummarizer(),
    )
    lid = LoopId(value="abcd1234")
    state_repo.save(_state(lid, frozenset()))
    ctx = builder.build(lid)

    # Compression applied: exactly the summarized window is surfaced.
    assert len(ctx.recent_observations) == len(observations)  # none dropped
    # First five are full tier (token_estimate preserved), rest compressed down.
    assert ctx.recent_observations[0].token_estimate == 200
    assert ctx.recent_observations[5].has_full_text is False
    # The token count reflects the compressed window, not the raw sum (8*200).
    assert ctx.observation_token_count < sum(o.token_estimate for o in observations)
    assert ctx.observation_token_count == sum(
        o.token_estimate for o in ctx.recent_observations
    )


def test_context_builder_without_summarizer_passthrough_uncompressed() -> None:
    """v0.7.3 Task 4: default (no summarizer) keeps the raw observations and the
    raw sum token count — existing behavior untouched."""
    catalog = TestCatalog(version="t-1", mappings={})
    state_repo = InMemoryLoopStateRepository()
    observations = tuple(
        ObservationSummary(
            observation_id=f"obs-{i}",
            tool_or_case_id=f"tool-{i}",
            target_digest=f"digest-{i}",
            key_signals=("s1", "s2", "s3"),
            confidence=0.7,
            has_full_text=True,
            full_text_ref=f"ref-{i}",
            token_estimate=200,
        )
        for i in range(8)
    )
    builder = DefaultLoopContextBuilder(
        catalog=catalog,
        state_repo=state_repo,
        asset_subgraph_provider=lambda aid: (),
        observation_provider=lambda lid: observations,
    )
    lid = LoopId(value="abcd1234")
    state_repo.save(_state(lid, frozenset()))
    ctx = builder.build(lid)

    assert ctx.recent_observations == observations
    assert ctx.recent_observations[5].has_full_text is True
    assert ctx.observation_token_count == 8 * 200
