# src/secopent/application/reasoning_loop/context_builder.py
"""DefaultLoopContextBuilder (spec §3.4).

Pure composition: read state, read catalog, call providers for subgraph /
observations, freeze into a LoopContext. v0.7.0 keeps providers pluggable
so v0.7.3 (Handbooks) and v0.7.5 (AttackChain wiring) can substitute them.
"""
from __future__ import annotations

from collections.abc import Callable

from ...domain.catalog.models import TestCatalog
from ...domain.reasoning_loop.models import (
    AvailableCapability,
    HandbookSummary,
    LoopContext,
    LoopId,
    ObservationSummary,
)
from ..ports.loop_context import LoopContextBuilder
from ..ports.loop_state import LoopStateRepository
from .handbook_selector import HandbookSelector
from .summarizer import ObservationSummarizer

AssetSubgraphProvider = Callable[[str], tuple[str, ...]]
ObservationProvider = Callable[[LoopId], tuple[ObservationSummary, ...]]
ToolCapabilityProvider = Callable[[str], tuple[AvailableCapability, ...]]

# v0.7.4 Task 2: handbook injection knobs. ``_HANDBOOK_ASSET_CLASS`` is a single
# constant so the asset-class mapping can be swapped for a real classifier in a
# later milestone (see the milestone Open/Notes). ``_HANDBOOK_K`` and
# ``_HANDBOOK_MAX_TOKENS`` bound the number of hints and their token weight.
_HANDBOOK_ASSET_CLASS = "web"
_HANDBOOK_K = 3
_HANDBOOK_MAX_TOKENS = 400
# Capped dictionary size for observation-derived keywords so the selector call
# never explodes in cardinality.
_HANDBOOK_KEYWORD_CAP = 8


class DefaultLoopContextBuilder(LoopContextBuilder):
    def __init__(
        self,
        *,
        catalog: TestCatalog,
        state_repo: LoopStateRepository,
        asset_subgraph_provider: AssetSubgraphProvider,
        observation_provider: ObservationProvider,
        tool_provider: ToolCapabilityProvider | None = None,
        summarizer: ObservationSummarizer | None = None,
        handbook_selector: HandbookSelector | None = None,
    ) -> None:
        self._catalog = catalog
        self._state_repo = state_repo
        self._asset_provider = asset_subgraph_provider
        self._observation_provider = observation_provider
        # ``tool_provider`` supplies the registered scan-tool capabilities the
        # proposer may route ``run_tool`` work to. It is a per-assessment
        # callable (assessment_id -> the tools in scope/catalogued) so the
        # SchemaGate's SCHEMA_UNKNOWN_TOOL check has a real, knowledge-backed
        # capability set instead of the empty tuple (the v0.7.1 seam fix; it
        # was "built but not wired"). Defaults to empty so callers that don't
        # surface tools (older unit tests) get no loadable tools.
        self._tool_provider = tool_provider
        # ``summarizer`` (v0.7.3 Task 4) applies the 3-tier observation
        # compression before the window is embedded in LoopContext. Defaults to
        # None = raw passthrough (the pre-v0.7.3 behavior), so existing callers
        # and unit tests that don't inject it keep the uncompressed window and
        # the raw token sum.
        self._summarizer = summarizer
        # ``handbook_selector`` (v0.7.4 Task 2) distills curated handbooks into
        # LoopContext.handbook_hints after ranking them against observation
        # keywords. Defaults to None = no handbook injection, keeping older
        # callers/tests unchanged. The hint token weight is bounded by
        # ``_HANDBOOK_MAX_TOKENS`` inside the selector, so BudgetGate sees a
        # capped contribution from handbooks.
        self._handbook_selector = handbook_selector

    def _derive_keywords(
        self, recent_observations: tuple[ObservationSummary, ...]
    ) -> tuple[str, ...]:
        """Flatten observation key_signals into a capped, deduped keyword tuple."""
        seen: list[str] = []
        for obs in recent_observations:
            for signal in obs.key_signals:
                lowered = str(signal).lower()
                if lowered not in seen:
                    seen.append(lowered)
        return tuple(seen[:_HANDBOOK_KEYWORD_CAP])

    def _select_handbook_hints(self, keywords: tuple[str, ...]) -> tuple[HandbookSummary, ...]:
        if self._handbook_selector is None or not keywords:
            return ()
        selected = self._handbook_selector.select(
            asset_class=_HANDBOOK_ASSET_CLASS,
            keywords=keywords,
            k=_HANDBOOK_K,
            max_tokens=_HANDBOOK_MAX_TOKENS,
        )
        return tuple(
            HandbookSummary(
                id=h.id,
                title=h.title,
                attack_surface=tuple(sorted(h.attack_surface)),
                recon_endpoints=tuple(sorted(h.recon_endpoints)),
                payload_classes=tuple(sorted(h.payload_classes)),
                verification_hint=h.verification_hint,
            )
            for h in selected
        )

    def build(self, loop_id: LoopId) -> LoopContext:
        state = self._state_repo.get(loop_id)
        if state is None:
            raise ValueError(f"loop_id {loop_id.value!r} not found")
        assessment_id = state.assessment_id
        recent_observations = self._observation_provider(loop_id)
        if self._summarizer is not None:
            # v0.7.3 Task 4: compress the raw window; the summarized token count
            # replaces the raw sum so the proposer's observation budget reflects
            # what is actually surfaced.
            window = self._summarizer.summarize(recent_observations)
            recent_observations = window.observations
            token_count = window.tokens
        else:
            token_count = sum(o.token_estimate for o in recent_observations)
        # Registered scan-tool capabilities for this assessment (knowledgeed
        # source for the SchemaGate SCHEMA_UNKNOWN_TOOL check).
        available_tools = (
            self._tool_provider(assessment_id) if self._tool_provider else ()
        )

        # Compute catalog required classes from the catalog (per-assessment
        # mappings are out of scope for v0.7.0 — the state carries them).
        catalog_total = sum(len(c) for c in self._catalog.mappings.values())
        remaining = state.catalog_required_remaining
        executed_count = max(catalog_total - len(remaining), 0)
        # Empty catalog ⇒ zero floor classes catalogued ⇒ 0.0 progress (no
        # floor has been marked done). Matches the TDD contract below.
        progress = (executed_count / catalog_total) if catalog_total else 0.0

        # v0.7.4 Task 2: rank curated handbooks against observation keywords and
        # surface the top ones as LoopContext.handbook_hints (token-bounded to
        # _HANDBOOK_MAX_TOKENS inside the selector, so BudgetGate sees a capped
        # contribution).
        keywords = self._derive_keywords(recent_observations)
        handbook_hints = self._select_handbook_hints(keywords)

        return LoopContext(
            asset_subgraph=self._asset_provider(assessment_id),
            recent_observations=recent_observations,
            observation_token_count=token_count,
            catalog_already_executed=state.catalog_required_executed,
            catalog_still_required=remaining,
            catalog_floor_progress=progress,
            unconfirmed_candidates=(),
            confirmed_findings_recent=(),
            chain_hypotheses_pending=(),
            available_tools=available_tools,
            available_cases=(),
            available_peers=(),
            handbook_hints=handbook_hints,
            budget_remaining=state.budget.snapshot(),
            loop_step=0,  # orchestrator updates this on each step
            max_steps=50,
            elapsed_seconds=0,
        )
