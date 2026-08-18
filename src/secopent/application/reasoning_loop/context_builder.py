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
    LoopContext,
    LoopId,
    ObservationSummary,
)
from ..ports.loop_context import LoopContextBuilder
from ..ports.loop_state import LoopStateRepository

AssetSubgraphProvider = Callable[[str], tuple[str, ...]]
ObservationProvider = Callable[[LoopId], tuple[ObservationSummary, ...]]


class DefaultLoopContextBuilder(LoopContextBuilder):
    def __init__(
        self,
        *,
        catalog: TestCatalog,
        state_repo: LoopStateRepository,
        asset_subgraph_provider: AssetSubgraphProvider,
        observation_provider: ObservationProvider,
    ) -> None:
        self._catalog = catalog
        self._state_repo = state_repo
        self._asset_provider = asset_subgraph_provider
        self._observation_provider = observation_provider

    def build(self, loop_id: LoopId) -> LoopContext:
        state = self._state_repo.get(loop_id)
        if state is None:
            raise ValueError(f"loop_id {loop_id.value!r} not found")
        assessment_id = state.assessment_id
        recent_observations = self._observation_provider(loop_id)
        token_count = sum(o.token_estimate for o in recent_observations)

        # Compute catalog required classes from the catalog (per-assessment
        # mappings are out of scope for v0.7.0 — the state carries them).
        catalog_total = sum(len(c) for c in self._catalog.mappings.values())
        remaining = state.catalog_required_remaining
        executed_count = max(catalog_total - len(remaining), 0)
        # Empty catalog ⇒ zero floor classes catalogued ⇒ 0.0 progress (no
        # floor has been marked done). Matches the TDD contract below.
        progress = (executed_count / catalog_total) if catalog_total else 0.0

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
            available_tools=(),
            available_cases=(),
            available_peers=(),
            budget_remaining=state.budget.snapshot(),
            loop_step=0,  # orchestrator updates this on each step
            max_steps=50,
            elapsed_seconds=0,
        )
