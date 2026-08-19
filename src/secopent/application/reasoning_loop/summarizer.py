# src/secopent/application/reasoning_loop/summarizer.py
"""ObservationSummarizer — 3-tier window compression (v0.7.3 Task 1, spec §8).

Windows are ordered newest-first (index 0 == most recent). Tiers:
- 0..4   full       : key_signals verbatim, has_full_text=True, full token cost
- 5..19  signal     : signal + path only, has_full_text=False, reduced token cost
- 20+     fingerprint: target_digest + confidence only, minimal token cost

Every observation is represented (none dropped outright) so the summarizer
remains composable with ``LoopContext.recent_observations`` (a
``tuple[ObservationSummary, ...]``). ``SummarizedWindow.tokens`` is the sum of
the compressed windows' per-observation ``token_estimate`` — the value
ContextBuilder feeds into ``LoopContext.observation_token_count``, so wiring it
in (v0.7.3 Task 4) is a drop-in.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ...domain.reasoning_loop.models import ObservationSummary

# Compression constants (token model — deterministic, testable).
FULL_TIER_LIMIT = 5         # first 5 observations: full text kept
SIGNAL_TIER_LIMIT = 20      # observations 5..19: signal + path only
# Signal tier cost: a path anchor plus a fixed charge per retained signal.
_SIGNAL_PATH_BASE = 40
_SIGNAL_PER_SIGNAL = 5
# Fingerprint tier cost: digest + confidence only, flat.
_FINGERPRINT_BASE = 20


@dataclass(frozen=True, slots=True)
class SummarizedWindow:
    """Compressed observation window with a degraded token estimate.

    ``observations`` is a ``tuple[ObservationSummary, ...]`` whose per-item
    ``token_estimate`` / ``has_full_text`` / ``key_signals`` reflect the tier
    each observation was compressed into. ``tokens`` is the total prompt cost
    of the window; ``dropped_count`` is the number of observations reduced to
    the most-degraded (fingerprint) tier — an explicit degradation signal for
    audit, rather than a silent cap.
    """

    observations: tuple[ObservationSummary, ...]
    tokens: int
    dropped_count: int


class ObservationSummarizer:
    """Applies the 3-tier compression strategy to an observation window."""

    def summarize(
        self, observations: Sequence[ObservationSummary]
    ) -> SummarizedWindow:
        window: list[ObservationSummary] = []
        dropped = 0
        for index, obs in enumerate(observations):
            if index < FULL_TIER_LIMIT:
                window.append(obs)  # full tier: verbatim
            elif index < SIGNAL_TIER_LIMIT:
                window.append(_to_signal(obs))
            else:
                window.append(_to_fingerprint(obs))
                dropped += 1
        compressed = tuple(window)
        return SummarizedWindow(
            observations=compressed,
            tokens=sum(w.token_estimate for w in compressed),
            dropped_count=dropped,
        )


def _to_signal(obs: ObservationSummary) -> ObservationSummary:
    """Signal tier: drop full text, keep signals + path, reduce token cost."""
    return ObservationSummary(
        observation_id=obs.observation_id,
        tool_or_case_id=obs.tool_or_case_id,
        target_digest=obs.target_digest,
        key_signals=obs.key_signals,
        confidence=obs.confidence,
        has_full_text=False,
        full_text_ref=None,
        token_estimate=_SIGNAL_PATH_BASE
        + _SIGNAL_PER_SIGNAL * len(obs.key_signals),
    )


def _to_fingerprint(obs: ObservationSummary) -> ObservationSummary:
    """Fingerprint tier: digest + confidence only, minimal token cost."""
    return ObservationSummary(
        observation_id=obs.observation_id,
        tool_or_case_id=obs.tool_or_case_id,
        target_digest=obs.target_digest,
        key_signals=(),
        confidence=obs.confidence,
        has_full_text=False,
        full_text_ref=None,
        token_estimate=_FINGERPRINT_BASE,
    )