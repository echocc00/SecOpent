# tests/application/reasoning_loop/test_summarizer.py
"""ObservationSummarizer — 3-tier window summarization (v0.7.3 Task 1).

Tiers (newest-first window, index 0..):
- 0..4   full       : key_signals verbatim, has_full_text=True, full token cost
- 5..19  signal     : signal + path only, has_full_text=False, reduced token cost
- 20+     fingerprint: digest + confidence only, minimal token cost

Every observation is represented; ``dropped_count`` counts the most-degraded
(fingerprint) tier for an explicit degradation signal.
"""
from __future__ import annotations

from collections.abc import Sequence

from secopent.application.reasoning_loop.summarizer import (
    ObservationSummarizer,
    SummarizedWindow,
)
from secopent.domain.reasoning_loop.models import ObservationSummary


def _obs(n: int, *, base_tokens: int = 100) -> ObservationSummary:
    return ObservationSummary(
        observation_id=f"obs-{n}",
        tool_or_case_id=f"tool-{n % 3}",
        target_digest=f"sha256:{n:064x}",
        key_signals=(f"sig-{n}", f"sig-{n + 1}"),
        confidence=0.8,
        has_full_text=True,
        full_text_ref=f"ev-{n}",
        token_estimate=base_tokens,
    )


def _make(n: int) -> list[ObservationSummary]:
    return [_obs(i) for i in range(n)]


def _window(make_n: int) -> SummarizedWindow:
    return ObservationSummarizer().summarize(_make(make_n))


class TestSummarizer:
    def test_first_five_full_text_signal_level(self) -> None:
        # n=3 → 全 signal 保留, has_full_text=True
        w = _window(3)
        assert w.dropped_count == 0
        assert len(w.observations) == 3
        for o in w.observations:
            assert o.has_full_text is True
            assert len(o.key_signals) == 2
            assert o.token_estimate == 100

    def test_5_20_signal_plus_path(self) -> None:
        # n=12 → 前 5 full, 6-12 压缩 signal+path (has_full_text=False)
        w = _window(12)
        assert w.dropped_count == 0
        assert len(w.observations) == 12
        # first 5 are full
        for o in w.observations[:5]:
            assert o.has_full_text is True
            assert len(o.key_signals) == 2
            assert o.token_estimate == 100
        # 6-12 are signal: has_full_text=False, signal kept, lower tokens than full
        for o in w.observations[5:]:
            assert o.has_full_text is False
            assert len(o.key_signals) == 2  # signal still present
            assert o.token_estimate < 100

    def test_beyond_20_fingerprint_only(self) -> None:
        # n=25 → >20 只 fingerprint (token_estimate 低)
        w = _window(25)
        assert w.dropped_count == 5  # index 20..24 are fingerprint tier
        assert len(w.observations) == 25
        for o in w.observations[:5]:
            assert o.has_full_text is True
        for o in w.observations[5:20]:
            assert o.has_full_text is False
            assert len(o.key_signals) == 2
        # fingerprint tier: digest + confidence only -> no signals, empty signal list
        for o in w.observations[20:]:
            assert o.has_full_text is False
            assert o.key_signals == ()
            assert o.token_estimate <= w.observations[5].token_estimate

    def test_token_estimate_correct(self) -> None:
        # token_estimate 随层压缩而降低; window.tokens 为各观察之和
        w12 = _window(12)
        assert w12.tokens == sum(o.token_estimate for o in w12.observations)
        # signal-tier observation cheaper than its full form (100)
        assert all(o.token_estimate < 100 for o in w12.observations[5:])
        # fingerprint-tier window strictly cheaper than signal-tier window
        w25 = _window(25)
        assert w25.tokens < w12.tokens * (25 / 12)
        assert w25.observations[20].token_estimate < w12.observations[5].token_estimate

    def test_empty_input(self) -> None:
        w = _window(0)
        assert w.observations == ()
        assert w.tokens == 0
        assert w.dropped_count == 0

    def test_observation_sequence_type(self) -> None:
        # Sequence[ObservationSummary] input, not just list
        seq: Sequence[ObservationSummary] = tuple(_make(3))
        w = ObservationSummarizer().summarize(seq)
        assert len(w.observations) == 3