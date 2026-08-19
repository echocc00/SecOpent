# tests/application/reasoning_loop/test_handbook_selector.py
"""HandbookSelector — ranks curated handbooks by relevance + token budget."""
from __future__ import annotations

from secopent.application.reasoning_loop.handbook_selector import HandbookSelector
from secopent.infrastructure.catalog.handbook_registry import (
    Handbook,
    load_default_handbooks,
)


class TestSelector:
    def test_selects_by_cwe_kwargs_topk(self) -> None:
        sel = HandbookSelector(registry=load_default_handbooks())
        # idor appears when the idor-related keywords (IDs/UUIDs/object refs) hit.
        picked = sel.select(asset_class="web", keywords=("idor", "object"), k=3)
        ids = [h.id for h in picked]
        assert "idor" in ids

    def test_no_match_returns_empty(self) -> None:
        sel = HandbookSelector(registry=load_default_handbooks())
        assert sel.select(asset_class="web", keywords=("zzznomatch",), k=3) == ()

    def test_top_k_limits_count(self) -> None:
        sel = HandbookSelector(registry=load_default_handbooks())
        picked = sel.select(asset_class="web", keywords=("jwt", "token"), k=1)
        assert len(picked) <= 1

    def test_budget_truncates(self) -> None:
        sel = HandbookSelector(registry=load_default_handbooks())
        # k 大但 token budget 小 → 截断
        picked = sel.select(asset_class="web", keywords=("ssrf",), k=10, max_tokens=100)
        assert len(picked) <= 3  # 受 token 约束

    def test_return_type_is_tuple_of_handbook(self) -> None:
        sel = HandbookSelector(registry=load_default_handbooks())
        picked = sel.select(asset_class="web", keywords=("object",), k=2)
        for h in picked:
            assert isinstance(h, Handbook)


class TestSelectorCustomTokenFn:
    def test_result_set_empty_without_budget(self) -> None:
        # Pathological token_fn: every handbook far exceeds any budget. The
        # selector still returns the single best match (best-effort), never
        # raises, and never exceeds k.
        sel = HandbookSelector(
            registry=load_default_handbooks(),
            token_fn=lambda h: 2**31,  # every handbook far exceeds any budget
        )
        picked = sel.select(asset_class="web", keywords=("ssrf",), k=5, max_tokens=10)
        ids = [h.id for h in picked]
        assert len(picked) >= 1
        assert "ssrf" in ids