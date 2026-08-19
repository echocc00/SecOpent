# src/secopent/application/reasoning_loop/handbook_selector.py
"""HandbookSelector — pick the most relevant curated handbooks for a loop step.

Given an asset class and observation keywords, rank the packaged handbooks by
signal overlap (CWE / OWASP / keyword hits against attack_surface and
recon_endpoints) and return the top-k that fit inside a token budget. The
payload is consumed as *context hints* by the planner/LLM — never executed
directly (the case engine + oracle are the execution/vetting path).
"""
from __future__ import annotations

from collections.abc import Callable

from secopent.infrastructure.catalog.handbook_registry import Handbook, HandbookRegistry


def _default_token_fn(handbook: Handbook) -> int:
    """Estimate tokens as roughly a quarter of the payload text length.

    Itemises payload_classes + attack_surface only (the curated, dense hints
    the LLM actually consumes); provenance/verification metadata is excluded.
    """
    text = " ".join((*handbook.attack_surface, *handbook.payload_classes))
    return max(1, len(text) // 4)


class HandbookSelector:
    """Deterministic relevance ranking over a HandbookRegistry."""

    def __init__(
        self,
        registry: HandbookRegistry,
        *,
        token_fn: Callable[[Handbook], int] | None = None,
    ) -> None:
        self._handbooks = registry.all()
        self._token_fn = token_fn or _default_token_fn

    @staticmethod
    def _keyword_score(handbook: Handbook, keywords: tuple[str, ...]) -> int:
        # Keywords are matched against CWE/OWASP ids, the handbook id (so a
        # published name like "ssrf" finds its handbook), and the attack_surface
        # / recon_endpoints text the LLM actually consumes.
        id_hit = sum(1 for kw in keywords if kw in handbook.id.lower())
        return (
            id_hit
            + sum(
                1
                for cwe in handbook.cwe
                if any(kw in cwe.lower() for kw in keywords)
            )
            + sum(
                1
                for owasp in handbook.owasp
                if any(kw in owasp.lower() for kw in keywords)
            )
            + sum(
                1
                for field in (*handbook.attack_surface, *handbook.recon_endpoints)
                if any(kw in field.lower() for kw in keywords)
            )
        )

    def select(
        self,
        asset_class: str,
        keywords: tuple[str, ...],
        *,
        k: int = 3,
        max_tokens: int = 2048,
    ) -> tuple[Handbook, ...]:
        """Return the top-k matching handbooks, token-truncated to max_tokens.

        asset_class is accepted for interface stability (a dedicated asset-class
        mapping lands in a later milestone; "web" is the safe default). Only
        handbooks with at least one signal match are considered; the best match
        is always included even if it alone exceeds the token budget, then
        further candidates are dropped once the running total would exceed it.
        """
        del asset_class
        keywords = tuple(str(kw).lower() for kw in keywords)
        ranked = sorted(
            (
                (self._keyword_score(h, keywords), h)
                for h in self._handbooks
                if self._keyword_score(h, keywords) > 0
            ),
            key=lambda pair: (-pair[0], pair[1].id),
        )

        picked: list[Handbook] = []
        running = 0
        for _score, handbook in ranked[:k]:
            tokens = self._token_fn(handbook)
            if picked and running + tokens > max_tokens:
                break
            picked.append(handbook)
            running += tokens
        return tuple(picked)


__all__ = ["HandbookSelector", "_default_token_fn"]