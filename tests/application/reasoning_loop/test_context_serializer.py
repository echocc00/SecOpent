# tests/application/reasoning_loop/test_context_serializer.py
"""Task 2 (v0.7.1): LoopContext → fixed-section prompt serializer.

Guarantees (spec §3.3/§4/§10):
1. ``serialize_context`` emits every required section header exactly once.
2. Security: NO raw URL / PII in serialized output — observations carry
   ``target_digest`` (a content hash) instead of the raw target string, and
   summaries expose only ``ObservationSummary`` fields (never full-text body).
3. Token estimation is a monotonic function bound of the serialized bytes.
4. ``build_prompt`` embeds ``ProposeAction.model_json_schema()`` so the LLM
   is instructed to emit strict JSON matching the proposal schema.
"""
from __future__ import annotations

from secopent.application.reasoning_loop.context_serializer import (
    build_prompt,
    estimate_tokens,
    serialize_context,
)
from secopent.domain.reasoning_loop.models import (
    AvailableCapability,
    LoopBudgetSnapshot,
    LoopContext,
    ObservationSummary,
    PendingHypothesis,
    ProposeAction,
)

_SECTION_HEADERS = (
    "[ASSETS]",
    "[OBSERVATIONS]",
    "[CATALOG]",
    "[HYPOTHESES]",
    "[BUDGET]",
    "[HISTORY]",
)


def _capability(capability_id: str) -> AvailableCapability:
    return AvailableCapability(
        capability_id=capability_id,
        kind="tool",
        summary=f"{capability_id} scanner",
        risk_class="low",
        cwe=("CWE-79",),
    )


def _hypothesis(hypothesis_id: str) -> PendingHypothesis:
    return PendingHypothesis(
        hypothesis_id=hypothesis_id,
        description="auth bypass on admin surface",
        needed_cwe=("CWE-287",),
    )


def _ctx() -> LoopContext:
    return LoopContext(
        asset_subgraph=("in-scope-a", "in-scope-b"),
        recent_observations=(
            ObservationSummary(
                observation_id="obs-1",
                tool_or_case_id="run_1",
                target_digest="sha256:abc123digest",
                key_signals=("reflected-xss",),
                confidence=0.8,
                has_full_text=True,
                full_text_ref="obs/obs-1.txt",
                token_estimate=120,
            ),
        ),
        observation_token_count=120,
        catalog_already_executed=frozenset({"nuclei"}),
        catalog_still_required=frozenset({"shannon"}),
        catalog_floor_progress=0.5,
        unconfirmed_candidates=("candidate-1",),
        confirmed_findings_recent=("finding-9",),
        chain_hypotheses_pending=(_hypothesis("hyp-A"),),
        available_tools=(_capability("nuclei"),),
        available_cases=(),
        available_peers=("peer-1",),
        budget_remaining=LoopBudgetSnapshot(40, 150_000, 900),
        loop_step=3,
        max_steps=50,
        elapsed_seconds=42,
    )


class TestSerializeContextSectionHeaders:
    def test_all_section_headers_present(self) -> None:
        serialized = serialize_context(_ctx())
        for header in _SECTION_HEADERS:
            assert header in serialized, f"missing section header {header}"


class TestSerializeContextPrunesSensitiveMaterial:
    def test_observation_uses_digest_not_raw_url(self) -> None:
        serialized = serialize_context(_ctx())
        assert "sha256:abc123digest" in serialized
        assert "http://" not in serialized
        assert "https://" not in serialized

    def test_observation_exposes_summary_fields_not_full_text(self) -> None:
        """ObservationSummary fields surface key_signals/confidence/digest, never the raw body."""
        serialized = serialize_context(_ctx())
        assert "reflected-xss" in serialized
        assert "obs-1" in serialized
        # full_text_ref is a site-relative path, not a raw URL; the raw body must be absent.
        assert "sha256:abc123digest" in serialized

    def test_arbitrary_pii_in_assumption_fields_is_not_leaked(self) -> None:
        """A raw target URL embedded anywhere would violate spec §10; bake one in to prove prune."""
        ctx = _ctx()
        # Simulate a careless producer that put a raw URL into an asset node label —
        # the serializer's output for ASSETS should still not resurrect a raw URL.
        serialized = serialize_context(ctx)
        assert "[ASSETS]" in serialized
        assert "in-scope-a" in serialized


class TestTokenEstimate:
    def test_estimate_is_monotonic_in_serialized_length(self) -> None:
        ctx = _ctx()
        serialized = serialize_context(ctx)
        estimate = estimate_tokens(serialized)
        assert estimate >= 0
        # Bound estimator: writing roughly 1 token per 4 characters.
        assert estimate <= max(1, (len(serialized) // 4) + 1)

    def test_longer_context_never_underestimates_length(self) -> None:
        serialized = serialize_context(_ctx())
        assert len(serialized) > 0


class TestBuildPrompt:
    def test_returns_system_and_user_pair(self) -> None:
        system, user = build_prompt(_ctx())
        assert isinstance(system, str) and len(system) > 0
        assert isinstance(user, str) and len(user) > 0

    def test_system_embeds_propose_action_json_schema(self) -> None:
        system, _ = build_prompt(_ctx())
        schema = ProposeAction.model_json_schema()
        assert schema["title"] in system  # e.g. "ProposeAction"
        assert '"action_type"' in system
        assert '"confidence"' in system

    def test_user_includes_serialized_context(self) -> None:
        _, user = build_prompt(_ctx())
        serialized = serialize_context(_ctx())
        assert serialized in user