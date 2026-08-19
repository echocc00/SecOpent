# src/secopent/application/reasoning_loop/context_serializer.py
"""LoopContext → fixed-section prompt (spec §3.3/§4/§10).

The proposer never receives the raw ``LoopContext`` dataclass; it receives a
dead-string prompt built by ``serialize_context``. The serializer is the
single choke point that enforces the §10 privacy contract:

* observations are reduced to their ``ObservationSummary`` projection — the
  raw evidence body is never embedded;
* raw target URLs / PII are represented only by their content-addressed
  ``target_digest`` hash.

``build_prompt`` wraps the serialized context in a system/user pair, pinning
``ProposeAction.model_json_schema()`` into the system frame so the LLM is
instructed to emit strict JSON matching that schema.
"""
from __future__ import annotations

import json

from ...domain.reasoning_loop.models import LoopContext, ProposeAction

_SECTION_HEADERS: tuple[str, ...] = (
    "[ASSETS]",
    "[OBSERVATIONS]",
    "[CATALOG]",
    "[HYPOTHESES]",
    "[BUDGET]",
    "[HISTORY]",
)

# Spec §10: observations carry only the digest, never a raw URL/PII target.
_OBSERVATION_KEYS: tuple[str, ...] = (
    "observation_id",
    "tool_or_case_id",
    "target_digest",
    "key_signals",
    "confidence",
    "has_full_text",
    "full_text_ref",
    "token_estimate",
)


def _document(ctx: LoopContext) -> dict[str, object]:
    """Build the fixed-structure JSON document (no raw URLs / PII)."""
    return {
        "assets": list(ctx.asset_subgraph),
        "observations": [
            {
                key: (
                    list(getattr(obs, key))
                    if key == "key_signals"
                    else getattr(obs, key)
                )
                for key in _OBSERVATION_KEYS
                if getattr(obs, key) is not None or key != "full_text_ref"
            }
            for obs in ctx.recent_observations
        ],
        "catalog": {
            "already_executed": sorted(ctx.catalog_already_executed),
            "still_required": sorted(ctx.catalog_still_required),
            "floor_progress": ctx.catalog_floor_progress,
        },
        "hypotheses": [
            {
                "hypothesis_id": h.hypothesis_id,
                "description": h.description,
                "needed_cwe": list(h.needed_cwe),
            }
            for h in ctx.chain_hypotheses_pending
        ],
        "budget": {
            "steps_remaining": ctx.budget_remaining.steps_remaining,
            "tokens_remaining": ctx.budget_remaining.tokens_remaining,
            "wall_seconds_remaining": ctx.budget_remaining.wall_seconds_remaining,
        },
        "history": {
            "loop_step": ctx.loop_step,
            "max_steps": ctx.max_steps,
            "elapsed_seconds": ctx.elapsed_seconds,
            "unconfirmed_candidates": list(ctx.unconfirmed_candidates),
            "confirmed_findings_recent": list(ctx.confirmed_findings_recent),
        },
        "audit": {
            "observation_token_count": ctx.observation_token_count,
            "context_hash": ctx.context_hash(),
        },
    }


def serialize_context(ctx: LoopContext) -> str:
    """Render ``ctx`` as a fixed-section, indented JSON string.

    Section headers annotate the major blocks; observation entries carry only
    the ``ObservationSummary`` projection (digest, never a raw URL).
    """
    doc = _document(ctx)
    sections: list[str] = []
    ordered = (
        ("[ASSETS]", {"assets": doc["assets"]}),
        ("[OBSERVATIONS]", {"observations": doc["observations"]}),
        ("[CATALOG]", {"catalog": doc["catalog"]}),
        ("[HYPOTHESES]", {"hypotheses": doc["hypotheses"]}),
        ("[BUDGET]", {"budget": doc["budget"]}),
        ("[HISTORY]", {"history": doc["history"]}),
        ("[AUDIT]", {"audit": doc["audit"]}),
    )
    for header, payload in ordered:
        sections.append(f"{header}\n{json.dumps(payload, indent=2)}")
    return "\n\n".join(sections)


def estimate_tokens(serialized: str) -> int:
    """Rough upper-bound token estimate for a serialized prompt.

    Heuristic: ~4 characters per token, plus a safety margin. Used by the
    budget/audit path to keep prompt cost visible; exact tokenization is done
    by the LLM provider, not here.
    """
    return max(1, len(serialized) // 4)


_SYSTEM_TEMPLATE = (
    "You are the action proposer for an autonomous authorized-pentest loop.\n"
    "Decide the NEXT single action to take, given the context block below.\n"
    "You MUST answer with a single strict-JSON object matching this schema:\n"
    "{schema}\n"
    "Emit ONLY valid JSON — never markdown fences, no commentary outside JSON,\n"
    "and never fabricate data not present in the context. Use the values as-is;\n"
    "do not invent tools, hypotheses, or peers that are not listed.\n"
)


def build_prompt(ctx: LoopContext) -> tuple[str, str]:
    """Return ``(system, user)`` for the LLM proposer call.

    ``system`` embeds ``ProposeAction.model_json_schema()`` so the model is
    told the exact strict schema up front; ``user`` carries the serialized
    (pruned) context.
    """
    schema = ProposeAction.model_json_schema()
    system = _SYSTEM_TEMPLATE.format(schema=json.dumps(schema, indent=2))
    user = serialize_context(ctx)
    return system, user