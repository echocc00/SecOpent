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
import re

from ...domain.reasoning_loop.models import (
    LoopContext,
    ObservationSummary,
    ProposeAction,
)

_SECTION_HEADERS: tuple[str, ...] = (
    "[ASSETS]",
    "[OBSERVATIONS]",
    "[CATALOG]",
    "[HYPOTHESES]",
    "[BUDGET]",
    "[HISTORY]",
)

# ``full_text_ref`` MUST be a site-relative path — never a raw URL / absolute
# URI. Anything else (http(s)://..., data:, //host, etc.) is stripped to keep
# the serializer's no-raw-URL contract (§10). ASCII path chars + '/' '.' '-' '_'.
_RELATIVE_REF_RE = re.compile(r"^[a-zA-Z0-9_./-]+$")
_URL_PREFIXES: tuple[str, ...] = ("http://", "https://", "//", "data:", "file:")


def _sanitize_full_text_ref(ref: str | None) -> str | None:
    """Return ``ref`` only if it is a safe relative path, else ``None``.

    Prevents an upstream producer from smuggling an absolute URL / scheme
    prefix into the LLM prompt. ``None`` omits the field entirely.
    """
    if ref is None:
        return None
    lowered = ref.lower()
    if any(lowered.startswith(p) for p in _URL_PREFIXES):
        return None
    if not _RELATIVE_REF_RE.fullmatch(ref):
        return None
    return ref


def _project_observation(obs: ObservationSummary) -> dict[str, object]:
    """Project one ``ObservationSummary`` onto its serializable dict.

    Only the summary fields are emitted (never the raw evidence body); the
    ``full_text_ref`` is sanitized to a relative path (dropped if invalid).
    """
    projected: dict[str, object] = {
        "observation_id": obs.observation_id,
        "tool_or_case_id": obs.tool_or_case_id,
        "target_digest": obs.target_digest,
        "key_signals": list(obs.key_signals),
        "confidence": obs.confidence,
        "has_full_text": obs.has_full_text,
        "token_estimate": obs.token_estimate,
    }
    sanitized_ref = _sanitize_full_text_ref(obs.full_text_ref)
    if sanitized_ref is not None:
        projected["full_text_ref"] = sanitized_ref
    return projected


def _document(ctx: LoopContext) -> dict[str, object]:
    """Build the fixed-structure JSON document (no raw URLs / PII)."""
    return {
        "assets": list(ctx.asset_subgraph),
        "observations": [
            _project_observation(obs)
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