# src/secopent/application/reasoning_loop/proposer.py
"""RealLoopActionProposer — LLM-backed action proposer (spec §4).

The proposer calls the injected ``LoopLLMBackend`` (implemented in
infrastructure, e.g. RemoteOpenAICompatibleBackend / OllamaBackend) with a
schema-pinned prompt built by ``context_serializer``, then strict-validates the
model's JSON into a ``ProposeAction``. Malformed or schema-violating output is
retried (``max_retries``) and typed as ``RETRYABLE``; an unavailable backend is
typed as ``BACKEND_UNAVAILABLE`` so the composition layer can apply the
degradation policy WITHOUT ever weakening the schema gate.

``propose`` returns a typed ``LLMProposalResult``, NOT a raw action: the
orchestrator's ``LoopActionProposer`` port expects ``ProposeAction | None``,
so the composition adapter maps non-OK outcomes to ``None`` (a transient
backend-unavailable step). This keeps the "LLM only proposes, Schema is strict"
boundary intact.
"""
from __future__ import annotations

import json
import re

from ...domain.reasoning_loop.models import LoopContext, ProposeAction
from .context_serializer import build_prompt
from .llm_backend import (
    LLMBackendUnavailable,
    LLMProposalResult,
    LoopLLMBackend,
    ProposalOutcome,
)


class RealLoopActionProposer:
    """Strict-JSON LLM proposer over a single ``LoopLLMBackend``."""

    def __init__(
        self,
        *,
        backend: LoopLLMBackend,
        max_retries: int = 1,
    ) -> None:
        self._backend = backend
        # Number of retries AFTER the model's first reply: total attempts
        # permitted is ``1 + max_retries``.
        self._max_retries = max_retries

    def propose(self, context: LoopContext) -> LLMProposalResult:
        """Ask the backend for the next action; return a typed result."""
        system, user = build_prompt(context)
        prompt = f"{system}\n\n{user}"
        max_attempts = 1 + self._max_retries
        last_error = ""
        for attempt in range(1, max_attempts + 1):
            try:
                raw = self._backend.complete(prompt)
            except LLMBackendUnavailable as exc:
                return LLMProposalResult(
                    outcome=ProposalOutcome.BACKEND_UNAVAILABLE,
                    error=str(exc),
                    attempts=attempt,
                )
            action, err = _parse_action(raw)
            if action is not None:
                return LLMProposalResult(
                    outcome=ProposalOutcome.OK,
                    action=action,
                    attempts=attempt,
                )
            last_error = err  # not the last allowed attempt -> retry with fresh JSON
        # Allowed attempts exhausted on bad output: retryable, not fatal.
        return LLMProposalResult(
            outcome=ProposalOutcome.RETRYABLE,
            error=last_error,
            attempts=max_attempts,
        )


_FENCE_OPEN = re.compile(r"^```[ \t]*[a-zA-Z0-9_-]*[ \t]*\r?\n?")
_FENCE_CLOSE = re.compile(r"\r?\n?[ \t]*```$")


def _strip_markdown_fence(raw: str) -> str:
    """Strip a ```json … ``` stub wrapper some models (e.g. MiniMax abab6.5s)
    put around JSON replies. Only a leading/trailing fence is removed; the
    payload itself is still strictly parsed by the caller."""
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = _FENCE_OPEN.sub("", cleaned)
        cleaned = _FENCE_CLOSE.sub("", cleaned).strip()
    return cleaned


def _parse_action(raw: str) -> tuple[ProposeAction | None, str]:
    """Strictly parse the backend's JSON into a ProposeAction.

    Returns ``(None, reason)`` when the output is malformed JSON or violates
    the strict schema (extra fields, invalid enum, missing payload keys), so
    the proposer can retry instead of fabricating a shape-valid action.
    """
    data: object
    try:
        data = json.loads(_strip_markdown_fence(raw))
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc}"
    if not isinstance(data, dict):
        return None, "JSON payload is not an object"
    try:
        action = ProposeAction.model_validate(data)
    except Exception as exc:  # pydantic ValidationError etc. -> schema violation
        return None, f"schema violation: {exc}"
    return action, ""