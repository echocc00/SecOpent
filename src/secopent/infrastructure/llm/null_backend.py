"""Null LLM backend (offline/degraded fallback).

Satisfies the application-layer ModelBackend Protocol with a no-op completion.
Used when no real LLM is configured so LLM-assisted endpoints degrade to their
deterministic path (an empty completion fails JSON parsing and the caller falls
back to the rule-computed result). The LLM is never allowed to decide - an
empty proposal simply means "no LLM suggestion", and the deterministic layer's
result stands.
"""
from __future__ import annotations


class NullModelBackend:
    """A model backend that returns an empty completion (offline fallback)."""

    def complete(self, prompt: str) -> str:  # noqa: ARG002 - prompt intentionally unused
        return ""
