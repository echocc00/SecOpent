"""LLM backend abstraction (Phase A Task A1, Step 5).

Per design §12.8 (RemoteModelGateway) + §12.11 (LLM operational constraints):
- LLM ONLY proposes/drafts; never decides (§4.9 LLM boundary).
- Data classification: Secret never sent, Restricted denied, Sensitive redacted.
- Budget/rate limits + degradation: remote -> local -> stop agent (keep catalog).

This module defines the LLMBackend Protocol (interface), a remote
OpenAI-compatible backend, and a local Ollama backend (v0.5.0 Phase 3, 3.4).

Decision (Phase A): use remote large model (MiniMax/DeepSeek/Claude/GPT) as
primary; since v0.5.0 the backend is config-driven (config/llm.yaml,
``backend: remote | ollama | null``) with a local Ollama option for
air-gapped / cost-sensitive deployments.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class LLMResponse:
    """A response from an LLM backend."""

    text: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    finish_reason: str  # "stop" | "length" | "error" | ...


class LLMBackend(Protocol):
    """Interface for LLM backends (remote or local).

    Implementations:
    - RemoteOpenAICompatibleBackend: any OpenAI-compatible API (MiniMax/DeepSeek/Qwen/Claude/GPT)
    - OllamaBackend: a locally running ``ollama serve`` (v0.5.0 Phase 3, 3.4)
    - NullModelBackend: offline no-op fallback (application layer)
    """

    def generate(
        self,
        *,
        messages: list[dict[str, str]],
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> LLMResponse:
        """Generate a completion. Raises LLMError on failure (caller handles degradation)."""
        ...

    def is_available(self) -> bool:
        """Return True if the backend is configured and reachable."""
        ...


class LLMError(Exception):
    """LLM backend failure (network, auth, rate limit, etc.). Caller degrades."""


# Backend selection is config-driven (config/llm.yaml). The RemoteModelGateway
# (application/remote_model.py) injects the chosen backend. Local backend is a
# future implementation point - the Protocol above is the contract.
