# src/secopent/application/reasoning_loop/llm_backend.py
"""LLM-backend abstraction for the loop proposer (spec §4).

The proposer calls NOTHING directly; it depends on ``LoopLLMBackend``
(implemented in infrastructure, e.g. RemoteOpenAICompatibleBackend /
OllamaBackend behind RemoteModelGateway). Errors are typed so the
degradation policy can distinguish retryable from fatal.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

from ...domain.common.errors import DomainError


class LLMBackendUnavailable(DomainError):
    """The configured LLM backend is down / not configured."""


class LLMBackendProtocolError(DomainError):
    """The backend returned non-JSON or schema-violating output."""


class ProposalOutcome(Enum):
    OK = "ok"
    RETRYABLE = "retryable"            # bad JSON / schema — nudge context, retry
    POLICY_BLOCKED = "policy_blocked"  # repeated failure — stop loop
    BACKEND_UNAVAILABLE = "backend_unavailable"  # fatal — degrade to catalog


@runtime_checkable
class LoopLLMBackend(Protocol):
    """One complete() call; may raise LLMBackendUnavailable."""

    def complete(self, prompt: str) -> str: ...


@dataclass(frozen=True, slots=True)
class LLMProposalResult:
    """Outcome of one propose() attempt."""

    outcome: ProposalOutcome
    action: object | None = None      # ProposeAction when OK
    error: str = ""
    attempts: int = 0