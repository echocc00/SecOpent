# src/secopent/application/remote_model.py
"""RemoteModelGateway: governed LLM access with operational constraints (§12.11).

Every model call flows through: data classification -> redaction -> policy ->
audit. Rules:

- **Secret** data is NEVER sent (raises); **Restricted** is default-deny;
  **Sensitive** is redacted before sending.
- **Local-first**: a local model (Ollama/vLLM) serves by default so scanning
  works with no external LLM; a remote API (Claude/GPT) is used only when
  preferred AND within budget.
- **Operational constraints**: daily token budget (default 500K), rate limit
  (default 10 req/min), prompt size cap (default 32K). Exceeding budget or rate
  degrades to local. Alert thresholds at 80% (warn) and 100% (degrade).

The backend is an injected Protocol (local + optional remote); audit is optional.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol, runtime_checkable

from ..domain.common.errors import DomainError
from .evidence import Redactor


class DataClassification(StrEnum):
    """Data sensitivity tiers governing model access."""

    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"
    SECRET = "secret"


class SecretNeverSent(DomainError):
    """Secret-classified data must never be sent to a model."""


class RestrictedDenied(DomainError):
    """Restricted data is default-deny for model access."""


class PromptTooLarge(DomainError):
    """The prompt exceeds the configured size cap."""


@dataclass(frozen=True, slots=True)
class ModelBudget:
    """LLM operational constraints (§12.11)."""

    daily_token_budget: int = 500_000
    rate_limit_per_min: int = 10
    prompt_size_cap: int = 32_000


@dataclass(frozen=True, slots=True)
class ModelResponse:
    """The result of a governed model call."""

    text: str
    backend: str  # "local" or "remote"
    degraded: bool  # True if constraints forced a fallback to local
    redacted: bool
    alert: str | None  # "budget_80_warn" / "budget_100_degrade" / None


@runtime_checkable
class ModelBackend(Protocol):
    """A model endpoint (local Ollama/vLLM or a remote API)."""

    def complete(self, prompt: str) -> str: ...


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


class RemoteModelGateway:
    """Govern model access: classification, redaction, budget, rate, audit."""

    def __init__(
        self,
        *,
        local_backend: ModelBackend,
        redactor: Redactor,
        remote_backend: ModelBackend | None = None,
        budget: ModelBudget | None = None,
        audit: object | None = None,
    ) -> None:
        self._local = local_backend
        self._remote = remote_backend
        self._redactor = redactor
        self._budget = budget or ModelBudget()
        self._audit = audit
        self._tokens_used = 0
        self._request_times: list[datetime] = []

    def call(
        self,
        prompt: str,
        *,
        classification: DataClassification,
        now: datetime,
        prefer_remote: bool = False,
    ) -> ModelResponse:
        # Classification policy.
        if classification is DataClassification.SECRET:
            raise SecretNeverSent("secret data must never be sent to a model")
        if classification is DataClassification.RESTRICTED:
            raise RestrictedDenied("restricted data is default-deny for model access")

        # Redaction (Sensitive is redacted before sending).
        text = prompt
        redacted = False
        if classification is DataClassification.SENSITIVE:
            text = self._redactor.redact(prompt).redacted_text
            redacted = True

        # Prompt size cap.
        if len(text) > self._budget.prompt_size_cap:
            raise PromptTooLarge(
                f"prompt length {len(text)} exceeds cap {self._budget.prompt_size_cap}"
            )

        estimate = _estimate_tokens(text)

        # Backend selection: local-first; remote only if preferred + available.
        use_remote = prefer_remote and self._remote is not None
        degraded = False
        if use_remote and (
            self._rate_exceeded(now)
            or self._tokens_used + estimate > self._budget.daily_token_budget
        ):
            use_remote = False
            degraded = True

        # Alert thresholds (projected usage after this call).
        ratio = (self._tokens_used + estimate) / self._budget.daily_token_budget
        alert: str | None = None
        if ratio >= 1.0:
            alert = "budget_100_degrade"
        elif ratio >= 0.8:
            alert = "budget_80_warn"

        backend: ModelBackend
        if use_remote and self._remote is not None:
            backend = self._remote
            backend_name = "remote"
        else:
            backend = self._local
            backend_name = "local"
        result = backend.complete(text)

        self._tokens_used += estimate
        self._request_times.append(now)
        self._record_audit(
            classification=classification,
            backend=backend_name,
            redacted=redacted,
            degraded=degraded,
            alert=alert,
            tokens=estimate,
        )
        return ModelResponse(
            text=result,
            backend=backend_name,
            degraded=degraded,
            redacted=redacted,
            alert=alert,
        )

    def _rate_exceeded(self, now: datetime) -> bool:
        window_start = now - timedelta(minutes=1)
        recent = [t for t in self._request_times if t >= window_start]
        return len(recent) >= self._budget.rate_limit_per_min

    def _record_audit(self, **fields: object) -> None:
        audit = self._audit
        if audit is None:
            return
        record = getattr(audit, "record", None)
        if record is None:
            return
        record(
            actor="model_gateway",
            action="model.call",
            resource_type="model",
            resource_id=str(fields.get("backend", "")),
            payload=fields,
        )
