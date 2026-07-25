# src/secopent/application/model_builder.py
"""ModelBuilder: import + human-validate + sign AppModels (§11.9, ADR-005).

The documented path imports a spec (OpenAPI/Postman/...) into a DRAFT AppModel
via an injected importer. A human then enriches it (states, invariants, field
trust boundaries, roles) and validates it; signing applies an Ed25519-style
signature over the model's stable digest.

Per the LLM边界, the LLM may PROPOSE a model (the traffic/LLM draft path) but it
can NEVER validate or sign - those are human-only actions. The signer is
injected (Ed25519 lives in infrastructure) so the application layer stays
framework-free.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import Any, Protocol, runtime_checkable

from ..domain.appmodel.lifecycle import AppModelStatus, can_transition
from ..domain.appmodel.models import AppModel
from ..domain.common.errors import DomainError

_HUMAN = "human"
_AGENT = "agent"


@runtime_checkable
class ModelImporter(Protocol):
    """Turns a source document into a DRAFT AppModel."""

    source_type: str

    def to_draft(self, data: Mapping[str, Any]) -> AppModel: ...


@runtime_checkable
class ModelSigner(Protocol):
    """Signs a model digest payload (Ed25519 in infrastructure)."""

    def sign(self, payload: bytes) -> str: ...


class ModelPermissionError(DomainError):
    """Raised when an agent attempts a human-only action (validate/sign)."""


class ModelNotFoundError(DomainError):
    """Raised when an app_id is not in the builder."""


class ModelTransitionError(DomainError):
    """Raised on an out-of-order lifecycle transition."""


class ModelBuilder:
    """Import, human-validate, and sign AppModels."""

    def __init__(
        self,
        importers: Mapping[str, ModelImporter],
        signer: ModelSigner | None = None,
    ) -> None:
        self._importers = dict(importers)
        self._signer = signer
        self._models: dict[str, AppModel] = {}

    def import_model(self, source_type: str, data: Mapping[str, Any]) -> AppModel:
        """Import a spec into a DRAFT AppModel and register it."""
        importer = self._importers.get(source_type)
        if importer is None:
            raise DomainError(f"no importer registered for source_type={source_type!r}")
        draft = importer.to_draft(data)
        self._models[draft.app_id] = draft
        return draft

    def register_proposed(self, model: AppModel) -> AppModel:
        """Register an LLM-proposed model (status LLM_PROPOSED)."""
        proposed = replace(model, status=AppModelStatus.LLM_PROPOSED)
        self._models[proposed.app_id] = proposed
        return proposed

    def get(self, app_id: str) -> AppModel:
        model = self._models.get(app_id)
        if model is None:
            raise ModelNotFoundError(f"app model not found: {app_id}")
        return model

    def validate(
        self,
        app_id: str,
        *,
        actor_role: str,
        corrections: AppModel | None = None,
    ) -> AppModel:
        """Human-only: apply human corrections and move to HUMAN_VALIDATED."""
        self._require_human(actor_role)
        current = self.get(app_id)
        self._check_transition(current.status, AppModelStatus.HUMAN_VALIDATED)
        base = corrections if corrections is not None else current
        validated = replace(base, app_id=app_id, status=AppModelStatus.HUMAN_VALIDATED)
        self._models[app_id] = validated
        return validated

    def sign(self, app_id: str, *, actor_role: str) -> AppModel:
        """Human-only: sign the model's stable digest and move to SIGNED."""
        self._require_human(actor_role)
        current = self.get(app_id)
        self._check_transition(current.status, AppModelStatus.SIGNED)
        if self._signer is None:
            raise DomainError("no signer configured for ModelBuilder")
        signature = self._signer.sign(current.digest.encode("utf-8"))
        signed = replace(current, status=AppModelStatus.SIGNED, signature=signature)
        self._models[app_id] = signed
        return signed

    def _check_transition(self, source: AppModelStatus, target: AppModelStatus) -> None:
        if not can_transition(source, target):
            raise ModelTransitionError(
                f"cannot transition model {source.value} -> {target.value}"
            )

    @staticmethod
    def _require_human(actor_role: str) -> None:
        if actor_role == _AGENT:
            raise ModelPermissionError(
                "agents cannot validate or sign app models (human-only action)"
            )
        if actor_role != _HUMAN:
            raise ModelPermissionError(f"unknown actor role: {actor_role!r}")
