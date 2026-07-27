# src/secopent/application/appmodels.py
"""AppModelService: AppModel lifecycle + human-only signing (§4.6/§11.9).

An AppModel moves DRAFT -> HUMAN_VALIDATED -> SIGNED (-> PUBLISHED via the
ModelRegistry). Per the LLM boundary, an agent may create/propose a model but a
HUMAN must validate and sign it. Signing applies an Ed25519-style signature over
the model's stable content digest (``CaseSigner``-compatible callable); the
signing key is held server-side and injected at the composition root.

Storage is injected behind the ``AppModelRegistry`` port (in-memory default for
tests, SqlAlchemy for the REST API), mirroring the CaseService pattern.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from typing import Protocol

from ..domain.appmodel.lifecycle import AppModelStatus, can_transition
from ..domain.appmodel.models import AppModel
from ..domain.common.errors import DomainError

# Signer signs the model digest bytes and returns a signature string.
ModelSigner = Callable[[bytes], str]

_HUMAN = "human"
_AGENT = "agent"


class AppModelNotFoundError(DomainError):
    """Raised when an (app_id, version) is unknown."""


class AppModelPermissionError(DomainError):
    """Raised when an agent attempts a human-only action (validate/sign)."""


class AppModelTransitionError(DomainError):
    """Raised on an out-of-order lifecycle transition."""


class AppModelRegistry(Protocol):
    """Storage port for AppModels (in-memory for tests, SqlAlchemy for prod)."""

    def put(self, model: AppModel) -> None: ...
    def get(self, app_id: str, version: str) -> AppModel | None: ...
    def list(self) -> list[AppModel]: ...


class InMemoryAppModelRegistry:
    """Default in-memory AppModelRegistry (tests)."""

    def __init__(self) -> None:
        self._models: dict[tuple[str, str], AppModel] = {}

    def put(self, model: AppModel) -> None:
        self._models[(model.app_id, model.version)] = model

    def get(self, app_id: str, version: str) -> AppModel | None:
        return self._models.get((app_id, version))

    def list(self) -> list[AppModel]:
        return [self._models[key] for key in sorted(self._models)]


class AppModelService:
    """Manage the AppModel lifecycle and enforce human-only validate/sign."""

    def __init__(self, registry: AppModelRegistry | None = None) -> None:
        self._registry: AppModelRegistry = registry or InMemoryAppModelRegistry()

    def create(self, model: AppModel) -> AppModel:
        """Register a model as a DRAFT (an agent may propose; a human may draft)."""
        draft = replace(model, status=AppModelStatus.DRAFT)
        self._registry.put(draft)
        return draft

    def get(self, app_id: str, version: str) -> AppModel:
        model = self._registry.get(app_id, version)
        if model is None:
            raise AppModelNotFoundError(f"app model not found: {app_id}@{version}")
        return model

    def list_all(self) -> list[AppModel]:
        return self._registry.list()

    def validate(self, app_id: str, version: str, *, actor_role: str) -> AppModel:
        """Human-only: advance to HUMAN_VALIDATED (a human has reviewed the model)."""
        self._require_human(actor_role)
        return self._transition(app_id, version, AppModelStatus.HUMAN_VALIDATED)

    def sign(
        self, app_id: str, version: str, *, signer: ModelSigner, actor_role: str
    ) -> AppModel:
        """Human-only: HUMAN_VALIDATED -> SIGNED, signing the content digest."""
        self._require_human(actor_role)
        model = self.get(app_id, version)
        self._check_transition(model, AppModelStatus.SIGNED)
        signed = replace(
            model,
            status=AppModelStatus.SIGNED,
            signature=signer(model.digest.encode("utf-8")),
        )
        self._registry.put(signed)
        return signed

    def _transition(
        self, app_id: str, version: str, to_status: AppModelStatus
    ) -> AppModel:
        model = self.get(app_id, version)
        self._check_transition(model, to_status)
        updated = replace(model, status=to_status)
        self._registry.put(updated)
        return updated

    @staticmethod
    def _check_transition(model: AppModel, to_status: AppModelStatus) -> None:
        if not can_transition(model.status, to_status):
            raise AppModelTransitionError(
                f"app model {model.app_id}@{model.version}: cannot transition "
                f"{model.status.value} -> {to_status.value}"
            )

    @staticmethod
    def _require_human(actor_role: str) -> None:
        if actor_role == _AGENT:
            raise AppModelPermissionError(
                "agents cannot validate or sign app models (human-only action)"
            )
        if actor_role != _HUMAN:
            raise AppModelPermissionError(f"unknown actor role: {actor_role!r}")
