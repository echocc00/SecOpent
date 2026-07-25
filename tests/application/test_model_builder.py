"""TDD tests for ModelBuilder lifecycle (M3 Task 4, §11.9 + LLM边界).

The ModelBuilder imports a DRAFT, a human validates (optionally applying
corrections), and signs the model's stable digest. The LLM may propose but can
never validate or sign (human-only). Transitions must follow the lifecycle order.
"""
from __future__ import annotations

import pytest

from secopent.application.model_builder import (
    ModelBuilder,
    ModelPermissionError,
    ModelTransitionError,
)
from secopent.domain.appmodel.lifecycle import AppModelStatus
from secopent.domain.appmodel.models import AppModel, Invariant
from secopent.infrastructure.model_sources.openapi import OpenApiImporter

_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Shop", "version": "1.0.0"},
    "paths": {"/checkout": {"post": {"operationId": "checkout"}}},
}


class FakeSigner:
    def sign(self, payload: bytes) -> str:
        return "sig:" + payload.hex()[:8]


@pytest.fixture
def builder() -> ModelBuilder:
    return ModelBuilder({"openapi": OpenApiImporter()}, signer=FakeSigner())


def test_import_produces_draft(builder: ModelBuilder) -> None:
    model = builder.import_model("openapi", _SPEC)
    assert model.status is AppModelStatus.DRAFT
    assert builder.get("shop").app_id == "shop"


def test_human_validate_moves_to_validated(builder: ModelBuilder) -> None:
    builder.import_model("openapi", _SPEC)
    validated = builder.validate("shop", actor_role="human")
    assert validated.status is AppModelStatus.HUMAN_VALIDATED


def test_agent_cannot_validate(builder: ModelBuilder) -> None:
    builder.import_model("openapi", _SPEC)
    with pytest.raises(ModelPermissionError):
        builder.validate("shop", actor_role="agent")


def test_validate_applies_human_corrections(builder: ModelBuilder) -> None:
    builder.import_model("openapi", _SPEC)
    current = builder.get("shop")
    enriched = AppModel(
        app_id="shop",
        version="1.0.0",
        states=("cart", "paid"),
        transitions=current.transitions,
        invariants=(Invariant(id="i1", expr="cart.total >= 0"),),
    )
    validated = builder.validate("shop", actor_role="human", corrections=enriched)
    assert validated.states == ("cart", "paid")
    assert validated.invariants[0].expr == "cart.total >= 0"
    assert validated.status is AppModelStatus.HUMAN_VALIDATED


def test_human_sign_moves_to_signed_with_signature(builder: ModelBuilder) -> None:
    builder.import_model("openapi", _SPEC)
    builder.validate("shop", actor_role="human")
    signed = builder.sign("shop", actor_role="human")
    assert signed.status is AppModelStatus.SIGNED
    assert signed.signature is not None
    assert signed.signature.startswith("sig:")


def test_signature_is_over_stable_digest(builder: ModelBuilder) -> None:
    builder.import_model("openapi", _SPEC)
    builder.validate("shop", actor_role="human")
    signed = builder.sign("shop", actor_role="human")
    assert signed.signature == "sig:" + signed.digest.encode("utf-8").hex()[:8]


def test_agent_cannot_sign(builder: ModelBuilder) -> None:
    builder.import_model("openapi", _SPEC)
    builder.validate("shop", actor_role="human")
    with pytest.raises(ModelPermissionError):
        builder.sign("shop", actor_role="agent")


def test_sign_before_validate_rejected(builder: ModelBuilder) -> None:
    builder.import_model("openapi", _SPEC)  # DRAFT
    with pytest.raises(ModelTransitionError):
        builder.sign("shop", actor_role="human")


def test_llm_proposed_then_human_validated(builder: ModelBuilder) -> None:
    draft = OpenApiImporter().to_draft(_SPEC)
    builder.register_proposed(draft)
    assert builder.get("shop").status is AppModelStatus.LLM_PROPOSED
    validated = builder.validate("shop", actor_role="human")
    assert validated.status is AppModelStatus.HUMAN_VALIDATED


def test_unknown_source_type_rejected(builder: ModelBuilder) -> None:
    from secopent.domain.common.errors import DomainError

    with pytest.raises(DomainError):
        builder.import_model("grpc", {})
