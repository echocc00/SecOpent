"""TDD tests for the AppModel domain + lifecycle (M3 Task 1, §4.6/§11.9).

An AppModel is a versioned, signed formal description of an application's
business logic: a state machine (states + transitions), invariants
(e.g. ``cart.total >= 0``), fields with trust boundaries (server vs client
source), roles/capabilities, and idempotency flags. It moves through
DRAFT -> LLM_PROPOSED -> HUMAN_VALIDATED -> SIGNED -> PUBLISHED -> SUPERSEDED.
The digest covers the model CONTENT (stable across lifecycle) so the Ed25519
signature signs a stable target; the LLM may propose but never signs (LLM边界).
"""
from __future__ import annotations

import pytest

from secopent.domain.appmodel.lifecycle import (
    AppModelStatus,
    can_transition,
)
from secopent.domain.appmodel.models import (
    AppModel,
    Field,
    Invariant,
    Role,
    Transition,
)
from secopent.domain.common.errors import DomainValidationError


def _model(**overrides: object) -> AppModel:
    base: dict[str, object] = {
        "app_id": "shop",
        "version": "1.0.0",
        "states": ("anonymous", "logged_in", "cart", "paid"),
        "transitions": (
            Transition(
                id="t1",
                from_state="cart",
                to_state="paid",
                endpoint="POST /checkout",
                params=("cart_id",),
                idempotent=False,
            ),
        ),
        "invariants": (Invariant(id="i1", expr="cart.total >= 0"),),
        "fields": (
            Field(name="qty", type="int", range=(0, 1000), trusted_source="client"),
        ),
        "roles": (Role(id="buyer", capabilities=("checkout",)),),
    }
    base.update(overrides)
    return AppModel(**base)  # type: ignore[arg-type]


def test_transition_requires_core_fields() -> None:
    with pytest.raises(DomainValidationError):
        Transition(
            id="", from_state="a", to_state="b", endpoint="GET /", params=(), idempotent=True
        )


def test_invariant_requires_expr() -> None:
    with pytest.raises(DomainValidationError):
        Invariant(id="i", expr="")


def test_field_requires_name_and_trusted_source() -> None:
    with pytest.raises(DomainValidationError):
        Field(name="", type="int", range=None, trusted_source="client")
    with pytest.raises(DomainValidationError):
        Field(name="qty", type="int", range=None, trusted_source="alien")


def test_role_requires_id() -> None:
    with pytest.raises(DomainValidationError):
        Role(id="", capabilities=("x",))


def test_model_requires_app_id_version_states() -> None:
    with pytest.raises(DomainValidationError):
        _model(app_id="")
    with pytest.raises(DomainValidationError):
        _model(states=())


def test_model_defaults_to_draft_unsigned() -> None:
    model = _model()
    assert model.status is AppModelStatus.DRAFT
    assert model.signature is None
    assert model.idempotency == ()
    assert model.out_of_scope_rules == ()


def test_model_computes_digest() -> None:
    model = _model()
    assert model.digest.startswith("sha256:")


def test_digest_stable_across_identical_content() -> None:
    assert _model().digest == _model().digest


def test_digest_independent_of_status_and_signature() -> None:
    # The digest covers content only, so lifecycle/signature metadata must not
    # change it (the signature signs a stable digest).
    draft = _model()
    signed = AppModel(
        app_id="shop",
        version="1.0.0",
        states=("anonymous", "logged_in", "cart", "paid"),
        transitions=draft.transitions,
        invariants=draft.invariants,
        fields=draft.fields,
        roles=draft.roles,
        status=AppModelStatus.SIGNED,
        signature="sig-abc",
    )
    assert signed.digest == draft.digest


def test_digest_changes_with_content() -> None:
    a = _model()
    b = _model(invariants=(Invariant(id="i2", expr="cart.total <= 10000"),))
    assert a.digest != b.digest


def test_model_is_immutable() -> None:
    model = _model()
    with pytest.raises(AttributeError):
        model.version = "2.0.0"  # type: ignore[misc]


def test_lifecycle_has_six_states() -> None:
    assert {s.value for s in AppModelStatus} == {
        "draft",
        "llm_proposed",
        "human_validated",
        "signed",
        "published",
        "superseded",
    }


def test_lifecycle_valid_transitions() -> None:
    assert can_transition(AppModelStatus.DRAFT, AppModelStatus.LLM_PROPOSED)
    assert can_transition(AppModelStatus.DRAFT, AppModelStatus.HUMAN_VALIDATED)
    assert can_transition(AppModelStatus.LLM_PROPOSED, AppModelStatus.HUMAN_VALIDATED)
    assert can_transition(AppModelStatus.HUMAN_VALIDATED, AppModelStatus.SIGNED)
    assert can_transition(AppModelStatus.SIGNED, AppModelStatus.PUBLISHED)
    assert can_transition(AppModelStatus.PUBLISHED, AppModelStatus.SUPERSEDED)


def test_lifecycle_rejects_skipping_to_published() -> None:
    assert not can_transition(AppModelStatus.DRAFT, AppModelStatus.PUBLISHED)
    assert not can_transition(AppModelStatus.SIGNED, AppModelStatus.SUPERSEDED)
    # SUPERSEDED is terminal.
    assert not can_transition(AppModelStatus.SUPERSEDED, AppModelStatus.DRAFT)
