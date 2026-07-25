# src/secopent/domain/appmodel/models.py
"""AppModel domain: a versioned, signed formal description of app logic (§4.6).

An AppModel captures an application's business logic so the LogicTestGenerator
can deterministically derive logic tests (skip-step / out-of-order / replay /
boundary / invariant-violation):

- **states / transitions**: the state machine (a transition is an endpoint that
  moves the app from one state to another, with params and an idempotency flag);
- **invariants**: business rules that must always hold (e.g. ``cart.total >= 0``);
- **fields**: typed inputs with a trust boundary (``server`` vs ``client`` source)
  and an optional valid range (drives boundary testing);
- **roles**: actors and their capabilities (drives authz / privilege tests);
- **out_of_scope_rules**: complex rules a human declares the model does NOT cover.

The ``digest`` covers the model CONTENT only (stable across lifecycle), so the
Ed25519 ``signature`` signs a stable target. The LLM may propose a model but a
human validates and signs it (LLM边界).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..common.canonical import canonical_digest
from ..common.errors import DomainValidationError
from .lifecycle import AppModelStatus

# A field's trust boundary: where its authoritative value comes from.
_TRUSTED_SOURCES = frozenset({"server", "client"})


@dataclass(frozen=True, slots=True)
class Transition:
    """A state-machine transition: an endpoint moving from_state -> to_state."""

    id: str
    from_state: str
    to_state: str
    endpoint: str
    params: tuple[str, ...] = ()
    idempotent: bool = False

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError("Transition.id must be non-empty")
        if not self.from_state:
            raise DomainValidationError("Transition.from_state must be non-empty")
        if not self.to_state:
            raise DomainValidationError("Transition.to_state must be non-empty")
        if not self.endpoint:
            raise DomainValidationError("Transition.endpoint must be non-empty")


@dataclass(frozen=True, slots=True)
class Invariant:
    """A business rule that must always hold (e.g. ``cart.total >= 0``)."""

    id: str
    expr: str

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError("Invariant.id must be non-empty")
        if not self.expr:
            raise DomainValidationError("Invariant.expr must be non-empty")


@dataclass(frozen=True, slots=True)
class Field:
    """A typed input with a trust boundary and optional valid range."""

    name: str
    type: str
    range: tuple[object, object] | None = None
    trusted_source: str = "client"

    def __post_init__(self) -> None:
        if not self.name:
            raise DomainValidationError("Field.name must be non-empty")
        if not self.type:
            raise DomainValidationError("Field.type must be non-empty")
        if self.trusted_source not in _TRUSTED_SOURCES:
            raise DomainValidationError(
                "Field.trusted_source must be 'server' or 'client'"
            )


@dataclass(frozen=True, slots=True)
class Role:
    """An actor and the capabilities it is granted."""

    id: str
    capabilities: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError("Role.id must be non-empty")


@dataclass(frozen=True, slots=True)
class AppModel:
    """A versioned, signed formal description of an application's logic."""

    app_id: str
    version: str
    states: tuple[str, ...]
    transitions: tuple[Transition, ...] = ()
    invariants: tuple[Invariant, ...] = ()
    fields: tuple[Field, ...] = ()
    roles: tuple[Role, ...] = ()
    idempotency: tuple[tuple[str, bool], ...] = ()
    out_of_scope_rules: tuple[str, ...] = ()
    status: AppModelStatus = AppModelStatus.DRAFT
    digest: str = field(default="")
    signature: str | None = None

    def __post_init__(self) -> None:
        if not self.app_id:
            raise DomainValidationError("AppModel.app_id must be non-empty")
        if not self.version:
            raise DomainValidationError("AppModel.version must be non-empty")
        if not self.states:
            raise DomainValidationError("AppModel.states must be non-empty")
        if not self.digest:
            object.__setattr__(self, "digest", canonical_digest(self._content_payload()))

    def _content_payload(self) -> dict[str, object]:
        """The content the digest covers (excludes lifecycle + signature metadata)."""
        return {
            "app_id": self.app_id,
            "version": self.version,
            "states": self.states,
            "transitions": self.transitions,
            "invariants": self.invariants,
            "fields": self.fields,
            "roles": self.roles,
            "idempotency": self.idempotency,
            "out_of_scope_rules": self.out_of_scope_rules,
        }
