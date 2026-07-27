# src/secopent/interfaces/api/routers/appmodels.py
"""AppModels resource router (Phase A P1, W1): model-driven logic models.

Exposes the AppModel lifecycle over a DB-backed ``AppModelService``:

    DRAFT -> HUMAN_VALIDATED -> SIGNED

The LLM boundary is enforced via ``actor_role``: an agent may create/propose a
model, but validate and sign are human-only (``"agent"`` -> 403). Signing uses
the server-held Ed25519 key (``app.state.case_signer``) over the model's stable
content digest - the private key never leaves the server.

Error mapping: not-found -> 404, agent-on-human-only -> 403, out-of-order
transition -> 409, validation failure -> 422.
"""
from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy.orm import Session

from ....application.appmodels import (
    AppModelNotFoundError,
    AppModelPermissionError,
    AppModelService,
    AppModelTransitionError,
)
from ....domain.appmodel.models import AppModel, Field, Invariant, Role, Transition
from ....domain.common.errors import DomainError
from ....infrastructure.repositories.sqlalchemy_appmodels import (
    SqlAlchemyAppModelRegistry,
)
from ..deps import DbSession
from ..schemas import (
    ActorRoleBody,
    AppModelCreate,
    AppModelOut,
    FieldOut,
    InvariantOut,
    RoleOut,
    TransitionOut,
)

router = APIRouter(prefix="/appmodels", tags=["appmodels"])


def _to_out(model: AppModel) -> AppModelOut:
    return AppModelOut(
        app_id=model.app_id,
        version=model.version,
        states=list(model.states),
        transitions=[
            TransitionOut(
                id=t.id,
                from_state=t.from_state,
                to_state=t.to_state,
                endpoint=t.endpoint,
                params=list(t.params),
                idempotent=t.idempotent,
            )
            for t in model.transitions
        ],
        invariants=[InvariantOut(id=i.id, expr=i.expr) for i in model.invariants],
        fields=[
            FieldOut(
                name=f.name,
                type=f.type,
                range=list(f.range) if f.range is not None else None,
                trusted_source=f.trusted_source,
            )
            for f in model.fields
        ],
        roles=[
            RoleOut(id=r.id, capabilities=list(r.capabilities)) for r in model.roles
        ],
        out_of_scope_rules=list(model.out_of_scope_rules),
        status=model.status.value,
        digest=model.digest,
        signature=model.signature,
    )


def _execute(action: Callable[[], AppModel]) -> AppModelOut:
    try:
        return _to_out(action())
    except AppModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AppModelPermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except AppModelTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except DomainError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _service(session: Session) -> AppModelService:
    return AppModelService(SqlAlchemyAppModelRegistry(session))


@router.post("", status_code=201, response_model=AppModelOut)
def create_app_model(payload: AppModelCreate, session: DbSession) -> AppModelOut:
    model = AppModel(
        app_id=payload.app_id,
        version=payload.version,
        states=tuple(payload.states),
        transitions=tuple(
            Transition(
                id=t.id,
                from_state=t.from_state,
                to_state=t.to_state,
                endpoint=t.endpoint,
                params=tuple(t.params),
                idempotent=t.idempotent,
            )
            for t in payload.transitions
        ),
        invariants=tuple(Invariant(id=i.id, expr=i.expr) for i in payload.invariants),
        fields=tuple(
            Field(
                name=f.name,
                type=f.type,
                range=(f.range[0], f.range[1]) if f.range is not None else None,
                trusted_source=f.trusted_source,
            )
            for f in payload.fields
        ),
        roles=tuple(
            Role(id=r.id, capabilities=tuple(r.capabilities)) for r in payload.roles
        ),
        out_of_scope_rules=tuple(payload.out_of_scope_rules),
    )
    return _execute(lambda: _service(session).create(model))


@router.get("", response_model=list[AppModelOut])
def list_app_models(session: DbSession) -> list[AppModelOut]:
    return [_to_out(m) for m in _service(session).list_all()]


@router.get("/{app_id}/{version}", response_model=AppModelOut)
def get_app_model(app_id: str, version: str, session: DbSession) -> AppModelOut:
    return _execute(lambda: _service(session).get(app_id, version))


@router.post("/{app_id}/{version}/validate", response_model=AppModelOut)
def validate_app_model(
    app_id: str, version: str, body: ActorRoleBody, session: DbSession
) -> AppModelOut:
    return _execute(
        lambda: _service(session).validate(app_id, version, actor_role=body.actor_role)
    )


@router.post("/{app_id}/{version}/sign", response_model=AppModelOut)
def sign_app_model(
    app_id: str, version: str, body: ActorRoleBody, request: Request, session: DbSession
) -> AppModelOut:
    signer = request.app.state.case_signer
    return _execute(
        lambda: _service(session).sign(
            app_id, version, signer=signer, actor_role=body.actor_role
        )
    )
