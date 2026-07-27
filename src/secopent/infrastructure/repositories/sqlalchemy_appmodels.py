# src/secopent/infrastructure/repositories/sqlalchemy_appmodels.py
"""SqlAlchemy AppModelRegistry: durable persistence for AppModel (§4.6/§11.9).

Implements the application-layer ``AppModelRegistry`` port (duck-typed). Nested
parts (transitions, invariants, fields, roles, idempotency) are JSON-encoded.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from ...domain.appmodel.lifecycle import AppModelStatus
from ...domain.appmodel.models import (
    AppModel,
    Field,
    Invariant,
    Role,
    Transition,
)
from ..db.appmodel_models import CoreAppModel


def _to_model(row: CoreAppModel) -> AppModel:
    return AppModel(
        app_id=row.app_id,
        version=row.version,
        states=tuple(row.states),
        transitions=tuple(
            Transition(
                id=t["id"],
                from_state=t["from_state"],
                to_state=t["to_state"],
                endpoint=t["endpoint"],
                params=tuple(t["params"]),
                idempotent=t["idempotent"],
            )
            for t in row.transitions
        ),
        invariants=tuple(Invariant(id=i["id"], expr=i["expr"]) for i in row.invariants),
        fields=tuple(
            Field(
                name=f["name"],
                type=f["type"],
                range=tuple(f["range"]) if f["range"] is not None else None,
                trusted_source=f["trusted_source"],
            )
            for f in row.fields
        ),
        roles=tuple(Role(id=r["id"], capabilities=tuple(r["capabilities"])) for r in row.roles),
        idempotency=tuple((k, bool(v)) for k, v in row.idempotency),
        out_of_scope_rules=tuple(row.out_of_scope_rules),
        status=AppModelStatus(row.status),
        digest=row.digest,
        signature=row.signature,
    )


def _from_model(model: AppModel) -> CoreAppModel:
    fields: list[dict[str, Any]] = [
        {
            "name": f.name,
            "type": f.type,
            "range": list(f.range) if f.range is not None else None,
            "trusted_source": f.trusted_source,
        }
        for f in model.fields
    ]
    return CoreAppModel(
        app_id=model.app_id,
        version=model.version,
        states=list(model.states),
        transitions=[
            {
                "id": t.id,
                "from_state": t.from_state,
                "to_state": t.to_state,
                "endpoint": t.endpoint,
                "params": list(t.params),
                "idempotent": t.idempotent,
            }
            for t in model.transitions
        ],
        invariants=[{"id": i.id, "expr": i.expr} for i in model.invariants],
        fields=fields,
        roles=[{"id": r.id, "capabilities": list(r.capabilities)} for r in model.roles],
        idempotency=[[k, v] for k, v in model.idempotency],
        out_of_scope_rules=list(model.out_of_scope_rules),
        status=model.status.value,
        digest=model.digest,
        signature=model.signature,
    )


class SqlAlchemyAppModelRegistry:
    """Persisted AppModelRegistry (satisfies the application port)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def put(self, model: AppModel) -> None:
        self._session.merge(_from_model(model))
        self._session.flush()

    def get(self, app_id: str, version: str) -> AppModel | None:
        row = self._session.get(CoreAppModel, (app_id, version))
        return _to_model(row) if row else None

    def list(self) -> list[AppModel]:
        rows = (
            self._session.query(CoreAppModel)
            .order_by(CoreAppModel.app_id, CoreAppModel.version)
            .all()
        )
        return [_to_model(row) for row in rows]
