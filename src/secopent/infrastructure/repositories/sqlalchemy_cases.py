# src/secopent/infrastructure/repositories/sqlalchemy_cases.py
"""SqlAlchemy CaseRegistry: durable persistence for CaseDefinition (§11.5).

Implements the application-layer ``CaseRegistry`` port (duck-typed) so the same
``CaseService`` lifecycle logic drives both the in-memory M2 surface and the
DB-backed REST API.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from ...domain.cases.models import (
    CaseAssertion,
    CaseDefinition,
    CaseOrigin,
    CaseStatus,
    CaseStep,
    CaseVerification,
)
from ...domain.policy.models import RiskClass
from ..db.case_models import CoreCase


def _to_case(row: CoreCase) -> CaseDefinition:
    verification = (
        CaseVerification(
            method=row.verification["method"], reproduce=row.verification["reproduce"]
        )
        if row.verification is not None
        else None
    )
    return CaseDefinition(
        id=row.id,
        version=row.version,
        author=row.author,
        risk=RiskClass(row.risk),
        target_type=row.target_type,
        schema=row.schema,
        steps=tuple(
            CaseStep(id=s["id"], action=s["action"], spec=s["spec"]) for s in row.steps
        ),
        preconditions=tuple(row.preconditions),
        assertions=tuple(
            CaseAssertion(id=a["id"], expression=a["expression"])
            for a in row.assertions
        ),
        evidence_req=tuple(row.evidence_req),
        cwe=tuple(row.cwe),
        cve=tuple(row.cve),
        owasp=tuple(row.owasp),
        verification=verification,
        signature=row.signature,
        min_engine_version=row.min_engine_version,
        origin=CaseOrigin(row.origin),
        status=CaseStatus(row.status),
        yaml=row.yaml,
    )


def _from_case(case: CaseDefinition) -> CoreCase:
    verification: dict[str, Any] | None = (
        {"method": case.verification.method, "reproduce": case.verification.reproduce}
        if case.verification is not None
        else None
    )
    return CoreCase(
        id=case.id,
        version=case.version,
        author=case.author,
        risk=case.risk.value,
        target_type=case.target_type,
        schema=case.schema,
        status=case.status.value,
        origin=case.origin.value,
        signature=case.signature,
        min_engine_version=case.min_engine_version,
        steps=[{"id": s.id, "action": s.action, "spec": s.spec} for s in case.steps],
        preconditions=list(case.preconditions),
        assertions=[{"id": a.id, "expression": a.expression} for a in case.assertions],
        evidence_req=list(case.evidence_req),
        cwe=list(case.cwe),
        cve=list(case.cve),
        owasp=list(case.owasp),
        verification=verification,
        yaml=case.yaml,
    )


class SqlAlchemyCaseRegistry:
    """Persisted CaseRegistry (satisfies the application CaseRegistry port)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def put(self, case: CaseDefinition) -> None:
        self._session.merge(_from_case(case))
        # Flush so a subsequent get() within the same request sees the write
        # (the request-scoped session commits at teardown).
        self._session.flush()

    def get(self, case_id: str) -> CaseDefinition | None:
        row = self._session.get(CoreCase, case_id)
        return _to_case(row) if row else None

    def list(self) -> list[CaseDefinition]:
        rows = self._session.query(CoreCase).order_by(CoreCase.id).all()
        return [_to_case(row) for row in rows]
