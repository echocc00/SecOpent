# src/secopent/interfaces/api/routers/cases.py
"""Cases resource router (Phase A P1, W1): the CaseStudio case lifecycle.

Exposes the YAML-case lifecycle over a DB-backed ``CaseService`` (a
``SqlAlchemyCaseRegistry`` is built per request from the request session):

    DRAFT -> VALIDATED -> REVIEWED -> SIGNED -> PUBLISHED

The LLM boundary is enforced via ``actor_role``: an agent may create and
validate a case, but review / sign / publish are human-only (``actor_role``
must be ``"human"``; ``"agent"`` is rejected with 403). Signing uses a
server-held Ed25519 key (``app.state.case_signer``) - the private key never
leaves the server, so the frontend can request a signature but never hold the
signing key.

Error mapping: not-found -> 404, permission (agent on human-only) -> 403,
out-of-order transition -> 409, risk-gate / validation failure -> 422.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy.orm import Session

from ....application.cases import (
    CaseNotFoundError,
    CasePermissionError,
    CaseService,
    CaseTransitionError,
)
from ....application.risk_analyzer import RiskAnalyzer
from ....application.signing_keys import SigningKeyNotFound
from ....domain.cases.models import CaseDefinition, CaseOrigin, CaseStatus, CaseStep
from ....domain.cases.risk import risk_rank
from ....domain.common.errors import DomainError
from ....domain.policy.models import RiskClass
from ....infrastructure.repositories.sqlalchemy_cases import SqlAlchemyCaseRegistry
from ..deps import DbSession
from ..schemas import (
    CaseAction,
    CaseAnalysisOut,
    CaseCreate,
    CaseOut,
    CaseStepOut,
    CaseYamlUpdate,
)

router = APIRouter(prefix="/cases", tags=["cases"])


def case_to_out(case: CaseDefinition) -> CaseOut:
    return CaseOut(
        id=case.id,
        version=case.version,
        author=case.author,
        risk=case.risk.value,
        target_type=case.target_type,
        case_schema=case.schema,
        status=case.status.value,
        origin=case.origin.value,
        signature=case.signature,
        steps=[
            CaseStepOut(id=s.id, action=s.action, spec=s.spec) for s in case.steps
        ],
        cwe=list(case.cwe),
        cve=list(case.cve),
        owasp=list(case.owasp),
        yaml=case.yaml,
    )


def _execute(action: Callable[[], CaseDefinition]) -> CaseOut:
    """Run a CaseService action, mapping domain errors to HTTP status codes."""
    try:
        return case_to_out(action())
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CasePermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except CaseTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except DomainError as exc:
        # RiskPublishDenied / RiskUndeclared / DomainValidationError.
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _service(session: Session) -> CaseService:
    return CaseService(RiskAnalyzer(), SqlAlchemyCaseRegistry(session))


@router.post("", status_code=201, response_model=CaseOut)
def create_case(payload: CaseCreate, session: DbSession) -> CaseOut:
    try:
        case = CaseDefinition(
            id=payload.id,
            version=payload.version,
            author=payload.author,
            risk=RiskClass(payload.risk),
            target_type=payload.target_type,
            schema=payload.case_schema,
            steps=tuple(
                CaseStep(id=s.id, action=s.action, spec=s.spec) for s in payload.steps
            ),
            cwe=tuple(payload.cwe),
            cve=tuple(payload.cve),
            owasp=tuple(payload.owasp),
            origin=CaseOrigin(payload.origin),
            yaml=payload.yaml,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid field: {exc}") from exc
    return _execute(lambda: _service(session).create_draft(case))


@router.get("", response_model=list[CaseOut])
def list_cases(session: DbSession) -> list[CaseOut]:
    return [case_to_out(c) for c in _service(session).list_all()]


@router.get("/{case_id}", response_model=CaseOut)
def get_case(case_id: str, session: DbSession) -> CaseOut:
    return _execute(lambda: _service(session).get(case_id))


@router.put("/{case_id}", response_model=CaseOut)
def update_case_yaml(
    case_id: str, body: CaseYamlUpdate, session: DbSession
) -> CaseOut:
    """Update a case's YAML source (CaseStudio Monaco editor).

    Only unsigned cases (DRAFT/VALIDATED) are editable; SIGNED/PUBLISHED cases
    are immutable (immutability after signing).
    """
    repo = SqlAlchemyCaseRegistry(session)
    existing = repo.get(case_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="case not found")
    if existing.status not in (CaseStatus.DRAFT, CaseStatus.VALIDATED):
        raise HTTPException(
            status_code=409,
            detail=f"cannot edit a {existing.status.value} case "
            "(signed/published cases are immutable)",
        )
    updated = replace(existing, yaml=body.yaml)
    repo.put(updated)
    return case_to_out(updated)


@router.post("/{case_id}/validate", response_model=CaseOut)
def validate_case(case_id: str, session: DbSession) -> CaseOut:
    return _execute(lambda: _service(session).validate(case_id))


@router.post("/{case_id}/analyze", response_model=CaseAnalysisOut)
def analyze_case(case_id: str, session: DbSession) -> CaseAnalysisOut:
    """Deterministic risk/schema analysis for the YAML editor (no transition).

    Runs the RiskAnalyzer over the case and reports the declared-vs-computed
    risk so the CaseStudio editor can preview risk and block publish on a
    mismatch. This is static analysis - nothing is executed, and the LLM is
    never involved.
    """
    case = SqlAlchemyCaseRegistry(session).get(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    computed = RiskAnalyzer().analyze(case)
    computed_value = computed.value if computed is not None else None
    denied = computed is None
    risk_ok = computed is not None and risk_rank(case.risk) >= risk_rank(computed)
    errors: list[str] = []
    if denied:
        errors.append(
            "deny-listed pattern present (shell / unbounded loop / out-of-scope)"
        )
    elif not risk_ok:
        errors.append(
            f"declared risk {case.risk.value} is below computed risk {computed_value}"
        )
    return CaseAnalysisOut(
        case_id=case.id,
        declared_risk=case.risk.value,
        computed_risk=computed_value,
        denied=denied,
        risk_ok=risk_ok,
        schema_ok=bool(case.steps) and not denied,
        errors=errors,
    )


@router.post("/{case_id}/review", response_model=CaseOut)
def review_case(case_id: str, body: CaseAction, session: DbSession) -> CaseOut:
    return _execute(lambda: _service(session).review(case_id, actor_role=body.actor_role))


@router.post("/{case_id}/sign", response_model=CaseOut)
def sign_case(
    case_id: str, body: CaseAction, request: Request, session: DbSession
) -> CaseOut:
    try:
        signer = request.app.state.signing_keys.signer_for(body.key_id)
    except SigningKeyNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _execute(
        lambda: _service(session).sign(
            case_id, signer=signer, actor_role=body.actor_role
        )
    )


@router.post("/{case_id}/publish", response_model=CaseOut)
def publish_case(case_id: str, body: CaseAction, session: DbSession) -> CaseOut:
    return _execute(lambda: _service(session).publish(case_id, actor_role=body.actor_role))
