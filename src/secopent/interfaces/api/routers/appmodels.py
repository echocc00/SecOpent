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

import json
from collections.abc import Callable
from dataclasses import replace

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy.orm import Session

from ....application.appmodels import (
    AppModelNotFoundError,
    AppModelPermissionError,
    AppModelService,
    AppModelTransitionError,
)
from ....application.cases import CaseService
from ....application.drift_detector import DriftDetector
from ....application.logic_generator import LogicTestGenerator
from ....application.model_builder import ModelImporter
from ....application.remote_model import DataClassification, RemoteModelGateway
from ....application.risk_analyzer import RiskAnalyzer
from ....application.signing_keys import SigningKeyNotFound
from ....domain.appmodel.lifecycle import AppModelStatus
from ....domain.appmodel.logic import LogicTestCase
from ....domain.appmodel.models import AppModel, Field, Invariant, Role, Transition
from ....domain.cases.models import CaseDefinition, CaseOrigin, CaseStep
from ....domain.common.canonical import utc_now
from ....domain.common.errors import DomainError
from ....domain.policy.models import RiskClass
from ....infrastructure.logic_strategies.invariant_strategy import InvariantStrategy
from ....infrastructure.logic_strategies.restler_strategy import RestlerStrategy
from ....infrastructure.logic_strategies.schemathesis_strategy import (
    SchemathesisStrategy,
)
from ....infrastructure.model_sources.openapi import OpenApiImporter
from ....infrastructure.model_sources.postman import PostmanImporter
from ....infrastructure.repositories.sqlalchemy_appmodels import (
    SqlAlchemyAppModelRegistry,
)
from ....infrastructure.repositories.sqlalchemy_cases import SqlAlchemyCaseRegistry
from ..deps import DbSession
from ..schemas import (
    ActorRoleBody,
    AppModelCreate,
    AppModelImport,
    AppModelOut,
    AppModelRevise,
    CaseOut,
    DriftReportOut,
    DriftRequest,
    FieldOut,
    InvariantOut,
    RoleOut,
    TransitionOut,
)
from .cases import case_to_out

router = APIRouter(prefix="/appmodels", tags=["appmodels"])

_IMPORTERS: dict[str, ModelImporter] = {
    "openapi": OpenApiImporter(),
    "postman": PostmanImporter(),
}


def _llm_propose_enrichment(
    gateway: RemoteModelGateway, draft: AppModel
) -> AppModel:
    """Ask the LLM to PROPOSE business states/invariants for an imported draft.

    The LLM only PROPOSES (§3.3, LLM boundary): its suggestions are merged into
    the draft and the result is registered as LLM_PROPOSED for human validation.
    An empty/unparseable completion (e.g. the null backend when no LLM is
    configured) simply yields the deterministic draft unchanged.
    """
    prompt = (
        "You assist a security engineer modeling an application. From these API "
        "endpoints, propose business states and invariants. Reply ONLY with JSON "
        '{"states": ["..."], "invariants": [{"id": "...", "expr": "..."}]}.\n'
        "Endpoints: " + ", ".join(t.endpoint for t in draft.transitions)
    )
    try:
        response = gateway.call(
            prompt, classification=DataClassification.INTERNAL, now=utc_now()
        )
        data = json.loads(response.text)
    except (DomainError, ValueError, json.JSONDecodeError):
        return draft  # LLM unavailable / unparseable -> deterministic draft

    states = list(draft.states)
    for state in data.get("states", []):
        if isinstance(state, str) and state and state not in states:
            states.append(state)
    invariants = list(draft.invariants)
    existing_ids = {i.id for i in invariants}
    for inv in data.get("invariants", []):
        if (
            isinstance(inv, dict)
            and inv.get("id")
            and inv.get("expr")
            and inv["id"] not in existing_ids
        ):
            invariants.append(Invariant(id=str(inv["id"]), expr=str(inv["expr"])))
            existing_ids.add(str(inv["id"]))
    return replace(draft, states=tuple(states), invariants=tuple(invariants))


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
    model = _to_domain(payload.app_id, payload.version, payload)
    return _execute(
        lambda: _service(session).create(model, proposed=payload.llm_proposed)
    )


@router.post("/import", status_code=201, response_model=AppModelOut)
def import_app_model(
    payload: AppModelImport, request: Request, session: DbSession
) -> AppModelOut:
    """Import an AppModel from an OpenAPI/Postman/traffic spec (§3.3).

    The importer builds a deterministic DRAFT. With ``use_llm``, the governed
    LLM gateway PROPOSES business states/invariants which are merged in and the
    model is registered as LLM_PROPOSED for human validation (the LLM never
    validates or signs - LLM boundary). Without an LLM the draft stays as the
    deterministic draft (LLM_PROPOSED, awaiting the same human validation).
    """
    importer = _IMPORTERS.get(payload.source_type)
    if importer is None:
        raise HTTPException(
            status_code=422,
            detail=f"unknown source_type: {payload.source_type}",
        )
    draft = importer.to_draft(payload.spec)
    service = _service(session)
    if not payload.use_llm:
        return _to_out(service.create(draft))
    gateway: RemoteModelGateway = request.app.state.model_gateway
    enriched = _llm_propose_enrichment(gateway, draft)
    return _to_out(service.create_proposed(enriched))


def _to_domain(app_id: str, version: str, payload: AppModelCreate) -> AppModel:
    """Build an AppModel domain object from a request body (path supplies ids)."""
    return AppModel(
        app_id=app_id,
        version=version,
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


@router.put("/{app_id}/{version}", response_model=AppModelOut)
def update_app_model(
    app_id: str, version: str, payload: AppModelCreate, session: DbSession
) -> AppModelOut:
    """Edit a model in place (only DRAFT/HUMAN_VALIDATED; signed -> revise)."""
    model = _to_domain(app_id, version, payload)
    return _execute(lambda: _service(session).update(model))


@router.post("/{app_id}/{version}/revise", status_code=201, response_model=AppModelOut)
def revise_app_model(
    app_id: str, version: str, payload: AppModelRevise, session: DbSession
) -> AppModelOut:
    """Create a new DRAFT version (version bump) from the edited content."""
    model = _to_domain(app_id, version, payload)
    return _execute(
        lambda: _service(session).revise(model, new_version=payload.new_version)
    )


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
    try:
        signer = request.app.state.signing_keys.signer_for(body.key_id)
    except SigningKeyNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _execute(
        lambda: _service(session).sign(
            app_id, version, signer=signer, actor_role=body.actor_role
        )
    )


# --- Test generation (model-driven logic tests, §11.10) ----------------------

_GENERATOR = LogicTestGenerator(
    [RestlerStrategy(), SchemathesisStrategy(), InvariantStrategy()]
)


def _logic_to_case(model: AppModel, ltc: LogicTestCase) -> CaseDefinition:
    """Wrap a generated LogicTestCase as a model-generated CaseDefinition.

    Logic tests are ACTIVE risk (they actively exercise the app); the single
    synthesized ``logic.test`` step carries the test class, target, and inputs.
    The case inherits trust from the human-signed model via the fast path.
    """
    sig_suffix = ltc.signature.removeprefix("sha256:")[:12]
    return CaseDefinition(
        id=f"logic:{ltc.test_class.value}:{sig_suffix}",
        version=model.version,
        author="logic-generator",
        risk=RiskClass.ACTIVE,
        target_type="logic",
        schema="secopent-logic/v1",
        steps=(
            CaseStep(
                id="t1",
                action="logic.test",
                spec={
                    "test_class": ltc.test_class.value,
                    "target": ltc.target,
                    "inputs": dict(ltc.inputs),
                    "signature": ltc.signature,
                    "app_model_digest": ltc.app_model_digest,
                },
            ),
        ),
        origin=CaseOrigin.MODEL_GENERATED,
    )


@router.post(
    "/{app_id}/{version}/generate-tests",
    status_code=201,
    response_model=list[CaseOut],
)
def generate_tests(
    app_id: str, version: str, session: DbSession
) -> list[CaseOut]:
    """Deterministically generate logic-test cases from a SIGNED AppModel.

    Generation is a pure function of the signed model (never the LLM). Each
    LogicTestCase is wrapped as a model-generated case and advanced through the
    case fast path (auto risk-gate; ACTIVE cases stop at VALIDATED pending human
    review). Idempotent: the same model yields the same case signatures.
    """
    model_service = AppModelService(SqlAlchemyAppModelRegistry(session))
    try:
        model = model_service.get(app_id, version)
    except AppModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if model.status is not AppModelStatus.SIGNED:
        raise HTTPException(
            status_code=409,
            detail=f"model must be SIGNED to generate tests (is {model.status.value})",
        )

    case_service = CaseService(RiskAnalyzer(), SqlAlchemyCaseRegistry(session))
    results: list[CaseOut] = []
    for ltc in _GENERATOR.generate(model):
        case = _logic_to_case(model, ltc)
        try:
            case_service.create_draft(case)
            advanced = case_service.fast_track_model_generated(case.id)
        except DomainError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        results.append(case_to_out(advanced))
    return results


# --- Drift detection (AppModel re-import diff, §11.9) ------------------------


@router.post("/{app_id}/{version}/drift", response_model=DriftReportOut)
def check_drift(
    app_id: str, version: str, payload: DriftRequest, session: DbSession
) -> DriftReportOut:
    """Diff a re-imported model against the stored one (endpoint-level drift).

    The client submits the re-imported states/transitions (e.g. from a fresh
    OpenAPI/Postman import); the DriftDetector reports added/removed/changed
    endpoints so the UI can prompt regeneration of affected logic tests.
    """
    current = SqlAlchemyAppModelRegistry(session).get(app_id, version)
    if current is None:
        raise HTTPException(status_code=404, detail="app model not found")
    reimported = AppModel(
        app_id=app_id,
        version=version,
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
    )
    report = DriftDetector().check(current, reimported)
    return DriftReportOut(
        app_id=report.app_id,
        added=list(report.added),
        removed=list(report.removed),
        changed=list(report.changed),
        has_drift=report.has_drift,
    )
