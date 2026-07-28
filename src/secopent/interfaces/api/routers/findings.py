# src/secopent/interfaces/api/routers/findings.py
"""Findings resource router (Phase A P1, W1).

DB-backed replacement for the M4 in-memory demonstration. Preserves the M4
API contract - command/query separation and ``Idempotency-Key`` replay - while
persisting real ``Finding`` domain entities via ``SqlAlchemyFindingRepository``.

The idempotency cache lives on ``app.state.idempotency`` (a per-app-instance
dict initialised in ``create_app``) so a repeated POST with the same key
returns the original response without writing a duplicate row.

The oracle N/N reproduction verdict (``oracle_verdict``) is recorded via
``POST /findings/{id}/verdict`` - a deterministic oracle result, never an LLM
judgment (LLM boundary).
"""
from __future__ import annotations

from dataclasses import replace

from fastapi import APIRouter, Header, HTTPException, Request

from ....domain.adapters.contracts import Severity
from ....domain.common.canonical import canonical_digest
from ....domain.findings.models import Finding, FindingStatus
from ....domain.verification.models import VerificationStatus
from ....infrastructure.repositories.sqlalchemy_findings import (
    SqlAlchemyFindingRepository,
)
from ..deps import DbSession
from ..schemas import FindingCreate, FindingOut, FindingVerdict

router = APIRouter(prefix="/findings", tags=["findings"])


def _to_out(finding: Finding) -> FindingOut:
    return FindingOut(
        id=finding.id,
        fingerprint=finding.fingerprint,
        title=finding.title,
        asset=finding.asset,
        severity=finding.severity.value,
        cwe=list(finding.cwe),
        cve=list(finding.cve),
        owasp=list(finding.owasp),
        status=finding.status.value,
        assessment_id=finding.assessment_id,
        oracle_verdict=finding.oracle_verdict.value,
    )


@router.post("", status_code=201, response_model=FindingOut)
def create_finding(
    payload: FindingCreate,
    request: Request,
    session: DbSession,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> FindingOut:
    # Idempotent replay: same key -> original response, no duplicate row.
    store: dict[str, FindingOut] = request.app.state.idempotency
    if idempotency_key is not None and idempotency_key in store:
        return store[idempotency_key]

    try:
        severity = Severity(payload.severity)
    except ValueError as exc:
        raise HTTPException(
            status_code=422, detail=f"invalid severity: {payload.severity}"
        ) from exc

    # Deterministic fingerprint over the content that identifies the finding.
    fingerprint = canonical_digest(
        {"title": payload.title, "asset": payload.asset, "cwe": payload.cwe}
    )
    finding = Finding(
        id=f"finding:{fingerprint.removeprefix('sha256:')[:16]}",
        fingerprint=fingerprint,
        title=payload.title,
        asset=payload.asset,
        severity=severity,
        cwe=tuple(payload.cwe),
        status=FindingStatus.DRAFT,
        assessment_id=payload.assessment_id,
    )
    SqlAlchemyFindingRepository(session).add(finding)
    out = _to_out(finding)
    if idempotency_key is not None:
        store[idempotency_key] = out
    return out


@router.get("", response_model=list[FindingOut])
def list_findings(
    session: DbSession,
    assessment_id: str | None = None,
    severity: str | None = None,
    oracle_verdict: str | None = None,
) -> list[FindingOut]:
    findings = SqlAlchemyFindingRepository(session).all(
        assessment_id=assessment_id,
        severity=severity,
        oracle_verdict=oracle_verdict,
    )
    return [_to_out(f) for f in findings]


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: str, session: DbSession) -> FindingOut:
    finding = SqlAlchemyFindingRepository(session).get(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return _to_out(finding)


@router.post("/{finding_id}/verdict", response_model=FindingOut)
def set_verdict(
    finding_id: str, body: FindingVerdict, session: DbSession
) -> FindingOut:
    """Record the oracle's N/N reproduction verdict on a finding.

    The verdict is written by the deterministic oracle (internal, via the
    application layer) or a human manual override. An agent may never set a
    finding's verdict - confirming/refuting findings is forbidden to the LLM
    (LLM boundary).
    """
    if body.actor_role == "agent":
        raise HTTPException(
            status_code=403,
            detail="agents cannot set finding verdicts (oracle/human only)",
        )
    repo = SqlAlchemyFindingRepository(session)
    finding = repo.get(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    try:
        verdict = VerificationStatus(body.verdict)
    except ValueError as exc:
        raise HTTPException(
            status_code=422, detail=f"invalid verdict: {body.verdict}"
        ) from exc
    updated = replace(finding, oracle_verdict=verdict)
    repo.add(updated)
    return _to_out(updated)
