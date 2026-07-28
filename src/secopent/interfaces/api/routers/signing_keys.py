# src/secopent/interfaces/api/routers/signing_keys.py
"""Signing keys router (Phase A P1, decision H): server-held Ed25519 keys.

Exposes only PUBLIC key information - the private material never leaves the
server (it lives encrypted in the SecretStore). The CaseStudio signing flow
selects a key by id and asks the server to sign; the frontend never holds a
private key.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from ....application.signing_keys import (
    SigningKeyInfo,
    SigningKeyNotFound,
    SigningKeyService,
)
from ....domain.common.canonical import utc_now
from ..schemas import ActorRoleBody, CreateSigningKey, SigningKeyOut

router = APIRouter(prefix="/signing-keys", tags=["signing-keys"])


def _service(request: Request) -> SigningKeyService:
    return request.app.state.signing_keys  # type: ignore[no-any-return]


def _to_out(info: SigningKeyInfo) -> SigningKeyOut:
    return SigningKeyOut(
        key_id=info.key_id,
        name=info.name,
        public_key=info.public_key,
        created_at=info.created_at,
        archived=info.archived,
    )


@router.get("", response_model=list[SigningKeyOut])
def list_signing_keys(request: Request) -> list[SigningKeyOut]:
    return [_to_out(k) for k in _service(request).list_keys()]


@router.post("", status_code=201, response_model=SigningKeyOut)
def create_signing_key(
    payload: CreateSigningKey, request: Request
) -> SigningKeyOut:
    # Creating a signing key is a privileged human-only admin action (LLM
    # boundary). Listing keys (GET) stays open for the UI key selector.
    if payload.actor_role != "human":
        raise HTTPException(
            status_code=403,
            detail="agents cannot create signing keys (human-only admin action)",
        )
    info = _service(request).create_key(payload.name, now=utc_now())
    return _to_out(info)


@router.post("/{key_id}/rotate", status_code=201, response_model=SigningKeyOut)
def rotate_signing_key(
    key_id: str, body: ActorRoleBody, request: Request
) -> SigningKeyOut:
    """Rotate a signing key (§3.8): create a new key, archive the old one.

    Human-only (LLM boundary). The archived key is retained so signatures made
    before rotation can still be verified; new signatures use the new key.
    """
    if body.actor_role != "human":
        raise HTTPException(
            status_code=403,
            detail="agents cannot rotate signing keys (human-only admin action)",
        )
    try:
        info = _service(request).rotate(key_id, now=utc_now())
    except SigningKeyNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _to_out(info)
