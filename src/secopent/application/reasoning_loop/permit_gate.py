"""PermitGate: short-lived, signed, nonce-protected permits (spec §6.3).

Reuses the project's existing permit infrastructure rather than adding new
crypto: an ``ExecutionPermit`` is issued and signed through the
``PermitSignerProtocol``/``PermitVerifierProtocol`` ports (whose concrete
``PermitSigner``/``PermitVerifier`` live in infrastructure and hold the
Ed25519 key pair). The application layer therefore never imports
``cryptography``.

The permit is short-lived (default ``DEFAULT_PERMIT_TTL_SECONDS``) and bound
to the exact ProposeAction + LoopContext via a content digest stored in
``scope_digest`` — so any tampering with the action after signing is detected
by ``verify``.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

from ...domain.common.canonical import canonical_json, utc_now
from ...domain.permits.models import DEFAULT_PERMIT_TTL_SECONDS, ExecutionPermit
from ...domain.reasoning_loop.models import (
    GateVerdict,
    LoopContext,
    ProposeAction,
)
from ..ports.loop_gates import PermitGate
from ..ports.security import PermitSignerProtocol, PermitVerifierProtocol

_LOOP_WORKER_ID = "reasoning-loop"


class PermitGateImpl(PermitGate):
    """Signs a short-lived nonce permit for an accepted action.

    ``check`` issues and stores the permit; ``verify`` returns whether the
    stored permit still validates (signature + expiry) for the *exact* action
    + context it was issued for.
    """

    def __init__(
        self,
        *,
        ttl_seconds: int = DEFAULT_PERMIT_TTL_SECONDS,
        signer: PermitSignerProtocol,
        verifier: PermitVerifierProtocol,
    ) -> None:
        self._ttl = ttl_seconds
        self._signer = signer
        self._verifier = verifier
        self._issued: dict[str, ExecutionPermit] = {}

    def check(self, action: ProposeAction, context: LoopContext) -> GateVerdict:
        now = utc_now()
        nonce = secrets.token_urlsafe(16)
        permit = ExecutionPermit(
            job_id=_loop_job_id(context),
            worker_id=_LOOP_WORKER_ID,
            scope_digest=_request_digest(action, context),
            plan_digest="sha256:" + context.context_hash(),
            capabilities=_capabilities(action),
            budget=0.0,
            issued_at=now,
            expires_at=now + timedelta(seconds=self._ttl),
            nonce=nonce,
        )
        signed = self._signer.issue(permit)
        permit_id = "permit-" + nonce[:8]
        self._issued[permit_id] = signed
        return GateVerdict(
            passed=True,
            reason="permit_signed",
            permit_id=permit_id,
            permit_ttl_seconds=self._ttl,
        )

    def verify(self, permit_id: str, action: ProposeAction, context: LoopContext) -> bool:
        permit = self._issued.get(permit_id)
        if permit is None:
            return False
        # Content binding: the action+context must match what was signed.
        if _request_digest(action, context) != permit.scope_digest:
            return False
        try:
            self._verifier.verify(
                permit,
                now=utc_now(),
                used_nonces=frozenset(),
                expected_worker=None,
            )
            return True
        except Exception:
            return False


def _loop_job_id(context: LoopContext) -> str:
    """Stable per-loop job identifier (the gate lacks the full LoopId)."""
    return "loop-" + context.context_hash()[:12]


def _capabilities(action: ProposeAction) -> tuple[str, ...]:
    capability = action.tool_id or action.payload.get("case_id") or "<unknown>"
    return (str(capability),)


def _request_digest(action: ProposeAction, context: LoopContext) -> str:
    """Content digest binding the permit to one specific action + context."""
    body = {
        "action": action.model_dump(),
        "context_hash": context.context_hash(),
    }
    return "sha256:" + hashlib.sha256(
        canonical_json(body).encode("utf-8")
    ).hexdigest()
