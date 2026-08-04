# src/secopent/application/canary.py
"""CanaryTokenManager: single-use confirmation tokens for the oracle (§9).

The oracle proves a finding is real by embedding a high-entropy, single-use
canary token in the probe (an echo command or an OOB callback subdomain) and
requiring that exact token to come back. This distinguishes a genuine injected
effect from a coincidental response.

Guarantees:
- tokens are high-entropy (``secrets.token_urlsafe``) and unique;
- a token is single-use - once verified it cannot be presented again;
- only tokens produced by ``generate`` are accepted;
- every generation/verification is audited, with the raw token redacted from
  the audit record (the canary is our secret, not evidence to leak).
"""
from __future__ import annotations

import hashlib
import secrets

from ..domain.common.errors import DomainError
from .ports.audit import AuditRecorder

# Placeholder the CaseEngine / probe templates use for the canary token.
CANARY_PLACEHOLDER = "{{canary_token}}"

# How many leading token chars may appear in an audit resource id (the rest is
# redacted so the audit chain never stores a reusable raw token).
_AUDIT_PREFIX_LEN = 8


class TokenNotIssuedError(DomainError):
    """Raised when a token that was never generated is presented."""


class TokenReuseError(DomainError):
    """Raised when a single-use token is presented more than once."""


def _audit_id(token: str) -> str:
    """A redacted, stable audit identifier for a token (no full token)."""
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
    return f"canary:{token[:_AUDIT_PREFIX_LEN]}:{digest}"


class CanaryTokenManager:
    """Generate, embed, and verify single-use canary tokens."""

    def __init__(self, audit: AuditRecorder, *, oob_domain: str = "oast.example.com") -> None:
        self._audit = audit
        self._oob_domain = oob_domain
        self._issued: set[str] = set()
        self._consumed: set[str] = set()

    def generate(self, *, actor: str, candidate_id: str) -> str:
        """Mint a fresh, unique, high-entropy canary token and audit it."""
        token = secrets.token_urlsafe(16)
        while token in self._issued:  # collision paranoia; practically never loops
            token = secrets.token_urlsafe(16)
        self._issued.add(token)
        self._audit.record(
            actor=actor,
            action="canary.generated",
            resource_type="canary_token",
            resource_id=_audit_id(token),
            payload={"candidate_id": candidate_id},
        )
        return token

    def embed(self, template: str, token: str) -> str:
        """Substitute the ``{{canary_token}}`` placeholder in a probe template."""
        self._require_issued(token)
        return template.replace(CANARY_PLACEHOLDER, token)

    def oob_subdomain(self, token: str) -> str:
        """Return the OOB callback subdomain for the token (``<token>.<domain>``)."""
        self._require_issued(token)
        return f"{token}.{self._oob_domain}"

    def verify_echo(self, response: str, token: str, *, actor: str) -> bool:
        """Check the token echoed back in ``response``; consume it (single-use).

        Returns True iff the exact token appears in the response. The token is
        consumed regardless of the outcome - a canary gets one verification
        attempt. Presenting a consumed or never-issued token raises.
        """
        self._require_issued(token)
        self._require_not_consumed(token)
        hit = token in response
        self._consumed.add(token)
        self._audit.record(
            actor=actor,
            action="canary.verified",
            resource_type="canary_token",
            resource_id=_audit_id(token),
            payload={"hit": hit},
        )
        return hit

    def _require_issued(self, token: str) -> None:
        if token not in self._issued:
            raise TokenNotIssuedError("canary token was never issued")

    def _require_not_consumed(self, token: str) -> None:
        if token in self._consumed:
            raise TokenReuseError("canary token is single-use and already consumed")
