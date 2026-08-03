# src/secopent/domain/cases/preflight.py
"""PreflightSpec: deterministic gray-box credential pre-check (§7).

Modeled on Shannon's validate-authentication + state-save pattern, rewritten:
before any authenticated case runs, the platform verifies the credentials
work (deterministic form submit + success marker assertion - no LLM) and
persists the authenticated session for case reuse. Secrets themselves live
in the secret store; this spec only carries FIELD NAMES and a secret-store
reference (never secret values - M5 rule).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..common.errors import DomainValidationError


class CredentialKind(StrEnum):
    FORM = "form"
    API_TOKEN = "api_token"
    BEARER = "bearer"


@dataclass(frozen=True, slots=True)
class PreflightSpec:
    """What the preflight check needs to verify credentials deterministically."""

    login_url: str
    credential_kind: CredentialKind
    username_field: str
    password_field: str
    success_marker: str  # substring/selector expected ONLY on successful auth
    requires_totp: bool = False
    totp_secret_ref: str = ""  # secret-store key name, not the secret
    session_state_ref: str = "default"  # key under which session is reused

    def __post_init__(self) -> None:
        if not self.login_url:
            raise DomainValidationError(
                "PreflightSpec.login_url must be non-empty"
            )
        if not self.success_marker:
            raise DomainValidationError(
                "PreflightSpec.success_marker must be non-empty"
            )
        if self.requires_totp and not self.totp_secret_ref:
            raise DomainValidationError(
                "PreflightSpec.totp_secret_ref required when requires_totp"
            )
