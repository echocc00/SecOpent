# src/secopent/application/preflight.py
"""PreflightService: deterministic credential verification (spec §7).

One attempt, no retry (any rejection = auth error, mirroring the proven
Shannon rule). On success the driver persists the authenticated session so
authenticated cases reuse it instead of logging in again. TOTP codes are
generated from the secret-store value (RFC 6238) at verify time.

The AuthDriver Protocol is inline so the application layer stays free of
browser/http coupling (real driver = P2 wiring or case-engine adapter).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from enum import StrEnum
from typing import Protocol, runtime_checkable

from ..domain.cases.preflight import PreflightSpec


class PreflightOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"


@runtime_checkable
class AuthDriver(Protocol):
    def submit_login(
        self,
        spec: PreflightSpec,
        username: str,
        password: str,
        totp: str | None,
    ) -> str:
        """Submit credentials once; return the response page/body text."""
        ...

    def save_session(self, spec: PreflightSpec) -> None:
        """Persist the authenticated session for case reuse."""
        ...


def _totp_now(secret_b32: str) -> str:
    """RFC 6238 6-digit code (30s step, sha1) - stdlib only."""
    key = base64.b32decode(secret_b32, casefold=True)
    counter = int(time.time() // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 1_000_000:06d}"


class PreflightService:
    """Verify gray-box credentials deterministically before case execution."""

    def __init__(self, *, driver: AuthDriver) -> None:
        self._driver = driver

    def verify(
        self,
        *,
        spec: PreflightSpec,
        username: str,
        password: str,
        secret_lookup: dict[str, str],
    ) -> PreflightOutcome:
        totp: str | None = None
        if spec.requires_totp:
            secret = secret_lookup[spec.totp_secret_ref]  # KeyError 上抛（配置错误≠认证失败）
            totp = _totp_now(secret)
        page = self._driver.submit_login(spec, username, password, totp)
        if spec.success_marker not in page:
            return PreflightOutcome.FAILURE
        self._driver.save_session(spec)
        return PreflightOutcome.SUCCESS
