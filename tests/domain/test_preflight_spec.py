# tests/domain/test_preflight_spec.py
"""PreflightSpec domain model (P1b Task 3)."""
from __future__ import annotations

import pytest

from secopent.domain.cases.preflight import (
    CredentialKind,
    PreflightSpec,
)
from secopent.domain.common.errors import DomainValidationError


class TestPreflightSpec:
    def test_builds_with_form_credentials(self) -> None:
        spec = PreflightSpec(
            login_url="http://host.docker.internal:3000/#/login",
            credential_kind=CredentialKind.FORM,
            username_field="email",
            password_field="password",
            success_marker="myAccount",
        )
        assert spec.requires_totp is False

    def test_requires_login_url(self) -> None:
        with pytest.raises(DomainValidationError):
            PreflightSpec(
                login_url="",
                credential_kind=CredentialKind.FORM,
                username_field="u",
                password_field="p",
                success_marker="ok",
            )

    def test_totp_requires_secret_reference(self) -> None:
        with pytest.raises(DomainValidationError):
            PreflightSpec(
                login_url="http://t/login",
                credential_kind=CredentialKind.FORM,
                username_field="u",
                password_field="p",
                success_marker="ok",
                requires_totp=True,
                totp_secret_ref="",  # 引用 secrets store 的键名，不能为空
            )
