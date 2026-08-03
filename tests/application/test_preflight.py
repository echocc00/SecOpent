# tests/application/test_preflight.py
"""PreflightService (P1b Task 4): deterministic credential verification."""
from __future__ import annotations

import pytest

from secopent.application.preflight import (
    AuthDriver,
    PreflightOutcome,
    PreflightService,
)
from secopent.domain.cases.preflight import CredentialKind, PreflightSpec


class FakeAuthDriver:
    """Records login attempts; returns canned results."""

    def __init__(self, *, succeeds: bool, page_text: str = "welcome myAccount") -> None:
        self.succeeds = succeeds
        self.page_text = page_text
        self.attempts: list[str] = []
        self.saved_states: list[str] = []

    def submit_login(self, spec: PreflightSpec, username: str, password: str,
                     totp: str | None) -> str:
        self.attempts.append(spec.login_url)
        if not self.succeeds:
            return "Invalid credentials"
        return self.page_text

    def save_session(self, spec: PreflightSpec) -> None:
        self.saved_states.append(spec.session_state_ref)


def _spec() -> PreflightSpec:
    return PreflightSpec(
        login_url="http://host.docker.internal:3000/#/login",
        credential_kind=CredentialKind.FORM,
        username_field="email",
        password_field="password",
        success_marker="myAccount",
    )


class TestPreflight:
    def test_success_when_marker_present(self) -> None:
        driver = FakeAuthDriver(succeeds=True)
        service = PreflightService(driver=driver)
        outcome = service.verify(
            spec=_spec(), username="u@example.com", password="pw", secret_lookup={},
        )
        assert outcome is PreflightOutcome.SUCCESS
        assert driver.saved_states == ["default"]  # 登录态已保存供复用

    def test_failure_when_marker_absent(self) -> None:
        driver = FakeAuthDriver(succeeds=False)
        service = PreflightService(driver=driver)
        outcome = service.verify(
            spec=_spec(), username="u", password="bad", secret_lookup={},
        )
        assert outcome is PreflightOutcome.FAILURE
        assert driver.saved_states == []  # 失败不保存会话

    def test_totp_code_fetched_from_secret_lookup(self) -> None:
        from secopent.domain.cases.preflight import PreflightSpec as PS

        spec = PS(
            login_url="http://t/login", credential_kind=CredentialKind.FORM,
            username_field="u", password_field="p", success_marker="ok",
            requires_totp=True, totp_secret_ref="vault://target/totp",
        )
        driver = FakeAuthDriver(succeeds=True, page_text="ok")
        service = PreflightService(driver=driver)
        outcome = service.verify(
            spec=spec, username="u", password="p",
            secret_lookup={"vault://target/totp": "JBSWY3DPEHPK3PXP"},
        )
        assert outcome is PreflightOutcome.SUCCESS

    def test_missing_totp_secret_is_error_not_failure(self) -> None:
        from secopent.domain.cases.preflight import PreflightSpec as PS

        spec = PS(
            login_url="http://t/login", credential_kind=CredentialKind.FORM,
            username_field="u", password_field="p", success_marker="ok",
            requires_totp=True, totp_secret_ref="vault://target/totp",
        )
        service = PreflightService(driver=FakeAuthDriver(succeeds=True))
        with pytest.raises(KeyError):
            service.verify(spec=spec, username="u", password="p", secret_lookup={})

    def test_exactly_one_attempt_no_retry(self) -> None:
        # Shannon 规则：任何拒绝 = 认证错误，不重试
        driver = FakeAuthDriver(succeeds=False)
        service = PreflightService(driver=driver)
        service.verify(spec=_spec(), username="u", password="p", secret_lookup={})
        assert len(driver.attempts) == 1
