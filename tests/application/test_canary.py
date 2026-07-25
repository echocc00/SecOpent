"""TDD tests for CanaryTokenManager (M2 Task 3, §9 OOB/echo confirmation).

A canary token is a high-entropy, single-use marker the oracle embeds in a
verification probe (echo command or OOB subdomain). A finding is only confirmed
when the exact token comes back - proving the observed effect is the injected
probe, not a coincidental response. Tokens are never reused, and every
generation/verification is audited.
"""
from __future__ import annotations

import pytest

from secopent.application.audit import AuditService
from secopent.application.canary import (
    CanaryTokenManager,
    TokenNotIssuedError,
    TokenReuseError,
)


@pytest.fixture
def audit_repo(memory_repositories):  # type: ignore[no-untyped-def]
    return memory_repositories.audit


@pytest.fixture
def audit(audit_repo) -> AuditService:  # type: ignore[no-untyped-def]
    return AuditService(audit_repo)


@pytest.fixture
def manager(audit: AuditService) -> CanaryTokenManager:
    return CanaryTokenManager(audit, oob_domain="oast.example.com")


def test_generate_returns_unique_high_entropy_tokens(manager: CanaryTokenManager) -> None:
    t1 = manager.generate(actor="oracle", candidate_id="cand-1")
    t2 = manager.generate(actor="oracle", candidate_id="cand-2")
    assert t1 != t2
    # secrets.token_urlsafe(16) -> 22 chars; assert a sane entropy floor.
    assert len(t1) >= 16


def test_generate_is_audited(
    manager: CanaryTokenManager, audit_repo
) -> None:  # type: ignore[no-untyped-def]
    manager.generate(actor="oracle", candidate_id="cand-1")
    events = audit_repo.list_events()
    assert any(e.action == "canary.generated" for e in events)


def test_embed_replaces_placeholder(manager: CanaryTokenManager) -> None:
    token = manager.generate(actor="oracle", candidate_id="cand-1")
    rendered = manager.embed("echo {{canary_token}}", token)
    assert rendered == f"echo {token}"
    assert "{{canary_token}}" not in rendered


def test_oob_subdomain_uses_token_as_label(manager: CanaryTokenManager) -> None:
    token = manager.generate(actor="oracle", candidate_id="cand-1")
    assert manager.oob_subdomain(token) == f"{token}.oast.example.com"


def test_verify_echo_true_when_token_present(manager: CanaryTokenManager) -> None:
    token = manager.generate(actor="oracle", candidate_id="cand-1")
    assert manager.verify_echo(f"prefix {token} suffix", token, actor="oracle") is True


def test_verify_echo_false_when_token_absent(manager: CanaryTokenManager) -> None:
    token = manager.generate(actor="oracle", candidate_id="cand-1")
    assert manager.verify_echo("no canary here", token, actor="oracle") is False


def test_verify_echo_is_audited(
    manager: CanaryTokenManager, audit_repo
) -> None:  # type: ignore[no-untyped-def]
    token = manager.generate(actor="oracle", candidate_id="cand-1")
    manager.verify_echo(token, token, actor="oracle")
    events = audit_repo.list_events()
    assert any(e.action == "canary.verified" for e in events)


def test_token_is_single_use(manager: CanaryTokenManager) -> None:
    token = manager.generate(actor="oracle", candidate_id="cand-1")
    manager.verify_echo(token, token, actor="oracle")
    with pytest.raises(TokenReuseError):
        manager.verify_echo(token, token, actor="oracle")


def test_unissued_token_rejected_on_verify(manager: CanaryTokenManager) -> None:
    with pytest.raises(TokenNotIssuedError):
        manager.verify_echo("anything", "not-a-real-token", actor="oracle")


def test_unissued_token_rejected_on_embed(manager: CanaryTokenManager) -> None:
    with pytest.raises(TokenNotIssuedError):
        manager.embed("echo {{canary_token}}", "not-a-real-token")


def test_audit_does_not_leak_full_token(
    manager: CanaryTokenManager, audit_repo
) -> None:  # type: ignore[no-untyped-def]
    token = manager.generate(actor="oracle", candidate_id="cand-1")
    events = audit_repo.list_events()
    # The raw token must not appear verbatim in the audit resource ids.
    assert all(token not in e.resource_id for e in events)
