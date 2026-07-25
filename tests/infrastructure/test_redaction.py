"""TDD tests for RedactionEngine (M2 Task 12, §13 redaction).

The RedactionEngine masks secrets/PII in evidence text using a curated regex
library. It distinguishes *our* secrets (canary tokens / own credentials passed
via ``ours_secrets`` - always masked as OURS) from *target* secrets (credentials
found on the target - masked as TARGET and flaggable as evidence). The matched
secret value is never stored in the Redaction record.
"""
from __future__ import annotations

from secopent.domain.evidence.models import RedactionResult, SecretOrigin
from secopent.infrastructure.evidence_store.redaction import RedactionEngine

_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.s5k7_signature_part"
_PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAKj34Gk=\n"
    "-----END RSA PRIVATE KEY-----"
)


def test_redacts_aws_access_key_as_target() -> None:
    engine = RedactionEngine()
    result = engine.redact(f"found key {_AWS_KEY} in config")
    assert _AWS_KEY not in result.redacted_text
    assert "[REDACTED:aws_access_key]" in result.redacted_text
    assert result.redactions[0].origin is SecretOrigin.TARGET


def test_redacts_our_secret_with_ours_origin() -> None:
    engine = RedactionEngine(ours_secrets=frozenset({_AWS_KEY}))
    result = engine.redact(f"our canary used {_AWS_KEY}")
    assert _AWS_KEY not in result.redacted_text
    assert result.redactions[0].origin is SecretOrigin.OURS


def test_redacts_jwt() -> None:
    result = RedactionEngine().redact(f"token: {_JWT}")
    assert _JWT not in result.redacted_text
    assert "[REDACTED:jwt]" in result.redacted_text


def test_redacts_private_key_block() -> None:
    result = RedactionEngine().redact(_PRIVATE_KEY)
    assert "MIIBOgIBAAJBAKj34Gk=" not in result.redacted_text
    assert "[REDACTED:private_key]" in result.redacted_text


def test_redacts_email_as_pii() -> None:
    result = RedactionEngine().redact("contact admin@example.com now")
    assert "admin@example.com" not in result.redacted_text
    assert "[REDACTED:email]" in result.redacted_text


def test_redacts_internal_ip() -> None:
    result = RedactionEngine().redact("backend at 10.0.0.5 and 192.168.1.10")
    assert "10.0.0.5" not in result.redacted_text
    assert "192.168.1.10" not in result.redacted_text
    assert result.count >= 2


def test_redacts_cn_mobile_and_id() -> None:
    result = RedactionEngine().redact("tel 13812345678 id 11010119900307651X")
    assert "13812345678" not in result.redacted_text
    assert "11010119900307651X" not in result.redacted_text


def test_no_secrets_unchanged() -> None:
    text = "GET /index.html 200 OK - nothing sensitive here"
    result = RedactionEngine().redact(text)
    assert result.redacted_text == text
    assert result.count == 0


def test_public_ip_not_redacted() -> None:
    # A public IP is not an internal address - must not be masked.
    result = RedactionEngine().redact("server 8.8.8.8 responded")
    assert "8.8.8.8" in result.redacted_text


def test_result_is_redaction_result() -> None:
    result = RedactionEngine().redact(_AWS_KEY)
    assert isinstance(result, RedactionResult)
