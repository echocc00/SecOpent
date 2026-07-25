# tests/domain/test_normalize.py
from __future__ import annotations
import pytest
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.scope.normalize import (
    normalize_domain,
    normalize_ip_or_network,
    normalize_port,
    normalize_url,
)


def test_normalize_domain_lowercases_and_strips_dot() -> None:
    assert normalize_domain("Example.Test.") == "example.test"


def test_normalize_domain_wildcard() -> None:
    assert normalize_domain("*.Example.Test") == "*.example.test"


def test_normalize_domain_rejects_empty_label() -> None:
    with pytest.raises(DomainValidationError):
        normalize_domain("example..test")


def test_normalize_ip_or_network() -> None:
    assert normalize_ip_or_network("192.0.2.1") == "192.0.2.1"
    assert normalize_ip_or_network("192.0.2.0/28") == "192.0.2.0/28"


def test_normalize_ip_rejects_invalid() -> None:
    with pytest.raises(DomainValidationError):
        normalize_ip_or_network("999.999.999.999")


def test_normalize_url_default_port_dropped() -> None:
    assert normalize_url("HTTPS://Example.Test:443/api/") == "https://example.test/api/"


def test_normalize_url_rejects_non_http() -> None:
    with pytest.raises(DomainValidationError):
        normalize_url("ftp://example.test")


def test_normalize_port_range() -> None:
    assert normalize_port(443) == 443
    with pytest.raises(DomainValidationError):
        normalize_port(0)
    with pytest.raises(DomainValidationError):
        normalize_port(70000)
    with pytest.raises(DomainValidationError):
        normalize_port(True)  # type: ignore[arg-type]
