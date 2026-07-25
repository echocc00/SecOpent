"""TDD tests for the scoped egress guard (M5 Task 8, §16.2 condition 6)."""
from __future__ import annotations

from datetime import UTC, datetime

from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot
from secopent.infrastructure.egress.egress_guard import (
    DEFAULT_BLOCKED_CIDRS,
    EgressGuard,
)

_NOON = datetime(2026, 1, 1, tzinfo=UTC)


class FakeResolver:
    def __init__(self, table: dict[str, tuple[str, ...]]) -> None:
        self._table = table

    def resolve(self, host: str) -> tuple[str, ...]:
        return self._table.get(host, ())


def _scope(include: tuple[str, ...] = ("example.com", "192.0.2.0/24")) -> ScopeSnapshot:
    return ScopeSnapshot(
        id="s",
        project_id="p",
        include=include,
        exclude=(),
        ports=(443,),
        limits=ScopeLimits(5.0, 3, 50_000),
        approved_by="a",
        approved_at=_NOON,
        digest="sha256:" + "0" * 64,
    )


def test_in_scope_destination_allowed() -> None:
    guard = EgressGuard(FakeResolver({}))
    assert guard.check("https://192.0.2.5/", _scope()).allowed is True


def test_cloud_metadata_always_blocked_even_if_in_scope() -> None:
    # The scope (mistakenly) includes the metadata IP; egress still blocks it.
    guard = EgressGuard(FakeResolver({}))
    scope = _scope(include=("169.254.169.254",))
    decision = guard.check("http://169.254.169.254/latest/meta-data", scope)
    assert decision.allowed is False
    assert decision.reason == "BLOCKED_DESTINATION"


def test_loopback_blocked() -> None:
    guard = EgressGuard(FakeResolver({}))
    decision = guard.check("http://127.0.0.1:8080/", _scope(include=("127.0.0.1",)))
    assert decision.allowed is False
    assert decision.reason == "BLOCKED_DESTINATION"


def test_out_of_scope_denied() -> None:
    guard = EgressGuard(FakeResolver({}))
    decision = guard.check("https://203.0.113.9/", _scope())
    assert decision.allowed is False
    assert decision.reason == "OUT_OF_SCOPE"


def test_dns_rebinding_to_metadata_blocked() -> None:
    # example.com is in scope but rebinds to metadata -> blocked at the IP recheck.
    guard = EgressGuard(FakeResolver({"example.com": ("169.254.169.254",)}))
    decision = guard.check("https://example.com/", _scope())
    assert decision.allowed is False
    assert decision.reason == "BLOCKED_DESTINATION"


def test_port_not_allowed_denied() -> None:
    guard = EgressGuard(FakeResolver({}))
    decision = guard.check("https://192.0.2.5:22/", _scope())
    assert decision.allowed is False
    assert decision.reason == "PORT_NOT_ALLOWED"


def test_configurable_blocked_cidr_docker_host() -> None:
    # Block the docker bridge in addition to the defaults.
    guard = EgressGuard(
        FakeResolver({}), blocked_cidrs=DEFAULT_BLOCKED_CIDRS + ("172.17.0.0/16",)
    )
    decision = guard.check("http://172.17.0.1:2375/", _scope(include=("172.17.0.1",)))
    assert decision.allowed is False
    assert decision.reason == "BLOCKED_DESTINATION"


def test_is_blocked_destination_fails_closed_on_garbage() -> None:
    guard = EgressGuard(FakeResolver({}))
    assert guard.is_blocked_destination("not-an-ip") is True
