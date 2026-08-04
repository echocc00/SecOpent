"""NftScopeEnforcer netns parameter (W3-F T2)."""
from __future__ import annotations

from secopent.infrastructure.egress.egress_guard import DnsResolver, EgressGuard
from secopent.infrastructure.egress.nft_scope import NftScopeEnforcer
from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot
from datetime import UTC, datetime


class _RecordingRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> None:
        self.calls.append(list(args))


class _StubDns(DnsResolver):
    def resolve(self, host: str) -> tuple[str, ...]:
        return ("192.0.2.10",)


def _snapshot(include: tuple[str, ...] = ("192.0.2.10",)) -> ScopeSnapshot:
    return ScopeSnapshot(
        id="s1", project_id="p1", include=include, exclude=(),
        ports=(80,), limits=ScopeLimits(requests_per_second=10, concurrency=2, max_requests=100),
        approved_by="a", approved_at=datetime.now(UTC), digest="sha256:s",
    )


def test_without_netns_nft_runs_in_default_namespace() -> None:
    runner = _RecordingRunner()
    enf = NftScopeEnforcer(_StubDns(), guard=EgressGuard(_StubDns()), runner=runner)
    enf.apply_scope(_snapshot())
    # Bare nft commands (host default netns).
    assert all(c[0] == "nft" for c in runner.calls)


def test_with_netns_nft_runs_via_ip_netns_exec() -> None:
    runner = _RecordingRunner()
    enf = NftScopeEnforcer(
        _StubDns(),
        guard=EgressGuard(_StubDns()),
        runner=runner,
        netns="secopent-asm-1",
    )
    enf.apply_scope(_snapshot())
    # Every nft command is prefixed with ip netns exec <netns>.
    assert all(
        c[:4] == ["ip", "netns", "exec", "secopent-asm-1"] and c[4] == "nft"
        for c in runner.calls
    )


def test_revoke_with_netns_also_prefixed() -> None:
    runner = _RecordingRunner()
    enf = NftScopeEnforcer(
        _StubDns(),
        guard=EgressGuard(_StubDns()),
        runner=runner,
        netns="secopent-asm-2",
    )
    enf.revoke()
    assert all(
        c[:4] == ["ip", "netns", "exec", "secopent-asm-2"] for c in runner.calls
    )
