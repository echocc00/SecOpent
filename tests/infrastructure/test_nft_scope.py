# tests/infrastructure/test_nft_scope.py
"""Unit tests for NftScopeEnforcer (P2-G / M5) - the decision logic, no nft binary.

The nft binary is injected as a recording runner and DNS as a fake resolver, so
these run on any platform (the live nft path is the CI egress job). They pin the
security contract:

- in-scope IPs/CIDRs are added to the allow set;
- sensitive ranges (cloud metadata 169.254.0.0/16, loopback 127.0.0.0/8) are
  added to the BLOCK set and never the allow set (fail closed);
- a target whose DNS resolution changes between lookups (rebinding) is rejected;
- the block set is pushed before the allow set (the nft chain checks it first);
- revoke flushes both sets.
"""
from __future__ import annotations

from datetime import UTC, datetime

from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot
from secopent.infrastructure.egress.nft_scope import NftScopeEnforcer, ScopeEnforcementResult


class FakeResolver:
    """DnsResolver double: canned answers per host; can simulate rebinding."""

    def __init__(self, answers: dict[str, list[tuple[str, ...]]]) -> None:
        # host -> list of answer-sets; each resolve() pops the next (rebinding).
        self._answers = {host: list(sets) for host, sets in answers.items()}

    def resolve(self, host: str) -> tuple[str, ...]:
        sets = self._answers.get(host)
        if not sets:
            return ()
        return sets.pop(0) if len(sets) > 1 else sets[0]


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> None:
        self.calls.append(list(args))


class FakeAudit:
    def __init__(self) -> None:
        self.events: list[tuple[str, str]] = []

    def record(self, *, actor: str, action: str, resource_type: str,
               resource_id: str, payload: dict[str, object], session=None) -> None:
        self.events.append((action, resource_id))


def _snapshot(include: tuple[str, ...]) -> ScopeSnapshot:
    return ScopeSnapshot(
        id="snap-1",
        project_id="proj-1",
        include=include,
        exclude=(),
        ports=(443,),
        limits=ScopeLimits(requests_per_second=5.0, concurrency=3, max_requests=50_000),
        approved_by="analyst",
        approved_at=datetime(2026, 1, 1, tzinfo=UTC),
        digest="sha256:" + "0" * 64,
    )


def _allow_commands(runner: FakeRunner, set_name: str) -> list[str]:
    # nft argv: [nft, add, element, inet, <table>, <set>, "{", <element>, "}"]
    return [c[7] for c in runner.calls if c[5] == set_name and c[1] == "add"]


def test_in_scope_ip_is_allowed() -> None:
    runner = FakeRunner()
    enforcer = NftScopeEnforcer(FakeResolver({}), runner=runner)
    result = enforcer.apply_scope(_snapshot(("93.184.216.34",)))
    assert result.allowed == ("93.184.216.34",)
    assert result.blocked == ()
    assert "93.184.216.34" in _allow_commands(runner, "allowed_targets")


def test_metadata_ip_is_blocked_not_allowed() -> None:
    runner = FakeRunner()
    enforcer = NftScopeEnforcer(FakeResolver({}), runner=runner)
    result = enforcer.apply_scope(_snapshot(("169.254.169.254",)))
    assert result.allowed == ()
    assert "169.254.169.254" in result.blocked
    assert "169.254.169.254" in result.rejected
    assert "169.254.169.254" in _allow_commands(runner, "blocked_targets")
    assert _allow_commands(runner, "allowed_targets") == []


def test_loopback_is_blocked() -> None:
    enforcer = NftScopeEnforcer(FakeResolver({}), runner=FakeRunner())
    result = enforcer.apply_scope(_snapshot(("127.0.0.1",)))
    assert result.allowed == ()
    assert "127.0.0.1" in result.blocked


def test_domain_resolves_to_allowed_ips() -> None:
    resolver = FakeResolver({"example.com": [("93.184.216.34",)]})
    runner = FakeRunner()
    enforcer = NftScopeEnforcer(resolver, runner=runner)
    result = enforcer.apply_scope(_snapshot(("example.com",)))
    assert result.allowed == ("93.184.216.34",)


def test_rebinding_target_is_rejected() -> None:
    # First lookup public, second lookup the metadata endpoint -> rebinding.
    resolver = FakeResolver(
        {"evil.example": [("93.184.216.34",), ("169.254.169.254",)]}
    )
    audit = FakeAudit()
    enforcer = NftScopeEnforcer(resolver, runner=FakeRunner(), audit=audit)
    result = enforcer.apply_scope(_snapshot(("evil.example",)))
    assert result.allowed == ()
    assert "evil.example" in result.rejected
    assert ("egress.rejected_rebinding", "evil.example") in audit.events


def test_domain_resolving_to_metadata_is_blocked() -> None:
    resolver = FakeResolver({"sneaky.example": [("169.254.169.254",)]})
    enforcer = NftScopeEnforcer(resolver, runner=FakeRunner())
    result = enforcer.apply_scope(_snapshot(("sneaky.example",)))
    assert result.allowed == ()
    assert "169.254.169.254" in result.blocked


def test_in_scope_cidr_is_allowed() -> None:
    runner = FakeRunner()
    enforcer = NftScopeEnforcer(FakeResolver({}), runner=runner)
    result = enforcer.apply_scope(_snapshot(("10.0.0.0/24",)))
    assert "10.0.0.0/24" in result.allowed
    assert "10.0.0.0/24" in _allow_commands(runner, "allowed_targets")


def test_cidr_overlapping_metadata_is_rejected() -> None:
    enforcer = NftScopeEnforcer(FakeResolver({}), runner=FakeRunner())
    result = enforcer.apply_scope(_snapshot(("169.254.1.0/24",)))
    assert result.allowed == ()
    assert "169.254.1.0/24" in result.rejected


def test_block_set_pushed_before_allow_set() -> None:
    runner = FakeRunner()
    enforcer = NftScopeEnforcer(FakeResolver({}), runner=runner)
    enforcer.apply_scope(_snapshot(("169.254.169.254", "93.184.216.34")))
    block_idx = next(i for i, c in enumerate(runner.calls) if c[5] == "blocked_targets")
    allow_idx = next(i for i, c in enumerate(runner.calls) if c[5] == "allowed_targets")
    assert block_idx < allow_idx, "blocked set must be pushed before the allow set"


def test_revoke_flushes_both_sets() -> None:
    runner = FakeRunner()
    enforcer = NftScopeEnforcer(FakeResolver({}), runner=runner)
    enforcer.revoke()
    flushes = [c for c in runner.calls if c[1] == "flush"]
    assert ["nft", "flush", "set", "inet", "secopent_egress", "allowed_targets"] in flushes
    assert ["nft", "flush", "set", "inet", "secopent_egress", "blocked_targets"] in flushes


def test_result_is_immutable_dataclass() -> None:
    result = ScopeEnforcementResult(allowed=(), blocked=(), rejected=())
    assert result.allowed == () and result.blocked == () and result.rejected == ()
