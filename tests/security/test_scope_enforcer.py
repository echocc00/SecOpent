"""TDD tests for ScopeEnforcer (M5 Task 1, §12 10-step chain + anti-rebinding).

The enforcer runs a 10-step chain (normalize -> explicit deny -> include match ->
DNS resolve -> resolved-IP recheck -> port/url -> time window -> risk -> approval
-> budget -> permit). Deny is first. The resolved-IP recheck defeats DNS
rebinding: even if a hostname is in scope, a resolution to cloud-metadata /
loopback / out-of-scope IPs is blocked. The DNS resolver is injected (mock here;
real resolver in M5).
"""
from __future__ import annotations

from datetime import UTC, datetime

from secopent.application.scope_enforcer import (
    EnforcementContext,
    ScopeEnforcer,
)
from secopent.domain.policy.models import RiskClass
from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot

_NOON = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


class FakeDnsResolver:
    def __init__(self, table: dict[str, tuple[str, ...]]) -> None:
        self._table = table

    def resolve(self, host: str) -> tuple[str, ...]:
        return self._table.get(host, ())


def _scope() -> ScopeSnapshot:
    return ScopeSnapshot(
        id="snap-1",
        project_id="proj-1",
        include=("example.com", "192.0.2.0/24"),
        exclude=("bad.example.com",),
        ports=(443,),
        limits=ScopeLimits(requests_per_second=5.0, concurrency=3, max_requests=50_000),
        approved_by="analyst",
        approved_at=_NOON,
        digest="sha256:" + "0" * 64,
    )


def _context(**overrides: object) -> EnforcementContext:
    base: dict[str, object] = {
        "risk": RiskClass.ACTIVE,
        "approved_risks": frozenset(
            {RiskClass.PASSIVE, RiskClass.LOW, RiskClass.ACTIVE}
        ),
        "approved": True,
        "budget_remaining": 100.0,
        "now": _NOON,
        "time_window": None,
        "permit_valid": True,
    }
    base.update(overrides)
    return EnforcementContext(**base)  # type: ignore[arg-type]


def _enforcer(table: dict[str, tuple[str, ...]] | None = None) -> ScopeEnforcer:
    table = table if table is not None else {"example.com": ("192.0.2.10",)}
    return ScopeEnforcer(FakeDnsResolver(table))


def test_in_scope_target_allowed() -> None:
    decision = _enforcer().check("https://example.com/", _scope(), _context())
    assert decision.allowed is True


def test_explicit_deny_wins_over_include() -> None:
    # bad.example.com would resolve in-scope but is explicitly excluded.
    enforcer = _enforcer({"bad.example.com": ("192.0.2.99",)})
    scope = ScopeSnapshot(
        id="s",
        project_id="p",
        include=("example.com", "192.0.2.0/24", "bad.example.com"),
        exclude=("bad.example.com",),
        ports=(443,),
        limits=ScopeLimits(5.0, 3, 50_000),
        approved_by="a",
        approved_at=_NOON,
        digest="sha256:" + "0" * 64,
    )
    decision = enforcer.check("https://bad.example.com/", scope, _context())
    assert decision.allowed is False
    assert decision.reason == "EXPLICIT_DENY"


def test_not_included_denied() -> None:
    decision = _enforcer({"other.com": ("203.0.113.5",)}).check(
        "https://other.com/", _scope(), _context()
    )
    assert decision.allowed is False
    assert decision.reason == "NOT_INCLUDED"


def test_dns_rebinding_to_metadata_blocked() -> None:
    # example.com is in scope, but it rebinds to cloud metadata -> blocked.
    enforcer = _enforcer({"example.com": ("169.254.169.254",)})
    decision = enforcer.check("https://example.com/", _scope(), _context())
    assert decision.allowed is False
    assert decision.reason == "REBINDING_BLOCKED"


def test_dns_rebinding_to_loopback_blocked() -> None:
    enforcer = _enforcer({"example.com": ("127.0.0.1",)})
    decision = enforcer.check("https://example.com/", _scope(), _context())
    assert decision.allowed is False
    assert decision.reason == "REBINDING_BLOCKED"


def test_resolved_ip_out_of_scope_blocked() -> None:
    # Resolves to a public IP that is NOT in the scope's include set.
    enforcer = _enforcer({"example.com": ("203.0.113.99",)})
    decision = enforcer.check("https://example.com/", _scope(), _context())
    assert decision.allowed is False
    assert decision.reason == "RESOLVED_IP_OUT_OF_SCOPE"


def test_port_not_allowed_denied() -> None:
    decision = _enforcer().check("https://example.com:8443/", _scope(), _context())
    assert decision.allowed is False
    assert decision.reason == "PORT_NOT_ALLOWED"


def test_outside_time_window_denied() -> None:
    # Allowed window 02:00-04:00; request at noon is outside.
    decision = _enforcer().check(
        "https://example.com/", _scope(), _context(time_window=(2, 4))
    )
    assert decision.allowed is False
    assert decision.reason == "OUTSIDE_TIME_WINDOW"


def test_risk_not_approved_denied() -> None:
    decision = _enforcer().check(
        "https://example.com/",
        _scope(),
        _context(risk=RiskClass.INTRUSIVE),  # not in approved_risks
    )
    assert decision.allowed is False
    assert decision.reason == "RISK_NOT_APPROVED"


def test_destructive_always_denied() -> None:
    decision = _enforcer().check(
        "https://example.com/",
        _scope(),
        _context(
            risk=RiskClass.DESTRUCTIVE,
            approved_risks=frozenset({RiskClass.DESTRUCTIVE}),
        ),
    )
    assert decision.allowed is False
    assert decision.reason == "DESTRUCTIVE_DENIED"


def test_not_approved_denied() -> None:
    decision = _enforcer().check(
        "https://example.com/", _scope(), _context(approved=False)
    )
    assert decision.allowed is False
    assert decision.reason == "NOT_APPROVED"


def test_budget_exhausted_denied() -> None:
    decision = _enforcer().check(
        "https://example.com/", _scope(), _context(budget_remaining=0.0)
    )
    assert decision.allowed is False
    assert decision.reason == "BUDGET_EXHAUSTED"


def test_invalid_permit_denied() -> None:
    decision = _enforcer().check(
        "https://example.com/", _scope(), _context(permit_valid=False)
    )
    assert decision.allowed is False
    assert decision.reason == "PERMIT_INVALID"


def test_ip_target_skips_dns_and_is_rechecked() -> None:
    # A direct in-scope IP target needs no DNS resolution and passes.
    decision = _enforcer().check("https://192.0.2.5/", _scope(), _context())
    assert decision.allowed is True


# ---------------------------------------------------------------------------
# HTTP-prefixed scope rules (issue v9 regression)
# ---------------------------------------------------------------------------


def _url_ip_scope() -> ScopeSnapshot:
    """The documented scope form - operators write URL rules, not bare IPs."""
    return ScopeSnapshot(
        id="s9", project_id="p9",
        include=("http://192.168.2.18:3000/",),
        exclude=(), ports=(3000, 8080),
        limits=ScopeLimits(5.0, 3, 50_000),
        approved_by="h", approved_at=_NOON, digest="sha256:" + "0" * 64,
    )


def test_http_prefixed_rule_allows_url_target() -> None:
    """v9: the documented scope form must pass the gate (was NOT_INCLUDED)."""
    decision = _enforcer().check(
        "http://192.168.2.18:3000", _url_ip_scope(), _context()
    )
    assert decision.allowed is True
    assert decision.reason == "ALLOWED"


def test_http_prefixed_rule_allows_bare_ip_target() -> None:
    # Scheme-stripped targets (how callers pass IPs) match the same rule.
    decision = _enforcer().check("8.133.200.235", _url_ip_scope(), _context())
    assert decision.reason == "NOT_INCLUDED"  # foreign host, correctly rejected
    ip_scope = ScopeSnapshot(
        id="s9b", project_id="p9b",
        include=("http://8.133.200.235/",), exclude=(), ports=(80,),
        limits=ScopeLimits(5.0, 3, 50_000),
        approved_by="h", approved_at=_NOON, digest="sha256:" + "0" * 64,
    )
    assert _enforcer().check("8.133.200.235", ip_scope, _context()).allowed is True


def test_http_prefixed_exclude_deny_wins() -> None:
    scope = ScopeSnapshot(
        id="s9c", project_id="p9c",
        include=("http://192.168.2.18:3000/",),
        exclude=("http://192.168.2.18/",), ports=(3000,),
        limits=ScopeLimits(5.0, 3, 50_000),
        approved_by="h", approved_at=_NOON, digest="sha256:" + "0" * 64,
    )
    decision = _enforcer().check(
        "http://192.168.2.18:3000", scope, _context()
    )
    assert decision.allowed is False
    assert decision.reason == "EXPLICIT_DENY"


def test_http_prefixed_rule_rejects_foreign_host() -> None:
    decision = _enforcer().check(
        "http://evil.example.com", _url_ip_scope(), _context()
    )
    assert decision.allowed is False
    assert decision.reason == "NOT_INCLUDED"


def test_http_prefixed_domain_rule_with_dns() -> None:
    """A URL domain rule resolves through the injected resolver and is rechecked.

    The resolved-IP recheck needs an IP-side rule to prove the resolution is
    in scope (a domain rule alone cannot prove an arbitrary IP belongs to it) -
    operators pair the domain with its authorized netblock, as here.
    """
    enforcer = _enforcer({"app.example.test": ("192.168.2.18",)})
    scope = ScopeSnapshot(
        id="s9d", project_id="p9d",
        include=("http://app.example.test:3000/", "192.168.2.0/24"),
        exclude=(), ports=(3000,),
        limits=ScopeLimits(5.0, 3, 50_000),
        approved_by="h", approved_at=_NOON, digest="sha256:" + "0" * 64,
    )
    decision = enforcer.check(
        "http://app.example.test:3000", scope, _context()
    )
    assert decision.allowed is True
