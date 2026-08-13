# src/secopent/application/scope_enforcer.py
"""ScopeEnforcer: 10-step execution chain with DNS-rebinding defense (§12).

Runs an ordered deny-first chain before any target is touched:

1. normalize target -> host + port
2. explicit deny (exclude wins over include)
3. include match
4. DNS resolve (injected resolver)
5. resolved-IP recheck - defeats DNS rebinding: a resolution to cloud-metadata /
   loopback / link-local, or to any IP outside the scope, is blocked even if the
   hostname itself was in scope
6. port/url
7. time window
8. risk (destructive always denied; else must be approved)
9. approval
10. budget (+ execution permit validity)

This is the execution-layer half of the API+execution double-check; the API layer
runs the same gate before dispatch.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit

from ..domain.policy.models import PolicyDecision, RiskClass
from ..domain.scope.models import ScopeSnapshot


@runtime_checkable
class DnsResolver(Protocol):
    """Resolves a hostname to its current IP addresses."""

    def resolve(self, host: str) -> tuple[str, ...]: ...


@dataclass(frozen=True, slots=True)
class EnforcementContext:
    """The non-scope inputs the chain needs (risk/approval/budget/window/permit)."""

    risk: RiskClass
    approved_risks: frozenset[RiskClass]
    approved: bool
    budget_remaining: float
    now: datetime
    time_window: tuple[int, int] | None = None  # (start_hour, end_hour) or None
    permit_valid: bool = True


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _split_target(target: str) -> tuple[str, int | None]:
    """Extract (host, port) from a URL, host:port, or bare host."""
    if target.startswith(("http://", "https://")):
        parsed = urlsplit(target)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return host, port
    if ":" in target:
        host, _, port_str = target.rpartition(":")
        try:
            return host, int(port_str)
        except ValueError:
            return target, None
    return target, None


def _is_blocked_ip(ip: str) -> bool:
    """Cloud-metadata / loopback / link-local / unspecified are always blocked."""
    addr = ipaddress.ip_address(ip)
    return (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_multicast
    )


def _deny(reason: str) -> PolicyDecision:
    return PolicyDecision(False, reason)


class ScopeEnforcer:
    """Enforce the 10-step scope chain against a target."""

    def __init__(self, dns_resolver: DnsResolver) -> None:
        self._dns = dns_resolver

    def check(
        self, target: str, scope: ScopeSnapshot, context: EnforcementContext
    ) -> PolicyDecision:
        # 1. Normalize.
        host, port = _split_target(target)
        if not host:
            return _deny("INVALID_TARGET")

        # 2. Explicit deny (exclude wins) - domain single matcher (v9: HTTP rules).
        if scope.excludes_host(host):
            return _deny("EXPLICIT_DENY")

        # 3. Include match.
        if not scope.includes_host(host):
            return _deny("NOT_INCLUDED")

        # 4. DNS resolve.
        resolved: tuple[str, ...]
        if _is_ip(host):
            resolved = (host,)
        else:
            resolved = self._dns.resolve(host)
            if not resolved:
                return _deny("DNS_RESOLUTION_FAILED")

        # 5. Resolved-IP recheck (anti-rebinding).
        for ip in resolved:
            if _is_blocked_ip(ip):
                return _deny("REBINDING_BLOCKED")
            if not scope.includes_ip(ip):
                return _deny("RESOLVED_IP_OUT_OF_SCOPE")

        # 6. Port / URL.
        if port is not None and not scope.includes_port(port):
            return _deny("PORT_NOT_ALLOWED")

        # 7. Time window.
        if context.time_window is not None:
            start, end = context.time_window
            if not start <= context.now.hour < end:
                return _deny("OUTSIDE_TIME_WINDOW")

        # 8. Risk.
        if context.risk is RiskClass.DESTRUCTIVE:
            return _deny("DESTRUCTIVE_DENIED")
        if context.risk not in context.approved_risks:
            return _deny("RISK_NOT_APPROVED")

        # 9. Approval.
        if not context.approved:
            return _deny("NOT_APPROVED")

        # 10. Budget + permit.
        if context.budget_remaining <= 0:
            return _deny("BUDGET_EXHAUSTED")
        if not context.permit_valid:
            return _deny("PERMIT_INVALID")

        return PolicyDecision(True, "ALLOWED")
