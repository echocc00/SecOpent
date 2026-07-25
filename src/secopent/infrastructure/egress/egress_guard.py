# src/secopent/infrastructure/egress/egress_guard.py
"""Scoped egress: network-layer destination enforcement (§12, §16.2 condition 6).

The execution-layer guard that decides whether a tool may open a connection to a
destination. It ALWAYS blocks sensitive destinations - cloud metadata
(169.254.169.254 / link-local), loopback, and any configured control-plane /
database / Docker-host CIDRs - EVEN if a scope mistakenly includes them. Other
destinations must be in scope and on an allowed port. DNS is resolved and each
resolved IP is rechecked (defeating DNS rebinding). netns/nftables enforcement
wraps this decision in M5; the decision logic is unit-tested here.
"""
from __future__ import annotations

import ipaddress
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit

from secopent.domain.policy.models import PolicyDecision
from secopent.domain.scope.models import ScopeSnapshot

# Always blocked, regardless of scope: cloud metadata + loopback.
DEFAULT_BLOCKED_CIDRS: tuple[str, ...] = ("169.254.0.0/16", "127.0.0.0/8")


@runtime_checkable
class DnsResolver(Protocol):
    def resolve(self, host: str) -> tuple[str, ...]: ...


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _split_target(target: str) -> tuple[str, int | None]:
    if target.startswith(("http://", "https://")):
        parsed = urlsplit(target)
        host = parsed.hostname or ""
        return host, parsed.port or (443 if parsed.scheme == "https" else 80)
    if ":" in target:
        host, _, port_str = target.rpartition(":")
        try:
            return host, int(port_str)
        except ValueError:
            return target, None
    return target, None


class EgressGuard:
    """Network-layer allow/deny for a destination, with always-blocked CIDRs."""

    def __init__(
        self,
        dns_resolver: DnsResolver,
        *,
        blocked_cidrs: tuple[str, ...] = DEFAULT_BLOCKED_CIDRS,
    ) -> None:
        self._dns = dns_resolver
        self._blocked = [ipaddress.ip_network(cidr, strict=False) for cidr in blocked_cidrs]

    def is_blocked_destination(self, ip: str) -> bool:
        """True if the IP is in an always-blocked range (metadata/loopback/...)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True  # unparseable -> fail closed
        return any(addr in network for network in self._blocked)

    def check(self, target: str, scope: ScopeSnapshot) -> PolicyDecision:
        """Decide whether a connection to ``target`` is permitted."""
        host, port = _split_target(target)
        if not host:
            return PolicyDecision(False, "INVALID_TARGET")

        resolved = (host,) if _is_ip(host) else self._dns.resolve(host)
        if not resolved:
            return PolicyDecision(False, "DNS_RESOLUTION_FAILED")

        for ip in resolved:
            if self.is_blocked_destination(ip):
                return PolicyDecision(False, "BLOCKED_DESTINATION")
            if not scope.includes_ip(ip):
                return PolicyDecision(False, "OUT_OF_SCOPE")

        if port is not None and not scope.includes_port(port):
            return PolicyDecision(False, "PORT_NOT_ALLOWED")

        return PolicyDecision(True, "ALLOWED")
