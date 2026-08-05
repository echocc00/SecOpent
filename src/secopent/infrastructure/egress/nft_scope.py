# src/secopent/infrastructure/egress/nft_scope.py
"""nftables scoped-egress enforcement (P2-G / M5).

The network-layer counterpart to the application-layer :class:`EgressGuard`.
Where ``EgressGuard`` refuses out-of-scope / sensitive destinations in-process
before a container runs, ``NftScopeEnforcer`` pushes the scoped allow-set into a
kernel nftables set so egress is enforced at the PACKET level regardless of
application logic (defence in depth):

- each scoped target is resolved to IPs with a **DNS-rebinding double-check** - a
  target whose resolution changes between two lookups is rejected and audited
  (defeats a hostname that passes scope on a public IP then rebinds onto the
  cloud-metadata endpoint at scan time);
- it **fails closed**: any IP/CIDR in an always-blocked range (cloud metadata
  ``169.254.0.0/16`` + loopback ``127.0.0.0/8`` - the same CIDRs as EgressGuard)
  goes to the block set, NEVER the allow set, and is audited as denied;
- it populates the ``allowed_targets`` / ``blocked_targets`` sets of the
  ``inet secopent_egress`` table (``scripts/provision/egress.nft``), whose output
  chain default-drops and checks blocked-before-allowed;
- :meth:`revoke` flushes both sets when the assessment ends.

The ``nft`` binary is invoked through an injectable ``runner`` and DNS through an
injectable :class:`DnsResolver`, so the decision logic is unit-testable on any
platform; ``nft`` itself runs on Linux (the CI ``egress`` job exercises it live).
"""
from __future__ import annotations

import ipaddress
import socket
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

from secopent.domain.common.errors import DomainError
from secopent.domain.scope.models import ScopeSnapshot

from .egress_guard import DEFAULT_BLOCKED_CIDRS, DnsResolver, EgressGuard


class DnsRebindingError(DomainError):
    """A target resolved to different IPs across lookups (possible rebinding)."""


@runtime_checkable
class AuditSink(Protocol):
    """Minimal audit surface the enforcer records allow/deny decisions to."""

    def record(
        self,
        *,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str,
        payload: dict[str, object],
        session: Any = None,
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class ScopeEnforcementResult:
    """Outcome of pushing a scope into the nft sets."""

    allowed: tuple[str, ...]  # IPs/CIDRs added to the nft allow set
    blocked: tuple[str, ...]  # IPs added to the nft block set (metadata/loopback)
    rejected: tuple[str, ...]  # targets refused (rebinding / blocked / unresolvable)


# nft command runner: argv list -> None (raises CalledProcessError on failure).
NftRunner = Callable[[list[str]], None]
_DEFAULT_TABLE = "secopent_egress"


def _default_runner(args: list[str]) -> None:
    subprocess.run(args, check=True)  # noqa: S603 - fixed nft argv, not a shell


class SocketDnsResolver:
    """Production :class:`DnsResolver`: resolves via the system resolver."""

    def resolve(self, host: str) -> tuple[str, ...]:
        try:
            infos = socket.getaddrinfo(host, None)
        except OSError:
            return ()
        return tuple(sorted({info[4][0] for info in infos}))


def _host_or_network(entry: str) -> str:
    """Extract the addressable host / IP / CIDR from a scope ``include`` entry.

    ``include`` entries are normalized to a URL, an IP/CIDR, or a domain (see
    ``ScopeDraft._normalize_target``). Strip a URL to its hostname and a
    ``host:port`` to its host; pass IPs/CIDRs/domains through unchanged.
    """
    if entry.startswith(("http://", "https://")):
        return urlsplit(entry).hostname or ""
    if "/" not in entry and entry.count(":") == 1:
        host, _, port = entry.rpartition(":")
        if port.isdigit():
            return host
    return entry


class NftScopeEnforcer:
    """Push a ScopeSnapshot's targets into nftables allow/block sets."""

    def __init__(
        self,
        dns_resolver: DnsResolver,
        *,
        guard: EgressGuard | None = None,
        runner: NftRunner | None = None,
        audit: AuditSink | None = None,
        table: str = _DEFAULT_TABLE,
        blocked_cidrs: tuple[str, ...] = DEFAULT_BLOCKED_CIDRS,
        netns: str | None = None,
    ) -> None:
        self._dns = dns_resolver
        self._guard = guard or EgressGuard(dns_resolver, blocked_cidrs=blocked_cidrs)
        self._runner = runner or _default_runner
        self._audit = audit
        self._table = table
        self._netns = netns
        self._blocked_nets = [
            ipaddress.ip_network(cidr, strict=False) for cidr in blocked_cidrs
        ]

    def apply_scope(
        self, snapshot: ScopeSnapshot, *, session: Any = None
    ) -> ScopeEnforcementResult:
        """Resolve scoped targets and populate the nft allow/block sets."""
        allowed: list[str] = []
        blocked: list[str] = []
        rejected: list[str] = []
        for entry in snapshot.include:
            host = _host_or_network(entry)
            if not host:
                rejected.append(entry)
                continue
            if "/" in host:  # CIDR network
                self._classify_network(
                    host, allowed, blocked, rejected, entry, session=session
                )
                continue
            try:
                ips = self._resolve_with_rebinding_check(host)
            except DnsRebindingError:
                rejected.append(entry)
                self._record("egress.rejected_rebinding", entry, session=session)
                continue
            for ip in ips:
                if self._guard.is_blocked_destination(ip):
                    if ip not in blocked:
                        blocked.append(ip)
                    rejected.append(entry)
                    self._record("egress.denied_blocked", ip, session=session)
                elif ip not in allowed:
                    allowed.append(ip)
                    self._record("egress.allowed", ip, session=session)
        # Blocked set is pushed first: the nft output chain checks it BEFORE the
        # allow set, so a sensitive range is dropped even if it were whitelisted.
        self._add_elements("blocked_targets", blocked)
        self._add_elements("allowed_targets", allowed)
        return ScopeEnforcementResult(tuple(allowed), tuple(blocked), tuple(rejected))

    def revoke(self) -> None:
        """Flush both sets (call when the assessment ends)."""
        self._run(["nft", "flush", "set", "inet", self._table, "allowed_targets"])
        self._run(["nft", "flush", "set", "inet", self._table, "blocked_targets"])

    # -- internals ------------------------------------------------------------

    def _classify_network(
        self,
        cidr: str,
        allowed: list[str],
        blocked: list[str],
        rejected: list[str],
        entry: str,
        *,
        session: Any = None,
    ) -> None:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            rejected.append(entry)
            return
        if any(network.overlaps(net) for net in self._blocked_nets):
            rejected.append(entry)
            self._record("egress.denied_blocked", cidr, session=session)
            return
        if cidr not in allowed:
            allowed.append(cidr)
            self._record("egress.allowed", cidr, session=session)

    def _resolve_with_rebinding_check(self, host: str) -> tuple[str, ...]:
        """Resolve a host twice; reject if the answers differ (rebinding)."""
        try:
            if ipaddress.ip_address(host):
                return (host,)
        except ValueError:
            pass
        first = set(self._dns.resolve(host))
        second = set(self._dns.resolve(host))
        if not first:
            raise DnsRebindingError(f"{host}: unresolvable")
        if first != second:
            raise DnsRebindingError(
                f"{host}: resolution changed {sorted(first)} -> {sorted(second)}"
            )
        return tuple(sorted(first))

    def _add_elements(self, set_name: str, elements: Sequence[str]) -> None:
        for element in elements:
            self._run(
                ["nft", "add", "element", "inet", self._table, set_name, "{", element, "}"]
            )

    def _run(self, args: list[str]) -> None:
        if self._netns is not None:
            # W3-F: run nft inside the isolated netns (ip netns exec <netns> nft ...).
            args = ["ip", "netns", "exec", self._netns, *args]
        self._runner(args)

    def _record(
        self, action: str, resource_id: str, *, session: Any = None
    ) -> None:
        if self._audit is None:
            return
        self._audit.record(
            actor="nft_scope",
            action=action,
            resource_type="scope",
            resource_id=resource_id,
            payload={},
            session=session,
        )
