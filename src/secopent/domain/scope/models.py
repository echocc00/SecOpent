from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from datetime import datetime
from urllib.parse import urlsplit

from ..common.canonical import canonical_digest, utc_now
from ..common.errors import DomainValidationError
from .normalize import (
    normalize_cloud_account,
    normalize_domain,
    normalize_ip_or_network,
    normalize_port,
    normalize_url,
)


@dataclass(frozen=True, slots=True)
class ScopeLimits:
    requests_per_second: float
    concurrency: int
    max_requests: int

    def __post_init__(self) -> None:
        if self.requests_per_second <= 0 or self.concurrency < 1 or self.max_requests < 1:
            raise DomainValidationError("scope limits must be positive")


@dataclass(frozen=True, slots=True)
class ScopeSnapshot:
    id: str
    project_id: str
    include: tuple[str, ...]
    exclude: tuple[str, ...]
    ports: tuple[int, ...]
    limits: ScopeLimits
    approved_by: str
    approved_at: datetime
    digest: str
    cloud_accounts: tuple[str, ...] = ()

    def _domain_matches(self, rule: str, domain: str) -> bool:
        if rule.startswith("*."):
            suffix = rule[2:]
            return domain.endswith("." + suffix) and domain != suffix
        return domain == rule

    def _target_matches(self, rule: str, value: str) -> bool:
        # An HTTP-prefixed rule (e.g. "http://8.133.200.235/") matches the
        # rule's HOST against the value's HOST - whether the value is a bare
        # IP/domain (includes_ip / includes_domain) or a full URL. Previously
        # this branch required value to also be HTTP-prefixed, so egress_guard
        # (which strips the scheme and passes a bare IP) could never match an
        # HTTP-prefixed scope rule (v8 scope/egress bug A).
        if rule.startswith(("http://", "https://")):
            rule_host = urlsplit(rule).hostname or ""
            if not rule_host:
                return False
            value_host = (
                urlsplit(value).hostname
                if value.startswith(("http://", "https://"))
                else value
            )
            if not value_host:
                return False
            return self._host_matches(rule_host, value_host)
        try:
            network = ipaddress.ip_network(rule, strict=False)
        except ValueError:
            return self._domain_matches(rule, normalize_domain(value))
        try:
            return ipaddress.ip_address(value) in network
        except ValueError:
            return False

    def _host_matches(self, rule_host: str, value_host: str) -> bool:
        """Match a bare host against an HTTP-rule host (IP or domain, wildcard)."""
        if self._domain_matches(rule_host, value_host):
            return True
        try:
            rule_net = ipaddress.ip_network(rule_host, strict=False)
        except ValueError:
            return False
        try:
            return ipaddress.ip_address(value_host) in rule_net
        except ValueError:
            return False

    def includes_ip(self, value: str) -> bool:
        normalized = normalize_ip_or_network(value)
        if "/" in normalized:
            raise DomainValidationError("target must be a single IP")
        return (
            not any(self._target_matches(rule, normalized) for rule in self.exclude)
            and any(self._target_matches(rule, normalized) for rule in self.include)
        )

    def includes_domain(self, value: str) -> bool:
        normalized = normalize_domain(value)
        return (
            not any(self._target_matches(rule, normalized) for rule in self.exclude)
            and any(self._target_matches(rule, normalized) for rule in self.include)
        )

    def includes_url(self, value: str) -> bool:
        normalized = normalize_url(value)
        host = urlsplit(normalized).hostname or ""

        def matches(rule: str) -> bool:
            if rule.startswith(("http://", "https://")):
                return normalized.startswith(rule)
            return self._target_matches(rule, host)

        return not any(matches(rule) for rule in self.exclude) and any(
            matches(rule) for rule in self.include
        )

    def matches_any(self, host: str, rules: tuple[str, ...]) -> bool:
        """True if any scope rule matches a host/IP value (v9 single matcher).

        The ONE host-vs-rule matcher both consumers share -
        ``ScopeSnapshot.includes_ip/includes_domain`` (post-resolution checks)
        and ``ScopeEnforcer``'s include/exclude steps (pre-scan check) - so a
        fix to URL-rule handling can never drift between the two again
        (v8 Fix A touched only ``_target_matches``; ``ScopeEnforcer``'s own
        private copy stayed broken for HTTP-prefixed rules, issue v9).
        """
        return any(self._target_matches(rule, host) for rule in rules)

    def includes_host(self, host: str) -> bool:
        """Whether ``host``/IP matches some include rule (deny-priority: exclude wins)."""
        return not self.matches_any(host, self.exclude) and self.matches_any(
            host, self.include
        )

    def excludes_host(self, host: str) -> bool:
        """Whether ``host``/IP matches ANY exclude rule (deny-priority)."""
        return self.matches_any(host, self.exclude)

    def includes_port(self, value: int) -> bool:
        return normalize_port(value) in self.ports

    def _cloud_account_excluded(self, normalized: str) -> bool:
        for rule in self.exclude:
            try:
                if normalize_cloud_account(rule) == normalized:
                    return True
            except DomainValidationError:
                # Rule is a network target (URL/IP/domain), not a cloud account.
                continue
        return False

    def includes_cloud_account(self, value: str) -> bool:
        """Return whether a cloud-account target (``provider:account_id``) is in scope.

        Deny优先: an account listed in ``exclude`` is denied even if it also
        appears in ``cloud_accounts``. The query value is normalized (provider
        lower-cased, whitespace stripped) before comparison.
        """
        normalized = normalize_cloud_account(value)
        if self._cloud_account_excluded(normalized):
            return False
        return normalized in self.cloud_accounts


@dataclass(frozen=True, slots=True)
class ScopeDraft:
    project_id: str
    include: tuple[str, ...]
    exclude: tuple[str, ...] = ()
    ports: tuple[int, ...] = (80, 443)
    limits: ScopeLimits = ScopeLimits(5.0, 3, 50_000)
    cloud_accounts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.project_id.strip() or not self.include:
            raise DomainValidationError("project and include targets are required")
        tuple(normalize_port(port) for port in self.ports)

    @staticmethod
    def _normalize_target(value: str) -> str:
        if value.strip().lower().startswith(("http://", "https://")):
            return normalize_url(value)
        try:
            return normalize_ip_or_network(value)
        except DomainValidationError:
            return normalize_domain(value)

    def freeze(self, *, snapshot_id: str, approved_by: str) -> ScopeSnapshot:
        approved_at = utc_now()
        include = tuple(sorted({self._normalize_target(item) for item in self.include}))
        exclude = tuple(sorted({self._normalize_target(item) for item in self.exclude}))
        ports = tuple(sorted({normalize_port(port) for port in self.ports}))
        cloud_accounts = tuple(
            sorted({normalize_cloud_account(item) for item in self.cloud_accounts})
        )
        payload = {
            "id": snapshot_id,
            "project_id": self.project_id,
            "include": include,
            "exclude": exclude,
            "ports": ports,
            "limits": asdict(self.limits),
            "cloud_accounts": cloud_accounts,
            "approved_by": approved_by,
            "approved_at": approved_at,
        }
        return ScopeSnapshot(
            snapshot_id, self.project_id, include, exclude, ports,
            self.limits, approved_by, approved_at, canonical_digest(payload),
            cloud_accounts,
        )
