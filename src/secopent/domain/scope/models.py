# src/secopent/domain/scope/models.py
from __future__ import annotations
import ipaddress
from dataclasses import asdict, dataclass
from datetime import datetime
from urllib.parse import urlsplit
from ..common.canonical import canonical_digest, utc_now
from ..common.errors import DomainValidationError
from .normalize import normalize_domain, normalize_ip_or_network, normalize_port, normalize_url


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

    def _domain_matches(self, rule: str, domain: str) -> bool:
        if rule.startswith("*."):
            suffix = rule[2:]
            return domain.endswith("." + suffix) and domain != suffix
        return domain == rule

    def _target_matches(self, rule: str, value: str) -> bool:
        if rule.startswith(("http://", "https://")):
            return value.startswith(("http://", "https://")) and normalize_url(value).startswith(rule)
        try:
            network = ipaddress.ip_network(rule, strict=False)
        except ValueError:
            return self._domain_matches(rule, normalize_domain(value))
        try:
            return ipaddress.ip_address(value) in network
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

    def includes_port(self, value: int) -> bool:
        return normalize_port(value) in self.ports


@dataclass(frozen=True, slots=True)
class ScopeDraft:
    project_id: str
    include: tuple[str, ...]
    exclude: tuple[str, ...] = ()
    ports: tuple[int, ...] = (80, 443)
    limits: ScopeLimits = ScopeLimits(5.0, 3, 50_000)

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
        payload = {
            "id": snapshot_id,
            "project_id": self.project_id,
            "include": include,
            "exclude": exclude,
            "ports": ports,
            "limits": asdict(self.limits),
            "approved_by": approved_by,
            "approved_at": approved_at,
        }
        return ScopeSnapshot(
            snapshot_id, self.project_id, include, exclude, ports,
            self.limits, approved_by, approved_at, canonical_digest(payload),
        )
