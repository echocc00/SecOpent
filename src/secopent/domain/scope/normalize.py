# src/secopent/domain/scope/normalize.py
from __future__ import annotations

import ipaddress
import posixpath
from urllib.parse import SplitResult, urlsplit, urlunsplit

from ..common.errors import DomainValidationError


def normalize_domain(value: str) -> str:
    domain = value.strip().rstrip(".").lower()
    wildcard = domain.startswith("*.")
    raw = domain[2:] if wildcard else domain
    try:
        encoded = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DomainValidationError("invalid domain") from exc
    if not encoded or any(not label for label in encoded.split(".")):
        raise DomainValidationError("invalid domain")
    return ("*." if wildcard else "") + encoded


def normalize_ip_or_network(value: str) -> str:
    try:
        if "/" in value:
            return str(ipaddress.ip_network(value.strip(), strict=False))
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise DomainValidationError("invalid IP or CIDR") from exc


def normalize_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise DomainValidationError("URL must use http or https")
    host = normalize_domain(parsed.hostname)
    port = parsed.port
    if port == (443 if scheme == "https" else 80):
        port = None
    netloc = host if port is None else f"{host}:{port}"
    path = posixpath.normpath("/" + parsed.path.lstrip("/"))
    if parsed.path.endswith("/") and not path.endswith("/"):
        path += "/"
    return urlunsplit(SplitResult(scheme, netloc, path, parsed.query, ""))


def normalize_port(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise DomainValidationError("port must be between 1 and 65535")
    return value


def normalize_cloud_account(value: str) -> str:
    """Normalize a cloud-account target of the form ``provider:account_id``.

    Cloud adapters (prowler/trivy/kube-bench/checkov/scoutsuite) target cloud
    accounts/images rather than network hosts, so they cannot be expressed as a
    URL/IP/domain. The canonical form lowercases the provider and preserves the
    account id verbatim (account ids are provider-specific: AWS 12-digit ids,
    Azure UUIDs, GCP project slugs) e.g. ``AWS:123456789012`` -> ``aws:123456789012``.

    Raises:
        DomainValidationError: if the value is not ``provider:account_id`` with
            a non-empty alphanumeric provider and non-empty account id.
    """
    raw = value.strip()
    provider, sep, account = raw.partition(":")
    if not sep:
        raise DomainValidationError("cloud account must be provider:account_id")
    provider = provider.strip().lower()
    account = account.strip()
    if not provider or not account:
        raise DomainValidationError("cloud account provider and id must be non-empty")
    if not provider.replace("-", "").replace("_", "").isalnum():
        raise DomainValidationError("invalid cloud provider")
    return f"{provider}:{account}"
