# src/secopent/domain/verification/registry.py
"""VerificationMethodRegistry: curated vuln-type -> verification method (§9).

The registry is the curation layer that sits above the oracle engine: it answers
"for this vulnerability type, how many independent reproductions (N) confirm it,
what retry strategy, and when does a flaky target become INCONCLUSIVE rather
than REFUTED?" The default registry seeds the 14 curated vulnerability classes.
"""
from __future__ import annotations

from collections.abc import Iterable

from ..common.errors import DomainValidationError
from .models import VerificationMethod, VulnType


class VerificationMethodRegistry:
    """Immutable lookup of VerificationMethod by VulnType."""

    def __init__(self, methods: Iterable[VerificationMethod]) -> None:
        by_type: dict[VulnType, VerificationMethod] = {}
        for method in methods:
            if method.vuln_type in by_type:
                raise DomainValidationError(
                    f"duplicate verification method for vuln_type={method.vuln_type.value}"
                )
            by_type[method.vuln_type] = method
        self._methods = by_type

    def method_for(self, vuln_type: VulnType) -> VerificationMethod | None:
        """Return the method for a vuln type, or None if not curated."""
        return self._methods.get(vuln_type)

    def require_method(self, vuln_type: VulnType) -> VerificationMethod:
        """Return the method for a vuln type, raising if it is not curated."""
        method = self._methods.get(vuln_type)
        if method is None:
            raise DomainValidationError(
                f"no verification method curated for vuln_type={vuln_type.value}"
            )
        return method

    def vuln_types(self) -> tuple[VulnType, ...]:
        """Return the curated vuln types, sorted by their string value."""
        return tuple(sorted(self._methods, key=lambda vt: vt.value))


def default_registry() -> VerificationMethodRegistry:
    """Seed the 14 curated verification methods.

    N values reflect verification cost/confidence: SQLi timing needs N=5
    independent delays; echo/OOB-based classes use N=3. SSRF/XXE/deserialization
    are out-of-band and carry a 30s callback window. All default to cross-worker
    retry with a 5xx threshold of 2 (two consecutive server-error inconclusives
    escalate to human review rather than REFUTED).
    """
    oob_window = 30
    return VerificationMethodRegistry(
        [
            VerificationMethod(vuln_type=VulnType.SQLI, default_n=5),
            VerificationMethod(vuln_type=VulnType.RCE, default_n=3),
            VerificationMethod(
                vuln_type=VulnType.SSRF, default_n=3, oob_window_seconds=oob_window
            ),
            VerificationMethod(
                vuln_type=VulnType.XXE, default_n=3, oob_window_seconds=oob_window
            ),
            VerificationMethod(
                vuln_type=VulnType.XSS, default_n=3, echo_enabled=True
            ),
            VerificationMethod(
                vuln_type=VulnType.DESERIALIZATION,
                default_n=3,
                oob_window_seconds=oob_window,
            ),
            VerificationMethod(vuln_type=VulnType.FILE_READ, default_n=3),
            VerificationMethod(vuln_type=VulnType.AUTH_BYPASS, default_n=3),
            VerificationMethod(vuln_type=VulnType.PATH_TRAVERSAL, default_n=3),
            VerificationMethod(vuln_type=VulnType.IDOR, default_n=3),
            VerificationMethod(vuln_type=VulnType.PARAM_TAMPERING, default_n=3),
            VerificationMethod(vuln_type=VulnType.MFA_BYPASS, default_n=3),
            VerificationMethod(vuln_type=VulnType.WEAK_CREDENTIALS, default_n=3),
            VerificationMethod(vuln_type=VulnType.PRIVILEGE_ESCALATION, default_n=3),
        ]
    )
