# src/secopent/infrastructure/catalog/default_catalog.py
"""Default TestCatalog seed (§3.1): OWASP WSTG + CIS baseline across four domains.

Seeded at startup when no catalog exists so plan generation works out of the
box (no operator import required). The classes are the curated "what to test"
baseline; each maps CWE/OWASP/CIS references to a risk tier that the Planner
uses to tier the execution DAG (recon before active before intrusive).

This is product IP content (infrastructure), not domain logic: the domain only
defines the TestCatalog/RequiredTestClass shapes.
"""
from __future__ import annotations

from ...domain.catalog.models import AssetType, RequiredTestClass, TestCatalog
from ...domain.policy.models import RiskClass

DEFAULT_CATALOG_VERSION = "2026.07-default"


def _tc(
    class_id: str, cwe: tuple[str, ...], owasp: tuple[str, ...], risk: RiskClass
) -> RequiredTestClass:
    return RequiredTestClass(id=class_id, cwe=cwe, owasp=owasp, risk=risk)


# --- Web application (OWASP WSTG) -------------------------------------------
_WEB_APP_CLASSES: tuple[RequiredTestClass, ...] = (
    _tc("wstg-info-01", ("CWE-200",), ("A01:2021",), RiskClass.PASSIVE),
    _tc("wstg-info-02", ("CWE-16",), ("A05:2021",), RiskClass.PASSIVE),
    _tc("wstg-inpv-01", ("CWE-89",), ("A03:2021",), RiskClass.ACTIVE),
    _tc("wstg-inpv-02", ("CWE-79",), ("A03:2021",), RiskClass.ACTIVE),
    _tc("wstg-inpv-03", ("CWE-918",), ("A10:2021",), RiskClass.ACTIVE),
    _tc("wstg-athn-01", ("CWE-287",), ("A07:2021",), RiskClass.ACTIVE),
    _tc("wstg-athz-01", ("CWE-284",), ("A01:2021",), RiskClass.ACTIVE),
    _tc("wstg-sess-01", ("CWE-614",), ("A07:2021",), RiskClass.ACTIVE),
    _tc("wstg-cryp-01", ("CWE-319",), ("A02:2021",), RiskClass.LOW),
)

# --- API (OWASP API Security) -----------------------------------------------
_API_CLASSES: tuple[RequiredTestClass, ...] = (
    _tc("api-bola", ("CWE-284",), ("API1:2023",), RiskClass.ACTIVE),
    _tc("api-bfla", ("CWE-285",), ("API5:2023",), RiskClass.ACTIVE),
    _tc("api-excessive-data", ("CWE-200",), ("API3:2023",), RiskClass.LOW),
    _tc("api-ssrf", ("CWE-918",), ("API10:2023",), RiskClass.ACTIVE),
    _tc("api-mass-assignment", ("CWE-915",), ("API3:2023",), RiskClass.ACTIVE),
)

# --- Network (IP/port) -------------------------------------------------------
_IP_PORT_CLASSES: tuple[RequiredTestClass, ...] = (
    _tc("net-port-scan", ("CWE-200",), (), RiskClass.PASSIVE),
    _tc("net-service-enum", ("CWE-200",), (), RiskClass.LOW),
    _tc("net-known-vuln", ("CWE-200",), (), RiskClass.ACTIVE),
)

# --- Cloud account (CIS benchmarks) -----------------------------------------
_CLOUD_CLASSES: tuple[RequiredTestClass, ...] = (
    _tc("cis-iam-1", ("CWE-732",), (), RiskClass.LOW),
    _tc("cis-logging-1", ("CWE-778",), ("A09:2021",), RiskClass.LOW),
    _tc("cis-public-exposure", ("CWE-284",), ("A01:2021",), RiskClass.ACTIVE),
    _tc("cis-metadata-1", ("CWE-918",), (), RiskClass.ACTIVE),
)


def build_default_catalog(version: str = DEFAULT_CATALOG_VERSION) -> TestCatalog:
    """Build the bundled default TestCatalog (four-domain OWASP/CIS baseline)."""
    return TestCatalog(
        version=version,
        mappings={
            AssetType.WEB_APP: _WEB_APP_CLASSES,
            AssetType.API: _API_CLASSES,
            AssetType.IP_PORT: _IP_PORT_CLASSES,
            AssetType.CLOUD_ACCOUNT: _CLOUD_CLASSES,
        },
    )
