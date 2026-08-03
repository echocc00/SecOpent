# src/secopent/infrastructure/catalog/extended_catalog.py
"""Extended TestCatalog: default classes + handbook-first-batch classes.

New VERSION (never edits the default): historical Assessments pin the old
snapshot; the coverage-degeneration gate (KnowledgeHealthMonitor) requires
new >= old, which adding classes satisfies.
"""
from __future__ import annotations

from ...domain.catalog.models import AssetType, RequiredTestClass, TestCatalog
from ...domain.policy.models import RiskClass
from .default_catalog import build_default_catalog

EXTENDED_CATALOG_VERSION = "2026.08-extended-p1a"


# Local copy of default_catalog._tc to avoid importing a private name
# (ruff PLC2701). Same signature, same semantics.
def _tc(
    class_id: str, cwe: tuple[str, ...], owasp: tuple[str, ...], risk: RiskClass
) -> RequiredTestClass:
    return RequiredTestClass(id=class_id, cwe=cwe, owasp=owasp, risk=risk)


_NEW_WEB_CLASSES: tuple[RequiredTestClass, ...] = (
    _tc("wstg-athn-jwt", ("CWE-287", "CWE-347"), ("A07:2021",), RiskClass.ACTIVE),
    _tc(
        "wstg-inpv-deserialization",
        ("CWE-502",),
        ("A08:2021",),
        RiskClass.INTRUSIVE,
    ),
    _tc(
        "wstg-inpv-path-traversal",
        ("CWE-22", "CWE-98"),
        ("A01:2021",),
        RiskClass.ACTIVE,
    ),
    _tc("wstg-athz-idor", ("CWE-639",), ("A01:2021",), RiskClass.ACTIVE),
    _tc(
        "wstg-buslogic-race",
        ("CWE-362", "CWE-367"),
        ("A04:2021",),
        RiskClass.ACTIVE,
    ),
    _tc("wstg-inpv-smuggling", ("CWE-444",), ("A03:2021",), RiskClass.INTRUSIVE),
    _tc(
        "wstg-clientside-proto-pollution",
        ("CWE-1321",),
        ("A03:2021",),
        RiskClass.ACTIVE,
    ),
)


def build_extended_catalog() -> TestCatalog:
    """Build the extended catalog (default + first-batch handbook classes)."""
    base = build_default_catalog()
    mappings = dict(base.mappings)
    mappings[AssetType.WEB_APP] = (
        mappings.get(AssetType.WEB_APP, ()) + _NEW_WEB_CLASSES
    )
    return TestCatalog(version=EXTENDED_CATALOG_VERSION, mappings=mappings)
