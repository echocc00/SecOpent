# src/secopent/domain/peer_agents/normalize.py
"""Deterministic normalization of peer findings (spec §4 归一化层).

Two gates, both deterministic (no LLM):
1. **scope gate** - the finding's asset must be inside the assessment scope;
2. **catalog gate** - the finding's CWE/OWASP must intersect at least one
   required test class for the asset type (same intersection semantics as
   ``domain.catalog.report._class_covered``), otherwise it is off-catalog
   noise and rejected.

Surviving findings become low-confidence Observations attributed to
``peer:<agent>``; only the oracle promotes them downstream.
"""
from __future__ import annotations

from ..adapters.contracts import (
    AdapterSource,
    CoverageDomain,
    Observation,
    Severity,
)
from ..catalog.models import AssetType, TestCatalog
from ..scope.models import ScopeSnapshot
from .models import PeerAgentFinding, PeerAgentRun

# Peer findings are claims, not measurements: neutral confidence; the
# oracle N/N decision is what matters downstream.
_PEER_CONFIDENCE = 0.5

_SEVERITY_BY_HINT = {severity.value: severity for severity in Severity}


def finding_in_scope(finding: PeerAgentFinding, scope: ScopeSnapshot) -> bool:
    """URL assets go through includes_url, bare hosts through includes_domain."""
    asset = finding.asset.strip()
    if asset.startswith(("http://", "https://")):
        return scope.includes_url(asset)
    return scope.includes_domain(asset)


def hits_required_catalog(
    finding: PeerAgentFinding, catalog: TestCatalog, asset_type: AssetType
) -> bool:
    """True iff the finding's CWE/OWASP intersects any required class."""
    finding_cwe = set(finding.cwe)
    finding_owasp = set(finding.owasp)
    for cls in catalog.required_for(asset_type):
        if finding_cwe & set(cls.cwe) or finding_owasp & set(cls.owasp):
            return True
    return False


def _map_severity(hint: str) -> tuple[Severity, bool]:
    severity = _SEVERITY_BY_HINT.get(hint.strip().lower())
    if severity is None:
        return Severity.INFO, False
    return severity, True


def normalize_finding(
    finding: PeerAgentFinding, run: PeerAgentRun
) -> Observation:
    """Convert one in-scope, on-catalog peer finding to an Observation."""
    severity, mapped = _map_severity(finding.severity_hint)
    raw: dict[str, object] = {
        "peer_run_id": run.id,
        "severity_hint": finding.severity_hint,
        "payload_summary": finding.payload_summary,
        "raw_ref": finding.raw_ref,
    }
    if not mapped:
        raw["severity_hint_unmapped"] = finding.severity_hint
    return Observation(
        external_id=finding.id,
        asset_identity=finding.asset,
        source=AdapterSource(
            name=f"peer:{run.agent_name}",
            version=run.agent_version,
            template_version="na",
        ),
        rule_id=finding.id,
        rule_version=run.agent_version,
        # P0 peers target web/API surfaces; P2 may map per descriptor
        # capability once non-web peers are adopted.
        coverage_domain=CoverageDomain.WEB,
        title=finding.title,
        severity=severity,
        confidence=_PEER_CONFIDENCE,
        cwe=finding.cwe,
        cve=finding.cve,
        owasp=finding.owasp,
        raw=raw,
    )
