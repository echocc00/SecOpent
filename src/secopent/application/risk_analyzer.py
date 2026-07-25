# src/secopent/application/risk_analyzer.py
"""RiskAnalyzer: static risk analysis as the case publish gate (§11.6).

Statically scans a case's DSL steps to compute its action risk and enforces the
publish rules: deny-listed patterns (Shell / unbounded loop / out-of-scope
target) block publish outright, and a case's declared risk must never be lower
than its computed risk (declaring higher is allowed - it is the conservative
choice). The scan is deterministic static analysis; nothing here executes the
case.
"""
from __future__ import annotations

from ..domain.cases.models import CaseDefinition
from ..domain.cases.risk import compute_risk, validate_declared_risk
from ..domain.policy.models import RiskClass


class RiskAnalyzer:
    """Static case risk analysis and publish-gate enforcement."""

    def analyze(self, case: CaseDefinition) -> RiskClass | None:
        """Return the computed risk, or None if a deny-listed pattern is present."""
        return compute_risk(case)

    def enforce_publish(self, case: CaseDefinition) -> None:
        """Raise RiskPublishDenied / RiskUndeclared if the case may not publish."""
        validate_declared_risk(case)
