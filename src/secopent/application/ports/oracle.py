"""Oracle verifier factory port (W3-A T4).

OracleService (application) orchestrates verification over a batch of Findings,
but each finding needs its own reproduction context (a per-finding scan against
that finding's asset). Building the concrete RescanVerifier is an infrastructure
concern, so the application depends on this factory Protocol and the composition
root supplies an implementation that wires RealScanRunner + template dir + canary.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ...domain.findings.models import Finding
from ..oracle import OracleVerifier


@runtime_checkable
class OracleVerifierFactory(Protocol):
    """Build a per-finding OracleVerifier (the reproduction backend)."""

    def for_finding(self, finding: Finding) -> OracleVerifier: ...
