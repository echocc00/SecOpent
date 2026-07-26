# src/secopent/infrastructure/oracle/rescan_verifier.py
"""RescanVerifier: the production oracle backend (ADR-014 revised).

The oracle confirms a candidate finding by RE-RUNNING the real scan and checking
the finding reproduces - deterministic N/N reproduction (no LLM, no external
agent). This replaced the originally-planned pentest-ai backend: A4 spike proved
ptai is an autonomous pentest agent, not a verification library, so the oracle
is self-built (see ADR-014 revision and sepcs/2026-07-27-a4-ptai-spike-findings.md).

Constructed per-scan with the RealScanRunner + the scan kwargs to reproduce; the
OracleEngine drives it N times and aggregates via decide_outcome. Verified live
against Juice Shop (SQLi confirmed at N/N in tests/e2e_real).
"""
from __future__ import annotations

from typing import Any

from secopent.domain.verification.models import (
    CandidateFinding,
    ReproductionStatus,
    VerificationMethod,
)

from ..adapters.real_scan import RealScanRunner


class RescanVerifier:
    """Confirm a finding by re-running the real scan and checking reproduction."""

    def __init__(self, runner: RealScanRunner, scan_kwargs: dict[str, Any]) -> None:
        self._runner = runner
        self._scan_kwargs = scan_kwargs

    def reproduce(
        self,
        candidate: CandidateFinding,
        method: VerificationMethod,
        *,
        canary_token: str,
    ) -> ReproductionStatus:
        """Re-run the scan; SUCCESS if the candidate's asset is found again."""
        result = self._runner.scan(**self._scan_kwargs)
        reproduced = any(
            candidate.target == observation.asset_identity
            or candidate.target in observation.asset_identity
            or observation.asset_identity in candidate.target
            for observation in result.observations
        )
        return ReproductionStatus.SUCCESS if reproduced else ReproductionStatus.FAILURE
