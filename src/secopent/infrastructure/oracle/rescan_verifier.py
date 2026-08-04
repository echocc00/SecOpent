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

from secopent.application.canary import CANARY_PLACEHOLDER, CanaryTokenManager
from secopent.domain.verification.models import (
    CandidateFinding,
    ReproductionStatus,
    VerificationMethod,
)

from ..adapters.real_scan import RealScanRunner


def _contains_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        return CANARY_PLACEHOLDER in value
    if isinstance(value, dict):
        return any(_contains_placeholder(v) for v in value.values())
    if isinstance(value, list | tuple):
        return any(_contains_placeholder(v) for v in value)
    return False


def _embed_canary(value: Any, canary: CanaryTokenManager, token: str) -> Any:
    """Recursively replace {{canary_token}} in every string within value."""
    if isinstance(value, str):
        return canary.embed(value, token) if CANARY_PLACEHOLDER in value else value
    if isinstance(value, dict):
        return {k: _embed_canary(v, canary, token) for k, v in value.items()}
    if isinstance(value, list):
        return [_embed_canary(v, canary, token) for v in value]
    if isinstance(value, tuple):
        return tuple(_embed_canary(v, canary, token) for v in value)
    return value


class RescanVerifier:
    """Confirm a finding by re-running the real scan and checking reproduction.

    When a ``CanaryTokenManager`` is injected AND the scan kwargs contain the
    ``{{canary_token}}`` placeholder, reproduce embeds the token, runs the scan,
    and requires the token to echo back in the tool's stdout (W2-C T4) - a
    genuine injected effect, not a coincidental response. Without a placeholder
    the legacy substring match on observations is used (backward compat).
    """

    def __init__(
        self,
        runner: RealScanRunner,
        scan_kwargs: dict[str, Any],
        *,
        canary: CanaryTokenManager | None = None,
    ) -> None:
        self._runner = runner
        self._scan_kwargs = scan_kwargs
        self._canary = canary

    def reproduce(
        self,
        candidate: CandidateFinding,
        method: VerificationMethod,
        *,
        canary_token: str,
    ) -> ReproductionStatus:
        """Re-run the scan; SUCCESS if the candidate reproduces (canary echo or
        legacy substring match)."""
        canary = self._canary
        if (
            canary is not None
            and bool(canary_token)
            and _contains_placeholder(self._scan_kwargs)
        ):
            # Canary path: embed the token, run, require it to echo in stdout.
            # verify_echo consumes the token (single-use); a non-echo is NOT a
            # confirmation even if the target string appears in observations.
            kwargs = _embed_canary(self._scan_kwargs, canary, canary_token)
            result = self._runner.scan(**kwargs)
            echoed = canary.verify_echo(result.stdout, canary_token, actor="oracle")
            return ReproductionStatus.SUCCESS if echoed else ReproductionStatus.FAILURE
        # Legacy path: substring match on the candidate's target.
        result = self._runner.scan(**self._scan_kwargs)
        reproduced = any(
            candidate.target == observation.asset_identity
            or candidate.target in observation.asset_identity
            or observation.asset_identity in candidate.target
            for observation in result.observations
        )
        return ReproductionStatus.SUCCESS if reproduced else ReproductionStatus.FAILURE
