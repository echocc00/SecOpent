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

Three reproduction paths (W2-C echo + W3-E OOB + legacy):
- OOB: InteractshClient wired + method.oob_window_seconds>0 + ``{{canary_oob_subdomain}}``
  placeholder -> embed canary as callback subdomain, scan, wait, require callback.
- Echo: CanaryTokenManager wired + ``{{canary_token}}`` placeholder -> embed, scan,
  require token in stdout.
- Legacy: substring match on observations (backward compat, no placeholder).
"""
from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from secopent.application.canary import CANARY_PLACEHOLDER, CanaryTokenManager
from secopent.domain.verification.models import (
    CandidateFinding,
    ReproductionStatus,
    VerificationMethod,
)

from ..adapters.real_scan import RealScanRunner
from .interactsh import InteractshClient

# Placeholder the probe templates use for the OOB callback subdomain (W3-E).
OOB_PLACEHOLDER = "{{canary_oob_subdomain}}"


def _contains(value: Any, marker: str) -> bool:
    if isinstance(value, str):
        return marker in value
    if isinstance(value, dict):
        return any(_contains(v, marker) for v in value.values())
    if isinstance(value, list | tuple):
        return any(_contains(v, marker) for v in value)
    return False


def _replace(value: Any, marker: str, replacement: str) -> Any:
    """Recursively replace ``marker`` with ``replacement`` in every string."""
    if isinstance(value, str):
        return value.replace(marker, replacement) if marker in value else value
    if isinstance(value, dict):
        return {k: _replace(v, marker, replacement) for k, v in value.items()}
    if isinstance(value, list):
        return [_replace(v, marker, replacement) for v in value]
    if isinstance(value, tuple):
        return tuple(_replace(v, marker, replacement) for v in value)
    return value


def _embed_canary(value: Any, canary: CanaryTokenManager, token: str) -> Any:
    """Recursively replace {{canary_token}} via the canary manager (single-use)."""
    return _replace(value, CANARY_PLACEHOLDER, token)


class RescanVerifier:
    """Confirm a finding by re-running the real scan and checking reproduction."""

    def __init__(
        self,
        runner: RealScanRunner,
        scan_kwargs: dict[str, Any],
        *,
        canary: CanaryTokenManager | None = None,
        interactsh: InteractshClient | None = None,
        oob_sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._runner = runner
        self._scan_kwargs = scan_kwargs
        self._canary = canary
        self._interactsh = interactsh
        self._oob_sleep = oob_sleep

    def reproduce(
        self,
        candidate: CandidateFinding,
        method: VerificationMethod,
        *,
        canary_token: str,
        session: Any = None,
    ) -> ReproductionStatus:
        """Re-run the scan; SUCCESS if the candidate reproduces."""
        # OOB path (W3-E): canary as callback subdomain, require an interaction.
        if (
            self._interactsh is not None
            and method.oob_window_seconds > 0
            and bool(canary_token)
            and _contains(self._scan_kwargs, OOB_PLACEHOLDER)
        ):
            subdomain, correlation = self._interactsh.allocate_correlated(canary_token)
            kwargs = _replace(self._scan_kwargs, OOB_PLACEHOLDER, subdomain)
            self._runner.scan(**kwargs)
            self._oob_sleep(method.oob_window_seconds)
            return (
                ReproductionStatus.SUCCESS
                if self._interactsh.has_callback(canary_token, correlation)
                else ReproductionStatus.FAILURE
            )
        canary = self._canary
        if (
            canary is not None
            and bool(canary_token)
            and _contains(self._scan_kwargs, CANARY_PLACEHOLDER)
        ):
            # Echo path: embed the token, run, require it to echo in stdout.
            # verify_echo consumes the token (single-use); a non-echo is NOT a
            # confirmation even if the target string appears in observations.
            kwargs = _embed_canary(self._scan_kwargs, canary, canary_token)
            result = self._runner.scan(**kwargs)
            echoed = canary.verify_echo(
                result.stdout, canary_token, actor="oracle", session=session
            )
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
