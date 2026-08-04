# src/secopent/infrastructure/oracle/verifier_factory.py
"""RescanVerifierFactory: concrete OracleVerifierFactory (W3-A T6).

Builds a per-finding RescanVerifier that re-runs the real scan against the
finding's asset. The factory holds the shared RealScanRunner + template dir +
canary; for each finding it constructs the scan_kwargs (nuclei -u <asset> with
the template mount) and returns a fresh RescanVerifier. The OracleEngine drives
that verifier N times for N/N reproduction.

This is the infrastructure-side glue so OracleService (application) stays free
of RealScanRunner/RescanVerifier imports - the application depends only on the
OracleVerifierFactory Protocol.
"""
from __future__ import annotations

from typing import Any

from ...application.oracle import OracleVerifier
from ..adapters.real_scan import RealScanRunner
from .rescan_verifier import RescanVerifier


class RescanVerifierFactory:
    """Builds per-finding RescanVerifiers over a shared scan runner + canary."""

    def __init__(
        self,
        scan_runner: RealScanRunner,
        template_host_dir: str | None,
        canary: Any,  # CanaryTokenManager (typed via the port in OracleService)
    ) -> None:
        self._scan_runner = scan_runner
        self._template_host_dir = template_host_dir
        self._canary = canary

    def for_finding(self, finding: Any) -> OracleVerifier:
        args = ["-t", "/templates/", "-u", finding.asset, "-jsonl", "-silent", "-duc"]
        scan_kwargs: dict[str, Any] = {"adapter_key": "nuclei", "args": args}
        if self._template_host_dir:
            scan_kwargs["mounts"] = {"/templates": self._template_host_dir}
        return RescanVerifier(self._scan_runner, scan_kwargs, canary=self._canary)
