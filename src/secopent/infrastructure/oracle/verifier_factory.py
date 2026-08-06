# src/secopent/infrastructure/oracle/verifier_factory.py
"""RescanVerifierFactory: concrete OracleVerifierFactory (W3-A T6).

Builds a per-finding RescanVerifier that re-runs the real scan against the
finding's asset. The factory holds the shared RealScanRunner + template dir +
canary + verification-method registry; for each finding it constructs the
scan_kwargs (nuclei -u <asset> with the template mount) and returns a fresh
RescanVerifier. The OracleEngine drives that verifier N times for N/N
reproduction.

Probe placeholders (both travel inside the ``-u`` URL so they actually reach
the target):
- OOB: ``cb={{canary_oob_subdomain}}`` is ALWAYS embedded - the OOB branch in
  reproduce() fires only for OOB methods (oob_window_seconds > 0) with a
  wired interactsh; for everyone else the literal is harmless (URL-encoded,
  ignored by the target, prefix-match still holds).
- Echo (v0.5.0 Phase 3, 3.1): ``echo={{canary_token}}`` is embedded ONLY for
  echo-enabled methods (reflection-type vulns, per the curated registry) -
  blanket embedding would switch every non-OOB finding to the stricter echo
  verification and regress non-reflection findings.

This is the infrastructure-side glue so OracleService (application) stays free
of RealScanRunner/RescanVerifier imports - the application depends only on the
OracleVerifierFactory Protocol.
"""
from __future__ import annotations

from typing import Any

from ...application.canary import CANARY_PLACEHOLDER
from ...application.oracle import OracleVerifier
from ...domain.verification.models import VulnType
from ...domain.verification.registry import VerificationMethodRegistry
from ..adapters.real_scan import RealScanRunner
from .interactsh import InteractshClient
from .rescan_verifier import OOB_PLACEHOLDER, RescanVerifier


class RescanVerifierFactory:
    """Builds per-finding RescanVerifiers over a shared scan runner + canary."""

    def __init__(
        self,
        scan_runner: RealScanRunner,
        template_host_dir: str | None,
        canary: Any,  # CanaryTokenManager (typed via the port in OracleService)
        *,
        interactsh: InteractshClient | None = None,
        method_registry: VerificationMethodRegistry | None = None,
    ) -> None:
        self._scan_runner = scan_runner
        self._template_host_dir = template_host_dir
        self._canary = canary
        self._interactsh = interactsh
        self._method_registry = method_registry

    def for_finding(self, finding: Any, vuln_type: VulnType | None = None) -> OracleVerifier:
        asset = finding.asset
        sep = "&" if "?" in asset else "?"
        url = f"{asset}{sep}cb={OOB_PLACEHOLDER}"
        # Echo gate (3.1/E1): the token must reach the target to be echoed,
        # so it rides in the probe URL itself. Echo-enabled methods have
        # oob_window_seconds == 0, so the OOB branch never fires for them and
        # the still-literal OOB placeholder is inert (same harmlessness as
        # the legacy path). Strict semantics (E2): once the echo placeholder
        # is present, the echo branch is the only confirmation path.
        if vuln_type is not None and self._method_registry is not None:
            method = self._method_registry.method_for(vuln_type)
            if method is not None and method.echo_enabled:
                url = f"{url}&echo={CANARY_PLACEHOLDER}"
        args = [
            "-t",
            "/templates/",
            "-u",
            url,
            "-jsonl",
            "-silent",
            "-duc",
        ]
        scan_kwargs: dict[str, Any] = {"adapter_key": "nuclei", "args": args}
        if self._template_host_dir:
            scan_kwargs["mounts"] = {"/templates": self._template_host_dir}
        return RescanVerifier(
            self._scan_runner,
            scan_kwargs,
            canary=self._canary,
            interactsh=self._interactsh,
        )
