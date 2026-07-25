# src/secopent/domain/findings/fingerprint.py
"""Deterministic finding fingerprint for cross-tool de-duplication (§13).

The fingerprint is a canonical digest of the vulnerability's identity: the
affected asset (which embeds path) plus its CWE and CVE attribution. It
deliberately EXCLUDES the reporting source/rule id, so the same vulnerability
found by different tools (nuclei vs zap vs dalfox) collapses to one Finding.
CWE/CVE order does not matter (sorted before hashing).
"""
from __future__ import annotations

from ..adapters.contracts import Observation
from ..common.canonical import canonical_digest


def observation_fingerprint(observation: Observation) -> str:
    """Compute the deterministic de-dup fingerprint for an Observation."""
    return canonical_digest(
        {
            "asset": observation.asset_identity,
            "cwe": tuple(sorted(observation.cwe)),
            "cve": tuple(sorted(observation.cve)),
        }
    )
