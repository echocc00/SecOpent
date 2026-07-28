# src/secopent/infrastructure/health_checkers.py
"""Infrastructure checkers for the KnowledgeHealthMonitor (§7.3).

Each checker satisfies one of the application-layer checker protocols:

- ``OsvReachabilityChecker`` pings the OSV.dev API (real network probe).
- ``GitFreshnessChecker`` reports days since the last commit of a local
  nuclei-templates clone; when no clone is configured it reports a large age
  (treated as stale - an honest "not present" rather than a false "fresh").
- ``CurationLagChecker`` / ``SignatureChecker`` are placeholders until the
  nuclei-templates curation pipeline and bundle signature tracking are wired
  (P3 §3.4); they report healthy (no detected problem) in the meantime.
"""
from __future__ import annotations

import subprocess


class OsvReachabilityChecker:
    """Probe OSV.dev reachability over HTTP (short timeout)."""

    def __init__(
        self,
        url: str = "https://api.osv.dev/v1/vulns/GHSA-xxxx",
        timeout: float = 5.0,
    ) -> None:
        self._url = url
        self._timeout = timeout

    def is_reachable(self, source: str) -> bool:
        import httpx

        try:
            response = httpx.get(self._url, timeout=self._timeout)
            # Any HTTP response means the source is reachable (even a 404).
            return response.status_code < 500
        except Exception:
            return False


class GitFreshnessChecker:
    """Days since the last commit of a local git clone (nuclei-templates)."""

    def __init__(self, repo_paths: dict[str, str] | None = None) -> None:
        # source -> local clone path; absent source => unknown => stale.
        self._repo_paths = repo_paths or {}

    def days_since_last_commit_for(self, source: str) -> int:
        path = self._repo_paths.get(source)
        if path is None:
            return 999  # no local clone -> cannot assert freshness -> stale
        try:
            result = subprocess.run(
                ["git", "-C", path, "log", "-1", "--format=%ct"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            last_ts = int(result.stdout.strip())
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return 999
        import time

        return max(0, int((time.time() - last_ts) // 86400))


class CurationLagChecker:
    """Placeholder: nuclei-templates curation lag is not measured yet (0)."""

    def unmapped_upstream_tags(self, source: str) -> int:
        return 0


class SignatureChecker:
    """Placeholder: no bundle signature failure is tracked yet (healthy)."""

    def last_signature_valid(self) -> bool:
        return True
