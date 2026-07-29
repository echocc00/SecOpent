# src/secopent/infrastructure/health_checkers.py
"""Infrastructure checkers for the KnowledgeHealthMonitor (§7.3, P3 §3.4).

Each checker satisfies one of the application-layer checker protocols
(``application/health.py``):

- ``OsvReachabilityChecker`` pings the OSV.dev API (real network probe).
- ``GitFreshnessChecker`` reports days since the last commit of a local
  nuclei-templates clone; when no clone is configured it reports a large age
  (treated as stale - an honest "not present" rather than a false "fresh").
- ``CurationLagChecker`` (P3 §3.4) counts upstream nuclei template tags that
  have no TestCatalog mapping. The upstream tag set comes from an injectable
  ``NucleiTagProvider``: ``LocalNucleiTagProvider`` parses a real clone;
  ``BundledNucleiTagProvider`` is a deterministic baseline for dev/CI without
  the (large) nuclei-templates repo. The tag->CWE/OWASP bridge is injected
  (the nuclei adapter's curated map) so this module stays free of cross-layer
  imports.
- ``SignatureChecker`` reports the most recent bundle signature verification
  (backed by ``BundleSignatureState`` updated by the intel bundle publisher).
"""
from __future__ import annotations

import subprocess
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Protocol

from ..domain.catalog.models import TestCatalog

# --- Source reachability ----------------------------------------------------


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
        except Exception:  # noqa: BLE001 - unreachable is the reported signal
            return False


# --- Source freshness -------------------------------------------------------


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


# --- Curation lag (P3 §3.4) -------------------------------------------------


class NucleiTagProvider(Protocol):
    """Supply the set of upstream nuclei template tags for a source."""

    def tags(self, source: str) -> frozenset[str]: ...


def _scan_nuclei_tags(root: Path) -> frozenset[str]:
    """Collect ``tags:`` entries from every ``*.yaml`` template under ``root``.

    nuclei templates carry a ``tags: foo,bar,baz`` field in their YAML header.
    Parsing is intentionally line-based (stdlib only, no YAML dependency): a
    malformed template simply contributes nothing rather than failing the scan.
    """
    tags: set[str] = set()
    for yaml_path in root.rglob("*.yaml"):
        try:
            text = yaml_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith("tags:"):
                continue
            value = stripped[len("tags:") :].strip()
            for raw in value.split(","):
                tag = raw.strip().strip("'\"").lower()
                if tag:
                    tags.add(tag)
    return frozenset(tags)


class LocalNucleiTagProvider:
    """Read the authoritative tag set from a local nuclei-templates clone."""

    def __init__(self, repo_paths: dict[str, str] | None = None) -> None:
        self._repo_paths = repo_paths or {}

    def tags(self, source: str) -> frozenset[str]:
        path = self._repo_paths.get(source)
        if path is None:
            return frozenset()
        root = Path(path)
        if not root.exists():
            return frozenset()
        return _scan_nuclei_tags(root)


# A deterministic baseline of frequently-seen nuclei tags, used when no local
# clone is configured (dev/CI). It deliberately mixes curated tags (present in
# the nuclei tag->CWE/OWASP map) with many product/tech-detect tags that have
# NO TestCatalog mapping, so the curation-lag detector reports a realistic
# non-zero lag instead of a false "nothing left to curate".
_BUNDLED_BASELINE_TAGS: frozenset[str] = frozenset(
    {
        # curated (mapped via the nuclei tag->CWE/OWASP bridge)
        "sqli", "xss", "ssrf", "rce", "lfi", "rfi", "ssti", "idor",
        "misconfig", "exposure", "default-login", "auth-bypass", "ssl",
        "open-redirect", "command-injection",
        # uncurated product / tech-detect / meta tags (no TestCatalog mapping)
        "cve2021", "cve2022", "cve2023", "log4j", "spring", "wordpress",
        "nginx", "apache", "tomcat", "iis", "grafana", "kibana", "jira",
        "confluence", "gitlab", "jenkins", "docker", "kubernetes", "aws",
        "azure", "gcp", "tech-detect", "robots-txt", "sitemap", "dns",
        "favicon", "headers", "httpbin", "fortinet", "paloalto",
    }
)


class BundledNucleiTagProvider:
    """Deterministic baseline tag set (no local clone required)."""

    def __init__(self, extra_tags: Iterable[str] = ()) -> None:
        self._tags = frozenset(
            _BUNDLED_BASELINE_TAGS | {t.strip().lower() for t in extra_tags if t.strip()}
        )

    def tags(self, source: str) -> frozenset[str]:
        return self._tags


def _catalog_coverage(catalog: TestCatalog) -> set[str]:
    """Union of every curated CWE/OWASP reference across the catalog."""
    coverage: set[str] = set()
    for classes in catalog.mappings.values():
        for test_class in classes:
            coverage.update(test_class.cwe)
            coverage.update(test_class.owasp)
    return coverage


# tag -> (cwe_tuple, owasp_tuple), e.g. the nuclei adapter's curated map.
TagCoverageMap = Mapping[str, tuple[Sequence[str], Sequence[str]]]


class CurationLagChecker:
    """Count upstream nuclei tags with no TestCatalog mapping (P3 §3.4).

    A tag is "mapped" iff it has an entry in the curated ``tag_map`` AND that
    entry's CWE/OWASP references intersect the TestCatalog's curated coverage.
    Everything else (uncurated tags, or curated-but-uncovered) counts as lag -
    matching the §7.3 alert "nuclei 新增 tag 但 TestCatalog 未映射".
    """

    def __init__(
        self,
        tag_provider: NucleiTagProvider,
        catalog: TestCatalog | None,
        tag_map: TagCoverageMap,
    ) -> None:
        self._tag_provider = tag_provider
        self._catalog = catalog
        self._tag_map = tag_map

    def unmapped_upstream_tags(self, source: str) -> int:
        if self._catalog is None:
            return 0  # no catalog -> coverage not measurable
        upstream = self._tag_provider.tags(source)
        if not upstream:
            return 0
        coverage = _catalog_coverage(self._catalog)
        mapped = 0
        for tag in upstream:
            entry = self._tag_map.get(tag)
            if entry is None:
                continue  # uncurated tag -> not mapped
            cwes, owasps = entry
            if (set(cwes) | set(owasps)) & coverage:
                mapped += 1
        return len(upstream) - mapped


# --- Bundle signature state (P3 §3.4) ---------------------------------------


class SignatureChecker:
    """Report the most recent bundle signature verification result.

    Reads ``last_valid`` off an injected state holder (the application-layer
    ``BundleSignatureState``, duck-typed here so infrastructure need not import
    application). With no state supplied, reports healthy (nothing has failed).
    """

    def __init__(self, state: object | None = None) -> None:
        self._state = state

    def last_signature_valid(self) -> bool:
        return bool(getattr(self._state, "last_valid", True))
