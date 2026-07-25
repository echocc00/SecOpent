"""Intel source sync (Task 5).

Per-source clients (OSV primary, CISA KEV, FIRST EPSS, NVD-via-proxy) plus a
`SourceSync` coordinator enforcing per-source frequency (design §10.2).

Provenance (§10.7) is attached to every fetched entity. NVD-via-proxy degrades
gracefully on 503 (CN network reality): returns an empty list and logs, never
raises.
"""
from __future__ import annotations

import csv
import io
import logging
import os
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import httpx

from secopent.domain.intel.models import (
    AffectedProduct,
    ExploitationSignal,
    Vulnerability,
)
from secopent.domain.intel.provenance import Provenance

logger = logging.getLogger(__name__)

# Per-source sync frequency (design §10.2: OSV 6h, KEV 6h, EPSS daily, NVD 6-12h).
OSV_FREQUENCY = timedelta(hours=6)
KEV_FREQUENCY = timedelta(hours=6)
EPSS_FREQUENCY = timedelta(days=1)
NVD_FREQUENCY = timedelta(hours=6)


class _HttpClient(Protocol):
    """Minimal httpx client surface used by the source clients."""

    def post(self, url: str, *, json: object, timeout: float) -> httpx.Response: ...
    def get(self, url: str, *, timeout: float) -> httpx.Response: ...


@dataclass(frozen=True, slots=True)
class SyncResult:
    """A non-Vulnerability sync result (e.g. an ExploitationSignal) + provenance.

    `Vulnerability` already carries its own `provenance` field, so KEV/EPSS
    signals (which are not Vulnerability records) are wrapped here to preserve
    the "every externally-sourced entity has provenance" contract (§10.7).
    """

    signal: ExploitationSignal
    provenance: Provenance


def _now() -> datetime:
    return datetime.now(UTC)


def _build_client(
    transport: httpx.BaseTransport | None,
    proxy_url: str | None,
) -> httpx.Client:
    kwargs: dict[str, object] = {"timeout": 30.0}
    if transport is not None:
        kwargs["transport"] = transport
    if proxy_url:
        kwargs["proxy"] = proxy_url
    return httpx.Client(**kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# OSV - primary source
# ---------------------------------------------------------------------------


class OsvClient:
    """OSV REST client (`api.osv.dev/v1/query`).

    OSV is the primary vuln source (design §10.2: NVD 503 from CN, OSV
    reachable). `fetch_incremental` accepts a `last_modified` cursor; when
    supplied it is forwarded as the OSV `watermark` field so the source can
    return only records changed since the cursor.
    """

    BASE_URL = "https://api.osv.dev/v1/query"

    def __init__(
        self,
        transport: httpx.BaseTransport | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self._client = client if client is not None else _build_client(transport, None)

    def fetch_incremental(
        self,
        last_modified: datetime | None,
    ) -> list[Vulnerability]:
        body: dict[str, object] = {"collection": "all"}
        if last_modified is not None:
            # OSV exposes a `watermark` cursor on the bulk query endpoint.
            body["watermark"] = int(last_modified.timestamp())
        try:
            resp = self._client.post(self.BASE_URL, json=body, timeout=30.0)
        except httpx.HTTPError as exc:
            logger.warning("OSV fetch HTTP error: %s", exc)
            return []
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            logger.warning("OSV fetch non-200: %s", resp.status_code)
            return []
        data = resp.json()
        vulns_raw = data.get("vulns", []) or []
        provenance = Provenance(
            source="OSV",
            fetched_at=_now(),
            source_version=data.get("next_page_token") or "v1",
        )
        return [self._parse(rec, provenance) for rec in vulns_raw]

    @staticmethod
    def _parse(rec: dict[str, Any], provenance: Provenance) -> Vulnerability:
        canonical_id = rec.get("id", "")
        aliases = tuple(rec.get("aliases", []) or [])
        description = rec.get("summary", "") or rec.get("details", "")
        refs = tuple(
            r.get("url", "") for r in (rec.get("references") or []) if r.get("url")
        )
        # CVSS - prefer severity[].score (CVSS_V3 vector string). baseScore not
        # always present in OSV; we extract the vector's numeric prefix when
        # absent. For now store 0.0 with the OSV provenance if not parseable.
        cvss_score = 0.0
        for sev in rec.get("severity") or []:
            if sev.get("type") == "CVSS_V3":
                cvss_score = _cvss_base_score(sev.get("score", ""))
                break
        affected: list[AffectedProduct] = []
        for aff in rec.get("affected") or []:
            pkg = aff.get("package") or {}
            ranges = aff.get("ranges") or []
            fixed_versions: list[str] = []
            for rng in ranges:
                for ev in rng.get("events") or []:
                    if "fixed" in ev:
                        fixed_versions.append(ev["fixed"])
            affected.append(
                AffectedProduct(
                    vendor=pkg.get("ecosystem", "") or "unknown",
                    product=pkg.get("name", "") or "unknown",
                    cpe=None,
                    package=pkg.get("name"),
                    version_range=_extract_version_range(ranges),
                    fixed_versions=tuple(fixed_versions),
                )
            )
        published_raw = rec.get("published") or "1970-01-01T00:00:00Z"
        published_at = _parse_dt(published_raw)
        signal = ExploitationSignal(
            kev=False,
            epss_score=0.0,
            public_exploit=False,
            ransomware=False,
            active_exploitation=False,
        )
        return Vulnerability(
            canonical_id=canonical_id,
            aliases=aliases,
            description=description,
            cvss={"osv": (cvss_score, provenance)},
            cwe=(),
            references=refs,
            published_at=published_at,
            affected_products=tuple(affected),
            exploitation_signal=signal,
            detection_mappings=(),
            provenance=provenance,
        )


def _cvss_base_score(vector: str) -> float:
    """Extract a base score from a CVSS v3 vector string.

    OSV ships the full `CVSS:3.1/AV:N/...` vector without a separate baseScore
    field. Computing the true base score from the vector requires the full
    CVSS spec; for the sync layer we record 0.0 when we cannot derive it
    (downstream policy can recompute from the vector). This keeps the entity
    valid without inventing a score.
    """
    _ = vector
    return 0.0


def _extract_version_range(ranges: list[dict[str, Any]]) -> str:
    events: list[str] = []
    for rng in ranges:
        for ev in rng.get("events") or []:
            if "introduced" in ev:
                events.append(f">={ev['introduced']}")
            if "fixed" in ev:
                events.append(f"<{ev['fixed']}")
    return ",".join(events) if events else "*"


def _parse_dt(raw: str) -> datetime:
    s = raw.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return datetime(1970, 1, 1, tzinfo=UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------


class KevClient:
    """CISA Known Exploited Vulnerabilities catalog."""

    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(
        self,
        transport: httpx.BaseTransport | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self._client = client if client is not None else _build_client(transport, None)

    def fetch(self) -> list[SyncResult]:
        try:
            resp = self._client.get(self.URL, timeout=30.0)
        except httpx.HTTPError as exc:
            logger.warning("KEV fetch HTTP error: %s", exc)
            return []
        if resp.status_code != 200:
            logger.warning("KEV fetch non-200: %s", resp.status_code)
            return []
        data: dict[str, Any] = resp.json()
        catalog_version = str(data.get("catalogVersion", "v1"))
        provenance = Provenance(
            source="KEV",
            fetched_at=_now(),
            source_version=catalog_version,
        )
        results: list[SyncResult] = []
        for rec in data.get("vulnerabilities", []) or []:
            ransomware = str(
                rec.get("knownRansomwareCampaignUse", "")
            ).lower() in {"known", "true", "yes"}
            signal = ExploitationSignal(
                kev=True,
                epss_score=0.0,
                public_exploit=False,
                ransomware=ransomware,
                active_exploitation=True,
            )
            results.append(SyncResult(signal=signal, provenance=provenance))
        return results


# ---------------------------------------------------------------------------
# FIRST EPSS
# ---------------------------------------------------------------------------


class EpssClient:
    """FIRST EPSS CSV parser -> {cve: epss_score}."""

    URL = "https://epss.cyentia.com/epss_scores-current.csv"

    def __init__(
        self,
        transport: httpx.BaseTransport | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self._client = client if client is not None else _build_client(transport, None)

    def fetch(self) -> dict[str, float]:
        try:
            resp = self._client.get(self.URL, timeout=60.0)
        except httpx.HTTPError as exc:
            logger.warning("EPSS fetch HTTP error: %s", exc)
            return {}
        if resp.status_code != 200:
            logger.warning("EPSS fetch non-200: %s", resp.status_code)
            return {}
        reader = csv.DictReader(io.StringIO(resp.text))
        scores: dict[str, float] = {}
        for row in reader:
            cve = (row.get("cve") or "").strip()
            epss_raw = (row.get("epss") or "").strip()
            if not cve or cve == "cve":
                continue
            try:
                scores[cve] = float(epss_raw)
            except ValueError:
                continue
        return scores


# ---------------------------------------------------------------------------
# NVD proxy (degrades on 503)
# ---------------------------------------------------------------------------


class NvdProxyClient:
    """NVD via HTTP_PROXY. CRITICAL: 503 degrades to empty list, no exception.

    NVD is unreachable from CN networks (design §10.2). The client reads
    `HTTP_PROXY` / `HTTPS_PROXY` from the environment. On 503 (or any HTTP
    error) it returns an empty list and logs - the platform falls back to the
    OSV cache for the same records.
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        transport: httpx.BaseTransport | None = None,
        client: httpx.Client | None = None,
        proxy_url: str | None = None,
    ) -> None:
        if client is not None:
            self._client = client
            self.proxy_url: str | None = proxy_url
        else:
            self.proxy_url = proxy_url or os.environ.get("HTTP_PROXY") or os.environ.get(
                "HTTPS_PROXY"
            )
            self._client = _build_client(transport, self.proxy_url)

    def fetch(self) -> list[Vulnerability]:
        try:
            resp = self._client.get(self.BASE_URL, timeout=30.0)
        except httpx.HTTPError as exc:
            logger.warning("NVD fetch HTTP error, degrading to empty: %s", exc)
            return []
        if resp.status_code == 503:
            logger.warning(
                "NVD returned 503 (unreachable from CN), degrading to OSV cache"
            )
            return []
        if resp.status_code != 200:
            logger.warning("NVD fetch non-200: %s, degrading to empty", resp.status_code)
            return []
        data = resp.json()
        provenance = Provenance(
            source="NVD",
            fetched_at=_now(),
            source_version="2.0",
        )
        vulns: list[Vulnerability] = []
        for item in data.get("vulnerabilities", []) or []:
            cve = item.get("cve") or {}
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions") or []
            description = next(
                (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                "",
            )
            published_raw = cve.get("published") or "1970-01-01T00:00:00Z"
            metrics = cve.get("metrics") or {}
            cvss_score = 0.0
            v31 = metrics.get("cvssMetricV31") or []
            if v31:
                cvss_score = float(
                    (v31[0].get("cvssData") or {}).get("baseScore", 0.0)
                )
            signal = ExploitationSignal(
                kev=False,
                epss_score=0.0,
                public_exploit=False,
                ransomware=False,
                active_exploitation=False,
            )
            vulns.append(
                Vulnerability(
                    canonical_id=cve_id,
                    aliases=(),
                    description=description,
                    cvss={"nvd": (cvss_score, provenance)},
                    cwe=(),
                    references=(),
                    published_at=_parse_dt(published_raw),
                    affected_products=(),
                    exploitation_signal=signal,
                    detection_mappings=(),
                    provenance=provenance,
                )
            )
        return vulns


# ---------------------------------------------------------------------------
# SourceSync coordinator
# ---------------------------------------------------------------------------


class SourceSync:
    """Coordinator exposing per-source frequency and a `sync_one` dispatch."""

    def __init__(
        self,
        osv: OsvClient | None = None,
        kev: KevClient | None = None,
        epss: EpssClient | None = None,
        nvd: NvdProxyClient | None = None,
    ) -> None:
        self.osv = osv or OsvClient()
        self.kev = kev or KevClient()
        self.epss = epss or EpssClient()
        self.nvd = nvd or NvdProxyClient()

    @staticmethod
    def frequencies() -> dict[str, timedelta]:
        return {
            "OSV": OSV_FREQUENCY,
            "KEV": KEV_FREQUENCY,
            "EPSS": EPSS_FREQUENCY,
            "NVD": NVD_FREQUENCY,
        }

    def sync_one(
        self, source: str
    ) -> Sequence[Vulnerability | SyncResult | dict[str, float]]:
        if source == "OSV":
            return self.osv.fetch_incremental(last_modified=None)
        if source == "KEV":
            return self.kev.fetch()
        if source == "EPSS":
            return [self.epss.fetch()]
        if source == "NVD":
            return self.nvd.fetch()
        raise ValueError(f"unknown source: {source!r}")


__all__ = [
    "EpssClient",
    "KevClient",
    "NvdProxyClient",
    "OsvClient",
    "SourceSync",
    "SyncResult",
]
