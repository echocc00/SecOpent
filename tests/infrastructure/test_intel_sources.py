"""TDD tests for intel source sync (Task 5).

All network is mocked via httpx.MockTransport - NO real calls to osv.dev /
cisa.gov / first.org / nvd.nist.gov in the test suite.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from secopent.domain.intel.models import (
    ExploitationSignal,
    Vulnerability,
)
from secopent.domain.intel.provenance import Provenance
from secopent.infrastructure.intel_sources import (
    EpssClient,
    KevClient,
    NvdProxyClient,
    OsvClient,
    SourceSync,
    SyncResult,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _provenance_now(source: str, version: str = "v1") -> Provenance:
    return Provenance(
        source=source,
        fetched_at=datetime.now(UTC),
        source_version=version,
    )


def _osv_record(cve: str = "CVE-2024-1234") -> dict[str, Any]:
    """Minimal OSV record schema."""
    return {
        "id": cve,
        "aliases": ["GHSA-abcd-efgh-ijkl"],
        "summary": "Test vuln",
        "published": "2024-01-01T00:00:00Z",
        "references": [{"type": "WEB", "url": "https://example.com"}],
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "acme-lib"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}
                ],
            }
        ],
    }


def _kev_record(cve: str = "CVE-2024-9999") -> dict[str, Any]:
    return {
        "cveID": cve,
        "vendorProject": "ACME",
        "product": "ACME-Product",
        "vulnerabilityName": "Test RCE",
        "dateAdded": "2024-06-01",
        "shortDescription": "Active exploitation",
        "requiredAction": "Apply patch",
        "dueDate": "2024-06-22",
        "knownRansomwareCampaignUse": "Known",
        "notes": "test",
    }


# ---------------------------------------------------------------------------
# OsvClient
# ---------------------------------------------------------------------------


def _osv_handler(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content.decode("utf-8"))
    if body.get("watermark"):
        # incremental cursor request - return empty
        return httpx.Response(200, json={"vulns": []})
    # full / first-page request
    return httpx.Response(
        200,
        json={"vulns": [_osv_record()], "next_page_token": "tok1"},
    )


def test_osv_fetch_incremental_uses_last_modified_cursor() -> None:
    """fetch_incremental MUST pass the last_modified cursor to the OSV API."""
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(200, json={"vulns": []})

    transport = httpx.MockTransport(handler)
    client = OsvClient(transport=transport)
    cursor = datetime(2024, 6, 1, tzinfo=UTC)
    client.fetch_incremental(last_modified=cursor)
    # OSV query MUST include a watermark/last_modified equivalent
    assert "watermark" in captured["body"] or "last_modified" in captured["body"]
    assert "collection" in captured["body"] or "package" in captured["body"]


def test_osv_parse_to_vulnerability_entities_with_provenance() -> None:
    """parse OSV JSON -> Vulnerability entities with provenance source=OSV."""
    transport = httpx.MockTransport(_osv_handler)
    client = OsvClient(transport=transport)
    vulns = client.fetch_incremental(last_modified=None)
    assert len(vulns) == 1
    v = vulns[0]
    assert isinstance(v, Vulnerability)
    assert v.canonical_id == "CVE-2024-1234"
    assert v.provenance.source == "OSV"
    assert v.provenance.fetched_at.tzinfo is not None
    assert v.provenance.source_version  # non-empty


def test_osv_404_returns_empty_no_crash() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)
    transport = httpx.MockTransport(handler)
    client = OsvClient(transport=transport)
    assert client.fetch_incremental(last_modified=None) == []


def test_osv_empty_response_returns_empty() -> None:
    transport = httpx.MockTransport(lambda r: httpx.Response(200, json={"vulns": []}))
    client = OsvClient(transport=transport)
    assert client.fetch_incremental(last_modified=None) == []


# ---------------------------------------------------------------------------
# KevClient
# ---------------------------------------------------------------------------


def _kev_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "catalogVersion": "2024.06.01",
            "dateReleased": "2024-06-01T00:00:00Z",
            "count": 2,
            "vulnerabilities": [_kev_record("CVE-2024-0001"), _kev_record("CVE-2024-0002")],
        },
    )


def test_kev_parse_to_exploitation_signals() -> None:
    transport = httpx.MockTransport(_kev_handler)
    client = KevClient(transport=transport)
    results = client.fetch()
    assert len(results) == 2
    for res in results:
        assert isinstance(res.signal, ExploitationSignal)
        assert res.signal.kev is True
        assert res.provenance.source == "KEV"
        assert res.provenance.fetched_at.tzinfo is not None
        assert res.provenance.source_version


def test_kev_count_matches_records() -> None:
    transport = httpx.MockTransport(_kev_handler)
    client = KevClient(transport=transport)
    results = client.fetch()
    assert len(results) == 2


def test_kev_ransomware_flag_parsed() -> None:
    transport = httpx.MockTransport(_kev_handler)
    client = KevClient(transport=transport)
    results = client.fetch()
    # both records have knownRansomwareCampaignUse=Known
    assert all(r.signal.ransomware for r in results)


# ---------------------------------------------------------------------------
# EpssClient
# ---------------------------------------------------------------------------


def _epss_handler(request: httpx.Request) -> httpx.Response:
    csv = "cve,epss,percentile\nCVE-2024-0001,0.5,0.95\nCVE-2024-0002,0.1,0.50\n"
    return httpx.Response(200, text=csv, headers={"content-type": "text/csv"})


def test_epss_parse_csv_to_mapping() -> None:
    transport = httpx.MockTransport(_epss_handler)
    client = EpssClient(transport=transport)
    scores = client.fetch()
    assert scores["CVE-2024-0001"] == pytest.approx(0.5)
    assert scores["CVE-2024-0002"] == pytest.approx(0.1)


def test_epss_skips_header_row() -> None:
    transport = httpx.MockTransport(_epss_handler)
    client = EpssClient(transport=transport)
    scores = client.fetch()
    assert "cve" not in scores  # header row skipped
    assert len(scores) == 2


# ---------------------------------------------------------------------------
# NvdProxyClient - 503 graceful degradation
# ---------------------------------------------------------------------------


def test_nvd_proxy_503_returns_empty_no_crash() -> None:
    """CRITICAL: NVD 503 from CN network MUST degrade to empty list, no exception."""
    transport = httpx.MockTransport(lambda r: httpx.Response(503))
    client = NvdProxyClient(transport=transport)
    result = client.fetch()
    assert result == []
    # MUST NOT raise - graceful degradation


def test_nvd_proxy_503_logs(caplog: pytest.LogCaptureFixture) -> None:
    transport = httpx.MockTransport(lambda r: httpx.Response(503))
    client = NvdProxyClient(transport=transport)
    with caplog.at_level("WARNING"):
        client.fetch()
    assert any("503" in rec.message or "degrad" in rec.message.lower() for rec in caplog.records)


def test_nvd_proxy_uses_http_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """NVD proxy MUST read HTTP_PROXY env for proxy config."""
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example:8080")
    client = NvdProxyClient()
    assert "proxy.example" in str(client.proxy_url) or client.proxy_url is not None


def test_nvd_proxy_200_returns_vulnerabilities() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "resultsPerPage": 1,
                "startIndex": 0,
                "totalResults": 1,
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-5555",
                            "descriptions": [{"lang": "en", "value": "NVD test"}],
                            "published": "2024-01-01T00:00:00.000",
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "cvssData": {
                                            "baseScore": 7.5,
                                            "vectorString": (
                                                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                                            ),
                                        },
                                        "type": "Primary",
                                    }
                                ]
                            },
                        }
                    }
                ],
            },
        )

    transport = httpx.MockTransport(handler)
    client = NvdProxyClient(transport=transport)
    vulns = client.fetch()
    assert len(vulns) == 1
    assert vulns[0].provenance.source == "NVD"


# ---------------------------------------------------------------------------
# SourceSync - per-source frequency
# ---------------------------------------------------------------------------


def test_source_sync_has_per_source_frequency() -> None:
    sync = SourceSync()
    freqs = sync.frequencies()
    assert freqs["OSV"] == timedelta(hours=6)
    assert freqs["KEV"] == timedelta(hours=6)
    assert freqs["EPSS"] == timedelta(days=1)
    # NVD 6-12h - pick within range
    assert timedelta(hours=6) <= freqs["NVD"] <= timedelta(hours=12)


def test_source_sync_sync_one_returns_entities(monkeypatch: pytest.MonkeyPatch) -> None:
    """sync_one(source) returns list of Vulnerability | ExploitationSignal."""
    sync = SourceSync()
    # inject mock clients
    sync.osv = OsvClient(transport=httpx.MockTransport(_osv_handler))
    sync.kev = KevClient(transport=httpx.MockTransport(_kev_handler))
    sync.epss = EpssClient(transport=httpx.MockTransport(_epss_handler))
    sync.nvd = NvdProxyClient(transport=httpx.MockTransport(lambda r: httpx.Response(503)))

    osv_results = sync.sync_one("OSV")
    assert all(isinstance(x, Vulnerability) for x in osv_results)
    kev_results = sync.sync_one("KEV")
    assert all(isinstance(x, SyncResult) for x in kev_results)
    assert all(isinstance(x.signal, ExploitationSignal) for x in kev_results)
    nvd_results = sync.sync_one("NVD")
    assert nvd_results == []  # 503 degraded
