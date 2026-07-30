# tests/infrastructure/test_github_bundle_fetcher.py
"""Tests for the GitHub Releases bundle fetcher + revocation (T17 / §⑨)."""
from __future__ import annotations

import pytest

from secopent.infrastructure.updates.github_bundle_fetcher import (
    BUNDLE_ASSET,
    REVOCATIONS_ASSET,
    SIG_ASSET,
    BundleFetchError,
    BundleRevokedError,
    GithubBundleFetcher,
    parse_github_source,
)


class _FakeResponse:
    def __init__(self, status_code: int, content: bytes = b"") -> None:
        self.status_code = status_code
        self.content = content


class _FakeClient:
    """httpx.Client double: serves canned content keyed by URL substring."""

    def __init__(self, assets: dict[str, bytes]) -> None:
        self._assets = assets
        self.requested: list[str] = []

    def get(self, url: str) -> _FakeResponse:
        self.requested.append(url)
        # Match on the asset name as the final path segment so "bundle.json"
        # is not confused with "bundle.json.sig".
        for key, content in self._assets.items():
            if url.endswith("/" + key):
                return _FakeResponse(200, content)
        return _FakeResponse(404)

    def close(self) -> None:
        return None


def test_parse_github_source_valid() -> None:
    assert parse_github_source("github:secopent/bundles:v2026.07") == (
        "secopent",
        "bundles",
        "v2026.07",
    )


def test_parse_github_source_rejects_bad_input() -> None:
    with pytest.raises(BundleFetchError):
        parse_github_source("https://example.com/x")
    with pytest.raises(BundleFetchError):
        parse_github_source("github:secopent/bundles")  # no tag
    with pytest.raises(BundleFetchError):
        parse_github_source("github:norepo:v1")  # no owner/repo slash


def test_fetch_returns_bundle_and_signature() -> None:
    client = _FakeClient(
        {BUNDLE_ASSET: b'{"bundle_id": "b1"}', SIG_ASSET: b"sig-bytes"}
    )
    fetcher = GithubBundleFetcher(client=client)  # type: ignore[arg-type]
    bundle, signature = fetcher.fetch("github:secopent/bundles:v1")
    assert bundle == b'{"bundle_id": "b1"}'
    assert signature == b"sig-bytes"


def test_fetch_revoked_bundle_raises() -> None:
    client = _FakeClient(
        {
            BUNDLE_ASSET: b"{}",
            SIG_ASSET: b"sig",
            REVOCATIONS_ASSET: b'{"revoked": ["v1"]}',
        }
    )
    fetcher = GithubBundleFetcher(client=client)  # type: ignore[arg-type]
    with pytest.raises(BundleRevokedError):
        fetcher.fetch("github:secopent/bundles:v1")


def test_fetch_unrevoked_when_tag_not_listed() -> None:
    client = _FakeClient(
        {
            BUNDLE_ASSET: b"bundle",
            SIG_ASSET: b"sig",
            REVOCATIONS_ASSET: b'{"revoked": ["vOLD"]}',
        }
    )
    fetcher = GithubBundleFetcher(client=client)  # type: ignore[arg-type]
    assert fetcher.fetch("github:secopent/bundles:v1") == (b"bundle", b"sig")


def test_fetch_missing_bundle_raises() -> None:
    client = _FakeClient({SIG_ASSET: b"sig"})  # no bundle.json
    fetcher = GithubBundleFetcher(client=client)  # type: ignore[arg-type]
    with pytest.raises(BundleFetchError):
        fetcher.fetch("github:secopent/bundles:v1")


def test_mirror_base_url_is_used() -> None:
    client = _FakeClient({BUNDLE_ASSET: b"b", SIG_ASSET: b"s"})
    fetcher = GithubBundleFetcher(
        client=client, base_url="https://gitee.example/mirror"  # type: ignore[arg-type]
    )
    fetcher.fetch("github:secopent/bundles:v1")
    assert any(url.startswith("https://gitee.example/mirror/") for url in client.requested)
