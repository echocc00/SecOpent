# src/secopent/infrastructure/updates/github_bundle_fetcher.py
"""GitHub Releases bundle fetcher (T17 / cross-cutting §⑨).

The production ``BundleFetcher`` implementation (the port is defined in
``application/ports/repositories.py``). It resolves a source of the form
``github:<owner>/<repo>:<tag>`` to a GitHub Release and downloads two assets:

- ``bundle.json``     - the bundle document (manifest + payload);
- ``bundle.json.sig`` - the detached Ed25519 signature over the bundle digest.

A third asset, ``revocations.json`` (``{"revoked": ["<tag>", ...]}``), is the
curator's revocation list: a revoked tag is refused with ``BundleRevokedError``
so ``sync`` never activates a retracted bundle. ``base_url`` is overridable so a
China deployment can point at a Gitee / CDN mirror instead of github.com.

Framework note: this is infrastructure (it uses ``httpx``); the application
``UpdateManager`` depends only on the ``BundleFetcher`` port.
"""
from __future__ import annotations

import json

import httpx

from secopent.domain.common.errors import DomainError

GITHUB_SCHEME = "github:"
DEFAULT_BASE_URL = "https://github.com"

BUNDLE_ASSET = "bundle.json"
SIG_ASSET = "bundle.json.sig"
REVOCATIONS_ASSET = "revocations.json"


class BundleFetchError(DomainError):
    """A bundle (or its signature) could not be fetched from the registry."""


class BundleRevokedError(DomainError):
    """The requested bundle has been revoked by the curator; refuse to sync."""


def parse_github_source(source: str) -> tuple[str, str, str]:
    """Parse ``github:<owner>/<repo>:<tag>`` into ``(owner, repo, tag)``."""
    if not source.startswith(GITHUB_SCHEME):
        raise BundleFetchError(f"not a github source: {source!r}")
    rest = source[len(GITHUB_SCHEME):]
    path, sep, tag = rest.rpartition(":")
    if not sep or not tag or "/" not in path:
        raise BundleFetchError(f"malformed github source: {source!r}")
    owner, _, repo = path.partition("/")
    if not owner or not repo:
        raise BundleFetchError(f"malformed github source: {source!r}")
    return owner, repo, tag


class GithubBundleFetcher:
    """Fetch ``(bundle_bytes, signature_bytes)`` from a GitHub Release."""

    def __init__(
        self,
        *,
        client: httpx.Client | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
    ) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    def fetch(self, source: str) -> tuple[bytes, bytes]:
        owner, repo, tag = parse_github_source(source)
        if self._is_revoked(owner, repo, tag):
            raise BundleRevokedError(
                f"bundle {tag!r} is revoked in {owner}/{repo}; refusing to sync"
            )
        bundle = self._download_asset(owner, repo, tag, BUNDLE_ASSET)
        signature = self._download_asset(owner, repo, tag, SIG_ASSET)
        return bundle, signature

    def _asset_url(self, owner: str, repo: str, tag: str, asset: str) -> str:
        return f"{self._base_url}/{owner}/{repo}/releases/download/{tag}/{asset}"

    def _download_asset(self, owner: str, repo: str, tag: str, asset: str) -> bytes:
        url = self._asset_url(owner, repo, tag, asset)
        client = self._client or httpx.Client(timeout=self._timeout, follow_redirects=True)
        try:
            response = client.get(url)
        finally:
            if self._client is None:
                client.close()
        if response.status_code != 200:
            raise BundleFetchError(
                f"failed to fetch {asset} for {owner}/{repo}@{tag}: "
                f"HTTP {response.status_code}"
            )
        return response.content

    def _is_revoked(self, owner: str, repo: str, tag: str) -> bool:
        """True iff the tag appears in the registry's revocation list.

        A missing/unreadable revocation list means nothing is revoked.
        """
        try:
            data = self._download_asset(owner, repo, tag, REVOCATIONS_ASSET)
        except BundleFetchError:
            return False
        try:
            doc = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
        revoked = doc.get("revoked", []) if isinstance(doc, dict) else doc
        return isinstance(revoked, list) and tag in revoked
