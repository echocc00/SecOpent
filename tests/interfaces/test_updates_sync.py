# tests/interfaces/test_updates_sync.py
"""Tests for POST /updates/sync (GitHub bundle registry fetch + revoke, T17)."""
from __future__ import annotations

import base64
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from secopent.domain.updates.models import UpdateBundle
from secopent.infrastructure.updates.github_bundle_fetcher import BundleRevokedError
from secopent.interfaces.api.main import create_app


class _FakeFetcher:
    """BundleFetcher double: returns a canned (bundle, sig) or raises revoked."""

    def __init__(
        self, result: tuple[bytes, bytes] | None = None, *, revoked: bool = False
    ) -> None:
        self._result = result
        self._revoked = revoked

    def fetch(self, source: str) -> tuple[bytes, bytes]:
        if self._revoked:
            raise BundleRevokedError(f"revoked: {source}")
        assert self._result is not None
        return self._result


def _signed_bundle_bytes(app: FastAPI) -> tuple[bytes, bytes]:
    """Build a bundle signed with the server's default key (verifies on sync)."""
    signing_keys = app.state.signing_keys
    key_id = signing_keys.default_key_id()
    signer = signing_keys.signer_for(key_id)
    bundle = UpdateBundle.create(
        bundle_id="intel-synctest",
        version="2026.07.30",
        schema_version="secopent-intel/v1",
        payload={"kind": "intel", "count": 1},
    )
    signature = base64.b64decode(signer(bundle.digest.encode("utf-8")))
    doc = {
        "bundle_id": bundle.bundle_id,
        "version": bundle.version,
        "schema_version": bundle.schema_version,
        "payload": dict(bundle.payload),
    }
    return json.dumps(doc).encode("utf-8"), signature


@pytest.fixture
def app() -> FastAPI:
    return create_app()


def test_sync_activates_a_verified_bundle(app: FastAPI) -> None:
    app.state.bundle_fetcher = _FakeFetcher(result=_signed_bundle_bytes(app))
    client = TestClient(app)
    resp = client.post(
        "/updates/sync",
        json={"source": "github:secopent/bundles:v2026.07", "actor_role": "human"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["bundle_id"] == "intel-synctest"
    assert client.get("/updates/active").json()["active_bundle_id"] == "intel-synctest"


def test_sync_rejects_revoked_bundle(app: FastAPI) -> None:
    app.state.bundle_fetcher = _FakeFetcher(revoked=True)
    resp = TestClient(app).post(
        "/updates/sync",
        json={"source": "github:secopent/bundles:v1", "actor_role": "human"},
    )
    assert resp.status_code == 409


def test_sync_rejects_agent(app: FastAPI) -> None:
    resp = TestClient(app).post(
        "/updates/sync", json={"source": "github:x/y:v1", "actor_role": "agent"}
    )
    assert resp.status_code == 403


def test_sync_rejects_invalid_signature(app: FastAPI) -> None:
    bundle_bytes, _ = _signed_bundle_bytes(app)
    app.state.bundle_fetcher = _FakeFetcher(result=(bundle_bytes, b"bad-signature"))
    resp = TestClient(app).post(
        "/updates/sync", json={"source": "github:x/y:v1", "actor_role": "human"}
    )
    assert resp.status_code == 422
