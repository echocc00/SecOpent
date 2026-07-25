# tests/application/test_update_manager.py
"""TDD tests for UpdateManager (M1 Task 6).

Covers the full Update Bundle pipeline (§10.3 / §10.4):
    download -> staging -> signature verify -> schema check
    -> preview diff -> atomic activate -> old snapshot retained
    -> rollback()

Network is mocked: tests inject an in-memory ``BundleRepository`` and a
fake ``SignatureVerifier`` so no Ed25519/cryptography or httpx code runs
here. The Ed25519 implementation lives in infrastructure and is exercised
by an infrastructure test, not here.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from secopent.application.audit import AuditService
from secopent.application.updates import UpdateManager
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.updates.models import UpdateBundle

# --- Test doubles -----------------------------------------------------------


@dataclass
class StagedBundle:
    """Mirror of CoreUpdateBundle row used by the in-memory repo."""

    bundle_id: str
    version: str
    digest: str
    payload: dict
    staged_at: str
    signature: bytes


@dataclass
class InMemoryUpdateBundleRepository:
    """In-memory stand-in for SqlAlchemyUpdateBundleRepository.

    Stores staged bundles keyed by id, plus a single-row activation pointer
    that mirrors ``CoreBundleActivation`` (singleton=1). Old staged bundles
    are *retained* on activation so rollback can repoint to them.
    """

    staged: dict[str, StagedBundle] = field(default_factory=dict)
    active_bundle_id: str | None = None
    previously_active_id: str | None = None
    fail_activation: bool = False

    def stage(self, bundle: UpdateBundle, signature: bytes) -> None:
        self.staged[bundle.bundle_id] = StagedBundle(
            bundle_id=bundle.bundle_id,
            version=bundle.version,
            digest=bundle.digest,
            payload=dict(bundle.payload),
            staged_at="2026-07-25T00:00:00Z",
            signature=signature,
        )

    def get_staged(self, bundle_id: str) -> StagedBundle | None:
        return self.staged.get(bundle_id)

    def list_staged(self) -> list[StagedBundle]:
        return list(self.staged.values())

    def activate(self, bundle_id: str) -> str:
        if self.fail_activation:
            raise RuntimeError("simulated activation failure")
        if bundle_id not in self.staged:
            raise KeyError(f"unknown bundle: {bundle_id}")
        self.previously_active_id = self.active_bundle_id
        self.active_bundle_id = bundle_id
        return bundle_id

    def get_active_bundle_id(self) -> str | None:
        return self.active_bundle_id

    def get_previous_bundle_id(self) -> str | None:
        return self.previously_active_id

    def rollback_to_previous(self) -> str | None:
        if self.previously_active_id is None:
            raise RuntimeError("no previous bundle to roll back to")
        current = self.active_bundle_id
        self.active_bundle_id = self.previously_active_id
        self.previously_active_id = current
        return self.active_bundle_id


class AcceptAllSignatureVerifier:
    """Fake verifier that accepts every signature. Used for happy-path tests."""

    def verify(self, bundle: UpdateBundle, signature: bytes, public_key: bytes) -> bool:
        return True


class RejectAllSignatureVerifier:
    """Fake verifier that rejects every signature. Used for rejection tests."""

    def verify(self, bundle: UpdateBundle, signature: bytes, public_key: bytes) -> bool:
        return False


@dataclass
class FakeFetcher:
    """Stand-in for the bundle download step. Returns canned bytes.

    ``payload`` is the raw bundle document (JSON-serialized manifest+payload)
    that the manager will parse. ``signature`` is the detached Ed25519 sig
    threaded through as ``payload["__signature__"]``.
    """

    payload: bytes = b""
    signature: bytes = b""

    def fetch(self, source: str) -> tuple[bytes, bytes]:
        return self.payload, self.signature


def _bundle_to_fetcher_bytes(bundle: UpdateBundle, signature: bytes = b"sig") -> bytes:
    """Serialize a bundle into the JSON document the manager's ``_fetch``
    parses. The detached signature is returned separately by the
    FakeFetcher; the bundle document itself only carries the manifest
    and payload so the bundle's canonical digest stays stable."""
    import json

    doc = {
        "bundle_id": bundle.bundle_id,
        "version": bundle.version,
        "schema_version": bundle.schema_version,
        "payload": dict(bundle.payload),
    }
    return json.dumps(doc).encode("utf-8")


def _make_bundle(
    bundle_id: str = "bundle-001",
    version: str = "2026.07.25",
    schema_version: str = "1",
    payload: dict | None = None,
) -> UpdateBundle:
    return UpdateBundle.create(
        bundle_id=bundle_id,
        version=version,
        schema_version=schema_version,
        payload=payload or {"catalog": {"v": version}, "intel": []},
    )


def _make_manager(
    repo: InMemoryUpdateBundleRepository,
    audit: AuditService,
    verifier,
    fetcher: FakeFetcher,
    *,
    expected_schema: str = "1",
    public_key: bytes = b"pk",
) -> UpdateManager:
    return UpdateManager(
        bundle_repository=repo,
        audit_service=audit,
        signature_verifier=verifier,
        fetcher=fetcher,
        expected_schema_version=expected_schema,
        public_key=public_key,
    )


# --- Happy path -------------------------------------------------------------


def test_sync_downloads_and_stages_then_activates(memory_repositories):
    repo = InMemoryUpdateBundleRepository()
    audit = AuditService(memory_repositories.audit)
    bundle = _make_bundle()
    fetcher = FakeFetcher(payload=_bundle_to_fetcher_bytes(bundle), signature=b"sig")
    manager = _make_manager(repo, audit, AcceptAllSignatureVerifier(), fetcher)

    result = manager.sync(source="https://updates.example/bundle.tar.zst")

    # bundle was staged
    assert repo.get_staged(bundle.bundle_id) is not None
    # activation pointer now points at the new bundle
    assert repo.get_active_bundle_id() == bundle.bundle_id
    # digest computed and exposed
    assert result.bundle_id == bundle.bundle_id
    assert result.version == bundle.version
    assert result.digest.startswith("sha256:")


def test_sync_retains_old_snapshot_for_rollback(memory_repositories):
    repo = InMemoryUpdateBundleRepository()
    audit = AuditService(memory_repositories.audit)

    # First sync: lands v1
    bundle_v1 = _make_bundle(bundle_id="b-v1", version="v1")
    fetcher_v1 = FakeFetcher(
        payload=_bundle_to_fetcher_bytes(bundle_v1), signature=b"sig1"
    )
    manager = _make_manager(repo, audit, AcceptAllSignatureVerifier(), fetcher_v1)
    manager.sync(source="src-1")
    assert repo.get_active_bundle_id() == "b-v1"

    # Second sync: lands v2; v1 must still be staged
    bundle_v2 = _make_bundle(bundle_id="b-v2", version="v2")
    fetcher_v2 = FakeFetcher(
        payload=_bundle_to_fetcher_bytes(bundle_v2), signature=b"sig2"
    )
    manager2 = _make_manager(repo, audit, AcceptAllSignatureVerifier(), fetcher_v2)
    manager2.sync(source="src-2")

    assert repo.get_active_bundle_id() == "b-v2"
    # old snapshot retained (not deleted)
    assert repo.get_staged("b-v1") is not None
    assert repo.get_staged("b-v2") is not None
    # previous pointer tracks v1 for rollback
    assert repo.get_previous_bundle_id() == "b-v1"


# --- Signature rejection ----------------------------------------------------


def test_signature_invalid_rejected_keeps_old_version(memory_repositories):
    repo = InMemoryUpdateBundleRepository()
    audit = AuditService(memory_repositories.audit)

    # Land an initial good bundle so there's an "old version" to keep.
    good_bundle = _make_bundle(bundle_id="b-good", version="good")
    fetcher_good = FakeFetcher(
        payload=_bundle_to_fetcher_bytes(good_bundle), signature=b"good-sig"
    )
    manager = _make_manager(repo, audit, AcceptAllSignatureVerifier(), fetcher_good)
    manager.sync(source="src-good")
    assert repo.get_active_bundle_id() == "b-good"

    # Now try a bundle whose signature is invalid.
    bad_bundle = _make_bundle(bundle_id="b-bad", version="bad")
    fetcher_bad = FakeFetcher(
        payload=_bundle_to_fetcher_bytes(bad_bundle), signature=b"bad-sig"
    )
    manager2 = _make_manager(repo, audit, RejectAllSignatureVerifier(), fetcher_bad)

    with pytest.raises(DomainValidationError, match="signature"):
        manager2.sync(source="src-bad")

    # old active version preserved
    assert repo.get_active_bundle_id() == "b-good"
    # bad bundle was staged but never activated
    assert repo.get_staged("b-bad") is not None


# --- Schema incompatibility -------------------------------------------------


def test_schema_incompatible_rejected(memory_repositories):
    repo = InMemoryUpdateBundleRepository()
    audit = AuditService(memory_repositories.audit)

    # Bundle advertises schema_version="2" but manager expects "1"
    bundle = _make_bundle(schema_version="2")
    fetcher = FakeFetcher(payload=_bundle_to_fetcher_bytes(bundle), signature=b"sig")
    manager = _make_manager(
        repo, audit, AcceptAllSignatureVerifier(), fetcher, expected_schema="1"
    )

    with pytest.raises(DomainValidationError, match="schema"):
        manager.sync(source="src")
    assert repo.get_active_bundle_id() is None


# --- Activation failure rollback --------------------------------------------


def test_activation_failure_rolls_back(memory_repositories):
    repo = InMemoryUpdateBundleRepository()
    audit = AuditService(memory_repositories.audit)

    # Land v1 successfully
    b1 = _make_bundle(bundle_id="b-1", version="v1")
    f1 = FakeFetcher(payload=_bundle_to_fetcher_bytes(b1), signature=b"s1")
    manager = _make_manager(repo, audit, AcceptAllSignatureVerifier(), f1)
    manager.sync(source="src-1")
    assert repo.get_active_bundle_id() == "b-1"

    # Now stage v2 but force the repo to fail activation
    repo.fail_activation = True
    b2 = _make_bundle(bundle_id="b-2", version="v2")
    f2 = FakeFetcher(payload=_bundle_to_fetcher_bytes(b2), signature=b"s2")
    manager2 = _make_manager(repo, audit, AcceptAllSignatureVerifier(), f2)

    with pytest.raises(RuntimeError, match="activation"):
        manager2.sync(source="src-2")

    # rollback: active pointer should still point at v1 (unchanged)
    assert repo.get_active_bundle_id() == "b-1"
    # old snapshot intact
    assert repo.get_staged("b-1") is not None


# --- Explicit rollback() ----------------------------------------------------


def test_rollback_restores_previous_active(memory_repositories):
    repo = InMemoryUpdateBundleRepository()
    audit = AuditService(memory_repositories.audit)

    b1 = _make_bundle(bundle_id="b-1", version="v1")
    f1 = FakeFetcher(payload=_bundle_to_fetcher_bytes(b1), signature=b"s1")
    manager = _make_manager(repo, audit, AcceptAllSignatureVerifier(), f1)
    manager.sync(source="src-1")

    b2 = _make_bundle(bundle_id="b-2", version="v2")
    f2 = FakeFetcher(payload=_bundle_to_fetcher_bytes(b2), signature=b"s2")
    manager2 = _make_manager(repo, audit, AcceptAllSignatureVerifier(), f2)
    manager2.sync(source="src-2")
    assert repo.get_active_bundle_id() == "b-2"

    restored = manager2.rollback()
    assert restored == "b-1"
    assert repo.get_active_bundle_id() == "b-1"


def test_rollback_without_previous_raises(memory_repositories):
    repo = InMemoryUpdateBundleRepository()
    audit = AuditService(memory_repositories.audit)
    b1 = _make_bundle(bundle_id="b-1", version="v1")
    f1 = FakeFetcher(payload=_bundle_to_fetcher_bytes(b1), signature=b"s1")
    manager = _make_manager(repo, audit, AcceptAllSignatureVerifier(), f1)
    manager.sync(source="src-1")

    with pytest.raises(RuntimeError, match="previous"):
        manager.rollback()


# --- Audit events -----------------------------------------------------------


def test_audit_events_emitted_for_sync_activate_rollback(memory_repositories):
    repo = InMemoryUpdateBundleRepository()
    audit = AuditService(memory_repositories.audit)

    # sync #1 -> emits update.synced + update.activated
    b1 = _make_bundle(bundle_id="b-1", version="v1")
    f1 = FakeFetcher(payload=_bundle_to_fetcher_bytes(b1), signature=b"s1")
    manager = _make_manager(repo, audit, AcceptAllSignatureVerifier(), f1)
    manager.sync(source="src-1")

    # sync #2 -> emits another update.synced + update.activated
    b2 = _make_bundle(bundle_id="b-2", version="v2")
    f2 = FakeFetcher(payload=_bundle_to_fetcher_bytes(b2), signature=b"s2")
    manager2 = _make_manager(repo, audit, AcceptAllSignatureVerifier(), f2)
    manager2.sync(source="src-2")

    # rollback -> emits update.rolled_back
    manager2.rollback()

    events = memory_repositories.audit.list_events()
    actions = [e.action for e in events]
    assert actions.count("update.synced") == 2
    assert actions.count("update.activated") == 2
    assert actions.count("update.rolled_back") == 1
    # audit chain still verifies
    assert AuditService.verify(events) is True


def test_audit_event_emitted_on_signature_rejection(memory_repositories):
    """A failed sync must still be audited so operators can see attempts."""
    repo = InMemoryUpdateBundleRepository()
    audit = AuditService(memory_repositories.audit)
    bundle = _make_bundle()
    fetcher = FakeFetcher(payload=_bundle_to_fetcher_bytes(bundle), signature=b"bad")
    manager = _make_manager(repo, audit, RejectAllSignatureVerifier(), fetcher)

    with pytest.raises(DomainValidationError):
        manager.sync(source="src")

    events = memory_repositories.audit.list_events()
    actions = [e.action for e in events]
    assert "update.rejected" in actions
