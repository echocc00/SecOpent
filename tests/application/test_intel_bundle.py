# tests/application/test_intel_bundle.py
"""TDD tests for IntelBundlePublisher (P3 §3.4-3).

No cryptography here: the verifier and signer are fakes (the real Ed25519 path
is exercised end-to-end by the interface test). Covers sign->verify->stage->
activate->audit, and the rejection path recording real signature state.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field

import pytest

from secopent.application.audit import AuditService
from secopent.application.health import BundleSignatureState
from secopent.application.intel_bundle import IntelBundlePublisher
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.updates.models import UpdateBundle


@dataclass
class FakeBundleStore:
    bundles: dict[str, dict] = field(default_factory=dict)
    active: str | None = None

    def add_bundle(self, bundle_id: str, version: str, digest: str, payload: dict) -> None:
        self.bundles[bundle_id] = {
            "version": version,
            "digest": digest,
            "payload": dict(payload),
        }

    def set_active_bundle(self, bundle_id: str) -> None:
        self.active = bundle_id


class _AcceptVerifier:
    def verify(self, bundle: UpdateBundle, signature: bytes, public_key: bytes) -> bool:
        return True


class _RejectVerifier:
    def verify(self, bundle: UpdateBundle, signature: bytes, public_key: bytes) -> bool:
        return False


def _signer(payload: bytes) -> str:
    return base64.b64encode(b"signature").decode("ascii")


_PUBLIC_KEY = base64.b64encode(b"public-key").decode("ascii")


def _publisher(audit: AuditService, store: FakeBundleStore, verifier, state):
    return IntelBundlePublisher(
        verifier=verifier,
        audit_service=audit,
        store=store,
        signature_state=state,
    )


def test_publish_stages_activates_and_audits(memory_repositories):
    audit = AuditService(memory_repositories.audit)
    store = FakeBundleStore()
    state = BundleSignatureState()
    publisher = _publisher(audit, store, _AcceptVerifier(), state)

    result = publisher.publish(
        bundle_id="intel-abc",
        version="2026-07-29T00:00:00+00:00",
        payload={"kind": "intel", "vulnerability_count": 3},
        signer=_signer,
        public_key=_PUBLIC_KEY,
    )

    assert result.signature_valid is True
    assert store.active == "intel-abc"
    assert store.bundles["intel-abc"]["payload"]["vulnerability_count"] == 3
    assert state.last_valid is True
    assert state.last_bundle_id == "intel-abc"
    actions = [e.action for e in memory_repositories.audit.list_events()]
    assert "update.published" in actions
    assert "update.rejected" not in actions


def test_publish_rejection_records_state_and_audits(memory_repositories):
    audit = AuditService(memory_repositories.audit)
    store = FakeBundleStore()
    state = BundleSignatureState()
    publisher = _publisher(audit, store, _RejectVerifier(), state)

    with pytest.raises(DomainValidationError):
        publisher.publish(
            bundle_id="intel-bad",
            version="v1",
            payload={"kind": "intel"},
            signer=_signer,
            public_key=_PUBLIC_KEY,
        )

    # Nothing staged/activated; the failed verification is recorded + audited.
    assert store.bundles == {}
    assert store.active is None
    assert state.last_valid is False
    assert state.last_bundle_id == "intel-bad"
    actions = [e.action for e in memory_repositories.audit.list_events()]
    assert "update.rejected" in actions
    assert "update.published" not in actions
