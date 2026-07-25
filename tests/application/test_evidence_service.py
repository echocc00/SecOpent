"""TDD tests for EvidenceService (M2 Task 12, §13 three-layer evidence).

The service captures RAW evidence, then derives REDACTED and SUMMARY layers as
distinct content-addressed objects linked back to the RAW (which is never
overwritten). Redacted/summary layers are independently signed.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from secopent.application.evidence import EvidenceService
from secopent.domain.evidence.models import EvidenceLayer
from secopent.infrastructure.evidence_store.local_cas import LocalCAS
from secopent.infrastructure.evidence_store.redaction import RedactionEngine

_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture
def cas(tmp_path: Path) -> LocalCAS:
    return LocalCAS(tmp_path)


@pytest.fixture
def service(cas: LocalCAS) -> EvidenceService:
    return EvidenceService(
        store=cas,
        redactor=RedactionEngine(),
        signer=lambda content: "sig:" + content[:4].hex(),
    )


def test_store_raw_returns_raw_evidence(service: EvidenceService, cas: LocalCAS) -> None:
    evidence = service.store_raw(evidence_id="e1", content=b"GET / 200")
    assert evidence.layer is EvidenceLayer.RAW
    assert evidence.source_id == ""
    assert cas.get(evidence.sha256) == b"GET / 200"


def test_redact_derives_new_object_linked_to_raw(
    service: EvidenceService, cas: LocalCAS
) -> None:
    raw = service.store_raw(evidence_id="e-raw", content=f"key {_AWS_KEY} leaked".encode())
    redacted = service.redact(
        evidence_id="e-red", raw=raw, text=f"key {_AWS_KEY} leaked"
    )
    assert redacted.layer is EvidenceLayer.REDACTED
    assert redacted.source_id == raw.id
    assert redacted.sha256 != raw.sha256
    # The stored redacted content no longer contains the secret.
    assert _AWS_KEY.encode() not in cas.get(redacted.sha256)


def test_raw_not_overwritten_by_redaction(
    service: EvidenceService, cas: LocalCAS
) -> None:
    content = f"key {_AWS_KEY} leaked".encode()
    raw = service.store_raw(evidence_id="e-raw", content=content)
    service.redact(evidence_id="e-red", raw=raw, text=content.decode())
    # RAW evidence still resolves to the original verbatim bytes.
    assert cas.get(raw.sha256) == content


def test_redacted_layer_independently_signed(service: EvidenceService) -> None:
    raw = service.store_raw(evidence_id="e-raw", content=b"x")
    redacted = service.redact(evidence_id="e-red", raw=raw, text="no secrets")
    assert redacted.signature.startswith("sig:")


def test_summarize_derives_summary_layer(service: EvidenceService) -> None:
    raw = service.store_raw(evidence_id="e-raw", content=b"lots of output")
    summary = service.summarize(evidence_id="e-sum", raw=raw, summary="200 OK, no finding")
    assert summary.layer is EvidenceLayer.SUMMARY
    assert summary.source_id == raw.id
    assert summary.signature.startswith("sig:")
