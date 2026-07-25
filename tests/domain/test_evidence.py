"""TDD tests for the Evidence domain (M2 Task 12, §13 evidence three-layer).

Evidence is captured in three layers: RAW (verbatim tool output), REDACTED
(secrets/PII masked), and SUMMARY (human-readable digest). Each layer is a
distinct content-addressed object (sha256) - redaction NEVER overwrites the RAW
layer; it produces a new object linked back to the RAW via ``source_id`` and
independently signed. ``SecretOrigin`` distinguishes our secrets (canary/own
credentials - always masked) from target secrets (found credentials - masked but
flagged as evidence).
"""
from __future__ import annotations

import pytest

from secopent.domain.common.errors import DomainValidationError
from secopent.domain.evidence.models import (
    Evidence,
    EvidenceLayer,
    Redaction,
    RedactionResult,
    SecretOrigin,
)

_SHA = "sha256:" + "a" * 64


def test_evidence_layer_has_three_layers() -> None:
    assert {layer.value for layer in EvidenceLayer} == {"raw", "redacted", "summary"}


def test_secret_origin_distinguishes_ours_from_target() -> None:
    assert {o.value for o in SecretOrigin} == {"ours", "target"}


def test_evidence_requires_core_fields() -> None:
    with pytest.raises(DomainValidationError):
        Evidence(id="", layer=EvidenceLayer.RAW, sha256=_SHA, storage_uri="cas://x")


def test_evidence_sha256_must_be_prefixed() -> None:
    with pytest.raises(DomainValidationError):
        Evidence(id="e1", layer=EvidenceLayer.RAW, sha256="noprefix", storage_uri="cas://x")


def test_raw_evidence_has_empty_source() -> None:
    evidence = Evidence(
        id="e-raw", layer=EvidenceLayer.RAW, sha256=_SHA, storage_uri="cas://raw"
    )
    assert evidence.source_id == ""
    assert evidence.signature == ""


def test_redacted_evidence_links_to_raw_source() -> None:
    raw = Evidence(id="e-raw", layer=EvidenceLayer.RAW, sha256=_SHA, storage_uri="cas://raw")
    redacted_sha = "sha256:" + "b" * 64
    redacted = Evidence(
        id="e-red",
        layer=EvidenceLayer.REDACTED,
        sha256=redacted_sha,
        storage_uri="cas://red",
        source_id=raw.id,
        signature="sig-1",
    )
    # Redaction produces a NEW object (different digest) linked to the RAW.
    assert redacted.sha256 != raw.sha256
    assert redacted.source_id == raw.id
    assert redacted.signature == "sig-1"


def test_redaction_requires_kind() -> None:
    with pytest.raises(DomainValidationError):
        Redaction(kind="", origin=SecretOrigin.OURS)


def test_redaction_result_counts_by_origin() -> None:
    result = RedactionResult(
        redacted_text="hello [REDACTED:aws_key] world [REDACTED:email]",
        redactions=(
            Redaction(kind="aws_key", origin=SecretOrigin.OURS),
            Redaction(kind="email", origin=SecretOrigin.TARGET),
        ),
    )
    assert result.count == 2
    assert result.count_by_origin(SecretOrigin.OURS) == 1
    assert result.count_by_origin(SecretOrigin.TARGET) == 1
