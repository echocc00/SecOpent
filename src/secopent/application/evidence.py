# src/secopent/application/evidence.py
"""EvidenceService: capture RAW evidence and derive REDACTED/SUMMARY layers (§13).

The service stores verbatim RAW evidence, then derives REDACTED (secrets/PII
masked) and SUMMARY layers as distinct content-addressed objects linked back to
the RAW via ``source_id`` - the RAW layer is never overwritten. REDACTED/SUMMARY
layers are independently signed.

Dependencies are injected as Protocols so the application layer stays free of
infrastructure coupling: ``EvidenceStore`` (content-addressed put), ``Redactor``
(secret/PII masking), and an optional content signer.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, runtime_checkable

from ..domain.evidence.models import Evidence, EvidenceLayer, RedactionResult


@runtime_checkable
class EvidenceStore(Protocol):
    """Content-addressed store: ``put`` returns (sha256 digest, storage URI)."""

    def put(self, content: bytes) -> tuple[str, str]: ...


@runtime_checkable
class Redactor(Protocol):
    """Masks secrets/PII in text, returning the redacted text + redaction log."""

    def redact(self, text: str) -> RedactionResult: ...


# Signs derived content independently; returns a signature string.
ContentSigner = Callable[[bytes], str]


class EvidenceService:
    """Capture and derive the three evidence layers."""

    def __init__(
        self,
        store: EvidenceStore,
        redactor: Redactor,
        signer: ContentSigner | None = None,
    ) -> None:
        self._store = store
        self._redactor = redactor
        self._signer = signer

    def store_raw(self, *, evidence_id: str, content: bytes) -> Evidence:
        """Store verbatim RAW evidence (never mutated afterwards)."""
        sha, uri = self._store.put(content)
        return Evidence(id=evidence_id, layer=EvidenceLayer.RAW, sha256=sha, storage_uri=uri)

    def redact(self, *, evidence_id: str, raw: Evidence, text: str) -> Evidence:
        """Derive a REDACTED layer from the RAW (new object, independently signed)."""
        result = self._redactor.redact(text)
        content = result.redacted_text.encode("utf-8")
        return self._derive(evidence_id, EvidenceLayer.REDACTED, raw.id, content)

    def summarize(self, *, evidence_id: str, raw: Evidence, summary: str) -> Evidence:
        """Derive a SUMMARY layer from the RAW (new object, independently signed)."""
        return self._derive(
            evidence_id, EvidenceLayer.SUMMARY, raw.id, summary.encode("utf-8")
        )

    def _derive(
        self, evidence_id: str, layer: EvidenceLayer, source_id: str, content: bytes
    ) -> Evidence:
        sha, uri = self._store.put(content)
        signature = self._signer(content) if self._signer is not None else ""
        return Evidence(
            id=evidence_id,
            layer=layer,
            sha256=sha,
            storage_uri=uri,
            source_id=source_id,
            signature=signature,
        )
