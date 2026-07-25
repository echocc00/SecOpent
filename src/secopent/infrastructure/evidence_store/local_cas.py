# src/secopent/infrastructure/evidence_store/local_cas.py
"""LocalCAS: filesystem content-addressed store for evidence (§13).

Objects are stored under ``<base>/sha256/<2-char-prefix>/<hex-digest>`` and
addressed by their sha256. Content addressing makes storage idempotent (the
same bytes always map to the same digest/URI) and lets downstream code read
evidence by digest without caring where the bytes live.
"""
from __future__ import annotations

import hashlib
from pathlib import Path


class LocalCAS:
    """A local filesystem content-addressed store."""

    def __init__(self, base_dir: Path) -> None:
        self._base = Path(base_dir)

    def put(self, content: bytes) -> tuple[str, str]:
        """Store content; return (sha256 digest, cas:// URI)."""
        hexd = hashlib.sha256(content).hexdigest()
        target = self._base / "sha256" / hexd[:2] / hexd
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return f"sha256:{hexd}", self.uri_for(f"sha256:{hexd}")

    def uri_for(self, sha256: str) -> str:
        """Return the cas:// URI for a sha256 digest."""
        hexd = sha256.removeprefix("sha256:")
        return f"cas://sha256/{hexd[:2]}/{hexd}"

    def get(self, sha256: str) -> bytes:
        """Read stored content by its sha256 digest."""
        hexd = sha256.removeprefix("sha256:")
        return (self._base / "sha256" / hexd[:2] / hexd).read_bytes()
