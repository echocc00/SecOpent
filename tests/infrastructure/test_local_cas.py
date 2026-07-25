"""TDD tests for LocalCAS (M2 Task 12, §13 content-addressed evidence store)."""
from __future__ import annotations

import hashlib
from pathlib import Path

from secopent.infrastructure.evidence_store.local_cas import LocalCAS


def test_put_returns_sha256_and_cas_uri(tmp_path: Path) -> None:
    cas = LocalCAS(tmp_path)
    content = b"raw tool output"
    sha, uri = cas.put(content)
    assert sha == "sha256:" + hashlib.sha256(content).hexdigest()
    assert uri.startswith("cas://sha256/")


def test_put_writes_under_prefix_layout(tmp_path: Path) -> None:
    cas = LocalCAS(tmp_path)
    content = b"some bytes"
    hexd = hashlib.sha256(content).hexdigest()
    cas.put(content)
    stored = tmp_path / "sha256" / hexd[:2] / hexd
    assert stored.is_file()
    assert stored.read_bytes() == content


def test_get_round_trips(tmp_path: Path) -> None:
    cas = LocalCAS(tmp_path)
    content = b"round trip me"
    sha, _ = cas.put(content)
    assert cas.get(sha) == content


def test_content_addressed_is_idempotent(tmp_path: Path) -> None:
    cas = LocalCAS(tmp_path)
    sha1, uri1 = cas.put(b"same")
    sha2, uri2 = cas.put(b"same")
    assert sha1 == sha2
    assert uri1 == uri2
