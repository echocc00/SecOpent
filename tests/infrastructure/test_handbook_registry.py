# tests/infrastructure/test_handbook_registry.py
"""HandbookRegistry: structured attack handbooks with provenance (P1a Task 1)."""
from __future__ import annotations

from pathlib import Path

import pytest

from secopent.infrastructure.catalog.handbook_registry import (
    Handbook,
    HandbookRegistry,
    HandbookSchemaError,
    load_default_handbooks,
)


def _write(dir_path: Path, name: str, content: str) -> None:
    dir_path.mkdir(parents=True, exist_ok=True)
    (dir_path / name).write_text(content, encoding="utf-8")


_VALID = """
id: ssrf
title: Server-Side Request Forgery
cwe: ["CWE-918"]
owasp: ["A10:2021"]
provenance:
  derived_from: "usestrix/strix skills/vulnerabilities/ssrf.md"
  license: "Apache-2.0"
attack_surface:
  - "URL/hostname parameters accepting external addresses"
recon_endpoints:
  - "/proxy?url="
payload_classes:
  - name: "internal-network"
    description: "requests to RFC1918 / loopback"
verification_hint: "oob-callback"
"""


class TestHandbookRegistry:
    def test_loads_valid_handbook(self, tmp_path: Path) -> None:
        _write(tmp_path, "ssrf.yaml", _VALID)
        registry = HandbookRegistry.load(tmp_path)
        handbook = registry.get("ssrf")
        assert isinstance(handbook, Handbook)
        assert handbook.cwe == ("CWE-918",)
        assert handbook.provenance_license == "Apache-2.0"

    def test_rejects_missing_provenance(self, tmp_path: Path) -> None:
        _write(tmp_path, "bad.yaml", _VALID.replace("provenance:", "provenance_x:"))
        with pytest.raises(HandbookSchemaError):
            HandbookRegistry.load(tmp_path)

    def test_rejects_missing_verification_hint(self, tmp_path: Path) -> None:
        _write(tmp_path, "bad.yaml", _VALID.replace("verification_hint: \"oob-callback\"", ""))
        with pytest.raises(HandbookSchemaError):
            HandbookRegistry.load(tmp_path)

    def test_default_handbooks_load_and_cover_first_batch(self) -> None:
        registry = load_default_handbooks()
        # 首期移植 8 类（见 Task 2 清单）
        assert len(registry.all()) >= 8
        for handbook in registry.all():
            assert handbook.provenance_license == "Apache-2.0"
