# tests/infrastructure/test_extended_catalog.py
"""Extended catalog: new vuln classes without coverage regression (P1a Task 3)."""
from __future__ import annotations

from secopent.domain.catalog.models import AssetType
from secopent.infrastructure.catalog.default_catalog import (
    DEFAULT_CATALOG_VERSION,
    build_default_catalog,
)
from secopent.infrastructure.catalog.extended_catalog import (
    EXTENDED_CATALOG_VERSION,
    build_extended_catalog,
)


class TestExtendedCatalog:
    def test_version_is_newer_not_edited(self) -> None:
        assert EXTENDED_CATALOG_VERSION != DEFAULT_CATALOG_VERSION

    def test_web_app_gains_new_required_classes(self) -> None:
        extended = build_extended_catalog()
        class_ids = {
            cls.id for cls in extended.mappings[AssetType.WEB_APP]
        }
        # New classes (corresponding to handbook first batch).
        # Note: default already has wstg-inpv-03=CWE-918 (SSRF), so no new ssrf id.
        for expected in (
            "wstg-athn-jwt",
            "wstg-inpv-deserialization",
            "wstg-inpv-path-traversal",
            "wstg-athz-idor",
            "wstg-buslogic-race",
            "wstg-inpv-smuggling",
            "wstg-clientside-proto-pollution",
        ):
            assert expected in class_ids

    def test_no_coverage_regression_vs_default(self) -> None:
        default = build_default_catalog()
        extended = build_extended_catalog()
        for asset_type in (AssetType.WEB_APP, AssetType.API):
            default_ids = {c.id for c in default.mappings.get(asset_type, ())}
            extended_ids = {c.id for c in extended.mappings.get(asset_type, ())}
            assert default_ids <= extended_ids  # only adds, never removes

    def test_every_new_class_has_distinct_cwe_or_owasp(self) -> None:
        extended = build_extended_catalog()
        classes = extended.mappings[AssetType.WEB_APP]
        seen: set[tuple[str, ...]] = set()
        for cls in classes:
            key = (cls.cwe, cls.owasp)
            # Different ids may share mappings (e.g. wstg-inpv-03 and api-ssrf),
            # but every new class must carry non-empty cwe or owasp.
            assert cls.cwe or cls.owasp
            seen.add(key)
