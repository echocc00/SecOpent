# tests/infrastructure/test_curation_lag.py
"""TDD tests for the real curation-lag checker + tag providers (P3 §3.4-2).

Also covers the BundleSignatureState/SignatureChecker pair (§3.4-3 prep).
"""
from __future__ import annotations

from secopent.application.health import BundleSignatureState
from secopent.domain.catalog.models import AssetType, RequiredTestClass, TestCatalog
from secopent.domain.policy.models import RiskClass
from secopent.infrastructure.catalog.default_catalog import build_default_catalog
from secopent.infrastructure.health_checkers import (
    BundledNucleiTagProvider,
    CurationLagChecker,
    LocalNucleiTagProvider,
    SignatureChecker,
)
from secopent.integrations.adapters import nuclei


class _FixedProvider:
    """Test double returning a fixed tag set."""

    def __init__(self, tags: frozenset[str]) -> None:
        self._tags = tags

    def tags(self, source: str) -> frozenset[str]:
        return self._tags


def test_local_provider_parses_yaml_tags(tmp_path):
    (tmp_path / "a.yaml").write_text("id: x\ninfo:\n  tags: sqli,xss\n", encoding="utf-8")
    (tmp_path / "b.yaml").write_text("info:\n  tags: 'cve2021', log4j\n", encoding="utf-8")
    (tmp_path / "notag.yaml").write_text("id: y\n", encoding="utf-8")
    provider = LocalNucleiTagProvider({"nuclei-templates": str(tmp_path)})
    assert provider.tags("nuclei-templates") == frozenset(
        {"sqli", "xss", "cve2021", "log4j"}
    )
    # Unknown source / missing path -> empty (not an error).
    assert provider.tags("other") == frozenset()


def test_bundled_provider_mixes_curated_and_uncurated():
    tags = BundledNucleiTagProvider().tags("nuclei-templates")
    tag_map = nuclei.tag_coverage_map()
    assert tags & set(tag_map)  # some curated tags present
    assert tags - set(tag_map)  # and some uncurated tags present
    # extra tags are folded in lower-cased.
    assert "MyTag" not in BundledNucleiTagProvider(["MyTag"]).tags("s")
    assert "mytag" in BundledNucleiTagProvider(["MyTag"]).tags("s")


def test_curation_lag_realistic_nonzero_with_default_catalog():
    checker = CurationLagChecker(
        BundledNucleiTagProvider(), build_default_catalog(), nuclei.tag_coverage_map()
    )
    # The bundled baseline includes many uncurated product/tech tags -> lag.
    assert checker.unmapped_upstream_tags("nuclei-templates") > 0


def test_curation_lag_zero_when_all_tags_covered():
    # Provider yields exactly the curated tag set; default catalog covers all.
    checker = CurationLagChecker(
        _FixedProvider(frozenset(nuclei.tag_coverage_map().keys())),
        build_default_catalog(),
        nuclei.tag_coverage_map(),
    )
    assert checker.unmapped_upstream_tags("nuclei-templates") == 0


def test_curation_lag_counts_curated_but_uncovered_tag():
    # A catalog whose coverage excludes rce's CWE-78/A03:2021 leaves rce unmapped.
    catalog = TestCatalog(
        version="t",
        mappings={
            AssetType.WEB_APP: (
                RequiredTestClass(
                    id="x", cwe=("CWE-999",), owasp=("Z99:9999",), risk=RiskClass.PASSIVE
                ),
            )
        },
    )
    checker = CurationLagChecker(
        _FixedProvider(frozenset({"rce"})), catalog, nuclei.tag_coverage_map()
    )
    assert checker.unmapped_upstream_tags("nuclei-templates") == 1


def test_curation_lag_no_catalog_or_no_tags_is_zero():
    tag_map = nuclei.tag_coverage_map()
    no_catalog = CurationLagChecker(BundledNucleiTagProvider(), None, tag_map)
    assert no_catalog.unmapped_upstream_tags("s") == 0
    assert CurationLagChecker(
        _FixedProvider(frozenset()), build_default_catalog(), tag_map
    ).unmapped_upstream_tags("s") == 0


def test_signature_state_and_checker():
    assert SignatureChecker(None).last_signature_valid() is True
    state = BundleSignatureState()
    checker = SignatureChecker(state)
    assert checker.last_signature_valid() is True  # default: no failure recorded
    state.record("bundle-1", valid=False)
    assert checker.last_signature_valid() is False
    assert state.last_bundle_id == "bundle-1"
    state.record("bundle-2", valid=True)
    assert checker.last_signature_valid() is True
