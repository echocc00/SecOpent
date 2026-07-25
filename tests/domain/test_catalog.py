# tests/domain/test_catalog.py
from __future__ import annotations

import pytest

from secopent.domain.catalog.coverage import CoverageMatrix
from secopent.domain.catalog.models import (
    AssetType,
    RequiredTestClass,
    TestCatalog,
)
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.policy.models import RiskClass

# --- AssetType ---------------------------------------------------------------


def test_asset_type_values() -> None:
    assert AssetType.WEB_APP == "web_app"
    assert AssetType.API == "api"
    assert AssetType.IP_PORT == "ip_port"
    assert AssetType.CLOUD_ACCOUNT == "cloud_account"
    assert AssetType.CONTAINER_K8S == "container_k8s"
    assert {member.value for member in AssetType} == {
        "web_app",
        "api",
        "ip_port",
        "cloud_account",
        "container_k8s",
    }


# --- RequiredTestClass -------------------------------------------------------


def test_required_test_class_is_frozen() -> None:
    cls_ = RequiredTestClass(
        id="TC-WEB-001",
        cwe=("CWE-79",),
        owasp=("A03:2021",),
        risk=RiskClass.LOW,
    )
    with pytest.raises(AttributeError):
        cls_.id = "other"  # type: ignore[misc]


def test_required_test_class_field_types() -> None:
    cls_ = RequiredTestClass(
        id="TC-WEB-001",
        cwe=("CWE-79", "CWE-89"),
        owasp=("A03:2021",),
        risk=RiskClass.PASSIVE,
    )
    assert cls_.id == "TC-WEB-001"
    assert cls_.cwe == ("CWE-79", "CWE-89")
    assert cls_.owasp == ("A03:2021",)
    assert cls_.risk is RiskClass.PASSIVE


# --- TestCatalog -------------------------------------------------------------


def _sample_catalog(version: str = "2026.07") -> TestCatalog:
    web_class = RequiredTestClass(
        id="TC-WEB-001",
        cwe=("CWE-79",),
        owasp=("A03:2021",),
        risk=RiskClass.LOW,
    )
    api_class = RequiredTestClass(
        id="TC-API-001",
        cwe=("CWE-306",),
        owasp=("A01:2021",),
        risk=RiskClass.ACTIVE,
    )
    return TestCatalog(
        version=version,
        mappings={
            AssetType.WEB_APP: (web_class,),
            AssetType.API: (api_class,),
        },
    )


def test_test_catalog_required_for_returns_tuple() -> None:
    catalog = _sample_catalog()
    web_classes = catalog.required_for(AssetType.WEB_APP)
    assert isinstance(web_classes, tuple)
    assert web_classes[0].id == "TC-WEB-001"


def test_test_catalog_required_for_unknown_returns_empty() -> None:
    catalog = _sample_catalog()
    assert catalog.required_for(AssetType.IP_PORT) == ()


def test_test_catalog_rejects_empty_version() -> None:
    with pytest.raises(DomainValidationError):
        TestCatalog(version="", mappings={})


def test_test_catalog_digest_stable_for_same_mappings() -> None:
    a = _sample_catalog()
    b = _sample_catalog()
    assert a.digest == b.digest
    assert a.digest.startswith("sha256:")


def test_test_catalog_digest_changes_when_mappings_change() -> None:
    a = _sample_catalog(version="2026.07")
    # Same version, different mappings -> different digest
    other = TestCatalog(
        version="2026.07",
        mappings={
            AssetType.WEB_APP: (
                RequiredTestClass(
                    id="TC-WEB-002",
                    cwe=("CWE-89",),
                    owasp=("A03:2021",),
                    risk=RiskClass.LOW,
                ),
            ),
        },
    )
    assert a.digest != other.digest


def test_test_catalog_digest_changes_with_version() -> None:
    a = _sample_catalog(version="2026.07")
    b = _sample_catalog(version="2026.08")
    assert a.digest != b.digest


def test_test_catalog_is_frozen() -> None:
    catalog = _sample_catalog()
    with pytest.raises(AttributeError):
        catalog.version = "other"  # type: ignore[misc]


# --- CoverageMatrix ----------------------------------------------------------


def _sample_matrix(
    total_items: int = 4,
    mappings: dict[str, tuple[str, ...]] | None = None,
) -> CoverageMatrix:
    if mappings is None:
        mappings = {
            "WSTG-INPV-01": ("TC-WEB-001",),
            "WSTG-ATHZ-01": ("TC-WEB-002",),
            "WSTG-SESS-01": (),
            "WSTG-CRYP-01": (),
        }
    return CoverageMatrix(
        version="2026.07",
        framework="OWASP_WSTG_4.2",
        mappings=mappings,
        total_items=total_items,
    )


def test_coverage_matrix_coverage_rate_full() -> None:
    matrix = CoverageMatrix(
        version="2026.07",
        framework="OWASP_WSTG_4.2",
        mappings={
            "WSTG-INPV-01": ("TC-WEB-001",),
            "WSTG-ATHZ-01": ("TC-WEB-002",),
        },
        total_items=2,
    )
    assert matrix.coverage_rate() == 1.0


def test_coverage_matrix_coverage_rate_half() -> None:
    matrix = _sample_matrix(total_items=4)
    # 2 covered / 4 total = 0.5
    assert matrix.coverage_rate() == 0.5


def test_coverage_matrix_coverage_rate_zero() -> None:
    matrix = CoverageMatrix(
        version="2026.07",
        framework="OWASP_WSTG_4.2",
        mappings={
            "WSTG-INPV-01": (),
            "WSTG-ATHZ-01": (),
        },
        total_items=2,
    )
    assert matrix.coverage_rate() == 0.0


def test_coverage_matrix_rejects_total_items_below_one() -> None:
    with pytest.raises(DomainValidationError):
        CoverageMatrix(
            version="2026.07",
            framework="OWASP_WSTG_4.2",
            mappings={},
            total_items=0,
        )


def test_coverage_matrix_rejects_empty_version() -> None:
    with pytest.raises(DomainValidationError):
        CoverageMatrix(
            version="",
            framework="OWASP_WSTG_4.2",
            mappings={},
            total_items=1,
        )


def test_coverage_matrix_rejects_empty_framework() -> None:
    with pytest.raises(DomainValidationError):
        CoverageMatrix(
            version="2026.07",
            framework="",
            mappings={},
            total_items=1,
        )


def test_coverage_matrix_rejects_negative_coverage() -> None:
    # total_items below 1 already rejected; here ensure that mappings with more
    # covered items than total_items is treated as invalid (rate > 1).
    with pytest.raises(DomainValidationError):
        CoverageMatrix(
            version="2026.07",
            framework="OWASP_WSTG_4.2",
            mappings={
                "WSTG-INPV-01": ("TC-WEB-001",),
                "WSTG-ATHZ-01": ("TC-WEB-002",),
            },
            total_items=1,
        )


def test_coverage_matrix_digest_stable() -> None:
    a = _sample_matrix()
    b = _sample_matrix()
    assert a.digest == b.digest
    assert a.digest.startswith("sha256:")


def test_coverage_matrix_digest_changes_with_total_items() -> None:
    a = _sample_matrix(total_items=4)
    b = _sample_matrix(total_items=5)
    assert a.digest != b.digest


def test_coverage_matrix_digest_changes_with_mappings() -> None:
    a = _sample_matrix()
    b = _sample_matrix(
        mappings={
            "WSTG-INPV-01": ("TC-WEB-001", "TC-WEB-009"),
            "WSTG-ATHZ-01": (),
            "WSTG-SESS-01": (),
            "WSTG-CRYP-01": (),
        },
    )
    assert a.digest != b.digest


def test_coverage_matrix_is_frozen() -> None:
    matrix = _sample_matrix()
    with pytest.raises(AttributeError):
        matrix.version = "other"  # type: ignore[misc]
