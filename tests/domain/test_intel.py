# tests/domain/test_intel.py
"""TDD tests for the intel domain entities and provenance.

Covers §10.1 (intelligence entities) and §10.7 (provenance) of the main
design. Every external-sourced field carries a `Provenance` record so the
platform can never silently overwrite one source's reading with another's
(NVD vs vendor CVSS, multiple KEV lists, etc.).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from secopent.domain.common.canonical import utc_now
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.intel.models import (
    AffectedProduct,
    DetectionMapping,
    ExploitationSignal,
    Vulnerability,
)
from secopent.domain.intel.provenance import Provenance
from secopent.domain.policy.models import RiskClass

# --- Provenance --------------------------------------------------------------


def _provenance(
    source: str = "nvd",
    fetched_at: datetime | None = None,
    source_version: str = "1.0",
) -> Provenance:
    return Provenance(
        source=source,
        fetched_at=fetched_at or utc_now(),
        source_version=source_version,
    )


def test_provenance_is_frozen() -> None:
    prov = _provenance()
    with pytest.raises(AttributeError):
        prov.source = "osv"  # type: ignore[misc]


def test_provenance_fields() -> None:
    fetched = utc_now()
    prov = Provenance(source="nvd", fetched_at=fetched, source_version="1.0")
    assert prov.source == "nvd"
    assert prov.fetched_at == fetched
    assert prov.source_version == "1.0"


def test_provenance_rejects_empty_source() -> None:
    with pytest.raises(DomainValidationError):
        Provenance(source="", fetched_at=utc_now(), source_version="1.0")


def test_provenance_rejects_naive_fetched_at() -> None:
    naive = datetime(2024, 1, 1, 12, 0, 0)  # no tzinfo
    with pytest.raises(DomainValidationError):
        Provenance(source="nvd", fetched_at=naive, source_version="1.0")


def test_provenance_accepts_timezone_aware_utc() -> None:
    aware = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
    prov = Provenance(source="nvd", fetched_at=aware, source_version="1.0")
    assert prov.fetched_at == aware


def test_provenance_rejects_empty_source_version() -> None:
    with pytest.raises(DomainValidationError):
        Provenance(source="nvd", fetched_at=utc_now(), source_version="")


# --- AffectedProduct ---------------------------------------------------------


def test_affected_product_fields() -> None:
    product = AffectedProduct(
        vendor="acme",
        product="widget",
        cpe="cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
        package="acme-widget",
        version_range=">=1.0,<2.0",
        fixed_versions=("2.0.1", "2.1.0"),
    )
    assert product.vendor == "acme"
    assert product.product == "widget"
    assert product.cpe == "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"
    assert product.package == "acme-widget"
    assert product.version_range == ">=1.0,<2.0"
    assert product.fixed_versions == ("2.0.1", "2.1.0")


def test_affected_product_is_frozen() -> None:
    product = AffectedProduct(
        vendor="acme",
        product="widget",
        cpe=None,
        package=None,
        version_range=">=1.0",
        fixed_versions=(),
    )
    with pytest.raises(AttributeError):
        product.vendor = "other"  # type: ignore[misc]


def test_affected_product_rejects_empty_vendor_and_product() -> None:
    with pytest.raises(DomainValidationError):
        AffectedProduct(
            vendor="",
            product="",
            cpe=None,
            package=None,
            version_range=">=1.0",
            fixed_versions=(),
        )


def test_affected_product_rejects_empty_vendor_only() -> None:
    # vendor + product both required; if either is missing the entity is invalid
    # because we need a stable identity for the affected product.
    with pytest.raises(DomainValidationError):
        AffectedProduct(
            vendor="",
            product="widget",
            cpe=None,
            package=None,
            version_range=">=1.0",
            fixed_versions=(),
        )


def test_affected_product_rejects_empty_product_only() -> None:
    with pytest.raises(DomainValidationError):
        AffectedProduct(
            vendor="acme",
            product="",
            cpe=None,
            package=None,
            version_range=">=1.0",
            fixed_versions=(),
        )


def test_affected_product_accepts_missing_cpe_and_package() -> None:
    # CPE and package name are not always known; version_range alone is enough
    # to anchor the affected product record.
    product = AffectedProduct(
        vendor="acme",
        product="widget",
        cpe=None,
        package=None,
        version_range=">=1.0,<2.0",
        fixed_versions=(),
    )
    assert product.cpe is None
    assert product.package is None


# --- ExploitationSignal ------------------------------------------------------


def test_exploitation_signal_defaults_to_safe() -> None:
    signal = ExploitationSignal(
        kev=False,
        epss_score=0.0,
        public_exploit=False,
        ransomware=False,
        active_exploitation=False,
    )
    assert signal.kev is False
    assert signal.epss_score == 0.0
    assert signal.public_exploit is False
    assert signal.ransomware is False
    assert signal.active_exploitation is False


def test_exploitation_signal_is_frozen() -> None:
    signal = ExploitationSignal(
        kev=True,
        epss_score=0.9,
        public_exploit=True,
        ransomware=False,
        active_exploitation=True,
    )
    with pytest.raises(AttributeError):
        signal.kev = False  # type: ignore[misc]


def test_exploitation_signal_rejects_epss_below_zero() -> None:
    with pytest.raises(DomainValidationError):
        ExploitationSignal(
            kev=False,
            epss_score=-0.01,
            public_exploit=False,
            ransomware=False,
            active_exploitation=False,
        )


def test_exploitation_signal_rejects_epss_above_one() -> None:
    with pytest.raises(DomainValidationError):
        ExploitationSignal(
            kev=False,
            epss_score=1.01,
            public_exploit=False,
            ransomware=False,
            active_exploitation=False,
        )


def test_exploitation_signal_accepts_epss_boundaries() -> None:
    lo = ExploitationSignal(
        kev=False,
        epss_score=0.0,
        public_exploit=False,
        ransomware=False,
        active_exploitation=False,
    )
    hi = ExploitationSignal(
        kev=True,
        epss_score=1.0,
        public_exploit=True,
        ransomware=True,
        active_exploitation=True,
    )
    assert lo.epss_score == 0.0
    assert hi.epss_score == 1.0


# --- DetectionMapping --------------------------------------------------------


def test_detection_mapping_fields() -> None:
    mapping = DetectionMapping(
        vulnerability_id="CVE-2024-1234",
        case_version="2026.07",
        detection_type="network",
        risk=RiskClass.LOW,
        confidence=0.85,
    )
    assert mapping.vulnerability_id == "CVE-2024-1234"
    assert mapping.case_version == "2026.07"
    assert mapping.detection_type == "network"
    assert mapping.risk is RiskClass.LOW
    assert mapping.confidence == pytest.approx(0.85)


def test_detection_mapping_is_frozen() -> None:
    mapping = DetectionMapping(
        vulnerability_id="CVE-2024-1234",
        case_version="2026.07",
        detection_type="network",
        risk=RiskClass.LOW,
        confidence=0.5,
    )
    with pytest.raises(AttributeError):
        mapping.confidence = 0.9  # type: ignore[misc]


def test_detection_mapping_rejects_confidence_below_zero() -> None:
    with pytest.raises(DomainValidationError):
        DetectionMapping(
            vulnerability_id="CVE-2024-1234",
            case_version="2026.07",
            detection_type="network",
            risk=RiskClass.LOW,
            confidence=-0.01,
        )


def test_detection_mapping_rejects_confidence_above_one() -> None:
    with pytest.raises(DomainValidationError):
        DetectionMapping(
            vulnerability_id="CVE-2024-1234",
            case_version="2026.07",
            detection_type="network",
            risk=RiskClass.LOW,
            confidence=1.01,
        )


def test_detection_mapping_accepts_confidence_boundaries() -> None:
    lo = DetectionMapping(
        vulnerability_id="CVE-2024-1234",
        case_version="2026.07",
        detection_type="network",
        risk=RiskClass.LOW,
        confidence=0.0,
    )
    hi = DetectionMapping(
        vulnerability_id="CVE-2024-1234",
        case_version="2026.07",
        detection_type="network",
        risk=RiskClass.LOW,
        confidence=1.0,
    )
    assert lo.confidence == 0.0
    assert hi.confidence == 1.0


def test_detection_mapping_rejects_empty_vulnerability_id() -> None:
    with pytest.raises(DomainValidationError):
        DetectionMapping(
            vulnerability_id="",
            case_version="2026.07",
            detection_type="network",
            risk=RiskClass.LOW,
            confidence=0.5,
        )


def test_detection_mapping_rejects_empty_case_version() -> None:
    with pytest.raises(DomainValidationError):
        DetectionMapping(
            vulnerability_id="CVE-2024-1234",
            case_version="",
            detection_type="network",
            risk=RiskClass.LOW,
            confidence=0.5,
        )


def test_detection_mapping_rejects_empty_detection_type() -> None:
    with pytest.raises(DomainValidationError):
        DetectionMapping(
            vulnerability_id="CVE-2024-1234",
            case_version="2026.07",
            detection_type="",
            risk=RiskClass.LOW,
            confidence=0.5,
        )


# --- Vulnerability -----------------------------------------------------------


def _sample_vulnerability(
    cvss: dict[str, tuple[float, Provenance]] | None = None,
) -> Vulnerability:
    if cvss is None:
        cvss = {
            "nvd": (7.5, _provenance(source="nvd")),
        }
    return Vulnerability(
        canonical_id="CVE-2024-1234",
        aliases=("CVE-2024-1234", "OSV-2024-1"),
        description="Heap overflow in acme widget.",
        cvss=cvss,
        cwe=("CWE-787",),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2024-1234",),
        published_at=datetime(2024, 6, 1, tzinfo=UTC),
        affected_products=(),
        exploitation_signal=ExploitationSignal(
            kev=False,
            epss_score=0.1,
            public_exploit=False,
            ransomware=False,
            active_exploitation=False,
        ),
        detection_mappings=(),
        provenance=_provenance(source="nvd"),
    )


def test_vulnerability_fields() -> None:
    vuln = _sample_vulnerability()
    assert vuln.canonical_id == "CVE-2024-1234"
    assert vuln.aliases == ("CVE-2024-1234", "OSV-2024-1")
    assert vuln.description == "Heap overflow in acme widget."
    assert vuln.cwe == ("CWE-787",)
    assert vuln.references == (
        "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
    )
    assert vuln.published_at == datetime(2024, 6, 1, tzinfo=UTC)
    assert vuln.cvss["nvd"][0] == 7.5
    assert vuln.cvss["nvd"][1].source == "nvd"


def test_vulnerability_is_frozen() -> None:
    vuln = _sample_vulnerability()
    with pytest.raises(AttributeError):
        vuln.canonical_id = "other"  # type: ignore[misc]


def test_vulnerability_rejects_empty_canonical_id() -> None:
    with pytest.raises(DomainValidationError):
        Vulnerability(
            canonical_id="",
            aliases=(),
            description="",
            cvss={},
            cwe=(),
            references=(),
            published_at=datetime(2024, 6, 1, tzinfo=UTC),
            affected_products=(),
            exploitation_signal=ExploitationSignal(
                kev=False,
                epss_score=0.0,
                public_exploit=False,
                ransomware=False,
                active_exploitation=False,
            ),
            detection_mappings=(),
            provenance=_provenance(),
        )


def test_vulnerability_rejects_naive_published_at() -> None:
    with pytest.raises(DomainValidationError):
        Vulnerability(
            canonical_id="CVE-2024-1234",
            aliases=(),
            description="",
            cvss={},
            cwe=(),
            references=(),
            published_at=datetime(2024, 6, 1),  # naive
            affected_products=(),
            exploitation_signal=ExploitationSignal(
                kev=False,
                epss_score=0.0,
                public_exploit=False,
                ransomware=False,
                active_exploitation=False,
            ),
            detection_mappings=(),
            provenance=_provenance(),
        )


def test_vulnerability_provenance_rejects_naive_fetched_at() -> None:
    # Provenance itself rejects naive datetimes at construction (see
    # test_provenance_rejects_naive_fetched_at). The Vulnerability constructor
    # therefore never sees a naive fetched_at - the invariant is enforced one
    # layer down. This test pins that contract: the failure surfaces as a
    # DomainValidationError, regardless of which dataclass raises it.
    with pytest.raises(DomainValidationError):
        Vulnerability(
            canonical_id="CVE-2024-1234",
            aliases=(),
            description="",
            cvss={},
            cwe=(),
            references=(),
            published_at=datetime(2024, 6, 1, tzinfo=UTC),
            affected_products=(),
            exploitation_signal=ExploitationSignal(
                kev=False,
                epss_score=0.0,
                public_exploit=False,
                ransomware=False,
                active_exploitation=False,
            ),
            detection_mappings=(),
            provenance=Provenance(  # type: ignore[arg-type]
                source="nvd",
                fetched_at=datetime(2024, 6, 1),  # naive
                source_version="1.0",
            ),
        )


def test_vulnerability_digest_stable_for_same_inputs() -> None:
    a = _sample_vulnerability()
    b = _sample_vulnerability()
    assert a.digest == b.digest
    assert a.digest.startswith("sha256:")


def test_vulnerability_digest_changes_with_canonical_id() -> None:
    a = _sample_vulnerability()
    b = _sample_vulnerability()
    object.__setattr__(b, "canonical_id", "CVE-2024-5678")
    b2 = Vulnerability(
        canonical_id="CVE-2024-5678",
        aliases=a.aliases,
        description=a.description,
        cvss=a.cvss,
        cwe=a.cwe,
        references=a.references,
        published_at=a.published_at,
        affected_products=a.affected_products,
        exploitation_signal=a.exploitation_signal,
        detection_mappings=a.detection_mappings,
        provenance=a.provenance,
    )
    assert a.digest != b2.digest


def test_vulnerability_digest_changes_with_cvss() -> None:
    a = _sample_vulnerability(
        cvss={"nvd": (7.5, _provenance(source="nvd"))},
    )
    b = _sample_vulnerability(
        cvss={"nvd": (8.0, _provenance(source="nvd"))},
    )
    assert a.digest != b.digest


# --- CVSS multi-source preservation (§10.7) ----------------------------------
#
# The platform MUST NOT overwrite one source's CVSS reading with another's.
# NVD and the upstream vendor can disagree on score (different vectors, different
# analyst judgement); both readings must be preserved so downstream consumers
# (CoverageService, DetectionMapping, operator review) can pick by policy.


def test_cvss_multi_source_preserved() -> None:
    nvd_prov = _provenance(source="nvd")
    vendor_prov = _provenance(source="vendor:acme")
    vuln = Vulnerability(
        canonical_id="CVE-2024-1234",
        aliases=(),
        description="",
        cvss={
            "nvd": (7.5, nvd_prov),
            "vendor:acme": (5.5, vendor_prov),
        },
        cwe=(),
        references=(),
        published_at=datetime(2024, 6, 1, tzinfo=UTC),
        affected_products=(),
        exploitation_signal=ExploitationSignal(
            kev=False,
            epss_score=0.0,
            public_exploit=False,
            ransomware=False,
            active_exploitation=False,
        ),
        detection_mappings=(),
        provenance=_provenance(),
    )
    assert set(vuln.cvss.keys()) == {"nvd", "vendor:acme"}
    assert vuln.cvss["nvd"] == (7.5, nvd_prov)
    assert vuln.cvss["vendor:acme"] == (5.5, vendor_prov)
    # The internal reading did NOT drop or overwrite either source.
    assert vuln.cvss["nvd"][0] != vuln.cvss["vendor:acme"][0]


def test_cvss_rejects_empty_source_key() -> None:
    # Empty source name would collide / be ambiguous in the multi-source map.
    with pytest.raises(DomainValidationError):
        Vulnerability(
            canonical_id="CVE-2024-1234",
            aliases=(),
            description="",
            cvss={"": (7.5, _provenance())},
            cwe=(),
            references=(),
            published_at=datetime(2024, 6, 1, tzinfo=UTC),
            affected_products=(),
            exploitation_signal=ExploitationSignal(
                kev=False,
                epss_score=0.0,
                public_exploit=False,
                ransomware=False,
                active_exploitation=False,
            ),
            detection_mappings=(),
            provenance=_provenance(),
        )


def test_cvss_rejects_score_below_zero() -> None:
    with pytest.raises(DomainValidationError):
        Vulnerability(
            canonical_id="CVE-2024-1234",
            aliases=(),
            description="",
            cvss={"nvd": (-0.1, _provenance())},
            cwe=(),
            references=(),
            published_at=datetime(2024, 6, 1, tzinfo=UTC),
            affected_products=(),
            exploitation_signal=ExploitationSignal(
                kev=False,
                epss_score=0.0,
                public_exploit=False,
                ransomware=False,
                active_exploitation=False,
            ),
            detection_mappings=(),
            provenance=_provenance(),
        )


def test_cvss_rejects_score_above_ten() -> None:
    with pytest.raises(DomainValidationError):
        Vulnerability(
            canonical_id="CVE-2024-1234",
            aliases=(),
            description="",
            cvss={"nvd": (10.1, _provenance())},
            cwe=(),
            references=(),
            published_at=datetime(2024, 6, 1, tzinfo=UTC),
            affected_products=(),
            exploitation_signal=ExploitationSignal(
                kev=False,
                epss_score=0.0,
                public_exploit=False,
                ransomware=False,
                active_exploitation=False,
            ),
            detection_mappings=(),
            provenance=_provenance(),
        )


# --- Aliases dedup (§10.1) ---------------------------------------------------


def test_vulnerability_aliases_dedup_preserves_order() -> None:
    vuln = Vulnerability(
        canonical_id="CVE-2024-1234",
        aliases=("CVE-2024-1234", "OSV-2024-1", "OSV-2024-1", "GHSA-aa11"),
        description="",
        cvss={},
        cwe=(),
        references=(),
        published_at=datetime(2024, 6, 1, tzinfo=UTC),
        affected_products=(),
        exploitation_signal=ExploitationSignal(
            kev=False,
            epss_score=0.0,
            public_exploit=False,
            ransomware=False,
            active_exploitation=False,
        ),
        detection_mappings=(),
        provenance=_provenance(),
    )
    # Dedup, order-preserving, original canonical_id stays first.
    assert vuln.aliases == ("CVE-2024-1234", "OSV-2024-1", "GHSA-aa11")


# --- End-to-end composition --------------------------------------------------


def test_vulnerability_with_full_record_round_trips() -> None:
    product = AffectedProduct(
        vendor="acme",
        product="widget",
        cpe="cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
        package="acme-widget",
        version_range=">=1.0,<2.0",
        fixed_versions=("2.0.1",),
    )
    mapping = DetectionMapping(
        vulnerability_id="CVE-2024-1234",
        case_version="2026.07",
        detection_type="network",
        risk=RiskClass.LOW,
        confidence=0.85,
    )
    signal = ExploitationSignal(
        kev=True,
        epss_score=0.95,
        public_exploit=True,
        ransomware=False,
        active_exploitation=True,
    )
    vuln = Vulnerability(
        canonical_id="CVE-2024-1234",
        aliases=("CVE-2024-1234", "OSV-2024-1"),
        description="Heap overflow in acme widget.",
        cvss={
            "nvd": (7.5, _provenance(source="nvd")),
            "vendor:acme": (5.5, _provenance(source="vendor:acme")),
        },
        cwe=("CWE-787",),
        references=("https://example.org/advisory",),
        published_at=datetime(2024, 6, 1, tzinfo=UTC),
        affected_products=(product,),
        exploitation_signal=signal,
        detection_mappings=(mapping,),
        provenance=_provenance(source="osv"),
    )
    assert vuln.affected_products[0].vendor == "acme"
    assert vuln.detection_mappings[0].detection_type == "network"
    assert vuln.exploitation_signal.kev is True
    assert set(vuln.cvss.keys()) == {"nvd", "vendor:acme"}
    assert vuln.digest.startswith("sha256:")


# --- Provenance timezone edge: non-UTC offset also accepted -------------------


def test_provenance_accepts_non_utc_offset() -> None:
    # Provenance must be timezone-aware; the canonical layer normalises to UTC.
    # We do not reject +05:00 offsets - the rule is "tz-aware", not "tz-UTC".
    from datetime import timezone

    plus5 = timezone(timedelta(hours=5))
    # 17:00 +05:00 == 12:00 UTC on the same day.
    local = datetime(2024, 6, 1, 17, 0, 0, tzinfo=plus5)
    prov = Provenance(source="nvd", fetched_at=local, source_version="1.0")
    expected_utc = datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC)
    assert prov.fetched_at.astimezone(UTC) == expected_utc
