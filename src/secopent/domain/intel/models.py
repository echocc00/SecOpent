# src/secopent/domain/intel/models.py
"""Intel domain entities (§10.1) with provenance (§10.7).

Entities:
- `Vulnerability` - canonical CVE/OSV/GHSA record with multi-source CVSS
- `AffectedProduct` - one (vendor, product, version_range) tuple touched by a vuln
- `ExploitationSignal` - KEV/EPSS/public-exploit/ransomware/active-exploitation
- `DetectionMapping` - how a vuln surfaces through one detection case

Every externally-sourced field carries a `Provenance` record. The CVSS field is
a `dict[str, tuple[float, Provenance]]` keyed by source name (e.g. ``"nvd"``,
``"vendor:acme"``); the platform MUST preserve all source readings rather than
picking a "winner" - downstream policy decides which score to honour.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ..common.canonical import canonical_digest
from ..common.errors import DomainValidationError
from ..policy.models import RiskClass
from .provenance import Provenance

# CVSS v3.x scores live in [0.0, 10.0]; the bounds are inclusive on both ends.
_CVSS_SCORE_MIN: float = 0.0
_CVSS_SCORE_MAX: float = 10.0
# EPSS and detection confidence are probabilities in [0.0, 1.0].
_PROB_MIN: float = 0.0
_PROB_MAX: float = 1.0


def _dedup_preserve_order(values: tuple[str, ...]) -> tuple[str, ...]:
    """Return the input tuple with duplicates removed, order preserved."""

    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return tuple(out)


@dataclass(frozen=True, slots=True)
class AffectedProduct:
    """One (vendor, product, version_range) record touched by a vulnerability.

    `cpe` and `package` are optional because not every source emits them, but
    `vendor` and `product` are required - the platform needs a stable identity
    to key affected-product records against the asset inventory.
    """

    vendor: str
    product: str
    cpe: str | None
    package: str | None
    version_range: str
    fixed_versions: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.vendor:
            raise DomainValidationError(
                "AffectedProduct.vendor must be non-empty"
            )
        if not self.product:
            raise DomainValidationError(
                "AffectedProduct.product must be non-empty"
            )


@dataclass(frozen=True, slots=True)
class ExploitationSignal:
    """Wild-exploitation signals for one vulnerability.

    `epss_score` is a probability in [0.0, 1.0] (FIRST EPSS). The boolean
    fields come from CISA KEV (`kev`), exploit-db/github public-exploit
    sightings (`public_exploit`), ransomware tracking feeds (`ransomware`),
    and active-in-the-wild telemetry (`active_exploitation`).
    """

    kev: bool
    epss_score: float
    public_exploit: bool
    ransomware: bool
    active_exploitation: bool

    def __post_init__(self) -> None:
        if not _PROB_MIN <= self.epss_score <= _PROB_MAX:
            raise DomainValidationError(
                f"ExploitationSignal.epss_score must be in "
                f"[{_PROB_MIN}, {_PROB_MAX}]"
            )


@dataclass(frozen=True, slots=True)
class DetectionMapping:
    """How a vulnerability surfaces through one detection case.

    `case_version` pins the test catalog version the mapping was authored
    against, so mappings remain reproducible across catalog updates. `risk` is
    the `RiskClass` of the detection case (M0). `confidence` is the
    analyst-assigned probability in [0.0, 1.0] that this detection case
    actually fires when the vuln is present.
    """

    vulnerability_id: str
    case_version: str
    detection_type: str
    risk: RiskClass
    confidence: float

    def __post_init__(self) -> None:
        if not self.vulnerability_id:
            raise DomainValidationError(
                "DetectionMapping.vulnerability_id must be non-empty"
            )
        if not self.case_version:
            raise DomainValidationError(
                "DetectionMapping.case_version must be non-empty"
            )
        if not self.detection_type:
            raise DomainValidationError(
                "DetectionMapping.detection_type must be non-empty"
            )
        if not _PROB_MIN <= self.confidence <= _PROB_MAX:
            raise DomainValidationError(
                f"DetectionMapping.confidence must be in "
                f"[{_PROB_MIN}, {_PROB_MAX}]"
            )


@dataclass(frozen=True, slots=True)
class Vulnerability:
    """Canonical vulnerability record (§10.1) with multi-source provenance.

    CVSS is keyed by source name. The platform MUST NOT overwrite one source's
    reading with another's (§10.7): if NVD scores 7.5 and the upstream vendor
    scores 5.5, both readings are preserved and downstream policy decides
    which to honour. ``cvss["nvd"] == (7.5, nvd_provenance)`` and
    ``cvss["vendor:acme"] == (5.5, vendor_provenance)`` coexist on the same
    record.

    `digest` is the canonical SHA-256 over the canonical-JSON projection of
    the record (see `secopent.domain.common.canonical`). It is stable for
    identical inputs and changes when any sourced field changes - including
    CVSS scores, alias lists, or affected-product sets.
    """

    canonical_id: str
    aliases: tuple[str, ...]
    description: str
    cvss: dict[str, tuple[float, Provenance]]
    cwe: tuple[str, ...]
    references: tuple[str, ...]
    published_at: datetime
    affected_products: tuple[AffectedProduct, ...]
    exploitation_signal: ExploitationSignal
    detection_mappings: tuple[DetectionMapping, ...]
    provenance: Provenance
    digest: str = field(default="")

    def __post_init__(self) -> None:
        if not self.canonical_id:
            raise DomainValidationError(
                "Vulnerability.canonical_id must be non-empty"
            )
        if self.published_at.tzinfo is None:
            raise DomainValidationError(
                "Vulnerability.published_at must be timezone-aware"
            )
        # Validate the CVSS multi-source map: every source key must be
        # non-empty, every score must be in [0.0, 10.0], and every value
        # must carry a Provenance record (already validated upstream, but
        # we re-check the score bounds here so the contract is self-contained).
        for source, (score, _prov) in self.cvss.items():
            if not source:
                raise DomainValidationError(
                    "Vulnerability.cvss source key must be non-empty"
                )
            if not _CVSS_SCORE_MIN <= score <= _CVSS_SCORE_MAX:
                raise DomainValidationError(
                    f"Vulnerability.cvss[{source!r}] score must be in "
                    f"[{_CVSS_SCORE_MIN}, {_CVSS_SCORE_MAX}]"
                )
        # Dedup aliases order-preserving (canonical_id stays first because it
        # already leads the tuple when callers build it that way).
        object.__setattr__(self, "aliases", _dedup_preserve_order(self.aliases))
        if not self.digest:
            object.__setattr__(
                self,
                "digest",
                canonical_digest(
                    {
                        "canonical_id": self.canonical_id,
                        "aliases": self.aliases,
                        "description": self.description,
                        "cvss": self.cvss,
                        "cwe": self.cwe,
                        "references": self.references,
                        "published_at": self.published_at,
                        "affected_products": self.affected_products,
                        "exploitation_signal": self.exploitation_signal,
                        "detection_mappings": self.detection_mappings,
                        "provenance": self.provenance,
                    }
                ),
            )
