# src/secopent/infrastructure/repositories/sqlalchemy_intel.py
"""SqlAlchemy repositories for the intel knowledge layer + UpdateManager bundles.

The intel repository persists a ``Vulnerability`` across five ORM tables
(``CoreVulnerability`` + child rows for affected products, exploitation
signal, and detection mappings) and keeps the ``core_vulnerabilities_fts``
FTS5 virtual table in sync on every insert so callers can search by keyword,
CVE, or CWE (§10 of the main design).

The update repository stores bundles and the single-row activation pointer
used by ``UpdateManager`` (Task 6).
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from ...domain.intel.models import (
    AffectedProduct,
    DetectionMapping,
    ExploitationSignal,
    Vulnerability,
)
from ...domain.intel.provenance import Provenance
from ...domain.policy.models import RiskClass
from ..db.intel_models import (
    CoreAffectedProduct,
    CoreDetectionMapping,
    CoreExploitationSignal,
    CoreVulnerability,
)
from ..db.update_models import CoreBundleActivation, CoreUpdateBundle

# --- Provenance / CVSS serialization ----------------------------------------


def _provenance_to_dict(prov: Provenance) -> dict[str, Any]:
    return {
        "source": prov.source,
        "fetched_at": prov.fetched_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "source_version": prov.source_version,
    }


def _provenance_from_dict(data: dict[str, Any]) -> Provenance:
    fetched_at = datetime.fromisoformat(data["fetched_at"].replace("Z", "+00:00"))
    return Provenance(
        source=data["source"],
        fetched_at=fetched_at,
        source_version=data["source_version"],
    )


def _cvss_to_dict(cvss: dict[str, tuple[float, Provenance]]) -> dict[str, Any]:
    return {
        source: {"score": score, "provenance": _provenance_to_dict(prov)}
        for source, (score, prov) in cvss.items()
    }


def _cvss_from_dict(data: dict[str, Any]) -> dict[str, tuple[float, Provenance]]:
    return {
        source: (entry["score"], _provenance_from_dict(entry["provenance"]))
        for source, entry in data.items()
    }


# --- Vulnerability <-> ORM --------------------------------------------------


def _to_vulnerability(row: CoreVulnerability, session: Session) -> Vulnerability:
    # Load child rows in one round-trip each (child tables are small per vuln).
    products = session.execute(
        select(CoreAffectedProduct)
        .where(CoreAffectedProduct.vulnerability_id == row.canonical_id)
    ).scalars().all()
    signal_row = session.execute(
        select(CoreExploitationSignal)
        .where(CoreExploitationSignal.vulnerability_id == row.canonical_id)
    ).scalars().first()
    mappings = session.execute(
        select(CoreDetectionMapping)
        .where(CoreDetectionMapping.vulnerability_id == row.canonical_id)
    ).scalars().all()

    affected = tuple(
        AffectedProduct(
            vendor=p.vendor, product=p.product, cpe=p.cpe, package=p.package,
            version_range=p.version_range, fixed_versions=tuple(p.fixed_versions),
        )
        for p in products
    )
    signal = ExploitationSignal(
        kev=signal_row.kev if signal_row else False,
        epss_score=signal_row.epss_score if signal_row else 0.0,
        public_exploit=signal_row.public_exploit if signal_row else False,
        ransomware=signal_row.ransomware if signal_row else False,
        active_exploitation=signal_row.active_exploitation if signal_row else False,
    )
    detection_mappings = tuple(
        DetectionMapping(
            vulnerability_id=m.vulnerability_id,
            case_version=m.case_version,
            detection_type=m.detection_type,
            risk=RiskClass(m.risk),
            confidence=m.confidence,
        )
        for m in mappings
    )
    published_at = row.published_at
    if published_at.tzinfo is None:
        published_at = published_at.replace(tzinfo=UTC)
    return Vulnerability(
        canonical_id=row.canonical_id,
        aliases=tuple(row.aliases),
        description=row.description,
        cvss=_cvss_from_dict(row.cvss),
        cwe=tuple(row.cwe),
        references=tuple(row.references),
        published_at=published_at,
        affected_products=affected,
        exploitation_signal=signal,
        detection_mappings=detection_mappings,
        provenance=_provenance_from_dict(row.provenance),
        digest=row.digest,
    )


def _fts_index_vuln(session: Session, vuln: Vulnerability) -> None:
    """Insert one row into the FTS5 virtual table mirroring the vulnerability.

    ``canonical_id`` is UNINDEXED in the FTS schema (see test fixture) so it
    is stored for retrieval but not tokenized. ``cve`` is the canonical_id
    plus any aliases so a search by CVE-XXXX-YYYY hits both the canonical id
    and the alias. ``cwe`` is the space-joined CWE list so a search by
    CWE-787 hits every vuln tagged with that CWE.
    """

    cve_field = " ".join({vuln.canonical_id, *vuln.aliases})
    cwe_field = " ".join(vuln.cwe)
    session.execute(
        text(
            "INSERT INTO core_vulnerabilities_fts "
            "(canonical_id, cve, description, cwe) VALUES (:cid, :cve, :desc, :cwe)"
        ),
        {
            "cid": vuln.canonical_id,
            "cve": cve_field,
            "desc": vuln.description,
            "cwe": cwe_field,
        },
    )


class SqlAlchemyIntelRepository:
    """Persisted Vulnerability store with FTS5 search."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        self._session.merge(CoreVulnerability(
            canonical_id=vuln.canonical_id,
            aliases=list(vuln.aliases),
            description=vuln.description,
            cvss=_cvss_to_dict(vuln.cvss),
            cwe=list(vuln.cwe),
            references=list(vuln.references),
            published_at=vuln.published_at,
            provenance=_provenance_to_dict(vuln.provenance),
            digest=vuln.digest,
        ))
        # Flush so the parent row is visible to the FK on child inserts.
        # merge() does not guarantee ordering relative to subsequent adds.
        self._session.flush()
        # Child rows: delete-then-insert to keep merge semantics idempotent.
        self._session.execute(
            text("DELETE FROM core_affected_products WHERE vulnerability_id = :cid"),
            {"cid": vuln.canonical_id},
        )
        for product in vuln.affected_products:
            self._session.add(CoreAffectedProduct(
                vulnerability_id=vuln.canonical_id,
                vendor=product.vendor, product=product.product,
                cpe=product.cpe, package=product.package,
                version_range=product.version_range,
                fixed_versions=list(product.fixed_versions),
            ))
        self._session.execute(
            text("DELETE FROM core_exploitation_signals WHERE vulnerability_id = :cid"),
            {"cid": vuln.canonical_id},
        )
        self._session.add(CoreExploitationSignal(
            vulnerability_id=vuln.canonical_id,
            kev=vuln.exploitation_signal.kev,
            epss_score=vuln.exploitation_signal.epss_score,
            public_exploit=vuln.exploitation_signal.public_exploit,
            ransomware=vuln.exploitation_signal.ransomware,
            active_exploitation=vuln.exploitation_signal.active_exploitation,
        ))
        self._session.execute(
            text("DELETE FROM core_detection_mappings WHERE vulnerability_id = :cid"),
            {"cid": vuln.canonical_id},
        )
        for m in vuln.detection_mappings:
            self._session.add(CoreDetectionMapping(
                vulnerability_id=vuln.canonical_id,
                case_version=m.case_version,
                detection_type=m.detection_type,
                risk=m.risk.value,
                confidence=m.confidence,
            ))
        # FTS5 sync: replace any existing FTS row for this canonical_id, then
        # insert the new one so re-adding an already-stored vuln does not
        # duplicate search hits.
        self._session.execute(
            text("DELETE FROM core_vulnerabilities_fts WHERE canonical_id = :cid"),
            {"cid": vuln.canonical_id},
        )
        _fts_index_vuln(self._session, vuln)

    def get_vulnerability(self, canonical_id: str) -> Vulnerability | None:
        row = self._session.get(CoreVulnerability, canonical_id)
        if not row:
            return None
        return _to_vulnerability(row, self._session)

    def search_fts(
        self,
        keyword: str | None = None,
        cve: str | None = None,
        cwe: str | None = None,
    ) -> list[Vulnerability]:
        """Search vulnerabilities by keyword, CVE, or CWE.

        Only one of ``keyword`` / ``cve`` / ``cwe`` is honored at a time
        (caller can issue multiple searches to combine). An empty query
        returns an empty list - the platform never returns "all rows" from
        a search endpoint.
        """

        query = cve or cwe or keyword
        if not query:
            return []
        # FTS5 MATCH uses double-quotes for phrase queries; the caller passes
        # a single token (e.g. "CVE-2024-1234" or "widget") so we quote it to
        # avoid hyphens being interpreted as NOT operators.
        # Choose the column to match against: cve/cwe go to their dedicated
        # columns, keyword goes to the union of cve+description+cwe.
        if cve:
            column = "cve"
        elif cwe:
            column = "cwe"
        else:
            column = "description"  # keyword: match the description column
        stmt = text(
            "SELECT canonical_id FROM core_vulnerabilities_fts "
            f"WHERE {column} MATCH :q"
        )
        rows = self._session.execute(stmt, {"q": f'"{query}"'}).all()
        result: list[Vulnerability] = []
        for r in rows:
            vuln = self.get_vulnerability(r[0])
            if vuln is not None:
                result.append(vuln)
        return result

    def count_vulnerabilities(self) -> int:
        """Total number of canonical vulnerability records in the store."""
        return int(
            self._session.execute(
                select(func.count()).select_from(CoreVulnerability)
            ).scalar_one()
        )


# --- Update bundle repository ----------------------------------------------


class SqlAlchemyUpdateRepository:
    """Persisted UpdateBundle store with single-active-bundle pointer."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add_bundle(
        self, bundle_id: str, version: str, digest: str, payload: dict[str, Any]
    ) -> None:
        from ...domain.common.canonical import utc_now
        self._session.merge(CoreUpdateBundle(
            bundle_id=bundle_id, version=version, digest=digest,
            payload=payload, staged_at=utc_now(),
        ))

    def get_bundle(self, bundle_id: str) -> dict[str, Any] | None:
        row = self._session.get(CoreUpdateBundle, bundle_id)
        if not row:
            return None
        return {
            "bundle_id": row.bundle_id,
            "version": row.version,
            "digest": row.digest,
            "payload": row.payload,
            "staged_at": row.staged_at,
        }

    def set_active_bundle(self, bundle_id: str) -> None:
        # Upsert the singleton row: delete then insert keeps the operation
        # idempotent and avoids per-dialect upsert quirks.
        self._session.execute(text("DELETE FROM core_bundle_activations"))
        self._session.add(CoreBundleActivation(
            singleton=1, active_bundle_id=bundle_id,
        ))

    def get_active_bundle_id(self) -> str | None:
        row = self._session.execute(
            select(CoreBundleActivation).where(CoreBundleActivation.singleton == 1)
        ).scalars().first()
        return row.active_bundle_id if row else None


__all__ = [
    "SqlAlchemyIntelRepository",
    "SqlAlchemyUpdateRepository",
]
