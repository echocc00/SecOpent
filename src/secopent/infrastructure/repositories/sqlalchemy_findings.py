# src/secopent/infrastructure/repositories/sqlalchemy_findings.py
"""SqlAlchemy repository for correlated findings (§13)."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...domain.adapters.contracts import Severity
from ...domain.findings.models import Finding, FindingStatus
from ...domain.verification.models import VerificationStatus
from ..db.finding_models import CoreFinding


def _to_finding(row: CoreFinding) -> Finding:
    return Finding(
        id=row.id,
        fingerprint=row.fingerprint,
        title=row.title,
        asset=row.asset,
        severity=Severity(row.severity),
        cwe=tuple(row.cwe),
        cve=tuple(row.cve),
        owasp=tuple(row.owasp),
        observation_ids=tuple(row.observation_ids),
        evidence_ids=tuple(row.evidence_ids),
        status=FindingStatus(row.status),
        assessment_id=row.assessment_id,
        oracle_verdict=VerificationStatus(row.oracle_verdict),
    )


def _from_finding(finding: Finding) -> CoreFinding:
    return CoreFinding(
        id=finding.id,
        fingerprint=finding.fingerprint,
        title=finding.title,
        asset=finding.asset,
        severity=finding.severity.value,
        cwe=list(finding.cwe),
        cve=list(finding.cve),
        owasp=list(finding.owasp),
        observation_ids=list(finding.observation_ids),
        evidence_ids=list(finding.evidence_ids),
        status=finding.status.value,
        assessment_id=finding.assessment_id,
        oracle_verdict=finding.oracle_verdict.value,
    )


class SqlAlchemyFindingRepository:
    """Persisted Finding store."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, finding: Finding) -> None:
        self._session.merge(_from_finding(finding))

    def get(self, finding_id: str) -> Finding | None:
        row = self._session.get(CoreFinding, finding_id)
        return _to_finding(row) if row else None

    def all(
        self,
        *,
        assessment_id: str | None = None,
        severity: str | None = None,
        oracle_verdict: str | None = None,
    ) -> list[Finding]:
        stmt = select(CoreFinding)
        if assessment_id is not None:
            stmt = stmt.where(CoreFinding.assessment_id == assessment_id)
        if severity is not None:
            stmt = stmt.where(CoreFinding.severity == severity)
        if oracle_verdict is not None:
            stmt = stmt.where(CoreFinding.oracle_verdict == oracle_verdict)
        rows = self._session.execute(stmt).scalars().all()
        return [_to_finding(row) for row in rows]
