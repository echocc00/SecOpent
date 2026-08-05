# src/secopent/application/oracle_service.py
"""OracleService: orchestrate oracle verification over correlated Findings (W3-A T4).

For each Finding with a mappable CWE -> VulnType, the service asks the injected
OracleVerifierFactory for a per-finding reproduction backend, runs OracleEngine
N/N verification, and on CONFIRMED persists a ConfirmedFinding. Every verified
finding's oracle_verdict is updated. Unmappable findings are skipped (verdict
stays PENDING). Best-effort: a single finding whose reproduction raises is
audited and skipped, never aborting the batch.

The LLM is never in this path - only deterministic oracle code confirms.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

import structlog

from ..domain.common.canonical import utc_now
from ..domain.findings.models import Finding
from ..domain.verification.cwe_mapping import vuln_type_for_cwes
from ..domain.verification.models import (
    CandidateFinding,
    VerificationStatus,
    VulnType,
)
from ..domain.verification.registry import VerificationMethodRegistry
from .audit import AuditService
from .audit_chain import AuditChain
from .canary import CanaryTokenManager
from .oracle import OracleEngine
from .ports.oracle import OracleVerifierFactory

_logger = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class OracleSummary:
    confirmed: int = 0
    refuted: int = 0
    inconclusive: int = 0
    skipped: int = 0
    failed: int = 0


class OracleService:
    """Run the oracle over a batch of Findings and persist results."""

    def __init__(
        self,
        *,
        registry: VerificationMethodRegistry,
        canary: CanaryTokenManager,
        verifier_factory: OracleVerifierFactory,
    ) -> None:
        self._registry = registry
        self._canary = canary
        self._verifier_factory = verifier_factory

    def verify_findings(
        self,
        findings: Iterable[Finding],
        *,
        finding_repo: Any,
        confirmed_repo: Any,
        audit: AuditService,
        audit_chain: AuditChain | None,
        actor: str,
        verified_at: datetime | None = None,
        session: Any = None,
    ) -> OracleSummary:
        """Verify each mappable finding; persist ConfirmedFindings + verdicts."""
        verified_at = verified_at or utc_now()
        confirmed = refuted = inconclusive = skipped = failed = 0
        for finding in findings:
            vuln_type = vuln_type_for_cwes(finding.cwe)
            if vuln_type is None:
                skipped += 1
                continue
            try:
                status = self._verify_one(
                    finding,
                    vuln_type,
                    finding_repo,
                    confirmed_repo,
                    audit,
                    audit_chain,
                    actor,
                    verified_at,
                    session=session,
                )
            except Exception as exc:  # noqa: BLE001 - best-effort, never abort batch
                failed += 1
                _logger.warning(
                    "oracle verification failed for finding",
                    finding_id=finding.id,
                    error=str(exc),
                    exc_info=True,
                )
                self._audit(
                    audit, audit_chain, actor, finding.id,
                    "oracle.verification_failed", {"reason": str(exc)},
                )
                continue
            if status is VerificationStatus.CONFIRMED:
                confirmed += 1
            elif status is VerificationStatus.REFUTED:
                refuted += 1
            elif status is VerificationStatus.INCONCLUSIVE:
                inconclusive += 1
        return OracleSummary(
            confirmed=confirmed,
            refuted=refuted,
            inconclusive=inconclusive,
            skipped=skipped,
            failed=failed,
        )

    def _verify_one(
        self,
        finding: Finding,
        vuln_type: VulnType,
        finding_repo: Any,
        confirmed_repo: Any,
        audit: AuditService,
        audit_chain: AuditChain | None,
        actor: str,
        verified_at: datetime,
        session: Any = None,
    ) -> VerificationStatus:
        candidate = CandidateFinding(
            id=finding.id,
            observation_id=(
                finding.observation_ids[0] if finding.observation_ids else finding.id
            ),
            vuln_type=vuln_type,
            target=finding.asset,
        )
        verifier = self._verifier_factory.for_finding(finding)
        engine = OracleEngine(
            registry=self._registry,
            verifier=verifier,
            canary=self._canary,
        )
        result = engine.verify(candidate, actor=actor, session=session)
        if result.status is VerificationStatus.CONFIRMED:
            confirmed = engine.confirm(
                candidate,
                result,
                evidence_ids=finding.evidence_ids,
                verified_at=verified_at,
            )
            confirmed_repo.add(confirmed)
        finding_repo.add(replace(finding, oracle_verdict=result.status))
        self._audit(
            audit, audit_chain, actor, finding.id, "oracle.verified",
            {
                "vuln_type": vuln_type.value,
                "status": result.status.value,
                "successes": result.successes,
                "attempts": result.attempts,
                "reason": result.reason,
            },
        )
        return result.status

    def _audit(
        self,
        audit: AuditService,
        audit_chain: AuditChain | None,
        actor: str,
        finding_id: str,
        action: str,
        payload: dict[str, object],
    ) -> None:
        audit.record(
            actor=actor,
            action=action,
            resource_type="finding",
            resource_id=finding_id,
            payload=payload,
        )
        if audit_chain is not None:
            _session = getattr(getattr(audit, "_repo", None), "session", None)
            audit_chain.record(
                actor=actor,
                action=action,
                resource_type="finding",
                resource_id=finding_id,
                payload=payload,
                session=_session,
            )
