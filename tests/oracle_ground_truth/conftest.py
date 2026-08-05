"""Shared fixtures for the oracle ground-truth range regression (M2 Task 5).

Real target ranges (Juice Shop / crAPI / vulhub) run in docker-compose in M5
E2E. Docker is unavailable in the M2 environment, so these tests stand in a
``GroundTruthVerifier`` that simulates each range's known ground truth: a
present vulnerability yields N/N successful reproductions (-> CONFIRMED), an
absent one yields failures (-> REFUTED). This keeps the oracle's decision logic
regression-tested per target class until the real ranges come online.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from secopent.application.audit import AuditService
from secopent.application.canary import CanaryTokenManager
from secopent.application.oracle import OracleEngine
from secopent.domain.audit.models import GENESIS_HASH, AuditEvent
from secopent.domain.verification.models import (
    CandidateFinding,
    ReproductionStatus,
    VerificationMethod,
    VulnType,
)
from secopent.domain.verification.registry import default_registry


@dataclass
class _MemoryAuditRepo:
    events: list[AuditEvent] = field(default_factory=list)

    def add(self, e: AuditEvent) -> None:
        self.events.append(e)

    def list_events(self) -> list[AuditEvent]:
        return list(self.events)

    def last_hash(self) -> str:
        return self.events[-1].event_hash.removeprefix("sha256:") if self.events else GENESIS_HASH


class GroundTruthVerifier:
    """Simulate a range's ground truth for one candidate.

    ``vuln_present=True`` -> every reproduction succeeds (the vuln is really
    there, so the oracle reaches N/N). ``vuln_present=False`` -> every
    reproduction fails (a clean / patched target).
    """

    def __init__(self, *, vuln_present: bool) -> None:
        self._vuln_present = vuln_present
        self.reproductions = 0

    def reproduce(
        self,
        candidate: CandidateFinding,
        method: VerificationMethod,
        *,
        canary_token: str,
    session=None,
    ) -> ReproductionStatus:
        self.reproductions += 1
        return ReproductionStatus.SUCCESS if self._vuln_present else ReproductionStatus.FAILURE


@pytest.fixture
def make_oracle():  # type: ignore[no-untyped-def]
    """Return a factory: make_oracle(vuln_present=...) -> (oracle, verifier)."""

    def _factory(*, vuln_present: bool) -> tuple[OracleEngine, GroundTruthVerifier]:
        verifier = GroundTruthVerifier(vuln_present=vuln_present)
        audit = AuditService(_MemoryAuditRepo())
        engine = OracleEngine(
            registry=default_registry(),
            verifier=verifier,
            canary=CanaryTokenManager(audit),
        )
        return engine, verifier

    return _factory


@pytest.fixture
def make_candidate():  # type: ignore[no-untyped-def]
    """Return a factory building a CandidateFinding for a vuln type/target."""

    def _make(vuln_type: VulnType, target: str = "https://range.test/") -> CandidateFinding:
        return CandidateFinding(
            id="cand-range",
            observation_id="obs-range",
            vuln_type=vuln_type,
            target=target,
        )

    return _make
