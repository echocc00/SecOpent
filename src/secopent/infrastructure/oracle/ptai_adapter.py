# src/secopent/infrastructure/oracle/ptai_adapter.py
"""PtaiAdapter: pentest-ai backend for the OracleEngine (ADR-014: adopt, not rebuild).

The adapter wraps the pentest-ai (``ptai``) verification API behind the
``OracleVerifier`` contract the OracleEngine expects: a single independent
reproduction that reports SUCCESS / FAILURE / SERVER_ERROR. pentest-ai is an
optional runtime dependency; the module is imported lazily so the adapter can be
unit-tested with an injected fake module on hosts where ``ptai`` is not
installed (real ptai execution is wired in M5 E2E).
"""
from __future__ import annotations

from typing import Any, Protocol

from secopent.domain.verification.models import (
    CandidateFinding,
    ReproductionStatus,
    VerificationMethod,
)


class _PtaiModule(Protocol):
    """The slice of the ptai API the adapter uses."""

    def verify(
        self, *, target: str, vuln_type: str, canary_token: str, n: int
    ) -> str: ...


def _import_ptai() -> Any:
    """Import pentest-ai lazily; raise a clear error if it is unavailable."""
    try:
        import ptai  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "pentest-ai (ptai) is not installed; install it or inject a ptai "
            "module into PtaiAdapter for testing"
        ) from exc
    return ptai


class PtaiAdapter:
    """Adapt pentest-ai's verify API to the OracleVerifier contract."""

    def __init__(self, ptai_module: _PtaiModule | None = None) -> None:
        self._ptai = ptai_module

    def reproduce(
        self,
        candidate: CandidateFinding,
        method: VerificationMethod,
        *,
        canary_token: str,
    ) -> ReproductionStatus:
        """Run one pentest-ai reproduction and map its outcome to a status."""
        ptai = self._ptai if self._ptai is not None else _import_ptai()
        raw = ptai.verify(
            target=candidate.target,
            vuln_type=method.vuln_type.value,
            canary_token=canary_token,
            n=1,
        )
        return ReproductionStatus(str(raw).lower())
