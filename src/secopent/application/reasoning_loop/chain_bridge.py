# src/secopent/application/reasoning_loop/chain_bridge.py
"""ChainBridge — AttackChain pending hypotheses into LoopContext (spec §3.4, v0.7.5).

Closes the AttackChain hypothesis loop: confirmed findings feed the
ChainEngine, whose un-verified pending links are surfaced to the LLM as
``LoopContext.chain_hypotheses_pending``. This replaces the hardcoded ``()``
the context builder returned, so the SchemaGate's SCHEMA_UNKNOWN_HYPOTHESIS
check has a real, knowledge-backed hypothesis set to validate request_chain
actions against.

The bridge is backend-agnostic: confirmed findings arrive through an injected
``finding_provider`` callable (default empty), so it does not depend on
LoopContext construction internals or an assessment repository.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable

from ...domain.findings.models import Finding
from ...domain.reasoning_loop.models import PendingHypothesis
from ..chain_engine import ChainEngine, PendingVerificationTask


class ChainBridge:
    """Translate ChainEngine pending-verification tasks into PendingHypothesis."""

    def __init__(
        self,
        *,
        engine: ChainEngine,
        finding_provider: Callable[[], Iterable[Finding]] = lambda: (),
    ) -> None:
        self._engine = engine
        self._finding_provider = finding_provider

    def sync(self) -> tuple[PendingHypothesis, ...]:
        """Feed confirmed findings → hypotheses → pending tasks → hypotheses."""
        findings = self._finding_provider()
        chains = self._engine.hypothesize_from_findings(findings)
        tasks = self._engine.pending_verification_tasks(chains)
        return tuple(self._to_hypothesis(task) for task in tasks)

    @staticmethod
    def valid_hypothesis(
        hypothesis_id: str, pending: tuple[PendingHypothesis, ...]
    ) -> bool:
        return any(h.hypothesis_id == hypothesis_id for h in pending)

    @staticmethod
    def _to_hypothesis(task: PendingVerificationTask) -> PendingHypothesis:
        cwe_label = "/".join(task.required_cwe) if task.required_cwe else "evidence"
        asset_hint = task.asset_hint or "the target asset"
        return PendingHypothesis(
            hypothesis_id=task.key,
            description=f"confirm '{cwe_label}' evidence on {asset_hint}",
            needed_cwe=task.required_cwe,
        )
