# src/secopent/application/reasoning_loop/chain_bridge.py
"""ChainBridge — AttackChain pending hypotheses into LoopContext (spec §3.4, v0.7.5).

Closes the AttackChain hypothesis loop: confirmed findings feed the
ChainEngine, whose un-verified pending links are surfaced to the LLM as
``LoopContext.chain_hypotheses_pending``. This replaces the hardcoded ``()``
the context builder returned, so the SchemaGate's SCHEMA_UNKNOWN_HYPOTHESIS
check has a real, knowledge-backed hypothesis set to validate request_chain
actions against.

Task 2 (提供驱动 / verification-progress-driven): the engine mints a FRESH
``chain-{uuid}`` / ``pv-{uuid}`` id on every ``hypothesize_from_findings``
call, so a hypothesis proposed at step N could never be resolved at step N+1.
The bridge therefore owns a DETERMINISTIC identity scheme: each pending link is
keyed canonically by ``(template_id, link_index, sorted(required_cwe))`` (see
``_canonical_id``), NOT the volatile engine key. Repeated ``sync()`` calls over
the same template + findings yield the SAME ``hypothesis_id``. A
``HypothesesStore`` persists the canonical id -> (chain_id, link_index,
required_cwe, progressed) mapping across sync() calls so progress on one
hypothesis survives the engine's fresh-id churn. ``mark_pending_progress``
records that a hypothesis was evidenced; the next ``sync()`` drops it from the
pending set, and ``next_priorities`` ranks whatever remains by urgency.

The engine itself is immutable and untouched: the store's role is limited to
stable identity + progress bookkeeping, while the bridge always mirrors the
engine's honest output for confirmation status. ``HypothesesStore`` is an
injectable protocol so v0.7.8 can swap in a DB-backed store.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Protocol

from ...domain.findings.attack_chain import AttackChain, ChainStatus
from ...domain.findings.models import Finding
from ...domain.reasoning_loop.models import PendingHypothesis
from ..chain_engine import ChainEngine, PendingVerificationTask


@dataclass(frozen=True, slots=True)
class PendingPriority:
    """Ranked pointer to a pending hypotheses: most urgent first.

    ``priority_score`` is a relative int — higher = more urgent (a pending link
    that must be resolved before later links, or one with fewer remaining CWEs,
    scores higher). ``chain_id`` is the engine chain id captured at record time
    (traceability only — it is NOT part of the stable identity key).
    """

    hypothesis_id: str
    priority_score: int
    chain_id: str | None = None


@dataclass(frozen=True, slots=True)
class ConcludedChain:
    """A chain the engine reports fully confirmed — the loop may stop proposing
    work on it. ``template_id`` is the stable logical identity (the engine's own
    ``chain.id`` carries a volatile uuid per hypothesize call, so it is not a
    reliable cross-sync handle). Ordering of ``concluded_chains()`` is
    deterministic: sorted by ``template_id``."""

    template_id: str


@dataclass(frozen=True, slots=True)
class HypothesisRecord:
    """Persisted meta for one canonical hypothesis (kept immutable; progress
    transitions create a new record rather than mutating this one)."""

    hypothesis_id: str
    chain_id: str
    link_index: int
    required_cwe: tuple[str, ...]
    progressed: bool = False

    def with_progress(self) -> HypothesisRecord:
        return HypothesisRecord(
            hypothesis_id=self.hypothesis_id,
            chain_id=self.chain_id,
            link_index=self.link_index,
            required_cwe=self.required_cwe,
            progressed=True,
        )


class HypothesesStore(Protocol):
    """Persists canonical hypothesis identity + progress across sync() calls.

    Injectable so a later milestone (v0.7.8) can back it with a DB without
    changing the bridge. The default is ``InMemoryHypothesesStore``.
    """

    def record(
        self,
        hypothesis_id: str,
        *,
        chain_id: str,
        link_index: int,
        required_cwe: tuple[str, ...],
    ) -> None: ...

    def get(self, hypothesis_id: str) -> HypothesisRecord | None: ...

    def mark_progress(self, hypothesis_id: str) -> None: ...


class InMemoryHypothesesStore:
    """Default in-memory HypothesesStore. Records are immutable; progress
    replaces the entry with a new progressed record."""

    def __init__(self) -> None:
        self._records: dict[str, HypothesisRecord] = {}

    def record(
        self,
        hypothesis_id: str,
        *,
        chain_id: str,
        link_index: int,
        required_cwe: tuple[str, ...],
    ) -> None:
        # Keep the FIRST-seen identity meta; only progress may be re-stamped.
        existing = self._records.get(hypothesis_id)
        if existing is None:
            self._records[hypothesis_id] = HypothesisRecord(
                hypothesis_id=hypothesis_id,
                chain_id=chain_id,
                link_index=link_index,
                required_cwe=required_cwe,
            )

    def get(self, hypothesis_id: str) -> HypothesisRecord | None:
        return self._records.get(hypothesis_id)

    def mark_progress(self, hypothesis_id: str) -> None:
        existing = self._records.get(hypothesis_id)
        if existing is not None and not existing.progressed:
            self._records[hypothesis_id] = existing.with_progress()


class ChainBridge:
    """Translate ChainEngine pending-verification tasks into PendingHypothesis.

    Owns the deterministic hypothesis identity scheme (v0.7.5 Task 2) so a
    hypothesis proposed at step N can still be resolved at step N+1.
    """

    def __init__(
        self,
        *,
        engine: ChainEngine,
        finding_provider: Callable[[], Iterable[Finding]] = lambda: (),
        store: HypothesesStore | None = None,
    ) -> None:
        self._engine = engine
        self._finding_provider = finding_provider
        self._store = store if store is not None else InMemoryHypothesesStore()
        self._last_chains: tuple[AttackChain, ...] = ()

    def sync(self) -> tuple[PendingHypothesis, ...]:
        """Feed confirmed findings → hypotheses → pending tasks → hypotheses.

        Produces STABLE hypothesis ids keyed on ``(template_id, link_index,
        sorted(required_cwe))``, so re-running over the same findings surfaces
        the same ids. Hypotheses already marked progressed are dropped.
        """
        findings = self._finding_provider()
        chains = self._engine.hypothesize_from_findings(findings)
        self._last_chains = chains
        tasks = self._engine.pending_verification_tasks(chains)
        tasks_iter = iter(tasks)
        results: list[PendingHypothesis] = []
        for chain in chains:
            # The engine's tasks correspond exactly to each chain's un-confirmed
            # links in link order (chain_engine._tasks_for zips chain.links with
            # template.links, strict=True) — so link_index is the enumerate index.
            for link_index, link in enumerate(chain.links):
                if link.is_confirmed:
                    continue
                task = next(tasks_iter, None)
                if task is None:
                    break
                hypothesis_id = self._canonical_id(
                    chain.template_id, link_index, task.required_cwe
                )
                record = self._store.get(hypothesis_id)
                if record is not None and record.progressed:
                    continue
                self._store.record(
                    hypothesis_id,
                    chain_id=chain.id,
                    link_index=link_index,
                    required_cwe=task.required_cwe,
                )
                results.append(self._to_hypothesis(hypothesis_id, task))
        return tuple(results)

    def concluded_chains(self) -> tuple[ConcludedChain, ...]:
        """Chains the last ``sync()`` reported fully CONFIRMED — the loop may
        stop proposing verification work on these.

        Derived honestly from the engine's own status (stored last-sync chains),
        never hand-computed here. Deterministic order: sorted by ``template_id``.
        """
        concluded = [
            ConcludedChain(template_id=chain.template_id)
            for chain in self._last_chains
            if chain.status is ChainStatus.CONFIRMED
        ]
        concluded.sort(key=lambda c: c.template_id)
        return tuple(concluded)

    @staticmethod
    def valid_hypothesis(
        hypothesis_id: str, pending: tuple[PendingHypothesis, ...]
    ) -> bool:
        return any(h.hypothesis_id == hypothesis_id for h in pending)

    def mark_pending_progress(self, hypothesis_id: str) -> None:
        """Record that a pending hypothesis was evidenced / progressed.

        The engine's confirmation status is untouched (mirrored honestly on the
        next sync()); this only sets the store's bookkeeping flag so the next
        ``sync()`` drops the hypothesis from the pending set.
        """
        self._store.mark_progress(hypothesis_id)

    def next_priorities(
        self, pending: tuple[PendingHypothesis, ...]
    ) -> tuple[PendingPriority, ...]:
        """Rank pending hypotheses by urgency, most urgent first.

        Deterministic order: sort by ``(-priority_score, hypothesis_id)``.
        ``priority_score`` rewards earlier un-resolved links (must be confirmed
        before later links) and punishes a larger remaining CWE set.
        """
        scored: list[PendingPriority] = []
        for hypo in pending:
            record = self._store.get(hypo.hypothesis_id)
            link_index = record.link_index if record is not None else 0
            priority_score = -link_index * 10 - len(hypo.needed_cwe)
            scored.append(
                PendingPriority(
                    hypothesis_id=hypo.hypothesis_id,
                    priority_score=priority_score,
                    chain_id=record.chain_id if record is not None else None,
                )
            )
        scored.sort(key=lambda p: (-p.priority_score, p.hypothesis_id))
        return tuple(scored)

    @staticmethod
    def _canonical_id(
        template_id: str, link_index: int, required_cwe: tuple[str, ...]
    ) -> str:
        """Stable hash-based id from the link's logical identity.

        Keyed on ``(template_id, link_index, sorted(required_cwe))`` — NOT the
        volatile engine ``pending_verification_key`` — so the same template +
        link position always mint the same ``hyp-...`` id.
        """
        key = f"{template_id}:{link_index}:{','.join(sorted(required_cwe))}"
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
        return f"hyp-{digest}"

    @staticmethod
    def _to_hypothesis(
        hypothesis_id: str, task: PendingVerificationTask
    ) -> PendingHypothesis:
        cwe_label = "/".join(task.required_cwe) if task.required_cwe else "evidence"
        asset_hint = task.asset_hint or "the target asset"
        return PendingHypothesis(
            hypothesis_id=hypothesis_id,
            description=f"confirm '{cwe_label}' evidence on {asset_hint}",
            needed_cwe=task.required_cwe,
        )
