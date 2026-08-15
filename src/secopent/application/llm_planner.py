"""LLMPlanner (v0.6.3): catalog floor + LLM test-class selection (spec §4.2).

The deterministic required classes (``TestCatalog.required_for`` per asset
type) are ALWAYS included - the LLM may only ADD classes it deems relevant to
the mission intent (never subtract; the catalog is the coverage guarantee).
``risk_cap`` filters the final set (calls "add a class above the cap" are
dropped instead of raising - the floor still stands). Any LLM failure or
absence degrades to the deterministic plan, so a mission never fails because
the model is down.

The LLM is deliberately offered the WHOLE catalog (all mapped classes across
asset types) as candidates - that is what makes "add" meaningful - but its
answer is validated: unknown ids are dropped, ids above the risk cap are
dropped, and the required floor is unioned in regardless of what it says.
"""
from __future__ import annotations

import json
from collections.abc import Sequence

from ..domain.assessments.models import ExecutionPlan, PlanStep
from ..domain.catalog.models import AssetType, RequiredTestClass, TestCatalog
from ..domain.policy.models import RiskClass
from .remote_model import ModelBackend

# Default adapter (runner) per asset type - mirrors application/planner.py.
_DEFAULT_RUNNERS: dict[AssetType, str] = {
    AssetType.WEB_APP: "nuclei",
    AssetType.API: "nuclei",
    AssetType.IP_PORT: "nmap",
    AssetType.CLOUD_ACCOUNT: "prowler",
    AssetType.CONTAINER_K8S: "trivy",
}

# Severity/risk ladder for cap comparison.
_RISK_RANK: dict[RiskClass, int] = {
    RiskClass.PASSIVE: 0,
    RiskClass.LOW: 1,
    RiskClass.ACTIVE: 2,
    RiskClass.INTRUSIVE: 3,
    RiskClass.DESTRUCTIVE: 4,
}


def _rank(risk: RiskClass) -> int:
    return _RISK_RANK[risk]


class LLMPlanner:
    """Intent-driven plan generation with a deterministic required floor."""

    def __init__(
        self,
        backend: ModelBackend | None,
        catalog: TestCatalog,
        runner_map: dict[AssetType, str] | None = None,
    ) -> None:
        self._backend = backend
        self._catalog = catalog
        self._runners = dict(_DEFAULT_RUNNERS)
        if runner_map:
            self._runners.update(runner_map)

    def generate(
        self,
        *,
        plan_id: str,
        assessment_id: str,
        asset_types: Sequence[AssetType],
        intent: str,
        risk_cap: RiskClass | None = None,
    ) -> ExecutionPlan:
        """Build a plan: required floor ∪ LLM-selected classes, risk-filtered.

        ``intent`` is the free-text mission goal (e.g. "find exposed admin
        panels"); ``risk_cap`` bounds which classes may run. The cap applies
        to the floor too: a mission that declares itself low-risk cannot carry
        an ACTIVE required class (the grant's covers_risks would reject such a
        plan anyway - declaring the cap is the mission's own risk decision).
        Without a cap the floor is, by construction, the coverage promise.
        """
        floor = self._capped(self._floor_classes(asset_types), risk_cap)
        llm_added: set[RequiredTestClass] = set()
        if self._backend is not None:
            llm_added = self._capped(self._llm_classes(intent, risk_cap), risk_cap)

        steps: list[PlanStep] = []
        for asset_type in asset_types:
            for cls in sorted(
                (c for c in floor if c in self._catalog.required_for(asset_type)),
                key=lambda c: c.id,
            ):
                steps.append(self._to_step(asset_type, cls, intent))
        # LLM additions: they are catalog classes the mission's LLM deemed
        # relevant; add each with ITS OWN asset type (id prefix) as the step's
        # classification, regardless of which asset_types the mission listed -
        # the catalog is the curated set of security test classes, and a
        # relevant class is valuable for any mission target.
        existing_keys = {s.key for s in steps}
        for cls in sorted(llm_added, key=lambda c: c.id):
            owner = self._asset_type_of(cls.id)
            if owner is None:
                continue
            step = self._to_step(owner, cls, intent)
            if step.key not in existing_keys:
                steps.append(step)
                existing_keys.add(step.key)
        return ExecutionPlan.create(
            plan_id=plan_id,
            assessment_id=assessment_id,
            version=1,
            steps=tuple(steps),
        )

    def _capped(
        self, classes: set[RequiredTestClass], risk_cap: RiskClass | None
    ) -> set[RequiredTestClass]:
        if risk_cap is None:
            return classes
        return {c for c in classes if _rank(c.risk) <= _rank(risk_cap)}

    # -- floor ----------------------------------------------------------------

    def _floor_classes(
        self, asset_types: Sequence[AssetType]
    ) -> set[RequiredTestClass]:
        required: set[RequiredTestClass] = set()
        for asset_type in asset_types:
            required |= set(self._catalog.required_for(asset_type))
        return required

    # -- LLM selection ----------------------------------------------------------

    def _llm_classes(
        self, intent: str, risk_cap: RiskClass | None
    ) -> set[RequiredTestClass]:
        try:
            raw = self._backend.complete(  # type: ignore[union-attr]
                self._build_prompt(intent, risk_cap)
            )
            chosen_ids = {
                str(item)
                for item in json.loads(raw)
                if isinstance(item, str)
            }
        except Exception:  # noqa: BLE001 - degrade to the floor on ANY model failure
            return set()
        known = {
            cls.id: cls
            for mapping in self._catalog.mappings.values()
            for cls in mapping
        }
        result: set[RequiredTestClass] = set()
        for cid in chosen_ids:
            cls = known.get(cid)
            if cls is None:
                continue  # unknown id (hallucinated) - drop silently
            if risk_cap is not None and _rank(cls.risk) > _rank(risk_cap):
                continue  # above the cap - drop, never raise
            result.add(cls)
        return result

    def _build_prompt(self, intent: str, risk_cap: RiskClass | None) -> str:
        candidates = [
            f'- "{cls.id}" (risk={cls.risk.value}, cwe={",".join(cls.cwe) or "-"})'
            for mapping in self._catalog.mappings.values()
            for cls in mapping
        ]
        lines = "\n".join(candidates)
        cap = risk_cap.value if risk_cap else "no cap"
        return (
            "You select security test classes for an authorized pentest mission.\n"
            f"Mission intent: {intent}\n"
            f"Risk cap: {cap}. A class AT or BELOW the cap may be selected; "
            "classes above it must NOT be selected.\n"
            'Choose the most relevant class ids from this exact list. '
            'Reply with ONLY a JSON array of strings, e.g. ["a","b"].\n'
            f"Candidates:\n{lines}"
        )

    # -- step mapping -------------------------------------------------------------

    def _asset_type_of(self, class_id: str) -> AssetType | None:
        """Map a catalog class id prefix (e.g. "web_app:...") to its AssetType."""
        prefix, _, _rest = class_id.partition(":")
        for asset_type in AssetType:
            if asset_type.value == prefix:
                return asset_type
        return None

    def _to_step(
        self, asset_type: AssetType, cls: RequiredTestClass, intent: str
    ) -> PlanStep:
        return PlanStep(
            key=f"{asset_type.value}:{cls.id.removeprefix(f'{asset_type.value}:')}",
            runner=self._runners.get(asset_type, "adapter"),
            risk=cls.risk,
            parameters={
                "asset_type": asset_type.value,
                "test_class": cls.id,
                "cwe": cls.cwe,
                "owasp": cls.owasp,
                "intent": intent,
            },
            dependencies=(),
        )