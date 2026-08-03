# src/secopent/infrastructure/peer_agents/strix_backend.py
"""StrixBackend: run Strix in a peer-worker container, parse its artifacts.

The peer-worker image carries strix-agent (version-pinned) + entrypoint.py.
Exchange contract (mounted at /exchange):
- input.json   (host -> container): {run_id, targets, instruction}
- out/vulnerabilities.json, out/run.json  (container -> host)

LLM credentials enter ONLY via container env (never files): StrixBackend
pulls them from the injected secret_lookup at invocation time.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from ...domain.peer_agents.models import (
    PeerAgentDescriptor,
    PeerAgentFinding,
    PeerAgentReport,
    PeerAgentRun,
)
from ..adapters.base import ContainerResult
from .harness import PeerInvocation
from .strix_report import parse_vulnerabilities_json

_SCOPE_INSTRUCTION = (
    "Test ONLY the provided targets. Do not scan, probe, or exploit any "
    "host, domain, or URL outside the provided target list. Authorized "
    "security assessment."
)


class StrixBackend:
    """PeerAgentBackend for usestrix/strix (Apache-2.0)."""

    def __init__(
        self,
        *,
        llm_provider: str,
        secret_lookup: Mapping[str, str],
        llm_key_name: str = "LLM_API_KEY",
    ) -> None:
        self._llm_provider = llm_provider
        self._secrets = secret_lookup
        self._llm_key_name = llm_key_name

    def build_invocation(
        self,
        run: PeerAgentRun,
        descriptor: PeerAgentDescriptor,
        workdir: Path,
    ) -> PeerInvocation:
        api_key = self._secrets[self._llm_key_name]  # KeyError = config error
        exchange = workdir / "exchange"
        (exchange / "out").mkdir(parents=True, exist_ok=True)
        (exchange / "input.json").write_text(
            json.dumps(
                {
                    "run_id": run.id,
                    "targets": list(run.targets),
                    "instruction": _SCOPE_INSTRUCTION,
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        return PeerInvocation(
            image_digest=descriptor.image_digest,
            command=("python", "/opt/entrypoint.py"),
            mounts={"/exchange": str(exchange)},
            capabilities=(),
            resource_limits={"memory_mb": 4096, "cpus": "2"},
            env={
                "STRIX_LLM": self._llm_provider,
                self._llm_key_name: api_key,
            },
        )

    def parse_report(
        self, result: ContainerResult, workdir: Path
    ) -> PeerAgentReport:
        out_dir = workdir / "exchange" / "out"
        vuln_path = out_dir / "vulnerabilities.json"
        findings: tuple[PeerAgentFinding, ...] = ()
        if vuln_path.exists():
            findings = parse_vulnerabilities_json(  # type: ignore[assignment]
                vuln_path.read_text(encoding="utf-8"),
                run_id=self._run_id_from_input(workdir),
                agent="strix",
            )
        cost = self._cost_from_run_json(out_dir / "run.json")
        return PeerAgentReport(
            run_id=self._run_id_from_input(workdir),
            findings=findings,
            wall_seconds=0.0,  # harness guarantees measured-wall floor
            cost_units=cost,
            exit_code=result.exit_code,
        )

    @staticmethod
    def _run_id_from_input(workdir: Path) -> str:
        input_path = workdir / "exchange" / "input.json"
        if input_path.exists():
            data = json.loads(input_path.read_text(encoding="utf-8"))
            return str(data.get("run_id", ""))
        return ""

    @staticmethod
    def _cost_from_run_json(path: Path) -> float:
        if not path.exists():
            return 0.0
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return 0.0
        usage = data.get("llm_usage") or {}
        value = usage.get("total_cost_usd", 0.0)
        return float(value) if isinstance(value, int | float) else 0.0
