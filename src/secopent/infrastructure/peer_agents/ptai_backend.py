# src/secopent/infrastructure/peer_agents/ptai_backend.py
"""PtaiBackend: run ptai in a peer-worker container, parse its artifacts
(Phase 2.10; A4 spike re-scope).

ptai (0xSteph, MIT, https://pentestai.xyz) is an *autonomous* AI pentest
agent, NOT an oracle backend (A4 spike confirmed this and re-scoped it as a
future peer agent). Integration shape mirrors StrixBackend / ShannonBackend:
exchange contract on a mounted ``/exchange`` dir, LLM key via container env
only, output parsed by ``ptai_report.parse_ptai_artifacts``.

**Image strategy (Linux-only):** ptai's heavy deps (impacket / bloodhound /
scapy / paramiko) install cleanly only on Linux; the Windows dev environment
cannot ``pip install ptai`` with deps. The peer-worker-ptai image must be
built on a Linux worker. The catalog entry carries ``digest=""`` (unpinned)
until the first Linux build records a manifest-list digest - the executor's
digest check skips tag-only refs (no ``@``), so a locally-built image works
until a registry push pins it. ``build_invocation`` uses the descriptor's
``image_digest`` directly so the catalog stays the single source of truth.

**Output format (TBD):** ptai is autonomous, so its output is free-form
markdown + optional JSON fragments. ``parse_report`` is permissive
(Shannon-style): JSON arrays of finding-like objects yield findings,
markdown blocks with a severity word + URL yield findings, anything else
counts as a problem and never raises. Real schema collection happens on a
Linux first-run; this permissive parser is the stable contract.
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
from .ptai_report import parse_ptai_artifacts

_SCOPE_INSTRUCTION = (
    "Test ONLY the provided targets. Do not scan, probe, or exploit any "
    "host, domain, or URL outside the provided target list. Authorized "
    "security assessment."
)

# ptai is invoked via its CLI (``ptai`` or ``pentest-ai``); the peer-worker
# image's entrypoint selects whichever executable is present.
_PTAI_COMMAND: tuple[str, ...] = ("ptai", "--mcp-server")


class PtaiBackend:
    """PeerAgentBackend for 0xSteph/ptai (MIT, autonomous pentest agent)."""

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
            command=_PTAI_COMMAND,
            mounts={"/exchange": str(exchange)},
            capabilities=(),
            resource_limits={"memory_mb": 4096, "cpus": "2"},
            env={
                "PTAI_LLM": self._llm_provider,
                self._llm_key_name: api_key,
            },
        )

    def parse_report(
        self, result: ContainerResult, workdir: Path
    ) -> PeerAgentReport:
        out_dir = workdir / "exchange" / "out"
        run_id = self._run_id_from_input(workdir)
        findings: list[PeerAgentFinding] = []
        # ptai's output format is TBD (autonomous agent). Scan every artifact
        # in out/ - JSON or markdown - and let the permissive parser pick up
        # whatever finding-like blocks it can. Never raise on content drift.
        if out_dir.exists():
            for artifact in sorted(out_dir.iterdir()):
                if not artifact.is_file():
                    continue
                try:
                    content = artifact.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                parsed, _problems = parse_ptai_artifacts(
                    content, run_id=run_id, agent="ptai"
                )
                findings.extend(parsed)
        return PeerAgentReport(
            run_id=run_id,
            findings=tuple(findings),
            wall_seconds=0.0,  # harness guarantees measured-wall floor
            cost_units=0.0,  # ptai does not self-report cost; wall+external meter
            exit_code=result.exit_code,
        )

    @staticmethod
    def _run_id_from_input(workdir: Path) -> str:
        input_path = workdir / "exchange" / "input.json"
        if input_path.exists():
            try:
                data = json.loads(input_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return ""
            return str(data.get("run_id", ""))
        return ""
