# src/secopent/infrastructure/peer_agents/shannon_backend.py
"""ShannonBackend: AGPL-isolated Shannon integration (spec §10, decision D2).

Isolation invariants:
- NO code import/link/copy from Shannon sources; interaction surface is ONLY
  CLI/env in + .shannon/deliverables/ out (process-level AGPL firewall);
- the target repo is mounted as a THROWAWAY WORKING COPY (original repo is
  never visible/writable to the peer container);
- LLM key via container env only (never files).
"""
from __future__ import annotations

import shutil
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
from .shannon_deliverables import parse_deliverable_markdown

_ANALYSIS_SUFFIX = "_analysis_deliverable.md"


class ShannonBackend:
    """PeerAgentBackend for Keygraph Shannon (white-box, AGPL-isolated)."""

    def __init__(
        self,
        *,
        repo_path: Path,
        llm_key_name: str,
        secret_lookup: Mapping[str, str],
    ) -> None:
        self._repo = Path(repo_path)
        self._llm_key_name = llm_key_name
        self._secrets = secret_lookup

    def build_invocation(
        self,
        run: PeerAgentRun,
        descriptor: PeerAgentDescriptor,
        workdir: Path,
    ) -> PeerInvocation:
        api_key = self._secrets[self._llm_key_name]
        copy_root = Path(workdir) / "repo-copy"
        _copy_repo(self._repo, copy_root)
        # Self-contained run_id marker (P0 harness does not write this file;
        # ShannonBackend owns the marker so parse_report can read it back).
        run_id_marker = Path(workdir) / "run_id.txt"
        run_id_marker.parent.mkdir(parents=True, exist_ok=True)
        run_id_marker.write_text(run.id, encoding="utf-8")
        return PeerInvocation(
            image_digest=descriptor.image_digest,
            command=("shannon", "start", "-u", run.targets[0], "-r", "/repo"),
            mounts={"/repo": str(copy_root)},
            capabilities=(),
            resource_limits={"memory_mb": 4096, "cpus": "2"},
            env={
                self._llm_key_name: api_key,
                "WEB_URL": run.targets[0],
            },
        )

    def parse_report(
        self, result: ContainerResult, workdir: Path
    ) -> PeerAgentReport:
        deliverables = Path(workdir) / "repo-copy" / ".shannon" / "deliverables"
        findings: list[PeerAgentFinding] = []
        problems = 0
        if deliverables.exists():
            for md_file in sorted(deliverables.glob("*.md")):
                vuln_class = md_file.name.removesuffix(_ANALYSIS_SUFFIX)
                parsed, issues = parse_deliverable_markdown(
                    md_file.read_text(encoding="utf-8"),
                    run_id=self._run_id(workdir), agent="shannon",
                    vuln_class=vuln_class,
                )
                findings.extend(parsed)
                problems += issues
        report_findings = tuple(findings)
        return PeerAgentReport(
            run_id=self._run_id(workdir),
            findings=report_findings,
            wall_seconds=0.0,
            cost_units=0.0,  # Shannon 不自报成本；以墙钟+外部计量为准
            exit_code=result.exit_code,
        )

    @staticmethod
    def _run_id(workdir: Path) -> str:
        marker = Path(workdir) / "run_id.txt"
        if marker.exists():
            return marker.read_text(encoding="utf-8").strip()
        return ""


def _copy_repo(repo: Path, destination: Path) -> None:
    """Working copy WITHOUT vcs metadata (peer never sees .git)."""
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        repo, destination,
        ignore=shutil.ignore_patterns(".git", ".hg", "__pycache__"),
        dirs_exist_ok=True,
    )
