# P2 Strix Peer Agent Implementation Plan（首个真实 peer agent 接入）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 把 Strix 作为第一个真实 peer agent 接入 P0 契约层：报告解析器（基于 Strix 真实产物 schema）、peer-worker 容器运行档、descriptor 注册、响应式再规划触发、A/B 价值验收脚手架。

**Architecture:** Strix 不能嵌套进加固工具容器（它自身需要 Docker sandbox），因此引入**独立治理档"peer-worker 容器"**：digest 钉死镜像 + 资源限制 + peer 标签 + 交换目录 + Docker socket 挂载（Strix 内部 sandbox 构成第二层隔离）。范围/预算/审计仍由 SecOpent 应用层门禁执行（与工具 adapter 同等待遇）。这是有记录的架构偏离（ADR，见 Task 6）。

**Tech Stack:** Python 3.12, pytest（fixture 驱动解析器测试）, Docker（peer-worker 镜像）, strix-agent（PyPI，版本钉死）。

**Spec:** `docs/superpowers/specs/2026-08-04-strix-shannon-layered-integration-design.md` §8

**前置：** Plan #1（P0）DoD 通过；Linux worker 或本机 Docker Desktop 可用（真实运行），Windows 环境跑 mock/fixture 测试。

---

## 文件结构

| 文件 | 职责 | 动作 |
|------|------|------|
| `src/secopent/infrastructure/peer_agents/strix_report.py` | vulnerabilities.json 解析 + CWE 归一 | 新建 |
| `src/secopent/infrastructure/peer_agents/strix_backend.py` | StrixBackend（PeerAgentBackend 实现） | 新建 |
| `src/secopent/infrastructure/peer_agents/worker_images/strix/Dockerfile` | peer-worker 镜像定义 | 新建 |
| `src/secopent/infrastructure/peer_agents/worker_images/strix/entrypoint.py` | 容器内执行脚本 | 新建 |
| `src/secopent/infrastructure/peer_agents/image_catalog.py` | 填 strix 镜像条目 | 修改 |
| `src/secopent/infrastructure/peer_agents/harness.py` | PeerInvocation 增加 env 字段 | 修改 |
| `src/secopent/application/peer_agents.py` | launch 后触发 Plan Version 追加（响应式再规划） | 修改 |
| `src/secopent/infrastructure/composition.py`（或现有组合根） | 注册 strix descriptor | 修改 |
| `tests/fixtures/peer_reports/strix_vulnerabilities.json` | 真实 schema fixture | 新建 |
| `tests/infrastructure/test_strix_report.py` | 解析器测试 | 新建 |
| `tests/infrastructure/test_strix_backend.py` | backend 构建/解析测试 | 新建 |
| `tests/application/test_peer_reactive_replan.py` | 响应式再规划测试 | 新建 |
| `tests/e2e_real/test_peer_strix_ab.py` | A/B 真实验收（条件跳过） | 新建 |
| `docs/architecture/peer-agents.md` | 更新：peer-worker 档 + Strix 接入 | 修改 |
| `sepcs/2026-XX-adr-peer-worker-profile.md` | ADR：peer-worker 容器档偏离 | 新建 |

---

## Task 1：Strix 报告解析器（fixture 驱动）

**Strix 产物 schema（源自 strix/tools/reporting/tool.py + report/sarif.py 实测）**：`strix_runs/<run>/vulnerabilities.json` 为列表，每条含 `title/description/impact/target/severity/cwe（变体："CWE-306"|"cwe: 306"|"306"）/cve/cvss_breakdown/poc_description/poc_script_code/remediation_steps/evidence/agent_name`；另有 `run.json`（运行记录）与 SARIF。

- [ ] **1.1 创建 fixture** `tests/fixtures/peer_reports/strix_vulnerabilities.json`（按上述 schema 手写 3 条：一条 CWE-89 high、一条 cwe 变体 "cwe: 918"、一条无 cwe 的 info 级；字段值用明显靶场风格如 `http://host.docker.internal:3000/rest/...`）。
- [ ] **1.2 写失败测试** `tests/infrastructure/test_strix_report.py`：

```python
# tests/infrastructure/test_strix_report.py
"""Strix vulnerabilities.json parser (P2 Task 1) - fixture-driven."""
from __future__ import annotations

from pathlib import Path

import pytest

from secopent.infrastructure.peer_agents.strix_report import (
    StrixReportParseError,
    normalize_cwe,
    parse_vulnerabilities_json,
)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "peer_reports" / "strix_vulnerabilities.json"


class TestNormalizeCwe:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("CWE-89", "CWE-89"),
            ("cwe: 918", "CWE-918"),
            ("306", "CWE-306"),
            ("", ""),
        ],
    )
    def test_variants(self, raw: str, expected: str) -> None:
        assert normalize_cwe(raw) == expected


class TestParser:
    def test_parses_fixture_into_findings(self) -> None:
        findings = parse_vulnerabilities_json(
            FIXTURE.read_text(encoding="utf-8"), run_id="run-x", agent="strix",
        )
        assert len(findings) == 3
        first = findings[0]
        assert first.run_id == "run-x"
        assert first.agent_name == "strix"
        assert first.asset.startswith("http://")
        assert "CWE-89" in first.cwe
        assert first.severity_hint == "high"
        assert first.payload_summary  # poc_description 摘要

    def test_missing_target_rejected_as_parse_error_entry(self) -> None:
        # 无 target 的条目丢弃并计入 parse 问题，不抛掉整个报告
        findings, problems = parse_vulnerabilities_json(
            '[{"title": "no target", "severity": "high"}]',
            run_id="r", agent="strix", with_problems=True,
        )
        assert findings == ()
        assert problems == 1

    def test_corrupt_json_raises(self) -> None:
        with pytest.raises(StrixReportParseError):
            parse_vulnerabilities_json("{not json", run_id="r", agent="strix")
```

> 说明：`parse_vulnerabilities_json` 双形态——默认返回 tuple；`with_problems=True` 返回 `(tuple, problems_count)`（实现上用 overload 或两个函数，执行时择一并保持测试一致）。

- [ ] **1.3 运行确认失败** → 1.4 **实现** `src/secopent/infrastructure/peer_agents/strix_report.py`：

```python
# src/secopent/infrastructure/peer_agents/strix_report.py
"""Parse Strix run artifacts into PeerAgentFindings (P2).

Source schema verified against usestrix/strix v1.4.x
(strix/tools/reporting/tool.py record fields, strix/report/sarif.py CWE
normalization notes). Parser is permissive on optional fields, strict on
JSON validity; entries without a usable target are dropped and counted.
"""
from __future__ import annotations

import json
from typing import Any

from ...domain.common.errors import DomainError
from ...domain.peer_agents.models import PeerAgentFinding

# poc_description 摘要长度上限（Observation.raw 不做全文搬运）。
_SUMMARY_MAX = 500


class StrixReportParseError(DomainError):
    """The Strix report artifact is not parseable JSON / not a list."""


def normalize_cwe(raw: str) -> str:
    """Normalize Strix CWE variants ('CWE-306' / 'cwe: 306' / '306')."""
    digits = "".join(ch for ch in str(raw) if ch.isdigit())
    if not digits:
        return ""
    return f"CWE-{int(digits)}"


def _entry_to_finding(
    entry: dict[str, Any], run_id: str, agent: str, index: int
) -> PeerAgentFinding | None:
    target = str(entry.get("target") or "").strip()
    title = str(entry.get("title") or "").strip()
    if not target or not title:
        return None
    cwe_raw = str(entry.get("cwe") or "")
    cwe_norm = normalize_cwe(cwe_raw)
    poc = str(entry.get("poc_description") or "").strip()
    return PeerAgentFinding(
        id=f"strix-{run_id}-{index}",
        run_id=run_id,
        agent_name=agent,
        title=title,
        asset=target,
        severity_hint=str(entry.get("severity") or "info"),
        cwe=(cwe_norm,) if cwe_norm else (),
        cve=(str(entry["cve"]),) if entry.get("cve") else (),
        payload_summary=poc[:_SUMMARY_MAX],
        raw_ref="",  # CAS 引用由 backend 在收集产物时回填
    )


def parse_vulnerabilities_json(
    content: str,
    *,
    run_id: str,
    agent: str,
    with_problems: bool = False,
):
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise StrixReportParseError(f"invalid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise StrixReportParseError("vulnerabilities.json must be a list")
    findings: list[PeerAgentFinding] = []
    problems = 0
    for index, entry in enumerate(data):
        if not isinstance(entry, dict):
            problems += 1
            continue
        finding = _entry_to_finding(entry, run_id, agent, index)
        if finding is None:
            problems += 1
            continue
        findings.append(finding)
    if with_problems:
        return tuple(findings), problems
    return tuple(findings)
```

- [ ] **1.5 运行确认通过** → **1.6 提交**：`feat(peer): strix vulnerabilities.json parser + CWE normalize (P2 Task 1)`

---

## Task 2：PeerInvocation 增加 env + StrixBackend

- [ ] **2.1 修改** `harness.py::PeerInvocation` 追加字段 `env: Mapping[str, str] = {}`（frozen dataclass 加默认值字段，保持既构造调用兼容）；`execute()` 将 `env` 透传给 executor.run（见 2.2 执行器扩展）。同步 `base.py::ContainerExecutor` Protocol 与 `subprocess_executor.py::run/_build_args` 增加 `env: Mapping[str, str] = {}`：`_build_args` 中现有 `--env HOME=/tmp` 之后追加 `for key, value in env.items(): args += ["--env", f"{key}={value}"]`。补回归测试：既有 subprocess_executor 测试全绿 + 新测试断言 env 注入与 HOME 共存。
- [ ] **2.2 写失败测试** `tests/infrastructure/test_strix_backend.py`：

```python
# tests/infrastructure/test_strix_backend.py
"""StrixBackend: invocation building + report collection (P2 Task 2)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from secopent.domain.peer_agents.models import (
    PeerAgentBudget, PeerAgentDescriptor, PeerAgentRun, PeerAgentTrustLevel,
)
from secopent.infrastructure.adapters.base import ContainerResult
from secopent.infrastructure.peer_agents.strix_backend import StrixBackend


def _descriptor() -> PeerAgentDescriptor:
    return PeerAgentDescriptor(
        name="strix", version="1.4.1", license="Apache-2.0",
        trust_level=PeerAgentTrustLevel.ADOPTED_EXTERNAL,
        capabilities=("web", "api"), cost_class="llm_tokens",
        default_budget=PeerAgentBudget(max_wall_seconds=1800, max_cost_units=100),
        image_digest="secopent/peer-worker-strix@sha256:" + "b" * 64,
    )


def _run() -> PeerAgentRun:
    return PeerAgentRun(
        id="peer-run-42", agent_name="strix", agent_version="1.4.1",
        assessment_id="asmt-1",
        targets=("http://host.docker.internal:3000",),
        budget=PeerAgentBudget(max_wall_seconds=1800, max_cost_units=100),
        permit_id="p-1",
    )


class TestBuildInvocation:
    def test_invocation_carries_exchange_mount_and_env(self, tmp_path) -> None:
        backend = StrixBackend(
            llm_provider="openai/gpt-x",
            secret_lookup={"LLM_API_KEY": "sk-test"},
        )
        invocation = backend.build_invocation(_run(), _descriptor(), tmp_path)
        assert invocation.image_digest == _descriptor().image_digest
        assert "/exchange" in invocation.mounts.values() or any(
            "exchange" in v for v in invocation.mounts.values()
        )
        assert invocation.env["STRIX_LLM"] == "openai/gpt-x"
        assert invocation.env["LLM_API_KEY"] == "sk-test"
        # 范围注入在 command（input.json 由 entrypoint 读取，targets 不外泄到 argv 亦可）
        input_file = tmp_path / "input.json"
        assert input_file.exists()
        payload = json.loads(input_file.read_text(encoding="utf-8"))
        assert payload["targets"] == ["http://host.docker.internal:3000"]
        assert payload["run_id"] == "peer-run-42"

    def test_missing_llm_secret_raises_keyerror(self, tmp_path) -> None:
        backend = StrixBackend(llm_provider="openai/gpt-x", secret_lookup={})
        with pytest.raises(KeyError):
            backend.build_invocation(_run(), _descriptor(), tmp_path)


class TestParseReport:
    def test_parses_findings_from_exchange_out(self, tmp_path) -> None:
        out = tmp_path / "out"
        out.mkdir()
        fixture = (
            Path(__file__).resolve().parents[1]
            / "fixtures" / "peer_reports" / "strix_vulnerabilities.json"
        )
        (out / "vulnerabilities.json").write_text(
            fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )
        (out / "run.json").write_text('{"llm_usage": {"total_cost_usd": 1.25}}', encoding="utf-8")
        backend = StrixBackend(llm_provider="x", secret_lookup={"LLM_API_KEY": "k"})
        result = ContainerResult(stdout="", stderr="", exit_code=0, artifacts_dir=out)
        report = backend.parse_report(result, tmp_path)
        assert report.exit_code == 0
        assert len(report.findings) == 3
        assert report.cost_units == pytest.approx(1.25)

    def test_missing_report_yields_empty_findings_not_crash(self, tmp_path) -> None:
        (tmp_path / "out").mkdir()
        backend = StrixBackend(llm_provider="x", secret_lookup={"LLM_API_KEY": "k"})
        result = ContainerResult(stdout="", stderr="boom", exit_code=1, artifacts_dir=tmp_path / "out")
        report = backend.parse_report(result, tmp_path)
        assert report.findings == ()
        assert report.exit_code == 1
```

- [ ] **2.3 运行确认失败** → 2.4 **实现** `src/secopent/infrastructure/peer_agents/strix_backend.py`：

```python
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
from pathlib import Path
from typing import Mapping

from ...domain.peer_agents.models import (
    PeerAgentDescriptor,
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
        api_key = self._secrets[self._llm_key_name]  # KeyError 上抛 = 配置错误
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
        findings: tuple = ()
        if vuln_path.exists():
            findings = parse_vulnerabilities_json(
                vuln_path.read_text(encoding="utf-8"),
                run_id=self._run_id_from_input(workdir),
                agent="strix",
            )
        cost = self._cost_from_run_json(out_dir / "run.json")
        return PeerAgentReport(
            run_id=self._run_id_from_input(workdir),
            findings=findings,
            wall_seconds=0.0,  # harness 以实测墙钟兜底（max 语义）
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
        return float(value) if isinstance(value, (int, float)) else 0.0
```

- [ ] **2.5 运行确认通过** → **2.6 提交**：`feat(peer): strix backend invocation+report parsing (P2 Task 2)`

---

## Task 3：peer-worker 镜像（Dockerfile + entrypoint）

- [ ] **3.1 创建** `src/secopent/infrastructure/peer_agents/worker_images/strix/Dockerfile`：

```dockerfile
# secopent peer-worker: strix (version-pinned). Digest is recorded in
# PEER_IMAGE_CATALOG after build/pull (supply-chain policy §8.1).
FROM python:3.12-slim

RUN pip install --no-cache-dir strix-agent==1.4.1

COPY entrypoint.py /opt/entrypoint.py

# non-root where possible; strix's own sandbox runs nested containers via the
# mounted docker socket (peer-worker profile, see ADR peer-worker-profile).
USER 65532:65532
WORKDIR /exchange

ENTRYPOINT ["python", "/opt/entrypoint.py"]
```

- [ ] **3.2 创建** `entrypoint.py`（容器内）：

```python
# peer-worker entrypoint: read /exchange/input.json, run strix, leave
# artifacts under /exchange/out/. Exit code mirrors strix's.
import json
import os
import subprocess
import sys
from pathlib import Path

EXCHANGE = Path("/exchange")
OUT = EXCHANGE / "out"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    payload = json.loads((EXCHANGE / "input.json").read_text(encoding="utf-8"))
    targets = payload["targets"]
    instruction = payload.get("instruction", "")
    cmd = ["strix"]
    for target in targets:
        cmd += ["--target", target]
    if instruction:
        cmd += ["--instruction", instruction]
    cmd += ["--run-name", str(payload["run_id"])]
    proc = subprocess.run(cmd, cwd=str(EXCHANGE), check=False)
    # strix writes strix_runs/<run-name>/; lift the key artifacts to out/
    run_dir = EXCHANGE / "strix_runs" / str(payload["run_id"])
    for name in ("vulnerabilities.json", "run.json"):
        src = run_dir / name
        if src.exists():
            (OUT / name).write_bytes(src.read_bytes())
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **3.3 单测 entrypoint 逻辑**（`tests/infrastructure/test_peer_worker_entrypoint.py`）：把 entrypoint.py 当模块加载（importlib from path），mock subprocess.run + 伪造 strix_runs 目录，断言产物搬运与退出码透传。
- [ ] **3.4 填** `PEER_IMAGE_CATALOG["strix"]`（tag/digest 字段：本地构建后 `docker images --digests` 记录；CI 未构建前 digest 留空 + 注释说明钉死流程，同 IMAGE_CATALOG 惯例）。
- [ ] **3.5 提交**：`feat(peer): strix peer-worker image + entrypoint (P2 Task 3)`

---

## Task 4：descriptor 注册 + 组合根接线

- [ ] **4.1 写失败测试** `tests/infrastructure/test_peer_composition.py`：断言组合根工厂（`create_production_*` 同层新函数 `create_peer_agent_service(...)`）返回的 service registry 含 `strix` descriptor（version 来自 PEER_IMAGE_CATALOG/strix-agent 钉死版本）、harness backends 含 `strix`。
- [ ] **4.2 实现** `src/secopent/infrastructure/peer_agents/composition.py`：

```python
# src/secopent/infrastructure/peer_agents/composition.py
"""Composition wiring for peer agents (P2)."""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ...application.peer_agents import PeerAgentService
from ...application.audit import AuditService
from ...application.ports.repositories import PeerRunRepository
from ...domain.peer_agents.models import (
    PeerAgentBudget,
    PeerAgentDescriptor,
    PeerAgentTrustLevel,
)
from ...domain.peer_agents.registry import PeerAgentRegistry
from ..adapters.subprocess_executor import SubprocessContainerExecutor
from .harness import ContainerPeerAgentHarness
from .image_catalog import PEER_IMAGE_CATALOG
from .strix_backend import StrixBackend

STRIX_VERSION = "1.4.1"  # 与 worker Dockerfile 钉死版本一致
STRIX_DEFAULT_BUDGET = PeerAgentBudget(
    max_wall_seconds=60 * 60,      # 1h 墙钟
    max_cost_units=200.0,          # USD 成本类上限（self-reported）
)


def strix_descriptor() -> PeerAgentDescriptor:
    image = PEER_IMAGE_CATALOG.get("strix")
    digest = f"{image.name}@{image.digest}" if image and image.digest else ""
    return PeerAgentDescriptor(
        name="strix",
        version=STRIX_VERSION,
        license="Apache-2.0",
        trust_level=PeerAgentTrustLevel.ADOPTED_EXTERNAL,
        capabilities=("web", "api"),
        cost_class="llm_tokens",
        default_budget=STRIX_DEFAULT_BUDGET,
        image_digest=digest,
    )


def create_peer_agent_service(
    *,
    audit: AuditService,
    runs: PeerRunRepository,
    llm_provider: str,
    secret_lookup: Mapping[str, str],
    workdir_root: Path,
) -> PeerAgentService:
    registry = PeerAgentRegistry()
    registry.register(strix_descriptor())
    harness = ContainerPeerAgentHarness(
        executor=SubprocessContainerExecutor(default_timeout=STRIX_DEFAULT_BUDGET.max_wall_seconds),
        backends={
            "strix": StrixBackend(
                llm_provider=llm_provider, secret_lookup=secret_lookup,
            ),
        },
        workdir_root=workdir_root,
    )
    return PeerAgentService(
        registry=registry, harness=harness, audit=audit, runs=runs,
    )
```

- [ ] **4.3 运行确认通过** → **4.4 提交**：`feat(peer): composition wiring with pinned strix descriptor (P2 Task 4)`

---

## Task 5：响应式再规划触发（发现 → Plan Version 追加）

- [ ] **5.1 写失败测试** `tests/application/test_peer_reactive_replan.py`：

```python
# tests/application/test_peer_reactive_replan.py
"""Reactive re-planning: peer discoveries propose plan additions (spec D4①).

Peer findings that reference assets NOT yet in the Assessment's plan, or
confirmed-chain needs (P2b), generate a PlanVersionProposal - NEVER an
automatic plan change: proposals queue for human approval (M4 DoD:
'Agent 追加动作生成新 Plan Version').
"""
from __future__ import annotations

from secopent.application.peer_agents import PeerRunOutcome
from secopent.application.peer_replan import (
    PlanVersionProposal,
    propose_replan_from_outcome,
)
from secopent.domain.peer_agents.models import (
    PeerAgentBudget, PeerAgentRun, PeerRunStatus,
)
# observations 构造复用 P0 测试 helper（peer:strix 来源的 Observation）


class TestReplanProposal:
    def test_new_asset_triggers_proposal(self) -> None:
        outcome = _outcome_with_assets(
            planned=("http://host.docker.internal:3000",),
            observed=("http://host.docker.internal:3000",
                      "http://internal-api.docker:8080"),
        )
        proposals = propose_replan_from_outcome(outcome, planned_assets=outcome.run.targets)
        assert len(proposals) == 1
        proposal = proposals[0]
        assert isinstance(proposal, PlanVersionProposal)
        assert proposal.reason == "peer_discovered_asset"
        assert "http://internal-api.docker:8080" in proposal.subjects
        assert proposal.approved is False  # 人审前不得生效

    def test_no_new_asset_no_proposal(self) -> None:
        outcome = _outcome_with_assets(
            planned=("http://host.docker.internal:3000",),
            observed=("http://host.docker.internal:3000",),
        )
        assert propose_replan_from_outcome(outcome, planned_assets=outcome.run.targets) == ()
```

- [ ] **5.2 运行确认失败** → 5.3 **实现** `src/secopent/application/peer_replan.py`（`PlanVersionProposal` frozen 模型：run_id/reason/subjects/approved=False/proposed_at；`propose_replan_from_outcome` 从 outcome.observations 的 asset_identity 集合中减去 planned 目标，剩余资产生成提案）。提案持久化复用 AssessmentRepository 的 approval 流（本任务只产出提案对象 + 审计事件；审批接线沿用既有 Approval 模型）。
- [ ] **5.4 运行确认通过** → **5.5 提交**：`feat(app): reactive re-planning proposals from peer discoveries (P2 Task 5)`

---

## Task 6：ADR——peer-worker 容器档偏离

- [ ] **6.1 新建** `sepcs/2026-XX-adr-peer-worker-container-profile.md`：
  - 背景：Strix 需 Docker sandbox，不能进加固工具容器（cap-drop ALL + 只读根与 docker socket 需求冲突）
  - 决策：新增"peer-worker"容器档——digest 钉死、资源限制、peer_run 标签、交换目录、**Docker socket 挂载**；第二层隔离由 Strix 自身 sandbox 提供
  - 补偿控制：应用层 scope 门禁不变、instruction 范围注入、墙钟/成本熔断、Emergency Stop 标签覆盖、peer-worker 镜像签名+钉死、网络 egress 限制列为 M5 nftables 范围（同工具容器路线图）
  - 被否选项：① Strix 直接跑宿主（更差隔离）② 注册 Strix 自定义 local backend 免 Docker（agent shell 直接落宿主，风险最高）③ Docker-in-Docker（性能与存储驱动问题）
- [ ] **6.2 提交**：`docs: ADR peer-worker container profile (P2 Task 6)`

---

## Task 7：A/B 验收脚手架 + 文档 + 质量门

- [ ] **7.1 创建** `tests/e2e_real/test_peer_strix_ab.py`：

```python
# tests/e2e_real/test_peer_strix_ab.py
"""A/B value gate: deterministic adapters vs +Strix on live ranges.

SKIP CONDITIONS (auto): Docker unavailable, strix image not pinned, or no
LLM key in secret store/env. This is the spec §8 value gate - results
(recorded to the run report, not asserted hard) decide P3's observation gate.
"""
from __future__ import annotations

import os
import shutil

import pytest

pytestmark = pytest.mark.integration

_SKIP_REASON = None
if shutil.which("docker") is None:
    _SKIP_REASON = "docker unavailable"
elif not os.environ.get("SECOPENT_PEER_LLM_KEY") and not os.environ.get("LLM_API_KEY"):
    _SKIP_REASON = "no LLM key for peer agent A/B"

pytestmark = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")


@pytest.mark.peer_real
def test_strix_ab_on_juice_shop(record_property) -> None:
    """Baseline adapters vs adapters+strix peer on live Juice Shop.

    Outputs go to test-results/strix_ab.json for the P3 observation gate;
    assertions only guard process integrity, not value numbers.
    """
    import datetime
    import json
    from pathlib import Path

    from secopent.application.ports.peer_runs import InMemoryPeerRunRepository
    from secopent.infrastructure.peer_agents.composition import (
        create_peer_agent_service,
    )
    from tests.e2e_real.conftest import TARGETS  # juice_shop URL 常量

    juice = TARGETS["juice_shop"]

    # --- 基线：现有真扫流程（复用本文件四域测试的 runner 构造）---
    from secopent.infrastructure.adapters.base import create_production_runner
    from tests.e2e_real.conftest import build_scope_snapshot  # 若 conftest 无此 helper，
    # 则按 tests/domain/test_scope.py::_snapshot 构造包含 juice 目标的快照

    runner = create_production_runner()
    baseline_observations = runner.run_web_baseline(juice)  # conftest 提供的基线入口；
    # 若不存在，则以 nuclei+httpx 两个 AdapterInput 显式构造（与 test_four_domain 同款）

    # --- 实验组：基线 + strix peer ---
    service = create_peer_agent_service(
        audit=_make_audit_service(),           # 内存 AuditRepository（同 P0 测试 fake）
        runs=InMemoryPeerRunRepository(),
        llm_provider=os.environ.get("SECOPENT_PEER_LLM", "openai/gpt-4o-mini"),
        secret_lookup={"LLM_API_KEY": os.environ.get(
            "SECOPENT_PEER_LLM_KEY", os.environ.get("LLM_API_KEY", ""))},
        workdir_root=Path("test-results") / "peer_work",
    )
    outcome = service.launch(
        assessment_id="ab-juice", agent_name="strix", targets=(juice,),
        scope=build_scope_snapshot(juice), catalog=_ab_catalog(),
        asset_type=_web_app_asset_type(), actor="ab-test", permit_id="permit-ab",
    )

    total_observations = list(baseline_observations) + list(outcome.observations)
    report = {
        "date": datetime.date.today().isoformat(),
        "baseline_observation_count": len(baseline_observations),
        "peer_observation_count": len(outcome.observations),
        "peer_rejected": [
            {"reason": r.reason.value, "title": r.finding.title}
            for r in outcome.rejected
        ],
        "peer_run_status": outcome.run.status.value,
    }
    out_path = Path("test-results") / "strix_ab.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    record_property("strix_ab_report", str(out_path))
    assert out_path.exists()
```

（`_make_audit_service` / `_ab_catalog` / `_web_app_asset_type` 三个 helper 与 P0 应用测试同款构造；`create_production_runner` 的基线入口以 `tests/e2e_real/conftest.py` 现状为准，缺什么补什么，不改既有测试语义。）

- [ ] **7.2 更新** `docs/architecture/peer-agents.md`：peer-worker 档、Strix 接入图、secret 路径、A/B 验收说明。
- [ ] **7.3 全量质量门**：`py -3.12 -m pytest -q`（integration 无 Docker 自动跳过）+ `ruff` + `mypy` + `git diff --check`。
- [ ] **7.4 提交**：`test(peer): strix A/B value gate scaffold + docs (P2 Task 7)`

---

## DoD

- [ ] vulnerabilities.json 解析器对真实 schema fixture 全绿（含 CWE 变体、脏条目计数、坏 JSON 抛错）
- [ ] StrixBackend：input.json 只含 run_id/targets/instruction；LLM key 仅走 env；缺 secret 抛 KeyError
- [ ] peer-worker entrypoint 产物搬运 + 退出码透传单测绿
- [ ] descriptor 版本钉死（1.4.1）+ 预算默认（1h / $200 类）
- [ ] 响应式再规划：新资产 → 未批准提案（不自动改计划）；无新资产 → 无提案
- [ ] ADR 记录 peer-worker 档偏离与补偿控制
- [ ] A/B 脚手架在无 Docker/无 key 环境自动跳过，不阻塞 CI
- [ ] 全量测试 + lint + type 绿

## 已知注意

- 真实 A/B 跑需要 Linux + Docker + LLM key + 拉取 strix-agent 依赖的镜像（国内网络走既有镜像源策略）。环境不满足时本计划所有单元/契约测试仍可全绿，真实跑结果以落盘 JSON 交验收人复核。
- `strix-agent==1.4.1` 为撰写时最新版；执行日若有新版，升级须同步改 Dockerfile + composition 常量 + ADR（不允许漂移）。
- entrypoint 的 USER 65532 与 docker socket 权限可能冲突（socket 通常 root:docker）；若权限拒绝，worker Dockerfile 改回 root 并在 ADR 中记录该妥协（peer-worker 档本已偏离加固基线）。
