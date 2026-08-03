# P3 Shannon Peer Agent Implementation Plan（AGPL 进程隔离 + 观察门）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 把 Shannon 作为第二个 peer agent 接入（白盒场景补位）：deliverables 解析器、repo 工作副本隔离、AGPL 合规清单、观察门评估。全程进程/容器隔离，零代码链接。

**Architecture:** Shannon 以官方容器镜像（digest 钉死）独立运行，交互面仅两个：CLI/env 参数进、`.shannon/deliverables/` 目录出。目标 repo 以**一次性工作副本**挂载（原 repo 对 peer 不可见不可写），跑完解析 deliverables markdown → PeerAgentFinding。AGPL-3.0 合规：不导入/不复制/不链接其代码，镜像独立进程运行，归属声明入 ADR checklist。

**Tech Stack:** Python 3.12, pytest（fixture 驱动）, Docker。

**Spec:** `docs/superpowers/specs/2026-08-04-strix-shannon-layered-integration-design.md` §10

**前置：** Plan #1（P0）DoD；建议 Plan #4（P2）完成后执行（观察门依赖 P2 A/B 基线）。

---

## 文件结构

| 文件 | 职责 | 动作 |
|------|------|------|
| `src/secopent/infrastructure/peer_agents/shannon_backend.py` | ShannonBackend（调用构建 + deliverables 解析） | 新建 |
| `src/secopent/infrastructure/peer_agents/shannon_deliverables.py` | deliverables markdown 解析器 | 新建 |
| `src/secopent/infrastructure/peer_agents/image_catalog.py` | 填 shannon 镜像条目 | 修改 |
| `src/secopent/infrastructure/peer_agents/composition.py` | 可选注册 shannon descriptor | 修改 |
| `tests/fixtures/peer_reports/shannon_injection_deliverable.md` | deliverable fixture | 新建 |
| `tests/fixtures/peer_reports/shannon_exploit_deliverable.md` | exploit deliverable fixture | 新建 |
| `tests/infrastructure/test_shannon_deliverables.py` | 解析器测试 | 新建 |
| `tests/infrastructure/test_shannon_backend.py` | backend 测试（repo 副本隔离断言） | 新建 |
| `sepcs/2026-XX-adr-shannon-agpl-compliance.md` | AGPL 合规 ADR + checklist | 新建 |
| `docs/research/shannon-observation-gate.md` | 观察门评估记录模板 | 新建 |

---

## Task 1：deliverables markdown 解析器（fixture 驱动）

**Shannon deliverables 结构（源自 apps/worker 源码分析）**：`.shannon/deliverables/` 下 `<vuln-class>_analysis_deliverable.md`（分析结论）与 exploit 产物；内容由其 agent 生成，格式不完全受控。解析策略：**宽容解析**——识别"Findings/Vulnerabilities"章节下的条目（标题 + severity + 目标 + CWE 线索），解析失败的段落计入 problems 不崩溃。

- [ ] **1.1 创建 fixtures**（代表性 markdown，两类各一份）：
  - `shannon_injection_deliverable.md`：含 2 个 finding 条目（一个 SQLi HIGH 带 `/api/login` 目标与 CWE-89 标注，一个 LOW 无 CWE 标注）
  - `shannon_exploit_deliverable.md`：含 1 个 exploit 记录（含 PoC curl 命令块 + 目标 URL）
- [ ] **1.2 写失败测试** `tests/infrastructure/test_shannon_deliverables.py`：

```python
# tests/infrastructure/test_shannon_deliverables.py
"""Shannon deliverables parser (P3 Task 1) - permissive markdown parsing."""
from __future__ import annotations

from pathlib import Path

from secopent.infrastructure.peer_agents.shannon_deliverables import (
    parse_deliverable_markdown,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "peer_reports"


class TestAnalysisDeliverable:
    def test_extracts_findings_with_severity_and_target(self) -> None:
        content = (FIXTURES / "shannon_injection_deliverable.md").read_text(encoding="utf-8")
        findings, problems = parse_deliverable_markdown(
            content, run_id="run-s1", agent="shannon", vuln_class="injection",
        )
        assert len(findings) == 2
        assert findings[0].severity_hint.lower() == "high"
        assert findings[0].asset  # 目标 URL/host 非空
        assert "CWE-89" in findings[0].cwe
        assert problems == 0

    def test_finding_without_cwe_kept_with_empty_cwe(self) -> None:
        content = (FIXTURES / "shannon_injection_deliverable.md").read_text(encoding="utf-8")
        findings, _ = parse_deliverable_markdown(
            content, run_id="run-s1", agent="shannon", vuln_class="injection",
        )
        assert any(f.cwe == () for f in findings)


class TestExploitDeliverable:
    def test_exploit_record_maps_target_from_poc(self) -> None:
        content = (FIXTURES / "shannon_exploit_deliverable.md").read_text(encoding="utf-8")
        findings, problems = parse_deliverable_markdown(
            content, run_id="run-s1", agent="shannon", vuln_class="exploit",
        )
        assert len(findings) == 1
        assert findings[0].asset.startswith("http")
        assert findings[0].payload_summary  # PoC 摘要


class TestPermissiveness:
    def test_empty_document_yields_zero_findings_not_error(self) -> None:
        findings, problems = parse_deliverable_markdown(
            "", run_id="r", agent="shannon", vuln_class="injection",
        )
        assert findings == () and problems == 0

    def test_unstructured_text_counts_as_problem(self) -> None:
        findings, problems = parse_deliverable_markdown(
            "just prose without any findings section",
            run_id="r", agent="shannon", vuln_class="injection",
        )
        assert findings == () and problems == 1
```

- [ ] **1.3 运行确认失败** → 1.4 **实现** `src/secopent/infrastructure/peer_agents/shannon_deliverables.py`：

```python
# src/secopent/infrastructure/peer_agents/shannon_deliverables.py
"""Permissive parser for Shannon deliverables markdown (P3).

Shannon's agents author free-form markdown deliverables (no schema
guarantee). Parser contract: heading-delimited blocks carrying a severity
word + a URL become findings; blocks with a severity word but no URL count
as problems; an entirely structureless non-empty document is one problem.
Never raises on content drift - problems are counted, findings survive.
"""
from __future__ import annotations

import re

from ...domain.peer_agents.models import PeerAgentFinding

_SEVERITY_WORDS = ("critical", "high", "medium", "low", "info")
_URL_PATTERN = re.compile(r"https?://[^\s)\]\"'>]+")
_CWE_PATTERN = re.compile(r"CWE-\d{1,4}")
_HEADING_PATTERN = re.compile(r"^#{1,4}\s+", re.MULTILINE)
_CODE_FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
_SUMMARY_MAX = 500


def parse_deliverable_markdown(
    content: str, *, run_id: str, agent: str, vuln_class: str
) -> tuple[tuple[PeerAgentFinding, ...], int]:
    """Return (findings, problem_count) for one deliverable document."""
    text = content.strip()
    if not text:
        return (), 0
    blocks = _split_blocks(text)
    findings: list[PeerAgentFinding] = []
    problems = 0
    for index, block in enumerate(blocks):
        lowered = block.lower()
        severity = next((w for w in _SEVERITY_WORDS if w in lowered), None)
        if severity is None:
            continue  # 非 finding 块（概述/方法说明等）
        urls = _URL_PATTERN.findall(block)
        if not urls:
            problems += 1
            continue
        cwes = tuple(sorted(set(_CWE_PATTERN.findall(block))))
        findings.append(PeerAgentFinding(
            id=f"shannon-{run_id}-{vuln_class}-{index}",
            run_id=run_id,
            agent_name=agent,
            title=_block_title(block),
            asset=urls[0],
            severity_hint=severity,
            cwe=cwes,
            payload_summary=_code_summary(block),
            raw_ref="",
        ))
    if not findings and not problems:
        problems = 1  # 有内容但完全无结构
    return tuple(findings), problems


def _split_blocks(text: str) -> tuple[str, ...]:
    positions = [m.start() for m in _HEADING_PATTERN.finditer(text)]
    if not positions:
        return (text,)
    blocks: list[str] = []
    for start, end in zip(positions, positions[1:] + [len(text)]):
        chunk = text[start:end].strip()
        if chunk:
            blocks.append(chunk)
    return tuple(blocks)


def _block_title(block: str) -> str:
    first_line = block.splitlines()[0]
    return _HEADING_PATTERN.sub("", first_line, count=1).strip() or "untitled"


def _code_summary(block: str) -> str:
    match = _CODE_FENCE.search(block)
    if match:
        return match.group(1).strip()[:_SUMMARY_MAX]
    url_match = _URL_PATTERN.search(block)
    if url_match:
        after = block[url_match.end():].strip().splitlines()
        if after:
            return after[0][:_SUMMARY_MAX]
    return ""
```
- [ ] **1.5 运行确认通过** → **1.6 提交**：`feat(peer): shannon deliverables permissive parser (P3 Task 1)`

---

## Task 2：ShannonBackend（repo 工作副本隔离）

- [ ] **2.1 写失败测试** `tests/infrastructure/test_shannon_backend.py`：

```python
# tests/infrastructure/test_shannon_backend.py
"""ShannonBackend: invocation + repo working-copy isolation (P3 Task 2)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from secopent.domain.peer_agents.models import (
    PeerAgentBudget, PeerAgentDescriptor, PeerAgentRun, PeerAgentTrustLevel,
)
from secopent.infrastructure.adapters.base import ContainerResult
from secopent.infrastructure.peer_agents.shannon_backend import ShannonBackend


def _descriptor() -> PeerAgentDescriptor:
    return PeerAgentDescriptor(
        name="shannon", version="2.0", license="AGPL-3.0",
        trust_level=PeerAgentTrustLevel.ADOPTED_EXTERNAL,
        capabilities=("web", "whitebox"), cost_class="llm_tokens",
        default_budget=PeerAgentBudget(max_wall_seconds=3600, max_cost_units=200),
        image_digest="keygraph/shannon@sha256:" + "c" * 64,
    )


def _run() -> PeerAgentRun:
    return PeerAgentRun(
        id="peer-run-s1", agent_name="shannon", agent_version="2.0",
        assessment_id="asmt-1", targets=("http://host.docker.internal:3000",),
        budget=PeerAgentBudget(max_wall_seconds=3600, max_cost_units=200),
        permit_id="p-1",
    )


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "target-repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("print('hi')", encoding="utf-8")
    (repo / ".git").mkdir()
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main", encoding="utf-8")
    return repo


class TestRepoIsolation:
    def test_build_invocation_copies_repo_not_mounts_original(self, tmp_path) -> None:
        repo = _make_repo(tmp_path)
        backend = ShannonBackend(
            repo_path=repo, llm_key_name="ANTHROPIC_API_KEY",
            secret_lookup={"ANTHROPIC_API_KEY": "sk-ant-test"},
        )
        invocation = backend.build_invocation(_run(), _descriptor(), tmp_path / "work")
        # 挂载的宿主路径必须是工作副本，不得是原 repo
        mounted_sources = list(invocation.mounts.values())
        assert all(str(repo) not in src for src in mounted_sources)
        copy_root = next(
            src for src in mounted_sources if "repo-copy" in src
        )
        assert Path(copy_root, "src", "app.py").exists()  # 副本内容可见

    def test_env_carries_llm_key_and_web_url(self, tmp_path) -> None:
        repo = _make_repo(tmp_path)
        backend = ShannonBackend(
            repo_path=repo, llm_key_name="ANTHROPIC_API_KEY",
            secret_lookup={"ANTHROPIC_API_KEY": "sk-ant-test"},
        )
        invocation = backend.build_invocation(_run(), _descriptor(), tmp_path / "work")
        assert invocation.env["ANTHROPIC_API_KEY"] == "sk-ant-test"
        assert invocation.env["WEB_URL"] == "http://host.docker.internal:3000"


class TestParseReport:
    def test_parses_deliverables_from_copy(self, tmp_path) -> None:
        work = tmp_path / "work"
        copy = work / "repo-copy"
        (copy / ".shannon" / "deliverables").mkdir(parents=True)
        fixture = (
            Path(__file__).resolve().parents[1] / "fixtures" / "peer_reports"
            / "shannon_injection_deliverable.md"
        )
        (copy / ".shannon" / "deliverables" / "injection_analysis_deliverable.md").write_text(
            fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )
        backend = ShannonBackend(
            repo_path=tmp_path, llm_key_name="K", secret_lookup={"K": "v"},
        )
        result = ContainerResult(stdout="", stderr="", exit_code=0, artifacts_dir=copy)
        report = backend.parse_report(result, work)
        assert report.exit_code == 0
        assert len(report.findings) == 2

    def test_no_deliverables_yields_empty_report(self, tmp_path) -> None:
        work = tmp_path / "work"
        (work / "repo-copy").mkdir(parents=True)
        backend = ShannonBackend(
            repo_path=tmp_path, llm_key_name="K", secret_lookup={"K": "v"},
        )
        result = ContainerResult(stdout="", stderr="", exit_code=1, artifacts_dir=work / "repo-copy")
        report = backend.parse_report(result, work)
        assert report.findings == ()
```

- [ ] **2.2 运行确认失败** → 2.3 **实现** `src/secopent/infrastructure/peer_agents/shannon_backend.py`：

```python
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
        findings: list = []
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
```

（`run_id.txt` 由 harness 在 workdir 写入——若 P0 harness 未写该标记，则 backend 从 invocation env 注入 `SHANNON_RUN_ID` 并在此改读；执行时以 P0 harness 现状择一并保持测试一致。）

- [ ] **2.4 运行确认通过** → **2.5 提交**：`feat(peer): shannon backend with repo working-copy isolation (P3 Task 2)`

---

## Task 3：descriptor 可选注册 + 镜像条目

- [ ] **3.1 修改** `image_catalog.py`：`PEER_IMAGE_CATALOG["shannon"] = ImageRef("keygraph/shannon", "<tag>", "")`（digest 首次拉取后钉死，注释说明）。
- [ ] **3.2 修改** `composition.py`：`create_peer_agent_service(..., enable_shannon: bool = False, shannon_repo_path: Path | None = None)`——仅当显式启用且提供 repo 路径时注册 shannon descriptor（license 字段如实写 `AGPL-3.0`，trust level `ADOPTED_EXTERNAL`，capabilities `("web", "whitebox")`）。写对应测试：默认不注册；启用后注册且 descriptor.license == "AGPL-3.0"。
- [ ] **3.3 运行确认通过** → **3.4 提交**：`feat(peer): optional shannon registration behind flag (P3 Task 3)`

---

## Task 4：AGPL 合规 ADR + 观察门记录模板

- [ ] **4.1 新建** `sepcs/2026-XX-adr-shannon-agpl-compliance.md`：
  - 决策：进程隔离调用（D2）；checklist：① 无 import/链接/代码复制（代码审查证据：grep 无 shannon 源码引用）② 交互面仅 CLI/env + deliverables 文件 ③ 镜像独立容器运行，digest 钉死 ④ 归属声明（Keygraph Shannon, AGPL-3.0, keygraph.io）⑤ 分发形态说明：SecOpent 不分发 Shannon 二进制/镜像本体，由部署方自行拉取（拉取行为不构成我们的分发）⑥ 若未来修改 Shannon 本体则必须开源该修改——当前无此行为
  - 被否选项：vendor 其代码（AGPL 传染产品 IP，违反 O4=B）；仅借鉴不运行（损失白盒增量价值）
- [ ] **4.2 新建** `docs/research/shannon-observation-gate.md`：观察门评估模板——输入（P2 A/B 基线数据、crAPI 白盒 Shannon 跑结果）、判据（白盒增量确认发现 > 0？与 Strix 黑盒结果重叠度？单次成本？）、决策栏（保留为白盒备选 / 降级 / 不做）+ 日期签名栏。
- [ ] **4.3 提交**：`docs: shannon AGPL compliance ADR + observation gate template (P3 Task 4)`

---

## Task 5：质量门

- [ ] **5.1 全量**：pytest + ruff + mypy + `git diff --check`；架构边界测试保持绿（shannon 相关模块零 AGPL 代码引用——可加一条 grep 型测试：`tests/security/test_no_agpl_code.py` 断言 `src/` 下无 "Copyright (C) 2025 Keygraph" 字样）。
- [ ] **5.2 提交**：`test(peer): AGPL code-absence guard + P3 quality gate`

---

## DoD

- [ ] deliverables 宽容解析：fixture 两类文件全绿；空文档零发现零崩溃；无结构文本计 problem
- [ ] repo 隔离断言：挂载源是工作副本、原 repo 路径不出现在 mounts、副本不含 .git
- [ ] LLM key 仅 env；缺 secret 抛 KeyError
- [ ] shannon 默认不注册，显式启用才注册（license 如实标注 AGPL-3.0）
- [ ] AGPL 合规 checklist ADR 就位；`test_no_agpl_code` 守卫绿
- [ ] 观察门模板就位（真实跑与决策记录在环境具备时补录）
- [ ] 全量测试 + lint + type 绿

## 已知注意

- Shannon deliverables 格式由上游 agent 生成、无 schema 保证；解析器以"宽容 + 计数"为纲，上游格式漂移时重制 fixture 并回归。
- 真实跑需要 `keygraph/shannon` 镜像（国内拉取走镜像源策略）+ Anthropic key；观察门评估数据在 Linux 环境产出后填入 `shannon-observation-gate.md` 并据此执行 spec §10 的保留/降级/不做决策。
