# P2b AttackChain Implementation Plan（漏洞链构建）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 让 SecOpent 输出"已验证攻击链"：在已确认 findings 之上做图推理，三种假设源（确定性模板匹配 / LLM 提议 / peer 链声称），逐环补证闭环，复合严重度，报告首屏呈现。

**Architecture:** 链是 ConfirmedFinding 之间的有序链接；ChainEngine 是应用层确定性服务，复用 `domain/findings/chain_templates`（P1a③）与 `FindingCorrelation` 的指纹体系。不变式：**LLM/peer 只贡献 HYPOTHESIS，任何一环的确认权只在 oracle**；一环未确认 = 全链不得 CONFIRMED（可 PARTIALLY_VERIFIED）。补证需求生成验证任务投影（接 oracle 队列），即"响应式再规划"的第一真实触发源。

**Tech Stack:** Python 3.12, pytest；无新框架。

**Spec:** `docs/superpowers/specs/2026-08-04-strix-shannon-layered-integration-design.md` §9

**前置：** Plan #1（P0）与 Plan #3 Task 5（chain_templates）完成。M4 的 Asset Graph 若未落地，链内资产关系降级为 asset 字符串相等/前缀匹配（本计划按降级形态实现，Asset Graph 落地后可无损升级）。

---

## 文件结构

| 文件 | 职责 | 动作 |
|------|------|------|
| `src/secopent/domain/findings/attack_chain.py` | AttackChain/ChainLink/状态机/复合严重度 | 新建 |
| `src/secopent/application/chain_engine.py` | ChainEngine：三假设源 + 补证投影 | 新建 |
| `src/secopent/application/ports/chain_proposals.py` | LLM/peer 提议端口 Protocol | 新建 |
| `tests/domain/test_attack_chain.py` | 链模型测试 | 新建 |
| `tests/application/test_chain_engine.py` | 引擎测试（fake 提议源） | 新建 |
| `src/secopent/application/report_renderer.py` | 报告追加攻击链章节 | 修改 |
| `tests/application/test_report_chain_section.py` | 报告章节测试 | 新建 |
| `docs/architecture/attack-chain.md` | 架构文档 | 新建 |
| `README.md` | Reference docs 链接 | 修改 |

---

## Task 1：domain 模型——链、环、状态机、复合严重度

- [ ] **1.1 写失败测试** `tests/domain/test_attack_chain.py`：

```python
# tests/domain/test_attack_chain.py
"""AttackChain domain (spec §9): links, state machine, composite severity."""
from __future__ import annotations

import pytest

from secopent.domain.adapters.contracts import Severity
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.findings.attack_chain import (
    AttackChain,
    ChainLink,
    ChainStatus,
    composite_severity,
)


def _link(finding_id: str = "", pending: bool = False) -> ChainLink:
    if pending:
        return ChainLink(confirmed_finding_id="", pending_verification_key=f"pv-{finding_id or 'x'}")
    return ChainLink(confirmed_finding_id=finding_id or "finding:abc123")


class TestChainLink:
    def test_link_needs_confirmed_or_pending(self) -> None:
        with pytest.raises(DomainValidationError):
            ChainLink(confirmed_finding_id="", pending_verification_key="")

    def test_confirmed_link(self) -> None:
        link = _link("finding:xyz")
        assert link.is_confirmed


class TestAttackChain:
    def test_requires_at_least_two_links(self) -> None:
        with pytest.raises(DomainValidationError):
            AttackChain(
                id="chain-1", template_id="t", hypothesis_source="template",
                links=(_link("finding:a"),),
            )

    def test_initial_status_is_hypothesis(self) -> None:
        chain = AttackChain(
            id="chain-1", template_id="auth-bypass-plus-idor",
            hypothesis_source="template",
            links=(_link("finding:a"), _link("finding:b")),
        )
        assert chain.status is ChainStatus.HYPOTHESIS

    def test_status_transition_confirmed_requires_all_links_confirmed(self) -> None:
        chain = AttackChain(
            id="chain-1", template_id="t", hypothesis_source="template",
            links=(_link("finding:a"), _link(pending=True)),
        )
        assert chain.all_links_confirmed is False
        assert chain.status is ChainStatus.HYPOTHESIS


class TestCompositeSeverity:
    def test_chain_severity_is_max_of_links(self) -> None:
        assert composite_severity(
            (Severity.LOW, Severity.HIGH), asset_critical=False,
        ) is Severity.HIGH

    def test_escalates_one_level_when_reaching_critical_asset(self) -> None:
        assert composite_severity(
            (Severity.MEDIUM, Severity.MEDIUM), asset_critical=True,
        ) is Severity.HIGH

    def test_never_exceeds_critical(self) -> None:
        assert composite_severity(
            (Severity.CRITICAL,), asset_critical=True,
        ) is Severity.CRITICAL
```

- [ ] **1.2 运行确认失败** → 1.3 **实现** `src/secopent/domain/findings/attack_chain.py`：

```python
# src/secopent/domain/findings/attack_chain.py
"""AttackChain: verified attack paths over confirmed findings (spec §9).

State machine: HYPOTHESIS -> PARTIALLY_VERIFIED -> CONFIRMED_CHAIN | REFUTED.
Only oracle-confirmed findings may fill links; pending links carry a
verification key pointing at an oracle-queue task. LLM/peer sources can
create chains but NEVER confirm them (LLM边界 extended to chain level).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..adapters.contracts import Severity
from ..common.errors import DomainValidationError


class ChainStatus(StrEnum):
    HYPOTHESIS = "hypothesis"
    PARTIALLY_VERIFIED = "partially_verified"
    CONFIRMED = "confirmed_chain"
    REFUTED = "refuted"


class ChainHypothesisSource(StrEnum):
    TEMPLATE = "template"        # 确定性模板匹配
    LLM = "llm_proposal"         # LLM 提议（仅提议）
    PEER = "peer_claim"          # peer agent 链声称（untrusted）


@dataclass(frozen=True, slots=True)
class ChainLink:
    """One link: either an oracle-confirmed finding or a pending verification."""

    confirmed_finding_id: str = ""
    pending_verification_key: str = ""
    note: str = ""

    def __post_init__(self) -> None:
        if not self.confirmed_finding_id and not self.pending_verification_key:
            raise DomainValidationError(
                "ChainLink needs confirmed_finding_id or pending_verification_key"
            )

    @property
    def is_confirmed(self) -> bool:
        return bool(self.confirmed_finding_id)


@dataclass(frozen=True, slots=True)
class AttackChain:
    id: str
    template_id: str  # 模板 id 或自由链的描述性 id
    hypothesis_source: str  # ChainHypothesisSource value
    links: tuple[ChainLink, ...]
    status: ChainStatus = ChainStatus.HYPOTHESIS
    severity: Severity = Severity.INFO

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError("AttackChain.id must be non-empty")
        if len(self.links) < 2:
            raise DomainValidationError("AttackChain needs at least 2 links")

    @property
    def all_links_confirmed(self) -> bool:
        return all(link.is_confirmed for link in self.links)


_SEVERITY_ORDER = (
    Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL,
)


def composite_severity(
    link_severities: tuple[Severity, ...], *, asset_critical: bool
) -> Severity:
    """Deterministic composite: max link severity, +1 level if the chain
    terminates on a critical asset (capped at CRITICAL)."""
    if not link_severities:
        return Severity.INFO
    top = max(link_severities, key=_SEVERITY_ORDER.index)
    if asset_critical:
        index = min(_SEVERITY_ORDER.index(top) + 1, len(_SEVERITY_ORDER) - 1)
        return _SEVERITY_ORDER[index]
    return top
```

- [ ] **1.4 运行确认通过** → **1.5 提交**：`feat(domain): AttackChain model, state machine, composite severity (P2b Task 1)`

---

## Task 2：ChainEngine——确定性模板假设源

- [ ] **2.1 写失败测试** `tests/application/test_chain_engine.py`：

```python
# tests/application/test_chain_engine.py
"""ChainEngine: hypothesis generation + verification projection (P2b)."""
from __future__ import annotations

from secopent.application.chain_engine import ChainEngine
from secopent.domain.adapters.contracts import Severity
from secopent.domain.findings.attack_chain import ChainStatus
from secopent.domain.findings.chain_templates import default_chain_templates
from secopent.domain.findings.models import Finding, FindingStatus


def _confirmed(finding_id: str, cwe: str, asset: str,
               severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id=finding_id, fingerprint=f"fp-{finding_id}", title=f"t-{cwe}",
        asset=asset, severity=severity, cwe=(cwe,),
        status=FindingStatus.VALIDATED,
    )


class TestTemplateHypotheses:
    def test_matching_confirmed_findings_yield_confirmed_chain(self) -> None:
        engine = ChainEngine(templates=default_chain_templates())
        findings = (
            _confirmed("finding:a", "CWE-287", "http://app/login"),
            _confirmed("finding:b", "CWE-639", "http://app/api/profile"),
        )
        chains = engine.hypothesize_from_findings(findings)
        matched = [c for c in chains if c.template_id == "auth-bypass-plus-idor"]
        assert len(matched) == 1
        chain = matched[0]
        assert chain.all_links_confirmed
        assert chain.status is ChainStatus.CONFIRMED
        assert chain.severity in (Severity.HIGH, Severity.CRITICAL)

    def test_partial_match_yields_hypothesis_with_pending_links(self) -> None:
        engine = ChainEngine(templates=default_chain_templates())
        findings = (_confirmed("finding:a", "CWE-287", "http://app/login"),)
        chains = engine.hypothesize_from_findings(findings)
        matched = [c for c in chains if c.template_id == "auth-bypass-plus-idor"]
        assert len(matched) == 1
        chain = matched[0]
        assert chain.status is ChainStatus.HYPOTHESIS
        pending = [l for l in chain.links if not l.is_confirmed]
        assert len(pending) == 1  # IDOR 环待补证

    def test_verification_projection_lists_pending_keys(self) -> None:
        engine = ChainEngine(templates=default_chain_templates())
        findings = (_confirmed("finding:a", "CWE-287", "http://app/login"),)
        chains = engine.hypothesize_from_findings(findings)
        tasks = engine.pending_verification_tasks(chains)
        assert len(tasks) == 1
        assert tasks[0].required_cwe == ("CWE-639", "CWE-284")

    def test_only_validated_findings_feed_chains(self) -> None:
        engine = ChainEngine(templates=default_chain_templates())
        draft = Finding(
            id="finding:draft", fingerprint="fp-d", title="t",
            asset="http://app", severity=Severity.HIGH, cwe=("CWE-287",),
            status=FindingStatus.CANDIDATE,  # 未 oracle 确认
        )
        confirmed = _confirmed("finding:b", "CWE-639", "http://app/api")
        chains = engine.hypothesize_from_findings((draft, confirmed))
        assert all(c.template_id != "auth-bypass-plus-idor" or
                   not c.all_links_confirmed for c in chains)
```

- [ ] **2.2 运行确认失败** → 2.3 **实现** `src/secopent/application/chain_engine.py`：

```python
# src/secopent/application/chain_engine.py
"""ChainEngine: attack-chain hypotheses over confirmed findings (spec §9).

Hypothesis source #1 (this task): deterministic template matching. The
matcher extends chain_templates.match_template with link binding: matched
template links bind to concrete confirmed findings; unmatched trailing links
become pending verification tasks (the re-verification loop). Only
FindingStatus.VALIDATED findings participate - oracle is the sole confirmer.
"""
from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass

from ..domain.adapters.contracts import Severity
from ..domain.findings.attack_chain import (
    AttackChain,
    ChainLink,
    ChainStatus,
    composite_severity,
)
from ..domain.findings.chain_templates import AttackChainTemplate
from ..domain.findings.models import Finding, FindingStatus


@dataclass(frozen=True, slots=True)
class PendingVerificationTask:
    """补证投影：链中未确认环 → oracle 队列任务（响应式再规划触发源）."""

    key: str
    chain_id: str
    required_cwe: tuple[str, ...]
    asset_hint: str


class ChainEngine:
    """Generate and track attack-chain hypotheses."""

    def __init__(self, *, templates: tuple[AttackChainTemplate, ...]) -> None:
        self._templates = templates

    def hypothesize_from_findings(
        self, findings: Iterable[Finding]
    ) -> tuple[AttackChain, ...]:
        validated = [
            f for f in findings if f.status is FindingStatus.VALIDATED
        ]
        chains: list[AttackChain] = []
        for template in self._templates:
            chain = self._match_template(template, validated)
            if chain is not None:
                chains.append(chain)
        return tuple(chains)

    def pending_verification_tasks(
        self, chains: Iterable[AttackChain]
    ) -> tuple[PendingVerificationTask, ...]:
        tasks: list[PendingVerificationTask] = []
        for chain in chains:
            tasks.extend(self._tasks_for(chain))
        return tuple(tasks)

    # -- internals ---------------------------------------------------------

    def _match_template(
        self, template: AttackChainTemplate, findings: list[Finding]
    ) -> AttackChain | None:
        links: list[ChainLink] = []
        position = 0
        matched_any = False
        for link_spec in template.links:
            bound: Finding | None = None
            for index in range(position, len(findings)):
                finding = findings[index]
                if not (set(link_spec.cwe_any) & set(finding.cwe)):
                    continue
                if link_spec.asset_pattern and link_spec.asset_pattern not in finding.asset:
                    continue
                bound = finding
                position = index + 1
                break
            if bound is not None:
                matched_any = True
                links.append(ChainLink(confirmed_finding_id=bound.id))
            else:
                links.append(ChainLink(
                    pending_verification_key=f"pv-{uuid.uuid4().hex[:10]}",
                    note=f"requires CWE any of {link_spec.cwe_any}",
                ))
        if not matched_any:
            return None
        chain_id = f"chain-{template.id}-{uuid.uuid4().hex[:8]}"
        all_confirmed = all(link.is_confirmed for link in links)
        # 首环起即部分确认 → PARTIALLY_VERIFIED，否则 HYPOTHESIS
        status = (
            ChainStatus.CONFIRMED if all_confirmed
            else (ChainStatus.PARTIALLY_VERIFIED if links[0].is_confirmed
                  else ChainStatus.HYPOTHESIS)
        )
        severity = composite_severity(
            self._confirmed_severities(links, findings),
            asset_critical=False,  # Asset Graph 落地后接入资产价值
        )
        return AttackChain(
            id=chain_id, template_id=template.id,
            hypothesis_source="template", links=tuple(links),
            status=status, severity=severity,
        )

    @staticmethod
    def _confirmed_severities(
        links: list[ChainLink], findings: list[Finding]
    ) -> tuple[Severity, ...]:
        by_id = {f.id: f for f in findings}
        return tuple(
            by_id[link.confirmed_finding_id].severity
            for link in links if link.is_confirmed and link.confirmed_finding_id in by_id
        )

    def _tasks_for(
        self, chain: AttackChain
    ) -> tuple[PendingVerificationTask, ...]:
        template = next(
            (t for t in self._templates if t.id == chain.template_id), None
        )
        if template is None:
            return ()
        tasks: list[PendingVerificationTask] = []
        for link, spec in zip(chain.links, template.links):
            if not link.is_confirmed:
                tasks.append(PendingVerificationTask(
                    key=link.pending_verification_key,
                    chain_id=chain.id,
                    required_cwe=spec.cwe_any,
                    asset_hint=spec.asset_pattern,
                ))
        return tuple(tasks)
```

- [ ] **2.4 运行确认通过** → **2.5 提交**：`feat(app): ChainEngine template hypotheses + verification projection (P2b Task 2)`

---

## Task 3：LLM 提议端口 + peer 链声称端口（仅提议，fake 测试）

- [ ] **3.1 写失败测试** `tests/application/test_chain_proposals.py`：

```python
# tests/application/test_chain_proposals.py
"""Chain proposal ports: llm/peer sources PROPOSE only (P2b Task 3)."""
from __future__ import annotations

from secopent.application.chain_engine import ChainEngine
from secopent.application.ports.chain_proposals import ChainProposal
from secopent.domain.findings.attack_chain import ChainStatus
from secopent.domain.findings.chain_templates import default_chain_templates

# _confirmed() 复用 test_chain_engine.py 的构造（提取为共享 helper 或复制）


class TestProposalHypotheses:
    def test_proposal_binds_validated_findings_and_pends_missing(self) -> None:
        engine = ChainEngine(templates=default_chain_templates())
        confirmed = _confirmed("finding:a", "CWE-287", "http://app/login")
        proposal = ChainProposal(
            proposer="llm:test-model",
            template_hint="auth-bypass-plus-idor",
            finding_ids=("finding:a", "finding:does-not-exist"),
        )
        chains = engine.hypothesize_from_proposals((proposal,), (confirmed,))
        assert len(chains) == 1
        chain = chains[0]
        assert chain.hypothesis_source == "llm_proposal"
        assert chain.status is not ChainStatus.CONFIRMED
        assert chain.links[0].is_confirmed
        assert not chain.links[1].is_confirmed  # 未确认引用 → pending

    def test_peer_claim_marked_as_peer_source(self) -> None:
        engine = ChainEngine(templates=default_chain_templates())
        confirmed_a = _confirmed("finding:a", "CWE-287", "http://app/login")
        confirmed_b = _confirmed("finding:b", "CWE-639", "http://app/api")
        proposal = ChainProposal(
            proposer="peer:strix",
            template_hint="auth-bypass-plus-idor",
            finding_ids=("finding:a", "finding:b"),
        )
        chains = engine.hypothesize_from_proposals(
            (proposal,), (confirmed_a, confirmed_b)
        )
        assert chains[0].hypothesis_source == "peer_claim"
        assert chains[0].status is ChainStatus.CONFIRMED

    def test_llm_claim_of_confirmation_not_honored(self) -> None:
        # LLM 声称 finding 已确认，但该 finding 仅是 CANDIDATE → 保持 pending
        from secopent.domain.adapters.contracts import Severity
        from secopent.domain.findings.models import Finding, FindingStatus

        candidate = Finding(
            id="finding:cand", fingerprint="fp-c", title="t",
            asset="http://app", severity=Severity.HIGH, cwe=("CWE-639",),
            status=FindingStatus.CANDIDATE,
        )
        confirmed = _confirmed("finding:a", "CWE-287", "http://app/login")
        engine = ChainEngine(templates=default_chain_templates())
        proposal = ChainProposal(
            proposer="llm:m",
            template_hint="auth-bypass-plus-idor",
            finding_ids=("finding:a", "finding:cand"),
        )
        chains = engine.hypothesize_from_proposals((proposal,), (confirmed, candidate))
        assert not chains[0].all_links_confirmed
```
- [ ] **3.2 实现** `src/secopent/application/ports/chain_proposals.py`：

```python
# src/secopent/application/ports/chain_proposals.py
"""Proposal ports for chain hypotheses (spec §9 sources ②③).

Both sources PROPOSE only. A proposed link counts as confirmed iff it
references a Finding whose status is VALIDATED (oracle-confirmed); any
other claim stays pending. Ports are Protocols so tests inject fakes and
the real LLM proposal generator (P2b 后续/M4 LLM 面）与 peer 解析器按接线接入。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ...domain.findings.models import Finding


@dataclass(frozen=True, slots=True)
class ChainProposal:
    proposer: str            # "llm:<model>" 或 "peer:strix"
    template_hint: str       # 模板 id 或自由描述 id
    finding_ids: tuple[str, ...]  # 声称的环顺序（可含未确认引用）


@runtime_checkable
class ChainProposalSource(Protocol):
    def propose(
        self, findings: tuple[Finding, ...]
    ) -> tuple[ChainProposal, ...]: ...
```

并在 `ChainEngine` 增加 `hypothesize_from_proposals`（完整代码）：

```python
    def hypothesize_from_proposals(
        self,
        proposals: Iterable[ChainProposal],
        findings: Iterable[Finding],
    ) -> tuple[AttackChain, ...]:
        """Source ②③: proposals bind ONLY to VALIDATED findings; every other
        referenced id becomes a pending link - claims never confirm."""
        validated_by_id = {
            f.id: f for f in findings if f.status is FindingStatus.VALIDATED
        }
        chains: list[AttackChain] = []
        for proposal in proposals:
            links = tuple(
                ChainLink(confirmed_finding_id=finding_id)
                if finding_id in validated_by_id
                else ChainLink(
                    pending_verification_key=f"pv-{uuid.uuid4().hex[:10]}",
                    note=f"proposed by {proposal.proposer}",
                )
                for finding_id in proposal.finding_ids
            )
            if len(links) < 2:
                continue
            all_confirmed = all(link.is_confirmed for link in links)
            status = (
                ChainStatus.CONFIRMED if all_confirmed
                else (ChainStatus.PARTIALLY_VERIFIED if links and links[0].is_confirmed
                      else ChainStatus.HYPOTHESIS)
            )
            severity = composite_severity(
                tuple(
                    validated_by_id[link.confirmed_finding_id].severity
                    for link in links if link.is_confirmed
                ),
                asset_critical=False,
            )
            source = ("peer_claim" if proposal.proposer.startswith("peer:")
                      else "llm_proposal")
            chains.append(AttackChain(
                id=f"chain-{uuid.uuid4().hex[:12]}",
                template_id=proposal.template_hint,
                hypothesis_source=source,
                links=links, status=status, severity=severity,
            ))
        return tuple(chains)
```

（imports 追加：`from ..application.ports.chain_proposals import ChainProposal` 置于 chain_engine.py 顶部，`Iterable` 已在。）
- [ ] **3.3 运行确认通过** → **3.4 提交**：`feat(app): chain proposal ports for llm/peer sources (P2b Task 3)`

---

## Task 4：报告章节渲染

- [ ] **4.1 写失败测试** `tests/application/test_report_chain_section.py`：CONFIRMED 链渲染含"攻击路径"标题 + 逐环 finding 引用 + 复合严重度；PARTIALLY/HYPOTHESIS 链进"建议优先修复路径"小节并注明未确认环；无链时章节输出"本次评估未发现可验证攻击链"。
- [ ] **4.2 实现**：在 `application/report_renderer.py` 追加 `render_chain_section(chains: Iterable[AttackChain]) -> str`（纯函数，Markdown；若现有 renderer 是模板化结构则按其约定挂载新节）。
- [ ] **4.3 运行确认通过** → **4.4 提交**：`feat(report): attack chain sections (P2b Task 4)`

---

## Task 5：文档 + 质量门

- [ ] **5.1 新建** `docs/architecture/attack-chain.md`：状态机图（文字版）、三假设源、补证闭环与响应式再规划的关系、LLM 边界声明、复合严重度规则。
- [ ] **5.2 修改** `README.md` Reference docs 链接。
- [ ] **5.3 全量质量门**：pytest + ruff + mypy + `git diff --check`。
- [ ] **5.4 提交**：`docs: attack chain architecture + P2b quality gate`

---

## DoD

- [ ] 链状态机：全环确认 → CONFIRMED；首环确认其余 pending → PARTIALLY_VERIFIED；纯假设 → HYPOTHESIS
- [ ] 只有 VALIDATED findings 能成为 confirmed link（CANDIDATE/DRAFT 一律 pending）
- [ ] 补证投影：pending 环产出 PendingVerificationTask（含 required_cwe）
- [ ] LLM/peer 提议端口：声称未确认环不被接受为 confirmed
- [ ] 复合严重度：max + 关键资产升级 + CRITICAL 封顶
- [ ] 报告章节：确认链首屏 / 假设链建议区 / 空链文案
- [ ] 全量测试 + lint + type 绿

## 已知注意

- 资产价值判定（`asset_critical`）暂固定 False；Asset Graph（M4）落地后由图查询注入，不破坏现有测试。
- zip(links, template.links) 仅对模板源链有效；proposal 源的补证任务在 proposal 中自带 CWE 提示（ChainProposal 可扩展 `required_cwe_per_link`，执行时按测试需要补字段并同步更新 Task 3 测试）。
