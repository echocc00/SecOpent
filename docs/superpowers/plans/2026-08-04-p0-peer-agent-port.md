# P0 PeerAgentPort 契约层 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 建立外部自主渗透 agent（Strix/Shannon 类）作为"低信任发现源"接入 SecOpent 的完整契约层：domain 模型 + 注册表 + 确定性归一化 + 应用服务 + 容器运行壳，全部可用 mock 测试，不依赖真实 agent。

**Architecture:** peer agent 与工具 adapter 同级——只产 Observation，裁决权在 oracle。新增 `domain/peer_agents`（模型/注册表/归一化）、`application/peer_agents.py`（PeerAgentService，内联 PeerAgentHarness Protocol）、`infrastructure/peer_agents/`（容器运行壳，复用 SubprocessContainerExecutor 加固）。范围门禁（scope）与目录门禁（catalog）在归一化层确定性执行；预算熔断与 Emergency Stop 复用现有 permit/terminator 体系。

**Tech Stack:** Python 3.12, dataclasses(frozen+slots), Protocol, pytest, ruff, mypy；Docker 仅出现在 infrastructure 层（domain/application 零框架依赖）。

**Spec:** `docs/superpowers/specs/2026-08-04-strix-shannon-layered-integration-design.md` §4-§5

**计划拆分说明（writing-plans scope check）：** 本设计共 6 个子计划，本文件是 **Plan #1（P0，关键路径）**。其余按 SecOpent 路线图纪律（接口稳定后才写详细计划）分别立项：
| 计划 | 触发条件 |
|------|----------|
| Plan #2 P1b 工程内化（checkpoint/preflight/deliverables） | 独立并行，可随时立项 |
| Plan #3 P1a 知识移植（Strix 手册→case DSL/链模板） | 独立并行，可随时立项 |
| Plan #4 P2 Strix peer agent | 本计划 DoD 通过 + Linux worker 可用 |
| Plan #5 P2b AttackChain | Plan #4 验收 + M4 Asset Graph/Correlation 落地 |
| Plan #6 P3 Shannon peer | Plan #4 A/B 价值门通过 |

---

## 文件结构

| 文件 | 职责 | 动作 |
|------|------|------|
| `src/secopent/domain/peer_agents/__init__.py` | 包导出 | 新建 |
| `src/secopent/domain/peer_agents/models.py` | 枚举/错误/预算/Descriptor/Run/Finding/Report 模型 | 新建 |
| `src/secopent/domain/peer_agents/registry.py` | PeerAgentRegistry（确定性登记） | 新建 |
| `src/secopent/domain/peer_agents/normalize.py` | scope/catalog 双门禁 + Finding→Observation | 新建 |
| `src/secopent/application/peer_agents.py` | PeerAgentService + PeerAgentHarness Protocol | 新建 |
| `src/secopent/application/ports/repositories.py` | 追加 PeerRunRepository Protocol | 修改 |
| `src/secopent/infrastructure/peer_agents/__init__.py` | 包 | 新建 |
| `src/secopent/infrastructure/peer_agents/harness.py` | PeerAgentBackend Protocol + ContainerPeerAgentHarness | 新建 |
| `src/secopent/infrastructure/peer_agents/image_catalog.py` | PEER_IMAGE_CATALOG（P0 空骨架） | 新建 |
| `src/secopent/infrastructure/adapters/subprocess_executor.py` | run() 增加 extra_labels 参数 | 修改 |
| `src/secopent/infrastructure/adapters/base.py` | ContainerExecutor Protocol 增加 extra_labels | 修改 |
| `tests/domain/test_peer_agents.py` | 模型/注册表/归一化单测 | 新建 |
| `tests/application/test_peer_agents_service.py` | 服务级单测（fake harness/repo/audit） | 新建 |
| `tests/infrastructure/test_peer_agent_harness.py` | harness 单测（fake executor/backend） | 新建 |
| `tests/integration/test_subprocess_executor.py` | extra_labels 集成断言 | 修改 |
| `docs/architecture/peer-agents.md` | 架构文档 | 新建 |
| `README.md` | Reference docs 追加链接 | 修改 |

---

## Task 1：domain 模型——错误、枚举、预算

- [ ] **1.1 写失败测试** `tests/domain/test_peer_agents.py`：

```python
# tests/domain/test_peer_agents.py
"""Domain tests for peer agent models (integration spec §5 P0)."""
from __future__ import annotations

import pytest

from secopent.domain.common.errors import DomainValidationError
from secopent.domain.peer_agents.models import (
    PeerAgentBudget,
    PeerAgentDescriptor,
    PeerAgentFinding,
    PeerAgentReport,
    PeerAgentRun,
    PeerAgentTrustLevel,
    PeerRunStatus,
    RejectionReason,
)


def _budget() -> PeerAgentBudget:
    return PeerAgentBudget(max_wall_seconds=1800, max_cost_units=100.0)


def _descriptor() -> PeerAgentDescriptor:
    return PeerAgentDescriptor(
        name="strix",
        version="1.4.1",
        license="Apache-2.0",
        trust_level=PeerAgentTrustLevel.ADOPTED_EXTERNAL,
        capabilities=("web", "api"),
        cost_class="llm_tokens",
        default_budget=_budget(),
    )


class TestPeerAgentBudget:
    def test_rejects_negative_wall_seconds(self) -> None:
        with pytest.raises(DomainValidationError):
            PeerAgentBudget(max_wall_seconds=-1, max_cost_units=10.0)

    def test_rejects_negative_cost_units(self) -> None:
        with pytest.raises(DomainValidationError):
            PeerAgentBudget(max_wall_seconds=60, max_cost_units=-0.1)

    def test_accepts_zero_budget(self) -> None:
        budget = PeerAgentBudget(max_wall_seconds=0, max_cost_units=0.0)
        assert budget.max_wall_seconds == 0


class TestPeerAgentDescriptor:
    def test_rejects_empty_name(self) -> None:
        with pytest.raises(DomainValidationError):
            PeerAgentDescriptor(
                name="", version="1.0", license="MIT",
                trust_level=PeerAgentTrustLevel.UNTRUSTED,
                capabilities=(), cost_class="llm_tokens",
                default_budget=_budget(),
            )

    def test_is_frozen(self) -> None:
        descriptor = _descriptor()
        with pytest.raises(AttributeError):
            descriptor.name = "other"  # type: ignore[misc]


class TestPeerAgentRun:
    def test_defaults_to_pending_with_no_timestamps(self) -> None:
        run = PeerAgentRun(
            id="run-1", agent_name="strix", agent_version="1.4.1",
            assessment_id="asmt-1", targets=("http://host.docker.internal:3000",),
            budget=_budget(), permit_id="permit-1",
        )
        assert run.status is PeerRunStatus.PENDING
        assert run.started_at is None and run.finished_at is None

    def test_rejects_empty_targets(self) -> None:
        with pytest.raises(DomainValidationError):
            PeerAgentRun(
                id="run-1", agent_name="strix", agent_version="1.4.1",
                assessment_id="asmt-1", targets=(), budget=_budget(),
                permit_id="permit-1",
            )


class TestPeerAgentFinding:
    def test_requires_provenance_fields(self) -> None:
        with pytest.raises(DomainValidationError):
            PeerAgentFinding(
                id="f-1", run_id="", agent_name="strix", title="SQLi",
                asset="http://t", severity_hint="high",
            )

    def test_defaults_empty_hint_tuples(self) -> None:
        finding = PeerAgentFinding(
            id="f-1", run_id="run-1", agent_name="strix",
            title="SQLi in /login", asset="http://host.docker.internal:3000",
            severity_hint="high",
        )
        assert finding.cwe == () and finding.owasp == () and finding.cve == ()


class TestPeerAgentReport:
    def test_holds_findings_and_costs(self) -> None:
        finding = PeerAgentFinding(
            id="f-1", run_id="run-1", agent_name="strix",
            title="t", asset="http://t", severity_hint="low",
        )
        report = PeerAgentReport(
            run_id="run-1", findings=(finding,),
            wall_seconds=120.5, cost_units=3.2, exit_code=0,
        )
        assert len(report.findings) == 1


class TestEnums:
    def test_trust_levels(self) -> None:
        assert PeerAgentTrustLevel.ADOPTED_EXTERNAL.value == "adopted_external_agent"
        assert PeerAgentTrustLevel.UNTRUSTED.value == "untrusted"

    def test_rejection_reasons_cover_spec_gates(self) -> None:
        # spec §4: 目录外噪音拒收 + scope 越界拒收 + 解析失败
        assert {r.value for r in RejectionReason} == {
            "out_of_scope", "out_of_catalog", "parse_error",
        }
```

- [ ] **1.2 运行确认失败**：`py -3.12 -m pytest tests/domain/test_peer_agents.py -q` → ModuleNotFoundError
- [ ] **1.3 实现** `src/secopent/domain/peer_agents/__init__.py`（空文件加 docstring）与 `models.py`：

```python
# src/secopent/domain/peer_agents/__init__.py
"""Peer agent domain: external autonomous pentest agents as low-trust
discovery sources (integration spec §4)."""
```

```python
# src/secopent/domain/peer_agents/models.py
"""Peer agent domain models (integration spec §4-§5, extends ADR-014/A4).

A peer agent is an external autonomous pentesting agent (Strix, Shannon, ...)
treated as a LOW-TRUST DISCOVERY SOURCE - on par with tool adapters. Its
findings are untrusted Observations-in-waiting: they must pass the scope
re-check, the catalog gate, and oracle N/N verification exactly like tool
output. The LLM边界 holds: peer agents (LLM-driven) never mark anything
Confirmed - only the OracleEngine does.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from ..common.errors import DomainError, DomainValidationError


class PeerAgentNotRegistered(DomainError):
    """The peer agent name is not in the deterministic registry."""


class PeerAgentTrustDenied(DomainError):
    """The peer agent's trust level does not permit execution."""


class PeerRunScopeViolation(DomainError):
    """A launch target (or reported finding asset) is outside the scope."""


class PeerRunBudgetExceeded(DomainError):
    """The run exceeded its wall-clock or cost budget."""


class PeerAgentTrustLevel(StrEnum):
    """Trust levels for external agents (A4 spike precedent)."""

    ADOPTED_EXTERNAL = "adopted_external_agent"
    UNTRUSTED = "untrusted"


class PeerRunStatus(StrEnum):
    """Peer run lifecycle states."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    BUDGET_EXCEEDED = "budget_exceeded"
    STOPPED = "stopped"
    FAILED = "failed"


class RejectionReason(StrEnum):
    """Why a peer finding was rejected at the normalization gate."""

    OUT_OF_SCOPE = "out_of_scope"
    OUT_OF_CATALOG = "out_of_catalog"
    PARSE_ERROR = "parse_error"


@dataclass(frozen=True, slots=True)
class PeerAgentBudget:
    """Per-run budget caps (spec §4: Permit 增加墙钟时长 + LLM 成本类)."""

    max_wall_seconds: int
    max_cost_units: float

    def __post_init__(self) -> None:
        if self.max_wall_seconds < 0:
            raise DomainValidationError(
                "PeerAgentBudget.max_wall_seconds must be >= 0"
            )
        if self.max_cost_units < 0:
            raise DomainValidationError(
                "PeerAgentBudget.max_cost_units must be >= 0"
            )


@dataclass(frozen=True, slots=True)
class PeerAgentDescriptor:
    """Registered identity of an allowed peer agent (curated, deterministic).

    ``image_digest`` is empty until the image is pinned (same policy as
    ``infrastructure/adapters/image_catalog.py``).
    """

    name: str
    version: str
    license: str
    trust_level: PeerAgentTrustLevel
    capabilities: tuple[str, ...]
    cost_class: str
    default_budget: PeerAgentBudget
    image_digest: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            raise DomainValidationError(
                "PeerAgentDescriptor.name must be non-empty"
            )
        if not self.version:
            raise DomainValidationError(
                "PeerAgentDescriptor.version must be non-empty"
            )


@dataclass(frozen=True, slots=True)
class PeerAgentRun:
    """One execution of a peer agent against in-scope targets."""

    id: str
    agent_name: str
    agent_version: str
    assessment_id: str
    targets: tuple[str, ...]
    budget: PeerAgentBudget
    permit_id: str
    status: PeerRunStatus = PeerRunStatus.PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError("PeerAgentRun.id must be non-empty")
        if not self.targets:
            raise DomainValidationError(
                "PeerAgentRun.targets must be non-empty"
            )


@dataclass(frozen=True, slots=True)
class PeerAgentFinding:
    """An UNTRUSTED finding reported by a peer agent (pre-normalization).

    ``severity_hint`` is the agent's free-text severity; normalization maps it
    deterministically onto ``Severity`` (unknown hints downgrade to INFO and
    are recorded in the Observation's ``raw``).
    """

    id: str
    run_id: str
    agent_name: str
    title: str
    asset: str
    severity_hint: str
    cwe: tuple[str, ...] = ()
    cve: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    payload_summary: str = ""
    raw_ref: str = ""  # cas:// URI of the raw report fragment

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError(
                "PeerAgentFinding.id must be non-empty"
            )
        if not self.run_id:
            raise DomainValidationError(
                "PeerAgentFinding.run_id must be non-empty"
            )
        if not self.title:
            raise DomainValidationError(
                "PeerAgentFinding.title must be non-empty"
            )
        if not self.asset:
            raise DomainValidationError(
                "PeerAgentFinding.asset must be non-empty"
            )


@dataclass(frozen=True, slots=True)
class RejectedFinding:
    """A rejected peer finding, retained for audit (never silently dropped)."""

    finding: PeerAgentFinding
    reason: RejectionReason
    detail: str = ""


@dataclass(frozen=True, slots=True)
class PeerAgentReport:
    """Parsed output of one peer run (wall/cost are self-reported by the
    backend; the budget post-check treats them as audit data)."""

    run_id: str
    findings: tuple[PeerAgentFinding, ...]
    wall_seconds: float
    cost_units: float
    exit_code: int
```

- [ ] **1.4 运行确认通过**：`py -3.12 -m pytest tests/domain/test_peer_agents.py -q`
- [ ] **1.5 提交**：`git add src/secopent/domain/peer_agents tests/domain/test_peer_agents.py && git commit -m "feat(domain): peer agent models, errors, trust levels (P0 Task 1)"`

---

## Task 2：PeerAgentRegistry（确定性登记）

- [ ] **2.1 追加失败测试**（同文件新增）：

```python
from secopent.domain.peer_agents.registry import (
    PeerAgentAlreadyRegistered,
    PeerAgentRegistry,
    default_registry,
)


class TestPeerAgentRegistry:
    def test_default_registry_is_empty(self) -> None:
        assert default_registry().all() == ()

    def test_register_then_get(self) -> None:
        registry = PeerAgentRegistry()
        descriptor = _descriptor()
        registry.register(descriptor)
        assert registry.get("strix") == descriptor

    def test_get_unknown_returns_none(self) -> None:
        assert PeerAgentRegistry().get("nope") is None

    def test_duplicate_registration_rejected(self) -> None:
        registry = PeerAgentRegistry()
        registry.register(_descriptor())
        with pytest.raises(PeerAgentAlreadyRegistered):
            registry.register(_descriptor())

    def test_all_returns_registered_descriptors(self) -> None:
        registry = PeerAgentRegistry()
        registry.register(_descriptor())
        assert len(registry.all()) == 1
```

- [ ] **2.2 运行确认失败** → 2.3 **实现** `src/secopent/domain/peer_agents/registry.py`：

```python
# src/secopent/domain/peer_agents/registry.py
"""Deterministic registry of allowed peer agents (curated, no LLM).

Mirrors the VerificationMethodRegistry curation pattern: the registry is
empty by default; entries are added explicitly at the composition root
(P2 registers Strix there). Duplicate name registration is a configuration
error, never a silent override.
"""
from __future__ import annotations

from ..common.errors import DomainError
from .models import PeerAgentDescriptor


class PeerAgentAlreadyRegistered(DomainError):
    """A peer agent with this name is already registered."""


class PeerAgentRegistry:
    """In-memory registry of allowed peer agent descriptors."""

    def __init__(self) -> None:
        self._agents: dict[str, PeerAgentDescriptor] = {}

    def register(self, descriptor: PeerAgentDescriptor) -> None:
        if descriptor.name in self._agents:
            raise PeerAgentAlreadyRegistered(
                f"peer agent already registered: {descriptor.name}"
            )
        self._agents[descriptor.name] = descriptor

    def get(self, name: str) -> PeerAgentDescriptor | None:
        return self._agents.get(name)

    def all(self) -> tuple[PeerAgentDescriptor, ...]:
        return tuple(self._agents.values())


def default_registry() -> PeerAgentRegistry:
    """Empty registry; the composition root registers adopted agents."""
    return PeerAgentRegistry()
```

- [ ] **2.4 运行确认通过** → **2.5 提交**：`feat(domain): peer agent registry with duplicate rejection (P0 Task 2)`

---

## Task 3：归一化——scope/catalog 双门禁 + Finding→Observation

- [ ] **3.1 追加失败测试**：

```python
from secopent.domain.adapters.contracts import CoverageDomain, Severity
from secopent.domain.catalog.models import AssetType, RequiredTestClass, TestCatalog
from secopent.domain.peer_agents.normalize import (
    hits_required_catalog,
    finding_in_scope,
    normalize_finding,
)
from secopent.domain.scope.models import ScopeSnapshot


def _scope() -> ScopeSnapshot:
    """构造方式与 tests/domain/test_scope.py::_snapshot 同款。"""
    from datetime import datetime, UTC

    from secopent.domain.scope.models import ScopeLimits

    return ScopeSnapshot(
        id="snap",
        project_id="proj",
        include=("host.docker.internal", "http://host.docker.internal:3000"),
        exclude=(),
        ports=(3000,),
        limits=ScopeLimits(requests_per_second=5.0, concurrency=3, max_requests=1000),
        approved_by="analyst",
        approved_at=datetime(2026, 1, 1, tzinfo=UTC),
        digest="sha256:" + "0" * 64,
    )


def _catalog() -> TestCatalog:
    from secopent.domain.policy.models import RiskClass

    return TestCatalog(
        version="test-1",
        mappings={
            AssetType.WEB_APP: (
                RequiredTestClass(
                    id="sql-injection",
                    cwe=("CWE-89",),
                    owasp=("WSTG-INPV-05",),
                    risk=RiskClass.ACTIVE,
                ),
            ),
        },
    )


def _finding(**overrides: object) -> PeerAgentFinding:
    base: dict[str, object] = dict(
        id="f-1", run_id="run-1", agent_name="strix",
        title="SQLi in /login",
        asset="http://host.docker.internal:3000",
        severity_hint="high", cwe=("CWE-89",), owasp=("WSTG-INPV-05",),
    )
    base.update(overrides)
    return PeerAgentFinding(**base)  # type: ignore[arg-type]


class TestScopeGate:
    def test_url_asset_in_scope(self) -> None:
        assert finding_in_scope(_finding(), _scope()) is True

    def test_foreign_asset_out_of_scope(self) -> None:
        foreign = _finding(asset="http://evil.example.com")
        assert finding_in_scope(foreign, _scope()) is False

    def test_bare_hostname_checked_as_domain(self) -> None:
        bare = _finding(asset="host.docker.internal")
        assert finding_in_scope(bare, _scope()) is True


class TestCatalogGate:
    def test_finding_with_matching_cwe_hits_catalog(self) -> None:
        assert hits_required_catalog(_finding(), _catalog(), AssetType.WEB_APP) is True

    def test_finding_without_matching_class_misses_catalog(self) -> None:
        off = _finding(cwe=("CWE-79",), owasp=())
        assert hits_required_catalog(off, _catalog(), AssetType.WEB_APP) is False


class TestNormalizeFinding:
    def test_maps_to_observation_with_peer_source(self) -> None:
        run = PeerAgentRun(
            id="run-1", agent_name="strix", agent_version="1.4.1",
            assessment_id="asmt-1",
            targets=("http://host.docker.internal:3000",),
            budget=_budget(), permit_id="permit-1",
        )
        observation = normalize_finding(_finding(), run)
        assert observation.source.name == "peer:strix"
        assert observation.source.version == "1.4.1"
        assert observation.external_id == "f-1"
        assert observation.coverage_domain is CoverageDomain.WEB
        assert observation.confidence == 0.5
        assert observation.raw["peer_run_id"] == "run-1"

    def test_known_severity_hint_maps_to_enum(self) -> None:
        run = PeerAgentRun(
            id="run-1", agent_name="strix", agent_version="1.4.1",
            assessment_id="asmt-1", targets=("http://t",),
            budget=_budget(), permit_id="p",
        )
        observation = normalize_finding(_finding(severity_hint="CRITICAL"), run)
        assert observation.severity is Severity.CRITICAL

    def test_unknown_severity_hint_downgrades_to_info_and_records(self) -> None:
        run = PeerAgentRun(
            id="run-1", agent_name="strix", agent_version="1.4.1",
            assessment_id="asmt-1", targets=("http://t",),
            budget=_budget(), permit_id="p",
        )
        observation = normalize_finding(
            _finding(severity_hint="apocalyptic"), run
        )
        assert observation.severity is Severity.INFO
        assert observation.raw["severity_hint_unmapped"] == "apocalyptic"
```

> ⚠️ 实现前核对：`ScopeSnapshot` / `TestCatalog` / `RequiredTestClass` / `AssetType` 的确切字段以 `src/secopent/domain/scope/models.py`、`src/secopent/domain/catalog/models.py` 现状为准（上面按已知约定书写；若字段名有出入，测试构造同步修正，断言语义不变）。

- [ ] **3.2 运行确认失败** → 3.3 **实现** `src/secopent/domain/peer_agents/normalize.py`：

```python
# src/secopent/domain/peer_agents/normalize.py
"""Deterministic normalization of peer findings (spec §4 归一化层).

Two gates, both deterministic (no LLM):
1. **scope gate** - the finding's asset must be inside the assessment scope;
2. **catalog gate** - the finding's CWE/OWASP must intersect at least one
   required test class for the asset type (same intersection semantics as
   ``domain.catalog.report._class_covered``), otherwise it is off-catalog
   noise and rejected.

Surviving findings become low-confidence Observations attributed to
``peer:<agent>``; only the oracle promotes them downstream.
"""
from __future__ import annotations

from ..adapters.contracts import (
    AdapterSource,
    CoverageDomain,
    Observation,
    Severity,
)
from ..catalog.models import AssetType, TestCatalog
from ..scope.models import ScopeSnapshot
from .models import PeerAgentFinding, PeerAgentRun

# Peer findings are claims, not measurements: neutral confidence; the
# oracle N/N decision is what matters downstream.
_PEER_CONFIDENCE = 0.5

_SEVERITY_BY_HINT = {severity.value: severity for severity in Severity}


def finding_in_scope(finding: PeerAgentFinding, scope: ScopeSnapshot) -> bool:
    """URL assets go through includes_url, bare hosts through includes_domain."""
    asset = finding.asset.strip()
    if asset.startswith(("http://", "https://")):
        return scope.includes_url(asset)
    return scope.includes_domain(asset)


def hits_required_catalog(
    finding: PeerAgentFinding, catalog: TestCatalog, asset_type: AssetType
) -> bool:
    """True iff the finding's CWE/OWASP intersects any required class."""
    finding_cwe = set(finding.cwe)
    finding_owasp = set(finding.owasp)
    for cls in catalog.required_for(asset_type):
        if finding_cwe & set(cls.cwe) or finding_owasp & set(cls.owasp):
            return True
    return False


def _map_severity(hint: str) -> tuple[Severity, bool]:
    severity = _SEVERITY_BY_HINT.get(hint.strip().lower())
    if severity is None:
        return Severity.INFO, False
    return severity, True


def normalize_finding(
    finding: PeerAgentFinding, run: PeerAgentRun
) -> Observation:
    """Convert one in-scope, on-catalog peer finding to an Observation."""
    severity, mapped = _map_severity(finding.severity_hint)
    raw: dict[str, object] = {
        "peer_run_id": run.id,
        "severity_hint": finding.severity_hint,
        "payload_summary": finding.payload_summary,
        "raw_ref": finding.raw_ref,
    }
    if not mapped:
        raw["severity_hint_unmapped"] = finding.severity_hint
    return Observation(
        external_id=finding.id,
        asset_identity=finding.asset,
        source=AdapterSource(
            name=f"peer:{run.agent_name}",
            version=run.agent_version,
            template_version="na",
        ),
        rule_id=finding.id,
        rule_version=run.agent_version,
        # P0 peers target web/API surfaces; P2 may map per descriptor
        # capability once non-web peers are adopted.
        coverage_domain=CoverageDomain.WEB,
        title=finding.title,
        severity=severity,
        confidence=_PEER_CONFIDENCE,
        cwe=finding.cwe,
        cve=finding.cve,
        owasp=finding.owasp,
        raw=raw,
    )
```

- [ ] **3.4 运行确认通过** → **3.5 提交**：`feat(domain): peer finding normalization with scope+catalog gates (P0 Task 3)`

---

## Task 4：PeerRunRepository 端口 + 内存实现

- [ ] **4.1 修改** `src/secopent/application/ports/repositories.py`，追加（imports 区加 `from ...domain.peer_agents.models import PeerAgentRun`）：

```python
class PeerRunRepository(Protocol):
    """Persistence port for peer agent runs (P0 ships the in-memory impl;
    the SQLite table lands with P2 wiring)."""

    def add(self, run: PeerAgentRun) -> None: ...
    def save(self, run: PeerAgentRun) -> None: ...  # upsert (status updates)
    def get(self, run_id: str) -> PeerAgentRun | None: ...
```

- [ ] **4.2 写失败测试** `tests/application/test_peer_agents_service.py` 的 fake（先只测 repo）：

```python
# tests/application/test_peer_agents_service.py
"""Application tests for PeerAgentService (integration spec §5 P0)."""
from __future__ import annotations

from secopent.application.ports.peer_runs import InMemoryPeerRunRepository
# ...（Task 5/6 会继续在此文件追加）


class TestInMemoryPeerRunRepository:
    def test_add_get_save_roundtrip(self) -> None:
        from secopent.domain.peer_agents.models import (
            PeerAgentBudget, PeerAgentRun, PeerRunStatus,
        )
        repo = InMemoryPeerRunRepository()
        run = PeerAgentRun(
            id="run-1", agent_name="strix", agent_version="1.4.1",
            assessment_id="asmt-1", targets=("http://t",),
            budget=PeerAgentBudget(max_wall_seconds=60, max_cost_units=1.0),
            permit_id="p-1",
        )
        repo.add(run)
        assert repo.get("run-1") == run
        updated = PeerAgentRun(
            id=run.id, agent_name=run.agent_name,
            agent_version=run.agent_version,
            assessment_id=run.assessment_id, targets=run.targets,
            budget=run.budget, permit_id=run.permit_id,
            status=PeerRunStatus.COMPLETED,
        )
        repo.save(updated)
        assert repo.get("run-1").status is PeerRunStatus.COMPLETED
```

- [ ] **4.3 实现** `src/secopent/application/ports/peer_runs.py`：

```python
# src/secopent/application/ports/peer_runs.py
"""In-memory PeerRunRepository implementation (P0).

The SQLite-backed implementation lands with P2 wiring (see plan #4); the
in-memory repo serves Lite mode and all tests. Kept in application/ports
alongside the Protocol usage, mirroring how other Lite-mode in-memory
repositories are provided.
"""
from __future__ import annotations

from ...domain.peer_agents.models import PeerAgentRun


class InMemoryPeerRunRepository:
    """Dict-backed PeerRunRepository (satisfies the Protocol structurally)."""

    def __init__(self) -> None:
        self._runs: dict[str, PeerAgentRun] = {}

    def add(self, run: PeerAgentRun) -> None:
        self._runs[run.id] = run

    def save(self, run: PeerAgentRun) -> None:
        self._runs[run.id] = run

    def get(self, run_id: str) -> PeerAgentRun | None:
        return self._runs.get(run_id)
```

- [ ] **4.4 运行确认通过** → **4.5 提交**：`feat(ports): PeerRunRepository protocol + in-memory impl (P0 Task 4)`

---

## Task 5：PeerAgentService——launch 主路径

- [ ] **5.1 追加失败测试**（`tests/application/test_peer_agents_service.py`）：

```python
import pytest

from secopent.application.audit import AuditService
from secopent.application.peer_agents import (
    PeerAgentHarness,
    PeerAgentService,
    PeerRunOutcome,
)
from secopent.application.ports.peer_runs import InMemoryPeerRunRepository
from secopent.application.ports.repositories import AuditRepository
# AuditRepository 的内存 fake 复用 tests/application/conftest.py 中现有实现
# （test_audit_service.py 同款）；若 conftest 无现成 fake，则按
# AuditRepository Protocol 写 10 行内存版。
from secopent.domain.catalog.models import AssetType
from secopent.domain.peer_agents.models import (
    PeerAgentBudget,
    PeerAgentDescriptor,
    PeerAgentFinding,
    PeerAgentReport,
    PeerAgentTrustLevel,
    PeerRunStatus,
)
from secopent.domain.peer_agents.registry import PeerAgentRegistry
# _scope()/_catalog()/_descriptor() 构造复用 Task 3 测试中的 helper
# （提取到 tests/conftest.py 或本文件内复制，保持与 domain 测试一致）。


class FakeHarness:
    """Records execute/terminate calls; returns a canned report."""

    def __init__(self, report: PeerAgentReport) -> None:
        self.report = report
        self.executed: list[str] = []
        self.terminated: list[str] = []

    def execute(self, run, descriptor) -> PeerAgentReport:
        self.executed.append(run.id)
        return self.report

    def terminate(self, run_id: str) -> bool:
        self.terminated.append(run_id)
        return True


def _service(harness: FakeHarness) -> PeerAgentService:
    registry = PeerAgentRegistry()
    registry.register(_descriptor())
    audit = AuditService(repo=_in_memory_audit_repo())
    return PeerAgentService(
        registry=registry,
        harness=harness,
        audit=audit,
        runs=InMemoryPeerRunRepository(),
    )


def _report_with_sqli() -> PeerAgentReport:
    finding = PeerAgentFinding(
        id="f-1", run_id="run-1", agent_name="strix",
        title="SQLi in /login",
        asset="http://host.docker.internal:3000",
        severity_hint="high", cwe=("CWE-89",), owasp=("WSTG-INPV-05",),
    )
    return PeerAgentReport(
        run_id="run-1", findings=(finding,),
        wall_seconds=60.0, cost_units=2.0, exit_code=0,
    )


class TestLaunchHappyPath:
    def test_launch_produces_normalized_observation(self) -> None:
        service = _service(FakeHarness(_report_with_sqli()))
        outcome = service.launch(
            assessment_id="asmt-1",
            agent_name="strix",
            targets=("http://host.docker.internal:3000",),
            scope=_scope(),
            catalog=_catalog(),
            asset_type=AssetType.WEB_APP,
            actor="operator",
            permit_id="permit-1",
        )
        assert isinstance(outcome, PeerRunOutcome)
        assert outcome.run.status is PeerRunStatus.COMPLETED
        assert len(outcome.observations) == 1
        assert outcome.observations[0].source.name == "peer:strix"
        assert outcome.rejected == ()

    def test_launch_persists_run_and_audits(self) -> None:
        harness = FakeHarness(_report_with_sqli())
        service = _service(harness)
        outcome = service.launch(
            assessment_id="asmt-1", agent_name="strix",
            targets=("http://host.docker.internal:3000",),
            scope=_scope(), catalog=_catalog(),
            asset_type=AssetType.WEB_APP, actor="operator",
            permit_id="permit-1",
        )
        assert service._runs.get(outcome.run.id) is not None  # noqa: SLF001
        # 审计至少含 launch 与 collect 两条事件
        assert harness.executed == [outcome.run.id]
```

- [ ] **5.2 运行确认失败** → 5.3 **实现** `src/secopent/application/peer_agents.py`：

```python
# src/secopent/application/peer_agents.py
"""PeerAgentService: govern external autonomous pentest agents (spec §4-§5).

Peer agents are LOW-TRUST DISCOVERY SOURCES. The service enforces, in order:
registry membership, trust level, launch scope, budget caps, then normalizes
reported findings through the deterministic scope + catalog gates before they
may join the Assessment's Observations. Findings never skip the oracle: this
service only produces candidate Observations (LLM边界).

The harness Protocol is inline (same convention as emergency_stop.py) so the
application layer stays free of Docker coupling.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from ..domain.adapters.contracts import Observation
from ..domain.catalog.models import AssetType, TestCatalog
from ..domain.peer_agents.models import (
    PeerAgentDescriptor,
    PeerAgentFinding,
    PeerAgentReport,
    PeerAgentRun,
    PeerAgentTrustLevel,
    PeerRunStatus,
    PeerAgentBudgetExceeded,
    PeerAgentNotRegistered,
    PeerAgentTrustDenied,
    PeerRunScopeViolation,
    RejectedFinding,
    RejectionReason,
)
from ..domain.peer_agents.normalize import (
    finding_in_scope,
    hits_required_catalog,
    normalize_finding,
)
from ..domain.peer_agents.registry import PeerAgentRegistry
from ..domain.scope.models import ScopeSnapshot
from .audit import AuditService
from .ports.repositories import PeerRunRepository


@runtime_checkable
class PeerAgentHarness(Protocol):
    """Execution surface for peer agents (infra implements, tests fake)."""

    def execute(
        self, run: PeerAgentRun, descriptor: PeerAgentDescriptor
    ) -> PeerAgentReport: ...

    def terminate(self, run_id: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class PeerRunOutcome:
    """Result of one peer run: the run record plus gated results."""

    run: PeerAgentRun
    observations: tuple[Observation, ...]
    rejected: tuple[RejectedFinding, ...]


class PeerAgentService:
    """Launch, budget-gate, normalize, and stop peer agent runs."""

    def __init__(
        self,
        *,
        registry: PeerAgentRegistry,
        harness: PeerAgentHarness,
        audit: AuditService,
        runs: PeerRunRepository,
    ) -> None:
        self._registry = registry
        self._harness = harness
        self._audit = audit
        self._runs = runs

    def launch(
        self,
        *,
        assessment_id: str,
        agent_name: str,
        targets: tuple[str, ...],
        scope: ScopeSnapshot,
        catalog: TestCatalog,
        asset_type: AssetType,
        actor: str,
        permit_id: str,
    ) -> PeerRunOutcome:
        descriptor = self._registry.get(agent_name)
        if descriptor is None:
            raise PeerAgentNotRegistered(
                f"peer agent not registered: {agent_name}"
            )
        if descriptor.trust_level is not PeerAgentTrustLevel.ADOPTED_EXTERNAL:
            raise PeerAgentTrustDenied(
                f"peer agent trust level denies execution: {agent_name} "
                f"({descriptor.trust_level.value})"
            )
        for target in targets:
            if not (scope.includes_url(target) or scope.includes_domain(target)):
                raise PeerRunScopeViolation(
                    f"peer launch target outside scope: {target}"
                )

        run = PeerAgentRun(
            id=f"peer-run-{uuid.uuid4().hex[:12]}",
            agent_name=descriptor.name,
            agent_version=descriptor.version,
            assessment_id=assessment_id,
            targets=targets,
            budget=descriptor.default_budget,
            permit_id=permit_id,
            status=PeerRunStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
        self._runs.add(run)
        self._audit.record(
            actor=actor, action="peer_run.launch",
            resource_type="peer_agent_run", resource_id=run.id,
            payload={"agent": descriptor.name, "targets": list(targets),
                     "permit_id": permit_id},
        )

        try:
            report = self._harness.execute(run, descriptor)
        except Exception:
            self._finish(run, PeerRunStatus.FAILED, actor)
            raise

        status = PeerRunStatus.COMPLETED
        over_wall = report.wall_seconds > run.budget.max_wall_seconds
        over_cost = report.cost_units > run.budget.max_cost_units
        if over_wall or over_cost:
            status = PeerRunStatus.BUDGET_EXCEEDED
            self._audit.record(
                actor=actor, action="peer_run.budget_exceeded",
                resource_type="peer_agent_run", resource_id=run.id,
                payload={"wall_seconds": report.wall_seconds,
                         "cost_units": report.cost_units},
            )
        # Evidence preservation: findings produced before the breach are
        # still normalized (spec §12 - 证据不被静默丢弃).

        observations, rejected = self._normalize(
            report, run, scope, catalog, asset_type
        )
        finished = self._finish(run, status, actor)
        self._audit.record(
            actor=actor, action="peer_run.collect",
            resource_type="peer_agent_run", resource_id=run.id,
            payload={
                "findings_total": len(report.findings),
                "observations_accepted": len(observations),
                "findings_rejected": len(rejected),
                "rejection_reasons": [r.reason.value for r in rejected],
                "exit_code": report.exit_code,
            },
        )
        return PeerRunOutcome(
            run=finished, observations=observations, rejected=rejected
        )

    def stop(self, *, run_id: str, actor: str, reason: str) -> bool:
        """Terminate an active peer run (Emergency Stop path, spec §5)."""
        run = self._runs.get(run_id)
        if run is None:
            return False
        terminated = self._harness.terminate(run_id)
        self._finish(run, PeerRunStatus.STOPPED, actor)
        self._audit.record(
            actor=actor, action="peer_run.stop",
            resource_type="peer_agent_run", resource_id=run_id,
            payload={"reason": reason, "terminated": terminated},
        )
        return terminated

    # -- internals ---------------------------------------------------------

    def _normalize(
        self,
        report: PeerAgentReport,
        run: PeerAgentRun,
        scope: ScopeSnapshot,
        catalog: TestCatalog,
        asset_type: AssetType,
    ) -> tuple[tuple[Observation, ...], tuple[RejectedFinding, ...]]:
        observations: list[Observation] = []
        rejected: list[RejectedFinding] = []
        for finding in report.findings:
            if not finding_in_scope(finding, scope):
                rejected.append(RejectedFinding(
                    finding=finding, reason=RejectionReason.OUT_OF_SCOPE,
                    detail=f"asset outside scope: {finding.asset}",
                ))
                continue
            if not hits_required_catalog(finding, catalog, asset_type):
                rejected.append(RejectedFinding(
                    finding=finding, reason=RejectionReason.OUT_OF_CATALOG,
                    detail="CWE/OWASP intersects no required test class",
                ))
                continue
            observations.append(normalize_finding(finding, run))
        return tuple(observations), tuple(rejected)

    def _finish(
        self, run: PeerAgentRun, status: PeerRunStatus, actor: str
    ) -> PeerAgentRun:
        finished = PeerAgentRun(
            id=run.id, agent_name=run.agent_name,
            agent_version=run.agent_version,
            assessment_id=run.assessment_id, targets=run.targets,
            budget=run.budget, permit_id=run.permit_id,
            status=status, started_at=run.started_at,
            finished_at=datetime.now(timezone.utc),
        )
        self._runs.save(finished)
        return finished
```

- [ ] **5.4 运行确认通过** → **5.5 提交**：`feat(app): PeerAgentService launch path with budget+audit (P0 Task 5)`

---

## Task 6：PeerAgentService——四类拒绝路径 + stop

- [ ] **6.1 追加失败测试**（同文件）：

```python
from secopent.domain.peer_agents.models import (
    PeerAgentNotRegistered,
    PeerAgentTrustDenied,
    PeerRunScopeViolation,
)


class TestLaunchDenials:
    def test_unregistered_agent_rejected(self) -> None:
        service = _service(FakeHarness(_report_with_sqli()))
        with pytest.raises(PeerAgentNotRegistered):
            service.launch(
                assessment_id="asmt-1", agent_name="unknown-agent",
                targets=("http://host.docker.internal:3000",),
                scope=_scope(), catalog=_catalog(),
                asset_type=AssetType.WEB_APP, actor="op", permit_id="p",
            )

    def test_untrusted_agent_rejected(self) -> None:
        registry = PeerAgentRegistry()
        registry.register(PeerAgentDescriptor(
            name="sketchy", version="0.1", license="unknown",
            trust_level=PeerAgentTrustLevel.UNTRUSTED,
            capabilities=(), cost_class="llm_tokens",
            default_budget=PeerAgentBudget(max_wall_seconds=60, max_cost_units=1),
        ))
        service = PeerAgentService(
            registry=registry, harness=FakeHarness(_report_with_sqli()),
            audit=AuditService(repo=_in_memory_audit_repo()),
            runs=InMemoryPeerRunRepository(),
        )
        with pytest.raises(PeerAgentTrustDenied):
            service.launch(
                assessment_id="asmt-1", agent_name="sketchy",
                targets=("http://host.docker.internal:3000",),
                scope=_scope(), catalog=_catalog(),
                asset_type=AssetType.WEB_APP, actor="op", permit_id="p",
            )

    def test_out_of_scope_launch_target_rejected(self) -> None:
        service = _service(FakeHarness(_report_with_sqli()))
        with pytest.raises(PeerRunScopeViolation):
            service.launch(
                assessment_id="asmt-1", agent_name="strix",
                targets=("http://evil.example.com",),
                scope=_scope(), catalog=_catalog(),
                asset_type=AssetType.WEB_APP, actor="op", permit_id="p",
            )


class TestFindingGates:
    def test_out_of_scope_finding_rejected_not_normalized(self) -> None:
        foreign = PeerAgentReport(
            run_id="run-1",
            findings=(PeerAgentFinding(
                id="f-9", run_id="run-1", agent_name="strix",
                title="SQLi", asset="http://evil.example.com",
                severity_hint="high", cwe=("CWE-89",),
            ),),
            wall_seconds=1.0, cost_units=0.1, exit_code=0,
        )
        outcome = _service(FakeHarness(foreign)).launch(
            assessment_id="asmt-1", agent_name="strix",
            targets=("http://host.docker.internal:3000",),
            scope=_scope(), catalog=_catalog(),
            asset_type=AssetType.WEB_APP, actor="op", permit_id="p",
        )
        assert outcome.observations == ()
        assert len(outcome.rejected) == 1
        assert outcome.rejected[0].reason.value == "out_of_scope"

    def test_off_catalog_finding_rejected(self) -> None:
        noise = PeerAgentReport(
            run_id="run-1",
            findings=(PeerAgentFinding(
                id="f-8", run_id="run-1", agent_name="strix",
                title="info leak", asset="http://host.docker.internal:3000",
                severity_hint="info", cwe=("CWE-200",), owasp=(),
            ),),
            wall_seconds=1.0, cost_units=0.1, exit_code=0,
        )
        outcome = _service(FakeHarness(noise)).launch(
            assessment_id="asmt-1", agent_name="strix",
            targets=("http://host.docker.internal:3000",),
            scope=_scope(), catalog=_catalog(),
            asset_type=AssetType.WEB_APP, actor="op", permit_id="p",
        )
        assert outcome.observations == ()
        assert outcome.rejected[0].reason.value == "out_of_catalog"

    def test_budget_exceed_marks_status_but_keeps_findings(self) -> None:
        over = PeerAgentReport(
            run_id="run-1", findings=_report_with_sqli().findings,
            wall_seconds=10_000.0, cost_units=0.0, exit_code=0,
        )
        outcome = _service(FakeHarness(over)).launch(
            assessment_id="asmt-1", agent_name="strix",
            targets=("http://host.docker.internal:3000",),
            scope=_scope(), catalog=_catalog(),
            asset_type=AssetType.WEB_APP, actor="op", permit_id="p",
        )
        assert outcome.run.status is PeerRunStatus.BUDGET_EXCEEDED
        assert len(outcome.observations) == 1  # 证据保留


class TestStop:
    def test_stop_terminates_and_records(self) -> None:
        harness = FakeHarness(_report_with_sqli())
        service = _service(harness)
        outcome = service.launch(
            assessment_id="asmt-1", agent_name="strix",
            targets=("http://host.docker.internal:3000",),
            scope=_scope(), catalog=_catalog(),
            asset_type=AssetType.WEB_APP, actor="op", permit_id="p",
        )
        assert service.stop(
            run_id=outcome.run.id, actor="op", reason="emergency"
        ) is True
        assert harness.terminated == [outcome.run.id]

    def test_stop_unknown_run_returns_false(self) -> None:
        service = _service(FakeHarness(_report_with_sqli()))
        assert service.stop(run_id="nope", actor="op", reason="x") is False
```

- [ ] **6.2 运行**——Task 5 的实现应已使大部分通过；若有红，修实现（不改测试语义）→ **6.3 全绿后提交**：`test(app): peer service denial paths, gates, stop (P0 Task 6)`

---

## Task 7：执行器 extra_labels 扩展（向后兼容）

- [ ] **7.1 追加失败测试** `tests/infrastructure/test_subprocess_executor_labels.py`：

```python
# tests/infrastructure/test_subprocess_executor_labels.py
"""extra_labels support on SubprocessContainerExecutor (P0 Task 7).

Uses a fake docker binary (echoing args) so the test runs without Docker.
"""
from __future__ import annotations

import sys
from pathlib import Path

from secopent.infrastructure.adapters.subprocess_executor import (
    SubprocessContainerExecutor,
)


class _ArgsRecorder:
    """Capture the argv the executor would pass to docker."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []


def test_extra_labels_appear_in_docker_args(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run(args, **kwargs):  # noqa: ANN001 - subprocess shape
        captured.setdefault("args", list(args))

        class _Result:
            returncode = 0
            stdout = ""
            stderr = ""

        return _Result()

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)
    executor = SubprocessContainerExecutor(docker_bin="docker")
    executor.run(
        image_digest="alpine:3.20",  # tag-only: digest check skipped
        command=["true"],
        mounts={},
        network_policy="scoped-egress",
        resource_limits={},
        extra_labels={"secopent.peer_run": "peer-run-abc"},
    )
    args = captured["args"]
    idx = args.index("--label")
    # 既有 secopent=execution label 保留，且新增 peer label
    labels = [args[i + 1] for i, a in enumerate(args) if a == "--label"]
    assert "secopent=execution" in labels
    assert "secopent.peer_run=peer-run-abc" in labels


def test_run_without_extra_labels_unchanged(monkeypatch) -> None:
    def fake_run(args, **kwargs):  # noqa: ANN001
        class _Result:
            returncode = 0
            stdout = ""
            stderr = ""

        return _Result()

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)
    executor = SubprocessContainerExecutor()
    result = executor.run(
        image_digest="alpine:3.20", command=["true"], mounts={},
        network_policy="scoped-egress", resource_limits={},
    )
    assert result.exit_code == 0
```

- [ ] **7.2 运行确认失败**（TypeError: unexpected keyword）→ 7.3 **修改** `subprocess_executor.py::run` 与 `_build_args` 增加 `extra_labels: Mapping[str, str] = {}` 参数（`Mapping` 已在 imports）；在 `_build_args` 现有 `--label secopent=execution` 之后追加：

```python
        for key, value in extra_labels.items():
            args += ["--label", f"{key}={value}"]
```

- [ ] **7.4 同步修改** `base.py::ContainerExecutor` Protocol 的 `run` 签名追加 `extra_labels: Mapping[str, str] = ...`（Protocol 写法：`extra_labels: Mapping[str, str]`，无默认值；调用侧 AdapterRunner 不传该参数时由实现默认值兜底——注意 Protocol 结构兼容性：若现有 mock executor 不接受该 kwarg，AdapterRunner 调用不传即可，不破坏）。运行 `tests/integration/test_subprocess_executor.py` 与 `tests/infrastructure/` 相关测试确认无回归。
- [ ] **7.5 提交**：`feat(executor): extra_labels for peer-run container labeling (P0 Task 7)`

---

## Task 8：ContainerPeerAgentHarness（infrastructure）

- [ ] **8.1 写失败测试** `tests/infrastructure/test_peer_agent_harness.py`：

```python
# tests/infrastructure/test_peer_agent_harness.py
"""ContainerPeerAgentHarness tests with fake executor + fake backend."""
from __future__ import annotations

from pathlib import Path

import pytest

from secopent.domain.peer_agents.models import (
    PeerAgentBudget,
    PeerAgentDescriptor,
    PeerAgentFinding,
    PeerAgentReport,
    PeerAgentRun,
    PeerAgentTrustLevel,
)
from secopent.infrastructure.adapters.base import ContainerResult
from secopent.infrastructure.peer_agents.harness import (
    ContainerPeerAgentHarness,
    PeerAgentBackend,
    PeerAgentBackendMissing,
    PeerInvocation,
)


def _descriptor() -> PeerAgentDescriptor:
    return PeerAgentDescriptor(
        name="fakepeer", version="1.0", license="MIT",
        trust_level=PeerAgentTrustLevel.ADOPTED_EXTERNAL,
        capabilities=("web",), cost_class="llm_tokens",
        default_budget=PeerAgentBudget(max_wall_seconds=60, max_cost_units=5),
        image_digest="fake/peer@sha256:" + "a" * 64,
    )


def _run() -> PeerAgentRun:
    return PeerAgentRun(
        id="peer-run-1", agent_name="fakepeer", agent_version="1.0",
        assessment_id="asmt-1", targets=("http://host.docker.internal:3000",),
        budget=PeerAgentBudget(max_wall_seconds=60, max_cost_units=5),
        permit_id="p-1",
    )


class FakeBackend:
    def build_invocation(self, run, descriptor, workdir: Path) -> PeerInvocation:
        return PeerInvocation(
            image_digest=descriptor.image_digest,
            command=("fakepeer", "--target", run.targets[0]),
            mounts={"/work/output": str(workdir / "out")},
            capabilities=(),
            resource_limits={"memory_mb": 1024, "cpus": "1"},
        )

    def parse_report(self, result: ContainerResult, workdir: Path) -> PeerAgentReport:
        return PeerAgentReport(
            run_id="peer-run-1", findings=(), wall_seconds=1.0,
            cost_units=0.5, exit_code=result.exit_code,
        )


class FakeExecutor:
    def __init__(self, result: ContainerResult | None = None) -> None:
        self.calls: list[dict] = []
        self.result = result or ContainerResult(
            stdout="", stderr="", exit_code=0, artifacts_dir=Path(".")
        )

    def run(self, **kwargs) -> ContainerResult:
        self.calls.append(kwargs)
        return self.result


class TestHarnessExecute:
    def test_execute_invokes_executor_with_hardening(self, tmp_path) -> None:
        executor = FakeExecutor()
        harness = ContainerPeerAgentHarness(
            executor=executor,
            backends={"fakepeer": FakeBackend()},
            workdir_root=tmp_path,
        )
        report = harness.execute(_run(), _descriptor())
        assert report.exit_code == 0
        call = executor.calls[0]
        assert call["image_digest"].startswith("fake/peer@sha256:")
        assert call["network_policy"] == "scoped-egress"
        assert call["extra_labels"] == {"secopent.peer_run": "peer-run-1"}

    def test_missing_backend_raises(self, tmp_path) -> None:
        harness = ContainerPeerAgentHarness(
            executor=FakeExecutor(), backends={}, workdir_root=tmp_path,
        )
        with pytest.raises(PeerAgentBackendMissing):
            harness.execute(_run(), _descriptor())


class TestHarnessTerminate:
    def test_terminate_kills_labeled_containers(self, monkeypatch) -> None:
        calls: list[list[str]] = []

        def fake_run(args, **kwargs):  # noqa: ANN001
            calls.append(list(args))

            class _Result:
                returncode = 0
                stdout = "cid1\n" if args[1] == "ps" else ""
                stderr = ""

            return _Result()

        import subprocess

        monkeypatch.setattr(subprocess, "run", fake_run)
        harness = ContainerPeerAgentHarness(
            executor=FakeExecutor(), backends={}, workdir_root=Path("."),
            docker_bin="docker",
        )
        assert harness.terminate("peer-run-1") is True
        assert any(c[:2] == ["docker", "ps"] for c in calls)
        assert any(c[:2] == ["docker", "kill"] and "cid1" in c for c in calls)

    def test_terminate_no_containers_returns_false(self, monkeypatch) -> None:
        def fake_run(args, **kwargs):  # noqa: ANN001
            class _Result:
                returncode = 0
                stdout = ""
                stderr = ""

            return _Result()

        import subprocess

        monkeypatch.setattr(subprocess, "run", fake_run)
        harness = ContainerPeerAgentHarness(
            executor=FakeExecutor(), backends={}, workdir_root=Path("."),
        )
        assert harness.terminate("peer-run-x") is False
```

- [ ] **8.2 运行确认失败** → 8.3 **实现** `src/secopent/infrastructure/peer_agents/__init__.py`（docstring）与 `harness.py`：

```python
# src/secopent/infrastructure/peer_agents/harness.py
"""ContainerPeerAgentHarness: run peer agents in hardened containers.

Reuses SubprocessContainerExecutor hardening (digest pinning, non-root,
cap-drop ALL, read-only rootfs, resource limits, bridge network). Each peer
run labels its container ``secopent.peer_run=<run_id>`` so:
- targeted stop can ``docker kill`` by label (this module's ``terminate``);
- the global Emergency Stop's DockerContainerTerminator (label
  ``secopent=execution``) still catches peer containers automatically.

Backends are per-agent strategies (P2: StrixBackend; P3: ShannonBackend).
P0 ships no real backend - contract tests use fakes.
"""
from __future__ import annotations

import subprocess
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from ...domain.common.errors import DomainError
from ...domain.peer_agents.models import (
    PeerAgentDescriptor,
    PeerAgentReport,
    PeerAgentRun,
)
from ..adapters.base import ContainerResult


class PeerAgentBackendMissing(DomainError):
    """No backend registered for this peer agent name."""


@dataclass(frozen=True, slots=True)
class PeerInvocation:
    """Everything the harness needs to run one peer agent container."""

    image_digest: str
    command: Sequence[str]
    mounts: Mapping[str, str]
    capabilities: Sequence[str]
    resource_limits: Mapping[str, object]


@runtime_checkable
class PeerAgentBackend(Protocol):
    """Per-agent invocation + report parsing strategy."""

    def build_invocation(
        self,
        run: PeerAgentRun,
        descriptor: PeerAgentDescriptor,
        workdir: Path,
    ) -> PeerInvocation: ...

    def parse_report(
        self, result: ContainerResult, workdir: Path
    ) -> PeerAgentReport: ...


class _Executor(Protocol):
    def run(
        self,
        *,
        image_digest: str,
        command: Sequence[str],
        mounts: Mapping[str, str],
        network_policy: str,
        resource_limits: Mapping[str, object],
        capabilities: Sequence[str] = (),
        extra_labels: Mapping[str, str] = ...,
    ) -> ContainerResult: ...


class ContainerPeerAgentHarness:
    """PeerAgentHarness backed by hardened docker containers."""

    def __init__(
        self,
        *,
        executor: _Executor,
        backends: Mapping[str, PeerAgentBackend],
        workdir_root: Path,
        docker_bin: str = "docker",
        terminate_timeout: int = 30,
    ) -> None:
        self._executor = executor
        self._backends = dict(backends)
        self._workdir_root = Path(workdir_root)
        self._docker = docker_bin
        self._terminate_timeout = terminate_timeout

    def execute(
        self, run: PeerAgentRun, descriptor: PeerAgentDescriptor
    ) -> PeerAgentReport:
        backend = self._backends.get(descriptor.name)
        if backend is None:
            raise PeerAgentBackendMissing(
                f"no peer agent backend registered: {descriptor.name}"
            )
        workdir = self._workdir_root / f"{run.id}-{uuid.uuid4().hex[:6]}"
        (workdir / "out").mkdir(parents=True, exist_ok=True)
        invocation = backend.build_invocation(run, descriptor, workdir)
        started = time.monotonic()
        result = self._executor.run(
            image_digest=invocation.image_digest,
            command=list(invocation.command),
            mounts=dict(invocation.mounts),
            network_policy="scoped-egress",
            resource_limits=dict(invocation.resource_limits),
            capabilities=tuple(invocation.capabilities),
            extra_labels={"secopent.peer_run": run.id},
        )
        wall = time.monotonic() - started
        report = backend.parse_report(result, workdir)
        # Backends report their own wall/cost; the harness guarantees wall is
        # at least the measured container wall (self-reported floor guard).
        return PeerAgentReport(
            run_id=run.id,
            findings=report.findings,
            wall_seconds=max(report.wall_seconds, wall),
            cost_units=report.cost_units,
            exit_code=report.exit_code,
        )

    def terminate(self, run_id: str) -> bool:
        """Kill containers labeled for this peer run; True if any were killed."""
        listed = subprocess.run(  # noqa: S603
            [self._docker, "ps", "-q", "--filter",
             f"label=secopent.peer_run={run_id}"],
            capture_output=True, text=True,
            timeout=self._terminate_timeout, check=False,
        )
        container_ids = [c for c in listed.stdout.split() if c]
        if not container_ids:
            return False
        killed = subprocess.run(  # noqa: S603
            [self._docker, "kill", *container_ids],
            capture_output=True, text=True,
            timeout=self._terminate_timeout, check=False,
        )
        return killed.returncode == 0
```

- [ ] **8.4 运行确认通过** → **8.5 提交**：`feat(infra): container peer agent harness with label-based stop (P0 Task 8)`

---

## Task 9：PEER_IMAGE_CATALOG 骨架

- [ ] **9.1 实现** `src/secopent/infrastructure/peer_agents/image_catalog.py`（无需测试的纯数据，加 docstring 说明 P2 填 strix digest、P3 填 shannon digest，规则同 `adapters/image_catalog.py`）：

```python
# src/secopent/infrastructure/peer_agents/image_catalog.py
"""Image catalog for peer agents (spec §5 P0; entries land with P2/P3).

Same digest-pinning policy as ``infrastructure/adapters/image_catalog.py``:
``docker pull <image>@<digest>``, record the digest here, upgrades require an
explicit catalog change + re-pin. P2 adds the Strix entry (plan #4), P3 the
Shannon entry (plan #6) - digests are filled after the first pull.
"""
from __future__ import annotations

from ..adapters.image_catalog import ImageRef

PEER_IMAGE_CATALOG: dict[str, ImageRef] = {
    # P2: "strix": ImageRef("usestrix/strix", "<tag>", ""),
    # P3: "shannon": ImageRef("keygraph/shannon", "<tag>", ""),
}
```

- [ ] **9.2 提交**：`feat(infra): peer image catalog skeleton (P0 Task 9)`

---

## Task 10：架构文档 + README + 质量门

- [ ] **10.1 新建** `docs/architecture/peer-agents.md`：按现有架构文档风格（参考 `core-boundaries.md`）写：定位（低信任发现源）、数据流（launch→harness→normalize 双门禁→oracle 队列）、信任级、预算、Emergency Stop 关系、与 ADR-014/A4 的承继、P0 边界（无真实 backend）。
- [ ] **10.2 修改** `README.md` 的 "Reference docs" 列表追加：`[Peer agents](docs/architecture/peer-agents.md)`。
- [ ] **10.3 全量质量门**：

```bash
py -3.12 -m pytest -q
py -3.12 -m ruff check src tests
py -3.12 -m mypy src
git diff --check
```

（架构边界测试 `tests/test_architecture_boundaries.py` 必须保持绿——新 domain 模块零框架导入。）

- [ ] **10.4 提交**：`docs: peer agents architecture + P0 quality gate`

---

## DoD（里程碑验收，对齐路线图纪律）

- [ ] mock peer agent 端到端：launch → harness.execute → 归一化 → observations 产出（TestLaunchHappyPath 绿）
- [ ] 未登记 agent 拒跑（PeerAgentNotRegistered）
- [ ] 信任级不符拒跑（PeerAgentTrustDenied）
- [ ] launch 目标越界拒绝（PeerRunScopeViolation）
- [ ] finding 越界拒收 + 审计（out_of_scope，不进 observations）
- [ ] finding 目录外拒收（out_of_catalog）
- [ ] 预算超限标记 BUDGET_EXCEEDED 且证据保留
- [ ] stop()/Emergency Stop 路径：label 定位 + docker kill + 审计
- [ ] domain/application 无框架导入（边界测试绿）
- [ ] 全量 pytest + ruff + mypy + `git diff --check` 绿
- [ ] 独立提交序列（每 Task 一提交，不混入无关变更）

## 已知注意

- **Permit 校验边界**：P0 的 PeerAgentService 记录并携带 `permit_id`（审计关联），Permit 的 Ed25519 签名/过期/重放深度校验沿用 M1 permit 基础设施，在 P2 真实接线时由 worker 层执行（与 tool adapter 的 permit 消费路径一致）；P0 契约测试不重复实现签名校验。

- `_scope()`/`_catalog()`/`_in_memory_audit_repo()` 测试 helper 的字段以现有 domain 模型为准；Task 3 已注明核对点。
- `extra_labels` 加入 Protocol 后，其他既有 mock executor（tests 中）若以位置参数实现 `run` 不受影响（新增为 kwarg）。
- Windows 开发环境无 Docker 不影响本计划：harness 测试全 fake；真实容器行为是 Plan #4（P2，Linux）范围。
