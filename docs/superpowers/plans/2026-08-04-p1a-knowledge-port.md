# P1a 知识移植 Implementation Plan（Strix skills → 策展层）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 把 Strix 的漏洞类攻击手册（Apache-2.0）转译为 SecOpent 策展层资产：① 结构化攻击手册库（含 provenance 与归属）；② 新漏洞类的 TestCatalog 扩展 + case DSL 种子（DRAFT，待人审签名）；③ 攻击链模板（供 P2b ChainEngine）。不整段复制 prompt 素材，只提取确定性知识。

**Architecture:** 手册以 YAML 结构化数据落 `infrastructure/catalog/handbooks/`（产品策展子层，O4=B 属产品 IP 侧；引用 Strix 内容处保留 Apache-2.0 归属），经 `HandbookRegistry` 加载并校验；catalog 扩展走新版本号（不修改旧版本，历史 Assessment 钉旧快照不受影响）；case 种子以 CaseDefinition(DRAFT) 形态进 case registry fixture 目录。

**Tech Stack:** Python 3.12, YAML（安全 loader 复用 `domain/cases/yaml_schema` 同款约束）, pytest。

**Spec:** `docs/superpowers/specs/2026-08-04-strix-shannon-layered-integration-design.md` §6

**前置：** 无（独立并行）。源材料：本地克隆 `F:\claudepc\_research_tmp\strix\strix\skills\vulnerabilities\*.md`。

---

## 文件结构

| 文件 | 职责 | 动作 |
|------|------|------|
| `src/secopent/infrastructure/catalog/handbooks/*.yaml` | 首期 8 份结构化攻击手册 | 新建 |
| `src/secopent/infrastructure/catalog/handbook_registry.py` | HandbookRegistry 加载 + schema 校验 | 新建 |
| `src/secopent/infrastructure/catalog/extended_catalog.py` | 扩展 TestCatalog（新版本，含新类） | 新建 |
| `src/secopent/domain/findings/chain_templates.py` | AttackChainTemplate domain 模型 + 策展模板 | 新建 |
| `tests/fixtures/cases/seed/*.yaml` | case DSL 种子（DRAFT） | 新建 |
| `tests/infrastructure/test_handbook_registry.py` | 手册加载测试 | 新建 |
| `tests/infrastructure/test_extended_catalog.py` | 扩展 catalog 测试（含覆盖率不退化断言） | 新建 |
| `tests/domain/test_chain_templates.py` | 链模板测试 | 新建 |
| `NOTICE`（或 `LICENSE-THIRD-PARTY.md`） | Strix Apache-2.0 归属声明 | 新建/修改 |
| `docs/architecture/knowledge-layer.md` | 追加手册子层说明 | 修改 |

---

## Task 1：Handbook schema + Registry

- [ ] **1.1 写失败测试** `tests/infrastructure/test_handbook_registry.py`：

```python
# tests/infrastructure/test_handbook_registry.py
"""HandbookRegistry: structured attack handbooks with provenance (P1a Task 1)."""
from __future__ import annotations

from pathlib import Path

import pytest

from secopent.infrastructure.catalog.handbook_registry import (
    Handbook,
    HandbookRegistry,
    HandbookSchemaError,
    load_default_handbooks,
)


def _write(dir_path: Path, name: str, content: str) -> None:
    dir_path.mkdir(parents=True, exist_ok=True)
    (dir_path / name).write_text(content, encoding="utf-8")


_VALID = """
id: ssrf
title: Server-Side Request Forgery
cwe: ["CWE-918"]
owasp: ["A10:2021"]
provenance:
  derived_from: "usestrix/strix skills/vulnerabilities/ssrf.md"
  license: "Apache-2.0"
attack_surface:
  - "URL/hostname parameters accepting external addresses"
recon_endpoints:
  - "/proxy?url="
payload_classes:
  - name: "internal-network"
    description: "requests to RFC1918 / loopback"
verification_hint: "oob-callback"
"""


class TestHandbookRegistry:
    def test_loads_valid_handbook(self, tmp_path: Path) -> None:
        _write(tmp_path, "ssrf.yaml", _VALID)
        registry = HandbookRegistry.load(tmp_path)
        handbook = registry.get("ssrf")
        assert isinstance(handbook, Handbook)
        assert handbook.cwe == ("CWE-918",)
        assert handbook.provenance_license == "Apache-2.0"

    def test_rejects_missing_provenance(self, tmp_path: Path) -> None:
        _write(tmp_path, "bad.yaml", _VALID.replace("provenance:", "provenance_x:"))
        with pytest.raises(HandbookSchemaError):
            HandbookRegistry.load(tmp_path)

    def test_rejects_missing_verification_hint(self, tmp_path: Path) -> None:
        _write(tmp_path, "bad.yaml", _VALID.replace("verification_hint: \"oob-callback\"", ""))
        with pytest.raises(HandbookSchemaError):
            HandbookRegistry.load(tmp_path)

    def test_default_handbooks_load_and_cover_first_batch(self) -> None:
        registry = load_default_handbooks()
        # 首期移植 8 类（见 Task 2 清单）
        assert len(registry.all()) >= 8
        for handbook in registry.all():
            assert handbook.provenance_license == "Apache-2.0"
```

- [ ] **1.2 运行确认失败** → 1.3 **实现** `src/secopent/infrastructure/catalog/handbook_registry.py`：

```python
# src/secopent/infrastructure/catalog/handbook_registry.py
"""HandbookRegistry: curated structured attack handbooks (spec §6 P1a).

Handbooks are the deterministic distillation of attack-knowledge sources
(first batch derived from usestrix/strix skills, Apache-2.0, attribution in
NOTICE). Shape: attack_surface / recon_endpoints / payload_classes /
verification_hint - consumed by planner context and case authoring, NEVER
executed directly (the case engine executes cases, the oracle verifies).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ...domain.common.errors import DomainError

_REQUIRED_FIELDS = (
    "id", "title", "cwe", "owasp", "provenance",
    "attack_surface", "payload_classes", "verification_hint",
)
_PROVENANCE_FIELDS = ("derived_from", "license")


class HandbookSchemaError(DomainError):
    """A handbook file violates the curation schema."""


@dataclass(frozen=True, slots=True)
class Handbook:
    id: str
    title: str
    cwe: tuple[str, ...]
    owasp: tuple[str, ...]
    provenance_source: str
    provenance_license: str
    attack_surface: tuple[str, ...]
    recon_endpoints: tuple[str, ...]
    payload_classes: tuple[str, ...]
    verification_hint: str


def _parse(data: dict[str, Any], path: Path) -> Handbook:
    for field_name in _REQUIRED_FIELDS:
        if field_name not in data or data[field_name] in (None, "", []):
            raise HandbookSchemaError(f"{path}: missing field '{field_name}'")
    provenance = data["provenance"]
    if not isinstance(provenance, dict):
        raise HandbookSchemaError(f"{path}: provenance must be a mapping")
    for field_name in _PROVENANCE_FIELDS:
        if field_name not in provenance:
            raise HandbookSchemaError(
                f"{path}: provenance missing '{field_name}'"
            )
    return Handbook(
        id=str(data["id"]),
        title=str(data["title"]),
        cwe=tuple(str(c) for c in data["cwe"]),
        owasp=tuple(str(o) for o in data["owasp"]),
        provenance_source=str(provenance["derived_from"]),
        provenance_license=str(provenance["license"]),
        attack_surface=tuple(str(s) for s in data["attack_surface"]),
        recon_endpoints=tuple(str(e) for e in data.get("recon_endpoints", [])),
        payload_classes=tuple(
            str(p["name"]) if isinstance(p, dict) else str(p)
            for p in data["payload_classes"]
        ),
        verification_hint=str(data["verification_hint"]),
    )


class HandbookRegistry:
    """All curated handbooks, keyed by id."""

    def __init__(self, handbooks: tuple[Handbook, ...]) -> None:
        self._by_id = {h.id: h for h in handbooks}

    @classmethod
    def load(cls, directory: Path) -> "HandbookRegistry":
        handbooks: list[Handbook] = []
        for path in sorted(Path(directory).glob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise HandbookSchemaError(f"{path}: top level must be a mapping")
            handbooks.append(_parse(data, path))
        return cls(tuple(handbooks))

    def get(self, handbook_id: str) -> Handbook | None:
        return self._by_id.get(handbook_id)

    def all(self) -> tuple[Handbook, ...]:
        return tuple(self._by_id.values())


def load_default_handbooks() -> HandbookRegistry:
    """Load the packaged handbook set (ships with the product)."""
    return HandbookRegistry.load(Path(__file__).parent / "handbooks")
```

- [ ] **1.4 运行确认通过**（Task 2 手册文件就位前，`test_default_handbooks_load_and_cover_first_batch` 会红——先跳过该测试：`pytest -k "not default_handbooks"`）→ **1.5 提交**：`feat(curation): handbook registry with provenance schema (P1a Task 1)`

---

## Task 2：首期 8 份手册内容（从 Strix skills 转译）

**转译规则**（每份手册执行一遍）：
1. 读源文件 `F:\claudepc\_research_tmp\strix\strix\skills\vulnerabilities\<name>.md`
2. 提取：Attack Surface 段落 → `attack_surface` 列表；Reconnaissance 的端点/参数表 → `recon_endpoints`；利用手法分类 → `payload_classes`（name+description 压成 name 与一行 description）
3. 填 `cwe`/`owasp`（以 CWE/NVD 官方映射为准，不照抄 Strix 标注）与 `verification_hint`（取值限定：`oob-callback` / `echo-reproduce` / `time-delay` / `diff-reproduce`，对齐 VerificationMethodRegistry 方法族）
4. `provenance.derived_from` 写 `usestrix/strix skills/vulnerabilities/<file>.md`，`license: Apache-2.0`

- [ ] **2.1 创建** `src/secopent/infrastructure/catalog/handbooks/` 并按上表产出 8 份 YAML：

| 手册 id | 源文件 | CWE | verification_hint |
|---------|--------|-----|-------------------|
| `ssrf` | ssrf.md | CWE-918 | oob-callback |
| `insecure-deserialization` | insecure_deserialization.md | CWE-502 | oob-callback |
| `path-traversal` | path_traversal_lfi_rfi.md | CWE-22, CWE-98 | echo-reproduce |
| `race-conditions` | race_conditions.md | CWE-362, CWE-367 | diff-reproduce |
| `authentication-jwt` | authentication_jwt.md | CWE-287, CWE-347 | diff-reproduce |
| `idor` | idor.md | CWE-639 | diff-reproduce |
| `http-request-smuggling` | http_request_smuggling.md | CWE-444 | time-delay |
| `prototype-pollution` | prototype_pollution.md | CWE-1321 | diff-reproduce |

（每份内容按转译规则从源 md 提取；禁止整段复制英文 prompt 指令句，只留事实性攻击面/端点/手法分类知识。）

- [ ] **2.2 运行** `py -3.12 -m pytest tests/infrastructure/test_handbook_registry.py -q` 全绿（含 default 覆盖测试）
- [ ] **2.3 新建/修改** `LICENSE-THIRD-PARTY.md`：

```markdown
# Third-Party Attribution

## usestrix/strix (Apache License 2.0)

The attack handbooks under `src/secopent/infrastructure/catalog/handbooks/`
are derivative knowledge distillations of the vulnerability skill documents
of the Strix project (https://github.com/usestrix/strix), used under the
Apache License, Version 2.0. See the `provenance` field of each handbook for
the specific source file. No Strix code is included or executed.
```

- [ ] **2.4 提交**：`feat(curation): first-batch handbooks distilled from Strix skills (P1a Task 2)`

---

## Task 3：扩展 TestCatalog（新版本 + 覆盖率不退化）

- [ ] **3.1 写失败测试** `tests/infrastructure/test_extended_catalog.py`：

```python
# tests/infrastructure/test_extended_catalog.py
"""Extended catalog: new vuln classes without coverage regression (P1a Task 3)."""
from __future__ import annotations

from secopent.domain.catalog.models import AssetType
from secopent.infrastructure.catalog.default_catalog import (
    DEFAULT_CATALOG_VERSION,
    build_default_catalog,
)
from secopent.infrastructure.catalog.extended_catalog import (
    EXTENDED_CATALOG_VERSION,
    build_extended_catalog,
)


class TestExtendedCatalog:
    def test_version_is_newer_not_edited(self) -> None:
        assert EXTENDED_CATALOG_VERSION != DEFAULT_CATALOG_VERSION

    def test_web_app_gains_new_required_classes(self) -> None:
        extended = build_extended_catalog()
        class_ids = {
            cls.id for cls in extended.mappings[AssetType.WEB_APP]
        }
        # 新增类（对应手册首批）
        for expected in (
            "wstg-inpv-ssrf",       # 注：默认已有 inpv-03=CWE-918，扩展类不得重复 id
            "wstg-athn-jwt",
            "wstg-inpv-deserialization",
            "wstg-inpv-path-traversal",
            "wstg-athz-idor",
            "wstg-buslogic-race",
        ):
            assert expected in class_ids

    def test_no_coverage_regression_vs_default(self) -> None:
        default = build_default_catalog()
        extended = build_extended_catalog()
        for asset_type in (AssetType.WEB_APP, AssetType.API):
            default_ids = {c.id for c in default.mappings.get(asset_type, ())}
            extended_ids = {c.id for c in extended.mappings.get(asset_type, ())}
            assert default_ids <= extended_ids  # 只增不减

    def test_every_new_class_has_distinct_cwe_or_owasp(self) -> None:
        extended = build_extended_catalog()
        classes = extended.mappings[AssetType.WEB_APP]
        seen: set[tuple[str, ...]] = set()
        for cls in classes:
            key = (cls.cwe, cls.owasp)
            # 允许不同 id 共享映射（如 wstg-inpv-03 与 api-ssrf），
            # 但新类必须携带非空 cwe 或 owasp
            assert cls.cwe or cls.owasp
            seen.add(key)
```

- [ ] **3.2 运行确认失败** → 3.3 **实现** `src/secopent/infrastructure/catalog/extended_catalog.py`：

```python
# src/secopent/infrastructure/catalog/extended_catalog.py
"""Extended TestCatalog: default classes + handbook-first-batch classes.

New VERSION (never edits the default): historical Assessments pin the old
snapshot; the coverage-degeneration gate (KnowledgeHealthMonitor) requires
new >= old, which adding classes satisfies.
"""
from __future__ import annotations

from ...domain.catalog.models import AssetType, TestCatalog
from ...domain.policy.models import RiskClass
from .default_catalog import build_default_catalog, _tc

EXTENDED_CATALOG_VERSION = "2026.08-extended-p1a"

_NEW_WEB_CLASSES = (
    _tc("wstg-athn-jwt", ("CWE-287", "CWE-347"), ("A07:2021",), RiskClass.ACTIVE),
    _tc("wstg-inpv-deserialization", ("CWE-502",), ("A08:2021",), RiskClass.INTRUSIVE),
    _tc("wstg-inpv-path-traversal", ("CWE-22", "CWE-98"), ("A01:2021",), RiskClass.ACTIVE),
    _tc("wstg-athz-idor", ("CWE-639",), ("A01:2021",), RiskClass.ACTIVE),
    _tc("wstg-buslogic-race", ("CWE-362", "CWE-367"), ("A04:2021",), RiskClass.ACTIVE),
    _tc("wstg-inpv-smuggling", ("CWE-444",), ("A03:2021",), RiskClass.INTRUSIVE),
    _tc("wstg-clientside-proto-pollution", ("CWE-1321",), ("A03:2021",), RiskClass.ACTIVE),
)


def build_extended_catalog() -> TestCatalog:
    base = build_default_catalog()
    mappings = dict(base.mappings)
    mappings[AssetType.WEB_APP] = (
        mappings.get(AssetType.WEB_APP, ()) + _NEW_WEB_CLASSES
    )
    return TestCatalog(version=EXTENDED_CATALOG_VERSION, mappings=mappings)
```

> ⚠️ 核对点：`_tc` 与 `build_default_catalog` 的导出名以 `default_catalog.py` 现状为准（下划线前缀函数若不便跨模块引用，则在 extended 内复制 3 行同款 helper 并注明）。`ssrf` 类默认已有（wstg-inpv-03=CWE-918），故扩展不重复添加 ssrf 类——测试断言清单中不含 ssrf 新 id。

- [ ] **3.4 运行确认通过** → **3.5 提交**：`feat(curation): extended catalog with 7 new web classes (P1a Task 3)`

---

## Task 4：case DSL 种子（DRAFT，人审后才签名发布）

- [ ] **4.1 创建** `tests/fixtures/cases/seed/` 目录，产出 4 份种子 YAML（首期 8 类中可用现有动词 `http.request` / `extract.regex` 表达的 4 类；其余 4 类（反序列化/走私/竞态/原型链）需要新动词或脚本动作，列为后续策展任务，不塞假动词）。种子模板（以 IDOR 为例）：

```yaml
# tests/fixtures/cases/seed/idor-horizontal.yaml
id: seed-idor-horizontal
version: "0.1.0"
author: "p1a-knowledge-port"
risk: active
target_type: web_app
schema: secopent.case/v1
origin: manual          # DRAFT 种子；签名发布前保持 manual/草稿链路
status: draft
cwe: ["CWE-639"]
owasp: ["API1:2023"]
preconditions:
  - "two distinct user sessions (user_a, user_b) available via secret store refs"
steps:
  - id: fetch-own-resource
    action: http.request
    spec:
      method: GET
      url: "{{base_url}}/api/profile/{{user_a_id}}"
      session: user_a
  - id: fetch-other-resource
    action: http.request
    spec:
      method: GET
      url: "{{base_url}}/api/profile/{{user_b_id}}"
      session: user_a
assertions:
  - id: other-resource-denied
    expression: "steps['fetch-other-resource'].status in (401, 403)"
evidence_req: ["response-body", "status-code"]
verification:
  method: idor
  reproduce: 3
```

同构产出：`jwt-alg-confusion.yaml`（steps：取 token → 构造 alg=none/HS256 混淆请求 → 断言 401）、`path-traversal-read.yaml`（`../../etc/passwd` 变体请求 + echo 断言占位符）、`race-double-spend.yaml`（`retry`/并发请求 + diff 断言——若现有动词无法表达并发，则种子仅含 preconditions+steps 骨架并注明 `# TODO(P2b+): requires concurrent-request verb` 属设计留白，不是实现占位）。

- [ ] **4.2 写解析测试** `tests/infrastructure/test_case_seeds.py`：用 `case_from_mapping`（yaml_schema）逐个解析种子文件，断言：解析成功、status 为 draft、verification.reproduce ≥ 1、cwe 非空。
- [ ] **4.3 运行确认通过** → **4.4 提交**：`feat(curation): case DSL seeds for IDOR/JWT/path-traversal/race (P1a Task 4)`

---

## Task 5：攻击链模板（domain，供 P2b）

- [ ] **5.1 写失败测试** `tests/domain/test_chain_templates.py`：

```python
# tests/domain/test_chain_templates.py
"""Attack chain templates: curated link patterns (P1a Task 5, consumed by P2b)."""
from __future__ import annotations

import pytest

from secopent.domain.common.errors import DomainValidationError
from secopent.domain.findings.chain_templates import (
    AttackChainTemplate,
    ChainLinkSpec,
    default_chain_templates,
    match_template,
)


class TestTemplateModel:
    def test_template_requires_at_least_two_links(self) -> None:
        with pytest.raises(DomainValidationError):
            AttackChainTemplate(
                id="one-link",
                name="degenerate",
                links=(ChainLinkSpec(cwe_any=("CWE-89",)),),
                tactic="initial-access",
            )

    def test_well_formed_template(self) -> None:
        template = AttackChainTemplate(
            id="ssrf-to-cloud-creds",
            name="SSRF -> cloud metadata -> credential leak",
            links=(
                ChainLinkSpec(cwe_any=("CWE-918",)),
                ChainLinkSpec(cwe_any=("CWE-918",), asset_pattern="169.254.169.254"),
                ChainLinkSpec(cwe_any=("CWE-522", "CWE-312")),
            ),
            tactic="credential-access",
        )
        assert len(template.links) == 3


class TestMatching:
    def test_matches_confirmed_findings_in_order(self) -> None:
        template = AttackChainTemplate(
            id="authz-to-priv",
            name="auth bypass -> IDOR",
            links=(
                ChainLinkSpec(cwe_any=("CWE-287",)),
                ChainLinkSpec(cwe_any=("CWE-639",)),
            ),
            tactic="privilege-escalation",
        )
        # findings 以 (cwe_tuple, asset) 元组模拟 P2b 的 ConfirmedFinding 投影
        findings = (
            (("CWE-287",), "http://app/login"),
            (("CWE-639",), "http://app/api/profile"),
        )
        assert match_template(template, findings) is True

    def test_no_match_when_link_missing(self) -> None:
        template = AttackChainTemplate(
            id="authz-to-priv",
            name="auth bypass -> IDOR",
            links=(
                ChainLinkSpec(cwe_any=("CWE-287",)),
                ChainLinkSpec(cwe_any=("CWE-639",)),
            ),
            tactic="privilege-escalation",
        )
        findings = ((("CWE-287",), "http://app/login"),)
        assert match_template(template, findings) is False


class TestDefaultTemplates:
    def test_first_batch_covers_five_patterns(self) -> None:
        templates = default_chain_templates()
        ids = {t.id for t in templates}
        assert {
            "ssrf-to-cloud-creds",
            "auth-bypass-plus-idor",
            "sqli-to-credential-theft",
            "xss-to-session-theft",
            "weak-creds-to-admin-takeover",
        } <= ids
```

- [ ] **5.2 运行确认失败** → 5.3 **实现** `src/secopent/domain/findings/chain_templates.py`：

```python
# src/secopent/domain/findings/chain_templates.py
"""AttackChainTemplate: curated attack-chain link patterns (spec §9, P1a③).

Deterministic curation content: a template is an ordered list of link specs
(matched by CWE family and optional asset pattern). P2b's ChainEngine uses
them as one of three hypothesis sources. Templates never confirm anything -
every link must still be backed by an oracle-confirmed finding (LLM边界).
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ..common.errors import DomainValidationError


@dataclass(frozen=True, slots=True)
class ChainLinkSpec:
    """One link in a chain template: CWE family (+ optional asset pattern)."""

    cwe_any: tuple[str, ...]
    asset_pattern: str = ""  # substring match on finding asset ("" = any)


@dataclass(frozen=True, slots=True)
class AttackChainTemplate:
    id: str
    name: str
    links: tuple[ChainLinkSpec, ...]
    tactic: str  # ATT&CK tactic label (curation metadata)

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError(
                "AttackChainTemplate.id must be non-empty"
            )
        if len(self.links) < 2:
            raise DomainValidationError(
                "AttackChainTemplate needs at least 2 links"
            )


def match_template(
    template: AttackChainTemplate,
    findings: Sequence[tuple[tuple[str, ...], str]],
) -> bool:
    """Order-preserving subsequence match of link specs over findings.

    ``findings`` items are ``(cwe_tuple, asset)`` projections of confirmed
    findings. Each link spec must match a finding AFTER the previous link's
    match position; CWE match = set intersection; asset_pattern = substring.
    """
    position = 0
    for link in template.links:
        matched = False
        for index in range(position, len(findings)):
            cwes, asset = findings[index]
            if not (set(link.cwe_any) & set(cwes)):
                continue
            if link.asset_pattern and link.asset_pattern not in asset:
                continue
            position = index + 1
            matched = True
            break
        if not matched:
            return False
    return True


def default_chain_templates() -> tuple[AttackChainTemplate, ...]:
    """First curated batch (spec §9 链模板示例 + 行业常见链)."""
    return (
        AttackChainTemplate(
            id="ssrf-to-cloud-creds",
            name="SSRF -> cloud metadata -> credential leak",
            links=(
                ChainLinkSpec(cwe_any=("CWE-918",)),
                ChainLinkSpec(
                    cwe_any=("CWE-918", "CWE-200"),
                    asset_pattern="169.254.169.254",
                ),
                ChainLinkSpec(cwe_any=("CWE-522", "CWE-312", "CWE-200")),
            ),
            tactic="credential-access",
        ),
        AttackChainTemplate(
            id="auth-bypass-plus-idor",
            name="Authentication bypass -> IDOR horizontal escalation",
            links=(
                ChainLinkSpec(cwe_any=("CWE-287", "CWE-288")),
                ChainLinkSpec(cwe_any=("CWE-639", "CWE-284")),
            ),
            tactic="privilege-escalation",
        ),
        AttackChainTemplate(
            id="sqli-to-credential-theft",
            name="SQL injection -> credential dump -> credential stuffing",
            links=(
                ChainLinkSpec(cwe_any=("CWE-89",)),
                ChainLinkSpec(cwe_any=("CWE-256", "CWE-312", "CWE-200")),
                ChainLinkSpec(cwe_any=("CWE-798", "CWE-640")),
            ),
            tactic="credential-access",
        ),
        AttackChainTemplate(
            id="xss-to-session-theft",
            name="Stored XSS -> session token theft -> account takeover",
            links=(
                ChainLinkSpec(cwe_any=("CWE-79",)),
                ChainLinkSpec(cwe_any=("CWE-384", "CWE-614")),
                ChainLinkSpec(cwe_any=("CWE-287",)),
            ),
            tactic="collection",
        ),
        AttackChainTemplate(
            id="weak-creds-to-admin-takeover",
            name="Weak credentials -> admin panel -> privilege abuse",
            links=(
                ChainLinkSpec(cwe_any=("CWE-521", "CWE-798")),
                ChainLinkSpec(cwe_any=("CWE-269", "CWE-285")),
            ),
            tactic="privilege-escalation",
        ),
    )
```

- [ ] **5.4 运行确认通过** → **5.5 提交**：`feat(domain): attack chain templates + matcher (P1a Task 5)`

---

## Task 6：文档 + 质量门

- [ ] **6.1 修改** `docs/architecture/knowledge-layer.md`：策展子层追加"攻击手册（handbooks）"条目（来源、provenance、许可证归属、消费方：planner 上下文/case 编写/P2b 链模板）。
- [ ] **6.2 全量质量门**：`py -3.12 -m pytest -q` + `ruff check src tests` + `mypy src` + `git diff --check`。
- [ ] **6.3 提交**：`docs: handbook curation layer + P1a quality gate`

---

## DoD

- [ ] HandbookRegistry 加载 ≥8 份手册，schema 校验拒绝缺 provenance / verification_hint 的文件
- [ ] 每份手册 provenance 指向 Strix 源文件 + Apache-2.0；LICENSE-THIRD-PARTY.md 归属就位
- [ ] 扩展 catalog 新版本号；默认类一个不少（覆盖率不退化断言绿）
- [ ] 4 份 case 种子可被 `case_from_mapping` 解析，status=draft、verification 完整
- [ ] 链模板 ≥5 条；match_template 顺序子序列匹配语义测试绿
- [ ] 全量测试 + lint + type 绿

## 已知注意

- 手册内容转译是人工策展动作：本计划的规则约束提取方式，执行者需逐份阅读 Strix 源 md 后产出 YAML（不可凭空编造攻击面条目）。
- 竞态/走私等 case 种子受现有动词限制，允许"骨架 + 设计留白注释"，不算实现占位。
- `_tc` 跨模块引用若触发 ruff 私有访问告警，在 extended_catalog 内建同款 helper。
