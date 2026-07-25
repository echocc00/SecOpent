# M1 知识层+情报+四域 Adapter Pack 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 建立 TestCatalog + CoverageMatrix + IntelStore + UpdateManager + KnowledgeHealthMonitor + 四域 Adapter Pack（资产测绘/Web-API/网络主机/云容器），实现"测什么"知识层 + 引擎执行层，输出归一化 Observation 喂覆盖矩阵。

**Architecture:** TestCatalog/CoverageMatrix 是策展知识层（产品 IP，版本化，per-Assessment 快照）。IntelStore 聚合 OSV/KEV/EPSS（curl 实测 OSV 主源，NVD 503 备用）。Adapter Pack 按 §8 统一契约（manifest+Dockerfile+parser+run.sh+fixtures），每 Adapter 输出归一化 Observation（Faraday 式）。UpdateManager 复用 M0 Repository Contract + Audit hash chain。

**Tech Stack:** Python 3.11+, SQLAlchemy 2.0, SQLite FTS5, httpx, PyYAML, pydantic v2, Docker SDK, ProjectDiscovery 工具链（subfinder/httpx/naabu/katana/nuclei）, nmap, Prowler, Trivy, kube-bench, checkov, ScoutSuite, dalfox, RESTler, Schemathesis.

**DoD（对应主设计 §13 M1）:**
- 4 域工具可执行（资产测绘/Web-API/网络主机/云容器）
- 输出归一化 Observation（§8.3 schema）
- 覆盖矩阵可算（CoverageMatrix 映射 OWASP/CIS）
- 情报可查（IntelStore FTS5 + OSV/KEV/EPSS）
- 每 Adapter 契约测试通过（5 类 fixture：positive/negative/timeout/scope_deny/malformed）

**依赖：** M0 已落地（ScopeSnapshot / PolicyDecision / RiskClass / Repository Contract / AuditEvent）

**参考：** 主设计 §4（目录驱动）/§7（知识层）/§8（四域 Adapter）/§10（情报）；ADR-003/007/008/009

---

## 0. 文件结构

```text
src/secopent/
  domain/
    catalog/
      models.py          # TestCatalog, AssetType, RequiredTestClass
      coverage.py        # CoverageMatrix, FrameworkMapping, CoverageReport
    intel/
      models.py          # Vulnerability, AffectedProduct, ExploitationSignal, DetectionMapping
      provenance.py      # Provenance 字段
    adapters/
      contracts.py       # AdapterManifest, AdapterInput, AdapterOutput, Observation
  application/
    catalog.py           # CatalogService（查必修类）
    coverage.py          # CoverageService（算覆盖率）
    intel.py             # IntelService（查询 + 同步调度）
    updates.py           # UpdateManager（bundle 同步）
    health.py            # KnowledgeHealthMonitor
  infrastructure/
    db/
      catalog_models.py  # core_test_catalog, core_coverage_matrix
      intel_models.py    # core_vulnerabilities, core_affected_products, ...
      update_models.py   # core_update_bundles, core_bundle_activations
    repositories/
      sqlalchemy_catalog.py
      sqlalchemy_intel.py
    intel_sources/
      osv.py             # OSV REST 增量
      kev.py             # CISA KEV JSON
      epss.py            # FIRST EPSS CSV
      nvd_proxy.py       # NVD 经代理（备用）
    adapters/
      base.py            # AdapterRunner（容器执行 + scope 强制）
      parser_base.py     # 归一化 parser 基类
  integrations/
    adapters/
      subfinder/, httpx/, naabu/, katana/, fingerprinthub/
      nuclei/, dalfox/, restler/, schemathesis/, zap/
      nmap/, nuclei_tcp/
      prowler/, trivy/, kube_bench/, checkov/, scoutsuite/
tests/
  domain/test_catalog.py, test_coverage.py, test_intel.py
  application/test_catalog_service.py, test_intel_service.py, test_update_manager.py
  infrastructure/test_intel_sources.py, test_adapter_runner.py
  adapter_contract/
    test_subfinder.py, test_nuclei.py, test_nmap.py, test_prowler.py, test_trivy.py, ...
```

---

## Task 1: TestCatalog Domain + CoverageMatrix

**Files:** `domain/catalog/models.py`, `domain/catalog/coverage.py`, `tests/domain/test_catalog.py`

- [ ] **Step 1: 写失败测试** - AssetType 枚举（WEB_APP/API/IP_PORT/CLOUD_ACCOUNT/CONTAINER_K8S）；TestCatalog 含资产类型->必修测试类映射；CoverageMatrix 映射 OWASP WSTG 条目->测试类；覆盖率 = 映射条目/总条目
- [ ] **Step 2: RED** - import fail
- [ ] **Step 3: 实现** - `TestCatalog(version, mappings: dict[AssetType, tuple[RequiredTestClass,...]])`；`CoverageMatrix(version, framework, mappings: dict[str, tuple[TestClassId,...]], total_items)`；`coverage_rate() -> float`；digest 用 M0 canonical_digest
- [ ] **Step 4: GREEN** - 覆盖率计算 + digest 稳定
- [ ] **Step 5: 提交** `feat(catalog): add test catalog and coverage matrix`

关键代码：
```python
class AssetType(StrEnum):
    WEB_APP = "web_app"; API = "api"; IP_PORT = "ip_port"
    CLOUD_ACCOUNT = "cloud_account"; CONTAINER_K8S = "container_k8s"

@dataclass(frozen=True, slots=True)
class RequiredTestClass:
    id: str; cwe: tuple[str,...]; owasp: tuple[str,...]; risk: RiskClass

@dataclass(frozen=True, slots=True)
class TestCatalog:
    version: str; mappings: dict[AssetType, tuple[RequiredTestClass,...]]
    digest: str  # canonical_digest
    def required_for(self, asset_type: AssetType) -> tuple[RequiredTestClass,...]: ...

@dataclass(frozen=True, slots=True)
class CoverageMatrix:
    version: str; framework: str  # "OWASP_WSTG_4.2"
    mappings: dict[str, tuple[str,...]]  # framework_item_id -> test_class_ids
    total_items: int
    def coverage_rate(self) -> float:
        covered = sum(1 for v in self.mappings.values() if v)
        return covered / self.total_items
```

## Task 2: Intel Domain（4 类实体 + provenance）

**Files:** `domain/intel/models.py`, `domain/intel/provenance.py`, `tests/domain/test_intel.py`

- [ ] **Step 1: 测试** - Vulnerability/AffectedProduct/ExploitationSignal/DetectionMapping 4 实体；每字段带 Provenance(source, fetched_at, source_version)
- [ ] **Step 3: 实现** - 4 个 frozen dataclass；Provenance 字段；alias 去重；CVSS 保留多源（NVD vs 厂商）
- [ ] **Step 5: 提交** `feat(intel): add vulnerability intel entities with provenance`

## Task 3: Adapter Contracts（manifest + input/output + Observation）

**Files:** `domain/adapters/contracts.py`, `tests/domain/test_adapter_contracts.py`

- [ ] **Step 1: 测试** - AdapterManifest（id/version/upstream digest/risk_class/coverage_domain/input_schema/output_schema/network_policy）；AdapterInput（run_id/scope_snapshot/targets/options/execution_policy）；AdapterOutput（status/artifacts/observations/errors）；Observation（§8.3 schema：external_id/asset_identity/source/rule_id/coverage_domain/title/severity/confidence/cwe/cve/owasp/evidence_artifact_ids/raw）
- [ ] **Step 3: 实现** - pydantic v2 models；Observation 强制 cwe/cve/owasp 喂 CoverageMatrix
- [ ] **Step 5: 提交** `feat(adapters): add adapter contracts and observation schema`

## Task 4: Catalog/Intel/Update Repository（SQLite + FTS5）

**Files:** `infrastructure/db/catalog_models.py`, `intel_models.py`, `update_models.py`, `repositories/sqlalchemy_catalog.py`, `sqlalchemy_intel.py`, `tests/infrastructure/test_catalog_intel_repository.py`

- [ ] **Step 1: 测试** - TestCatalog/CoverageMatrix 持久化 + 按 version 查；Vulnerability FTS5 全文检索（by cve/keyword/cwe）；UpdateBundle 激活记录
- [ ] **Step 3: 实现** - CoreTestCatalog/CoreCoverageMatrix/CoreVulnerability/CoreAffectedProduct/CoreExploitationSignal/CoreDetectionMapping/CoreIntelSnapshot/CoreUpdateBundle ORM；SqlAlchemyCatalogRepository/IntelRepository；FTS5 虚拟表（CVE/描述/关键字）
- [ ] **Step 5: 提交** `feat(infra): persist catalog intel with fts5`

## Task 5: Intel Sources 同步（OSV 主源 + KEV + EPSS + NVD 代理）

**Files:** `infrastructure/intel_sources/osv.py`, `kev.py`, `epss.py`, `nvd_proxy.py`, `tests/infrastructure/test_intel_sources.py`

- [ ] **Step 1: 测试** - OSV 增量拉取（last_modified 游标，mock httpx）；KEV JSON 下载（1653 条解析）；EPSS CSV 解析；NVD 代理（503 降级）；每源 provenance 标注
- [ ] **Step 3: 实现** - OsvClient（`api.osv.dev/v1/query`，6h 增量）；KevClient（`cisa.gov/known-exploited-vulnerabilities.json`）；EpssClient（first.org CSV，每日）；NvdProxyClient（经 HTTP 代理，503 降级到 OSV 缓存）；SourceSync 调度器（每源频率）
- [ ] **Step 5: 提交** `feat(intel): sync osv kev epss with provenance`

## Task 6: UpdateManager（bundle 同步 + staging + 原子激活 + 回滚）

**Files:** `application/updates.py`, `tests/application/test_update_manager.py`

- [ ] **Step 1: 测试** - bundle 下载->Staging DB->签名校验->schema 检查->预览 diff->原子激活->旧快照保留->回滚；签名失败拒绝；激活失败回滚
- [ ] **Step 3: 实现** - UpdateManager.sync(source)；StagingDB 暂存；Ed25519 签名校验（cryptography）；schema 兼容检查；原子激活（指针切换）；旧快照保留 30 天；回滚方法；全程 AuditEvent
- [ ] **Step 5: 提交** `feat(updates): add bundle sync with staging and rollback`

## Task 7: KnowledgeHealthMonitor（源停更/策展滞后/覆盖率退化/源失效）

**Files:** `application/health.py`, `tests/application/test_health_monitor.py`

- [ ] **Step 1: 测试** - nuclei-templates 7 天无 commit 告警；nuclei 新增 100 tag 但 TestCatalog 未映射告警；新版覆盖率<旧版阻止发布（选项 D，0 容忍 + override-with-reason）；OSV API 不可达降级缓存；bundle 签名失效告警
- [ ] **Step 3: 实现** - KnowledgeHealthMonitor.check_all()；5 类检测；覆盖率退化门禁（0 容忍，override 需 reason + 路线图 + 审计）
- [ ] **Step 5: 提交** `feat(health): add knowledge health monitor with coverage regression gate`

## Task 8: AdapterRunner（容器执行 + scope 强制 + 产物归一化）

**Files:** `infrastructure/adapters/base.py`, `tests/infrastructure/test_adapter_runner.py`

- [ ] **Step 1: 测试** - AdapterRunner.run(manifest, input) -> output；scope 强制（调 M0 PolicyEngine，scope 外目标阻断）；容器执行（Docker SDK，digest 固定，non-root，cap-drop ALL）；产物上传 CAS（sha256）；Observation 归一化
- [ ] **Step 3: 实现** - AdapterRunner：拉镜像（digest 校验）-> 创建容器（--network=scoped-egress，--user=nonroot，--cap-drop=ALL，--read-only，资源限制）-> 注入 input.json -> 执行 -> 收集 stdout/stderr + artifacts -> parser 归一化 -> 返回 AdapterOutput；scope 强制复用 M0 PolicyEngine.evaluate
- [ ] **Step 5: 提交** `feat(adapters): add container adapter runner with scope enforcement`

## Task 9: 资产测绘 Adapter Pack（subfinder/httpx/naabu/katana/FingerprintHub）

**Files:** `integrations/adapters/subfinder/`（manifest.yaml + Dockerfile + run.sh + parser.py + fixtures/）等 5 个，`tests/adapter_contract/test_subfinder.py` 等

- [ ] **Step 1: 测试** - 每 Adapter 5 类 fixture（positive/negative/timeout/scope_deny/malformed）；parser 输出 Observation（coverage_domain=asset）
- [ ] **Step 3: 实现** - subfinder：`subfinder -d {domain} -json -o /out/subfinder.json`，parser 提取子域 -> Observation（asset_identity=domain）；httpx：`httpx -json -o /out/httpx.json`，parser 提取存活+tech -> Observation；naabu 端口；katana 爬取；FingerprintHub 指纹。每 Adapter Dockerfile 用 PD 官方镜像 digest 固定
- [ ] **Step 5: 提交** `feat(adapters): add asset mapping adapter pack`

## Task 10: Web/API Adapter Pack（nuclei/dalfox/RESTler/Schemathesis + ZAP Standalone-only）

**Files:** `integrations/adapters/nuclei/`, `dalfox/`, `restler/`, `schemathesis/`, `zap/`

- [ ] **Step 1: 测试** - nuclei `-jsonl` 输出解析 -> Observation（cwe/cve/owasp 喂 CoverageMatrix）；dalfox XSS -> Observation；RESTler 序列测试 -> Observation（跳步/乱序/重放类）；Schemathesis boundary -> Observation（越界类）；ZAP 仅 Standalone 标记
- [ ] **Step 3: 实现** - nuclei：`nuclei -l targets.txt -jsonl -o /out/nuclei.jsonl`，parser 映射 template tag->CWE/OWASP；dalfox：`dalfox url {target} --json`;RESTler：`restler_fuzz --grammar_file ...`；Schemathesis：`schemathesis run --openapi ...`；ZAP：被动+主动扫描，Standalone-only manifest 标记
- [ ] **Step 5: 提交** `feat(adapters): add web api adapter pack`

## Task 11: 网络主机 Adapter Pack（nmap+NSE / nuclei TCP）

**Files:** `integrations/adapters/nmap/`, `nuclei_tcp/`

- [ ] **Step 1: 测试** - nmap `-sV -oX /out/nmap.xml` 解析 -> Observation（service/version）；NSE 输出解析；nuclei TCP/dns/ssl 模板；GPL 独立进程容器
- [ ] **Step 3: 实现** - nmap：`nmap -sV -sC -oX /out/nmap.xml -iL /in/targets.txt`，parser XML->Observation（coverage_domain=network）；nmap NSE 结果分类；nuclei TCP 模板
- [ ] **Step 5: 提交** `feat(adapters): add network host adapter pack`

## Task 12: 云容器 Adapter Pack（Prowler/Trivy/kube-bench/checkov/ScoutSuite）

**Files:** `integrations/adapters/prowler/`, `trivy/`, `kube_bench/`, `checkov/`, `scoutsuite/`

- [ ] **Step 1: 测试** - Prowler AWS JSON -> Observation（CIS 检查项）；Trivy 镜像扫描 JSON；kube-bench JSON；checkov IaC；ScoutSuite 多云（GPL 独立进程）
- [ ] **Step 3: 实现** - Prowler：`prowler aws -M json`，parser 映射 CIS 检查项->Observation（coverage_domain=cloud）；Trivy：`trivy image --format json`；kube-bench：`kube-bench --json`；checkov：`checkov -f ... --json`；ScoutSuite 独立进程
- [ ] **Step 5: 提交** `feat(adapters): add cloud container adapter pack`

## Task 13: CoverageService（算覆盖率 + 报告）

**Files:** `application/coverage.py`, `tests/application/test_coverage_service.py`

- [ ] **Step 1: 测试** - 给定 Assessment 的所有 Observation，算覆盖矩阵（哪些必修类已执行）；覆盖率报告生成；0 未执行必修类门禁
- [ ] **Step 3: 实现** - CoverageService.compute(assessment_id) -> CoverageReport；按 asset_type 查 TestCatalog 必修类；匹配 Observation 的 cwe/owasp；标记未覆盖必修类；门禁：0 未执行才能结题
- [ ] **Step 5: 提交** `feat(coverage): add coverage service with gate`

## Task 14: M1 质量门 + 文档

- [ ] ruff/mypy strict（domain/application）+ pytest 全绿 + 契约测试全绿
- [ ] `docs/architecture/knowledge-layer.md` + `docs/adapters/` 每 Adapter README
- [ ] 提交 `docs(m1): close knowledge layer and adapter pack baseline`

---

## M1 最终验收

- [ ] TestCatalog/CoverageMatrix 持久化 + 覆盖率可算
- [ ] IntelStore FTS5 可查（OSV/KEV/EPSS 同步）
- [ ] UpdateManager bundle 同步 + 回滚
- [ ] KnowledgeHealthMonitor 5 类检测 + 覆盖率退化门禁（选项 D）
- [ ] 4 域 Adapter Pack 每个含 5 类 fixture 契约测试
- [ ] AdapterRunner 容器执行 + scope 强制 + 产物归一化
- [ ] CoverageService 覆盖矩阵门禁
- [ ] ruff/mypy/pytest 全绿

## 下一步

M1 通过后，写 M2 验证+用例引擎详细计划。M2 依赖 M1 的 AdapterOutput/Observation + M0 的 Repository/Audit。
