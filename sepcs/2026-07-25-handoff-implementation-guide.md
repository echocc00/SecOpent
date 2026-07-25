# SecOpent 实现交接指南（给下个开发模型）

> **目的**：让接手的模型清楚当前进度、接下来具体做什么、怎么做、如何验收。
> **原模型**：完成本指南后换模型开发 M1 剩余 + M2-M5，全部完成后原模型回来验收。
> **最后更新**：2026-07-25（M1 Task 12 部分完成时）

---

## 1. 当前状态（接手第一件事：确认此状态）

### 仓库
- 路径：`F:\claudepc\SecOpent`（git 仓库，Apache-2.0）
- shell cwd 提示：会话 cwd 是 `F:\claudepc\opencut002`，但代码在 `F:\claudepc\SecOpent`。所有 bash 命令用 `cd /f/claudepc/SecOpent && ...` 形式（shell 会在命令间重置 cwd）。

### 已完成
- **M0 地基+确定性脊柱**：✅ 完整完成（12 任务 TDD，54 测试，ruff/mypy strict clean）
- **M1 Task 1-11**：✅ 完成（TestCatalog/CoverageMatrix/Intel/Adapter Contracts/Repository/IntelSources/UpdateManager/HealthMonitor/AdapterRunner/资产测绘 Pack/Web-API Pack/网络主机 Pack）
- **M1 Task 12 云容器 Pack**：⚠️ 部分完成（4/5 adapter 已提交：prowler/trivy/kube_bench/checkov；scoutsuite + 测试文件未完成）

### 当前测试与质量
- `py -3.12 -m pytest -q`：**306 passed**（master 绿）
- `py -3.12 -m ruff check src tests`：All checks passed
- `py -3.12 -m mypy src/secopent/domain src/secopent/application`：Success, 35 source files strict clean
- 最新 commit：`947a266 feat(adapters): add 4 cloud container adapters`

### 未提交的 WIP（在仓库里但未 commit）
- `tests/adapter_contract/test_cloud_container_adapters.py.wip`（Task 12 测试文件，18 pass / 17 fail，重命名为 .wip 避免被 pytest 收集）
- 已删除：`src/secopent/integrations/adapters/scoutsuite/`（空目录，待重做）

### 验证命令（接手后先跑一遍确认）
```bash
cd /f/claudepc/SecOpent && py -3.12 -m pytest -q && py -3.12 -m ruff check src tests && py -3.12 -m mypy src/secopent/domain src/secopent/application && git log --oneline | head -20
```

---

## 2. 环境约束

| 项 | 状态 | 影响 |
|---|---|---|
| Python | 3.12.10（`py -3.12`） | 用 StrEnum / PEP 604 / `datetime.UTC` |
| Git | 2.54 | 正常 |
| Docker | ❌ 未安装 | Adapter 执行测试全 mock；真实容器执行推迟到 M5 E2E |
| nuclei/nmap/subfinder 等工具 | ❌ 未安装 | Adapter parser 测试用 fixture 文件（sample 工具输出）；真实工具执行 M5 |
| 子代理（Agent tool） | ✅ 可用（subagent-driven 模式验证过） | 但有 5 小时配额限制，注意用量 |
| 网络 | 国内，OSV/KEV/EPSS 可达，NVD 503 | Intel source 测试全 mock 网络（httpx.MockTransport） |

**关键约束**：domain/ 和 application/ 层禁止导入 fastapi/sqlalchemy/httpx/docker/mcp/cryptography（`tests/test_architecture_boundaries.py` AST 守卫强制）。infrastructure/ 层可用 SQLAlchemy/httpx/cryptography。

---

## 3. 文件地图（所有资料位置）

### 设计文档（`F:\claudepc\SecOpent\sepcs\`）
| 文件 | 内容 |
|---|---|
| `2026-07-25-catalog-driven-agent-workbench-design.md` | 主设计 §1-§24（定位/边界/脊柱/目录驱动/领域模型/分层/知识层/四域Adapter/验证/情报/POC/数据部署安全/里程碑/风险/DoD/取舍/旧设计/评审吸收/术语表/商业定位/文档结构/引用） |
| `2026-07-25-architecture-detail.md` | 6 张 Mermaid 图（三方分工/Assessment 流程/Update 同步/Scope 链/AppModel 状态机/确定性脊柱） |
| `2026-07-25-roadmap.md` | 路线图（M0-M5 + 风险 + DoD + Out of Scope + V2 预留） |
| `2026-07-25-decisions.md` | 17 条 ADR（含 Context/Decision/Consequences/Rejected alternatives） |
| `2026-07-25-m0-foundation-plan.md` | M0 完整 TDD 计划（已完成，可作 TDD 风格参考） |
| `2026-07-25-m1-knowledge-adapter-plan.md` | M1 任务级计划（14 任务） |
| `2026-07-25-m2-verification-case-engine-plan.md` | M2 任务级计划（13 任务） |
| `2026-07-25-m3-model-driven-logic-plan.md` | M3 任务级计划（12 任务） |
| `2026-07-25-m4-agent-interface-report-plan.md` | M4 任务级计划（13 任务） |
| `2026-07-25-m5-security-beta-plan.md` | M5 任务级计划（14 任务） |
| `2026-07-24-*.md`（4 份） | 旧设计，已取代，仅参考 |
| `2026-07-25-m0-domain-policy-baseline.md` | 旧 M0 计划，已取代 |

### 代码（`F:\claudepc\SecOpent\src\secopent\`）
```
domain/                    # 框架无关（AST 守卫强制）
  common/canonical.py      # canonical_json, canonical_digest (sha256:), utc_now
  common/errors.py         # DomainError, DomainValidationError
  projects/models.py       # Project, ProjectStatus
  scope/normalize.py       # normalize_domain/ip_or_network/url/port
  scope/models.py          # ScopeDraft, ScopeSnapshot (Deny优先), ScopeLimits
  policy/models.py         # RiskClass(Passive/Low/Active/Intrusive/Destructive), ExecutionMode, PolicyDecision, ActionRequest
  policy/engine.py         # evaluate() 决策顺序: Destructive->scope->risk->capability->ALLOWED
  assessments/models.py    # Assessment, ExecutionPlan(DAG环检测), PlanStep, Approval, AssessmentStatus
  audit/models.py          # AuditEvent (hash chain + verify_chain 篡改检测), GENESIS_HASH
  catalog/models.py        # AssetType, RequiredTestClass, TestCatalog (M1)
  catalog/coverage.py      # CoverageMatrix, coverage_rate() (M1)
  intel/models.py          # Vulnerability, AffectedProduct, ExploitationSignal, DetectionMapping (M1)
  intel/provenance.py      # Provenance (M1)
  adapters/contracts.py    # AdapterManifest, AdapterInput, AdapterOutput, Observation, Severity, CoverageDomain (M1)
  updates/models.py        # UpdateBundle (M1)
application/               # 框架无关（AST 守卫强制）
  ports/repositories.py    # Protocol: Project/Scope/Assessment/Audit Repository, BundleFetcher, SignatureVerifier, BundleRepository
  audit.py                 # AuditService (record, verify)
  projects.py, scopes.py, assessments.py  # Services
  updates.py               # UpdateManager (sync, staging, activate, rollback) (M1)
  health.py                # KnowledgeHealthMonitor (5 detectors + 覆盖率退化门禁 选项D) (M1)
infrastructure/            # 可用 SQLAlchemy/httpx/cryptography
  db/sqlite.py             # create_sqlite_engine (WAL/foreign_keys/busy_timeout)
  db/core_models.py        # CoreBase + 6 M0 ORM 表
  db/catalog_models.py     # CoreTestCatalog, CoreCoverageMatrix (M1)
  db/intel_models.py       # CoreVulnerabilities + FTS5 (M1)
  db/update_models.py      # CoreUpdateBundle, CoreBundleActivation (M1)
  repositories/sqlalchemy_core.py      # M0 Repository 实现
  repositories/sqlalchemy_catalog.py   # M1 Catalog Repository
  repositories/sqlalchemy_intel.py     # M1 Intel Repository (FTS5 search)
  intel_sources/__init__.py            # OsvClient/KevClient/EpssClient/NvdProxyClient/SourceSync (M1, 全 mock 测试)
  signing/ed25519.py                   # Ed25519SignatureVerifier (M1)
  adapters/base.py                     # AdapterRunner (scope强制+容器执行+归一化), ContainerExecutor Protocol, ScopeDeniedError (M1)
integrations/adapters/      # Adapter Pack 实现（M1）
  _common.py               # safe_jsonl_load helper
  subfinder/, httpx/, naabu/, katana/, fingerprinthub/   # 资产测绘 Pack (Task 9)
  nuclei/, dalfox/, restler/, schemathesis/, zap/        # Web-API Pack (Task 10)
  nmap/, nuclei_tcp/                                      # 网络主机 Pack (Task 11)
  prowler/, trivy/, kube_bench/, checkov/                # 云容器 Pack (Task 12, 4/5 已提交)
  # scoutsuite/ 待做
```

### 测试（`F:\claudepc\SecOpent\tests\`）
- `test_architecture_boundaries.py` - 框架守卫（domain/application 禁导入 fastapi/sqlalchemy/httpx/docker/mcp/cryptography）
- `domain/` - 领域单元测试
- `application/` - 应用服务测试（含 conftest.py memory_repositories fixture）
- `infrastructure/` - SQLite/Repository/IntelSources 测试
- `adapter_contract/` - Adapter parser 契约测试（5 fixture 类 × adapter）
- `test_docs_consistency.py` - 文档一致性测试

### 配置
- `pyproject.toml` - ruff (E/F/I/B/UP/SIM) + mypy (strict for domain/application) + pytest (pythonpath=src)
- 依赖：sqlalchemy>=2.0, httpx>=0.27, cryptography>=42.0；dev: pytest/pytest-cov/ruff/mypy

---

## 4. 接下来要做的（按顺序，含详细 spec）

### 4.1 M1 Task 12 收尾（云容器 Pack，当前阻塞点）

#### 4.1.1 cloud-account scope 设计缺口（必须先解决）

**问题**：M0 `ScopeSnapshot` 只能规范化 URL/IP/domain（`scope/normalize.py` 的 `_normalize_target` 走 url->ip->domain 三步，cloud-account ID 如 `aws:123456789012` 三步全失败，触发 `DomainValidationError`）。云适配器的目标是 cloud-account ID，无法走网络 scope。

**解决方案 B（推荐，AdapterRunner 按域分流 + ScopeSnapshot 扩展 cloud_accounts 字段）**：

1. **扩展 M0 domain/scope**（最小改动）：
   - `domain/scope/normalize.py` 加 `normalize_cloud_account(value: str) -> str`：规范化 `provider:account_id` 格式（如 `aws:123456789012`），小写 provider，校验非空。
   - `domain/scope/models.py` 的 `ScopeDraft` 加字段 `cloud_accounts: tuple[str, ...] = ()`；`ScopeSnapshot` 加字段 `cloud_accounts: tuple[str, ...]`；加方法 `includes_cloud_account(value: str) -> bool`（Deny 优先：不在 exclude 且在 include cloud_accounts）。
   - `freeze()` 规范化 cloud_accounts 入 digest。
   - **测试**：扩展 `tests/domain/test_scope.py` 加 cloud_accounts 用例（含/不含、Deny 优先、规范化）。注意：现有 ScopeSnapshot 测试不能回归（加字段要有默认值）。
   - **mypy strict**：domain 层必须保持 strict clean。

2. **AdapterRunner 按域分流**（`infrastructure/adapters/base.py`）：
   - `_enforce_scope(target, manifest, scope_snapshot)`：
     - 若 `manifest.coverage_domain` 含 `cloud` 或 target 匹配 cloud-account 格式（`provider:account_id`）-> 调 `scope_snapshot.includes_cloud_account(target)`
     - 否则 -> 走 M0 逻辑（PolicyEngine.evaluate + includes_url/port）
   - PolicyEngine 对 cloud 域：cloud 目标不走 port/url 校验，只走 cloud_accounts 校验 + risk/capability（可加 `evaluate_cloud` 或在 AdapterRunner 内联判断，不强制走 PolicyEngine）。
   - **测试**：扩展 `tests/infrastructure/test_adapter_runner.py` 加 cloud 目标用例（in-scope cloud 通过、out-of-scope cloud 拒绝）。

3. **修测试 fixture**（`tests/adapter_contract/test_cloud_container_adapters.py.wip` -> 改回 `.py`）：
   - `scope_snapshot` fixture 的 `include` 改为 `("example.com", "10.0.0.0/24")` + `cloud_accounts=("aws:123456789012",)`（用新字段，不塞进 include）。
   - timeout 测试：target `("aws:123456789012",)` 在 cloud_accounts 内 -> 通过 scope -> executor 跑 -> timeout。
   - scope_deny 测试：target `("aws:999999999999",)` 不在 cloud_accounts -> ScopeDeniedError。

#### 4.1.2 实现 scoutsuite adapter

- `src/secopent/integrations/adapters/scoutsuite/__init__.py`：manifest（license="GPL-2.0-or-later", permissions 含 "independent_process", coverage_domain=(cloud,), risk_class=Passive）+ `parse(stdout, source, artifacts) -> tuple[Observation,...]`（解析 ScoutSuite JSON findings -> Observation, coverage_domain=cloud）。
- `fixtures/`：positive.json（sample ScoutSuite findings）、negative.json（空）、timeout.txt、malformed.json。
- 参照 prowler/checkov 的 __init__.py 模式（已提交的 4 个 adapter 之一）。

#### 4.1.3 修 checkov malformed 测试

- 检查 `checkov/__init__.py` 的 `parse` 对 malformed JSON 是否返回空 tuple（不 crash）。若 crash，加 try/except 返回 `()`。参照 `_common.py` 的 `safe_jsonl_load` 模式。

#### 4.1.4 验收（M1 Task 12）
- `py -3.12 -m pytest -q tests/adapter_contract/test_cloud_container_adapters.py` 全绿（5 adapter × 5 fixture + manifest 测试）
- 全套 `py -3.12 -m pytest -q` 无回归（306 + 新 cloud 测试）
- ruff/mypy strict clean
- commit：`feat(adapters): complete cloud container adapter pack with scoutsuite and cloud scope`

---

### 4.2 M1 Task 13: CoverageService

**目标**：给定 Assessment 的所有 Observation，算覆盖矩阵（哪些必修测试类已执行），覆盖率报告，0 未执行必修类门禁。

**Files**：
- `src/secopent/application/coverage.py` - CoverageService
- `tests/application/test_coverage_service.py`

**实现 spec**：
1. `CoverageService` 类，依赖 `CatalogRepository`（查 TestCatalog 必修类）+ `ObservationRepository`（查 Assessment 的 Observations，M4 才有持久化，M1 用 in-memory list 输入）。
2. `compute(asset_type: AssetType, observations: list[Observation], catalog: TestCatalog) -> CoverageReport`：
   - 查 catalog.required_for(asset_type) -> 必修测试类集合
   - 对每个必修类，检查 observations 是否有匹配（按 cwe/owasp 匹配 Observation 的 cwe/owasp tuple）
   - 标记 covered / uncovered
   - CoverageReport（frozen dataclass: asset_type, required_classes, covered_classes, uncovered_classes, coverage_rate）
3. `enforce_gate(report: CoverageReport) -> None`：若有 uncovered_classes -> raise CoverageGapError（0 未执行必修类才能结题）。
4. **测试**：
   - 给定 asset_type=WEB_APP + catalog 必修 [sqli(CWE-89), xss(CWE-79), ssrf(CWE-918)] + observations 含 CWE-89 + CWE-79 -> CoverageReport uncovered=[ssrf], rate=2/3
   - enforce_gate：有 uncovered -> raise；全 covered -> 通过
   - 空 observations -> 全 uncovered -> raise

**验收**：
- 测试全绿，全套无回归，ruff/mypy strict clean
- commit：`feat(coverage): add coverage service with gate`

---

### 4.3 M1 Task 14: 质量门 + 文档

**目标**：M1 收尾，质量门全绿 + 文档同步。

**Files**：
- `docs/architecture/knowledge-layer.md`（新建）
- `docs/adapters/`（每 adapter 一个 README，或一个总 README）
- `tests/test_docs_consistency.py`（扩展）

**步骤**：
1. 扩展 `tests/test_docs_consistency.py`：加测试 `test_knowledge_layer_doc_exists`、`test_adapters_doc_exists`、`test_readme_mentions_m1_complete`
2. 写 `docs/architecture/knowledge-layer.md`：四子层结构 + 来源 + 维护 + 退化门禁
3. 写 `docs/adapters/README.md`：4 域 adapter 清单 + manifest 契约 + fixture 说明
4. 更新 `README.md`：M1 状态
5. 全质量门：
   - `py -3.12 -m pytest -q --cov=src --cov-fail-under=70`（M1 目标 70%，逐步提 80）
   - `py -3.12 -m ruff check src tests` 0 errors
   - `py -3.12 -m mypy src/secopent/domain src/secopent/application` 0 errors strict
   - `py -3.12 -m compileall -q src tests` exit 0
   - `git diff --check` clean
6. **验收**：M1 DoD 全达标（见 §5.2）
7. commit：`docs(m1): close knowledge layer and adapter pack baseline` + `git tag v0.1.0-m1`

---

### 4.4 M2 验证+用例引擎（8-12 天，13 任务）

**计划文件**：`sepcs/2026-07-25-m2-verification-case-engine-plan.md`（任务级，按它执行）

**M0/M1 landed 模式参考**（M2 必须遵循）：
- frozen dataclass + slots（domain 层）
- canonical_digest 版本化
- DomainValidationError 校验
- Protocol port（application 层）+ SqlAlchemy 实现（infrastructure 层），保持 domain/application 框架无关
- Adapter 契约（M1 Task 3 的 Observation schema）+ fixture 测试模式
- 子代理 TDD：写测试 -> RED -> 实现 -> GREEN + ruff + mypy -> commit

**M2 关键集成点**：
- OracleEngine 采纳 pentest-ai（`pip install ptai`，MIT，决策 22）。若 ptai 不可装/不可用，用 ptai 的范式自建（N/N 复证 + canary token + 证据胶囊），但优先采纳。
- VerificationMethodRegistry 是策展层（domain，产品 IP）覆盖在 ptai 之上。
- 自托管 Interactsh（决策 H4，国内公共 OOB 不稳）。M2 锁定方案：Docker 部署 interactsh-server（若 Docker 不可用，测试用 mock InteractshClient，真实部署 M5）。
- oracle ground-truth 靶场集（Juice Shop/crAPI/vulhub）：M2 起 docker-compose 靶场（若 Docker 不可用，测试用 fixture 模拟靶场输出，真实靶场回归 M5）。
- CaseEngine YAML DSL：Nuclei YAML 兼容 + 扩展（canary_token/verification/classification）。AST 解析不用 eval。
- PythonPluginSandbox：M2 锁定 seccomp profile（gVisor 需内核支持，Lite 2C2G 不友好）。若 Docker 不可用，测试用 mock sandbox，真实沙箱 M5。
- Evidence 三层 RAW/REDACTED/SUMMARY + RedactionEngine（regex 库 + 我方/目标 secret 区分）。

**M2 注意**：ptai/Interactsh/Docker/靶场 在当前环境可能不可用。策略：domain/application 层先做完（纯 Python，可测），infrastructure 层（ptai adapter/Interactsh client/sandbox）用 Protocol + mock 测试。真实集成 M5 E2E。

**M2 验收**：见 `sepcs/2026-07-25-m2-verification-case-engine-plan.md` 的"M2 最终验收"清单 + `roadmap.md` DoD。

---

### 4.5 M3 模型驱动逻辑测试（3-5 天，12 任务）

**计划文件**：`sepcs/2026-07-25-m3-model-driven-logic-plan.md`

**关键**：
- LogicTestGenerator 编排层（决策 23）：采纳 RESTler（跳步/乱序/重放）+ Schemathesis（越界）+ 自建不变量违反。signature 幂等（sha256(app_model_digest + test_class + generation_strategy_version)）。
- AppModel domain（状态机+不变量+字段信任边界+角色+幂等性），Ed25519 签名（cryptography，infrastructure 层）。
- ModelBuilder 后端 API（M4 做 Web UI）：有文档路径（OpenAPI/Postman/GraphQL/gRPC 导入）+ 无文档路径（流量录制 + LLM 起草）。LLM 起草经 RemoteModelGateway（M5 才完整，M3 先建 Gateway 接口 + mock LLM）。
- DriftDetector：重新导入 diff。
- RESTler/Schemathesis 作为 Adapter（M1 Task 10 已加 adapter 骨架，M3 调用它们生成 Case）。

**M3 验收**：5 类测试生成 + signature 幂等 + 漂移检测。见 plan 文件。

---

### 4.6 M4 Agent 接口+编排+报告+Web（8-12 天，13 任务）

**计划文件**：`sepcs/2026-07-25-m4-agent-interface-report-plan.md`

**关键**：
- MCP Server：自写编排 tool + 采纳 cve-mcp-server/mcp-security-hub（标 trust level，决策 M8）。MCP Python SDK（`pip install mcp`）。
- CLI：Typer。
- FastAPI OpenAPI：长任务 SSE。
- Web Case Studio：HTMX 或 React。M3 后端 API + M4 Web UI。
- Planner：从 TestCatalog + AppModel 生成确定性 DAG（agent 只加不减）。
- Orchestrator：V1 单机 + DB Job Lease（远程 Worker 推 V2，决策 O1=B）。
- ReportRenderer：Jinja2 模板数据驱动 + Redaction 延伸（M2 RedactionEngine 在渲染层再过）。
- FindingCorrelation：确定性指纹去重（资产+CWE/CVE+路径+参数）。

**M4 验收**：agent 端到端编排 + 覆盖矩阵门禁 + 报告数据驱动 + Case Studio 可用。见 plan 文件。

---

### 4.7 M5 安全加固+Beta（10-15 天，14 任务）

**计划文件**：`sepcs/2026-07-25-m5-security-beta-plan.md`

**关键**：
- ScopeEnforcer 10 步执行链（含 DNS 二次校验防 rebinding）+ API/执行层双校验
- ExecutionPermit Ed25519 签名 + nonce + 短时
- SecretStore（keyring/加密文件/KMS）
- AuditChain 完整（密钥管理 + Permit nonce + Log rotation 续链 + GDPR 保留，从 M0 hash chain 升级）
- EmergencyStop
- RemoteModelGateway（分级+脱敏+授权+审计+LLM 运营约束 §12.11：本地优先 Ollama/vLLM + 远程可选，预算/限速/降级）
- PromptInjectionGuard
- Scoped Egress 完整（HTTP 代理 + TCP netns + nftables + 云 metadata 必阻）
- PostgreSQL Contract 切换验证（Repository 抽象 M0 预留，M5 验证切 PG 不重构）
- E2E（Juice Shop/crAPI/httpbin，需 Docker）
- 14 安全条件（§16.2）
- STRIDE 威胁建模归档
- CI（GitHub Actions：ruff/mypy/pytest/compose smoke/编码卫生）

**M5 验收 = V1 Beta DoD**：见 `sepcs/2026-07-25-m5-security-beta-plan.md` 的"M5 最终验收"（35 项）+ `roadmap.md` DoD。`git tag v0.1.0-beta1`。

---

## 5. 验收标准

### 5.1 各里程碑 DoD
- **M0**（已完成）：见 `m0-foundation-plan.md`，54 测试 + ruff/mypy clean
- **M1**：4 域工具可执行（parser 测过）+ 输出归一化 Observation + 覆盖矩阵可算 + 情报可查 + 每 adapter 5 类 fixture 契约测试通过
- **M2**：oracle N/N 生效（采纳 ptai）+ YAML Case 可执行 + Python 沙箱隔离 + 风险分析门禁 + oracle 靶场集回归
- **M3**：模型可建可签 + 5 类测试自动生成 + signature 幂等 + 漂移可检测
- **M4**：agent 端到端编排 + 覆盖矩阵门禁 + 报告数据驱动 + Case Studio 可用
- **M5**：14 安全条件全过 + E2E 绿 + PG Contract + STRIDE + CI + Lite 2C2G 可跑

### 5.2 V1 Beta 最终 DoD（§15，35 项）
见 `sepcs/2026-07-25-catalog-driven-agent-workbench-design.md` §15 或 `roadmap.md` §3。全部 35 项打勾 = V1 Beta。

### 5.3 每个任务的验收（TDD 通用）
- 写测试（RED 确认）
- 实现
- GREEN（测试通过）
- `py -3.12 -m ruff check src tests` 0 errors
- `py -3.12 -m mypy src/secopent/domain src/secopent/application` 0 errors strict（domain/application 层）
- 全套 `py -3.12 -m pytest -q` 无回归
- `git diff --check` clean
- commit（conventional commits：feat/refactor/test/docs/...）

---

## 6. 执行方式（subagent-driven + TDD）

### 6.1 模式
- 每个任务派一个子代理（Agent tool，subagent_type=general-purpose）实现
- 实现后主会话内联验证（跑测试 + ruff + mypy + git log）
- 简单任务内联验证即可；复杂任务派 spec review + code review 子代理
- 连续执行，不在任务间停（除非 BLOCKED 或配额超限）

### 6.2 子代理 prompt 模板（已验证有效）
```
You are implementing M{X} Task {N} of the SecOpent project.

## Context
- Repo root: `F:\claudepc\SecOpent` ({当前测试数} tests passing)
- Python: 3.12 (`py -3.12`), Shell: Git Bash (`cd /f/claudepc/SecOpent && ...`)
- Plan file: `F:\claudepc\SecOpent\sepcs\2026-07-25-m{X}-{name}-plan.md` (read Task {N} section)
- Main design §{相关节}
- M0/M1 landed patterns: frozen dataclass + slots, canonical_digest, DomainValidationError, Protocol port + SqlAlchemy impl

## Task
Execute **Task {N}: {name}** from the plan, TDD strictly:
1. Step 1: Create {test file} with tests covering {spec}
2. Step 2: Run pytest -> verify RED
3. Step 3: Implement {files} with {key code/patterns}
4. Step 4: Run pytest -> GREEN + full suite no regression + ruff + mypy strict
5. Step 5: Commit `git add ... && git commit -m "feat(...): ..."`

## Critical rules
- Domain/application 层 stdlib + secopent.* only (NO frameworks - test_architecture_boundaries enforces)
- {其他关键约束}

## Report
Report: (1) RED confirmed, (2) GREEN count + full suite, (3) ruff, (4) mypy, (5) commit hash.
```

### 6.3 配额注意
- 子代理有 5 小时配额限制。若遇 429，等配额重置（错误消息会给时间）后继续。
- 主会话内联编辑不受子代理配额影响，但大量编辑也会消耗主会话配额。
- 策略：优先用子代理（隔离上下文），配额紧时主会话内联处理小任务。

---

## 7. 关键设计决策（已锁定，勿改）

见 `sepcs/2026-07-25-decisions.md` 17 条 ADR。摘要：
1. 推倒重来（非渐进）
2. 混合框架脊柱（非纯 agent/纯框架）
3. 目录驱动覆盖（TestCatalog，agent 只加不减）
4. oracle N/N 验证（非 LLM 判定）
5. 模型驱动逻辑测试（非方法论门禁）
6. Nuclei YAML 基础+扩展（非自研 DSL）
7. MCP 采纳优先（非全自写）
8. OSV 主源（非 NVD，国内 503）
9. 聚合层 + CoverageMatrix 开源；TestCatalog/AppModel/OracleEngine 产品 IP
10. A 全架构 + O1/O3 缩范围（远程 Worker V2，逻辑测试 5 类）
11. 远程 Worker 推 V2（O1=B）
12. LogicTestGenerator 5 类（采纳 RESTler+Schemathesis，O3=B 调整后覆盖 5 类）
13. CoverageMatrix 开源（O4=B）
14. OracleEngine 采纳 pentest-ai（非自建）
15. V1 市场实验定位（非直接 ToB）
16. Audit M0 起步（非 M5）
17. Repository 抽象 M0（非 SQLite-only）
+ cloud-account scope 方案 B（本指南 §4.1.1，M1 Task 12 锁定）

**LLM 边界**（贯穿全程）：LLM 仅提议，确定性层裁决。禁区：Finding 确认（只 oracle）、severity 定级（CVSS 计算）、报告数字（DB 计算）、覆盖率判定（CoverageMatrix）、证据完整性（SHA256）、scope 改动/用例发布/Capability 提升。

---

## 8. 完成后

当 M1 Task 12-14 + M2-M5 全部完成：
1. 跑全套验收：
   ```bash
   cd /f/claudepc/SecOpent && py -3.12 -m pytest -q --cov=src --cov-fail-under=70
   py -3.12 -m ruff check src tests
   py -3.12 -m mypy src/secopent/domain src/secopent/application
   py -3.12 -m compileall -q src tests
   git diff --check
   git log --oneline | head -50
   ```
2. 确认 V1 Beta DoD（§15，35 项）全打勾
3. `git tag v0.1.0-beta1`
4. 通知原模型（我）来验收。原模型会：
   - 跑全套测试 + 质量门
   - 派最终代码审查子代理审整个实现（设计一致性 + 确定性脊柱 + LLM 边界 + 14 安全条件 + E2E）
   - 出验收报告（APPROVE / NEEDS_CHANGES）

---

## 9. 快速参考

### 9.1 常用命令
```bash
# 跑测试
cd /f/claudepc/SecOpent && py -3.12 -m pytest -q
# 跑单个测试文件
cd /f/claudepc/SecOpent && py -3.12 -m pytest -q tests/domain/test_scope.py
# ruff
cd /f/claudepc/SecOpent && py -3.12 -m ruff check src tests
# ruff 自动修
cd /f/claudepc/SecOpent && py -3.12 -m ruff check --fix src tests
# mypy strict（domain+application）
cd /f/claudepc/SecOpent && py -3.12 -m mypy src/secopent/domain src/secopent/application
# git log
cd /f/claudepc/SecOpent && git log --oneline | head -20
# 装依赖（若换环境）
cd /f/claudepc/SecOpent && py -3.12 -m pip install -e ".[dev]"
```

### 9.2 立即下一步（接手后第一件事）
1. 跑 `cd /f/claudepc/SecOpent && py -3.12 -m pytest -q` 确认 306 测试绿
2. 读本指南 §4.1（M1 Task 12 收尾，含 cloud-scope 方案 B）
3. 按 §4.1.1 扩展 ScopeSnapshot 加 cloud_accounts 字段（先改 domain + 测试，再改 AdapterRunner，再修 cloud 测试 fixture，再做 scoutsuite，最后跑全绿 commit）
4. 然后按 §4.2、§4.3、§4.4... 顺序推进

### 9.3 遇到问题时
- **配额超限（429）**：等重置（错误消息给时间），或主会话内联处理小任务
- **Docker/工具不可用**：用 mock + fixture 测试，真实集成 M5
- **设计决策不明**：查 `decisions.md` ADR + 主设计文档对应节
- **cloud-account scope**：按本指南 §4.1.1 方案 B（已锁定）
- **LLM 边界**：查 §7，LLM 永不在裁决位

---

*本指南由原模型编写于 M1 Task 12 部分完成时。接手模型按 §4 顺序推进，全完成后通知原模型验收。*
