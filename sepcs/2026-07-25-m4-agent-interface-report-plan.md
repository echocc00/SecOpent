# M4 Agent 接口+编排+报告+Web Case Studio 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans.

**Goal:** 实现 MCP Server（自写编排 tool + 采纳 cve-mcp-server/mcp-security-hub，采纳 MCP 标 trust level）+ CLI + Web Case Studio 可视化建模 UI + Planner（确定性 DAG）+ Orchestrator（V1 单机 + DB Lease）+ FindingCorrelation + ReportRenderer（含 Redaction 延伸）+ AssetGraph，实现 agent 端到端编排 + 覆盖矩阵门禁 + 报告数据驱动。

**Architecture:** 接口层 MCP/CLI/Web 共用同一 Application Service。Planner 从 TestCatalog（必修类）+ AppModel（逻辑测试）生成确定性 DAG，agent 只能 ADD 不能 SUBTRACT。Orchestrator V1 单机执行 + DB Job Lease（远程 Worker 推 V2）。ReportRenderer 模板数据驱动，Redaction 延伸到渲染层。Web Case Studio M3 后端 API + M4 Web UI。

**Tech Stack:** Python 3.11+, FastAPI, MCP Python SDK, Typer, Jinja2, React/HTMX（Web）, pydantic v2, SQLAlchemy.

**DoD（对应主设计 §13 M4）:**
- agent 可端到端编排（MCP assessment_start->报告）
- 覆盖矩阵门禁生效（0 未执行必修类才能结题）
- 报告数据驱动 + 脱敏（Redaction 延伸 Report）
- Case Studio 可视化建模可用（M3 后端 + M4 Web UI）

**依赖：** M0（Domain/Policy/Repository/Audit）+ M1（Catalog/Adapter/Observation/CoverageMatrix）+ M2（Case/oracle/Evidence）+ M3（AppModel/LogicTestGenerator）

**参考：** 主设计 §6（分层）/§11（POC）/§12（安全）；ADR-002/007/010/011

---

## 0. 文件结构

```text
src/secopent/
  domain/
    assets/
      models.py          # AssetNode, AssetEdge（关系表，非图数据库）
      graph.py           # AssetGraph（Domain->IP->Port->Service->URL->Endpoint->Technology）
    findings/
      models.py          # Observation, CandidateFinding, ConfirmedFinding, FindingStatus
      fingerprint.py     # 确定性指纹去重（资产+CWE/CVE+路径+参数）
    plans/
      models.py          # ExecutionPlan（M0 已有，扩展 DAG 排课）
    reports/
      models.py          # Report, ReportVersion, ReportStatus
  application/
    planner.py           # Planner（确定性 DAG from TestCatalog + AppModel）
    orchestrator.py      # Orchestrator（V1 单机 + DB Job Lease + 重试/超时/幂等/预算）
    asset_graph.py       # AssetGraphService
    finding_correlation.py  # 确定性指纹去重
    report_renderer.py   # ReportRenderer（模板 + 数据驱动 + Redaction 延伸）
    jobs.py              # JobService（Lease/续租/重领）
  interfaces/
    mcp/
      server.py          # MCP Server（自写编排 tool）
      tools/
        project.py, scope.py, assessment.py, plan.py, approval.py
        asset.py, finding.py, evidence.py, intel.py, report.py, update.py
      adopted/           # 采纳 MCP（cve-mcp-server/mcp-security-hub，trust level 标记）
    cli/
      main.py            # Typer CLI（init/serve/worker/project/scope/assessment/...）
    api/
      main.py            # FastAPI（OpenAPI，长任务 SSE）
      routers/           # projects/scopes/assessments/plans/approvals/workers/jobs/tools/cases/intel/assets/findings/evidence/updates/reports/audit
    web/
      main.py            # Web Case Studio 后端路由
      static/            # 前端（HTMX 或 React）
      templates/         # Dashboard/NewAssessment/AssessmentDetail/ApprovalCenter/Findings/CaseStudio/Updates
  infrastructure/
    db/
      asset_models.py, finding_models.py, report_models.py, job_models.py
      repositories/sqlalchemy_assets.py, sqlalchemy_findings.py, sqlalchemy_reports.py, sqlalchemy_jobs.py
    report_templates/
      report.md.j2, executive_summary.md.j2, coverage_matrix.md.j2
tests/
  application/test_planner.py, test_orchestrator.py, test_finding_correlation.py, test_report_renderer.py
  interfaces/test_mcp_server.py, test_cli.py, test_api.py, test_web.py
```

---

## Task 1: AssetGraph Domain + 关系表

**Files:** `domain/assets/models.py`, `domain/assets/graph.py`, `tests/domain/test_assets.py`

- [ ] **Step 1: 测试** - AssetNode（type/value：Domain/IP/Port/Service/URL/Endpoint/Technology）；AssetEdge（src/dst/rel：resolves_to/exposes/runs/serves/contains/uses）；AssetGraph 添加节点边；查询（按资产找关联）
- [ ] **Step 3: 实现** - frozen dataclass；关系表表达（不引入图数据库）；AssetGraph.add_node/add_edge/query
- [ ] **Step 5: 提交** `feat(assets): add asset graph with relation table`

## Task 2: Finding 流水线 + 确定性指纹去重

**Files:** `domain/findings/models.py`, `domain/findings/fingerprint.py`, `application/finding_correlation.py`, `tests/domain/test_findings.py`

- [ ] **Step 1: 测试** - Observation（M1 已有，扩展 status）；CandidateFinding（observation_id/status）；ConfirmedFinding（evidence_ids/verified_at/oracle_result）；FindingStatus（DRAFT/CANDIDATE/VALIDATED/REPORTED/.../CLOSED）；确定性指纹（资产+CWE/CVE+路径+参数）；跨工具去重
- [ ] **Step 3: 实现** - Finding dataclass + 状态机；Fingerprint.compute(observation) = canonical_digest；FindingCorrelation.dedupe(observations) -> merged findings
- [ ] **Step 5: 提交** `feat(findings): add finding pipeline with deterministic fingerprint`

## Task 3: Planner（确定性 DAG from TestCatalog + AppModel）

**Files:** `application/planner.py`, `tests/application/test_planner.py`

- [ ] **Step 1: 测试** - Planner.generate(assessment_id) -> ExecutionPlan；从 TestCatalog 查资产类型必修类；从 AppModel（若存在）生成逻辑测试；DAG 排课（必修类强制，agent 不能删减）；PlanStep 含 adapter_id/case_id/risk/parameters/dependencies
- [ ] **Step 3: 实现** - Planner 调 CatalogService（M1）查必修类；调 LogicTestGenerator（M3）生成逻辑测试；按资产类型排课；DAG 拓扑排序；digest（M0 canonical_digest）
- [ ] **Step 5: 提交** `feat(planner): add deterministic dag from catalog and appmodel`

## Task 4: Orchestrator（V1 单机 + DB Job Lease）

**Files:** `application/orchestrator.py`, `application/jobs.py`, `infrastructure/db/job_models.py`, `tests/application/test_orchestrator.py`

- [ ] **Step 1: 测试** - Orchestrator.dispatch(plan) -> Jobs；DB Job Lease（idempotency_key/attempt/max_attempts/lease_owner/lease_expires_at/result_digest）；Job 状态（PENDING/BLOCKED/READY/LEASED/RUNNING/SUCCEEDED/FAILED/SKIPPED/POLICY_DENIED）；失败分类（输入非法/超 scope/未审批/Worker 不可用/超时/解析失败）；重试策略（指数退避，有上限）；Job 失联 Lease 过期可重领
- [ ] **Step 3: 实现** - V1 单机执行（不搞分布式，O1=B）；DB Job Lease（SQLite，无 Redis）；JobService.lease/renew/complete/fail；Orchestrator 调 AdapterRunner（M1）执行；重试策略表（§7.3）
- [ ] **Step 5: 提交** `feat(orchestrator): add single machine orchestration with db lease`

## Task 5: MCP Server（自写编排 tool + 采纳 trust level）

**Files:** `interfaces/mcp/server.py`, `interfaces/mcp/tools/*`, `interfaces/mcp/adopted/*`, `tests/interfaces/test_mcp_server.py`

- [ ] **Step 1: 测试** - MCP tool 分 6 组（项目Scope/计划执行/资产/用例工具/漏洞证据/更新报告）；自写 tool：project_create/scope_draft/scope_validate/scope_freeze/plan_generate/plan_approve/assessment_start/pause/resume/cancel/status/asset_list/finding_list/finding_validate/intel_search/report_render；禁止暴露 shell/docker_run/execute_python；采纳 MCP（cve-mcp-server/mcp-security-hub）输出标 untrusted_external_mcp
- [ ] **Step 3: 实现** - MCP Python SDK；tool 注册；每 tool 绑定 Project/Scope/Plan/Policy/Approval/Audit；采纳 MCP wrapper 标 trust level；经 PolicyEngine 校验
- [ ] **Step 5: 提交** `feat(mcp): add mcp server with self-written and adopted tools`

## Task 6: CLI

**Files:** `interfaces/cli/main.py`, `tests/interfaces/test_cli.py`

- [ ] **Step 1: 测试** - 主命令 init/serve/worker/project/scope/assessment/tool/case/intel/update/finding/evidence/report/doctor；CLI 只调 Application Service；从仓库根/测试目录/任意目录都能跑
- [ ] **Step 3: 实现** - Typer；每子命令调对应 Service；workspace_root 解析（M0 已有）；跨 CWD 测试
- [ ] **Step 5: 提交** `feat(cli): add typer cli`

## Task 7: FastAPI OpenAPI（长任务 SSE）

**Files:** `interfaces/api/main.py`, `routers/*`, `tests/interfaces/test_api.py`

- [ ] **Step 1: 测试** - 资源 API（projects/scopes/assessments/plans/approvals/workers/jobs/tools/cases/intel/assets/findings/evidence/updates/reports/audit）；Command/Query 分离；幂等（Idempotency-Key/external_id/content_hash）；长任务返回 ID + SSE 状态；401/403/404/422
- [ ] **Step 3: 实现** - FastAPI + APIRouter；Pydantic schema；SSE 状态推送；幂等键；tenant_middleware（M0 已有）
- [ ] **Step 5: 提交** `feat(api): add fastapi openapi with sse`

## Task 8: ReportRenderer（模板 + 数据驱动 + Redaction 延伸）

**Files:** `application/report_renderer.py`, `infrastructure/report_templates/*`, `tests/application/test_report_renderer.py`

- [ ] **Step 1: 测试** - 报告固定结构（执行摘要/范围/方法/资产清单/发现/证据/修复/覆盖矩阵/附录）；Finding 字段自动填（标题/摘要/severity/CVSS/受影响资产/evidence_id/修复从 CWE 或 nuclei 模板取）；覆盖矩阵自动算（从 CoverageService）；证据自动嵌（截图/请求响应+hash）；数字可追溯（每数字->DB 查询）；声明可追溯（每声明->evidence_id）；完整性校验（章节填满+0 未验证+覆盖矩阵全绿+证据 hash+审计链）；**Redaction 延伸 Report 渲染层（M9）**--报告叙述引用证据摘要时再过 RedactionEngine
- [ ] **Step 3: 实现** - Jinja2 模板；ReportRenderer.render(assessment_id) -> Report；从 Finding/Evidence/CoverageMatrix 自动填；RedactionEngine（M2）在渲染层再过；数字一致性校验；LLM 仅可选执行摘要润色（人签）
- [ ] **Step 5: 提交** `feat(report): add data-driven renderer with redaction`

## Task 9: Web Case Studio 后端 API

**Files:** `interfaces/web/main.py`, `tests/interfaces/test_web.py`

- [ ] **Step 1: 测试** - 7 页（Dashboard/NewAssessment/AssessmentDetail/ApprovalCenter/Findings/CaseStudio/Updates）；Case Studio 模型编辑/Schema/风险/Fixture/Dry Run/Diff/审核/签名；不提供浏览器任意代码执行
- [ ] **Step 3: 实现** - FastAPI Web 路由；Case Studio 调 ModelBuilder（M3）/CaseService（M2）；Approval Center 调 ApprovalService；签名 Ed25519
- [ ] **Step 5: 提交** `feat(web): add case studio backend api`

## Task 10: Web Case Studio 前端（可视化建模）

**Files:** `interfaces/web/static/*`, `templates/*`

- [ ] **Step 1: 测试** - 可视化建模 UI（状态机图编辑/不变量编辑/trust 边界标记/角色能力）；YAML 编辑+Schema 校验+风险预览+Fixture+Dry Run+Diff+审核+签名；7 页可达
- [ ] **Step 3: 实现** - HTMX 或 React；状态机图（mermaid.js 或 vis.js）；表单编辑；调 Web 后端 API；签名流程
- [ ] **Step 5: 提交** `feat(web): add visual case studio frontend`

## Task 11: AssetGraphService + Job/Report Repository

**Files:** `application/asset_graph.py`, `infrastructure/repositories/sqlalchemy_assets.py`, `sqlalchemy_findings.py`, `sqlalchemy_reports.py`, `sqlalchemy_jobs.py`, `tests/infrastructure/test_repositories.py`

- [ ] **Step 1: 测试** - AssetGraph 持久化（节点+边）；Finding/Report/Job 持久化；Repository Contract（M0 抽象）
- [ ] **Step 3: 实现** - CoreAssetNode/CoreAssetEdge/CoreFinding/CoreReport/CoreJob ORM；SqlAlchemy Repository
- [ ] **Step 5: 提交** `feat(infra): persist assets findings reports jobs`

## Task 12: 端到端编排集成测试

**Files:** `tests/integration/test_e2e_assessment.py`

- [ ] **Step 1: 测试** - E2E：assessment_start -> Planner 生成 DAG -> 人审批 -> Orchestrator 派 Job -> Adapter 执行 -> Observation -> oracle N/N -> CoverageMatrix 全绿 -> Report 渲染；覆盖矩阵门禁生效
- [ ] **Step 3: 实现** - 集成测试用 Juice Shop/crAPI/httpbin fixture；mock Adapter 输出；验证全链路
- [ ] **Step 5: 提交** `test(e2e): add end to end assessment integration`

## Task 13: M4 质量门 + 文档

- [ ] ruff/mypy + pytest 全绿 + E2E 绿
- [ ] `docs/architecture/interfaces.md` + `docs/api/openapi.yaml` + `docs/web/case-studio.md`
- [ ] 提交 `docs(m4): close agent interface and report baseline`

---

## M4 最终验收

- [ ] MCP Server 自写 tool + 采纳 MCP 标 trust level
- [ ] CLI 13 命令，跨 CWD 可跑
- [ ] FastAPI OpenAPI + SSE 长任务
- [ ] Web Case Studio 可视化建模可用
- [ ] Planner 确定性 DAG（agent 不能删减必修类）
- [ ] Orchestrator V1 单机 + DB Job Lease
- [ ] FindingCorrelation 确定性指纹去重
- [ ] ReportRenderer 数据驱动 + Redaction 延伸
- [ ] 覆盖矩阵门禁生效（0 未执行必修类才能结题）
- [ ] E2E（Juice Shop/crAPI/httpbin）绿
- [ ] ruff/mypy/pytest 全绿

## 下一步

M4 通过后，写 M5 安全加固+Beta 详细计划。M5 依赖 M4 全链路就绪，做安全加固 + PG Contract + E2E + CI + STRIDE。
