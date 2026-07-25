> Status: 已退出。。关库 `docs/roadmap.md` 和 `docs/superpowers/plans/2026-07-24-m1-documentation-roadmap.md`。

# SecOpent MVP 实施计划（已完成部分 + 缺口）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** 把 2026-07-24 当日的 MVP 仓库状态与"下一步规划"挂钩，避免与 `2026-07-24-next-development-roadmap.md` 重叠。

**Architecture:** 模块化单体 + 隔离 Worker + Connector 适配。本文件仅复述已完成能力，详细任务分配见 next-development-roadmap.md。

**Tech Stack:** Python 3.11, FastAPI 0.115, SQLAlchemy 2.0, Alembic 1.14, Pydantic 2.10, psycopg 3, boto3, httpx, structlog, MinIO/S3, Docker Compose.

---

## 1. 已交付（2026-07-24 截止）

- 仓库策略 + Apache-2.0 LICENSE + NOTICE
- 设计规范（中文 36.8KB，覆盖 20 节）
- Quickstart + Phase 1 威胁模型
- 工作区解析 `src/secopent/shared/utils/workspace.py`（含 5 个测试）
- 编码卫生基线 `tests/test_encoding_hygiene.py`
- 数据：SQLAlchemy Base + TenantMixin + Organization 模型 + Alembic env + 0001_initial 迁移（11 张表）
- 鉴权/策略：TenantContext、tenant_middleware、RBAC 6 角色、ABAC 2 规则、local_principal 头依赖
- 共享 schema：Scope / ScopeSnapshot / RunRequest / RunResult / ArtifactRef / FindingSeverity / FindingCreate / EvidenceCreate / ObservationPayload
- 存储：S3ObjectStore + sha256 helper
- 核心服务：Scope / Assets / Findings / Evidence / Reports / Retests / Audit / Runs（dict 实现，pytest 全绿）
- 适配器契约：AdapterInput / AdapterOutput / AdapterManifest + run_adapter_container
- 适配器：nmap、nuclei（manifest / Dockerfile / run.sh / parser + parse_test）
- Worker：runtime + artifacts + scope + signer + observation_result
- Connectors：MispClient / MispEnrichment / JiraClient / JiraExport / WazuhClient / WazuhIngest（带 httpx 测试 transport）
- API：create_app + tenant_middleware + /api/findings + /api/findings/internal（占位）
- 部署：Dockerfile.api / Dockerfile.worker / docker-compose.yml（含 minio-init）
- e2e demo：src/secopent/examples/e2e_demo.py（256 行）+ test_e2e_demo.py
- 测试：72 passed (py3.12)

## 2. 关键缺陷（必须先修）

| 类别 | 位置 | 现象 | 修复 Owner |
|---|---|---|---|
| BOM | 6 个源文件 | AST 解析失败（py<3.10） | 路由 -> Phase 0 |
| 控制字符 | docs/quickstart.md | U+0008 出现在围栏 | 路由 -> Phase 0 |
| 重复定义 | WazuhIngest._severity | level=0/1/2 走错分支 | 路由 -> Phase 0 |
| Adapter run.sh 缺目标 | nmap | 容器内拿不到 targets | 路由 -> Phase 0 + Phase 2 |
| SessionLocal 提前绑定 | app/db/session.py | 环境变量不生效 | 路由 -> Phase 0 |
| 持久化缺失 | 所有 service | dict 当库 | 路由 -> Phase 1 |
| 真实 API 缺失 | app/main.py | 仅 2 个端点 | 路由 -> Phase 1 |
| Worker token + 白名单 | worker/* | 全部文件都上传 | 路由 -> Phase 1/2 |
| Adapter 容器安全 | adapters/runner.py | 仅 --network=none | 路由 -> Phase 2 |
| CI 缺失 | .github/ | 无 lint/type/test/smoke | 路由 -> Phase 4 |

## 3. 后续动作

完整任务清单与优先级见 `docs/superpowers/plans/2026-07-24-next-development-roadmap.md`。
