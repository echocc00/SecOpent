# P0 + P1 W1 验收 + 后续开发计划

> **日期**：2026-07-27
> **角色**：设计 + 验收（本文档由验收方写）
> **状态**：P0 + P1 W1 验收通过，规划 P1 剩余 + P2/P3

---

## 1. 验收结论：P0 + P1 W1 通过 ✅

### 1.1 质量门全绿
| 项 | 结果 |
|---|---|
| 测试 | 818 passed（+2 from P1 W1 API 测试） |
| e2e_real | 2 passed（真实 Juice Shop SQLi oracle） |
| ruff | All checks passed |
| mypy strict | 184 文件 0 错误（+8 from P1 W1 新文件） |
| verify_env | 5/5 ALL PASS |

### 1.2 P0 验收（commit 36ef63e, tag v1.0-p0）
| 检查项 | 结果 |
|---|---|
| ADR-014 修正 | ✅ 标题改"自建 RescanVerifier，ptai 重定位 peer agent"，含 A4 spike 发现 |
| PtaiAdapter 删除 | ✅ `infrastructure/oracle/` 仅剩 `__init__/interactsh/rescan_verifier` |
| RescanVerifier 移入 src | ✅ `src/secopent/infrastructure/oracle/rescan_verifier.py:27` |
| ptai 残留引用 | ✅ clean（src/ tests/ 无 ptai_adapter/PtaiAdapter） |
| 设计文档更新 | ✅ §1.2 决策22 / §9.2 / §16 第26条 / §22.5 已改 |
| 全套无回归 | ✅ 818 passed（-5 ptai 测试 +7 其他） |

### 1.3 P1 W1 验收（commits f01d640 + 444082c）
| 检查项 | 结果 |
|---|---|
| DB session 依赖 | ✅ `deps.py` Annotated DbSession |
| SqlAlchemyProjectRepository | ✅ 补齐（之前缺） |
| schemas.py | ✅ Pydantic 响应模型 |
| 4 资源路由 | ✅ projects/scopes/assessments/tools 挂载 |
| OpenAPI spec | ✅ 11 paths（4 新 + health/findings/SSE） |
| TestClient 端到端 | ✅ API 测试绿 |
| 架构边界 | ✅ domain/application 仍框架无关 |

**P0 + P1 W1 验收通过，无问题。**

---

## 2. 后续开发计划

### 2.1 P1 剩余（3-4 周，当前在 W1）

#### W1 剩余：11 资源路由（2-3 天）

已有 backing（repository/service），仅需接线 REST 路由。按**前端依赖优先** + **已有 repository 优先**排序：

| 优先级 | 资源 | backing 状态 | 路由 | 备注 |
|---|---|---|---|---|
| **P1a** | findings | ✅ repository + main.py 已有 | 移入 routers/findings.py + 扩展（by assessment） | main.py 现有 3 endpoint 移过来 + 加 `GET /assessments/{id}/findings` |
| **P1a** | intel | ✅ sqlalchemy_intel | `GET /intel/search?q=` + `GET /intel/{cve}` | FTS5 搜索已有 |
| **P1a** | updates | ✅ update_models + UpdateManager | `GET /updates/health` + `GET /updates/bundles` + `POST /updates/sync` | KnowledgeHealthMonitor 已有 |
| **P1a** | audit | ✅ audit_chain | `GET /audit/events` | 审计事件查询 |
| **P1b** | plans | ✅ AssessmentRepository.save_plan | `POST /assessments/{id}/plans` + `GET /plans/{id}` | 接线 AssessmentService.attach_plan |
| **P1b** | approvals | ✅ save_approval | `POST /approvals` + `GET /approvals?status=` + `POST /approvals/{id}/decide` | 审批流 |
| **P1b** | jobs | ✅ JobService | `GET /assessments/{id}/jobs` + `POST /jobs/{id}/retry` | job 状态 + 重试 |
| **P1c** | assets | ✅ sqlalchemy_assets | `GET /assessments/{id}/assets` | 资产图查询 |
| **P1c** | evidence | ✅ evidence_store | `GET /findings/{id}/evidence` + `GET /evidence/{id}` | 三层证据 |
| **P1c** | reports | ✅ report_renderer | `POST /assessments/{id}/reports` + `GET /reports/{id}` | 报告生成 |
| **P1d** | cases + appmodels | ✅ CaseService + ModelRegistry | `GET/POST /cases` + `POST /cases/{id}/validate/dry-run/publish` + `GET/POST /appmodels` + `POST /appmodels/{id}/sign/generate-tests` | **CaseStudio 用，最复杂** |

**W1 完成标志**：OpenAPI ~30 paths，所有资源 REST 可达。

#### W2-W3：React 脚手架 + API client（2 天）
- Vite + TS + Tailwind + shadcn/ui 项目初始化
- `npx openapi-typescript http://localhost:8000/openapi.json -o src/api/generated.ts`
- TanStack Query hooks 封装
- Layout + Router + Sidebar（7 页导航）
- **前置**：确认 node/npm 可用（`node --version`）

#### W4-W7：核心页（8-12 天）
- W4 Dashboard + Findings + Updates（简单 CRUD，2-3 天）
- W5 NewAssessment 向导（Scope 冻结 + Plan 生成，2-3 天）
- W6 AssessmentDetail（Plan DAG react-flow + SSE 实时事件，3-4 天）
- W7 ApprovalCenter（1-2 天）

#### W8-W9：CaseStudio（5-7 天，最复杂）
- AppModel react-flow 状态机编辑器
- Monaco YAML 编辑器 + schema 校验
- Ed25519 签名面板（后端签名）
- 5 类测试生成 + Dry Run
- DriftDetector 视图

#### W10-W11：测试 + 集成（4-6 天）
- Playwright 7 页 + CaseStudio 流程
- 生产构建（`npm run build` -> FastAPI StaticFiles）
- 打磨

### 2.2 P1 验收标准（开发模型完成后我验收）
- [ ] OpenAPI ~30 paths，14 资源 REST 可达
- [ ] React SPA 7 页可达
- [ ] CaseStudio：AppModel 建模 + YAML + 签名 + 5 类测试 + Dry Run
- [ ] Playwright 测试绿
- [ ] 生产构建 + FastAPI 静态服务
- [ ] 全套测试无回归 + ruff/mypy clean
- [ ] `git tag v1.1-web`

### 2.3 P2/P3/P4（P1 完成后）

| 优先级 | 任务 | 工期 | 依赖 |
|---|---|---|---|
| **P2** | crAPI/vulhub 真实 E2E 补全 | 1-2 周 | Docker 多镜像 |
| **P2** | Scoped Egress nftables 强化 | 1-2 周 | Docker WSL2 |
| **P2** | ptai peer agent 接入 | 1-2 周 | Linux 环境 |
| **P3** | Phase B 打磨（性能/策展/真实场景/文档） | 4-6 周 | P1+P2 |
| **P4** | V2（远程 Worker/多租户/ToB） | 3-4 月 | V1.1 稳定 |

---

## 3. 给开发模型的下一步

**立即**：继续 W1 剩余 11 资源路由，按 §2.1 优先级（P1a -> P1b -> P1c -> P1d）。

**每资源**：
1. 查 backing service/repository 接口
2. 加 schemas.py 响应模型（若缺）
3. 写 routers/{resource}.py
4. main.py 挂载
5. TestClient 测试
6. ruff + mypy + 全套无回归
7. commit

**W1 完成后**：起 W2 React 脚手架（先 `node --version` 确认环境）。

**参考**：`sepcs/2026-07-27-p1-web-case-studio-react-handoff.md`（完整 P1 架构 + 11 任务分解 + 7 页设计 + CaseStudio 细节）。

---

## 4. 我的角色

- **设计**：P1 架构已设计（React handoff 文档），W1-W11 任务已分解
- **验收**：每个阶段完成后我验收（质量门 + 设计一致性 + LLM 边界）
- **不做**：具体开发（开发模型执行）

**验收节奏**：
- W1 完成（11 资源全接线）-> 我验收 OpenAPI + 测试
- W4-W7 完成（核心页）-> 我验收 7 页可达
- W8-W9 完成（CaseStudio）-> 我验收建模+签名+测试生成
- W10-W11 完成（测试+构建）-> 我最终验收 + tag v1.1-web

---

*P0 + P1 W1 验收通过。开发模型按 §2.1 + §3 继续。*
