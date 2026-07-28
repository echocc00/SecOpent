# P1 W4-W9 + BE-1..BE-7 验收 + 后续开发详细计划

> **日期**：2026-07-28
> **角色**：设计 + 验收（本文档由验收方写）
> **状态**：W4-W9 + 9 项后端使能 **有条件通过**；3 个 LLM 边界缺口须在 v1.1-web tag 前修复
> **验收范围**：commit e73546f..029b9c0（12 个提交，BE-1..BE-7 + FE-shared/W4/W5-6-7/W8-9）

---

## 1. 验收结论：有条件通过 ⚠️

### 1.1 质量门全绿
| 项 | 结果 |
|---|---|
| 后端测试 | **884 passed**, 1 skipped, 2 deselected（+20 from W1+W2 基线 864） |
| ruff | All checks passed |
| mypy strict | **205 文件** 0 错（+2 from W1+W2 的 203） |
| 前端构建 | `tsc -b && vite build` clean |
| 前端包体 | 主包 **244 kB gzip** + CaseStudio 懒加载 **12.6 kB gzip**（达标） |
| 架构边界 | 96 boundary/security 测试 passed |
| 工作树 | clean（24 commits 全提交） |

### 1.2 API 表层（47 OpenAPI paths，17 资源）
全部资源 REST 可达，含本轮新增：
- `POST /findings/{id}/verdict`（BE-1，oracle 结论）
- `GET /approvals/pending` `/history` `POST /approvals/reject`（BE-2）
- `POST /cases/{id}/analyze` + `PUT /cases/{id}`（BE-3，YAML 存储+富校验）
- `PUT /appmodels/{id}/{v}` + `POST .../revise`（BE-4，版本化）
- `POST /assessments/{id}/plans`（BE-5，接 Planner）
- `GET/POST /signing-keys`（BE-7，多密钥）

### 1.3 前端 7 页 + CaseStudio 全交付
- **共享**：DataTable / SeverityBadge / StatusBadge / DagView（react-flow 免布局依赖）/ EvidenceViewer + 全端点 typed hooks
- **W4** Dashboard / Findings / Updates
- **W5/6/7** NewAssessment 5 步向导 / AssessmentDetail（DAG+SSE+Job）/ ApprovalCenter
- **W8/9** CaseStudio：react-flow 状态机编辑器 + 5 标签属性面板 + Monaco YAML + 人类签名流（选钥）+ 5 类测试生成 + 升版本保存 + 懒加载拆包

### 1.4 9 项决策落地核对
| 决策 | 落地 | 核对 |
|---|---|---|
| A 审批状态流转 | `AssessmentStatus.REJECTED` + reject 端点 + 审计链 | ✅ |
| B Finding oracle 结论 | 复用 `VerificationStatus` + verdict 端点 | ⚠️ 缺 actor_role（见 §2.2） |
| C Finding 关联+筛选 | `assessment_id` + 多维筛选 | ✅ |
| D Case YAML 后端存 | `CaseDefinition.yaml` + analyze + PUT | ✅ |
| E AppModel 升版本 | 草稿 PUT / 签名后 revise | ✅ |
| F 生成 plan 接 Planner | scope→资产类型→catalog→Planner DAG | ✅ |
| G Scope limits | rps/concurrency/max_requests | ✅ |
| H 多密钥 SecretStore | SigningKeyService + Ed25519KeyProvider | ⚠️ 缺 actor_role（见 §2.3） |
| I LLM_PROPOSED | `llm_proposed` 起步状态 | ✅ |

---

## 2. 必修问题（v1.1-web tag 前阻断）

LLM 边界是本产品的核心安全属性（§12）。dev model 在 BE-1/BE-2/BE-7 新建端点时**未沿用** cases.py / appmodels.py 的 `actor_role` 强制模式，留下 3 个缺口。

### 2.1 【HIGH】approvals approve/reject 未强制 human-only
**位置**：`src/secopent/interfaces/api/routers/approvals.py`
**问题**：
- `ApprovalCreate`（schemas.py:196）只有 `approved_by: str`，无 `actor_role`
- `ApprovalReject`（schemas.py:240）只有 `rejected_by: str`，无 `actor_role`
- 路由 docstring 明写"human-only"但代码**未强制**
- **后果**：agent 可调 `POST /approvals` 自批自己的 plan，违反"审批纯属人决策"边界

**修复**（对齐 cases.py:194 模式）：
1. `ApprovalCreate` / `ApprovalReject` 加 `actor_role: str = "human"` 字段
2. `create_approval` / `reject_approval` 传 `actor_role=body.actor_role` 到 service
3. `AssessmentService.approve` / `.reject` 校验 `actor_role != "human"` → 抛 `DomainValidationError`（403 映射）
4. 加测试：`actor_role="agent"` → 403（approve 与 reject 各一）

### 2.2 【HIGH】findings/verdict 未限定 oracle-only
**位置**：`src/secopent/interfaces/api/routers/findings.py:114-131`
**问题**：
- `FindingVerdict`（schemas.py:97）只有 `verdict: str`，无调用方标识
- 端点 docstring 写"Record the oracle's N/N reproduction verdict"但**任何人可调**
- **后果**：agent 可调 `POST /findings/{id}/verdict` 把自己的发现标 CONFIRMED，违反"LLM 永不定 Finding 确认"

**修复**（设计意图：verdict 只能由确定性 oracle 写，禁止 agent）：
1. `FindingVerdict` 加 `actor_role: str = "human"`（允许 human 手动覆盖 + oracle 系统，禁止 agent）
2. `set_verdict` 校验 `actor_role == "agent"` → 403
3. **注意**：oracle 系统内部调用走 application 层（不经 REST），REST 端点仅给 human 手动覆盖/测试用，故 `human` 默认值即可
4. 加测试：`actor_role="agent"` → 403

### 2.3 【MEDIUM】signing-keys POST 未强制 human-only
**位置**：`src/secopent/interfaces/api/routers/signing_keys.py:38-43`
**问题**：
- `CreateSigningKey`（schemas.py:388）无 `actor_role`
- 创建签名密钥是特权管理动作，不应 agent 可调
- GET（列表）agent 可见（UI 要展示选钥），POST（建钥）必须 human
- **后果**：agent 可创建自己的签名密钥（虽然 sign 仍需 human，但建钥本身是管理动作）

**修复**：
1. `CreateSigningKey` 加 `actor_role: str = "human"`
2. `create_signing_key` 校验 `actor_role != "human"` → 403
3. `list_signing_keys`（GET）不加限制（agent 可读）
4. 加测试：`actor_role="agent"` POST → 403；GET → 200

### 2.4 修复验收
- [ ] 3 处 actor_role 强制 + 各 1 个 403 测试
- [ ] 96 → 99 boundary/security 测试 passed
- [ ] mypy / ruff clean
- [ ] 全套 884 → 887 passed 无回归
- [ ] commit `fix(api): enforce actor_role on approvals/findings-verdict/signing-keys (LLM boundary)`

---

## 3. 诚实占位项（dev model 已申报，须在 P2 接线）

dev model 申报的 5 个占位项，依赖真实执行层，列入 P2：

| # | 占位 | 位置 | P2 接线 |
|---|---|---|---|
| P1 | Updates 5 探测器占位 | Updates.tsx | 接 KnowledgeHealthMonitor 5 类检测（源停更/策展滞后/覆盖率退化/源失效/签名失效）→ REST `GET /updates/health` 扩展 |
| P2 | DriftDetector 无 REST | CaseStudio DriftView | 加 `GET /appmodels/{id}/{v}/drift` → DriftDetector 结果 |
| P3 | Job 重试 | AssessmentDetail | `POST /jobs/{id}/retry` 接 JobService |
| P4 | 紧急停止 | AssessmentDetail | `POST /assessments/{id}/stop` → 状态 STOPPED + 审计 |
| P5 | 报告生成 | AssessmentDetail | `POST /assessments/{id}/reports` 接 report_renderer |
| P6 | Monaco CDN | YamlEditor | 本地 bundle monaco-editor（离线/合规要求） |

---

## 4. 后续开发计划

### 4.1 Phase 2 收尾（1.5-2 周）

#### W10：Playwright E2E（2-3 天）
**前置**：§2 三个边界修复完成。

**测试矩阵**（`tests/web/test_p1_browser.py`，`@pytest.mark.browser`）：

| 用例 | 流程 | 断言 |
|---|---|---|
| `test_dashboard_loads` | 进 / | 项目列表 + 系统状态可见 |
| `test_new_assessment_wizard` | 5 步向导全程 | scope 冻结显示 digest + plan DAG 渲染 |
| `test_assessment_detail_sse` | 进详情页 | SSE 连接 + 事件流接收 + DAG 节点状态变色 |
| `test_approval_center_approve` | pending→批准 | 列表移除 + history 出现 |
| `test_approval_center_reject` | pending→拒绝（填理由） | history 出现 + 审计链有 `approval.rejected` |
| `test_findings_filter_evidence` | 筛选 severity + 抽屉证据三层切换 | RAW/REDACTED/SUMMARY 切换 |
| `test_case_studio_model_edit` | 加状态节点 + 加转换 + 保存 | react-flow 画布持久化 |
| `test_case_studio_yaml_sign` | YAML 编辑 → analyze → validate → 选钥签名 | 状态 DRAFT→SIGNED |
| `test_case_studio_generate_tests` | 签名模型 → generate-tests | 5 类测试列出 + signature |
| `test_llm_boundary_agent_403` | actor_role=agent 调 sign/publish/approve/verdict | 全 403 |

**实现要点**：
- `conftest.py` fixture：起后端 uvicorn + `npm run preview` 静态服务 + Playwright page
- 用真实 in-memory SQLite + 预置 project/scope/catalog
- SSE 测试：`page.wait_for_event` 或 `expect(poll).toBe(...)`
- 截图失败留 artifact

#### W11：生产构建打磨（2-3 天）
1. **Monaco 本地化**（P6）：`vite-plugin-monaco-editor` 或 `monaco-editor` + `?worker` 导入，去掉 CDN 依赖（合规/离线）
2. **FastAPI 静态服务**：`main.py` 末尾 `app.mount("/", StaticFiles(directory=str(web_dist), html=True))`（兜底，在所有 router 之后）
3. **SPA fallback**：404 → index.html（react-router client routing）
4. **API 前缀统一**：确认 `/api` 前缀 vs 根路径（vite proxy rewrite 已配，生产需 StaticFiles + API router 共存）
5. **环境变量**：`SECOPTENT_WEB_DIST` 指向 dist，缺失则不 mount（开发模式不干扰）
6. **构建产物校验**：`npm run build` → `dist/` → FastAPI 服务 → 7 页可达

#### 边界修复（0.5 天，先做）
§2 的 3 个 actor_role 修复，**先于 W10**（E2E 依赖边界正确）。

### 4.2 P2 真实执行层（2-3 周，可与 W10-W11 部分并行）

#### P2-F：crAPI/vulhub 真实 E2E（1-2 周）
**目标**：把 2 个 e2e_real 测试扩到覆盖四域适配器的真实场景。

**测试矩阵**（`tests/e2e_real/`，`@pytest.mark.e2e_real`，需 Docker）：

| 域 | 靶标 | 适配器链 | oracle 验证 |
|---|---|---|---|
| Web/API | Juice Shop | subfinder→httpx→nuclei→dalfox | nuclei SQLi finding → RescanVerifier N/N CONFIRMED |
| Web/API | crAPI | katana→nuclei | BOLA/BFLA finding → oracle 复现 |
| Web/API | httpbin | Schemathesis（OpenAPI） | 5 类状态码/Schema 突变 |
| 网络 | 本机 metasploitable | nmap→naabu | 端口/服务 finding |
| 云 | 本地 docker socket | 5 云适配器 | 容器逃逸/权限 finding |
| 资产 | Juice Shop + httpbin | subfinder→httpx→katana | 资产图节点/边 |

**compose 文件**：`scripts/provision/docker-compose.targets.yml` 已有 Juice Shop + httpbin，加 crAPI service。

**关键**：每个 e2e_real 跑完留 evidence 三层（RAW/REDACTED/SUMMARY）+ audit 链可校验。

#### P2-G：Scoped Egress nftables 强化（1-2 周）
**现状**：option c（Docker bridge + host.docker.internal + app 层 PolicyEngine scope）
**目标**：M5 提前到 P2，网络层强制

**设计**（`scripts/provision/egress.nft` + 动态注入）：
1. Docker network `secopent-egress`（bridge，出站默认 DROP）
2. 评测启动时：scope normalize → IP 白名单 → `nft add element` 注入
3. DNS rebinding 防御：DNS 解析后二次校验 IP（PolicyEngine 已有，nft 层兜底）
4. Interactsh 通道：单独 allow host.docker.internal:8444
5. WSL2 注意：nftables 在 WSL2 内核需 `CONFIG_NFT_CHAIN_NAT`，Docker Desktop 用其自己的 netns

**验证**：恶意 scope（含 169.254.169.254 元数据 IP）→ nft DROP + 审计拒绝事件。

#### P2-占位接线（3-5 天，见 §3 表）
6 个占位项逐个接后端真实服务：
- P1 Updates health：扩 `GET /updates/health` 返回 5 探测器状态
- P2 Drift REST：加 `GET /appmodels/{id}/{v}/drift`
- P3 Job retry：加 `POST /jobs/{id}/retry`
- P4 Emergency stop：加 `POST /assessments/{id}/stop`
- P5 Report gen：加 `POST /assessments/{id}/reports`
- P6 Monaco 本地（已在 W11）

### 4.3 P3 Phase B 打磨（4-6 周，V1.1-stable）
- 性能：大评估的 plan DAG 渲染、SSE 背压、SQLite WAL 调优
- 策展：Case 库初始集（OWASP Top 10 + CIS 基线映射）
- 真实场景：3 类典型渗透流程跑通（Web 黑盒 / API / 云资产）
- 文档：用户手册 + Case Studio 建模指南 + Adapter 开发指南
- `git tag v1.1-stable`

### 4.4 P4 V2（3-4 月，V1.1 稳定后）
远程 Worker / 多租户 / ToB（见设计 §13 M5+）

---

## 5. 给开发模型的执行顺序

**第 1 步（0.5 天）**：修 §2 三个 LLM 边界缺口（先做，W10 依赖）
1. schemas.py 三处加 `actor_role: str = "human"`
2. approvals.py / findings.py / signing_keys.py 三处校验
3. service 层 approve/reject 校验
4. 3 个 403 测试 + 全套无回归 + commit

**第 2 步（2-3 天）**：W10 Playwright E2E（§4.1 矩阵 10 用例）

**第 3 步（2-3 天）**：W11 生产构建（Monaco 本地化 + StaticFiles + SPA fallback）

**第 4 步**：tag `v1.1-web`（W10-W11 + 边界修复全绿后）

**第 5 步起（P2，可与第 2-3 步并行）**：P2-F 真实 E2E / P2-G nftables / P2 占位接线

**参考**：
- 现有设计：`sepcs/2026-07-27-p1-p2-detailed-design-batch.md`（Part F crAPI/vulhub + Part G nftables 细节）
- 本轮验收：本文档 §2 修复点 + §3 占位项

---

## 6. 验收方角色

- **设计**：后续计划已出（本文档 §4）
- **验收**：每步完成后我验收（边界修复 → W10 → W11 → tag → P2 各项）
- **不做**：具体开发（dev model 执行）

**验收节奏**：
1. §2 边界修复完成 → 我验 3 个 403 测试 + 无回归
2. W10 完成 → 我验 10 个 Playwright 用例绿
3. W11 完成 → 我验生产构建 + FastAPI 静态服务 + tag v1.1-web
4. P2-F/G/占位 各项 → 分别验收

---

*W4-W9 + BE-1..BE-7 有条件通过。dev model 按 §5 执行，先修 §2 边界缺口。*
