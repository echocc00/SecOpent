# P1 交接：Web Case Studio（React）详细架构与实现

> **执行者**：开发模型（前端 + API 扩展）
> **工期**：3-4 周
> **前置**：P0 完成（设计与实现一致）；本机 Docker + FastAPI + 816 测试绿
> **目标**：从零构建 Web Case Studio（React SPA），7 页 + AppModel 可视化建模 + Case 编辑签名 + Playwright 测试
> **决策**：技术栈 React（用户已定）

---

## 1. 现状与缺口

### 1.1 当前 API 表面（极薄，需扩展）
`src/secopent/interfaces/api/main.py` 仅 4 endpoints：
- `GET /health`
- `POST /findings` / `GET /findings` / `GET /findings/{id}`
- `GET /assessments/{id}/events`（SSE）

**缺口**：Web UI 需要管理 14 类资源（projects/scopes/assessments/plans/approvals/jobs/tools/cases/intel/assets/findings/evidence/updates/reports），当前 API 只覆盖 findings。**P1 必须先扩 API**。

### 1.2 当前 Web 目录
`interfaces/web/` **不存在**。M4 只做了 MCP 注册表 + FastAPI（极薄）+ CLI。Web 前端从零构建。

---

## 2. 技术栈

| 层 | 选型 | 理由 |
|---|---|---|
| 框架 | **React 18 + TypeScript** | 用户选定；生态成熟 |
| 构建 | **Vite 5** | 快，dev proxy 简单 |
| 样式 | **Tailwind CSS 3** | 原子化，快 |
| 组件库 | **shadcn/ui**（Radix UI + Tailwind） | 可定制，无运行时依赖，copy-paste |
| 服务端状态 | **TanStack Query 5** | 缓存/失效/乐观更新，REST 标配 |
| 客户端状态 | **Zustand** | 轻量 UI 状态 |
| 路由 | **React Router 6** | 标配 |
| 状态机图 | **react-flow**（现 @xyflow/react） | AppModel 可视化编辑 |
| YAML 编辑器 | **@monaco-editor/react** | VS Code 内核，语法高亮+校验 |
| API client | **openapi-typescript** + **openapi-fetch** | 从 FastAPI OpenAPI 生成 TS 类型，类型安全 |
| 表单 | **react-hook-form** + **zod** | 表单校验 |
| 图标 | **lucide-react** | shadcn/ui 配套 |
| 测试 | **Playwright** | 浏览器 E2E |

**Python 侧**：FastAPI（已有）+ Pydantic v2（已有），加 `APIRouter` 按资源拆分。

---

## 3. 项目结构

```
src/secopent/
  interfaces/
    api/
      main.py                 # 修改：挂载所有 routers + 静态文件服务
      schemas.py              # 新增：Pydantic 响应模型（ProjectOut/ScopeOut/...）
      routers/                # 新增：按资源拆分
        __init__.py
        projects.py           # GET/POST /projects, GET/PUT/DELETE /projects/{id}
        scopes.py             # POST /scopes/draft, POST /scopes/{id}/freeze, GET /scopes/{id}
        assessments.py        # CRUD + /assessments/{id}/start
        plans.py              # POST /assessments/{id}/plans, GET /plans/{id}
        approvals.py          # POST /approvals, GET /approvals?status=pending
        jobs.py               # GET /assessments/{id}/jobs, POST /jobs/{id}/retry
        tools.py              # GET /tools (adapter registry)
        cases.py              # CRUD cases + /cases/{id}/validate + /cases/{id}/dry-run + /cases/{id}/publish
        intel.py              # GET /intel/search?q=, GET /intel/{cve}
        assets.py             # GET /assessments/{id}/assets (asset graph)
        findings.py           # 从 main.py 移入 + 扩展
        evidence.py           # GET /findings/{id}/evidence, GET /evidence/{id}
        updates.py            # GET /updates/bundles, POST /updates/sync, GET /updates/health
        reports.py            # POST /assessments/{id}/reports, GET /reports/{id}
        audit.py              # GET /audit/events
    web/                      # 新增：React SPA
      package.json
      vite.config.ts          # dev proxy /api -> http://localhost:8000
      tsconfig.json
      tailwind.config.js
      postcss.config.js
      index.html
      src/
        main.tsx
        App.tsx
        router.tsx            # 7 路由
        api/
          generated.ts        # openapi-typescript 生成（勿手改）
          client.ts           # openapi-fetch 封装
          hooks.ts            # TanStack Query hooks（useProjects/useAssessments/...）
        components/
          ui/                 # shadcn/ui 组件（button/dialog/table/...）
          layout/
            Sidebar.tsx       # 7 页导航
            Header.tsx        # 项目切换 + 用户
            Layout.tsx        # 整体布局
        pages/
          Dashboard.tsx
          NewAssessment.tsx
          AssessmentDetail.tsx
          ApprovalCenter.tsx
          Findings.tsx
          CaseStudio.tsx
          Updates.tsx
        features/
          case-studio/
            AppModelEditor.tsx     # react-flow 状态机图
            StateNode.tsx          # 状态节点组件
            TransitionEdge.tsx     # 转换边组件
            InvariantList.tsx      # 不变量编辑
            FieldTable.tsx         # 字段信任边界
            RoleEditor.tsx         # 角色能力
            YamlEditor.tsx         # Monaco YAML
            SigningPanel.tsx       # Ed25519 签名
            TestGenerator.tsx      # 5 类测试生成 + signature
            DriftView.tsx          # 漂移检测视图
          findings/
            FindingTable.tsx
            FindingDetail.tsx
            EvidenceViewer.tsx
            CoverageMatrix.tsx     # 覆盖矩阵可视化
        stores/
          uiStore.ts              # Zustand（侧边栏/主题/当前选中）
        lib/
          utils.ts                # cn() 等
          sse.ts                  # EventSource 封装（AssessmentDetail 实时事件）
tests/
  web/
    test_case_studio_browser.py   # Playwright（7 页 + Case Studio 流程）
```

---

## 4. API 扩展设计（P1 第一步，3-5 天）

### 4.1 原则
- Command/Query 分离：POST 写，GET 读
- 幂等：`Idempotency-Key` header（已有机制）
- 响应模型：每个资源 `XxxOut`（Pydantic），不暴露内部 domain dataclass
- 错误：401/403/404/422 统一格式
- OpenAPI：FastAPI 自动生成 `/openapi.json`，供前端生成 TS client

### 4.2 关键路由（最小可用集）

| 资源 | 方法 | 路径 | 说明 |
|---|---|---|---|
| projects | GET/POST | `/projects` | 列表/创建 |
| projects | GET/PUT/DELETE | `/projects/{id}` | 详情/更新/删除 |
| scopes | POST | `/scopes/draft` | 创建草稿 |
| scopes | POST | `/scopes/{id}/freeze` | 冻结快照 |
| scopes | GET | `/scopes/{id}` | 查快照 |
| assessments | POST | `/assessments` | 创建 |
| assessments | GET | `/assessments` | 列表 |
| assessments | GET | `/assessments/{id}` | 详情（含 plan + jobs 概要） |
| assessments | POST | `/assessments/{id}/start` | 启动（需 approval） |
| plans | POST | `/assessments/{id}/plans` | 生成/附加 plan |
| plans | GET | `/plans/{id}` | 查 plan（含 DAG steps） |
| approvals | POST | `/approvals` | 提交审批 |
| approvals | GET | `/approvals?status=pending` | 待审批列表 |
| approvals | POST | `/approvals/{id}/decide` | 批准/拒绝 |
| jobs | GET | `/assessments/{id}/jobs` | job 状态列表 |
| findings | GET | `/assessments/{id}/findings` | Assessment 的 findings |
| evidence | GET | `/findings/{id}/evidence` | 证据列表 |
| cases | GET/POST | `/cases` | Case 列表/创建 |
| cases | POST | `/cases/{id}/validate` | 校验 |
| cases | POST | `/cases/{id}/dry-run` | 靶场试跑 |
| cases | POST | `/cases/{id}/publish` | 发布（签名） |
| appmodels | GET/POST | `/appmodels` | AppModel 列表/导入 |
| appmodels | POST | `/appmodels/{id}/sign` | 签名 |
| appmodels | POST | `/appmodels/{id}/generate-tests` | 生成 5 类测试 |
| intel | GET | `/intel/search?q=` | 搜索 |
| updates | GET | `/updates/health` | 健康监控 |
| updates | POST | `/updates/sync` | 触发同步 |
| reports | POST | `/assessments/{id}/reports` | 生成报告 |
| audit | GET | `/audit/events` | 审计事件 |

### 4.3 Pydantic schemas（`api/schemas.py`）
每个资源的 `XxxOut` + `XxxCreate` 模型，从 domain dataclass 转换。示例：
```python
class ProjectOut(BaseModel):
    id: str
    name: str
    status: str
    created_at: datetime

class ScopeDraftCreate(BaseModel):
    project_id: str
    include: list[str]
    exclude: list[str] = []
    ports: list[int] = [80, 443]
```

### 4.4 生成 TS client
```bash
# 后端跑起来后
cd src/secopent/interfaces/web
npx openapi-typescript http://localhost:8000/openapi.json -o src/api/generated.ts
```
生成的 `generated.ts` 提供类型安全的 paths/schema。用 `openapi-fetch` 封装：
```typescript
// api/client.ts
import createClient from "openapi-fetch";
import type { paths } from "./generated";
export const api = createClient<paths>({ baseUrl: "/api" });
```

---

## 5. 7 页设计

### 5.1 Dashboard（仪表盘）
- 项目列表（卡片/表格）
- 最近 Assessment 摘要（状态 + 覆盖率 + finding 数）
- 系统状态（知识层健康 + 更新状态 + 靶场状态）
- 快速操作：新建 Assessment / 查看待审批

### 5.2 NewAssessment（新建评估向导）
- Stepper 表单：
  1. 选/建项目
  2. Scope 草稿（include/exclude/ports 输入，实时规范化预览）
  3. 冻结 Scope（显示 digest）
  4. 选执行模式（Approval/Autopilot）
  5. 生成 Plan（显示 DAG）
- 提交 -> 跳转 AssessmentDetail

### 5.3 AssessmentDetail（评估详情）
- 顶部：Assessment 元信息 + 状态 + Emergency Stop 按钮
- Plan DAG 可视化（react-flow 显示 PlanStep 依赖图，节点状态色：pending/running/done/failed）
- Job 列表（状态 + 重试按钮）
- 实时事件流（SSE `/assessments/{id}/events`，EventSource）
- Finding 摘要 + 覆盖矩阵进度
- 报告生成按钮

### 5.4 ApprovalCenter（审批中心）
- 待审批列表（plan/approval，按风险排序）
- 详情：plan DAG + scope + 风险 + capability
- 审批操作：批准 / 拒绝（带理由）
- 历史审批记录

### 5.5 Findings（发现）
- 表格：severity/confidence/asset/CWE/CVE/oracle 状态/时间
- 筛选：severity / oracle 状态 / 资产 / CWE
- 详情抽屉：证据列表（RAW/REDACTED/SUMMARY 三层切换）+ oracle 复现记录 + 覆盖矩阵贡献
- 覆盖矩阵可视化（OWASP/CIS 条目 -> 测试类 -> covered/uncovered）

### 5.6 CaseStudio（用例工作室，最复杂）
- 左：AppModel 列表 + 导入（OpenAPI/Postman 上传）+ 新建
- 中：AppModel 可视化编辑器（react-flow 状态机图）
  - 节点 = 状态，双击编辑
  - 边 = 转换，标签显示 endpoint
  - 工具栏：加状态/加转换/不变量/字段/角色
- 右：属性面板
  - 选中状态/转换的属性编辑
  - 不变量列表（expr 编辑）
  - 字段表（name/type/range/trusted_source 下拉）
  - 角色能力编辑
- 底部 Tab：
  - YAML（Monaco 编辑器，Case YAML Nuclei 兼容+扩展，schema 校验 + 风险预览）
  - 签名（Ed25519：上传私钥 or 生成密钥对 -> 签名 -> 状态变 SIGNED）
  - 测试生成（5 类测试列表 + signature + Dry Run 按钮）
  - 漂移（DriftDetector 结果，新增/移除端点高亮）

### 5.7 Updates（知识层更新）
- Bundle 历史（版本 + digest + 激活状态 + 时间）
- 健康监控（5 类检测：源停更/策展滞后/覆盖率退化/源失效/签名失效，告警红色）
- 触发同步按钮
- 覆盖率退化门禁状态（选项 D，override 记录）

---

## 6. Case Studio 核心实现细节

### 6.1 AppModel 可视化编辑器（react-flow）
```typescript
// features/case-studio/AppModelEditor.tsx
import { ReactFlow, Background, Controls } from "@xyflow/react";

// states -> nodes (位置自动布局或手动拖)
// transitions -> edges (label = endpoint)
// 选中节点 -> 右侧属性面板编辑
// 加节点/边 -> 调 API 更新 AppModel
// 保存 -> 校验 -> 调 /appmodels/{id} 更新
```

### 6.2 YAML 编辑器（Monaco）
```typescript
// features/case-studio/YamlEditor.tsx
import Editor from "@monaco-editor/react";
// 加载 Case YAML，Monaco yaml 语言
// onChange -> zod schema 校验 -> 风险预览（RiskAnalyzer 结果）
// 保存 -> POST /cases/{id} validate
```

### 6.3 签名流程（Ed25519）
- 前端不持私钥（安全）：签名在后端做
- 流程：用户点"签名" -> 后端用 SecretStore 取密钥 -> Ed25519 签 -> 状态 SIGNED
- 或：用户上传私钥文件 -> 后端临时加载 -> 签名 -> 丢弃
- API：`POST /appmodels/{id}/sign`（后端处理，前端只触发 + 显示结果）

### 6.4 测试生成
- `POST /appmodels/{id}/generate-tests` -> 后端 LogicTestGenerator 生成 5 类
- 前端展示：5 类列表（跳步/乱序/重放/越界/不变量违反），每类 Case + signature + 状态
- Dry Run：`POST /cases/{id}/dry-run` -> 跑靶场 -> 显示结果

---

## 7. 状态管理

### 7.1 TanStack Query（服务端数据）
```typescript
// api/hooks.ts
export const useProjects = () => useQuery({ queryKey: ["projects"], queryFn: () => api.GET("/projects") });
export const useAssessment = (id: string) => useQuery({ queryKey: ["assessments", id], queryFn: ... });
export const useApprovals = (status?: string) => useQuery({ queryKey: ["approvals", status], queryFn: ... });
// mutation + invalidate
export const useCreateAssessment = () => useMutation({
  mutationFn: (body) => api.POST("/assessments", { body }),
  onSuccess: () => queryClient.invalidateQueries({ queryKey: ["assessments"] }),
});
```

### 7.2 Zustand（UI 状态）
```typescript
// stores/uiStore.ts
interface UIState {
  sidebarCollapsed: boolean;
  currentProjectId: string | null;
  theme: "light" | "dark";
}
```

### 7.3 SSE（实时事件）
```typescript
// lib/sse.ts
export function subscribeAssessmentEvents(id: string, onEvent: (e: AssessmentEvent) => void) {
  const es = new EventSource(`/api/assessments/${id}/events`);
  es.onmessage = (msg) => onEvent(JSON.parse(msg.data));
  return () => es.close();
}
```

---

## 8. 构建/部署

### 8.1 开发
```bash
# 后端
cd /f/claudepc/SecOpent
py -3.12 -m uvicorn secopent.interfaces.api.main:create_app --factory --reload --port 8000
# 前端（另一个终端）
cd src/secopent/interfaces/web
npm install
npm run dev    # Vite dev server :5173, proxy /api -> :8000
```

### 8.2 生产构建
```bash
cd src/secopent/interfaces/web
npm run build  # -> dist/
# FastAPI 静态服务（main.py 加）：
# app.mount("/", StaticFiles(directory="web/dist", html=True), name="web")
```

### 8.3 OpenAPI client 重新生成（API 变更后）
```bash
cd src/secopent/interfaces/web
npx openapi-typescript http://localhost:8000/openapi.json -o src/api/generated.ts
```

---

## 9. 任务分解（3-4 周）

| # | 任务 | 工期 | 依赖 |
|---|---|---|---|
| W1 | API 扩展：schemas.py + 14 routers + main.py 挂载 | 3-5 天 | 无 |
| W2 | React 脚手架：Vite+TS+Tailwind+shadcn+Router+Layout | 1 天 | W1 |
| W3 | API client 生成 + TanStack Query hooks | 1 天 | W1,W2 |
| W4 | Dashboard + Findings + Updates（简单 CRUD 页） | 2-3 天 | W2,W3 |
| W5 | NewAssessment 向导 + Scope 冻结 + Plan 生成 | 2-3 天 | W3 |
| W6 | AssessmentDetail + Plan DAG + SSE 实时事件 | 3-4 天 | W3,W5 |
| W7 | ApprovalCenter | 1-2 天 | W3 |
| W8 | CaseStudio：AppModel react-flow 编辑器 | 3-4 天 | W3 |
| W9 | CaseStudio：YAML Monaco + 签名 + 测试生成 | 2-3 天 | W8 |
| W10 | Playwright 浏览器测试（7 页 + Case Studio 流程） | 2-3 天 | W4-W9 |
| W11 | 集成 + 打磨 + FastAPI 静态服务 | 2-3 天 | W10 |

**关键路径**：W1(API) -> W2-W3(脚手架+client) -> W5-W6(核心页) -> W8-W9(CaseStudio) -> W10(测试)

---

## 10. 验收标准

- [ ] API 扩展：14 资源 REST 路由，OpenAPI spec 生成，`/openapi.json` 可访问
- [ ] React SPA 7 页可达，路由正常
- [ ] Dashboard：项目/Assessment 摘要 + 系统状态
- [ ] NewAssessment：向导流程完整（项目->scope->冻结->plan）
- [ ] AssessmentDetail：DAG 可视化 + SSE 实时事件 + Job 状态
- [ ] ApprovalCenter：待审批列表 + 批准/拒绝
- [ ] Findings：表格 + 筛选 + 证据三层 + 覆盖矩阵
- [ ] CaseStudio：AppModel react-flow 编辑 + YAML Monaco + 签名 + 5 类测试生成 + Dry Run
- [ ] Updates：bundle 历史 + 健康监控 + 同步触发
- [ ] Playwright 测试：7 页可达 + Case Studio 建模签名全流程
- [ ] 生产构建：`npm run build` -> FastAPI 静态服务
- [ ] 全套测试无回归（816+ 仍绿）+ ruff/mypy clean
- [ ] `git tag v1.1-web`

---

## 11. 关键设计约束（勿违反）

1. **LLM 边界**：Web UI 不直接调 LLM；LLM 仅经 `RemoteModelGateway`（后端），UI 触发后端调
2. **签名在后端**：前端不持 Ed25519 私钥；签名经后端 SecretStore
3. **scope 强制在后端**：UI 输入 scope，后端 ScopeEnforcer 强制；UI 不做 scope 判定
4. **Case 发布需人审**：UI 提交发布，后端要求人审签名（不只是 UI 点按钮）
5. **Evidence 三层**：UI 切换 RAW/REDACTED/SUMMARY，RAW 受限访问（后端权限校验）
6. **domain/application 框架无关**：API 扩展在 interfaces 层，不污染 domain/application
7. **OpenAPI 单一真源**：后端定义 OpenAPI，前端生成 client，不手写类型

---

## 12. 注意事项

- **API 扩展是前置**：先做完 W1（14 routers），前端才有数据。不要先写前端再补 API。
- **react-flow 版本**：现 `@xyflow/react`（v12），不是旧 `react-flow-renderer`
- **Monaco 在 Vite**：需 `vite-plugin-monaco-editor` 或 CDN 加载
- **SSE 跨域**：dev 模式 Vite proxy 需配置 SSE（不缓冲）
- **FastAPI 静态服务**：`app.mount("/", StaticFiles(...))` 要在所有路由之后（兜底）
- **Playwright**：`@pytest.mark.browser`，CI 单独 job

---

*P1 完成后，产品有完整 Web UI，可进 Phase B 打磨（性能/策展/真实场景验证）-> V1.1-stable。*
