# P1 W2-W11 + P2 并行批量详细设计

> **一份文档覆盖全部后续设计深度**。开发模型一次拿到 B（脚手架）+ C（六页组件级）+ D（CaseStudio 深度）+ F（crAPI/vulhub E2E）+ G（nftables egress）。
> **前置**：W1 剩余 11 资源路由完成（批量 A，模式已验证）。
> **参考**：架构级设计见 `sepcs/2026-07-27-p1-web-case-studio-react-handoff.md`，本文档深化到组件级。

---

# Part B：W2-W3 React 脚手架 + API client（2 天）

## B.1 初始化命令序列

```bash
cd /f/claudepc/SecOpent/src/secopent/interfaces
npm create vite@latest web -- --template react-ts
cd web
npm install

# Tailwind CSS 4 (Vite plugin)
npm install tailwindcss @tailwindcss/vite

# shadcn/ui
npx shadcn@latest init -d   # -d = defaults (New York, Zinc, CSS variables)

# 核心依赖
npm install @tanstack/react-query @tanstack/react-query-devtools \
            zustand react-router-dom \
            @xyflow/react lucide-react \
            react-hook-form zod @hookform/resolvers

# Monaco editor (CaseStudio)
npm install @monaco-editor/react

# API client 生成
npm install -D openapi-typescript openapi-fetch
```

## B.2 配置文件

### `vite.config.ts`
```typescript
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": path.resolve(__dirname, "./src") } },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8000", changeOrigin: true },
      "/ws": { target: "ws://localhost:8000", ws: true },
    },
  },
  build: { outDir: "dist", sourcemap: true },
});
```

### `src/index.css`（Tailwind 4）
```css
@import "tailwindcss";
@import "@xyflow/react/dist/style.css";
```

### `tsconfig.json` 加 paths
```json
{ "compilerOptions": { "paths": { "@/*": ["./src/*"] } } }
```

## B.3 项目骨架

```
src/
  main.tsx                  # React root + QueryClient + RouterProvider
  App.tsx                   # <RouterProvider router={router} />
  router.tsx                # 7 路由 + Layout
  api/
    generated.ts            # openapi-typescript 生成（勿手改）
    client.ts               # openapi-fetch 封装
    hooks.ts                # TanStack Query hooks（按资源分组）
  components/
    ui/                     # shadcn/ui（button/dialog/table/drawer/badge/...）
    layout/
      Layout.tsx            # Sidebar + Header + <Outlet/>
      Sidebar.tsx           # 7 页导航
      Header.tsx            # 项目切换 + EmergencyStop
    shared/
      DataTable.tsx         # 通用表格（TanStack Table）
      SeverityBadge.tsx     # severity 色标
      StatusBadge.tsx       # 状态色标
      DagView.tsx           # react-flow DAG 通用组件
      EvidenceViewer.tsx    # 三层证据切换
  pages/
    Dashboard.tsx
    NewAssessment.tsx
    AssessmentDetail.tsx
    ApprovalCenter.tsx
    Findings.tsx
    CaseStudio.tsx
    Updates.tsx
  features/
    case-studio/            # Part D 详述
  stores/
    uiStore.ts              # Zustand
  lib/
    utils.ts                # cn() + 格式化
    sse.ts                  # EventSource 封装
```

## B.4 API client 生成 + 封装

### 生成（W1 完成后，后端跑起来）
```bash
cd src/secopent/interfaces/web
# 后端先跑：py -3.12 -m uvicorn secopent.interfaces.api.main:create_app --factory --port 8000
npx openapi-typescript http://localhost:8000/openapi.json -o src/api/generated.ts
```

### `src/api/client.ts`
```typescript
import createClient from "openapi-fetch";
import type { paths } from "./generated";

export const api = createClient<paths>({ baseUrl: "/api" });
```

### `src/api/hooks.ts`（按资源分组，TanStack Query）
```typescript
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";

// --- Projects ---
export const useProjects = () =>
  useQuery({ queryKey: ["projects"], queryFn: () => api.GET("/projects") });

export const useCreateProject = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: components["schemas"]["ProjectCreate"]) =>
      api.POST("/projects", { body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["projects"] }),
  });
};

// --- Assessments ---
export const useAssessments = (projectId?: string) =>
  useQuery({
    queryKey: ["assessments", projectId],
    queryFn: () => api.GET("/assessments", { params: { query: { project_id: projectId } } }),
  });

export const useAssessment = (id: string) =>
  useQuery({ queryKey: ["assessments", id], queryFn: () => api.GET("/assessments/{assessment_id}", { params: { path: { assessment_id: id } } }) });

// ... 每资源同样模式：useXxx (GET list), useXxxDetail (GET by id), useCreateXxx/useUpdateXxx (POST/PUT mutation)
```

## B.5 Layout + Router

### `src/router.tsx`
```typescript
import { createRouter } from "@tanstack/react-router"; // 或 react-router-dom
const routes = [
  { path: "/", element: <Layout/>, children: [
    { index: true, element: <Dashboard/> },
    { path: "assessments/new", element: <NewAssessment/> },
    { path: "assessments/:id", element: <AssessmentDetail/> },
    { path: "approvals", element: <ApprovalCenter/> },
    { path: "findings", element: <Findings/> },
    { path: "case-studio", element: <CaseStudio/> },
    { path: "updates", element: <Updates/> },
  ]},
];
```

### `src/stores/uiStore.ts`
```typescript
import { create } from "zustand";
interface UIState {
  sidebarCollapsed: boolean;
  currentProjectId: string | null;
  toggleSidebar: () => void;
  setProject: (id: string) => void;
}
export const useUIStore = create<UIState>((set) => ({
  sidebarCollapsed: false,
  currentProjectId: null,
  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
  setProject: (id) => set({ currentProjectId: id }),
}));
```

## B.6 验收 B
- [ ] `npm run dev` 启动 :5173，代理 /api -> :8000
- [ ] 7 路由可达（空页占位）
- [ ] `npm run build` 成功产出 dist/
- [ ] Sidebar 7 项导航
- [ ] `src/api/generated.ts` 从 OpenAPI 生成（类型安全）

---

# Part C：W4-W7 六页组件级设计（8-12 天）

## C.1 共享组件（先做，W4 前置）

### `components/shared/DataTable.tsx`
通用表格：列定义 + 排序 + 分页 + 行点击。基于 TanStack Table + shadcn Table。
```typescript
interface DataTableProps<T> {
  data: T[];
  columns: ColumnDef<T>[];
  onRowClick?: (row: T) => void;
  emptyMessage?: string;
}
```

### `components/shared/SeverityBadge.tsx`
```typescript
const COLORS = { critical: "red", high: "orange", medium: "yellow", low: "blue", info: "gray" };
export function SeverityBadge({ severity }: { severity: string }) {
  return <Badge variant={COLORS[severity] || "gray"}>{severity}</Badge>;
}
```

### `components/shared/DagView.tsx`（react-flow 通用 DAG）
```typescript
interface DagViewProps {
  nodes: Node[];      // {id, label, status}
  edges: Edge[];      // {source, target, label}
  onNodeClick?: (id: string) => void;
}
// status -> 色彩：pending=灰, running=蓝, done=绿, failed=红, skipped=黄
```

### `components/shared/EvidenceViewer.tsx`
```typescript
// 三层切换：RAW（受限）/ REDACTED / SUMMARY
// RAW 需后端权限校验（后端返回 403 则禁用 RAW tab）
interface EvidenceViewerProps { findingId: string; }
// -> useEvidence(findingId) -> [{layer, content_type, content}]
```

---

## C.2 W4a Dashboard（1 天）

### 组件树
```
Dashboard
├── ProjectSelector（Header 里，全局）
├── StatsCards
│   ├── ActiveAssessments count
│   ├── PendingApprovals count
│   ├── ConfirmedFindings count
│   └── CoverageAvg
├── RecentAssessments（DataTable，最近 5）
│   └── onRowClick -> /assessments/:id
├── SystemStatus
│   ├── KnowledgeHealth（5 detector 状态灯）
│   └── TargetsStatus（juice_shop/httpbin/interactsh 可达性）
└── QuickActions
    ├── New Assessment -> /assessments/new
    └── Pending Approvals -> /approvals
```

### API 调用
```typescript
const { data: assessments } = useAssessments(projectId);  // 最近
const { data: health } = useUpdatesHealth();              // 知识层健康
const { data: approvals } = useApprovals("pending");      // 待审批数
const { data: findings } = useFindings({ status: "confirmed" }); // 确认 finding 数
```

---

## C.3 W4b Findings（2 天）

### 组件树
```
Findings
├── FiltersBar
│   ├── SeverityFilter（multi-select）
│   ├── OracleStatusFilter（confirmed/refuted/inconclusive/pending）
│   ├── AssetFilter（text）
│   └── CWEFilter（text）
├── FindingTable（DataTable）
│   ├── columns: severity / asset / title / CWE / CVE / oracle_status / confidence / time
│   └── onRowClick -> open FindingDetailDrawer
├── FindingDetailDrawer（shadcn Sheet，右侧抽屉）
│   ├── FindingMeta（severity/confidence/asset/CWE/CVE/owasp）
│   ├── OracleResult（N/N 复现记录 + canary token + evidence）
│   ├── EvidenceViewer（三层切换）
│   └── CoverageContribution（此 finding 贡献的覆盖矩阵项）
└── CoverageMatrixPanel（可折叠）
    ├── OWASP WSTG 条目列表（covered/uncovered）
    └── CIS 条目列表
```

### API 调用
```typescript
const { data } = useFindings({ assessment_id, severity, oracle_status, ... });
const { data: finding } = useFinding(selectedId);
const { data: evidence } = useEvidence(selectedId);
const { data: coverage } = useCoverageMatrix(assessmentId);
```

### 状态
- 筛选状态用 URL search params（可分享/刷新保持）
- Drawer 开关用 local state

---

## C.4 W4c Updates（1 天）

### 组件树
```
Updates
├── HealthMonitor
│   ├── 5 DetectorCards（源停更/策展滞后/覆盖率退化/源失效/签名失效）
│   │   └── 每卡：状态灯 + 详情（如"nuclei-templates 7 天无 commit"）
│   └── CoverageRegressionGate（选项 D 状态 + override 记录）
├── BundleHistory（DataTable）
│   ├── columns: version / digest / status(active/superseded) / activated_at
│   └── onRowClick -> BundleDetail
├── BundleDetail（Drawer）
│   ├── manifest 内容
│   ├── 签名验证状态
│   └── diff 预览（vs 前版）
└── SyncButton -> useSyncUpdates() mutation
```

### API
```typescript
const { data: health } = useUpdatesHealth();
const { data: bundles } = useUpdateBundles();
const sync = useSyncUpdates();
```

---

## C.5 W5 NewAssessment 向导（2-3 天）

### 组件树
```
NewAssessment（Stepper，5 步）
├── Step1: ProjectSelect
│   ├── 选已有项目（Dropdown）
│   └── 或新建（inline form -> useCreateProject()）
├── Step2: ScopeDraft
│   ├── IncludeInput（多行输入，每行一个 URL/IP/domain）
│   ├── ExcludeInput（同上）
│   ├── PortsInput（逗号分隔）
│   ├── CloudAccountsInput（如 cloud 域目标）
│   └── NormalizePreview（实时调 API 规范化，显示规范化后结果 + 错误）
├── Step3: Freeze
│   ├── ScopeSummary（规范化后的 include/exclude/ports）
│   ├── LimitsForm（requests_per_second / concurrency / max_requests）
│   └── FreezeButton -> useFreezeScope() -> 显示 digest
├── Step4: Mode
│   ├── ModeSelect（Approval / ScopeAutopilot）
│   └── RiskApproval（选批准的风险类 + capability）
├── Step5: Plan
│   ├── GeneratePlanButton -> useGeneratePlan()
│   ├── PlanDagView（react-flow 显示 PlanStep DAG）
│   └── PlanDigest 显示
└── SubmitButton -> useCreateAssessment() + useAttachPlan() -> navigate /assessments/:id
```

### 状态机
```
step: 1 -> 2 -> 3 -> 4 -> 5 -> submit
每步: canNext 校验（Step2 需有效 include，Step3 需 freeze，Step5 需 plan）
canBack: 总是
```

### API
```typescript
const freeze = useFreezeScope();        // POST /scopes/draft -> freeze
const generatePlan = useGeneratePlan(); // POST /assessments/{id}/plans
const createAssessment = useCreateAssessment();
```

---

## C.6 W6 AssessmentDetail（3-4 天，含 SSE）

### 组件树
```
AssessmentDetail
├── DetailHeader
│   ├── Assessment meta（id/project/scope/mode/status）
│   ├── StatusBadge（实时更新 via SSE）
│   └── EmergencyStopButton -> useEmergencyStop()
├── PlanDagPanel
│   ├── DagView（react-flow，PlanStep DAG）
│   │   └── 节点色彩 = job 状态（实时更新 via SSE）
│   └── onNodeClick -> JobDetail
├── JobList（DataTable）
│   ├── columns: step_key / runner / status / attempt / duration / error
│   └── RetryButton（failed job）-> useRetryJob()
├── EventStream（SSE 实时事件流）
│   ├── 滚动日志（最新在顶）
│   └── 事件类型色标（job_started/completed/failed/finding/oracle/coverage）
├── FindingSummary
│   ├── Confirmed count + Refuted count + Inconclusive count
│   └── CoverageProgress（覆盖矩阵完成度进度条）
└── ReportButton -> useGenerateReport() -> 下载/预览
```

### SSE 实现
```typescript
// lib/sse.ts
export function subscribeAssessmentEvents(id: string, onEvent: (e: AssessmentEvent) => void) {
  const es = new EventSource(`/api/assessments/${id}/events`);
  es.onmessage = (msg) => {
    try { onEvent(JSON.parse(msg.data)); } catch {}
  };
  return () => es.close();
}

// AssessmentDetail.tsx
useEffect(() => {
  const unsub = subscribeAssessmentEvents(id, (e) => {
    queryClient.invalidateQueries({ queryKey: ["assessments", id] });
    queryClient.invalidateQueries({ queryKey: ["jobs", id] });
    // 更新事件流 state
    setEvents((prev) => [e, ...prev].slice(0, 100));
  });
  return unsub;
}, [id]);
```

### 实时更新策略
- SSE 事件触发 TanStack Query invalidate（自动重新 fetch）
- 节点色彩随 job 状态实时变化
- 事件流本地 state（不 query，SSE 推送）

---

## C.7 W7 ApprovalCenter（1-2 天）

### 组件树
```
ApprovalCenter
├── Tabs: Pending | History
├── PendingList（DataTable）
│   ├── columns: assessment / plan_digest / risk / capability / submitted_at
│   └── onRowClick -> ApprovalDetail
├── ApprovalDetail（Drawer 或全页）
│   ├── PlanDagView（react-flow，显示要批准的 plan）
│   ├── ScopeSummary（include/exclude/ports + digest）
│   ├── RiskTable（要批准的风险类 + capability）
│   └── DecideForm
│       ├── ApproveButton -> useDecideApproval({decision: "approve"})
│       └── RejectForm（理由输入）-> useDecideApproval({decision: "reject", reason})
└── HistoryList（已决策列表 + 决策结果 + 审计）
```

### API
```typescript
const { data: pending } = useApprovals("pending");
const { data: history } = useApprovals("decided");
const decide = useDecideApproval();
```

---

## C.8 验收 C
- [ ] Dashboard：项目/Assessment/健康状态/快速操作
- [ ] Findings：表格+筛选+证据三层+覆盖矩阵
- [ ] Updates：健康监控+bundle 历史+同步
- [ ] NewAssessment：5 步向导完整（项目->scope->冻结->模式->plan）
- [ ] AssessmentDetail：DAG 实时+SSE 事件流+Job 重试+报告
- [ ] ApprovalCenter：待审批+批准/拒绝+历史
- [ ] 每页响应式 + 加载/错误/空状态

---

# Part D：W8-W9 CaseStudio 深度设计（5-7 天，最复杂）

## D.1 整体布局（3-pane + bottom-tabs）

```
CaseStudio
├── LeftPane（AppModel 列表 + 导入）
│   ├── AppModelList（列表，选中高亮）
│   ├── ImportButton（上传 OpenAPI/Postman 文件）
│   └── NewButton（空 AppModel）
├── CenterPane（AppModelEditor，react-flow）
│   ├── Toolbar（加状态/加转换/保存/删除/布局）
│   └── ReactFlow Canvas（状态节点 + 转换边）
├── RightPane（PropertyPanel，选中对象属性）
│   ├── Tab: Properties（选中状态/转换的属性）
│   ├── Tab: Invariants（不变量列表 + 编辑）
│   ├── Tab: Fields（字段表 + trusted_source）
│   ├── Tab: Roles（角色 + capability）
│   └── Tab: OutOfScope（声明不覆盖的复杂规则）
└── BottomPane（Tabs，全宽）
    ├── Tab: YAML（Monaco Case 编辑器）
    ├── Tab: Signing（签名流程）
    ├── Tab: TestGen（5 类测试生成）
    └── Tab: Drift（漂移检测）
```

## D.2 AppModelEditor（react-flow，核心）

### 数据流
```
useAppModel(id) -> AppModel domain object
  -> transformToFlow(appModel) -> {nodes, edges}
    nodes = appModel.states.map(s => ({id: s, data: {label: s}, position: autoLayout(s)}))
    edges = appModel.transitions.map(t => ({id: t.id, source: t.from_state, target: t.to_state, label: t.endpoint}))
  -> <ReactFlow nodes={nodes} edges={edges} onNodeClick onConnect .../>
```

### 交互
| 操作 | 触发 | 效果 |
|---|---|---|
| 点节点 | onNodeClick | 右侧 PropertyPanel 显示状态属性 |
| 点边 | onEdgeClick | 右侧 PropertyPanel 显示转换属性（endpoint/params/idempotent） |
| 双击画布 | onDoubleClick | 弹出"新状态"对话框 -> 加节点 |
| 拖节点间 | onConnect | 弹出"新转换"对话框（endpoint/params） -> 加边 |
| 删节点/边 | 选中+Delete | 确认后删 -> 更新 AppModel |
| 保存 | Toolbar 按钮 | validate -> PUT /appmodels/{id} -> invalidate query |

### 自动布局
- 用 `dagre` 或 `elkjs` 做自动布局（状态机从左到右/从上到下）
- 用户可手动拖动节点（位置存 local state，保存时不持久化位置）

### 状态
```typescript
// features/case-studio/caseStudioStore.ts (Zustand)
interface CaseStudioState {
  selectedModelId: string | null;
  selectedNodeId: string | null;   // state or transition id
  selectedType: "state" | "transition" | null;
  isDirty: boolean;                // 未保存修改
  // actions
  selectModel: (id: string) => void;
  selectNode: (id: string, type: "state"|"transition") => void;
  markDirty: () => void;
  markClean: () => void;
}
```

## D.3 PropertyPanel（右侧属性）

### Properties Tab（选中对象属性）
- 选中 state：显示 state name（可编辑）+ 关联 transitions 列表
- 选中 transition：显示 from/to（只读）+ endpoint（可编辑）+ params（key-value 编辑器）+ idempotent（toggle）

### Invariants Tab
```
不变量列表（每行：id + expr + 删除按钮）
+ Add Invariant 按钮 -> 弹出输入 expr（如 "cart.total >= 0"）
编辑 expr -> inline edit
保存时随 AppModel 一起 PUT
```

### Fields Tab
```
字段表（DataTable）:
  columns: name | type | range_min | range_max | trusted_source(server/client)
+ Add Field 按钮
trusted_source 下拉: server / client
range 可选（数值类型才有）
```

### Roles Tab
```
角色列表（每行：role_id + capabilities 列表 + 删除）
+ Add Role 按钮
capability 编辑：multi-select（从 transitions 的 endpoint 派生）
```

### OutOfScope Tab
```
声明不覆盖的复杂规则列表（每行：rule 描述）
+ Add 按钮 -> 输入描述
这些规则在 LogicTestGenerator 时跳过，CoverageMatrix 标记"已声明超出范围"
```

## D.4 YAML 编辑器（Monaco，Bottom Tab）

### 组件
```typescript
// features/case-studio/YamlEditor.tsx
function YamlEditor({ caseId }: { caseId: string }) {
  const { data: caseData } = useCase(caseId);
  const [yaml, setYaml] = useState(caseData?.yaml || "");
  const [validation, setValidation] = useState<ValidationResult | null>(null);

  const validate = useValidateCase();
  const dryRun = useDryRunCase();
  const publish = usePublishCase();

  return (
    <div className="flex flex-col h-full">
      <Toolbar>
        <Button onClick={() => validate.mutate({ caseId, yaml })}>Validate</Button>
        <Button onClick={() => dryRun.mutate({ caseId })}>Dry Run</Button>
        <Button onClick={() => publish.mutate({ caseId })}>Publish</Button>
        <RiskPreview risk={validation?.computed_risk} declared={validation?.declared_risk} />
      </Toolbar>
      <Editor
        height="100%"
        language="yaml"
        value={yaml}
        onChange={(v) => setYaml(v || "")}
        options={{ minimap: { enabled: false }, wordWrap: "on" }}
      />
      <ValidationPanel result={validation} />  // schema 错误 + 风险分析结果
    </div>
  );
}
```

### 校验流程
1. 用户编辑 YAML
2. 点 Validate -> POST /cases/{id}/validate -> 返回 schema 校验 + RiskAnalyzer 结果
3. ValidationPanel 显示：schema 错误（红）/ 风险（声明 vs 计算对比）/ fixture 通过状态
4. 风险不匹配（声明 < 计算）-> 警告 + 阻止 Publish
5. Dry Run -> POST /cases/{id}/dry-run -> 在靶场跑 -> 显示结果
6. Publish -> 需人审签名 -> POST /cases/{id}/publish

## D.5 签名流程（Bottom Tab）

### SigningPanel
```typescript
function SigningPanel({ modelId }: { modelId: string }) {
  const { data: model } = useAppModel(modelId);
  const validate = useHumanValidateModel();  // POST /appmodels/{id}/validate
  const sign = useSignModel();               // POST /appmodels/{id}/sign

  return (
    <div>
      <StatusFlow current={model?.lifecycle_status} />
      {/* DRAFT -> LLM_PROPOSED -> HUMAN_VALIDATED -> SIGNED -> PUBLISHED */}

      {model?.lifecycle_status === "LLM_PROPOSED" && (
        <Button onClick={() => validate.mutate(modelId)}>
          Human Validate（人校验补不变量/trust 边界）
        </Button>
      )}

      {model?.lifecycle_status === "HUMAN_VALIDATED" && (
        <>
          <KeySelector />  {/* 选签名密钥（从 SecretStore） */}
          <Button onClick={() => sign.mutate(modelId)}>
            Sign（Ed25519 签名）
          </Button>
        </>
      )}

      {model?.lifecycle_status === "SIGNED" && (
        <div>
          <p>Signature: {model.signature?.slice(0, 32)}...</p>
          <p>Digest: {model.digest}</p>
          <Button onClick={() => generateTests.mutate(modelId)}>
            Generate 5-class Tests
          </Button>
        </div>
      )}
    </div>
  );
}
```

### 关键约束
- **签名在后端**：前端不持私钥，POST 触发后端用 SecretStore 密钥签名
- **状态机强制**：只能 LLM_PROPOSED -> HUMAN_VALIDATED -> SIGNED 顺序
- **签名后不可改**：SIGNED 状态的 AppModel 只读

## D.6 测试生成（Bottom Tab）

### TestGenerator
```typescript
function TestGenerator({ modelId }: { modelId: string }) {
  const { data: tests } = useGeneratedTests(modelId);  // GET /appmodels/{id}/tests
  const generate = useGenerateTests();                 // POST /appmodels/{id}/generate-tests
  const dryRun = useDryRunCase();

  const TEST_CLASSES = [
    { key: "skip_step", label: "跳步", source: "RESTler" },
    { key: "out_of_order", label: "乱序", source: "RESTler" },
    { key: "replay", label: "重放", source: "RESTler" },
    { key: "boundary", label: "越界", source: "Schemathesis" },
    { key: "invariant_violation", label: "不变量违反", source: "自建" },
  ];

  return (
    <div>
      <Button onClick={() => generate.mutate(modelId)}>Generate Tests</Button>
      <DataTable data={tests} columns={[
        { key: "test_class", label: "类型" },
        { key: "signature", label: "Signature", render: (v) => v.slice(0,16)+"..." },
        { key: "source", label: "来源" },
        { key: "status", label: "状态", render: StatusBadge },
        { key: "actions", label: "操作", render: (_, row) => (
          <Button size="sm" onClick={() => dryRun.mutate(row.id)}>Dry Run</Button>
        ) },
      ]} />
      {/* signature 幂等提示：同模型重复生成同 signature */}
    </div>
  );
}
```

### 生成后
- 5 类测试列表（每类可能有多个 Case）
- 每 Case 显示 signature（幂等验证）
- Dry Run 按钮 -> POST /cases/{id}/dry-run -> 显示靶场结果
- 状态：generated / validated / published

## D.7 漂移检测（Bottom Tab）

### DriftView
```typescript
function DriftView({ modelId }: { modelId: string }) {
  const { data: drift } = useDriftReport(modelId);  // GET /appmodels/{id}/drift
  const checkDrift = useCheckDrift();               // POST /appmodels/{id}/check-drift
  const regenerate = useRegenerateTests();

  return (
    <div>
      <Button onClick={() => checkDrift.mutate(modelId)}>Check Drift</Button>
      {drift && (
        <>
          <DiffSection title="New Endpoints" items={drift.new_endpoints} color="green" />
          <DiffSection title="Removed Endpoints" items={drift.removed_endpoints} color="red" />
          <DiffSection title="Changed" items={drift.changed} color="yellow" />
          {drift.has_drift && (
            <Button onClick={() => regenerate.mutate(modelId)}>
              Regenerate Tests（仅 changed signature）
            </Button>
          )}
        </>
      )}
    </div>
  );
}
```

## D.8 CaseStudio 状态流总结

```
用户选 AppModel
  -> useAppModel(id) 加载
  -> AppModelEditor 渲染（react-flow）
  -> 编辑（节点/边/属性/不变量/字段/角色）
  -> isDirty = true
  -> 保存（PUT /appmodels/{id}）-> isDirty = false
  
切到 YAML Tab
  -> 编辑 Case YAML
  -> Validate -> 显示 schema + 风险
  -> Dry Run -> 靶场结果
  -> Publish -> 需签名

切到 Signing Tab
  -> 状态流：LLM_PROPOSED -> HumanValidate -> SIGNED
  -> 签名后 Generate Tests

切到 TestGen Tab
  -> Generate -> 5 类 Case + signature
  -> Dry Run each

切到 Drift Tab
  -> Check Drift -> diff
  -> Regenerate if drift
```

## D.9 验收 D
- [ ] AppModel react-flow 编辑器：加/删/改状态+转换，保存
- [ ] PropertyPanel：Properties/Invariants/Fields/Roles/OutOfScope 五 tab
- [ ] YAML Monaco 编辑器 + Validate + Dry Run + Publish
- [ ] 签名流程：LLM_PROPOSED -> HumanValidate -> Sign -> 状态流转
- [ ] 5 类测试生成 + signature 幂等 + Dry Run
- [ ] 漂移检测 + 增量 regenerate
- [ ] isDirty 提示 + 离开确认

---

# Part F：P2 crAPI/vulhub 真实 E2E（1-2 周，可与 P1 并行）

## F.1 crAPI 配给

### `scripts/provision/docker-compose.crapi.yml`
crAPI 是多服务（web/api/auth/db），用官方 compose：
```yaml
# 从 https://github.com/crapi/crAPI 拉取 docker-compose
# 或内嵌简化版：
services:
  crapi-web:
    image: crapi/crapi-web:latest
    ports: ["8082:8082"]
    environment:
      - DB_HOST=crapi-db
      - API_HOST=crapi-api
  crapi-api:
    image: crapi/crapi-server:latest
    ports: ["8080:8080"]
    environment:
      - DB_HOST=crapi-db
  crapi-db:
    image: postgres:13-alpine
    environment:
      - POSTGRES_PASSWORD=crapi
      - POSTGRES_DB=crapi
  crapi-auth:
    image: crapi/crapi-identity:latest
    ports: ["8081:8081"]
networks:
  default:
    name: secopent-crapi
```

### 启动
```bash
docker compose -f scripts/provision/docker-compose.crapi.yml up -d
# 验证：curl http://localhost:8082（web）+ curl http://localhost:8080（api）
```

## F.2 crAPI 真实 E2E 测试

### `tests/e2e_real/test_crapi_real.py`
```python
@pytest.mark.e2e_real
def test_crapi_real_idor():
    """真实扫 crAPI，oracle 确认 IDOR/认证类 finding。"""
    # 1. scope: include http://host.docker.internal:8080 (api) + :8082 (web)
    # 2. Planner 生成 DAG（API 域必修类：IDOR/认证/参数污染）
    # 3. Orchestrator + SubprocessContainerExecutor 真跑 nuclei + RESTler
    # 4. oracle N/N 确认 IDOR Candidate
    # 5. 覆盖矩阵 + 报告
    assert report.has_confirmed_finding(cwe="CWE-639")  # IDOR
```

## F.3 vulhub 配给 + 测试

### 选 5 个 CVE 环境（覆盖不同类）
```yaml
# scripts/provision/docker-compose.vulhub.yml
services:
  # CVE-2024-XXXX RCE
  vulhub-rce:
    image: vulhub/some-product:version
    ports: ["8443:8080"]
  # CVE-2024-YYYY SQLi
  vulhub-sqli:
    image: vulhub/another:version
    ports: ["8444:80"]
  # ... 3 more
```

### `tests/oracle_ground_truth/test_vulhub_real.py`
```python
@pytest.mark.e2e_real
@pytest.mark.parametrize("cve,expected_cwe", [
    ("CVE-2024-XXXX", "CWE-78"),   # RCE
    ("CVE-2024-YYYY", "CWE-89"),   # SQLi
    ("CVE-2024-ZZZZ", "CWE-79"),   # XSS
    ("CVE-2024-AAAA", "CWE-918"),  # SSRF
    ("CVE-2024-BBBB", "CWE-22"),   # 路径穿越
])
def test_vulhub_real_cve(cve, expected_cwe):
    """oracle 对已知 CVE 真实确认。"""
    # 1. scope: include vulhub target
    # 2. nuclei 跑 CVE 专项模板
    # 3. oracle N/N 确认
    assert finding.cve == cve
    assert finding.cwe == expected_cwe
```

## F.4 验收 F
- [ ] crAPI 多镜像 compose 起来，3 端口可达
- [ ] crAPI 真实 E2E：≥1 Confirmed Finding（IDOR/认证）
- [ ] vulhub 5 CVE 环境起来
- [ ] vulhub 5 CVE oracle 真实确认全绿
- [ ] parser 修真实输出偏差

---

# Part G：P2 Scoped Egress nftables 强化（1-2 周，可与 P1 并行）

## G.1 目标
从 option c（app 层 EgressGuard + bridge）升级到网络层强制（nftables 阻 metadata/DB/Docker host/Scope 外）。

## G.2 Docker network + nftables 设计

### 创建 scoped-egress 网络
```bash
docker network create --driver bridge \
  --subnet 10.99.0.0/24 \
  --internal \  # 默认隔离，仅允许 nftables 放行的
  scoped-egress
```
注：`--internal` 网络默认无外网，需 nftables 放行 in-scope IP。

### nftables 规则（WSL2 内核）
```bash
# 阻断默认
nft add table inet scoped_egress
nft add chain inet scoped_egress forward '{ type filter hook forward priority 0; policy drop; }'

# 阻 metadata (169.254.169.254)
nft add rule inet scoped_egress forward ip daddr 169.254.0.0/16 drop
# 阻 loopback
nft add rule inet scoped_egress forward ip daddr 127.0.0.0/8 drop
# 阻 Docker host (host.docker.internal 解析的宿主 IP)
nft add rule inet scoped_egress forward ip daddr <host_ip> drop
# 阻 DB 端口
nft add rule inet scoped_egress forward tcp dport { 5432, 27017, 3306, 6379 } drop

# 放行 in-scope IP（从 scope_snapshot 动态注入）
nft add rule inet scoped_egress forward ip daddr <in_scope_ip> accept
# 放行 DNS (53) + HTTP/HTTPS (80/443) to in-scope
nft add rule inet scoped_egress forward tcp dport { 80, 443, 53 } ip daddr <in_scope_ip> accept
```

### 动态规则注入
```python
# src/secopent/infrastructure/egress/nftables_setup.py
class NftablesEgressSetup:
    def apply_scope(self, scope_snapshot: ScopeSnapshot) -> None:
        """根据 scope_snapshot 注入 nftables 放行规则。"""
        # 1. 清旧规则
        # 2. 阻 metadata/loopback/DB/host
        # 3. 放行 scope_snapshot.include 解析的 IP
        # 4. 验证规则生效
```

## G.3 SubprocessContainerExecutor 接入

### 修改
```python
# subprocess_executor.py
# 旧：--network bridge
# 新：--network scoped-egress
args += ["--network", "scoped-egress"]
```

### option c -> nftables 切换
- 生产：`--network scoped-egress`（nftables 强制）
- 测试/无 nftables：`--network bridge`（app 层 EgressGuard 兜底）
- 配置项：`config/egress.yaml` 选 mode（nftables / app_only）

## G.4 测试

### `tests/integration/test_scoped_egress_nftables.py`
```python
@pytest.mark.integration
def test_metadata_blocked_at_network_layer():
    """容器内访问 169.254.169.254 在 nftables 层被阻（非 app 层）。"""
    result = executor.run(
        image_digest="alpine@...",
        command=["sh", "-c", "wget -T 2 -q http://169.254.169.254/ && echo REACHABLE || echo BLOCKED"],
        network_policy="scoped-egress",
        ...
    )
    assert "BLOCKED" in result.stdout

@pytest.mark.integration
def test_db_port_blocked_at_network_layer():
    """DB 端口 5432 在 nftables 层被阻。"""
    result = executor.run(
        image_digest="alpine@...",
        command=["sh", "-c", "wget -T 2 -q http://host.docker.internal:5432/ && echo REACHABLE || echo BLOCKED"],
        ...
    )
    assert "BLOCKED" in result.stdout

@pytest.mark.integration
def test_in_scope_target_reachable():
    """in-scope 目标可达（juice_shop）。"""
    result = executor.run(
        image_digest="nuclei@...",
        command=["-u", "http://host.docker.internal:3000", "-silent"],
        ...
    )
    assert result.exit_code == 0
```

## G.5 WSL2 测试注意
- Docker Desktop 用 WSL2 内核，nftables 可用
- 但 Docker Desktop 的网络栈与原生 Linux 不同，`--internal` 网络行为需测试
- 若 WSL2 nftables 不生效，退回 option c（app 层），标注"Linux 部署时启用 nftables"

## G.6 验收 G
- [ ] `scoped-egress` Docker network 创建
- [ ] nftables 规则注入（metadata/DB/host 阻，in-scope 放行）
- [ ] SubprocessContainerExecutor 用 scoped-egress 网络
- [ ] metadata/DB 网络层阻断测试绿
- [ ] in-scope 目标可达测试绿
- [ ] 14 安全条件 egress 项升级为网络层强制

---

# 总结：批量推进 + 并行

```
P1 主线（Web UI）：
  A（W1 剩余）-> B（W2-W3 脚手架）-> C（W4-W7 六页）-> D（W8-W9 CaseStudio）-> E（W10-W11 测试+构建）

P2 并行线（独立于 Web）：
  F（crAPI/vulhub E2E）── 可与 C/D 并行
  G（nftables egress）── 可与 C/D 并行
```

| 批量 | 设计深度 | 工期 | 可并行 |
|---|---|---|---|
| A | ✅ 已有（模式验证） | 2-3 天 | 前置 |
| B | ✅ 本文 Part B | 2 天 | A 后 |
| C | ✅ 本文 Part C | 8-12 天 | B 后 |
| D | ✅ 本文 Part D | 5-7 天 | C 后 |
| E | ⚠️ 需补 Playwright 用例（W10 大纲已有） | 4-6 天 | D 后 |
| F | ✅ 本文 Part F | 1-2 周 | 与 C/D 并行 |
| G | ✅ 本文 Part G | 1-2 周 | 与 C/D 并行 |

**本文档覆盖 B+C+D+F+G 全部组件级/实现级设计。E（Playwright）待 D 完成后补测试用例（因需知最终页面结构）。**

开发模型按 A -> B -> C -> D -> E 顺序，F/G 可另起线并行。每阶段完成后我验收。
