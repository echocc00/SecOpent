# W10 -> W11 -> tag v1.1-web -> P2 详细实现方案

> **日期**：2026-07-28
> **角色**：设计 + 验收（本文档由验收方写，dev model 执行）
> **前置**：W4-W9 + BE-1..BE-7 已验收（见 `2026-07-28-w4w9-acceptance-and-followup.md`）；§2 三个 LLM 边界缺口已修复
> **本文档给出每一步的真实文件路径、真实服务签名、可执行代码骨架与验收点**

---

## 0. 执行顺序与依赖

```
FIX-LLM-BOUNDARY (0.5d, 已另文) ──┐
                                  ├──> W10 Playwright (2-3d) ──> W11 生产构建 (2-3d) ──> TAG v1.1-web
                                  │         │
                                  │         └──> (P2 并行) P2-F 真实 E2E / P2-G nftables / P2-占位接线
                                  └──────────────────────────────────────────────────────┘
```

**关键事实（核查所得，非假设）**：
- `tests/web/` **不存在**，W10 全新建
- `tests/e2e_real/conftest.py` 已有 `require_target` fixture + docker-skip 逻辑；目标 juice_shop:3000 / httpbin:8080
- `pyproject.toml` markers 已配：`integration` / `e2e_real` / `browser`；`addopts = "-m 'not e2e_real and not browser'"`
- `main.py` 的 `/assessments/{id}/events` SSE 是 **demo**（假 queued/running/completed），需转真实
- `main.py` **未挂 StaticFiles**（W11 工作）；`app.state.signing_keys` 已就绪
- `vite.config.ts` proxy `/api` rewrite 已配；build outDir `dist`，sourcemap on
- 5 个占位项的后端服务**全部已存在**，只差 REST 接线（见 §4）

---

## 1. W10：Playwright E2E（2-3 天）

### 1.1 环境准备

**安装**（`src/secopent/interfaces/web/package.json` devDeps）：
```bash
cd src/secopent/interfaces/web
npm i -D @playwright/test
npx playwright install chromium
```

**Python 侧**（已有 marker `browser`）：
```bash
py -3.12 -m pip install pytest-playwright
# 或纯 node 跑：npx playwright test（推荐，与前端同栈）
```

**推荐**：用 **node 版 Playwright**（`@playwright/test`），与前端同栈、TS 类型好、artifact 管理开箱。Python `pytest-playwright` 仅当想统一 pytest runner 时用。下文按 **node 版**给。

### 1.2 配置文件

**`src/secopent/interfaces/web/playwright.config.ts`**（新建）：
```typescript
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,          // 共享后端 fixture，串行更稳
  retries: process.env.CI ? 2 : 0,
  reporter: [["html", { open: "never" }], ["list"]],
  use: {
    baseURL: "http://localhost:5173",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      command: "py -3.12 -m uvicorn secopent.interfaces.api.main:create_app --factory --port 8000",
      url: "http://localhost:8000/health",
      reuseExistingServer: !process.env.CI,
      timeout: 30000,
    },
    {
      command: "npm run dev",
      url: "http://localhost:5173",
      reuseExistingServer: !process.env.CI,
      timeout: 30000,
    },
  ],
});
```

**`src/secopent/interfaces/web/e2e/fixtures.ts`**（新建，统一 seed + 清理）：
```typescript
import { test as base, expect } from "@playwright/test";

// 预置 project + scope + catalog，返回 assessment 创建链
type Fixtures = { seededProjectId: string; seededSigningKeyId: string };

export const test = base.extend<Fixtures>({
  seededProjectId: async ({ request }, use) => {
    const res = await request.post("/api/projects", { data: { name: `e2e-${Date.now()}` } });
    expect(res.status()).toBe(201);
    const { id } = await res.json();
    await use(id);
    // 清理由后端 in-memory SQLite 隔离保证（每次 uvicorn 重启即清）
  },
  seededSigningKeyId: async ({ request }, use) => {
    const res = await request.post("/api/signing-keys", { data: { name: `e2e-key-${Date.now()}`, actor_role: "human" } });
    const { key_id } = await res.json();
    await use(key_id);
  },
});
export { expect };
```

> **注意**：`webServer` 起的 uvicorn 用临时 SQLite（`create_app` 无 engine 参数时自动建 temp db），每次重启隔离。若需跨用例共享 seed，加 `globalSetup` 调 `/api/projects` 预置。

### 1.3 测试用例（10 个，对应设计 §C 验收矩阵）

**`e2e/01-dashboard.spec.ts`**：
```typescript
import { test, expect } from "./fixtures";
test("dashboard loads with project list + system status", async ({ page, seededProjectId }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /仪表盘|Dashboard/i })).toBeVisible();
  await expect(page.getByText(seededProjectId)).toBeVisible();   // 项目卡
  await expect(page.getByText(/知识层|Updates/i)).toBeVisible(); // 系统状态区
});
```

**`e2e/02-new-assessment.spec.ts`**（5 步向导）：
```typescript
test("new assessment wizard: project -> scope -> freeze -> mode -> plan", async ({ page, seededProjectId }) => {
  await page.goto("/assessments/new");
  // 1 选项目
  await page.getByLabel(/项目/).selectOption(seededProjectId);
  await page.getByRole("button", { name: /下一步|Next/ }).click();
  // 2 scope
  await page.getByLabel(/include/i).fill("http://localhost:3000");
  await page.getByRole("button", { name: /下一步|Next/ }).click();
  // 3 冻结（显示 digest）
  await page.getByRole("button", { name: /冻结|Freeze/ }).click();
  await expect(page.getByText(/sha256:[0-9a-f]{8}/)).toBeVisible();
  await page.getByRole("button", { name: /下一步|Next/ }).click();
  // 4 模式
  await page.getByLabel(/approval/i).check();
  await page.getByRole("button", { name: /下一步|Next/ }).click();
  // 5 生成 plan（DAG 渲染）
  await page.getByRole("button", { name: /生成.*[Pp]lan|Generate/ }).click();
  await expect(page.locator(".react-flow")).toBeVisible();
  await expect(page.locator(".react-flow__node").first()).toBeVisible();
});
```

**`e2e/03-assessment-detail-sse.spec.ts`**（SSE 实时）：
```typescript
test("assessment detail: SSE event stream + DAG node color", async ({ page }) => {
  // 前置：创建 assessment（API 直建，跳过向导）
  // ... POST /api/assessments ...
  await page.goto(`/assessments/${id}`);
  await expect(page.locator(".react-flow")).toBeVisible();
  // SSE demo 当前推 queued/running/completed；验证节点状态色变化
  const runningNode = page.locator(".react-flow__node[data-status='running']");
  await expect(runningNode).toBeVisible({ timeout: 5000 });
  // 完成态
  await expect(page.locator(".react-flow__node[data-status='completed']").first()).toBeVisible({ timeout: 5000 });
});
```

> **依赖**：SSE demo 必须先转真实（见 §4.6）或保留 demo 但前端节点状态映射要对。建议 W10 前先做 §4.6 的 SSE 真实化（小改）。

**`e2e/04-approval-center.spec.ts`**（批准 + 拒绝）：
```typescript
test("approve: pending -> approved, moves to history", async ({ page }) => {
  // 前置：建 assessment + 生成 plan + 进 AWAITING_APPROVAL
  await page.goto("/approvals");
  await page.getByRole("tab", { name: /待审|Pending/ }).click();
  await page.getByText(assessmentId).click();
  await page.getByRole("button", { name: /批准|Approve/ }).click();
  await expect(page.getByText(assessmentId)).toHaveCount(0); // 移出 pending
  await page.getByRole("tab", { name: /历史|History/ }).click();
  await expect(page.getByText(assessmentId)).toBeVisible();
});

test("reject: pending -> rejected with reason + audit chain", async ({ page, request }) => {
  await page.goto("/approvals");
  await page.getByText(assessmentId2).click();
  await page.getByLabel(/理由|Reason/).fill("scope too broad");
  await page.getByRole("button", { name: /拒绝|Reject/ }).click();
  // 校验审计链
  const audit = await request.get("/api/audit/events");
  const events = await audit.json();
  expect(events.some((e: any) => e.action === "approval.rejected" && e.resource_id === assessmentId2)).toBeTruthy();
});
```

**`e2e/05-findings-evidence.spec.ts`**（筛选 + 三层证据）：
```typescript
test("findings filter + evidence RAW/REDACTED/SUMMARY", async ({ page }) => {
  await page.goto("/findings");
  await page.getByLabel(/severity/i).selectOption("critical");
  await expect(page.locator("tr")).toHaveCount(1);
  await page.getByText(findingTitle).click();              // 抽屉
  await page.getByRole("tab", { name: /RAW/ }).click();
  await expect(page.getByText(/raw/i)).toBeVisible();
  await page.getByRole("tab", { name: /REDACTED/ }).click();
  await expect(page.getByText(/\*\*\*\*/)).toBeVisible();  // 脱敏标记
  await page.getByRole("tab", { name: /SUMMARY/ }).click();
});
```

**`e2e/06-case-studio-model.spec.ts`**（react-flow 建模）：
```typescript
test("case studio: add state + transition + save", async ({ page }) => {
  await page.goto("/case-studio");
  await page.getByRole("button", { name: /新建.*[Mm]odel|New/ }).click();
  await page.getByRole("button", { name: /加状态|Add State/ }).click();
  // 拖两个节点
  await page.mouse.click(200, 200);
  await page.mouse.click(400, 200);
  // 加转换（边）
  await page.getByRole("button", { name: /加转换|Add Transition/ }).click();
  // 连接（react-flow Handle 拖拽）
  await page.locator(".react-flow__handle.source").dragTo(page.locator(".react-flow__handle.target").first());
  await page.getByRole("button", { name: /保存|Save/ }).click();
  await expect(page.getByText(/已保存|saved/i)).toBeVisible();
});
```

**`e2e/07-case-studio-yaml-sign.spec.ts`**（YAML -> 签名）：
```typescript
test("case studio: yaml analyze -> validate -> sign", async ({ page, seededSigningKeyId }) => {
  await page.goto("/case-studio");
  // 选已有模型，切 YAML 标签
  await page.getByRole("tab", { name: /YAML/ }).click();
  await page.getByRole("button", { name: /分析|Analyze/ }).click();
  await expect(page.getByText(/declared|computed/i)).toBeVisible();
  await page.getByRole("button", { name: /校验|Validate/ }).click();
  await page.getByRole("tab", { name: /签名|Sign/ }).click();
  await page.getByLabel(/密钥|[Kk]ey/).selectOption(seededSigningKeyId);
  await page.getByRole("button", { name: /签名|Sign/ }).click();
  await expect(page.getByText(/SIGNED|已签名/)).toBeVisible();
});
```

**`e2e/08-case-studio-generate-tests.spec.ts`**：
```typescript
test("generate 5-class tests from signed model", async ({ page }) => {
  // 前置模型已签名
  await page.getByRole("tab", { name: /测试|[Tt]est/ }).click();
  await page.getByRole("button", { name: /生成.*测试|Generate/ }).click();
  await expect(page.getByText(/skip_step|跳步/)).toBeVisible();
  await expect(page.getByText(/out_of_order|乱序/)).toBeVisible();
  await expect(page.getByText(/replay|重放/)).toBeVisible();
  await expect(page.getByText(/boundary|越界/)).toBeVisible();
  await expect(page.getByText(/invariant|不变量/)).toBeVisible();
});
```

**`e2e/09-llm-boundary-agent-403.spec.ts`**（核心安全属性）：
```typescript
import { test, expect } from "@playwright/test";

test("agent actor_role is rejected on human-only endpoints", async ({ request }) => {
  // 直调 API（不经 UI），模拟 agent
  const cases = [
    { method: "POST", path: "/api/appmodels/{id}/{v}/sign", body: { actor_role: "agent" } },
    { method: "POST", path: "/api/cases/{id}/publish", body: { actor_role: "agent" } },
    { method: "POST", path: "/api/approvals", body: { actor_role: "agent", /*...*/ } },
    { method: "POST", path: "/api/approvals/reject", body: { actor_role: "agent", /*...*/ } },
    { method: "POST", path: "/api/findings/{id}/verdict", body: { actor_role: "agent", verdict: "confirmed" } },
    { method: "POST", path: "/api/signing-keys", body: { actor_role: "agent", name: "x" } },
  ];
  for (const c of cases) {
    const res = await request[c.method.toLowerCase()](c.path, { data: c.body });
    expect(res.status(), `${c.path}`).toBe(403);
  }
});
```

> **此用例是 §2 边界修复的验收闸**——3 个缺口修好后此测试才绿。

**`e2e/10-updates-health.spec.ts`**：
```typescript
test("updates page shows bundle + audit chain verify", async ({ page, request }) => {
  await page.goto("/updates");
  await expect(page.getByText(/active bundle|当前.*[Bb]undle/i)).toBeVisible();
  // 审计链校验（后端 /api/audit/verify）
  const verify = await request.get("/api/audit/verify");
  expect((await verify.json()).valid).toBeTruthy();
});
```

### 1.4 W10 验收点
- [ ] `npx playwright test` 10 用例全绿
- [ ] `e2e/09-llm-boundary-agent-403` 绿（依赖 §2 修复）
- [ ] CI artifact：失败截图 + trace 留档
- [ ] `pytest -m browser`（若用 Python 版）或 node 版不阻塞默认 `pytest`（`addopts` 已排除 browser）

---

## 2. W11：生产构建打磨（2-3 天）

### 2.1 Monaco 本地化（去 CDN）

**现状**：`@monaco-editor/react` 默认从 `cdn.jsdelivr.net` 加载 monaco 内核，离线/合规不通过。

**方案**（`src/secopent/interfaces/web/package.json` + vite.config.ts）：
```bash
npm i monaco-editor
```

**`vite.config.ts`** 加 worker 处理：
```typescript
import monacoEditorPlugin from "vite-plugin-monaco-editor";
// 或手动配置（vite-plugin-monaco-editor 对 vite 8 兼容性待验，手动更稳）：
export default defineConfig({
  // ...
  optimizeDeps: { include: ["monaco-editor/esm/vs/editor/editor.worker"] },
  build: {
    rollupOptions: {
      output: {
        manualChunks: { monaco: ["monaco-editor"] },
      },
    },
  },
});
```

**`YamlEditor.tsx`** 显式 loader（去掉 CDN 默认）：
```typescript
import { loader } from "@monaco-editor/react";
import * as monaco from "monaco-editor";
import editorWorker from "monaco-editor/esm/vs/editor/editor.worker?worker";

// 一次性配置（模块顶层）
self.MonacoEnvironment = { getWorker: () => new editorWorker() };
loader.config({ monaco });
```

**验收**：断网构建 + 运行，YAML 编辑器仍可用；bundle 多一个 monaco chunk（~600KB，可接受，已懒加载在 CaseStudio）。

### 2.2 FastAPI 静态服务 + SPA fallback

**`src/secopent/interfaces/api/main.py`** 末尾（`return app` 前）加：
```python
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

WEB_DIST = Path(os.environ.get("SECOPTENT_WEB_DIST", ""))

if WEB_DIST.exists():
    # 静态资源（带 hash 的 assets）
    app.mount("/assets", StaticFiles(directory=WEB_DIST / "assets"), name="web-assets")

    # SPA fallback：所有非 API 路由回 index.html（react-router client routing）
    @app.get("/{full_path:path}")
    def spa_fallback(full_path: str) -> FileResponse:
        # API 路由已注册，不会被这里捕获（FastAPI 优先匹配已注册路由）
        index = WEB_DIST / "index.html"
        return FileResponse(index)
```

**关键顺序**：`spa_fallback` 必须在所有 `include_router` 之后注册，FastAPI 按注册顺序匹配，API 路由优先。`/assets` 单独 mount 避免被 fallback 拦截。

**环境变量**：
- 开发：不设 `SECOPTENT_WEB_DIST` -> 不 mount（vite dev server :5173 走 proxy）
- 生产：`SECOPTENT_WEB_DIST=src/secopent/interfaces/web/dist`

**`main.py` 顶部加** `import os`。

### 2.3 构建 + 部署脚本

**`scripts/build_web.sh`**（新建）：
```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/src/secopent/interfaces/web"
npm run build
export SECOPTENT_WEB_DIST="$(pwd)/dist"
py -3.12 -m uvicorn secopent.interfaces.api.main:create_app --factory --port 8000
```

### 2.4 W11 验收点
- [ ] `SECOPTENT_WEB_DIST=dist uvicorn ...` 起服务
- [ ] 浏览器访问 `http://localhost:8000/`（非 5173）-> SPA 加载
- [ ] 7 页路由直接刷新（如 `/case-studio`）不 404（SPA fallback 生效）
- [ ] `/api/projects` 仍返回 JSON（API 与静态共存）
- [ ] 断网 Monaco 可用
- [ ] `npm run build` 产物 dist/ 提交或 CI 产物

---

## 3. TAG v1.1-web 验收清单

dev model 完成上述 + 边界修复后，我验收以下全部通过才 tag：

| 类别 | 项 | 命令/检查 |
|---|---|---|
| 边界 | 3 处 actor_role 强制 | `pytest -k "actor_role or boundary"` 全绿 |
| 后端 | 全套无回归 | `pytest -q` 887+ passed |
| 后端 | ruff/mypy | `ruff check .` + `mypy src/secopent` clean |
| 前端 | 构建 | `npm run build` clean |
| 前端 | 包体 | 主包 gzip < 300KB |
| E2E | Playwright 10 用例 | `npx playwright test` 全绿 |
| 生产 | 静态服务 | `:8000/` 加载 SPA + 7 页刷新不 404 |
| 文档 | 更新 README 部署段 | 单命令启动 |
| tag | 打标签 | `git tag v1.1-web -m "..."` |

---

## 4. P2-占位接线（3-5 天，可与 W10-W11 并行）

**核心发现**：5 个占位项的后端服务**全部已存在**，只差 REST 端点。逐个接线。

### 4.1 P1：Updates 5 探测器（`GET /updates/health` 扩展）

**现状后端**（`src/secopent/application/health.py:125`）：
```python
class KnowledgeHealthMonitor:
    def check_source_stale(self) -> tuple[HealthAlert, ...]      # 检测器1
    def check_curation_lag(self) -> tuple[HealthAlert, ...]      # 检测器2
    # 检测器3 覆盖率退化：enforce_coverage_gate（需 old+new CoverageMatrix，不在 check_all）
    def check_source_unreachable(self) -> tuple[HealthAlert, ...]# 检测器4
    def check_signature_invalid(self) -> tuple[HealthAlert, ...] # 检测器5
    def check_all(self) -> HealthReport                           # 聚合 1/2/4/5
```

**接线**：`updates.py` 路由扩 `GET /updates/health`：
```python
@router.get("/health", response_model=HealthReportOut)
def updates_health(session: DbSession) -> HealthReportOut:
    # 构造 monitor（注入真实 checker 或 stub）
    monitor = KnowledgeHealthMonitor(
        audit_service=AuditService(SqlAlchemyAuditRepository(session)),
        freshness_checker=...,    # infra GitFreshnessChecker
        curation_checker=...,
        reachability_checker=...,  # infra OsvReachabilityChecker
        signature_checker=...,
    )
    report = monitor.check_all()
    return _report_to_out(report)  # 含 alerts + 4 检测器状态
```

**前端 Updates.tsx**：5 探测器占位 -> 真实数据，每个 alert 红色/绿色卡片。第 5（覆盖率退化）显示 `enforce_coverage_gate` 最近一次 override 记录（从审计链读 `coverage.override` 事件）。

**验收**：`GET /updates/health` 返回 4 检测器状态 + 历史覆盖 override。

### 4.2 P2：DriftDetector REST（`GET /appmodels/{id}/{v}/drift`）

**现状后端**（`src/secopent/application/drift_detector.py:31`）：
```python
class DriftDetector:
    def check(self, current: AppModel, reimported: AppModel) -> DriftReport
        # -> DriftReport(app_id, added, removed, changed, has_drift)
```

**接线**：`appmodels.py` 加端点。需要"re-imported"模型——前端上传新 spec：
```python
@router.post("/{app_id}/{version}/drift", response_model=DriftReportOut)
def check_drift(app_id: str, version: str, payload: DriftRequest, session: DbSession) -> DriftReportOut:
    current = _repo(session).get(app_id, version)
    reimported = _from_spec(payload.spec)  # OpenAPI/Postman -> AppModel
    report = DriftDetector().check(current, reimported)
    return DriftReportOut(added=report.added, removed=report.removed, changed=report.changed, has_drift=report.has_drift)
```

**前端 DriftView.tsx**：上传 spec -> 调 drift -> 高亮 added（绿）/removed（红）/changed（黄）端点。

**验收**：上传改过的 OpenAPI -> 返回 diff；has_drift=true 时提示重新生成测试。

### 4.3 P3：Job 重试（`POST /jobs/{id}/retry`）

**现状后端**（`src/secopent/application/jobs.py:33`）：
```python
class JobService:
    def requeue(self, job_id: str) -> Job   # 即 retry
```

**接线**：`jobs.py` 路由加：
```python
@router.post("/{job_id}/retry", response_model=JobOut)
def retry_job(job_id: str, session: DbSession) -> JobOut:
    service = JobService()
    try:
        job = service.requeue(job_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _to_out(job)
```

**前端 AssessmentDetail.tsx**：Job 列表每行失败态显示"重试"按钮 -> 调 retry -> invalidate jobs query。

**验收**：失败 job 重试后状态回 READY。

### 4.4 P4：紧急停止（`POST /assessments/{id}/stop`）

**现状后端**（`src/secopent/application/emergency_stop.py:48`）：
```python
class EmergencyStop:
    def __init__(self, *, revoker: PermitRevoker, terminator: ContainerTerminator): ...
    def trigger(self, *, actor: str, reason: str) -> EmergencyReport
    def is_triggered(self) -> bool
```

**接线**：`assessments.py` 加端点（**human-only**）：
```python
@router.post("/{assessment_id}/stop", response_model=EmergencyReportOut)
def emergency_stop(assessment_id: str, payload: StopRequest, session: DbSession) -> EmergencyReportOut:
    if payload.actor_role != "human":
        raise HTTPException(status_code=403, detail="emergency stop is human-only")
    stop = EmergencyStop(revoker=..., terminator=...)  # infra 注入
    report = stop.trigger(actor=payload.actor, reason=payload.reason)
    AuditService(...).record(actor=payload.actor, action="assessment.emergency_stop",
                             resource_type="assessment", resource_id=assessment_id,
                             payload={"reason": payload.reason, "permits_revoked": report.permits_revoked})
    return _to_out(report)
```

**前端 AssessmentDetail.tsx**：顶部红色"紧急停止"按钮 -> 确认对话框（填理由）-> 调 stop。

**验收**：触发后 permits 全回收 + 审计链记录；agent 调 403。

### 4.5 P5：报告生成（`POST /assessments/{id}/reports`）

**现状后端**（`src/secopent/application/report_renderer.py:66`）：
```python
class ReportRenderer:
    def __init__(self, templates: TemplateRenderer, redactor: Redactor): ...
    def render(self, data: ReportData, *, report_id: str) -> Report
```

**接线**：`reports.py` 已有路由占位，补真实：
```python
@router.post("/assessments/{assessment_id}/reports", status_code=201, response_model=ReportOut)
def generate_report(assessment_id: str, session: DbSession) -> ReportOut:
    # 聚合 ReportData：findings + coverage_rate + scope
    findings = SqlAlchemyFindingRepository(session).list_by_assessment(assessment_id)
    data = ReportData(title=..., assessment_id=assessment_id, findings=findings, coverage_rate=...)
    renderer = ReportRenderer(JinjaTemplateRenderer(), DefaultRedactor())
    report = renderer.render(data, report_id=str(uuid4()))
    SqlAlchemyReportRepository(session).add(report)
    return _to_out(report)
```

**前端 AssessmentDetail.tsx**：报告生成按钮 -> 调 POST -> 跳转 `/reports/{id}` 展示。

**验收**：生成的报告含 exec summary + findings + remediation + 脱敏；completeness gate 跑过。

### 4.6 P6：SSE 真实化（`/assessments/{id}/events`）

**现状**（`main.py:102`）：demo 推假 `queued/running/completed`。

**真实化**：订阅 JobService 事件流：
```python
@app.get("/assessments/{assessment_id}/events")
def assessment_events(assessment_id: str, request: Request) -> StreamingResponse:
    def _stream() -> Iterator[str]:
        last_seen: tuple[Job, ...] = ()
        while True:
            if await request.is_disconnected():  # 同步版用 request.scope["app"]
                break
            jobs = JobService().all_for_assessment(assessment_id)
            for job in jobs:
                if job not in last_seen:
                    yield f"data: {json.dumps(_job_event(job))}\n\n"
            last_seen = jobs
            time.sleep(1)
    return StreamingResponse(_stream(), media_type="text/event-stream")
```

**简化方案**（推荐先做）：保留 demo 但前端 AssessmentDetail 把节点状态从 SSE 映射到 DAG 颜色（W6 已做）。真实 SSE 等 P2 远程 Worker 时再做（本地单机 job 事件直接轮询 `/jobs` 即可）。

**验收**：SSE 推真实 job 状态变更；前端 DAG 节点实时变色。

---

## 5. P2-F：crAPI/vulhub 真实 E2E（1-2 周）

### 5.1 靶标 compose 扩展

**`scripts/provision/docker-compose.targets.yml`** 加 crAPI：
```yaml
services:
  juice_shop: { image: "...", ports: ["3000:3000"] }   # 已有
  httpbin: { image: "...", ports: ["8080:80"] }          # 已有
  crapi:
    image: crapi/crapi-api:latest
    ports: ["8888:8080"]
    environment:
      - DB_HOST=crapi-db
  crapi-db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_PASSWORD=crapi
```

**注意**：crAPI 镜像若 Docker Hub 拉不动，配 daemon.json mirrors（docker.1panel.live）。

### 5.2 测试矩阵（`tests/e2e_real/`，扩展现有 `test_real_scans.py`）

| 文件 | 域 | 靶标 | 适配器链 | oracle |
|---|---|---|---|---|
| `test_web_juice_shop.py` | Web/API | Juice Shop | subfinder->httpx->nuclei->dalfox | RescanVerifier N/N |
| `test_web_crapi.py` | Web/API | crAPI | katana->nuclei | BOLA/BFLA 复现 |
| `test_api_httpbin.py` | API | httpbin | Schemathesis（OpenAPI） | 5 类状态码突变 |
| `test_network_local.py` | 网络 | 本机 metasploitable | nmap->naabu | 端口 finding |
| `test_cloud_docker.py` | 云 | 本地 docker.sock | 5 云适配器 | 容器逃逸 finding |
| `test_asset_graph.py` | 资产 | Juice+httpbin | subfinder->httpx->katana | 资产图节点/边 |

**每个测试结构**（沿用 `test_real_scans.py` 模式）：
```python
@pytest.mark.e2e_real
def test_juice_shop_sqli_oracle_confirmed(require_target):
    url = require_target("juice_shop")
    # 1. 跑 nuclei 真实容器
    observations = run_adapter("nuclei", target=url, templates=["sqli"])
    # 2. 关联成 finding
    findings = FindingCorrelator().correlate(observations)
    assert any(f.rule_id == "nuclei-sqli" for f in findings)
    # 3. oracle N/N 复现
    sqli_finding = next(f for f in findings if f.rule_id == "nuclei-sqli")
    verdict = RescanVerifier(n=3).verify(sqli_finding)
    assert verdict == VerificationStatus.CONFIRMED
    # 4. evidence 三层 + 审计链
    assert sqli_finding.evidence.raw_uri
    assert sqli_finding.evidence.redacted_uri
    assert sqli_finding.evidence.summary_uri
```

**验收**：`pytest -m e2e_real` 6 文件全绿（需 Docker + 靶标 up）；每个 finding 有三层 evidence + oracle 结论。

---

## 6. P2-G：nftables Scoped Egress（1-2 周）

### 6.1 设计

**现状**：option c（Docker bridge + host.docker.internal + app 层 PolicyEngine scope）
**目标**：网络层强制，scope 经 nftables 白名单

### 6.2 实现

**`scripts/provision/egress.nft`**（新建）：
```nft
#!/usr/sbin/nft -f
table inet secopent_egress {
    set allowed_targets { type ipv4_addr; flags interval; elements = {} }

    chain output {
        type filter hook output priority 0; policy drop;
        # 允许已建立的连接
        ct state established,related accept
        # 允许 DNS（解析阶段）
        udp dport 53 accept
        tcp dport 53 accept
        # 允许 Interactsh 通道（host.docker.internal）
        ip daddr 192.0.2.1 tcp dport 8444 accept  # host.docker.internal 映射
        # scope 白名单
        ip daddr @allowed_targets accept
        # 其余 DROP + 记日志
        log prefix "SECOPTENT_EGRESS_DROP " drop
    }
}
```

**动态注入**（`src/secopent/infrastructure/network/nft_scope.py`，新建）：
```python
class NftScopeEnforcer:
    """注入 scope 白名单到 nftables secopent_egress set。"""

    def apply_scope(self, snapshot: ScopeSnapshot) -> None:
        ips = self._resolve_and_dedupe(snapshot)  # 含 DNS rebinding 二次校验
        for ip in ips:
            subprocess.run(
                ["nft", "add", "element", "inet", "secopent_egress",
                 "allowed_targets", "{", ip, "}"],
                check=True,
            )
        # 拒绝元数据 IP（防云元数据泄露）
        for blocked in ("169.254.169.254", "fd00:ec2::254"):
            subprocess.run(["nft", "add", "element", ...], check=True)

    def revoke(self) -> None:
        subprocess.run(["nft", "flush", "set", "inet", "secopent_egress", "allowed_targets"], check=True)
```

**PolicyEngine 接线**：scope 10-step chain 第 6 步（IP Recheck）后调 `NftScopeEnforcer.apply_scope`。

### 6.3 WSL2 注意

- Docker Desktop on Windows 用 WSL2 后端，容器跑在 WSL2 netns
- nftables 需在 WSL2 内核执行（`wsl -e nft ...`）或 Docker Desktop 的 `com.docker.network` 命名空间
- **简化**：若 WSL2 nft 不可用，退回 option c（app 层 PolicyEngine + Docker `--network` 隔离），记为 P2-G 后半段

### 6.4 验收
- [ ] 恶意 scope（含 169.254.169.254）-> nft DROP + 审计拒绝事件
- [ ] 合法 scope -> 仅白名单 IP 可达
- [ ] 评测结束 -> `revoke()` 清空 set
- [ ] `pytest -m integration` 含 nft 测试（需 Linux，Windows 跳过）

---

## 7. 给 dev model 的执行清单

| 序 | 任务 | 工期 | 依赖 | 验收 |
|---|---|---|---|---|
| 1 | §2 边界修复（另文） | 0.5d | - | 3 个 403 测试 |
| 2 | §4.6 SSE 真实化（简化版） | 0.5d | 1 | AssessmentDetail DAG 变色 |
| 3 | W10 Playwright 10 用例 | 2-3d | 1,2 | `npx playwright test` 全绿 |
| 4 | W11 Monaco 本地 + StaticFiles | 2-3d | - | `:8000/` SPA + 断网 Monaco |
| 5 | **TAG v1.1-web** | - | 1-4 | §3 清单全过 |
| 6 | P2-占位 §4.1-4.5 | 2-3d | 5 | 5 端点真实数据 |
| 7 | P2-F crAPI/vulhub | 1-2w | 5 | 6 e2e_real 绿 |
| 8 | P2-G nftables | 1-2w | 5 | 恶意 scope DROP |

**并行**：6/7/8 可与 3/4 部分并行（不同文件域）。

**参考**：
- 验收基线：`sepcs/2026-07-28-w4w9-acceptance-and-followup.md`
- 现有 P2 设计：`sepcs/2026-07-27-p1-p2-detailed-design-batch.md`（Part F crAPI/vulhub + Part G nftables）

---

## 8. 验收方节奏

1. §2 边界修复 -> 我验 3 个 403
2. W10 -> 我验 10 用例（含边界用例 09）
3. W11 -> 我验生产构建 + SPA fallback
4. TAG -> 我按 §3 清单验 + 打 tag
5. P2 各项 -> 分别验收

*文档完。dev model 按 §7 执行。*
