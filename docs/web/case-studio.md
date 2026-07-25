# Web Case Studio（可视化建模）

> 状态：M4 规划基线（后端 API 复用 M3 ModelBuilder / M2 CaseService；前端 UI 在具备浏览器环境时落地）。
> 设计来源：`sepcs/2026-07-25-catalog-driven-agent-workbench-design.md` §11.9/§11.10。

Case Studio 让人**可视化建模并签发 AppModel**，是 M3 模型驱动逻辑测试的人机入口。

## 7 页

| 页 | 功能 |
|---|---|
| Dashboard | 项目/评估概览 |
| NewAssessment | 新建评估（选 scope + 资产类型） |
| AssessmentDetail | 计划 DAG / Job 状态 / 进度（SSE） |
| ApprovalCenter | 人审批（plan + scope digest） |
| Findings | 发现列表 / 验证状态 / 证据 |
| **CaseStudio** | 可视化建模（核心） |
| Updates | 知识层 bundle 同步状态 |

## CaseStudio 建模能力

- **状态机图编辑**：节点（states）+ 边（transitions，含 endpoint/params/幂等）；mermaid.js / vis.js 渲染。
- **不变量编辑**：`cart.total >= 0` 等业务规则（驱动 InvariantStrategy）。
- **trust 边界标记**：每字段标 `server` / `client` 来源。
- **角色能力**：roles + capabilities（驱动越权测试）。
- **YAML 编辑 + Schema 校验 + 风险预览**：调 RiskAnalyzer 静态分析（声明风险不得低于计算风险）。
- **Fixture + Dry Run + Diff**：5 类 fixture 校验；靶场 dry run；与上一版 diff（DriftDetector）。
- **审核 + 签名**：人校验补不变量 → HUMAN_VALIDATED → Ed25519 签名 → SIGNED。

## 后端 API

复用：
- ModelBuilder（M3）：`import_model`（OpenAPI/Postman/流量）/ `validate`（人校验）/ `sign`。
- CaseService（M2）：生命周期 + 风险门 + model_generated 快速通道。
- LogicTestGenerator（M3）：预览从模型生成的 5 类测试 + signature。
- DriftDetector（M3）：重新导入 diff。

## 安全边界

- **不提供浏览器任意代码执行**：建模是声明式的，执行在后端沙箱（M2 PythonPluginSandbox）。
- **审核/签名为人专属**：agent/LLM 禁止 review/sign/publish（LLM边界）。
- 所有变更经 Audit 留痕。
