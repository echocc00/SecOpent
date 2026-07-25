# 接口层（Interfaces: MCP / CLI / API / Web）

> 状态：M4 基线。MCP 工具注册表（自写编排工具 + 采纳 MCP 标 trust level）、FastAPI API（command/query + 幂等 + SSE）、CLI（argparse）。接口层是 Application Service 的薄分发层，无业务逻辑。
> 设计来源：`sepcs/2026-07-25-catalog-driven-agent-workbench-design.md` §6/§11/§12；ADR-002/007/010/011。

三类接口（MCP / CLI / API / Web）**共用同一组 Application Service**，保证确定性脊柱只有一个实现。

## MCP Server（§13，ADR-007 采纳优先）

`interfaces/mcp/tool_registry.py::McpToolRegistry`（框架无关，可在无 MCP SDK 下单测；SDK 在 M5 包装这些 spec）：

- **自写编排工具**（`self_written`，6 组 16 个）：project_create / scope_draft / scope_validate / scope_freeze / plan_generate / plan_approve / assessment_start/pause/resume/cancel/status / asset_list / finding_list / finding_validate / intel_search / report_render。每个绑定对应 Application Service，经 PolicyEngine 校验。
- **采纳外部 MCP**（cve-mcp-server / mcp-security-hub）：标 `adopted_external_mcp` / `untrusted_external_mcp` trust level。其输出**不可驱动确定性裁决**（只作情报参考）。
- **禁止暴露**：`shell` / `docker_run` / `execute_python` / `exec` / `eval` / `run_command` / `subprocess` 永不注册——agent 得到的是编排能力，不是任意执行。

## CLI（§13）

`interfaces/cli/main.py`：基于 argparse（typer 非依赖）的薄分发器，只调 Application Service，不相对 CWD 解析任何路径（跨目录可跑）。命令：`version` / `doctor`（确定性核心健康检查）。完整命令集（init/serve/worker/project/scope/assessment/tool/case/intel/update/finding/evidence/report）包装同一组 Service。

## FastAPI OpenAPI（§13，长任务 SSE）

`interfaces/api/main.py::create_app`（工厂，测试用隔离实例 + 内存 store；生产接 SqlAlchemy repository）：

- **Command/Query 分离**：POST 写、GET 读。
- **幂等**：重复 POST 带相同 `Idempotency-Key` 返回原始响应，不重复创建。
- **长任务 SSE**：`GET /assessments/{id}/events` 以 `text/event-stream` 推送状态（queued/running/completed）。
- 标准错误码：404（未知资源）/ 422（非法 payload）。

## Web Case Studio（§13，M3 后端 + M4 UI）

`interfaces/web/`（规划）：7 页（Dashboard / NewAssessment / AssessmentDetail / ApprovalCenter / Findings / CaseStudio / Updates）。Case Studio 调 ModelBuilder（M3）/ CaseService（M2）做可视化建模（状态机图编辑 / 不变量 / trust 边界 / 角色能力）+ YAML 编辑 + Schema 校验 + 风险预览 + Fixture + Dry Run + Diff + 审核 + 签名。**不提供浏览器任意代码执行**。审核/签名为人专属（LLM边界）。

## 分层约束

- `interfaces/` 可用框架（FastAPI / Jinja2 / pydantic / MCP SDK）；`domain/` 与 `application/` 禁框架（AST 守卫强制）。
- 所有接口经 PolicyEngine + Approval + Audit；agent 禁审核/签名/发布。
