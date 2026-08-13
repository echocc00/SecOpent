# 接口层（Interfaces: MCP / CLI / API / Web）

> 状态：M4 基线。MCP 工具注册表（自写编排工具 + 采纳 MCP 标 trust level）、FastAPI API（command/query + 幂等 + SSE）、CLI（argparse）。接口层是 Application Service 的薄分发层，无业务逻辑。
> 设计来源：`sepcs/2026-07-25-catalog-driven-agent-workbench-design.md` §6/§11/§12；ADR-002/007/010/011。

三类接口（MCP / CLI / API / Web）**共用同一组 Application Service**，保证确定性脊柱只有一个实现。

## MCP Server（§13，ADR-007 采纳优先 + 真实 transport）

`interfaces/mcp/` 有两个层次：

- **`tool_registry.py::McpToolRegistry`**（框架无关，可在无 MCP SDK 下单测）：
  - **自写编排工具**（`self_written`，6 组 17 个）：project_create / scope_draft / scope_validate / scope_freeze / assessment_create / plan_generate / plan_approve / assessment_start/pause/resume/cancel/status / asset_list / finding_list / finding_validate / intel_search / report_render。每个绑定对应 Application Service，经 PolicyEngine 校验。
  - **采纳外部 MCP**（cve-mcp-server / mcp-security-hub）：标 `adopted_external_mcp` / `untrusted_external_mcp` trust level。其输出**不可驱动确定性裁决**（只作情报参考）。
  - **禁止暴露**：`shell` / `docker_run` / `execute_python` / `exec` / `eval` / `run_command` / `subprocess` 永不注册——agent 得到的是编排能力，不是任意执行。
- **`handlers.py` + `server.py`（真实 FastMCP transport）**：
  - **16 个标准工具全部注册** → 17 个（含 assessment_create），handler 绑定真实 Application Services（镜像 API 路由的 repo/service 模式，短会话 unit_of_work，变更事件记入签名 AuditChain）。
  - **stdio**:`secopent-mcp` console script / `python -m secopent.interfaces.mcp.server`,直接复用 `create_app()` 组合根读 `app.state`,与 API 进程共享同一依赖图（同 DB/密钥/审计链）。
  - **Streamable HTTP**:挂载在既有 FastAPI 的 `/mcp`(stateless_http=True,`McpHttpTransport` 在宿主 lifespan 中初始化 FastMCP session manager;无鉴权——内部网假设,生产放反代/网络隔离后)。官方 MCP client 直接连 `http://host:8000/mcp`。
  - **人门控(HUMAN_REQUIRED)**:`plan_approve`/`assessment_start` 以 `actor_role="agent"` 调 service,捕获 `AssessmentPermissionError` 返回结构化 `{"status": "HUMAN_REQUIRED", ...}`——agent 学到"需要人"但**绝不会触发扫描/审批**。
  - **真控制面(M4,durable job lease + 协作取消)**:`assessment_pause`/`resume`/`cancel` 是真实运行控制——executor 在 step 边界消费 `core_assessments.control` 信号:暂停=完成进行中的 step 后停发新任务(jobs 保持 READY);恢复=`resume_assessment` 幂等 drain 剩余 READY jobs(API `POST /assessments/{id}/resume` 或经 MCP runtime 调度器,不重发 permit/nft);取消=剩余 jobs 标 SKIPPED + `assessment.cancelled` 审计。容器终止为部署级接线(默认 best-effort)。job 状态落 `core_jobs`(Web `/jobs` 可见),发行程重启后可恢复。
  - **只读语义**:`finding_validate` 只做证据/verdict 检查,绝不写 verdict(oracle/人专属);`report_render` 永不 LLM 润色。
  - 全链路 agent 可编排:project_create → scope_freeze → assessment_create → plan_generate(确定性,非 LLM);审批与启动仍人专属(HUMAN_REQUIRED)。

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
