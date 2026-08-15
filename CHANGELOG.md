# Changelog

All notable changes to SecOpent are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The version single source of truth is `src/secopent/__version__.py`; `scripts/release.sh`
stamps it and tags the matching `v<version>`.

## [Unreleased]

### v0.6.3 (in progress, EngagementGrant - Phase A)
- **feat(grants)**: `EngagementGrant` 授权契据域模型——人创建的一次性预授权(绑定 project + 内嵌 ScopeSnapshot 作边界 + risk caps + 有效期 + revoke),`covers_scope` 精确定义(每目标单独匹配,"授权 /24 ≠ 能扫 /8"),DESTRUCTIVE 构造拒绝
- **feat(grants)**: `GrantService`——create_human/revoke human-only(agent 建授权 = DENY),`authorize` 纯门(GRANT_NOT_FOUND/INACTIVE/SCOPE_MISMATCH/RISK_NOT_APPROVED)
- **feat(grants)**: `AssessmentService.approve/start` 增加 `grant_id` 路径——授权边界内 agent 可 approve/start,审计记 `grant:<id>`(agent 无法自盖章);start 时重新校验(revoked/过期 的 grant 不能启动已批准的执行);无 grant 的 agent 行为不变(HUMAN_REQUIRED)
- **feat(grants)**: 持久化 `core_grants` 表(alembic 增量迁移,幂等)+ embedded scope 复用 `core_scope_snapshots`(单一 matcher)— v0.5.x 存量 DB 走 `secopent db upgrade` 自动迁移
- **feat(mcp)**: `plan_approve`/`assessment_start` 删除 `if False else _human_required` 死代码,grant_id 透传真实执行;`grant_list` 新工具(agent 发现可用授权)
- **fix(execution)**: MCP grant-start 现在触发完整 executor(此前只置 QUEUED——v0.4.0 事故形态),`start_scheduler` 与 HTTP `/start` background task 完全一致
- **fix(grants)**: `SqlAlchemyGrantRepository.add` 幂等(revoke 重写不撞 UNIQUE)
- **docs**: `docs/deployment/grants.md` 运维指引(创建/吊销/安全建议/RAQ)

## [0.6.2] - 2026-08-13

### Added
- **防回归(v9 class)**: `execute_assessment` + URL-form scope e2e 回归(`test_http_prefixed_scope_runs_through_executor`);forbidden linter 新增 R4——host-vs-rule matcher 仅允许定义于 `domain/scope/models.py`;postmortem 归档 `docs/architecture/postmortems/v0.6.0-scope-enforcer-bug.md`

## [0.6.1] - 2026-08-13

### Fixed
- **fix(scope-enforcer)**: `ScopeEnforcer` 的私有 host-vs-rule matcher(`_host_matches_rule`)无 HTTP 前缀分支,任何 `http(s)://` 形式的 scope rule 均判 `NOT_INCLUDED`(v9 issue——v0.5.3 Fix A 只修了 domain 的 `includes_ip`,平行 matcher 失同步)→ `_check_plan_scope` 使所有 URL-form scope 的评估在启动前被拒。现删除私有复制,include/exclude 统一委托 `ScopeSnapshot.includes_host/excludes_host`(单一真源 `_target_matches`)

## [0.6.0] - 2026-08-13

### Added
- **feat(mcp)**: 真实 MCP Server 落地——17 个标准编排工具(含新增 `assessment_create`)全部绑定真实 Application Services,stdio(`secopent-mcp`)与 Streamable HTTP(`/mcp`,stateless)双 transport,共享 `create_app()` 组合根;`plan_approve`/`assessment_start` 对 agent 返回结构化 `HUMAN_REQUIRED`(LLM 边界不变,agent 永不触发扫描/审批);`finding_validate` 只读、`report_render` 永不 LLM 润色
- **feat(control-plane)**: durable job lease(M4 遗留 Task 11 兑现)——`JobStore` 协议 + `SqlAlchemyJobRepository` 原子条件 UPDATE lease,任务状态落 `core_jobs`(Web `/jobs` 首次可见真实任务,重启可恢复);`Assessment.control` 信号列(alembic `3f91c2a7d504`)驱动真暂停/真取消/真恢复:executor step 边界消费信号,pause 停发新任务、cancel 弃置剩余 jobs(SKIPPED)、resume 幂等 drain(`POST /assessments/{id}/resume` + MCP 调度)
- **feat(api)**: `POST /assessments/{id}/resume` 恢复端点
- **fix(api)**: `POST /jobs/{id}/retry` 改用 `JobStore.requeue`(幂等 add 曾吞掉更新,第二次 retry 应 409 却 200)

## [0.5.3] - 2026-08-08

### v0.5.3 (in progress)
- **fix(scope)**: `includes_ip` 现在匹配 HTTP-prefixed 规则(egress_guard/scope_enforcer 传裸 IP,此前 HTTP 分支要求 value 也带 scheme → HTTP-prefixed scope 目标恒 OUT_OF_SCOPE,v8 scope/egress bug A)
- **fix(execution)**: `_check_plan_scope` 现在检查 `scope.include` 的 concrete-host 目标(此前只查 plan 参数 `target`,而 catalog 计划从不生成该字段 → scope/egress 检查是死代码,v8 bug B)。误包含 metadata IP 的 scope 现在会被 egress_guard 拦截
- **test(egress)**: 钉住 HTTP-prefixed 规则 + 裸 IP egress target 的直连断言(in-scope ALLOWED / out-of-scope 拒绝)

## [0.5.2] - 2026-08-07

- **fix(execution)**: 容器 `exit_code != 0` 且**零产出**时抛 `StepFailure(WORKER_UNAVAILABLE)`（v8 根因 2）；非零 exit 但有产出（checkov 扫到违规 exit=1）是合法成功，不误伤
- **fix(execution)**: 空执行（0 step 成功 + 0 findings）→ 标 `FAILED` + `assessment.completed.empty_execution` 审计，不再伪报 COMPLETED（v8 §4.7）
- **fix(scan)**: 容器启动失败 wrap 成 `ContainerExecError` 并带 `docker logs` 诊断提示（v8 §3.2）
- **fix(egress)**: nft `apply_scope` 失败写 `egress.hardening_unavailable` 审计，不再静默降级（v8 §3.1）
- **fix(execution)**: 步骤成功但零 observations（容器跑了、probe 全失败）→ `assessment.completed` 审计 payload 带 `no_observations: true`，可与"target 干净"区分（v8 场景 #3）

## [0.5.1] - 2026-08-07

`Schema: no | Deps: no | Breaking: no` - hotfix: v0.4.0 NAS 升级事故（绿联 DXP4800PLUS
回滚 v0.2.0.2）的根因修复。netns 隔离从"平台假设 + 加固不降级 + 部分失败留残留"改为
"能力探测 + env 开关 + 降级 + 自清理"，存量 DB 升级路径自动化。postmortem 见
`docs/architecture/postmortems/v0.4.0-nas-netns-compatibility.md`。

### Fixed
- **netns 能力探测**（F1，`is_supported()`）：不再只看 `sys.platform=="linux"`（受限 NAS
  内核报 Linux 但缺 `ip netns`）。改为一次性 probe `ip netns add/del`（结果缓存）+ 日志，
  并支持 `SECOPTENT_NETNS_ENABLED=0` 强制关闭。探测失败报告不支持 → 调用方走降级分支。
- **daemon 降级**（F2）：netns create 失败不再杀死评估（此前 propagate 被 BackgroundTasks
  吞掉 → 评估永久 QUEUED、无 FAILED 无审计）。现审计 `netns.unavailable.degraded` + 回落
  默认 netns enforcer，评估照常执行（对齐 `apply_scope` 的 best-effort 模式）。
- **create 自清理**（F3）：create() 三步非原子（add→sidecar→attach），任一步失败会留下
  netns 文件 + sidecar 容器（调用方拿不到 handle 无法清理 → 后续评估撞 "File exists"/
  "Device or resource busy" 死循环）。现失败时先 `docker rm -f sidecar` + `ip netns del`
  再抛；修正 docstring 虚假的 "idempotent" 声明。
- **存量 DB 自动 stamp baseline**（F4）：v0.2.x DB（create_all 建表、无 alembic_version）
  使 `alembic upgrade head` 重跑 baseline 报 "table already exists"。`init_db` 与
  `secopent db upgrade` CLI 现自动检测并 stamp 到 baseline（非 head——存量 schema 是
  baseline 等价但缺 post-baseline 表如 core_audit_outbox），迁移只应用增量。
- **测试去环境依赖**（F5）：由 F1/F2 达成——受限 Linux 上曾失败的 11 个 netns 相关测试
  现走探测/降级路径确定性通过；real-docker 测试经能力探测门控（探测失败 skip 而非 fail）。

### Added
- **兼容性文档**（F6）：`docs/deployment/compatibility.md`（能力维度矩阵 + 环境分类 +
  `SECOPTENT_NETNS_ENABLED` + 残留清理 SOP + DB 升级路径）。事故现场需先清残留：
  `docker rm -f $(docker ps -aq --filter name=secopent-netns-)` 再删 `/run/netns/secopent-*`。

### Verified
- 1623 tests passed（default tier），ruff / mypy strict（287 files）/ bandit -ll /
  forbidden linter 全绿；F4 全流程单测（legacy DB → 自动 stamp → upgrade → outbox 表就位）。

## [0.5.0] - 2026-08-07

`Schema: no | Deps: no | Breaking: no` - Phase 3 功能缺口收口（设计存在但未激活的
能力全部激活）。设计文档 `docs/architecture/phase3-handoff.md`（含审阅勘误 E1-E5）。
3.2 Strix/Shannon 已在 v0.4.0 完成；本版落地其余 5 项，1611 passed（+41），零回归。

### Added
- **审计链生命周期 API**（Phase 3.6）：`POST /audit/rotate`（轮换日志段，新段从
  旧 tail 延续）+ `POST /audit/redact`（GDPR PII 掩码，哈希承诺保留）+
  `GET /audit/chain?redacted=true`（签名链导出）。均 human-only（agent 403，
  LLM 边界），事件经请求事务原子提交。
- **OllamaBackend**（Phase 3.4）：本地 `ollama serve` 后端（/api/generate，
  非流式；无 API key、无云出口），实现 application `ModelBackend.complete` +
  infrastructure `LLMBackend.generate/is_available` 双协议——RemoteModelGateway
  的数据分级/脱敏治理对本地模型同样生效。
- **DriftView 前端**（Phase 3.3）：CaseStudio 加回 Drift tab，粘贴 re-imported
  states/transitions → `POST /appmodels/{app_id}/{version}/drift` → 三栏渲染
  added/removed/changed，提示再生成受影响的 logic tests。复用 generated.ts
  既有类型（勘误 E3：不新建 API client 文件）。

### Changed
- **Echo canary per-method 门控**（Phase 3.1）：`VerificationMethod.echo_enabled`
  字段 + factory 按策展方法嵌入 `&echo={{canary_token}}` 到探测 URL——token 必须
  到达靶标才能回显（勘误 E1：独立 dict key 会撞 `RealScanRunner.scan` 严格签名
  且永远不进流量）。XSS 为唯一 echo-enabled 类，**严格语义**（勘误 E2）：无回显
  即 REFUTED，无 legacy fallback；OOB placeholder 保持 always-on，两分支互斥
  （echo 方法 oob_window=0）。此前 echo 分支是死代码，反射型 XSS 只能走宽松的
  legacy 子串匹配。已知行为变更：不回显的 stored/DOM XSS 发现将由弱确认变为
  REFUTED（重扫探针本就无法复现它们）。
- **LLM 后端配置驱动**（Phase 3.5，勘误 E4）：`_build_llm_backend` 按优先级
  `SECOPTENT_LLM_BACKEND` env（remote/ollama/null）> `config/llm.yaml`
  `backend:` 字段（`SECOPTENT_LLM_CONFIG` 覆盖路径）> `MINIMAX_API_KEY` 遗留
  fallback > null 选择后端；配置错误降级 null + warning，启动永不失败。
  `load_backend_from_config` 支持 remote/ollama/null 三种后端。
- **rotate/redact_pii session 线程化**（Phase 3.6）：`AuditChain.rotate` /
  `redact_pii` 加 `session=` 参数并透传 store append（v4/v5 bug class 残留收口）；
  forbidden linter R3 扩扫 `audit_chain.py`（先红后绿）。

### Verified
- 1611 tests passed（default tier），5 realism 通过，coverage 92.14%（gate 80%），
  ruff / mypy strict（287 files）/ bandit -ll / forbidden linter 全绿；前端
  `npx tsc -b` + `npm run build` 绿，drift/appmodel 后端测试（31）不回归。

## [0.4.0] - 2026-08-06

`Schema: yes | Deps: no | Breaking: no` - M5 里程碑：容器加固 + 真实 peer 后端 +
真实 E2E。handoff roadmap Phase 2 全部落地的代码层；v0.2.x 的 "wired but degraded"
特性在 M5 变为 fully operational。Phase 2 共 9 个提交（2.1-2.10），新增 61 个测试
（v0.3.0 基线 1513 -> 1574 passed），零回归。

### Added
- **适配器 digest pinning**（Phase 2.1）：9 个空 digest 适配器中 4 个真拉取并 pin
  （restler/schemathesis/trivy/checkov），manifest `upstream.digest` 改为从
  `IMAGE_CATALOG` 动态读取（不再硬编码占位符 `sha256:<adapter>-<ver>`）。剩余 5 个
  （fingerprinthub/zap/scoutsuite/prowler/kube_bench）因国内镜像 403/stall 待补，
  代码就绪，未来拉取成功即自动转绿。
- **Strix/Shannon 真实 peer 后端**（Phase 2.2）：构建 `secopent/peer-worker-strix`
  镜像（python:3.12-slim + strix-agent==1.4.1，digest pin）+ 拉取 `keygraph/shannon`
  镜像（digest pin）；`create_peer_agent_service` 切真实 `ContainerPeerAgentHarness`，
  无 LLM key 时降级回 `NullPeerAgentHarness` + warning（服务始终可构造）。
- **Netns sidecar 绑定**（Phase 2.3，Linux）：`NetnsIsolator.create()` 启动 sidecar
  容器（alpine sleep infinity）绑定命名 netns；扫描容器经 `--network=container:<sidecar>`
  共享其 network namespace；`--add-host` 在 netns 模式下自动省略。Windows 单测覆盖参数
  构造，真实 lifecycle 测试 Linux-only skip。
- **Curated seccomp profile**（Phase 2.5）：`scripts/provision/secopent-seccomp.json`
  denylist 策略，在 Docker 默认之上额外拒绝 33 个高危 syscall（ptrace/bpf/keyctl/
  mount/unshare/clone3/io_uring/perf_event_open 等）；执行器 opt-in `seccomp=` 参数。
- **CI e2e_real job**（Phase 2.6）：`.github/workflows/ci.yml` 新增 e2e-real job，
  release/workflow_dispatch 触发（PR 不跑），启动 Juice Shop + httpbin + interactsh，
  跑 `tests/e2e_real/`，失败上传 test-results 产物。
- **MCP 工具注册表接线**（Phase 2.9）：`tool_registry.py` 已完整但从未挂载 ->
  `build_default_registry()` 注册只读安全面（list_findings/get_finding/
  list_required_classes），挂到 `app.state`；safe-surface 守卫测试断言无 shell/docker/
  python/exec 工具名。
- **PtaiBackend**（Phase 2.10）：按 P0-P3 PeerAgentBackend 模式实现 ptai peer agent
  （宽容解析器 + opt-in 注册 `enable_ptai`，Linux-only）；承 A4 spike 决策。
- **interactsh 部署文档**（Phase 2.4）：`docs/deployment/interactsh.md`，端口修正
  （HTTP 8081 非 8443；HTTPS 因 `*.oast.local` 拿不到公网证书禁用，intranet OOB 走 HTTP）。

### Changed
- **RESTler parser 注册**（Phase 2.7）：`_ADAPTER_PARSERS` 此前只注册了 schemathesis，
  RESTler 资源限制配了但 parser 漏了 -> `RealScanRunner.scan("restler")` 会 ValueError。已修。
- **Schemathesis parser 增强**（Phase 2.8）：原 parser 只认 fixture JSON，真实 CLI 输出
  是 NDJSON 事件流混合人类可读进度。增强为三格式兼容（fixture JSON / 纯 NDJSON / 混合 stdout）。
- **Peer agent harness 降级路径**（Phase 2.2）：无 `LLM_API_KEY` 时回退
  `NullPeerAgentHarness` + `logging.warning`（比硬抛 KeyError 稳）。

### Fixed
- RESTler parser 未注册（`real_scan.py` `_ADAPTER_PARSERS` 缺 "restler" 键）- 扫描会直接
  `ValueError`。
- Schemathesis parser 与真实 CLI 输出格式脱节（只认 fixture JSON）- 真实扫描解析出 0 发现。
- interactsh 部署文档端口错误（8443 -> 8081）。

### Known Limitations / Deferred（Linux 验证项）
- 5 个 adapter digest 待补（fingerprinthub/zap/scoutsuite/prowler/kube_bench，国内镜像
  403/stall；代码就绪）。
- netns 真实 lifecycle + seccomp allowlist 收紧 + ptai 真镜像构建/输出 schema 采集 - 均
  需 Linux worker。
- RESTler e2e 需 operator 提供 OpenAPI spec + grammar compile（honest-skip，非 fake green）。
- `GET /catalog/latest` 偶发返回 200-null（已自愈，根因调查中，非本版引入）。

## [0.3.0] - 2026-08-06

`Schema: yes | Deps: no | Breaking: no` - architecture release: eradicate the
"implicit cross-boundary" bug class (v3 race / v4 lock / v5 leaks) at the root,
per `docs/architecture/postmortems/v0.2.0-implicit-boundaries.md` and the
handoff roadmap Phase 1. v0.2.0.x treated the symptoms (threading `session`
through every path); v0.3.0 removes the class by construction.

### Added
- **Transactional Outbox** (`core_audit_outbox` + alembic migration
  `811a5b9a583d`): the daemon writes ONE outbox row inside its short business
  transaction; a background `OutboxWorker` (1s poll, per-row transactions,
  id-order drain) fans each row out to `core_audit_events` +
  `core_signed_audit_events`. Audit leaves the hot path; failed rows are
  flagged, never dropped. Lifespan startup drains pending rows BEFORE serving
  (no permit-replay gap after crash+restart). Known trade-off: the queryable
  audit API is eventually consistent (delay <= poll interval); the signed
  chain stays complete and ordered. Permit nonces always take the direct
  synchronous path (replay detection never lags).
- **UnitOfWork** (`Database.unit_of_work()`): explicit transaction boundary -
  commit on clean exit, rollback on exception, always close. The assessment
  daemon uses it instead of manual commit/rollback/close.
- **Forbidden-pattern linter** (`scripts/lint_forbidden_patterns.py`, wired
  into CI): no raw `threading.Thread` in routers, no `.open_session()` on hot
  paths, audit `.record()` calls must thread `session=` (AST-based).
- **Integration graph** (`docs/architecture/integration-graph.md`): Mermaid
  source of truth for the assessment execution chain with a per-edge
  test-coverage table; PR template makes updating it a merge checklist item.
- Startup-recovery test (`tests/interfaces/test_startup_recovery.py`) - the
  one coverage GAP the integration graph surfaced.

### Changed
- **BackgroundTasks replace the daemon thread**: `POST /assessments/{id}/start`
  schedules a module-level `_run_assessment_daemon` via FastAPI BackgroundTasks
  (nothing captured from the request scope). The explicit `session.commit()`
  is kept - FastAPI 0.115 runs yield-dependency teardown AFTER background
  tasks, so the daemon's fresh session still needs the committed QUEUED row.
  SIGTERM drain semantics unchanged (threadpool threads register in
  `active_executions`).
- **Per-phase commits**: the daemon commits at phase boundaries through the
  already-threaded session (before the scan, after findings persist, after
  the oracle block, and per oracle finding) - the SQLite WAL write lock is
  released during the multi-minute scan/oracle phases instead of being held
  for the whole 8-15 min assessment (v4 root cause). Proven by a realism
  test: a second connection with a 1s busy timeout can write mid-scan;
  pre-v0.3.0 it raised `database is locked`.
- **AuditChain is thread-safe**: `record()` holds an RLock across the
  counter/tail/events mutation AND the store append (concurrent recorders -
  daemon, emergency-stop request threads, outbox worker - can no longer mint
  duplicate ids or persist out of order); readers snapshot under the lock.
- **Assessment state machine as data**: `ALLOWED_TRANSITIONS`
  (`domain/assessments/transitions.py`) is the single source of truth; every
  `AssessmentService` mutating method routes through `assert_transition`.

### Fixed
- **Guard gaps** (security-relevant): `attach_plan` and `approve` performed
  NO status check - a plan could be re-attached to an APPROVED assessment and
  a REJECTED assessment could be approved again. Both now enforce the
  transition table. Pinned by an exhaustive 12x12 transition-matrix test
  (144 cases) + service-level regressions.
- Outbox recorder joins the caller's transaction atomically - the audit row
  commits or rolls back with the business write (no orphaned audit for
  rolled-back work, no missing audit for committed work).

### Verified
- 1508 tests passed (default tier), 5 realism tests passed, coverage 92.41%
  (gate 80%), ruff / mypy strict (284 files) / bandit -ll / forbidden-pattern
  linter all clean.

## [0.2.0.2] - 2026-08-05

`Schema: no | Deps: no | Breaking: no` - hotfix: complete the v4 same-tx refactor.
v0.2.0.1's T3 refactor threaded `session` through `_audit_record` but missed 4
other audit-write paths on the daemon (issue v5). All 4 now thread `session`
through the daemon's `bg_session` so every audit INSERT joins one transaction.

### Fixed
- **v5 Leak 1** (commit `99ceb57`): `AuditChain.record_permit_nonce` now
  accepts + passes `session=`; `execute_assessment` passes `bg_session`. The
  `permit.used` signed audit event (2nd event after `assessment.started`) was
  opening its own connection -> `database is locked`.
- **v5 Leak 2** (commit `99ceb57`): `NftScopeEnforcer._record` /
  `AuditSink.record` Protocol now accept `session=`; `apply_scope` +
  `_classify_network` thread it through. The `egress.rejected_rebinding` /
  `egress.denied_blocked` / `egress.allowed` audit events (scope pre-check)
  were opening their own connections -> `database is locked`.
- **v5 Leak 3** (commit `068926e`): `CanaryTokenManager.generate` +
  `verify_echo` now accept `session=`; `OracleEngine.verify` +
  `OracleVerifier.reproduce` Protocol + `OracleService.verify_findings` +
  `_verify_one` thread it through. The `canary.generated` / `canary.verified`
  audit events (oracle verification phase) were opening their own connections.
- **v5 Leak 4** (commit `068926e`): `OracleService._audit` now extracts the
  session from the `audit` param (AuditService -> repo -> session) and passes
  it to `audit_chain.record(session=...)`. The `oracle.verified` /
  `oracle.verification_failed` signed audit events were opening their own
  connections.
- **AuditRecorder Protocol** (commit `068926e`): `AuditRecorder.record` +
  `AuditService.record` now accept `session: Any = None` for Protocol
  compatibility. `AuditService` ignores it (the repo is already bound to the
  correct session); `AuditChain` uses it (same-tx merge).

### Root cause (incomplete refactor)
v0.2.0.1's T3 refactor (commit `d95f7d3`) threaded `session` through
`_audit_record` (the main audit path) but the daemon has **4 other
audit-write paths** that call `audit_chain.record(...)` or `self._audit.record(...)`
directly, bypassing `_audit_record`. Each opened its own SQLite connection
while the daemon's `bg_session` held the WAL RESERVED lock -> `database is
locked`. The `@pytest.mark.realism` tier (v0.2.0.1 T5) covered `_audit_record`
+ `AuditChain.record` but NOT `record_permit_nonce`, `nft_scope._record`,
`canary.generate/verify_echo`, or `oracle._audit` -- the test gap that masked
all 4 leaks.

### Verified
- 1324 tests passed, ruff/mypy strict/bandit -ll all clean.
- Realism tier (`-m realism`): merged-tx audit path + concurrent store append
  both pass.

## [0.2.0.1] - 2026-08-05

`Schema: no | Deps: no | Breaking: no` - hotfix: unblock v0.2.0 NAS deployment.
Fixes the two High bugs surfaced by the v0.2.0 NAS rollout (postmortem at
`docs/architecture/postmortems/v0.2.0-implicit-boundaries.md`):
**v3 race** (assessment blocked) + **v4 lock** (database is locked).

### Fixed
- **v3 race** (T1): `start_assessment` now explicitly commits the session
  before spawning the daemon thread. Previously the daemon opened a fresh
  SQLite connection and read stale `APPROVED` status because the main
  thread's `APPROVED -> QUEUED` write had not yet committed (`session.flush()`
  is not enough - SQLite WAL hides uncommitted writes from new connections).
  Regression test: `tests/interfaces/test_start_assessment_race.py`.
- **v4 root-cause fix** (T3, full refactor): `_audit_record` now writes both
  `core_audit_events` + `core_signed_audit_events` in the SAME session / SAME
  transaction. Previously the signed store opened its own connection per event
  (cross-connection double-write), causing SQLite WAL lock contention under
  the high-frequency audit storm. The refactor: `SqlAlchemySignedAuditEventStore.append`
  + `AuditChain.record` + `DatabaseAuditRecorder.record` all accept an optional
  `session=` kwarg; `_audit_record` passes the daemon's `bg_session` so both
  INSERTs join one transaction, one WAL frame, one commit. The local
  `audit = AuditService(audit_repo)` shadowing in `execute_assessment` is
  removed. This eliminates the cross-connection contention at the root.
- **v4 mitigation** (T2): `busy_timeout` bumped 5s -> 60s (belt-and-suspenders
  after T3; covers edge cases under heavier load).
- **W4-A same-class prevention** (T4): `DatabaseAuditRecorder.record` accepts
  optional `session=`. Peer-agent audit (high-frequency during a peer run)
  used the same "open_session per call" pattern that caused v4; this API
  change prevents the same bug from biting W4-A when peer-agents are enabled.

### Added
- **Production-realism test tier** (T5): `@pytest.mark.realism` marker
  (opt-in, gated to release CI) + `tests/infrastructure/test_realism_concurrent_audit.py`
  (merged-transaction audit path: N events -> N rows in both tables, no
  OperationalError; + concurrent store append storm). The existing 1315 unit
  tests used in-memory SQLite + StaticPool (single connection, no contention),
  which fully masked v3 and v4. The new tier uses `tmp_path` real files +
  the default file-based pool - production-realism. Run with `pytest -m realism`.

### Deferred to v0.3.0
- **Transactional Outbox** (the proper "ultimate" root-cause fix): business
  write + outbox row in same transaction; background worker drains to both
  audit tables. v0.2.0.1's T3 refactor already merges the two audit tables
  into the same transaction (eliminates the cross-connection contention), so
  the Outbox mainly adds async/queue semantics (retries, decoupling).
- **FastAPI BackgroundTasks** (replaces `threading.Thread` daemon; eliminates
  the entire v3 race class).
- **Unit of Work pattern** (explicit transaction boundaries).
- **State machines as data** (typed transitions; `mark_running` compile-time-enforced).
- **Integration graph** (`docs/architecture/integration-graph.md`) as a PR gate.
- **AuditChain thread-safety** (`threading.Lock` on `_counter`/`_tail`) if
  concurrent recorders become a goal (currently single-threaded by design).

## [0.2.0] - 2026-08-04

`Schema: yes | Deps: no | Breaking: no` - architecture cleanup + release-readiness.
Wired the "built but not wired" security gaps (auth chain, oracle, audit
persistence, netns, OOB canary), made alembic the production schema source of
truth, exposed peer-agents over HTTP, and scrubbed the C1 credential leak.

### Added - W2-A / W3-A (authorization + oracle wiring)
- **Authorization chain wired end-to-end** (W2-A): PermitSigner/Verifier,
  EmergencyStop, ScopeEnforcer, AuditChain, PromptInjectionGuard, EgressGuard
  are constructed in `create_app` and threaded into `execute_assessment`. The
  "强授权链" selling point now holds at runtime, not just in unit tests.
- **Oracle N/N verification wired** (W3-A): `OracleService` runs after
  correlation; CWE→VulnType mapping drives `RescanVerifierFactory`; confirmed
  findings persist to the new `core_confirmed_findings` table. Best-effort:
  oracle failure does not block assessment completion (findings stay PENDING).

### Added - W3-C / W3-E / W4-C (audit persistence + OOB canary)
- **Signed audit chain persisted** (W3-C, H6): `SqlAlchemySignedAuditEventStore`
  + `SECOPTENT_AUDIT_KEY_PATH` (0600 Ed25519 key, auto-generated on first
  start). Tamper-evident chain survives restart. New `core_signed_audit_events`
  table.
- **OOB canary active** (W3-E + W4-C): `InteractshClient.allocate_correlated`
  + `HttpInteractshTransport` (self-hosted interactsh-server via
  `SECOPTENT_INTERACTSH_SERVER_URL`). Production scan_kwargs now embeds
  `{{canary_oob_subdomain}}`; OOB-class findings verify via callback.

### Added - W3-D / W3-F / W4-B (domain + netns)
- **Domain state machines** (W3-D): Report approve/release invariants,
  ExecutionPermit expiry, Project archive/reactivate (idempotent transitions).
- **Per-assessment netns isolation** (W3-F + W4-B): `NetnsIsolator` +
  `make_nft_enforcer` factory in the composition root; `start_assessment`
  creates/destroys a netns per assessment (Linux; non-Linux best-effort
  no-op). Docker-container-into-netns wiring remains a Linux-env deferral.

### Added - W4-A (peer-agent API surface)
- **Peer-agent service exposed** (W4-A): `PeerAgentService` constructed in
  `create_app` behind `SECOPTENT_PEER_AGENTS_ENABLED`; 5-route `peer_agents`
  router (launch / list / get / stop / list-agents) on root + `/api`.
  `NullPeerAgentHarness` degrades gracefully (strix/shannon image digests
  unpinned); `DatabaseAuditRecorder` keeps singleton-service audit
  session-safe. Real backends deferred to image digest pinning.

### Added - W4-D (schema management)
- **alembic as production source of truth** (W4-D): `secopent db
  upgrade/stamp/current` CLI; `init_db` mode via `SECOPTENT_DB_INIT`
  (auto/always/skip); fresh-DB stamp; baseline↔create_all schema-equivalence
  test (baseline now includes the W3-A/W3-C tables).

### Changed
- `init_db` default mode is `auto` (was unconditional `create_all`): fresh DBs
  still `create_all`; existing DBs skip create_all (alembic-managed). Prod
  pre-boot runs `secopent db upgrade` and sets `SECOPTENT_DB_INIT=skip`. See
  `docs/deployment.md` §4.
- `PeerAgentService.audit` widened to `AuditRecorder` (structural;
  `AuditService` still satisfies). `create_peer_agent_service` accepts a
  `harness=` override (used to inject `NullPeerAgentHarness`).
- `verifier_factory` embeds `{{canary_oob_subdomain}}` in the oracle rescan
  `-u` URL (additive; legacy substring match remains the fallback for
  non-OOB findings).

### Security
- **C1 credential leak**: cloud server credentials were in public GitHub
  history for 9 days. `git filter-repo` scrubbed local + remote history
  (force-pushed 2026-08-04); 6 release tags rewritten. **Password rotation +
  server compromise check remain user actions** - the creds were harvestable
  during the exposure window; scrubbing the canonical remote does not recall
  already-cloned copies.

### Removed
- Unreachable `EmergencyStop` fallback in the stop route (composition root is
  mandatory since W2-A); an unconfigured app now returns 503, not a silent
  0-permit revoke.
- Frontend `DriftView` placeholder tab + dead `PagePlaceholder` component
  (backend `POST /{app_id}/{version}/drift` endpoint stays for a future UI).

### Verified
- 1315 tests passed (5 skipped, 15 deselected), 92% coverage (CI gate 80%).
- ruff, mypy strict, bandit -ll (severity < MEDIUM), gitleaks full-history.
- alembic baseline == create_all schema (equivalence test).
- OOB canary branch fires E2E via `HttpInteractshTransport` (stub server).
- Per-assessment netns lifecycle: create + destroy incl. cleanup-on-failure.

### Notes
- Deferrals (documented, non-blocking for v0.2.0): peer-agent real backends
  (strix/shannon image digests), Docker-container-into-netns (Linux),
  interactsh-server deployment (operator), echo canary `{{canary_token}}`
  placeholder (per-method gate pending), adapter manifest digest pin to
  image_catalog (M5 container build).

## [0.1.6] - 2026-08-03

`Schema: no | Deps: no | Breaking: no` - end-to-end 0-findings root-cause fix.
Real-machine deployment (NAS + Docker + Juice Shop) surfaced that v0.1.5
assessments completed with 0 findings despite the orchestrator running all 9
nuclei steps. Systematic isolation testing (4 container tests + direct
subprocess vs executor comparison) located the root cause; this release fixes
it plus 5 related deployment gaps found in the same audit.

### Root cause (end-to-end 0 findings)
Three independent causes, all required to fix:
1. **`_production_step_runner` did not pass `template_host_dir`** - nuclei ran
   with built-in templates (needs network; fails offline/GFW). [A1]
2. **nuclei 3.11 rejects single-file `-t`** with "no templates provided" - the
   scan needs a directory mount. (nuclei v3 `-silent`/`-o`/stdout capture were
   all verified NOT at fault via 4 isolation tests.)
3. **default_timeout 180s too short** - 13k HTTP templates need 6-10 min; the
   scan was killed mid-run. [A3]
4. **nuclei OOM at 512m default** - loading 13k templates takes ~1.5GB. [C1]

### Fixed
- **A1**: `_production_step_runner` injects `template_host_dir` from
  `SECOPTENT_NUCLEI_TEMPLATE_DIR` env (offline/NAS deployments supply the
  downloaded template dir). [assessments.py]
- **A2**: URL adapters (nuclei/httpx/katana/dalfox) strip trailing slash from
  targets - `http://host:3000/` + `/api-docs` no longer produces `//api-docs`.
  [step_runner.py]
- **A3**: scan timeout is now `SECOPTENT_SCAN_TIMEOUT` env (default 1800s/30min,
  was 180s) - covers the full 13k-template HTTP set on a weak NAS. [assessments.py]
- **A4**: orchestrator exceptions now log via structlog (`assessment
  started/completed` info, `failed` warning with exc_info) - daemon-thread
  failures are no longer invisible in the API log. [execution.py]
- **A5**: `create_app` default DB is now `cwd/secopent.db` (stable, persists
  across restarts) instead of `tempfile.mkstemp` (fresh /tmp/tmp*.db each start
  = silent data loss). `tests/conftest.py` autouse fixture isolates tests via
  `SECOPTENT_DB_URL` -> tmp_path. [main.py, tests/conftest.py]
- **A6**: `step_runner` mounts single-file `template_host_dir` by name (not as
  a directory) - correct for adapters that accept a file; nuclei still requires
  a directory (3.11 limitation), so production uses a directory (A1). [step_runner.py]
- **C1**: nuclei added to `_ADAPTER_RESOURCE_LIMITS` at 2g/1cpu (13k templates
  load ~1.5GB; 512m default OOMed the container before any scan ran). [real_scan.py]

### Verified (real-machine)
- NAS deployment: end-to-end assessment `asm-9e1059d0b458` ran 9 nuclei steps
  (6+ min), audit chain complete, **1 finding** (Public Swagger API - Detect,
  severity info). v0.1.5 produced 0 findings.
- Data persists across API restart (SECOPTENT_DB_URL + A5 default).
- `@reboot` auto-start via `start-api.sh` with 3 env vars (DB_URL,
  NUCLEI_TEMPLATE_DIR, SCAN_TIMEOUT).

### Verified (CI)
- ruff + mypy clean on all changed source files.
- 1014 unit tests pass (2 platform skips), 59s.

### Notes
- Operators must set `SECOPTENT_NUCLEI_TEMPLATE_DIR` (path to the unpacked
  nuclei-templates dir) and optionally `SECOPTENT_SCAN_TIMEOUT` (default 1800).
  See docs/deployment/linux.md.
- `test_runs_nuclei_against_httpbin` (integration) still fails: its single-file
  fixture hits nuclei 3.11's "no templates provided" rejection. Fixing it needs
  a directory fixture (tracked separately; needs Docker to validate).
- The 3 Hermes local patches (template_host_dir injection, nuclei 2g resource,
  scan_timeout env) are superseded by this release - remove them after upgrade.


## [0.1.5] - 2026-08-03

`Schema: no | Deps: no | Breaking: no` - Linux/NAS deployment hardening pass.
Systematic analysis of Linux/NAS adaptation surfaced 16 gaps (4 P0 + 8 P1 + 4
P2); this release closes them all. The 4 P0 items are hard prerequisites for a
long-lived NAS install.

### Added - P0 (NAS long-run prerequisites)
- **SecretStore persistence** (`PersistentEncryptedFileBackend`): Fernet-
  encrypted secrets persisted to disk (0600, atomic writes) so signed
  Cases/AppModels stay verifiable after a restart. Fernet key in a separate
  auto-generated file. Env: `SECOPTENT_SECRET_STORE_PATH` +
  `SECOPTENT_SECRET_KEY_PATH`. Falls back to in-memory when unset (dev/test).
- **SigningKeyService metadata persistence**: public-key metadata persisted
  (0600 JSON) alongside the SecretStore; `ensure_default_key` is idempotent
  across restarts (the default signing key is reused, not regenerated).
- **SQLite/network-filesystem guard**: `create_sqlite_engine` refuses to start
  when the DB path is on NFS/SMB/CIFS/sshfs (WAL file locks are unreliable
  there -> silent DB corruption). Override with `SECOPTENT_ALLOW_NFS_DB=1`.
- **nftables boot unit** (`scripts/provision/secopent-egress.service`): preload
  the `secopent_egress` table at boot. Default DISABLED - the table's output
  chain default-DROPs all host egress, so enable ONLY on a dedicated isolation
  host, never a general-purpose NAS.
- **Graceful shutdown** (FastAPI lifespan): on SIGTERM, terminate in-flight
  execution containers (reuses the emergency-stop terminator) and join
  assessment threads (25s budget, matches systemd `TimeoutStopSec=30`).
  Leftover RUNNING assessments are transitioned to FAILED by startup recovery.

### Added - P1 (security / stability / ops)
- **`--ulimit nofile=65536`** on every adapter container (fuzzers EMFILE at the
  1024 default).
- **`secopent vacuum` CLI**: `wal_checkpoint(TRUNCATE)` + `VACUUM` to reclaim
  space (findings + audit chain grow); for cron on long-lived installs.
- **`SECOPTENT_MAX_PARALLEL_STEPS`** env: same-layer step concurrency (default
  1, NAS-safe; raise on strong hosts).
- **0600 file perms** enforced: backup/restore CLI writes + DB file (best-effort
  `chmod 0600`); systemd `UMask=0077` covers WAL/.shm sidecars.
- **systemd resource limits** documented: `MemoryMax=2G` `CPUQuota=200%`
  `TimeoutStopSec=30` `UMask=0077`.
- **Docker socket security** documented: rootless Docker or docker-socket-proxy
  (the `docker` group = root).
- **Docker log rotation** + **image-prune cron** documented.
- **SSD recommendation** documented: DB + Docker data-root on SSD (HDD tanks
  performance).

### Changed
- `egress.nft`: removed `flush ruleset` (it cleared the host's entire nftables
  ruleset, including the NAS firewall); now manages only its own table.

### Added - P2 (completeness)
- Target compose (`docker-compose.targets.yml`): per-service `deploy.resources.
  limits` (juice-shop 512m/1cpu, httpbin 128m/0.5, crapi 1g/1cpu).
- `verify_env.py`: port-conflict check (8000 API conflict = FAIL; 3000/8080
  in-use = info, may be the targets themselves).
- `docs/deployment/linux.md` rewritten (14 sections): SecretStore persistence,
  NFS guard, nftables modes, Docker security/maintenance, NAS hardware tuning,
  Interactsh NAT, backup/VACUUM, verification checklist.

### Verified
- ruff + mypy clean on all 8 changed source files.
- 1014 unit tests pass (2 platform skips), 49.5s.

### Notes
- NftScopeEnforcer remains unwired into the live execution path (T11 is
  implemented + unit-tested; production wiring tracked separately). The boot
  unit + `egress.nft` fix prepare for that wiring without changing current
  behavior.
- Adapter image digest-pinning (`scripts/pin_digests.py`) still pending a run
  on a Docker+internet host (carried over from v0.1.4).


## [0.1.4] - 2026-08-01

`Schema: no | Deps: no | Breaking: no` - systematic hardening pass. Independent
verification of the v0.1.4-pre fixes (commits ebaba9c..8e30e86) surfaced 3
residual defects + confirmed the 8 commits' root-cause patterns; this release
closes them.

### Fixed
- **Weak Docker skip guard** (root-cause A): `tests/integration/conftest.py` +
  `tests/e2e_real/conftest.py` used `shutil.which("docker")` which returns True
  even when the daemon is stopped, so integration tests FAILED (not skipped)
  with `ImageDigestMismatch`. Now uses `docker info` (daemon reachability).
- **Report coverage_rate hardcoded 0.0** (root-cause B): `POST /reports` set
  `coverage_rate=0.0` unconditionally. Now `execute_assessment` computes real
  coverage (CoverageService over the run's observations + catalog + asset types)
  and records it in the `assessment.completed` audit payload; the report reads
  it back. Falls back to 0.0 for pre-coverage runs.
- **ruff**: `real_scan.py` E501 + `tests/integration/conftest.py` 3 unused
  imports left by the v0.1.4-pre commits.

### Added
- **`_ADAPTER_RESOURCE_LIMITS`** expanded (root-cause D): schemathesis, restler,
  checkov, kube_bench now get 1g/1cpu (fuzzers OOM at the 512m default).
- **`scripts/pin_digests.py`** (root-cause C): pulls each `:latest` adapter
  image, resolves its sha256 digest, and (with `--apply`) auto-edits
  `image_catalog.py`. Run on a Docker+internet host to pin the 9 still-unpinned
  adapters (fingerprinthub/restler/schemathesis/zap/prowler/trivy/kube_bench/
  checkov/scoutsuite).

### Verified-OK (no action needed)
- **Parser error handling** (root-cause E): audited dalfox/kube_bench `return []`
  - both are legitimate top-level parse failures (no partial results dropped).
  dalfox NDJSON already `continue`s on bad lines (commit 5).
- **Unbounded loops** (root-cause F): SSE `while True` already capped at 3600
  iterations (commit 5); Orchestrator `run_to_completion` capped at 100 rounds.
- **4 "wired" endpoints** (root-cause B): drift + generate-tests genuinely call
  DriftDetector/LogicTestGenerator; job retry resets to READY (design: re-start
  picks up); only report coverage was a real bug (fixed above).

### Notes
- `:latest` adapter images remain a reproducibility/supply-chain risk until
  `scripts/pin_digests.py` is run on a provisioned host (documented in
  `docs/deployment/upgrade.md`).


## [0.1.3] - 2026-07-31

`Schema: no | Deps: no | Breaking: no` — upgrade tooling + runbook (no behavioral
change to the app). Closes the upgrade-path design gap: a single command +
documented procedure to move between versions on a Linux install.

### Added
- **`secopent upgrade`** CLI command: locates the repo root from the editable
  install, then runs `git pull` -> `pip install -e ".[dev]"` -> `npm install &&
  npm run build` -> `alembic upgrade head` -> `doctor`, with a restart reminder.
  Flags: `--dry-run`, `--no-frontend`, `--no-migrate`.
- **`docs/deployment/upgrade.md`**: full upgrade runbook (venv + container),
  per-version-type steps (patch/minor/major), rollback, Docker environment
  separation (app vs targets/images), verification checklist.
- **CHANGELOG convention**: each release now carries a `Schema | Deps | Breaking`
  marker so operators know whether a backup/migration is needed before upgrading.
  Prior releases (0.1.0-0.1.2) annotated retroactively.
- **Dockerfile auto-migration**: CMD now runs `alembic upgrade head` before
  uvicorn, so containerized deployments auto-migrate on startup (idempotent).
  `alembic.ini` + `alembic/` are now copied into the image.

### Notes
- App upgrades do **not** require updating Docker targets/images (those are
  independent infrastructure; see upgrade.md §5). Adapter images are
  digest-pinned and only change when `image_catalog.py` changes.
- `secopent upgrade` does not auto-restart the service (it cannot restart
  systemd); it prints the `systemctl restart` reminder.


## [0.1.2] - 2026-07-31

`Schema: no | Deps: no | Breaking: no`

P0 blocker fix: the execution layer was not wired to the API. Approving an
assessment left it stuck at APPROVED with no path to trigger scans. This release
connects `POST /assessments/{id}/start` to the existing Orchestrator, closing
the core user journey (scope -> plan -> approve -> **execute** -> findings).

### Added
- `POST /assessments/{id}/start` endpoint: APPROVED -> QUEUED, spawns a daemon
  thread that runs `Orchestrator.dispatch` + `run_to_completion`, correlates
  observations into findings (tagged with `assessment_id`), and transitions
  RUNNING -> COMPLETED (or FAILED on exception). Human-only (agent -> 403).
- `AssessmentService.start/mark_running/complete/fail` state-transition methods
  with status guards (start only from APPROVED, etc.).
- `application/execution.py`: the API -> Orchestrator bridge (background
  executor, audit-recorded start/completed/failed).
- Frontend: `Start` button on AssessmentDetail (visible when APPROVED) + the
  `Emergency Stop` button is now enabled while RUNNING/QUEUED (was disabled
  with "lands with execution layer (P2)" placeholder).
- `useStartAssessment` / `useStopAssessment` hooks.

### Fixed
- Emergency stop works through container termination: `POST /stop` kills active
  adapter containers -> the step's subprocess fails -> `run_to_completion` raises
  -> the executor records FAILED. No separate stop-flag polling needed.
- User manual §3 step 5 updated to reflect the now-wired execution trigger
  (was aspirational "lands with execution layer (P2)").

### Notes
- SSE already polled `assessment.status`; it now emits the real QUEUED ->
  RUNNING -> COMPLETED transitions during execution. Per-step (job-level) SSE
  is a future enhancement (DAG nodes color at assessment granularity today).
- Findings are persisted after `run_to_completion` (not incrementally per step);
  incremental findings are a future enhancement.


## [0.1.1] - 2026-07-31

`Schema: no | Deps: no | Breaking: no` - Linux deployment adaptation. No behavioral changes; the app is platform-agnostic
(Python code has no Windows paths/imports/platform branches, CI already runs on
ubuntu-latest). This release makes Linux first-class.

### Added
- Application `Dockerfile` (multi-stage: node builds the frontend, python:3.12-slim
  runs the app; installs docker CLI so the app can drive the host daemon via the
  mounted socket) + `.dockerignore`.
- `docs/deployment/linux.md`: Linux production deployment guide (venv + systemd
  service, containerized deployment with docker socket mount, nftables scoped
  egress, backup cron, journalctl logging, nginx reverse proxy, verification
  checklist).

### Changed
- `scripts/build_web.sh` and `scripts/verify_env.py`: replaced the Windows-only
  `py -3.12` launcher with `${PYTHON:-python3}` / `python3` (defaults to Linux;
  Windows users set `PYTHON=py` or use `py -3.12` per the README note).
- Docs (README, user-manual, environment-setup, adapter-guide): `py -3.12` ->
  `python3` throughout, with a one-line Windows note in README. Removed a
  hardcoded `F:\claudepc\SecOpent` path from environment-setup.

### Notes
- No file-permission changes were needed: `EncryptedFileBackend` and
  `Ed25519KeyProvider` keep secrets in memory (no on-disk secret file). The
  Linux deployment doc covers DB-file `chmod 600` at the ops layer.
- nftables scoped egress (T11) is runtime-usable on Linux for the first time
  (Windows could only unit-test it).


## [0.1.0] - 2026-07-31

`Schema: n/a (first release) | Deps: n/a | Breaking: no` - First public release. Catalog-driven, agent-native **authorized** pentest
workbench: a deterministic spine (Planner, PolicyEngine, CoverageMatrix, oracle)
with an LLM that only ever *proposes* — humans and the deterministic layer
decide scope, approval, signing, findings, and publish.

### Added — Core platform
- Deterministic spine: projects / scope / assessment / audit hash chain,
  `PolicyEngine` 10-step authorization chain (Deny-precedence, Destructive-never,
  DNS-rebinding defense), `Repository` contract (SQLite WAL default, PostgreSQL
  swappable via `SECOPTENT_DB_URL`).
- Knowledge layer: versioned `TestCatalog` (OWASP WSTG + CIS baseline, seeded at
  startup), `CoverageMatrix` with coverage-regression gate, signed (Ed25519)
  update bundles with staging → atomic activate → rollback.
- 17 adapters across four domains (asset: subfinder/httpx/naabu/katana; web/API:
  nuclei/dalfox + Schemathesis; network: nmap; cloud: trivy/prowler/kube_bench/
  checkov/scoutsuite), each digest-pinned, non-root, cap-drop.
- Verification: deterministic oracle with `RescanVerifier` (real N/N rescan
  reproduction → CONFIRMED), three-tier evidence (RAW/REDACTED/SUMMARY), seccomp
  sandbox for YAML case DSL (no-eval interpreter).
- Model-driven logic testing: signed `AppModel` (state machine + invariants +
  field trust boundaries + roles), 5-class `LogicTestGenerator` (skip_step /
  out_of_order / replay via RESTler, boundary via Schemathesis, invariant
  violation self-built) with idempotent signatures + `DriftDetector`.
- Orchestration: `Planner` DAG → `Orchestrator` (job lease + retry) →
  `AdapterStepRunner` (PlanStep → real tool container → observations →
  `result_digest`); `ReportRenderer` with completeness gate.
- Agent interface: MCP tool registry, FastAPI (47 paths) + SSE, CLI, Web Case
  Studio (React + @xyflow/react DAG + Monaco YAML editor, 7 pages).
- Security hardening: `ScopeEnforcer`, signed `ExecutionPermit`, `SecretStore`
  (encrypted file backend, multi-key Ed25519 signing, rotation), signed
  `AuditChain` (HMAC, tamper-detectable), `EmergencyStop`, `PromptInjectionGuard`,
  `RemoteModelGateway` (MiniMax / OpenAI-compatible), STRIDE threat model.

### Added — v1.1 (this release)
- End-to-end orchestration proven across all four domains (real nuclei/dalfox/
  nmap/naabu/httpx/checkov against Juice Shop / httpbin / local Docker).
- CI hardening: full-package strict mypy, frontend build, Playwright browser-e2e,
  real-orchestration e2e, SAST (bandit/gitleaks/pip-audit/npm audit), coverage
  gate 80%.
- Backup/restore: `secopent restore` (audit-chain-verified, atomic), `backup
  --include-secrets`, `scripts/verify_backup.py`, ops runbook.
- Release process: version single-source, this CHANGELOG, `scripts/release.sh`.
- Performance: SQLite WAL tuning, SSE backpressure (bounded queue + disconnect
  cleanup + dedup), DAG viewport virtualization, adapter `--parallel N` with
  race-free job lease.
- Observability: structlog (request_id/tenant binding, redaction), Prometheus
  `/metrics` (5 metric families), OpenTelemetry tracing, Grafana dashboard.
- i18n: zh/en localization (react-i18next, default zh-CN; backend
  `Accept-Language` error localization).
- Database migrations: Alembic baseline + SQLite→PostgreSQL migration script.

### Fixed
- Adapter tool output decoded as UTF-8 (was locale codec, e.g. gbk on zh-CN
  Windows, losing non-ASCII output).
- checkov parser flattens the multi-framework JSON array emitted by checkov ≥3.x.
- Adapter containers map `host.docker.internal:host-gateway` for Linux CI
  reachability (harmless on Docker Desktop).
- LLM boundary: `agent` actor role is denied (403) on human-only actions
  (sign/publish/approve/verdict/stop/signing-key-create).

### Known limitations
- trivy cloud scan requires a reachable vulnerability DB (network-gated in some
  regions; checkov covers the cloud/container IaC domain offline).
- nftables scoped egress enforcement is implemented + unit-tested with a Linux
  CI job, but runtime verification requires a Linux host.
- Remote Worker execution (multi-machine) is designed (Tier 1 design ready) but
  not yet implemented — adapters run on the controller host in this release.

### Notes
This is the first *public* release. Internal development milestones (M0–M5,
Phase A, P0–P3) preceded it; their tags are not published. 0.1.0 reflects
semver initial-development semantics (0.x).
