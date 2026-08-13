# 2026-08-13 MCP 控制面闭环:durable job lease + 协作取消(pause/resume/cancel 真停扫)设计

> 状态:Draft。前置:MCP transport 落地(`sepcs/` MCP 实现,17 标准工具,HUMAN_REQUIRED 门控)。
> 本设计解决 MCP `assessment_pause/resume/cancel` 当前"持久化-only"的诚实缺口:状态列改了,executor 照跑。

## 1. Context / 动机

MCP 控制面工具 `assessment_pause` / `assessment_resume` / `assessment_cancel` 已落地,但当前语义是**持久化-only**:`AssessmentService.pause/resume/cancel` 只改 `core_assessments.status` 列(经 `transitions.py` 状态机),正在跑的 executor 线程**不受影响**——暂停的 assessment 仍会扫完所有 step,运行中失败还会把 PAUSED 覆盖成 FAILED。工具描述已如实声明该限制,但作为安全工作台的编排面,这不可接受:操作员经 MCP 说"暂停",扫描必须真的停。

本设计的两个底层问题(§2)其实在 M4 就存在,与 MCP 无关:

- **job lease 不持久**:`JobService` 是纯内存 dict(进程内),`core_jobs` 表和 `SqlAlchemyJobRepository` 已建好但**无人写入**——Web 的 `/jobs` 界面看不到真实执行任务,进程重启丢所有执行状态。
- **无运行中取消信号**:任何 running assessment 都无法被中途停下(除 EmergencyStop 全量终止和 SIGTERM drain)。

## 2. 现状(证据)

| 组件 | 位置 | 现状 |
|---|---|---|
| Job 领域模型 | `domain/jobs/models.py:18-68` | PENDING→BLOCKED/READY→LEASED→RUNNING→SUCCEEDED/FAILED/SKIPPED/POLICY_DENIED;lease_owner + lease_expires_at;`RETRYABLE_FAILURES`/`POLICY_FAILURES` 分类已齐 |
| JobService | `application/jobs.py:39-138` | **纯内存 dict**;RLock 下原子 lease(READY|stale-LEASED→LEASED, attempt+1)、renew、requeue、leaseable 完整;docstring 明说 "SQLite-backed lease lands behind the same surface (Task 11)" |
| core_jobs 表 | `infrastructure/db/job_models.py:25-45` | 列全(含 idempotency_key unique、lease_expires_at、dependencies JSON);在 CoreBase.metadata 上(表已创建) |
| SqlAlchemyJobRepository | `infrastructure/repositories/sqlalchemy_jobs.py:48-62` | 仅 add(merge)/get/all;**无 lease 原子语义**;**无人调用**(HTTP `/jobs` 只读展示) |
| 执行循环 | `application/execution.py:439-442` | `jobs = JobService()`(in-memory)→ `Orchestrator(jobs, runner).dispatch(plan); run_to_completion(...)` |
| Orchestrator | `application/orchestrator.py:53-146` | `execute_ready` 每轮 leaseable→execute(worker 池);`run_to_completion` max_rounds=100 轮询;`_handle_failure` retry/deny |
| 取消信号 | `execution.py:354` | 仅执行前检查 `emergency_stop.is_triggered` 一次;运行时无任何检查点 |
| 停机 drain | `api/main.py:_drain_active_executions` | SIGTERM 时 `DockerContainerTerminator().terminate_active()` + join 等线程;不针对单 assessment |
| 状态机 | `domain/assessments/transitions.py` | RUNNING↔PAUSED、QUEUED/RUNNING/PAUSED→CANCELLED 已合法(前一阶段加入) |
| 状态迁移者 | `application/assessments.py:161-189` | `mark_running`/`complete`/`fail` 无条件执行,不知道暂停/取消 |

## 3. 问题 / 失败场景

1. **MCP pause 不真停**:操作员 pause 后,后台线程继续跑完剩余 step,可能已发起实际扫描请求(对授权靶标但不是操作员期望的当前状态)。
2. **cancel 不终止**:进行中的容器不被杀;`complete()`/`fail()` 之后覆盖 CANCELLED(状态机已被绕过——`mark_running`/`complete` 不经过 `assert_transition` 的 PAUSED guard 之外的目标检查,实际是直接 replace)。
3. **重启丢状态**:进程挂了,所有 job/执行进度丢失;startup recovery 只把 RUNNING/QUEUED→FAILED(`api/main.py` 启动恢复),job 粒度无恢复。
4. **/jobs 空表**:Web UI 的 job 视图是摆设,operators 看不到 step 级进度。
5. **多 worker 无持久互斥**:V2 分布式 worker(mcp-security-hub 容器采纳)需要 DB 级 lease 才能多进程安全租约。

## 4. 设计目标

T1. **真暂停**:pause 后,executor 在**当前 step 完成后不再发起新执行**;进行中的 step 允许自然结束(容器不可中断步,诚实边界)。
T2. **真取消**:cancel 后,当前容器被终止(复用 DockerContainerTerminator 按 assessment 过滤找),剩余 jobs 记为 SKIPPED,CANCELLED 终态不再被覆盖。
T3. **真恢复**:resume 在 executor 已退出的情况下,以幂等 dispatch 重启 drain,只执行剩余 READY jobs。
T4. **持久 lease**:job 状态/租约落 `core_jobs`,进程重启后 Web 可见、可恢复;`JobService` 接口不变(向后兼容测试),生产实现走 SQLAlchemy 原子更新。
T5. **单一真相**:暂停/取消信号与状态都持久化,executor 每轮从 DB 读取,内存无飘移状态。
T6. 安全边界不变:`plan_approve`/`assessment_start` 仍 HUMAN_REQUIRED;pause/resume/cancel 保持 agent 可调(控制面,不触发扫描)。

## 5. 方案

### 5.1 JobStore 协议 + 两个实现(durable lease)

```python
# domain/jobs/store.py (新) —— 或并入 application/ports/repositories.py
class JobStore(Protocol):
    def add(self, job: Job) -> None: ...            # 幂等(按 idempotency_key,返回已存在)
    def get(self, job_id: str) -> Job: ...
    def all(self) -> tuple[Job, ...]: ...
    def lease(self, job_id: str, *, owner: str, now: datetime) -> Job:
        """READY|stale-LEASED -> LEASED, attempt+1; 非法迁移抛 JobLeaseError."""
    def renew(self, job_id: str, *, owner: str, now: datetime) -> Job: ...
    def complete(self, job_id: str, *, result_digest: str) -> Job: ...
    def fail(self, job_id: str, *, failure_class: FailureClass) -> Job: ...
    def requeue(self, job_id: str) -> Job: ...
    def mark_ready(self, job_id: str) -> Job: ...
    def leaseable(self, now: datetime) -> tuple[Job, ...]: ...
```

- **`MemoryJobStore`** = 现有 `JobService` 内核对 `JobStore` 的适配(RLock 保留,测试与单测用)。
- **`SqlAlchemyJobStore`**(新文件 `infrastructure/repositories/sqlalchemy_job_store.py` 或扩展现有 repo):
  - 写路径:`add/complete/fail/...` = `merge(CoreJob)` + flush(SQLAlchemy,事务由调用方 UoW 负责——与审计链同事务,见 §5.4)。
  - **原子 lease**:SQLAlchemy `update(CoreJob).where(id==, and_(status=='ready' | (status=='leased' and lease_expires_at<=now))).values(status='leased', attempt=attempt+1, ...)`,按 `result.rowcount == 1` 判定成功,否则读回状态抛 `JobLeaseError`。多进程安全:UPDATE 条件原子,竞态由 SQLite/PG 写锁裁决,无需应用锁。
  - stale 判定统一用 `utc_now()`(`domain/common/canonical.py`,现有 `_phase_commit` 同源时钟)。
- **`JobService` 兼容层**:构造函数改为 `JobService(store: JobStore | None = None)` → 默认 MemoryJobStore;全部方法委托 store。现有测试零改动(docstring "SQLite-backed lease lands behind the same surface" 兑现)。

### 5.2 运行控制面(RuntimeControl)

持久化的 per-assessment 运行信号,放在 `core_assessments` 上(H2 前不新表):

```python
# domain/assessments/models.py 扩 Assessment 字段(向后兼容,默认 None)
@dataclass(frozen=True, slots=True)
class Assessment:
    ...
    control: ControlState = field(default=ControlState.NONE)   # 新

class ControlState(StrEnum):
    NONE = "none"
    PAUSE_REQUESTED = "pause_requested"
    RESUME_REQUESTED = "resume_requested"
    CANCEL_REQUESTED = "cancel_requested"
```

迁移:alembic 新 migration 加 `control` 列(默认 "none");旧行兼容。

语义(每轮执行在 `orchestrator.execute_ready` 与 `run_to_completion` 之间收敛,信号由 executor 消费并**清除**):

| 信号 | 写入者 | 消费点 | 效果 |
|---|---|---|---|
| PAUSE_REQUESTED | `AssessmentService.pause`(同时 status→PAUSED) | executor 每轮(step 完成后) | 停止发新一轮;线程退出;信号清为 NONE;状态保持 PAUSED |
| RESUME_REQUESTED | `AssessmentService.resume`(status→RUNNING) | 新后台线程(`_resume_drain`,§5.3) | 重启 drain;信号清 NONE |
| CANCEL_REQUESTED | `AssessmentService.cancel`(status→CANCELLED) | executor 每轮 + 立即 | 终止当前容器;剩余 jobs SKIPPED;线程退出 |

- **消费点**:`execute_ready` 开头读 `assessment.control`;或更简单——`run_to_completion` 每轮后刷新。执行中的 step 结束后在 `_execute` 返回处检查。
- **进行中 step 的终止(cancel)**:`DockerContainerTerminator` 增加 `terminate_for_assessment(assessment_id)`(容器以 assessment 命名/打标签,见 `infrastructure/safety/emergency_infra.py` 现有 `terminate_active` 的按名称/标签枚举逻辑);调用后 `runner.run` 抛 `StepFailure(WORKER_UNAVAILABLE)` 或被杀 → `_handle_failure` 走现有重试,但 cancel 信号使 orchestrator 不再 lease。
- **取消后的终态保护**:`mark_running`/`complete`/`fail` 在 replace 前检查当前 status:`if status is CANCELLED: raise/return`(绕过状态机的地方显式 guard,防止 CANCELLED 被覆盖——修复 §3.2)。

### 5.3 resume 重启 drain

executor 退出后(线程结束)的 resume 需要新线程:

```python
# application/execution.py 新增
def resume_assessment(*, assessment_id, ..., store: JobStore) -> None:
    # 轻量重启:不发新 permit/nft(原 permit 已记录),只 drain jobs
    orchestrator = Orchestrator(JobService(store), step_runner_factory(scope), ...)
    orchestrator.dispatch(plan)            # 幂等:core_jobs idempotency_key unique
    orchestrator.run_to_completion(...)    # 只跑剩余 READY/过期 LEASED
    ...照常 correlate/findings/status
```

- dispatch 幂等性已由 `core_jobs.idempotency_key` unique + `JobStore.add` 按 key 返回已在 job 保证(§5.1)。
- resume 路径在**同一**进程内由 `_run_assessment_daemon` 模式复用(starlette background task / 新线程)。
- 跨进程 resume(API 进程挂了,新进程拉起):startup recovery 保持现状(残留 RUNNING/QUEUED→FAILED),**本设计不实现跨进程恢复**(permit/nft 等执行期状态非持久,诚实留白,见 §8.3);`/jobs` 可见性 T4 已覆盖内存→DB 迁移。

### 5.4 事务与审计

- Job 写入与 assessment 状态迁移在**同一 UoW**内(`execute_assessment` 已有 `db.unit_of_work`),保证 job+状态原子可见。
- `_phase_commit(audit_repo)`(WAL 释放)仍照旧:每轮 flush jobs,长扫描期间不持有写锁。
- 审计事件:`assessment.pause_requested` / `assessment.resumed` / `assessment.cancelled` 走签名 `AuditChain`(MCP handler 已记,executor 消费信号时的实际停扫动作(action="assessment.paused" 语义不变,payload 增 `actual: true`)补记)。

### 5.5 MCP 工具描述更新

- `assessment_pause`:描述从 "persistence-only 注释" 改为 "完成当前 step 后停止发起新执行";返回含 `actual_stop: true/false`(已停/线程未在跑)。
- `assessment_cancel`:返回 `containers_terminated: n`。
- 移除 handlers.py 模块 docstring 与 `transitions.py` 注释里的 "persistence-only" 限制声明,更新 `docs/architecture/interfaces.md`。
- Web UI `/jobs`:表变真实数据,无需前端改动(读已通)。

## 6. 顺序与里程碑

| # | 里程碑 | 交付 | 依赖 | 状态 |
|---|---|---|---|---|
| M1 | Store 协议 + 两实现 | `JobStore` Protocol、MemoryJobStore 适配、SqlAlchemyJobStore(原子 lease)、JobService 兼容层 | 无 | ✅ 完成 |
| M2 | 同构性验证 | 行为矩阵测试:Memory vs SqlAlchemy 全方法等价;core_jobs 真实写入 | M1 | ✅ 完成 |
| M3 | 控制面字段 + 状态机守卫 | `Assessment.control` + alembic migration(`3f91c2a7d504`,幂等 add_column);终态守卫显式测试(CANCELLED 无出口已由 transitions 表保证);MCP `_assessment_out` 暴露 control | M1 | ✅ 完成 |
| M4 | 协作取消接线 | executor 每轮读取 control;pause 停止、cancel 终止(SKIPPED jobs + 终止钩子,真实 per-assessment 容器终止待适配器链 label 接入)、resume 轻量重启(`resume_assessment` + `POST /assessments/{id}/resume` + MCP runtime 调度器);审计补记(assessment.paused/cancelled actual) | M2+M3 | ✅ 完成 |
| M5 | MCP/文档收口 | 工具描述、handlers 返回增强、interfaces.md、CHANGELOG;`transition` 注释清理 | M4 | ✅ 完成 |
| M6 | 集成验证 | fake step_runner 集成测试(pause 后不再调用;cancel 终止;resume 幂等);完整套件 | M4 | ✅ 完成(含在 M4) |

## 7. 测试计划

- **单元(store 等价矩阵)**:对 `MemoryJobStore` / `SqlAlchemyJobStore`(tmp SQLite)参数化跑同一行为集:add 幂等、lease READY、lease stale-LEASED、lease 非法状态抛、renew 仅 owner、complete/fail/requeue/mark_ready、leaseable 过滤。新建 `tests/application/test_job_store.py`(当前无 jobs 单测文件)。
- **单元(守卫)**:`mark_running`/`complete`/`fail` 对 CANCELLED assessment 拒绝(不再覆盖终态)。参照 `tests/application/test_assessments_guard_gaps.py` 风格。
- **集成(fake runner)**:构建计数 StepRunner,`execute_assessment` 中途:
  - pause:执行中调用 service.pause + 写 control → runner 调用数不再增长;status==paused;jobs 停在 READY。
  - cancel:runner 抛后不再重试;剩余 jobs SKIPPED;status==cancelled 且其后 complete() 调用被拒。
  - resume:线程退出后 service.resume + `resume_assessment` → 仅剩余 READY jobs 被执行(dispatch 幂等,无重复执行)。参照 `tests/application/test_assessment_oracle_e2e.py` 的注入模式。
- **MCP handler**:`assessment_pause` 返回 `actual_stop` 字段;HTTP smoke 一次。
- **回归**:`pytest -m "not e2e_real and not browser and not perf and not realism"` 全绿;ruff/mypy。

## 8. 取舍与边界(明确不做)

8.1 **不中断进行中的 step**:容器/子进程同步执行无法安全中断(Docker kill 即丢半程物料);pause 只保证 step 边界停止。文档与工具描述诚实声明。
8.2 **跨进程 resume 不做**:permit/nft/outbox 执行期状态为进程内存(或单进程 UoW);重启恢复维持现有 startup recovery(RUNNING→FAILED)。T4 只承诺 job 持久可见,不承诺跨进程续跑。
8.3 **不引入新的取消 executor 专用表**:信号挂 `core_assessments.control`,单列足够,避免结构冗余(YAGNI)。
8.4 **多 worker V2 兼容**:DB 原子 lease 本身即为 V2 分布式 worker 提供了安全租约;本设计不交付 worker 调度。
8.5 **`SqlAlchemyJobRepository` 处置**:与 `SqlAlchemyJobStore` 合并(repo 已有 add/get/all 直接升级补 lease 语义),不保留两套。

## 9. 引用

- MCP transport 设计:`docs/architecture/interfaces.md` §MCP Server;`src/secopent/interfaces/mcp/{handlers,server,tool_registry}.py`
- 状态机:`domain/assessments/transitions.py`(RUNNING↔PAUSED / →CANCELLED 已合法)
- Job 模型/lease:`domain/jobs/models.py`、`application/jobs.py`
- 执行:`application/execution.py` §execute_assessment、`application/orchestrator.py`
- 表/Repo:`infrastructure/db/job_models.py`、`infrastructure/repositories/sqlalchemy_jobs.py`
- 停机/终止:`interfaces/api/main.py::_drain_active_executions`、`infrastructure/safety/emergency_infra.py`