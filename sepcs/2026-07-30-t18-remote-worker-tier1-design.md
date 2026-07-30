# T18 远程 Worker - Tier 1 详细设计（P4 §8.1）

> **日期**：2026-07-30
> **角色**：设计 + 验收方
> **前置**：v1.1-stable 打完后执行（当前 v1.1-stable 未 tag，T6-T10 待完成）
> **本文档基于实测接口**：StepRunner Protocol、AdapterStepRunner（T5 产出）、JobService lease（TTL 300s）、RealScanRunner
> **替代**：`v1.1-stable-final-and-p4-plan.md` §8.1 的草稿（升级到 Tier 1）

---

## 0. 问题与目标

**现状**：T5 的 `AdapterStepRunner` 在主控本机 Docker 跑适配器。受单机资源/网络/隔离限制：
- 大规模扫描吃本机 CPU/内存
- 中国网络墙影响某些镜像/DB（如 trivy 漏洞库）
- 多租户隔离需独立 Docker daemon

**目标**：适配器执行卸载到远程 Worker，主控调度。Worker 复用 `RealScanRunner`（不重写执行层），经网络边界调度。

**核心设计原则**（T5 验证有效）：**复用已验证机制，不重写**。Worker = "另一台机器上的 AdapterStepRunner + 网络边界"。RemoteStepRunner 实现同一 `StepRunner` Protocol，Orchestrator 零改动。

---

## 1. 真实接口（实测，设计基础）

### StepRunner Protocol（`application/orchestrator.py:46`）
```python
@runtime_checkable
class StepRunner(Protocol):
    def run(self, step: PlanStep) -> StepResult: ...   # 同步签名，返回 digest
```

### AdapterStepRunner（T5，`infrastructure/adapters/step_runner.py:71`）
- per-engagement 构造：`__init__(scan_runner: RealScanRunner, context: ScanContext)`
- 观测旁路字典（不改不可变 StepResult）
- `run(step)` -> 扫所有 targets -> 存观测 -> 返回 `StepResult(result_digest=...)`

### JobService lease（`application/jobs.py:42`）
```python
def lease(job_id, *, owner, now) -> Job        # READY/stale-LEASED -> LEASED，+attempt
def renew(job_id, *, owner, now) -> Job         # 仅 owner 可续
def complete(job_id, *, result_digest) -> Job   # LEASED -> COMPLETED
def fail(job_id, *, failure_class) -> Job
# lease_ttl_seconds=300，stale 自动可重租
```
**这是远程容错的天然基础**：worker = lease owner，掉线 -> TTL 过期 -> 别的 worker/本地重租。

### Orchestrator（`application/orchestrator.py:52`）
`__init__(jobs, runner, *, max_workers=1)` + `dispatch` + `run_to_completion` -- **零改动**，只是注入 RemoteStepRunner 替代 AdapterStepRunner。

---

## 2. 架构

```
┌──────────────── 主控（Controller，现有 FastAPI）────────────────┐
│  Orchestrator ──> RemoteStepRunner (StepRunner Protocol)        │
│  JobService（lease 管理）                                        │
│  WorkerRegistry（注册+心跳+能力）                                │
│  SecretStore（签名/验证，不下发）                                │
│  /workers/register /workers/{id}/heartbeat /workers/jobs/next   │
│  /workers/jobs/{id}/result                                      │
└──────────────────────────┬──────────────────────────────────────┘
                           │ mTLS + auth token
                           │ HTTP/JSON（poll 模型）
           ┌───────────────┴───────────────┐
           ▼                               ▼
┌─── Worker 1（远程机器）──┐      ┌─── Worker 2 ───┐
│  secopent worker 进程    │      │  独立 Docker    │
│  独立 Docker daemon      │      │  nftables scope │
│  nftables scope (P2-G)   │      │  能力: nuclei.. │
│  RealScanRunner (复用)   │      └─────────────────┘
│  能力: nuclei/dalfox/..  │
└──────────────────────────┘
```

**关键**：Worker 进程复用 `RealScanRunner` + `AdapterStepRunner` 的执行核心，只是观测结果经网络回传主控。

---

## 3. 协议设计（HTTP/JSON + poll，非 gRPC）

### 决策：HTTP/JSON，不用 gRPC
**理由**：
- 代码库 Python/FastAPI 原生 HTTP，无 grpc 依赖（已核查 pyproject 无 grpc/protobuf）
- job 频率低（渗透测试非高频），poll 足够，无需双向流
- 复用 FastAPI 路由 + Pydantic schema，零新工具链
- T5 教训：复用已有机制 > 引入新层
- **gRPC 留作 V2 选项**（若流式进度/高吞吐成瓶颈）

### Worker API（Controller 侧新增路由 `interfaces/api/routers/workers.py`）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/workers/register` | worker 启动注册，返回 worker_id + 能力声明 |
| POST | `/workers/{id}/heartbeat` | 心跳（续 lease 持有 job），10s 一次 |
| POST | `/workers/{id}/jobs/next` | 拉下一个匹配能力的 READY job -> lease 给自己 |
| POST | `/workers/jobs/{job_id}/result` | 回传结果（digest + observations） |
| GET | `/workers` | 列已注册 worker + 状态（运维用） |

### Poll 模型（worker 主动拉）
- Worker 每 N 秒 `POST /workers/{id}/jobs/next`（N=2，可配）
- Controller 原子 lease 一个匹配 worker 能力的 READY job
- Worker 跑完 `POST /workers/jobs/{id}/result`
- 心跳并行续 lease（防长任务 TTL 过期）

**为什么不 push**：worker 常在 NAT 后，poll 更稳；且 JobService lease 已是 pull 模型。

---

## 4. 数据模型与 Schema

### `schemas.py` 新增
```python
class WorkerCapability(BaseModel):
    adapters: list[str]          # ["nuclei","dalfox","nmap",...]
    docker_available: bool
    max_concurrent: int = 1
    labels: dict[str, str] = {}  # 区域/租户标签

class WorkerRegister(BaseModel):
    name: str
    capability: WorkerCapability
    auth_token: str              # 注册令牌（运维预发放）

class WorkerOut(BaseModel):
    id: str
    name: str
    capability: WorkerCapability
    status: str                  # active/idle/offline
    last_heartbeat: datetime
    active_jobs: int

class JobAssignment(BaseModel):
    job_id: str
    step_key: str
    runner: str                  # 适配器名
    parameters: dict[str, Any]
    scan_context: ScanContextPayload  # targets/mounts（序列化 ScanContext）

class JobResult(BaseModel):
    job_id: str
    result_digest: str
    observations: list[dict[str, Any]]   # 序列化 Observation（V1 直传，V2 改 artifact store）
    exit_code: int
    stdout_excerpt: str = ""     # 截断，防大日志
    stderr_excerpt: str = ""
```

### WorkerRegistry（`application/worker_registry.py`，新建）
```python
@dataclass(frozen=True, slots=True)
class WorkerInfo:
    id: str
    name: str
    capability: WorkerCapability
    status: WorkerStatus          # ACTIVE/IDLE/OFFLINE
    last_heartbeat: datetime
    active_jobs: int

class WorkerRegistry:
    def register(self, name, capability, token) -> WorkerInfo: ...
    def heartbeat(self, worker_id, now) -> WorkerInfo: ...
    def mark_offline(self, worker_id) -> None: ...   # TTL 过期调用
    def select(self, adapter: str, *, now: datetime) -> WorkerInfo | None:
        """选一个支持 adapter 且 active_jobs < max_concurrent 的 idle worker。"""
    def list_all(self) -> tuple[WorkerInfo, ...]: ...
```

---

## 5. RemoteStepRunner（核心胶水，镜像 AdapterStepRunner）

**文件**：`src/secopent/infrastructure/adapters/remote_step_runner.py`

```python
from ...application.orchestrator import StepRunner, StepFailure, FailureClass
from ...domain.adapters.contracts import Observation

class RemoteStepRunner(StepRunner):
    """StepRunner that dispatches to a remote Worker via the Worker API.

    镜像 AdapterStepRunner 的旁路观测字典契约，但 run() 不本地执行，
    而是经 WorkerRegistry 选 worker -> 拉结果。Orchestrator 零改动。
    """

    def __init__(self, registry: WorkerRegistry, client: WorkerClient,
                 *, fallback: StepRunner | None = None) -> None:
        self._registry = registry
        self._client = client            # HTTP client 封装
        self._fallback = fallback        # 无 worker 时退回本地 AdapterStepRunner
        self._observations: dict[str, tuple[Observation, ...]] = {}

    def run(self, step: PlanStep) -> StepResult:
        worker = self._registry.select(step.runner, now=utc_now())
        if worker is None:
            if self._fallback is not None:
                return self._fallback.run(step)   # 退回本地
            raise StepFailure(FailureClass.NO_WORKER, f"no worker for {step.runner}")
        try:
            result = self._client.run_job(worker.id, step, self._context)
        except WorkerUnavailableError:
            self._registry.mark_offline(worker.id)
            return self.run(step)                 # 重试，换 worker
        self._observations[step.key] = result.observations
        return StepResult(result_digest=result.result_digest)
```

**关键**：
- 实现同一 `StepRunner` Protocol -> Orchestrator 注入即可，零改动
- 旁路观测字典契约与 AdapterStepRunner 一致 -> 下游 FindingCorrelator 取观测方式不变
- `fallback` = 本地 AdapterStepRunner -> 无 worker 时不中断（开发/单机模式平滑过渡）
- worker 掉线自动重试换 worker

---

## 6. Worker 进程（`secopent worker` CLI）

**文件**：`src/secopent/interfaces/cli/worker.py`（新建）+ `infrastructure/worker/worker_process.py`

```python
class WorkerProcess:
    """远程 worker 主循环：注册 -> poll job -> 本地跑 -> 回传结果。"""

    def __init__(self, controller_url: str, auth_token: str,
                 capability: WorkerCapability) -> None:
        self._client = WorkerClient(controller_url, auth_token)
        self._capability = capability
        self._local = AdapterStepRunner(   # 复用 T5 执行核心！
            RealScanRunner(SubprocessExecutor()),
            context=ScanContext(...),       # 从 JobAssignment 重建
        )

    def run_forever(self) -> None:
        info = self._client.register(self._capability)
        while True:
            self._client.heartbeat(info.id)             # 续 lease
            job = self._client.next_job(info.id)        # poll
            if job is None:
                sleep(2); continue
            try:
                step = _to_plan_step(job)
                result = self._local.run(step)          # 本地 RealScanRunner 跑
                observations = self._local.observations_for(step.key)
                self._client.post_result(job.id, result, observations)
            except Exception as exc:
                self._client.post_failure(job.id, exc)
```

**CLI**：`secopent worker --controller https://ctrl:8000 --token XXX --adapters nuclei,dalfox`

**关键**：worker 复用 `AdapterStepRunner` + `RealScanRunner` + `SubprocessExecutor` 全套执行核心，只是套了网络边界。**执行层零重写**。

---

## 7. 调度与能力匹配

### 选 worker 算法（`WorkerRegistry.select`）
1. 过滤：`capability.adapters` 含 `step.runner` 且 `active_jobs < max_concurrent` 且 `status in (ACTIVE, IDLE)`
2. 排序：`active_jobs` 最少（负载均衡）-> `labels` 匹配（租户/区域亲和）-> 注册时间最早（稳定）
3. 原子 lease：`select` 返回前调 `JobService.lease(job_id, owner=worker_id, now)`，防两 worker 抢同一 job

### 能力声明
- worker 启动时探测本地 Docker + 已拉镜像 -> 声明 `adapters`
- 不支持某适配器 -> 不声明 -> 不被选 -> 主控 fallback 本地或报 NO_WORKER

### 降级链
```
RemoteStepRunner.run(step)
  -> select worker: 找到 -> 派发
  -> 找不到 -> fallback 本地 AdapterStepRunner
  -> 本地也不支持 -> StepFailure(NO_WORKER)
```

---

## 8. 安全

### 8.1 mTLS（worker <-> controller）
- Controller 持 CA + 自签证书；worker 持 CA 签发的 client 证书
- `WorkerClient` 用 `httpx` + `cert=(client.crt, client.key)` + `verify=ca.crt`
- 证书轮换：复用 §3.8 的 `SigningKeyService` 轮换机制（同套密钥管理）

### 8.2 注册令牌
- 运维预发放一次性 `auth_token`（`secopent worker-token issue --name w1`）
- worker 注册时验 token -> 换 worker_id + 长期 session token
- token 存 SecretStore（不落 git）

### 8.3 SecretStore 不下发
- **签名/验证只在主控**：worker 跑适配器产观测，但不签名 Case、不验 oracle 签名
- worker 只回传 observations + digest，主控做 FindingCorrelator + RescanVerifier + ReportRenderer
- 设计上 worker 是"无状态执行单元"，不持密钥

### 8.4 Scope 隔离（worker 侧）
- worker 拉到 job -> 从 `JobAssignment.scan_context` 取 targets
- worker 本地 `NftScopeEnforcer.apply_scope(snapshot)`（P2-G 复用）-> 仅白名单 IP 可达
- worker 独立 Docker daemon -> 容器隔离

---

## 9. 容错

### 故障场景与处理
| 故障 | 检测 | 处理 |
|---|---|---|
| worker 进程崩 | 心跳超时（>30s） | WorkerRegistry mark_offline + 该 worker 持有的 job lease TTL 过期 -> 别的 worker/本地重租 |
| 网络分区 | 心跳超时 | 同上，lease TTL 是天然兜底 |
| worker 跑 job 超时 | lease TTL（300s）过期 | job 回 READY，attempt+1，重租（JobService 已有 stale-LEASED 重租） |
| worker 报失败 | `post_failure` | `JobService.fail(job_id, failure_class)` -> 视策略重试或人工 |
| controller 重启 | worker poll 失败 | worker 退避重连；job 状态持久化在 DB，重启后 lease 仍有效 |

### 心跳与 lease 协同
- worker 每 10s `heartbeat`（续 worker 存活）
- worker 持有 job 期间，每 `lease_ttl/3`（100s）`renew` job lease
- 两层独立：worker 活着但 job 卡 -> job lease 过期重租；worker 死 -> 心跳超时 + job lease 过期

### 幂等
- `post_result` 带 `result_digest`，重复提交同 digest 幂等（JobService.complete 已校验状态）
- worker 重试时若 job 已 COMPLETED，`post_result` 返回 200 不重复处理

---

## 10. 实现任务分解

| # | 任务 | 文件 | 工期 |
|---|---|---|---|
| 1 | WorkerRegistry + WorkerInfo 模型 | `application/worker_registry.py` | 0.5d |
| 2 | schemas（WorkerCapability/JobAssignment/JobResult） | `interfaces/api/schemas.py` | 0.5d |
| 3 | workers 路由（register/heartbeat/next/result） | `interfaces/api/routers/workers.py` | 1d |
| 4 | WorkerClient（HTTP 封装 + mTLS） | `infrastructure/worker/client.py` | 1d |
| 5 | RemoteStepRunner（StepRunner 实现 + fallback） | `infrastructure/adapters/remote_step_runner.py` | 1d |
| 6 | WorkerProcess（注册+poll+本地跑+回传） | `infrastructure/worker/worker_process.py` + `cli/worker.py` | 1.5d |
| 7 | mTLS 证书签发 CLI + token 管理 | `cli/worker_token.py` + 复用 SigningKeyService | 1d |
| 8 | 调度原子 lease（select + JobService.lease 联动） | `application/worker_registry.py` | 0.5d |
| 9 | 容错（心跳超时扫描 + stale lease 清理后台任务） | `application/worker_health.py` | 1d |
| 10 | 主控注入 RemoteStepRunner（可配：local/remote/fallback） | `interfaces/api/main.py` compose | 0.5d |

**总工期：~8-9 天**（1.5-2 周，含测试 + 集成调试）

---

## 11. 测试设计

### 单元测试（`tests/infrastructure/test_remote_step_runner.py`）
- `test_select_worker_by_capability`：worker 声明 nuclei -> 选它跑 nuclei step
- `test_fallback_to_local`：无 worker -> 退本地 AdapterStepRunner
- `test_worker_offline_retries_other`：worker1 掉线 -> 换 worker2
- `test_no_worker_no_fallback_raises`：无 worker 无 fallback -> StepFailure(NO_WORKER)
- `test_observations_side_channel`：观测旁路字典与 AdapterStepRunner 一致

### WorkerRegistry 测试（`tests/application/test_worker_registry.py`）
- register/heartbeat/mark_offline/select 负载均衡
- 心跳超时 -> mark_offline
- 能力过滤

### 集成测试（`tests/integration/test_worker_e2e.py`，`@pytest.mark.integration`）
- 起假 controller（TestClient）+ 假 worker（in-process WorkerProcess）
- 跑一个 nuclei step 经 worker -> 验证结果回传 + observations 完整
- 杀 worker -> 验证 lease 过期 + 重租

### 安全测试（`tests/security/test_worker_mtls.py`）
- 无证书 worker 注册被拒
- 错误 token 被拒
- worker 持有 SecretStore 密钥的断言（应无）

---

## 12. 验收标准

- [ ] WorkerRegistry + RemoteStepRunner 单测全绿
- [ ] 集成测试：真 worker 跑 nuclei step 经网络回传，observations 完整
- [ ] 容错：杀 worker，lease 过期后 job 重租到本地 fallback，不丢
- [ ] mTLS：无证书/错 token 被拒
- [ ] Orchestrator 零改动（仅注入 RemoteStepRunner）
- [ ] 全套无回归 + ruff/mypy clean
- [ ] commit `feat(worker): remote Worker execution + RemoteStepRunner + mTLS (T18)`

---

## 13. 风险与依赖

| 风险 | 缓解 |
|---|---|
| 依赖 P2-G nftables（worker scope 隔离） | T11 先做；T18 可先不做 worker 侧 scope，记为 TODO |
| 依赖 §3.8 密钥轮换（mTLS 证书） | 已完成 |
| 多机环境验证 | 本机起 2 个 worker 进程（不同端口）模拟 |
| 观测大 payload | V1 直传（size limit），V2 改 artifact store（见 §14） |
| worker 能力探测不准 | 启动时 `docker images` + 试跑，运维可手填 `--adapters` |

---

## 14. V2 演进（不在本次）

- **gRPC**：若流式进度/高吞吐成瓶颈
- **Artifact Store**：观测走 S3 兼容存储，controller 按 digest 拉（解大 payload）
- **Worker 自动扩缩**：K8s/ Nomad 调度 worker 副本
- **跨区域 worker**：labels 路由 + 就近调度

---

## 15. 与现有任务的关系

- **T18 依赖**：T5（AdapterStepRunner，已完成）、§3.8（密钥轮换，已完成）、T11（nftables，未做，可后置）
- **T18 不依赖**：T6/T7/T8/T9/T10（v1.1-stable 路径）-- 但按交接 §6，**v1.1-stable 打完才做 T18**
- **T18 解锁**：T19 多租户（worker 可按租户标签隔离）、T21 集群化（多 worker 调度基础）

*远程 Worker Tier 1 设计完。v1.1-stable 打完后，dev model 按 §10 任务分解执行。*
