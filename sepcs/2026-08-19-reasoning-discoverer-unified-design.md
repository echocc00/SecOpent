# Reasoning / Discoverer 统一权威 spec（LLM 自驱走查循环 + 逻辑漏洞差分确认）

> 日期：2026-08-19
> 状态：设计定稿，待实现计划（A/B 硬门禁后放行 V1）
> 作者：Hermes 调研 + 用户思路 + Claude 收敛
> 本文件是 **ReasoningLoop**（`sepcs/2026-08-19-reasoning-loop-design.md`）与 **Agentic Discoverer**（`docs/architecture/agentic-discoverer-handoff.md`）两份设计**合并后的单一权威版**。冲突时以本文件为准。

---

## 0. 合并说明（本文件为什么存在）

同日产出了两份同构设计（LLM 自驱循环）：
- **reasoning-loop-design.md**（39KB，成熟）：LoopState / ProposeAction / LoopContext 数据模型、三道门、终止策略、审计、持久化、落地路径
- **agentic-discoverer-handoff.md**（55KB，含专门设计）：DIFF_SEMANTIC 逻辑漏洞差分确认 Oracle、L1/L2/L3 分级、复用清单

两者不互相引用，会导致执行者拿到两份矛盾 spec。**本文件合并两者**，并修正评审发现的三处过时事实 + 收敛重复。核心增量是 **DIFF_SEMANTIC**（reasoning-loop 没有的 Oracle 确认手段——逻辑漏洞的落点）。

---

## 1. 修正自两份原稿的三处过时事实

### 1.1 Peer agent 已落地（reasoning-loop §0.1 第 21 行错误）

当前状态（v0.6.5 仓库核实）：Strix/Shannon 并非"实现计划未写、digest 空、NullPeerAgentHarness 降级中"。
- **6 份实现计划已写**：`docs/superpowers/plans/2026-08-04-p{0,1a,1b,2,2b,3}-*.md`
- **镜像 digest 已 pin**：`infrastructure/peer_agents/image_catalog.py`（strix `peer-worker-strix:1.4.1`、shannon `keygraph/shannon`，均填真实 digest）
- **harness 已切真实**：`main.py:602-606`——有 `LLM_API_KEY` 时接 `ContainerPeerAgentHarness`（strix 注册），无 key 才降级 `NullPeerAgentHarness`（带 warning）
- **A/B 脚手架已建**：`tests/e2e_real/test_peer_strix_ab.py`

**影响**：本设计的 `request_peer` 动作直接调已接好的 `PeerAgentService`，无需重新造。

### 1.2 Handbooks 已落地（非"P1a 准备中"）

`infrastructure/catalog/handbooks/` 现有 **8 份**（ssrf/insecure-deserialization/path-traversal/race-conditions/authentication-jwt/idor/http-request-smuggling/prototype-pollution），通过 provenance schema 校验。可直接注入 LoopContext，是现成的。

### 1.3 三道门顺序（非开放问题）

Schema→Policy→Permit 合理（Schema 拒最快最便宜、Policy 次之、Permit 最后签发最小权限）。**保持，不再 debate。**

---

## 2. 定位声明（沿袭 discoverer 原稿，与 reasoning-loop 合并）

**Cybergym 是评估基准，不是产品架构。** SecOpent 是授权渗透工作台（范围签发/审批/OracleEngine 确认/审计链/人在回路）。

**补逻辑漏洞探测的正确路子**：把"LLM 自主探索逻辑漏洞"做成 SecOpent 一个**受保护的发现源**——比 Strix peer 更高自主度，但被确定性层兜底。LLM 决策"测什么/怎么测/怎么根据响应调整"；确定性层负责范围/预算/证据/Oracle 确认/人在回路审批。

> 这套思路已在 P0-P3 验证（peer = 低信任发现源），本设计是其**深化第二层**：不把整段测试外包给 Strix 容器，而是在 SecOpent 应用层把"测试循环内的决策"纳入审计。

---

## 3. 整体架构（合并版）

```
┌─────────────────── 不变 ───────────────────┐
│ 接口层 (MCP/CLI/Web)                        │ ← loop_create/status/stop/history
├────────────────────────────────────────────┤
│ 控制平面-编排                                │
│  Planner / Orchestrator / PolicyEngine /    │
│  ScopeEnforcer (不变)                        │
│  ★ ReasoningOrchestrator (新增，非新 daemon)  │ ← 循环主体，沿 Orchestrator 协作模式
│  ★ LoopActionProposer (LLM, propose-only)    │ ← 新增
│  AttackChainEngine (P2b 已落)                │ ← 假设闭环驱动
│  Quality Gates (不变)                        │
├────────────────────────────────────────────┤
│ 知识层 (TestCatalog/CoverageMatrix/AppModel/ │
│  LogicTestGenerator/Handbooks[8份已落地])    │ ← Handbooks 注入 LoopContext（关键使能）
├────────────────────────────────────────────┤
│ 执行平面 (Worker/SubprocessExecutor/Case     │
│  Engine/Tool Containers/Scoped Egress/       │
│  Permit/PeerAgentService+Strix[已接线])      │ ← loop 步经 JobService 调度，沙箱不变
├────────────────────────────────────────────┤
│ Oracle (OracleEngine N/N + canary + OOB +    │
│  ★ DIFF_SEMANTIC 差分确认[本次新增])          │ ← 逻辑漏洞的确认落点
├────────────────────────────────────────────┤
│ 基础设施 (DB/CAS/Secret Store/AuditChain/    │
│  Telemetry)                                 │ ← 新增 core_reasoning_loops + core_loop_steps
└────────────────────────────────────────────┘
```

**位置关键**：ReasoningOrchestrator 是 Orchestrator 的协作模式（沿 Job Lease），**不是新层、不是新 daemon**。循环步 = 一类 job，经同一执行平面（沙箱/seccomp/netns/审计不变）。

---

## 4. 数据模型（沿用 reasoning-loop 成熟版 + 补 DIFF 字段）

### 4.1 LoopState / LoopStep / LoopContext

沿用 `reasoning-loop-design.md §3` 的 `LoopState` / `LoopStep` / `LoopContext`（frozen dataclass，全字段确定性可序列化）。关键引用：

- `LoopState.phase`：`INITIALIZING / RUNNING / CONVERGED / CATALOG_FLOOR_DONE / BUDGET_EXHAUSTED / POLICY_BLOCKED / EMERGENCY_STOPPED / COMPLETED`（确定性命定，LLM 不可写）
- `LoopStep`：含 `proposed_action / 三道门 verdict / permit_id / execution_result / observation_signals / catalog_class_matched / oracle_progressed`（审计粒度）

### 4.2 ProposeAction（LLM 输出严格 Schema）

沿用 reasoning-loop §3.3 的 `ProposeAction`（Pydantic 严格，`action_type: run_tool/run_case/request_peer/request_oracle/request_chain/abort_step`）。

**本文件补充**：`request_oracle` 的 payload 需支持 DIFF_SEMANTIC 规格：
```python
class DiffSemanticPayload(BaseModel):
    candidate_id: str
    baseline_request: dict      # 正常路径请求（如 userA 自己的资源）
    assertion_request: dict     # 试探路径请求（如 userA 请求 userB 资源）
    expectation: Literal["deny", "single_spend", "state_reject", "state_change"]
    state_readback: str | None = None   # 状态回读端点
```
（`request_oracle` 触发时，候选必须是 `VulnType` 中逻辑类：IDOR/AUTH_BYPASS/MFA_BYPASS/PRIVILEGE_ESCALATION 等，见 §5.4。）

---

## 5. ★ DIFF_SEMANTIC：逻辑漏洞的差分确认 Oracle（本文件核心增量）

### 5.1 为什么 echo/oob 对逻辑漏洞无效（reasoning-loop 的最大盲点）

reasoning-loop §1.3 说"OracleEngine 的 canary echo + OOB 已经够强，不重做新 oracle"。**这是错的**——对逻辑漏洞：

| 逻辑漏洞 | echo 探针问题 | oob 探针问题 |
|----------|--------------|--------------|
| 越权/IDOR | 无 payload 可回显（越权返回的他人数据不出现在响应外） | 无外带通道 |
| 竞态/双花 | 并发差无回显 | 无外带 |
| 状态机绕过 | 非法迁移无 echo | 无外带 |

**逻辑漏洞的确认探针是"差分语义"**：同场景两条请求的结构差异 + 状态回读。这正是循环发现"疑似越权 200"后、Oracle 能否**真正确认**的关键——**没有 DIFF_SEMANTIC，循环产出的逻辑类候选无法确认，循环价值落空。**

### 5.2 设计

**VulnType 扩展**（`domain/verification/models.py`，VulnType 枚举已有 IDOR/AUTH_BYPASS/MFA_BYPASS/PRIVILEGE_ESCALATION；新增确认语义标记）：
```python
@dataclass(frozen=True, slots=True)
class VerificationMethod:
    ...
    echo_enabled: bool = False        # 已存在（反射型）
    diff_semantic: bool = False       # 新增：逻辑类走差分确认

# registry.py 为逻辑类注册 diff_semantic=True：
VerificationMethod(vuln_type=VulnType.IDOR, default_n=3, diff_semantic=True),
VerificationMethod(vuln_type=VulnType.AUTH_BYPASS, default_n=3, diff_semantic=True),
VerificationMethod(vuln_type=VulnType.MFA_BYPASS, default_n=3, diff_semantic=True),
VerificationMethod(vuln_type=VulnType.PRIVILEGE_ESCALATION, default_n=3, diff_semantic=True),
# 其余保持 echo_enabled/diff_semantic=False（可 OOB 的走 OOB，反射的走 echo）
```

### 5.3 DiffSemanticVerifier（新，实现 OracleVerifier Protocol）

`infrastructure/oracle/diff_semantic_verifier.py::DiffSemanticVerifier`：
```python
class DiffSemanticVerifier:
    """实现 OracleVerifier：用确定性结构差异 + 状态回读确认逻辑漏洞。"""
    def __init__(self, scan_runner, canary, diff_runner, session=...): ...
    def verify(self, diff: DiffSemanticPayload) -> VerificationDecision:
        # 1. http 执行 baseline_request → 记录响应 A
        # 2. http 执行 assertion_request → 记录响应 B
        # 3. 确定性断言：
        #    expectation == "deny"      → B 应 4xx（B.status in {401,403,400}）
        #    expectation == "single_spend" → 状态回读断言（余额）
        #    expectation == "state_reject" → 状态机非法迁移应拒绝
        #    B 是非拒绝且与 A 结构同型（达同一资源/业务对象）→ CONFIRMED 信号
        # 4. state_readback 存在 → 回读断言辅助
        # 5. N/N 复现（跨 session 重复 N 次，同现有 oracle）
        ...
```

**关键**：DIFF_SEMANTIC 的确认是**确定性结构差异 + 状态回读**，**不是 LLM 判断**。LLM（LoopActionProposer）只提供"怀疑点 + 两条请求 + 期望"，Oracle 用确定性规则裁决。**LLM 永不标记 Confirmed**（边界不破）。

`verifier_factory.py` 增 `method_lookup` 分流：`diff_semantic=True` 的方法 → `DiffSemanticVerifier`；`echo_enabled=True` → echo 路径；`oob_window_seconds>0` → OOB。承接 Phase 3 3.1 的 method_lookup 改造。

### 5.4 对接 Loop

- `LoopContext.unconfirmed_candidates` 中，逻辑类（diff_semantic 方法）候选携带 `ProposedDiff`（即 DiffSemanticPayload 的雏形）
- 循环步 `request_oracle` 触发 `DiffSemanticVerifier.verify()` → 确定性 CONFIRMED/REFUTED
- **竞态类**（RACE，不在现有 14 类枚举）——见 §7 边界，暂不新增枚举，A/B 验证 IDOR/AUTH_BYPASS 后按需扩展

### 5.5 测试

- `tests/infrastructure/test_diff_semantic_verifier.py`：`expectation="deny"` 实际 200 且结构同基线 → CONFIRMED；实际 403 → REFUTED；N/N 分歧 → INCONCLUSIVE（升级人审）；state_readback 辅助
- `tests/oracle_ground_truth/`：构造可测 IDOR/状态机靶场（Juice Shop 的越权路径）

---

## 6. 循环终止策略（沿用 reasoning-loop，解耦 catalog floor）

终止策略沿用 reasoning-loop §5 的 `LoopTerminationPolicy`，但**修正一处语义冲突（问题 C）**：

### 6.1 解耦 catalog floor 与循环终止

reasoning-loop §5 第 346-348 行把 `require_catalog_floor_green=True` 设为 COMPLETED 前提。这会把循环变成"catalog 的搬砖工"。

**修正**：catalog floor 是 **Assessment 的门禁**（`CoverageService.enforce_gate`，已存在），不是循环的终止条件。循环在此之上跑增量：
- 循环初始化时**调一次 LLMPlanner 生成 catalog floor**（确定性底座，只 ADD）
- 循环终止 = **收敛 / 预算 / 无信号 / 紧急停止**（不把"catalog 全绿"当循环终止，而是当循环运行的先决基线）
- 循环跑完，Assessment 的覆盖门禁另行由 `CoverageService` 把关（循环不该越权判定"测够了"）

### 6.2 终止决策表（沿用，去掉 floor 耦合）

| 触发 | 终态 |
|------|------|
| 预算耗尽（步数 50 / 墙钟 1800s / token 200K） | BUDGET_EXHAUSTED |
| 连续 5 步无新 Observation 信号 | CONVERGED |
| 连续 3 步被三道门拒 | POLICY_BLOCKED |
| EmergencyStop | EMERGENCY_STOPPED |
| 用户手动 stop | STOPPED |

### 6.3 循环内可暂停/续跑（人审批介入，已拍板要做）

**动机**：循环是长时、烧 token 的过程，且 LLM 提议可能越出人预期。operator 需要能在循环运行中**暂停**（不问断完成也不硬杀），人审当前上下文后**续跑**，全程审计。这符合"人在回路"定位，也是控成本手段。

**状态扩展**（`LoopPhase` 新增）：
```python
PAUSED = "paused"       # operator 或确定性策略请求暂停
RESUMED = "resumed"     # 记录已从暂停恢复（中间态，不入稳态）
```
终态保留 §6.2 的 `BUDGET_EXHAUSTED / CONVERGED / POLICY_BLOCKED / EMERGENCY_STOPPED / STOPPED`；`PAUSED` 是**可中断态**（可暂停 → 续跑 → 循环继续），`STOPPED` 是**终态**（不可续跑）。

**暂停语义**：
- `pause(loop_id, actor, reason)`：仅**在两个 job 的边界**暂停（不中断正在执行的 loop job——执行已完成或取消该 job，但不破坏已产出的 Observation/CAS）。对齐现有的 `StepGate`（`orchestrator.py:_check_gate` 的 "paused" 语义）。
- 暂停时：不再签发新 Permit、不再调 LLM 提议、已产出的 Observation 保留。
- 暂停写入：`LoopState.phase = PAUSED` + `loop.paused` 审计事件（actor/reason/上下文快照）。

**续跑语义**：
- `resume(loop_id, actor)`：**人审后显式续跑**，需经审批标记（`approved_by` + 签名，对齐 `assessment.approve` 模式）。续跑可选参数 `modified_context`（operator 可裁剪/追加 LoopContext 提示，如"注意某已知发现"）。
- 续跑时：重新评估预算（暂停期间墙钟/成本不归零，但可配置"暂停期不计入墙钟"）——默认**墙钟暂停期不计**，token 预算暂停期本就无消耗。
- 续跑写入：`LoopState.phase = RESUMED` + `loop.resumed` 审计事件 + allowed_actions 恢复。

**guard**：
- 暂停/续跑都是 human-only（agent 调用 403，对齐 `signing_keys` rotate 门禁）。
- 续跑必须显式（不许"暂停后自动续跑"）——防止有 operator 忘了就没意义。
- 暂停申请有超时（默认 60s 无人确认则忽略暂停请求，循环继续；或配置成"请求暂停后等待直到确认"——默认后者：暂停请求必须得到确认才算暂停，否则循环继续推进，避免暂停请求无人理时循环空转）。

**多暂停安全**：
- 并发 pause 幂等（同一 loop 只暂停一次，第二次 pause 返回当前已 PAUSED）。
- 续跑前检查：若已 STOPPED/EMERGENCY_STOPPED，拒绝续跑。
- 暂停期间 EmergencyStop 仍优先（EMERGENCY_STOPPED 覆盖 PAUSED）。

**对接终止策略**：暂停/续跑次数设上限（默认 3 次暂停），超过则循环进入 `STOPPED`（防无限暂停消耗资源）。

**落地**：`domain/reasoning_loop/models.py` 加 `PAUSED/RESUMED` + `pause_attempts` 字段；`application/ports/loop_gates.py` 或 `ReasoningOrchestrator` 加 `pause()/resume()`；`interfaces/api/routers/loops.py` 加 `POST /loops/{id}/pause` + `POST /loops/{id}/resume`（human-only）；CLI `secopent loop pause/resume`。

**测试**（TDD）：
- `pause` 在两 job 边界暂停，不中断已产观察；暂停期间不签新 Permit
- `resume` 需 human 审批 + 签名；agent 403
- resume 后墙钟暂停期不计、token 预算续跑
- 第二次 pause 幂等；STOPPED 后 resume 拒绝；EmergencyStop 覆盖 PAUSED
- pause > 3 次 → STOPPED

---

## 7. 三道门 + 执行平面（沿用，收敛重复）

### 7.1 三道门（不变，Schema→Policy→Permit）

沿用 reasoning-loop §6：SchemaGate（Pydantic 严格 + tool_id 必须在可用能力清单）→ PolicyGate（复用 PolicyEngine+ScopeEnforcer）→ PermitGate（复用 ExecutionPermit，短时+nonce+签名）。三道全确定性，不靠 LLM 自律。

### 7.2 收敛：不新建 LoopJob 子类（问题 B）

reasoning-loop §7 定义 `LoopJob(Job)` 子类 + `job_type="loop_step"`。**弃用**：JobService 的租约/幂等/优先级逻辑不必为 Job 子类特判。循环步 = 普通 Job，在 `PlanStep` 或 job parameters 里带 loop 元数据（loop_id/step_id/proposed_action_digest/permit_id）即可。Job 已有 `idempotency_key`（同一 loop_step 幂等重执行）、`lease`、`attempt`。

---

## 8. 预算 + 降级 + 审计（沿用）

- 预算：沿用 reasoning-loop §10（步数 50 / token 200K / 墙钟 1800s / 单步 8K / 错误率连续 5 步）。暂停期墙钟不计（§6.3）。
- 降级链：LLM 提议不可用 → LLMPlanner 单次模式 → 仅 catalog floor。**降级必须写 `loop.fallback_used` 审计事件**（不静默，对应 Cybergym 教训）
- 审计：沿用 reasoning-loop §12.3 的 6 个事件类型（created/step_proposed/gate_rejected/step_executed/terminated/fallback_used）+ `loop.paused` / `loop.resumed`（§6.3）
- 持久化：`core_reasoning_loops` + `core_loop_steps`（表结构沿用 reasoning-loop §12.1，补 `phase=PAUSED` + `pause_attempts` 字段）；LoopContext CAS 化（context_hash 关联，不做全量进 step 行）

---

## 9. 协同矩阵（合并 + 过时修正）

| 现有模块 | 协同 |
|---|---|
| `LLMPlanner` | 循环初始化必调一次生成 catalog floor（不复调） |
| `PeerAgentService` + Strix/Shannon（**已接线**） | 循环可 `request_peer` 触发一轮；Strix 结果仍走归一化 + oracle |
| `AttackChain` / `ChainEngine` | 循环步填 `hypothesis_id` 挂到链；`PendingVerificationTask` 入 LoopContext |
| `OracleEngine` + canary + OOB | 常规候选走此（不变） |
| **★ `VerificationMethodRegistry` diff_semantic** | 逻辑类候选走 DIFF_SEMANTIC（新） |
| `PolicyEngine` + `ScopeEnforcer` | 第二道门完全复用 |
| `ExecutionPermit` | 第三道门完全复用 |
| `LogicTestGenerator` | 循环可提议触发（确定性派生）+ 用生成 case 去跑 |
| `Handbooks`（**8 份已落地**） | 注入 LoopContext（关键使能） |
| `AuditChain` | 每步写 `loop.*` 审计 |
| `EmergencyStop` | 立即冻结 + 撤未用 Permit + 保留 Observation |
| `CoverageService` | Assessment 门禁（循环不越权判定） |

---

## 10. 落地路径（在 v1.1-stable 门禁后，v0.7.x P4）

```
0.7.0  ReasoningOrchestrator 骨架 + LoopState/LoopStep + 终止策略 + 审计
       + Mock Proposer（随机 ProposeAction 过三道门）
0.7.1  LoopActionProposer + SchemaGate
0.7.2  PermitGate 接线 + JobService 调度（普通 Job，无子类）
0.7.3  LoopContext 摘要策略 + BudgetGate + 降级链
0.7.4  Handbooks 注入（已 8 份，直接用）
0.7.5  AttackChain 假设闭环接线
0.7.6  ★ DIFF_SEMANTIC Oracle（DiffSemanticVerifier + registry + verifier_factory 分流）
0.7.7  ★ 循环内暂停/续跑（loop.paused/resumed 状态 + human-only pause/resume API
       + 两 job 边界暂停 + 暂停期墙钟不计 + 暂停次数上限 3）
0.7.8  MCP/CLI/Web 入口
0.7.9  ★ A/B 验收（Juice Shop/crAPI/vulhub）
       · 对照组：仅 catalog
       · 实验组：catalog + ReasoningLoop + DIFF_SEMANTIC
       · 判据：oracle 确认增量 > 0 且单次成本 < 对照组 1.5x → 放行；否则冻结
```

**（总阶段 0.7.0-0.7.9，DW 8-12 周；暂停/续跑 0.7.7 是放行的治理必要条件之一。）**

**总工期**：8-11 周。DIFF_SEMANTIC（0.7.6）是**放行必要条件**——没有它，逻辑类候选无法确认，循环增量不可证明。

---

## 11. 边界与 YAGNI

- ❌ 不引入 Temporal/LangGraph/CrewAI（现有 Orchestrator+Job Lease 够）
- ❌ 不移植 Strix 多 agent 编排（循环留在 SecOpent 内）
- ❌ 不做 CoT 模板（决策范围宽，输出 Schema 严）
- ❌ 不做 LLM 自评"循环要不要继续"（终止全确定性）
- ❌ 不新建 LoopJob 子类（普通 Job + 元数据）
- ❌ 不新造基础 oracle（DIFF_SEMANTIC 是逻辑类的补充，不是替代 echo/oob）
- ❌ RACE 等新 VulnType 暂不扩展（先 A/B 验证 IDOR/AUTH_BYPASS）
- ❌ 不自动触发循环（默认手动 loop_create，A/B 验证价值后再考虑自动；含"暂停后自动续跑"——续跑必须显式人审）
- ❌ 不做 Cybergym 级评测设施
- ❌ LLM 不裁决、不改 scope、不签名、不确认

---

## 12. 评审 checklist（全部已拍板）

- [x] Loop 位置：Orchestrator 协作模式（已定，非新 daemon）
- [x] 三道门顺序：Schema→Policy→Permit（已定，不改）
- [x] 不新建 LoopJob 子类（已收敛）
- [x] catalog floor 与循环终止解耦（已收敛）
- [x] DIFF_SEMANTIC 合并进权威版（本次核心增量）
- [x] peer agent / Handbooks 过时事实已修正
- [x] Loop 触发时机：**默认手动 loop_create**（A/B 验证价值后再考虑自动）
- [x] 循环内可暂停/续跑：**要做**（人审批介入，见 §6.3 强制章节）
- [x] Loop 状态进 DB：**确认**（`core_reasoning_loops` + `core_loop_steps` 表）
- [x] 预算默认值：**50 步 / 1800s 墙钟 / 200K token**（可配）
- [x] A/B 判据阈值：**oracle 确认增量 > 0 且单次成本 < 对照组 1.5x** 才放行

---

## 13. 一句话总结

**SecOpent 缺的不是"全 LLM 决策"，而是"在已保 catalog 下限 + 已校验 oracle 的两条护城河之间，加一条『LLM 自驱的窄循环』"。循环必须遵守：LLM 只提议、确定性三道门、终止策略可审计——并补上逻辑漏洞的差分确认 DIFF_SEMANTIC，否则循环产出的逻辑类候选无确认落点，价值落空。**
