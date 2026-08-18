# ReasoningLoop 系统设计 —— 在 SecOpent 内部补齐「LLM 自驱测试循环」

> ⚠️ **本文件已并入权威版**: 详见 `sepcs/2026-08-19-reasoning-discoverer-unified-design.md`（含 DIFF_SEMANTIC 修正 + 过时事实修订）。冲突时以权威版为准。本文件保留作设计过程记录。

> **日期**: 2026-08-19
> **作者**: Hermes 调研 + 设计(用户思路主导)
> **状态**: 设计草案,待 brainstorming
> **关联 spec**: `2026-07-25-catalog-driven-agent-workbench-design.md`(主架构)、`2026-08-04-strix-shannon-layered-integration-design.md`(peer 集成)、`docs/architecture/attack-chain.md`(链引擎)
> **关联调研**: `cybergym-research/调研报告.md`(对照基准)、`docs/research/ai-pentest-landscape-2026-08.md`(竞品)

---

## 0. 动机与对照

### 0.1 当前 SecOpent 的能力地图(诚实的盘点)

| 能力 | 当前状态 |
|---|---|
| 已知 CVE / 漏洞类覆盖 | ✅ **强**:TestCatalog + 17 个四域 adapter(nuclei/nmap/Prowler/Trivy/kube-bench/checkov)+ CoverageMatrix(OWASP WSTG/CIS/PTES 映射)+ 覆盖率门禁 |
| 业务逻辑 5 类(跳步/乱序/重放/越界/不变量违反) | ✅ **强**:AppModel + LogicTestGenerator(纯函数确定性,signature 幂等) |
| 漏洞验证 | ✅ **强**:OracleEngine N/N + canary token + 自托管 Interactsh OOB + 14 类漏洞方法策展 |
| 漏洞链 | ✅ **中(P2b 已落地)**:AttackChain + ChainEngine + 三假设源(template/llm_proposal/peer_claim) + 补证闭环 + 复合严重度 |
| 响应式再规划 | ⚠️ **P0 骨架**:已有 Strix P2 / Shannon P3 接入设计,**实现计划未写、镜像 digest 空、`NullPeerAgentHarness` 降级中** |
| **测试循环内 LLM 自主决策** | ❌ **缺**:LLMPlanner 是单次调用从 catalog 挑 class、LogicTestGenerator 是纯函数从签名模型派生——**没有"边跑边推理边调整下一步"的循环** |

### 0.2 Cybergym 范式的关键启示(基于已调研的子代理报告)

> Cybergym(`https://github.com/sunblaze-ucb/cybergym`,UCB Sunblaze Lab,ICLR 2026,740★)是一个让 LLM agent 生成 PoC 文件、并用真实漏洞容器跑出来验证 crash 的端到端 benchmark。**LLM 只管"猜输入",成功与否由 vul 镜像里进程 exit_code != 0 且 fix 镜像里同样 PoC 不崩这个二元 oracle 决定。**

**关键事实**(从子代理报告抽取,与 SecOpent 对照):

| 维度 | Cybergym | SecOpent(差异定位) |
|---|---|---|
| **循环主体** | **不在 agent 内**,而是 FastAPI server 的 `(agent_id, task_id, poc_hash)` 去重 + 每次重跑容器 | SecOpent 没有等价调度器;循环要**建在应用层** |
| **难度分级** | **实际 4 档**(L0-L3,不是 3 档),方式是"给 agent 多少上下文文件":源码 / +描述 / +崩溃输出 / +patch.diff | SecOpent 已有等价概念:有/无 API 文档(OpenAPI vs 流量录制)、人校验签名 vs 未签 |
| **LLM 决策范围** | **完全开放**——无 prompt 模板、无强制循环、agent 自己决定读什么跑什么 | SecOpent 现有 LLMPlanner 已限制 LLM "只能 ADD catalog class 不能减"——这更窄、更可控 |
| **Oracle 形式** | 二元 exit_code 判定(`!=0 && !=137`) | SecOpent 的 oracle N/N + canary echo + OOB 回调是**更强**的判定(精确回显 token 而非仅看进程崩) |
| **评分** | any-of / final-submission 二选 | SecOpent 是 per-Assessment 全面覆盖门禁(0 未验证) |
| **数据泄漏防御** | Squid 白名单代理 + 删 `.git`/`/tmp/poc` + mask_map.json 混淆 task ID | SecOpent 已有 Secret Store + 远程模型数据分级 + Scoped Egress |
| **致命缺陷(值得避)** | ①超时(137→300)也算成功,可被 hang 进程刷分;②API key 默认公开;③数据全在 HuggingFace,LLM 训练时见过;④submit.sh 暴露 server URL = 任何人都能跑任意输入;⑤只测单文件 PoC,不测多步链式利用 | SecOpent 已避免 ②③④(密钥管理 + 私有评估 + ScopeEnforcer),但 ①⑤ 是**循环设计的关键警示** |

### 0.3 关键设计修正(对比初版方案)

调研后修正三点:

1. **"循环"不必放在 agent 容器内**:Cybergym 用 HTTP server 做循环调度,SecOpent 已有 Orchestrator + Job Lease,直接在此之上扩**不是为新循环再造一个 daemon**
2. **"难度"是 context 维度,不是流程维度**:SecOpent 的"白盒/灰盒/黑盒"已是 context 维度,**不要做"多档流程分支"**——这是 Cybergym 用 4 档的真正动机(LLM 评测可比性),但生产工具不需要
3. **Oracle 必须严格**:**禁止**"超时=成功"这类宽松判定——SecOpent 的 canary echo 已经足够强,新循环必须复用,不引入新弱 oracle

---

## 1. 设计目标与边界

### 1.1 目标

在**已保 catalog 下限 + 已校验 oracle 的两条护城河之间**,补一条「**LLM 自驱的窄循环**」,让 SecOpent 能发现"已知模式之外的逻辑漏洞"——主要场景:
- **未知攻击面探测**:LLM 看到当前 Observation 后,提议"再跑某个相邻端点/某个变形 payload"
- **假设驱动补证**:LLM 看到 AttackChain 假设源提出"A 能到 B",自动提议验证 A→B 路径
- **未确认候选消化**:LLM 看到有 INCONCLUSIVE 的 Candidate,提议"换一种 oracle 方式再验"

### 1.2 不破的边界(对齐现有 LLM 边界 §12.10)

| 不破原则 | 落地方式 |
|---|---|
| LLM 不裁决 | 循环内 LLM 只**生成下一步行动候选**,经三道门(Schema/Policy/Permit)才真执行;**任何 action 必须经过现有 Permit 体系** |
| LLM 不减 catalog 下限 | 循环初始化时调一次 `LLMPlanner` 生成 catalog floor;循环只 ADD,**必修类全绿是循环硬终止条件** |
| Oracle 独占裁决 | 所有 Observation 走同一 oracle 流水线(N/N + canary + OOB);**不引入新 oracle 形态** |
| Per-Assessment 快照 | 循环每步写入 AuditEvent,关联 assessment_id;回放可重建 |
| LLM 不审 scope | 三道门第 2 道走现有 ScopeEnforcer + PolicyEngine,**完全确定性** |
| LLM 不可用 = 不挂 | 预算耗尽 / schema 失败 / EmergencyStop → 立刻冻结循环,跑纯 catalog 路径 |

### 1.3 不做(对齐 §11 YAGNI 风格)

- ❌ **不引入 Temporal / LangGraph / CrewAI**——现有 Orchestrator + Job Lease 够用
- ❌ **不移植 Strix 多 agent 编排机器**——违背"循环留在 SecOpent 内"原则
- ❌ **不重做新的 oracle**——canary echo + OOB 已经够强
- ❌ **不做 CoT 模板**——LLM 决策范围要宽,但**输出 Schema 必须严**(Pydantic 校验),把"严"压在出口而不是入口
- ❌ **不做 LLM 自评"循环要不要继续"**——终止策略全确定性,见 §5

---

## 2. 总体架构:在现有五层上的增量

```
┌─────────────────── 不变 ───────────────────┐
│ 接口层 (MCP/CLI/Web/OpenAPI)                  │ ← 新增 loop_create / loop_status / loop_stop
├──────────────────────────────────────────────┤
│ 控制平面 - 编排                                │
│  ┌─ Planner (确定性 DAG, 不变) ─┐             │
│  ├─ Orchestrator (Job Lease, 不变) ──────────┤ ← 新增 LoopJob 类型,可被调度
│  ├─ PolicyEngine + ScopeEnforcer (不变) ─────┤
│  ├─ ★ ReasoningLoopOrchestrator (新增) ──────┤ ← 循环主体,见 §3
│  ├─ LoopActionProposer (LLM, propose-only) ──┤ ← 新增,见 §4
│  ├─ AttackChainEngine (P2b 已落) ────────────┤ ← 假设闭环驱动器
│  └─ Quality Gates (不变)                     │
├──────────────────────────────────────────────┤
│ 控制平面 - 应用服务                            │
│  Project/Scope/Assessment/Plan/Approval/      │
│  AssetGraph/Finding/Evidence/Report/Retest/   │
│  Audit (全部不变)                              │
├──────────────────────────────────────────────┤
│ 知识层 (TestCatalog/CoverageMatrix/AppModel/  │
│  LogicTestGenerator/CatalogTestCase/Handbooks/ │
│  VerificationMethodRegistry/Intel Store)      │
│  ★ Handbooks 注入 LoopContext 是 LLM 推理素材  │ ← 复用 Strix skills 转译
├──────────────────────────────────────────────┤
│ 执行平面 (Worker / SubprocessExecutor / Case  │
│  Engine / Tool Containers / Scoped Egress /   │
│  Permit / PeerAgentService+Strix)             │
│  ← 新增 LoopStepRun 类型,执行单次 LLM 提议行动 │
├──────────────────────────────────────────────┤
│ 基础设施 (DB/CAS/Secret Store/Signing/        │
│  Update Bundles/Audit Hash Chain/Telemetry)   │
│  ← 新增 loop_steps 表 + LoopState CAS 对象    │
└──────────────────────────────────────────────┘
```

**位置关键**:ReasoningLoopOrchestrator 是**控制平面-编排**的应用服务,**不是新层、不是新 daemon**——它是 Orchestrator 的"协作模式",沿用 Job Lease 机制。

---

## 3. 核心数据模型

### 3.1 LoopState(循环实例状态)

```python
# src/secopent/domain/reasoning_loop/models.py
@dataclass(frozen=True)
class LoopId:
    """循环实例 ID,对应一次 Assessment 内可挂多个 Loop"""
    value: str

class LoopPhase(str, Enum):
    """循环阶段(确定性,LLM 不可写)"""
    INITIALIZING = "initializing"       # 调 LLMPlanner 生成底座
    RUNNING = "running"                 # 正常推进
    CONVERGED = "converged"             # 启发式收敛(无新信号)
    CATALOG_FLOOR_DONE = "floor_done"  # catalog 必修类全绿(可继续也可终止)
    BUDGET_EXHAUSTED = "budget_exhausted"  # 预算耗尽
    POLICY_BLOCKED = "policy_blocked"   # 三道门连续拒绝
    EMERGENCY_STOPPED = "emergency_stopped"
    COMPLETED = "completed"             # 正常结束

@dataclass(frozen=True)
class LoopState:
    """循环当前快照,所有字段确定性可序列化"""
    loop_id: LoopId
    assessment_id: AssessmentId
    phase: LoopPhase
    step_count: int                     # 已执行步数
    started_at: datetime
    last_step_at: datetime | None
    budget: LoopBudget                  # 剩余预算
    context_hash: str                   # 当前 LoopContext 的 content hash(可重放锚)
    catalog_required_remaining: set[str]  # 必修类还差哪些
    catalog_required_executed: set[str]    # 已跑过的必修类
    consecutive_no_signal: int          # 连续无新信号步数
    consecutive_policy_rejected: int    # 连续被门拒绝步数
```

### 3.2 LoopStep(循环步,审计粒度)

```python
@dataclass(frozen=True)
class LoopStep:
    """循环单步的完整快照(可重放、可审计)"""
    step_id: str                        # UUID
    loop_id: LoopId
    step_number: int
    timestamp: datetime

    # 提议侧(propose)
    context_hash_before: str            # 提议前 LoopContext 的 hash
    proposed_action: ProposeAction      # LLM 输出,见 §4
    propose_tokens_used: int
    propose_latency_ms: int
    propose_rationale: str              # LLM 给出的理由(进审计)

    # 三道门
    schema_check_passed: bool           # Pydantic 校验
    policy_decision: PolicyDecision     # "allow" / "deny: <reason>"
    permit_id: str | None               # 短时 Permit,签名

    # 执行侧
    tool_or_case_id: str                # nuclei template / case id / nmap script
    execution_result: Observation       # 跑出来的观察
    evidence_refs: list[str]            # CAS 路径

    # 反馈侧
    observation_signals: list[str]      # 新信号指纹(如新发现的 endpoint / 状态转移)
    catalog_class_matched: set[str]     # 这步命中了哪些 catalog class
    oracle_progressed: bool             # 是否触发 oracle 验证新候选

    # 元数据
    correlation_id: str                 # 与现有 audit_chain 关联
```

### 3.3 ProposeAction(LLM 输出 Schema,严格)

```python
class ProposeAction(BaseModel):
    """LLM 提议循环下一步行动的严格 Schema,Pydantic 校验"""
    # 行动类型(枚举,不可自由文字)
    action_type: Literal[
        "run_tool",        # 跑工具(必须填 tool_id)
        "run_case",        # 跑 case(必须填 case_id)
        "request_peer",    # 让 Strix/Shannon 来一轮(必须填 peer_name + instruction)
        "request_oracle",  # 对某个 Candidate 触发 oracle 验证(必须填 candidate_id)
        "request_chain",   # 让 ChainEngine 评估某条假设(必须填 hypothesis_id)
        "abort_step",      # 提议立即终止(经三道门后由确定性策略裁决是否真终止)
    ]

    # 行动载荷(每类型单独 Schema 校验,见下)
    payload: dict[str, Any]             # action_type-specific 子 Schema

    # 关联
    hypothesis_id: str | None = None    # 关联到 AttackChain 假设
    catalog_class_targeted: str | None  # 关联到 TestCatalog

    # 理由(给审计/报告用,不做 LLM 裁决依据)
    rationale: str                      # 50-500 字,why this action now

    # 自评置信度(给确定性层参考,不是裁决依据)
    confidence: float                   # 0.0-1.0,仅作策略辅助
```

每种 action_type 对应子 Schema(例:`run_tool` 必须有 `tool_id + parameters: dict[str, ToolParameter]`,参数必须命中 tool manifest 的 JSON Schema;`request_peer` 必须有 `peer_name` 在 PeerAgentRegistry + `instruction` 长度受预算控制)。

### 3.4 LoopContext(LLM 提议时的固定结构输入)

```python
@dataclass(frozen=True)
class LoopContext:
    """LLM 提议时的输入,严格结构化、可审计、可压缩"""
    # 资产视图(只相关 N 跳,防 prompt 膨胀)
    asset_subgraph: AssetSubgraph      # 现有 domain 层已支持子图提取

    # 最近 Observation(摘要 + 关键样本)
    recent_observations: tuple[ObservationSummary, ...]  # 最近 10 步,含原始 pointer
    observation_token_count: int       # 用于 budget 计算

    # 覆盖状态(catalog 必修类是否全绿)
    catalog_already_executed: frozenset[str]
    catalog_still_required: frozenset[str]
    catalog_floor_progress: float      # 0.0-1.0

    # 已有发现
    unconfirmed_candidates: tuple[CandidateFinding, ...]   # 待 oracle 验证
    confirmed_findings_recent: tuple[ConfirmedFinding, ...]  # 最近确认
    chain_hypotheses_pending: tuple[AttackHypothesis, ...]   # 待补证的链假设

    # 能力清单(Schema 化,LLM 只能从这挑)
    available_tools: AvailableCapabilities
    available_cases: AvailableCapabilities
    available_peers: tuple[PeerAgentDescriptor, ...]   # Strix/Shannon 注册表

    # 预算
    budget_remaining: LoopBudgetSnapshot

    # 上下文元信息
    loop_step: int
    max_steps: int
    elapsed_seconds: int
```

---

## 4. 提议层:LoopActionProposer(skill 边界严)

### 4.1 与 Strix 的本质区别

| 维度 | Strix peer | ReasoningLoop |
|---|---|---|
| 决策位置 | Strix 容器内部(我们看不到决策过程) | SecOpent 应用层(**全程审计**) |
| 决策范围 | 整个测试流程(侦察→利用→报告) | **只决策"下一步行动"**(侦察/验证已在 catalog 跑过) |
| 循环主体 | Strix 内部 Graph of Agents | Orchestrator 的协作模式,**沿用 Job Lease** |
| 输出 | 漏洞报告(经 parser 归一化) | ProposeAction(JSON Schema,经三道门) |
| 回退 | Strix 挂了换 Shannon | LoopActionProposer 不可用 → 冻结循环 → 跑纯 catalog |
| 治理 | Trust level `adopted_external_agent` | **完全在 SecOpent 内**,不走 peer trust |

**核心**:LoopActionProposer 是**窄接口**,只做"循环里下一步该怎么走"这一件事;不做"整段渗透"。把"侦察"留给 catalog + adapter,把"利用"留给 Strix(通过 ProposeAction.request_peer 触发),把"验证"留给 oracle——LLM 只做**串联与决策**。

### 4.2 Handbooks 注入(关键使能)

**现状**:SecOpent 的知识层已规划 Handbooks(来自 Strix skills Apache-2.0 转译,见 `docs/architecture/knowledge-layer.md` 第 21 行)。**没有 Handbooks 的循环 = 裸 LLM,效果差**。

**做法**:
- LoopContext 的 `available_tools` 和 `available_cases` 不只是冷冰冰的 Schema,**附带 Handbook 摘要**:`Handbook{attack_surface, recon_endpoints, payload_classes, verification_hint}`
- LLM 提议时能看到"这类漏洞一般怎么打、可用什么 payload、怎么验证"
- Handbooks 由 P1a 知识移植产生,版本化入 KnowledgeLayer;循环消费时取当前激活版本

### 4.3 提议 Prompt 结构

```
[SYSTEM]
You are a reasoning loop proposer for an authorized penetration test.
You see structured context (assets, observations, catalog coverage, hypotheses).
You output ONE ProposeAction (JSON Schema strict).
You NEVER decide scope, NEVER sign, NEVER confirm findings.
You propose; deterministic gates and oracle decide.

[CONTEXT]
{LoopContext JSON 序列化,定长字段 + 变长 Observation 摘要}

[HINTS] (从 Handbooks 提取的相关条目)
{top-k Handbook entries by asset class and current observation keywords}

[BUDGET]
{remaining budget, step count, max steps}

[HISTORY] (最近 5 步的 step_id + action_type + outcome,用于避免重复)
{...}

[OUTPUT] (strict JSON Schema)
ProposeAction { ... }
```

### 4.4 失败降级链

```
LoopActionProposer.complete()
  ├─ BackendAvailable + JSON valid → return ProposeAction
  ├─ JSON invalid → 单步 retry 一次(轻微重 prompt),再失败 → 拒绝(计 1 步)
  ├─ Schema 不匹配(枚举外/Pydantic fail) → 拒绝(计 1 步)
  ├─ Backend unavailable → 标记 unavailable,触发降级
  └─ Token 超限 → 标记 exhausted

降级链(确定性策略):
  ├─ 偶发失败(<3 步) → 重试
  ├─ 连续失败 ≥3 步 → 触发 §5 终止策略 "POLICY_BLOCKED"
  └─ Backend 长期不可用 → 立即冻结循环,转纯 catalog 路径
```

---

## 5. 终止策略:全确定性,LLM 不可写

```python
# src/secopent/domain/reasoning_loop/policies.py
@dataclass(frozen=True)
class LoopTerminationPolicy:
    """循环终止/收敛策略,全部确定性规则"""
    max_steps: int = 50                       # 循环总步上限
    max_wall_clock_seconds: int = 1800        # 30 分钟
    max_total_tokens: int = 200_000           # 循环总 token 上限

    no_signal_streak_to_converge: int = 5     # 连续 N 步无新信号 → CONVERGED
    policy_rejected_streak_to_stop: int = 3   # 连续 N 步被门拒 → POLICY_BLOCKED

    require_catalog_floor_green: bool = True  # 必须 floor 全绿才能 COMPLETED

    require_min_confirmed: int = 0            # 业务侧可配,最低要求确认数
```

**终止决策表**:

| 触发条件 | 终态 | 后续行为 |
|---|---|---|
| catalog 必修类全绿 AND 满足其他终止条件 | `COMPLETED` | 正常结束,生成 LoopReport 段 |
| catalog 必修类全绿 AND 仍有 budget AND 有未消化候选 | `CATALOG_FLOOR_DONE` | 转"消化 INCONCLUSIVE 候选"模式(降步速,可继续) |
| 步数 / 墙钟 / token 达上限 | `BUDGET_EXHAUSTED` | 强制结束,跑纯 catalog 路径补未完成必修 |
| 连续 5 步无新 Observation 信号 | `CONVERGED` | 启发式收敛,正常结束 |
| 连续 3 步被三道门拒 | `POLICY_BLOCKED` | 异常结束,审计标记 `loop:policy_blocked` |
| `EmergencyStop` 触发 | `EMERGENCY_STOPPED` | 立即停所有 LoopJob,撤销未用 Permit |

**关键约束**(对应 Cybergym 教训):
- ✅ **不允许"超时=成功"**(对应 Cybergym `_post_process_result` 把 exit 137→300 的错误):循环里任何超时都是 BUDGET_EXHAUSTED,不是成功信号
- ✅ **不允许"any-of"评分**:每步必须独立 verdict,不允许"循环跑完只要找到 N 个就算成功"
- ✅ **不允许"循环挂了就改 deterministic fallback"作为正常路径**:fallback 必须审计可见(写 `loop:fallback_used` 事件)

---

## 6. 三道门:全确定性,不靠 LLM 自律

```python
# src/secopent/application/ports/loop_gates.py
class LoopActionGate(Protocol):
    """三道门接口,所有门都返回确定性 verdict + reason"""
    def check(self, action: ProposeAction, context: LoopContext) -> GateVerdict: ...

@dataclass(frozen=True)
class GateVerdict:
    passed: bool
    reason: str                              # 失败原因(给审计/给 LLM 重 prompt)
    deny_code: str | None                    # 结构化拒绝码
    # 当 passed=True 时填充:
    permit_id: str | None                    # 短时签名 Permit
    permit_ttl_seconds: int | None
```

### 6.1 第一道:Schema Gate(纯确定性)

```python
class SchemaGate:
    """Pydantic 严格校验 + JSON Schema 二次校验"""
    def check(self, action, context):
        # 1. Pydantic model_validate(严格模式,任何 extra field 直接拒)
        # 2. payload 子 Schema 校验(action_type → sub-schema)
        # 3. tool_id/case_id 必须在 AvailableCapabilities 中存在
        # 4. parameters 必须命中 tool/case manifest 的 JSON Schema
        # 5. rationale 长度 50-500 字
        # 6. confidence ∈ [0, 1]
        ...
```

### 6.2 第二道:Policy Gate(复用现有 PolicyEngine)

```python
class PolicyGate:
    """复用 domain/policy + ScopeEnforcer,完全不变"""
    def check(self, action, context):
        # 把 ProposeAction 翻译为 PlanStep-like 对象,过 PolicyEngine
        # - scope 校验(目标必须在 in-scope)
        # - risk cap(超过当前 grant 风险等级 → 拒)
        # - capability(目标工具是否在注册表)
        # - budget(单步 token / cost)
        # - time window
        # - Destructive 永拒
        ...
```

**关键**:这一道不写新逻辑,**完全复用** `domain/policy/policy_engine.py`。

### 6.3 第三道:Permit Gate(复用现有 ExecutionPermit)

```python
class PermitGate:
    """签发短时、签名、带 nonce 的 Permit,绑定 Worker/Scope/Action"""
    def check(self, action, context):
        # 与现有 ExecutionPermit 同款,见 domain/permits/
        # nonce + 15 分钟 TTL + Ed25519 签 digest(action + worker + scope)
        # 拒签条件:permit 已存在/未撤销但目标不一致 → 拒
        ...
```

---

## 7. 执行平面:循环步 = LoopJob(沿用 Job Lease)

```python
# 循环步执行沿用 Orchestrator + JobService
@dataclass(frozen=True)
class LoopJob(Job):
    """循环步作为一类特殊 Job,经 JobService 调度"""
    job_type: Literal["loop_step"] = "loop_step"
    loop_id: LoopId
    step_id: str
    proposed_action_digest: str             # 提议的 SHA256(用于追溯)
    permit_id: str                          # 已签的 Permit
    tool_or_case_id: str
    parameters: dict[str, Any]
```

**关键**:循环步**不绕过 JobService**——经同一 Worker Agent / SubprocessExecutor / Scoped Egress 执行,**所有沙箱/seccomp/netns/审计不变**。

```python
# Orchestrator 增加循环感知
class Orchestrator:
    def execute_ready(self, owner, now) -> tuple[Job]:
        jobs = self._jobs.ready_jobs(owner, now)
        # LoopJob 优先(P0 编排策略)——循环步小、调度密
        return sorted(jobs, key=lambda j: (0 if isinstance(j, LoopJob) else 1, j.priority))
```

---

## 8. 反馈环:Observation → LoopContext 更新

```python
class LoopFeedback:
    """循环步执行后,更新 LoopContext 的策略"""
    def update(self, state: LoopState, step: LoopStep) -> LoopContext:
        # 1. 把新 Observation 入 recent_observations(滚动摘要)
        # 2. 检测信号指纹(新 endpoint / 状态转移 / 错误模式)→ observation_signals
        # 3. 若命中 catalog class id → catalog_already_executed +=
        # 4. 若新 CandidateFinding 入 unconfirmed_candidates
        # 5. 若 oracle 推进(找到 CONFIRMED)→ confirmed_findings_recent
        # 6. context_hash = sha256(序列化后的 LoopContext)→ 用于重放锚
        # 7. token 预算扣除
```

**Observation 摘要策略**(关键工程问题):
- 直接塞全文 → token 爆炸
- 仅保留 fingerprint + path → LLM 推理无上下文
- **推荐**:滚动摘要 + 关键样本完整保留

```python
@dataclass(frozen=True)
class ObservationSummary:
    observation_id: str
    tool_or_case_id: str
    target_digest: str                     # 目标 sha256,不暴露原始 URL/PII
    key_signals: tuple[str, ...]           # 新 endpoint / 状态 / 错误指纹
    confidence: float
    has_full_text: bool                    # 完整内容是否仍可取
    full_text_ref: str | None              # CAS 路径
    token_estimate: int                    # 摘要本身的 token 数
```

**压缩策略**:
- 最近 5 步保留完整摘要(信号级)
- 5-20 步保留关键信号 + 路径
- >20 步只保留 fingerprint(LLM 看不到细节,但能看到"曾经跑过什么")

---

## 9. 与现有模块的协同矩阵

| 现有模块 | 协同方式 |
|---|---|
| `LLMPlanner`(v0.6.4) | **循环初始化必调**——生成 catalog floor;循环里**不再调**,只复用结果 |
| `PeerAgentService` + Strix(设计中) | 循环可提议 `request_peer`,转 Strix 跑一轮;Strix 结果仍走归一化 + oracle |
| `AttackChain` 假设源 | LLM 提议可填 `hypothesis_id` 把行动挂到链;ChainEngine 评估后产生新 PendingVerificationTask,**Task 进入 LoopContext 让 LLM 看到"还要补证什么"** |
| `ChainEngine` | 循环每步检查未确认环,把"补证"作为高优先级行动建议(不强制 LLM 选) |
| `OracleEngine` N/N + canary + OOB | 循环步完成后,触发 candidate → oracle 流程(已有) |
| `PolicyEngine` + `ScopeEnforcer` | 第二道门**完全复用** |
| `ExecutionPermit` | 第三道门**完全复用** |
| `LogicTestGenerator` | 循环可提议"用 AppModel 派生新测试",把"生成"动作走 LogicTestGenerator(确定性),然后**再让循环用生成的 case 去跑** |
| `KnowledgeLayer` Handbooks(P1a 准备中) | **关键使能**:Handbook 摘要注入 LoopContext |
| `AuditChain` | 循环每步写 `loop.step` 审计(继承现有 hash chain) |
| `EmergencyStop` | 立即冻结循环,撤销未用 Permit,保留已收集 Observation |
| `DriftDetector` | 循环跑完自动触发 DriftDetector(已是 CI 用法) |
| `EngagementGrant` | 循环每步必须过 grant 校验(PolicyGate 已经做) |
| `CoverageMatrix` | 终止条件硬要求 `catalog_floor_green=True` |

---

## 10. 提议预算与降级链

### 10.1 预算维度

| 维度 | 默认 | 超限行为 |
|---|---|---|
| 循环总步数 | 50 | BUDGET_EXHAUSTED → 终止 |
| 循环总 token(LLM only) | 200K | 同上 |
| 循环墙钟 | 1800s(30min) | 同上 |
| 单步 token | 8K | 单步被拒,计 1 步 |
| 错误率(连续 5 步 schema 不合格) | -- | POLICY_BLOCKED |
| 单次 LLM 失败率(>20%) | -- | 触发降级 |

### 10.2 降级链

```
ReasoningLoop 可用
  ├─ LLM 提议可用 → 正常循环
  ├─ LLM 偶尔失败(单步 <3) → 单步重试
  ├─ LLM 连续失败 ≥3 → POLICY_BLOCKED 终止
  └─ LLM Backend 长期不可用 → 立即冻结循环,转纯 catalog 路径

LLM Backend 状态:
  ├─ 本地 Ollama/vLLM 7B 不可用 → 停循环,仅 deterministic
  ├─ 远程 Claude/GPT 不可用 → 降级本地(若可用)
  └─ 远程超 500K/天 token 预算 → 降级本地 → 全不可用 → 停循环
```

**对接 §12.11** 已有 LLM 运营约束:循环不破"远程超限降级本地,本地不可用停 agent 编排,仅留确定性 catalog 执行"。

---

## 11. 接口层增量(MCP/Web/CLI)

### 11.1 新增 MCP 工具

| 工具 | 谁能调 | 作用 |
|---|---|---|
| `loop_create` | human / agent | 创建 ReasoningLoop,关联 assessment_id,可选 risk_cap |
| `loop_status` | 任意 | 查询 LoopState(phase / step_count / budget / signals) |
| `loop_step_propose` | 仅内部(LoopActionProposer) | 调 LLM 提议(不暴露给用户) |
| `loop_step_execute` | 仅 Orchestrator | 把通过的 step 入 JobService(不暴露) |
| `loop_stop` | human / EmergencyStop | 显式停循环,审计 |
| `loop_history` | 任意(只读) | 查 LoopStep 历史(可重放) |

### 11.2 CLI/Web 入口(供人审)

```bash
secopent loop create --assessment-id <id> --risk-cap active
secopent loop status --loop-id <id>
secopent loop stop --loop-id <id> --reason "..."
secopent loop history --loop-id <id> --format json
```

### 11.3 Web Case Studio

- 新增 "Reasoning Loop" 标签页(类似 Findings / Coverage)
- 实时显示 LoopState(phase、step_count、budget 进度条、信号趋势)
- LoopStep 列表(可展开看每步的 proposed_action / 三道门 verdict / observation)
- "Stop Loop" 按钮(经 audit + 写 audit event)

---

## 12. 数据模型与持久化

### 12.1 新增表(alembic 迁移)

```sql
-- 循环实例
CREATE TABLE core_reasoning_loops (
    loop_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    phase TEXT NOT NULL,                 -- LoopPhase 枚举
    policy_snapshot TEXT NOT NULL,        -- 终止策略的 sha256(回放一致性)
    context_hash TEXT NOT NULL,           -- 当前 LoopContext 的 hash
    started_at TIMESTAMP NOT NULL,
    ended_at TIMESTAMP,
    budget_state TEXT,                    -- JSON 序列化 LoopBudget
    catalog_required_remaining TEXT,      -- JSON set
    catalog_required_executed TEXT,       -- JSON set
    correlation_id TEXT NOT NULL,         -- 与 audit_chain 关联
    UNIQUE(assessment_id, loop_id),
    FOREIGN KEY (assessment_id) REFERENCES core_assessments(assessment_id)
);

-- 循环步(粒度审计,可重放)
CREATE TABLE core_loop_steps (
    step_id TEXT PRIMARY KEY,
    loop_id TEXT NOT NULL,
    step_number INTEGER NOT NULL,
    timestamp TIMESTAMP NOT NULL,

    context_hash_before TEXT NOT NULL,
    proposed_action TEXT NOT NULL,        -- JSON 序列化 ProposeAction
    propose_tokens_used INTEGER NOT NULL,
    propose_latency_ms INTEGER NOT NULL,
    propose_rationale TEXT,

    schema_check_passed BOOLEAN NOT NULL,
    policy_decision TEXT NOT NULL,        -- JSON PolicyDecision
    permit_id TEXT,

    tool_or_case_id TEXT,
    execution_result TEXT,                -- JSON Observation
    evidence_refs TEXT,                   -- JSON list[str]

    observation_signals TEXT,             -- JSON list[str]
    catalog_class_matched TEXT,           -- JSON set
    oracle_progressed BOOLEAN NOT NULL DEFAULT FALSE,

    correlation_id TEXT NOT NULL,
    UNIQUE(loop_id, step_number),
    FOREIGN KEY (loop_id) REFERENCES core_reasoning_loops(loop_id)
);

CREATE INDEX idx_loop_steps_loop ON core_loop_steps(loop_id, step_number);
CREATE INDEX idx_loops_assessment ON core_reasoning_loops(assessment_id, phase);
```

### 12.2 CAS 对象

| 类型 | 内容 |
|---|---|
| `loop_context/<loop_id>/<context_hash>.json` | LoopContext 完整序列化(可重放) |
| `loop_propose/<step_id>/<propose_hash>.json` | LLM 完整 prompt + response(审计 / 可解释) |
| `loop_observation/<step_id>/<obs_id>.json` | 单步 Observation 完整内容(超摘要上限时存档) |

### 12.3 AuditEvent 增量

新增事件类型,继承现有 AuditChain:

| event_type | 字段 |
|---|---|
| `loop.created` | loop_id, assessment_id, grant_id, policy_snapshot |
| `loop.step_proposed` | step_id, action_type, rationale_hash |
| `loop.gate_rejected` | step_id, gate_name (schema/policy/permit), deny_code, reason |
| `loop.step_executed` | step_id, tool_or_case_id, permit_id, observation_ids |
| `loop.terminated` | loop_id, final_phase, total_steps, total_tokens, reason |
| `loop.fallback_used` | loop_id, fallback_type (no_llm_backend / policy_blocked) |

**关键**:`loop.fallback_used` 必须审计——让"循环挂了 → 自动降级 catalog"这件事**永远可见**,不能静默发生(对应 Cybergym "any-of 被 brute-force 污染"教训的逆用)。

---

## 13. 阶段落地:不抢 v1.1-stable 门禁

```
v1.1-stable (硬门禁 §3.2) 必须先打通
  ↓
v0.7.0 P4 阶段(可在 v1.1-stable 后启动):
  0.7.0  ReasoningLoop 骨架(domain 模型 + 终止策略 + AuditEvent,无 LLM)
         + Mock Proposer(随机生成 ProposeAction 通过三道门)
         + 单元/集成测试
         工期:5-7 天

  0.7.1  LoopActionProposer + Schema Gate(Pydantic 严格校验)
         + 三道门骨架(Schema → Policy → Permit,前两者)
         工期:3-5 天

  0.7.2  Permit Gate 接线 + JobService 调度 LoopJob
         + Orchestrator 优先级(LoopJob 优先)
         工期:3-5 天

  0.7.3  LoopContext 摘要策略 + BudgetGate + 降级链
         + Observation 摘要压缩(最近 5 完整 / 5-20 信号 / >20 fingerprint)
         工期:5-7 天

  0.7.4  Handbooks 注入(衔接 P1a 知识移植)
         + LoopContext 的 available_tools/cases 附带 Handbook 摘要
         工期:3-5 天

  0.7.5  AttackChain 假设闭环接线
         + LoopStep.hypothesis_id 关联 ChainEngine
         + ChainEngine 产生的 PendingVerificationTask 进入 LoopContext
         工期:3-5 天

  0.7.6  MCP / CLI / Web 入口
         + loop_create / loop_status / loop_stop / loop_history
         工期:3-5 天

  0.7.7  ★ A/B 验收(沿用 Strix P2 范式)
         + 靶场:Juice Shop / crAPI / vulhub
         + 对照组:仅 catalog
         + 实验组:catalog + ReasoningLoop
         + 指标:oracle 确认增量 / 误报率 / 单次总成本 / 用户审批次数
         + 判据:增量 > 0 且成本可接受 → 放行;否则冻结(同 Strix P3 决策)
         工期:1-2 周
```

**总工期估算**:6-10 周,符合 v1.1-stable 后的 P4 节奏。

**关键依赖**:
- 必须先有 P1a 知识移植(Handbooks 可用)
- 必须先有 P2 Strix peer(可选,但建议)— 否则循环只能跑 catalog + tools,失去 Strix 自驱利用的补强
- v1.1-stable 的 §3.2 端到端编排必须先绿(给靶场回归打基础)

**关键不依赖**(可并行):
- 不依赖 v0.6.4 LLMPlanner(虽必调,但 LLMPlanner 已落,无后续工作)
- 不依赖 P3 Shannon peer(可独立推进)

---

## 14. 测试策略

### 14.1 单元测试

| 模块 | 测试点 |
|---|---|
| `ProposeAction` Pydantic | 枚举外字段拒绝、payload 子 Schema 拒绝、rationale 长度边界 |
| `LoopTerminationPolicy` | 各终止条件触发、终态正确、复合条件优先级 |
| `SchemaGate` | 幻觉 tool_id 拒绝、超出 token 限单步拒、Pydantic extra 拒 |
| `PolicyGate` | 越 scope 拒、超 risk_cap 拒、缺 capability 拒(复用现有策略测试) |
| `PermitGate` | nonce 唯一、TTL 过期拒、签名不一致拒 |
| `LoopFeedback` | Observation 信号提取正确、context_hash 一致性 |

### 14.2 集成测试

| 场景 | 测试点 |
|---|---|
| Mock LLM 全流程 | 提议→三道门→JobService→Observation→LoopContext 更新→下一步 |
| 终止: catalog floor 全绿 | 必修类跑完后循环 COMPLETED |
| 终止: 预算耗尽 | 步数上限触发 BUDGET_EXHAUSTED,审计可见 |
| 终止: 连续被门拒 | POLICY_BLOCKED,fallback_used 审计 |
| EmergencyStop | 立即冻结,撤销未用 Permit,保留 Observation |
| 重放 | 同一 LoopContext 输入,LLM 输出必须同 schema(不强求同内容,因 LLM 非确定性,但 LoopState 字段必须确定性可重放) |

### 14.3 端到端测试(§14.4 的靶场回归基础上)

```python
@pytest.mark.e2e_real
def test_reasoning_loop_juice_shop_incremental():
    """catalog vs catalog+loop,对比 oracle 确认的增量"""
    # 同 §3.2 e2e_real 模式:跑 Juice Shop / crAPI / vulhub
    # 对照组仅 deterministic tools(无 loop)
    # 实验组 + ReasoningLoop(loop 0.7.x 全部启用,带 mock 或真 LLM)
    # 断言:实验组 oracle_confirmed > 对照组,且误报率不显著上升
    # 断言:cost<对照组 1.5x(LLM token),wallclock<对照组 2x
```

---

## 15. 风险与缓解

| 风险 | 缓解 |
|---|---|
| LLM 循环刷步数(故意跑无意义 action) | 三道门 + BudgetGate + 连续无信号终止 + 单步 cost 上限 |
| LLM hallucinate tool_id | Schema Gate Pydantic 严格校验 + tool_id 必须在 AvailableCapabilities |
| LLM 提议越 scope | Policy Gate 完全复用 ScopeEnforcer,**LLM 完全无 scope 决策权** |
| LLM 提议挑"低成本 step"刷步数 | BudgetGate 单步 cost 上限 + Observation 信号指纹检测"无新信号" |
| LLM 提议泄露敏感数据 | 红线在 RemoteModelGateway,循环调 LLM 走同款 gateway |
| LLM Backend 不可用 | 立即冻结 + fallback_used 审计 + 转纯 catalog |
| 循环与 catalog 并发跑导致资源争用 | LoopJob 由 JobService 统一调度,租约/资源预算同源 |
| 审计链被循环 step 暴增污染 | 循环每步写 AuditEvent 是必要的(回放要求),但用 batched_write 优化批量写 |
| 循环成本超 LLM 预算 | 严格 BudgetGate + 远程超 500K/天立即停(沿用 §12.11) |
| 循环被发现 oracle 弱判定(类似 Cybergym 超时漏洞) | 复用现有 oracle(canary echo + OOB),**不引入新 oracle** |
| Strix peer 也想"自驱循环"导致与本循环冲突 | 明确边界:Loop 调 Strix 是单次动作(`request_peer`),Strix 内部 Graph of Agents 仍是 Strix 自管 |

---

## 16. 与商业定位对齐(对齐 §22)

**§22.3 护城河**:四层非 LLM 可补——TestCatalog / AppModel / oracle N/N / 模型签名治理。

ReasoningLoop **不破任何一层**:
- ✅ TestCatalog:Loop 只 ADD,必经 catalog floor 全绿才能 COMPLETED
- ✅ AppModel:Loop 可提议触发 LogicTestGenerator(确定性)再跑,AppModel 仍是 SIGNED 模型
- ✅ oracle N/N:Loop 的每步观察仍走 oracle 流水线
- ✅ 模型签名治理:LLM 输出严格 Schema,LLM 不签名

**§22.4 V2 ToB**:Loop 是单 Assessment 内的协作模式,Repository Contract 抽象不变,ToB 多租户只需给 LoopState 加 `tenant_id`(已为 Repository 预留扩展点)。

**§22.5 开源同类**:本设计**不引入新依赖**——所有能力在现有 modules + 新增的 ~6 个文件内。Handbooks 已规划(Strix skills Apache-2.0,见 `LICENSE-THIRD-PARTY.md`)。

---

## 17. 一句话总结

**SecOpent 缺的不是"全 LLM 决策",而是"在已保 catalog 下限 + 已校验 oracle 的两条护城河之间,加一条『LLM 自驱的窄循环』"。这条循环必须遵守三件事:LLM 只提议、确定性层三道门、终止策略可审计——并明确禁止"超时=成功 / any-of 评分 / 静默 fallback"三类已知弱判定(对应 Cybergym 的 reward hacking 教训)。**

---

## 18. 评审 checklist(待 brainstorming)

- [ ] Loop 位置:确认 Orchestrator 协作模式 vs 新 daemon
- [ ] 终止策略默认值:50 步 / 30 min / 200K token 是否合适?
- [ ] Handbooks 必填还是可选?没有 Handbooks 时循环是否仍可跑(裸 LLM)?
- [ ] 三道门顺序:Schema → Policy → Permit vs 反过来(拒得快 vs 拒得准)
- [ ] Loop 触发时机:Assessment 启动时自动?还是检测到"已知模式全跑完但仍有未消化候选"才触发?
- [ ] Loop 与 Strix peer 优先级:Loop 触发 Strix 一轮,与 Strix 作为独立 peer agent,是否冲突?
- [ ] 是否需要"循环内可暂停 / 续跑"(人审批介入)?还是一气呵成?
- [ ] Loop 的 cost 上报对齐 §12.11,是否要把每步 cost 强制进 SUBMISSION-style 报告?
- [ ] Loop 状态是否进 DB Job Lease / 进 Outbox?
- [ ] LoopStep 的回放粒度:仅 ProposeAction 还是含 LoopContext 全量?