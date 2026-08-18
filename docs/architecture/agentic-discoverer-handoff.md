# Agentic Discoverer：LLM 自主逻辑漏洞探索能力设计与交接

> ⚠️ **本文件已并入权威版**: 详见 `sepcs/2026-08-19-reasoning-discoverer-unified-design.md`（合并 L1/L2/L3 + DIFF_SEMANTIC + 过时事实修订）。本文件保留作设计过程记录，其 L1/L2/L3 分级与 DIFF_SEMANTIC 细节已被权威版吸收。

> 日期：2026-08-06
> 状态：设计完成（L1+L2+L3），待实现计划
> 动机：Cybergym / Strix 暴露 SecOpent 盲区——业务逻辑漏洞（越权、竞态、支付篡改、状态机绕过）无签名可命中，对确定性扫描与 echo/oob 验证不可见
> 关联：P0-P3 peer agent 模式、Phase 3 3.4 preflight、AppModel/model_builder、Planner/Orchestrator、ExecutionPlan version+approve
> 前置：Phase 3（3.1-3.6）完成；LOGIC 验证方法未存在（本次新增 DIFF_SEMANTIC）

---

## 0. 定位声明（必须读）

**Cybergym 是评估基准，不是产品架构。** 它测"LLM agent 在隔离靶场能独立解出多少漏洞"（740★, 240GB 数据集, PoC 提交服务器全部是**评测**设施）。其价值主张是给模型能力打分，不是在生产环境测真实应用。

SecOpent 是**授权渗透工作台**（范围签发 / 审批 / OracleEngine 确认 / 审计链 / 人在回路）。两者方向相反：Cybergym 追求 LLM 决策最大化自由，SecOpent 追求决策可治理性。

**因此补强逻辑漏洞探测的正确路子，不是"把决策权全交给 LLM"（会绕开 Permit/scope/oracle），而是：**

> **把"LLM 自主探索逻辑漏洞"做成 SecOpent 一个受保护的发现源**——比 Strix peer agent 更高自主度，但被确定性层兜底。LLM 决策"测什么/怎么测/怎么根据响应调整"；确定性层负责范围/预算/证据/Oracle 确认/人在回路审批。

这套思路已在 P0-P3 验证（peer agent = 低信任发现源），本设计是其**深化第二层**。

### 名词
- **Discoverer**：随 LLM 自主决策循环的 peer-agent 类型，专攻逻辑漏洞
- **DIFF_SEMANTIC**：新增的 Oracle 验证方法，用"同场景请求差分"确认逻辑漏洞（越权/竞态/状态机绕过）
- **L1 / L2 / L3**：LLM 决策自主度的三档（定义见 §5）

---

## 1. 现状盲区（已核实，file:line）

| 能力 | 现状 | 为什么测不到逻辑漏洞 |
|------|------|-----------------------|
| 确定性扫描 | nuclei/dalfox/nmap（adapter） | **签名/模板匹配**——只能命中已知模式；业务逻辑漏洞无签名 |
| Case 引擎 | YAML 用例（`case_engine`） | **预写死步骤**——覆盖面 = 人工写过的，测不到未预见路径 |
| LLM 提议 | `ModelBackend.complete()`（`application/remote_model.py:75`） | **静态一次调用**——不根据目标响应迭代，无法"试探→看反馈→调下一发" |
| Peer agent (Strix) | P0-P3 已接 | 通用白盒/黑盒；且确认靠 echo/oob，**对逻辑漏洞构造不出确认探针** |
| Planner 计划 | `application/planner.py::Planner.generate` | 确定性 DAG，固定测试类——**无业务上下文** |
| AppModel | `model_builder` + `domain/appmodel/logic.py::LogicTestCase` | 有 states/transitions/fields + LogicTestCase，但**未接 LLM 自主探索** |

**Cybergym 启示**：逻辑漏洞确认本质 = "**理解业务规则 → 违反规则**"。LLM 强在差分请求、状态机非法迁移、角色权限错位——恰好是签名和 echo/oob 都覆盖不到的。

---

## 2. L1：Agentic Discoverer（受保护的自主探索器，本次重点）

### 2.1 架构

```
Agentic Discoverer（新 peer agent backend）
│
├─ 输入：AppModel（states/transitions/fields，复用 model_builder）
│        + scope + 预算(PeerAgentBudget) + Permit
│        + 已确认 findings（避免重复）+ 登录态（复用 Phase 3 3.4 preflight）
│
├─ 决策循环（LLM 自主，但每次动作用前过确定性闸门）：
│    观察状态 → 假设下一动作（请求/改参/换 session）→
│    调工具 → 看响应 → 更新状态假设 → 循环
│
├─ 工具集（受控，全经 egress/scope/harness）：
│    ① browse/auth.session（复用 preflight 登录态）
│    ② http.request（复用 case_engine 的 http verb）
│    ③ appmodel.inspect（states/transitions/fields）
│    ④ mutate.field / mutate.state（试探业务规则）
│    ⑤ evidence.capture（请求/响应/差分存 CAS）
│    ⑥ diff.propose（Output: 两条请求 + 各自业务期望，供 DIFF_SEMANTIC）
│
├─ 产出：CandidateFinding（含"业务规则假设 + 证据链 + 建议验证"）
└─ 出口：走 PeerAgentService._normalize 双门禁(scope+catalog)
        → DIFF_SEMANTIC OracleEngine 确认
```

### 2.2 决策循环（每次动作的确定性闸门）

```
loop:
  LLM 观察累积状态 -> 提议下一个动作 {tool, args, 业务意图}
  确定性闸门（非 LLM）：
    - scope 闸门：target 必须在 scope（ScopeEnforcer）
    - egress 闸门：网络出口受限
    - 预算：墙钟 + token 成本，超限触发 stop
    - 边界：tool 参数不能注入任意 CLI（如 case_engine 无 eval）
  通过 -> 执行工具 -> 响应落 CAS + 回填上下文 -> 继续
  产出 diff 假设 -> 交 DIFF_SEMANTIC Oracle
```

LLM 只做"决策下一步"，**每次动作到真实世界的路径都被确定性闸门拦一道**。这就是"自主但受保护"的精髓。

### 2.3 与现有骨架的复用（这是设计核心优势）

| 现有资产 | Discoverer 如何复用 |
|---------|---------------------|
| `PeerAgentHarness`（P0） | Discoverer = 另一个 backend，复用 launch/stop/预算/标签/Emergency Stop |
| `PeerAgentService._normalize` | 双门禁（scope+catalog）原样生效 |
| AppModel + `model_builder` | 业务上下文输入（states/transitions/fields） |
| `preflight` + 登录态（Phase 3 3.4） | Discoverer 复用已认证 session 做差分 |
| `case_engine` http verb | 用同一套 request 执行层 |
| `evidence_store` CAS | 每次请求/响应/差分落盘做证据 |
| `EmergencyStop` 标签机制 | 覆盖 Discoverer 容器 |
| `chain_templates`（P1a 3.5） | 发现的多步逻辑链可套用链模板 |

**不新建独立子系统——全挂在已有 peer/AppModel/evidence 骨架上。**

---

## 3. DIFF_SEMANTIC：逻辑漏洞的"差分确认"（本次的最大创新）

### 3.1 为什么 echo/oob 对逻辑漏洞无效

现有 Oracle 方法（`domain/verification/models.py::VerificationMethod`）：
- echo：要求 payload 在响应中精确回显 → 逻辑漏洞（越权返回 200 的他人数据）无 payload 可回显
- oob：要求外带回调子域 → 逻辑漏洞无外带通道

逻辑漏洞的确认探针是**差分语义**：

| 逻辑漏洞 | 差分探针 | 期望 vs 实际 |
|----------|----------|--------------|
| IDOR/越权 | userA session 请求 userB 资源 | 期望 403，实际 200 |
| 状态机绕过 | 未满足前置直接 POST transition | 期望 400，实际 200 |
| 竞态/双花 | 并发双提 | 期望余额减一，实际减二或零 |
| MFA 跳过 | 无 OTP 直接过 | 期望拒绝，实际放行 |

### 3.2 设计

**新增验证类型** `VulnType.LOGIC` + `VerificationMethod(oob_window_seconds=0, echo_enabled=False, diff_semantic=True)`（或新增 `VulnType` 细分：IDOR/STATE_MACHINE/RACE/PAYMENT——以 VulnType 枚举现状为准，倾向加细分枚举以精确覆盖）。

**Oracle 入口**——`OracleEngine` 新增 `DIFF_SEMANTIC` 验证：
```python
# 输入：Discoverer 提供的"证据差分对"
@dataclass(frozen=True, slots=True)
class DiffSemanticSpec:
    """两请求 + 各自业务期望，供确定性差分断言。"""
    baseline_request:  dict      # 正常路径请求（如 userA 自己的资源）
    assertion_request: dict      # 试探路径请求（如 userA 请求 userB 资源）
    expectation: str             # "deny"（期望拒绝）| "single_spend" | "state_reject"
    state_readback: str | None   # 状态回读端点（若有）
```
`verify(spec)`：
1. `http` 执行 baseline_request → 记录响应 A
2. `http` 执行 assertion_request → 记录响应 B
3. 确定性断言：`expectation == "deny"` → B 应 4xx 且 B ≠ A；若 B 为 200 且与 A 结构一致（达到的资源类型相同）→ **CONFIRMED**
4. `state_readback` 存在时 → 回读状态断言（如余额）辅助确认
5. N/N 复现同现有 Oracle（交叉 session 重复 N 次）

**关键**：DIFF_SEMANTIC 的确认是**确定性结构差异 + 状态回读**，**不是** LLM 判断。LLM（Discoverer）只提供"怀疑点 + 两条请求 + 期望"，Oracle 用确定性规则裁决。**LLM 永不标记 Confirmed**（边界不破）。

### 3.3 落地

- `domain/verification/models.py`：`VulnType` 加 `LOGIC`（或细分枚举）+ `VerificationMethod.diff_semantic: bool = False`
- `domain/verification/registry.py`：注册 `DIFF_SEMANTIC` 方法族（default_n、差分窗口）
- `infrastructure/oracle/diff_semantic_verifier.py`：`DiffSemanticVerifier`（新，实现 `OracleVerifier`）
- `infrastructure/oracle/verifier_factory.py`：`method_lookup` 分流到 DIFF_SEMANTIC（承接 Phase 3 3.1 的 method lookup 改造）

### 3.4 测试（TDD）
- `tests/domain/test_verification_method.py`：diff_semantic 字段 + LOGIC 注册
- `tests/infrastructure/test_diff_semantic_verifier.py`：
  - `expectation="deny"` + 实际 200 且结构同基线 → CONFIRMED
  - 实际 403 → REFUTED
  - N/N 分歧 → INCONCLUSIVE（升级人审，同现有 5xx 逻辑）
  - `state_readback` 余额断言辅助
- `tests/oracle_ground_truth/`：构造可测的 IDOR/状态机绕过靶场差分确认

---

## 4. L2：发现→回写草稿 Case（把 LLM 探索固化为可复用资产）

### 4.1 动机
L1 每次从零跑 LLM，成本高。L2 让 Discoverer 把已确认的逻辑漏洞路径**转成 case DSL 草稿**（固化 steps + assertions + DIFF_SEMANTIC verification），下次确定性 Case 引擎直接跑，不用再烧 LLM token。

### 4.2 设计
- Discoverer 在 **CONFIRMED 后**，调用 `case_engine` 的 case 生成器，把"证据差分对"转成 `CaseDefinition`：
  - `steps`：baseline 请求 + assertion 请求（复用 `http.request` verb）
  - `assertions`：`status in (401,403)` 或 `state_readback` 表达式
  - `verification`：`method=logic, reproduce=N`
  - `origin=CaseOrigin.AGENT`（新增枚举值，或复用现有 `auto_generated`），`status=DRAFT`
- **必须人审 + 签名**才入 CaseRegistry（Phase 3 3.4 之外的既有 case 审批流）；未签名不得正式执行（DRY，`case_engine` 现有规则）
- 回写是**草稿**，明确标注"由 Discoverer 生成，待人工确认"——绝不自动发布（护栏）

### 4.3 细节
- `domain/cases/models.py`：`CaseOrigin` 加 `AGENT`；`CaseDefinition` 加 `generated_by: str = ""`（记 discoverer run_id）
- `application/discoverer_authoring.py`：`render_case_draft(confirmed_chain, diff_spec) -> CaseDefinition`（纯函数，TDD）
- 测试：render 出的 case 可被 `case_from_mapping` 解析、status=draft、含 DIFF_SEMANTIC verification、generated_by 指向 run_id

---

## 5. L3：LLM 参与计划生成（完全重排，但护栏不破）

### 5.1 你选"完全重排"——设计必须解决的核心冲突

`Planner`（`application/planner.py`）的确定性构造性保证 = **"必修类 0 未执行才能结题"**（CoverageService）。若 LLM 能随意丢步骤，覆盖门禁被架空。

**正确拆解：L3 的"完全重排"作用于下一版计划（Plan Proposal），不是篡改已批准的运行中计划。**

- 已批准计划在 `AssessmentService.approve` 时**钉死 plan digest + scope**（`assessments.py:86-92`）——运行中不可改，这是审批不变量
- L3 的 LLM 在**当前计划执行期或执行后**，根据 Discoverer 发现提出**新计划版本** `ExecutionPlan.version + 1`，作为**未签名 Proposal**
- Proposal 走审批流 → 人审 + 签名后成为新批准计划 → 追加执行

**这样既有"完全重排"的深度（LLM 可加/删/改任何 step），又不撕裂审批不变量**——所有变更先落"待签"状态。

### 5.2 L3 设计

**新增 `PlanProposal`（domain）**：
```python
@dataclass(frozen=True, slots=True)
class PlanProposal:
    id: str
    assessment_id: str
    source: str            # "discoverer" | "llm_agentic"
    base_plan_digest: str  # 基于哪一版
    proposed_version: int  # base + 1
    steps_delta: tuple[StepOp, ...]   # StepOp: ADD(step) | REMOVE(key) | REORDER(keys)
    rationale: str         # LLM 理由（人审参考）
    approved: bool = False
    signature: str = ""    # 人审签名后置
```

**入口**——`application/planner.py` 新增 `Planner.apply_proposal(base_plan, proposal) -> ExecutionPlan`（确定性应用，校验 DAG 合法 + 依赖完整 + 覆盖门禁检查）：
- 校验：新版本 steps 引用已存在 key 的依赖合法（`ExecutionPlan.create` 已做 DAG 环/依赖检查）
- **覆盖门禁**：`apply_proposal` 后跑 `CoverageService.enforce_gate`——若 LLM 重排导致必修类 0 覆盖，**拒绝**并报错（护栏显式化：LLM 想丢步骤，门禁说不）
- 目的：**不是让 LLM 决定"不测什么"，而是让 LLM 决定"额外测什么 + 优先级"**——丢掉必修类是门禁的活，不是 LLM 的自由

### 5.3 自主度边界（L3 最终形状）
| 维度 | LLM 可做 | 不可做 |
|------|----------|--------|
| 加步骤 | ✅ 任意（含新 Discoverer 用例、新 adapter 目标） | - |
| 删步骤 | ⚠️ 尝试但被覆盖门禁拦（必修类必留） | 丢必修类 |
| 重排 | ✅ 任意（改变执行序） | 破坏 DAG 依赖（校验拦截） |
| 改范围 | ❌ | 超出 scope（Proposal period 不扩 scope） |
| 自动执行 | ❌（仅生成 Proposal，需人审签名） | 未批准即执行 |

**L3 完全重排的深度保留，护栏通过"覆盖门禁 + 审批"两层兜底。**

### 5.4 落地
- `domain/assessments/plan_proposal.py`：`PlanProposal` + `StepOp`（frozen dataclasses，TDD）
- `application/planner.py`：`apply_proposal()`（确定性，注入 CoverageService 作门禁）
- `application/assessments.py`：`propose_plan_revision(assessment_id, proposal, actor)`——只落 proposal，不进执行；`approve_plan_revision(proposal, approved_by)`——人审 + 签名 + 变为新批准计划
- `interfaces/api/routers/assessments.py`：`POST 计划重排提案` + `POST 审批重排提案`（human-only，agent 403，对齐 `signing_keys` 门禁模式）

### 5.5 测试（TDD）
- `tests/domain/test_plan_proposal.py`：StepOp 合法性、version 递增、approve 前不可执行
- `tests/application/test_planner_proposal.py`：ADD 步骤生成的计划 DAG 合法；REMOVE 必修类 → CoverageGateError；REORDER 依赖合法；proposal 未签名不可执行
- `tests/interfaces/test_plan_revision_api.py`：agent 403 / human 200 / 重排后需新签名

---

## 6. 决策自主度分级总览

```
L1 Discoverer-Scoped（本次实现核心）
   LLM 决策"动作序列"，man解定工具集 + AppModel + scope，
   每 action 过 egress/scope/预算闸门，产出 CandidateFinding
   → "受审的自主测试员"

L2 Discoverer-Authoring（本次实现，L1 之上）
   LLM 把已确认路径转成 case DSL 草稿，人审+签名后入 case 引擎
   → LLM 发现的路径固化为可复用用例（回流到策展层）

L3 Agentic Planner（本次实现，含完全重排）
   LLM 提 PlanProposal（加/删/重排步骤，version+1 待签），
   覆盖门禁拦截丢必修类，人审+签名后成为新批准计划
   → LLM 参与计划，但护栏显式
```

三档叠加 = 从"扫描已知"到"自主探索 + 固化 + 驱动计划"的完整闭环，确定性层全程兜底。

---

## 7. 边界与护栏汇总

| 护栏 | 机制 | L 适用 |
|------|------|--------|
| 范围 | `ScopeEnforcer` + egress + `PeerAgentBudget` | L1/L2/L3 |
| 预算 | `PeerAgentBudget`（墙钟+token 成本）超限熔断 | L1 |
| 证据 | 每动作请求/响应/差分落 CAS，无证据不发 report | L1/L2 |
| 确认 | Discoverer 永不标 Confirmed；DIFF_SEMANTIC Oracle 确定性裁决 | L1/L2 |
| 人在回路 | 发现走审批；L2 case 草稿人审签名 | L1/L2/L3 |
| 覆盖门禁 | L3 丢必修类被拒 | L3 |
| 计划审批 | L3 PlanProposal 需人审 + 新签名才执行 | L3 |
| 成本 | Discoverer 单次探索上限 + 超额熔断 | L1/L2 |

---

## 8. 工程量 / 排期 / 依赖

| 阶段 | 内容 | 工时 | 依赖 |
|------|------|------|------|
| LD-0 | DISCOVERER backend + 决策循环骨架 + 工具集装配 | 2-3d | P0-P3 harness、Phase 3 3.4 preflight |
| LD-1 | DIFF_SEMANTIC Oracle + Verifier + registry | 2d | Phase 3 3.1 method lookup 改造 |
| LD-2 | Discoverer 产出 CandidateFinding + evidence（差分对） | 1-2d | LD-0/LD-1 |
| LD-3 | L2 回写草稿 case + origin=AGENT + 人审 | 1-2d | LD-1 |
| LD-4 | L3 PlanProposal + apply_proposal + 覆盖门禁 + API | 3-4d | LD-1，CoverageService |
| LD-5 | ground-truth 靶场回归 + 全量门禁 + 文档 | 1d | 全部 |

**约 10-14 工作日**。每阶段 TDD、独立 commit（对齐 Strix/Shannon 计划风格）。

---

## 9. 风险与缓解

| 风险 | 缓解 |
|------|------|
| Discoverer 烧 token 失控 | `PeerAgentBudget` 硬上限 + 超额熔断 + 每次 action 后成本累计算账 |
| LLM 死循环/空转（Cybergym 已验证此问题） | action 级 monotonic 步数上限 + 上下文预算 + 超限 stop |
| 逻辑漏洞 DIFF 误报 | DIFF_SEMANTIC 确定性结构断言 + N/N + 状态回读 + 5xx→INCONCLUSIVE 升级人审 |
| LLM 生成的差分请求越权到 scope 外 | egress + ScopeEnforcer 每 action 拦截 |
| L3 重排撕裂审批不变量 | PlanProposal 待签 + 覆盖门禁 + `ExecutionPlan.create` DAG 校验 |
| L2 草稿 case 污染 case registry | origin=AGENT + DRAFT + 人审签名强制，未签名不可正式执行 |
| 与 catalog null 问题混杂 | 独立 scope，catalog null 单独跟踪 |

---

## 10. 交接清单（执行者 checklist）

### 文件变更预览
| 文件 | 动作 |
|------|------|
| `domain/verification/models.py` | VulnType 加 LOGIC（或细分）+ diff_semantic 字段 |
| `domain/verification/registry.py` | 注册 DIFF_SEMANTIC 方法族 |
| `infrastructure/oracle/diff_semantic_verifier.py` | DiffSemanticVerifier（新） |
| `infrastructure/oracle/verifier_factory.py` | method_lookup 分流（承接 3.1） |
| `domain/cases/models.py` | CaseOrigin.AGENT + generated_by 字段 |
| `application/discoverer_authoring.py` | render_case_draft（新） |
| `domain/assessments/plan_proposal.py` | PlanProposal + StepOp（新） |
| `application/planner.py` | apply_proposal() |
| `application/assessments.py` | propose_plan_revision / approve_plan_revision |
| `interfaces/api/routers/assessments.py` | 重排提案 + 审批端点 |
| `infrastructure/peer_agents/discoverer_backend.py` | Discoverer backend（新，实现 PeerAgentBackend） |
| `infrastructure/peer_agents/composition.py` | 注册 discoverer |

### 执行序
1. Phase 3（3.1-3.6）先完成——LD-1 依赖 3.1 的 method lookup
2. LD-0 → LD-5 逐段 TDD
3. 全量门禁（pytest + ruff + mypy + `git diff --check`）
4. ground-truth 靶场回归（IDOR + 状态机 + 竞态）
5. ADR：Discoverer 自主度边界 + DIFF_SEMANTIC 确认机制
6. CHANGELOG + 发版

### 不做（YAGNI / 超范围）
- ❌ 全自动无护栏 Discoverer（违背定位）
- ❌ LLM 直接改测评范围（scope 不可扩）
- ❌ L2 自动发布 case（必须人审）
- ❌ L3 未签名自动执行（必须审批）
- ❌ Cybergym 级 benchmark 设施（本设计是产品能力，不是评测）
- ❌ 覆盖门禁豁免（L3 丢必修类恒拒）

---

## 11. 结论

这套设计把 Cybergym/Strix 式"LLM 自主决策"**吸收为 SecOpent 一个受保护的发现源**：
- **L1**：LLM 自主探索逻辑漏洞，DIFF_SEMANTIC Oracle 确定性确认
- **L2**：发现的路径固化为人审签名的 case 草稿，回流策展层
- **L3**：LLM 提 PlanProposal（含完全重排），覆盖门禁 + 审批兜底

全程确定性层（scope / 预算 / 证据 / Oracle / 覆盖门禁 / 审批）**掌控护栏**，LLM 负责"发散的探索"与"业务理解"，这正是 SecOpent 保下限哲学的正确延伸——**不是让 LLM 承担裁决，而是让 LLM 补上确定性手段的死角（逻辑漏洞）**。
