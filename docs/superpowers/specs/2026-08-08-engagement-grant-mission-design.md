# EngagementGrant + Mission: Agent 委托执行设计

> **日期**: 2026-08-08
> **状态**: 已批准(brainstorm 4 决策确认)
> **目标版本**: v0.6.0(Phase A)+ v0.6.x(Phase B)
> **背景**: MCP 的 `plan_approve`/`assessment_start` 用 `if False else _human_required` 硬编码死代码([handlers.py:493-535](src/secopent/interfaces/mcp/handlers.py))——agent 永远无法触发真实扫描。本设计把审批从"per-operation 必须人"升级为"**人一次性预授权(grant)+ agent 在边界内自治执行(mission)**",不绕过审批,而是显式建模委托授权。

---

## 1. 目标

1. **Agent 可执行**:外部 agent(Hermes 等)对已获授权的目标,自主完成 plan_approve → assessment_start 全流程。
2. **人在边界上**:grant 创建是 human-only;agent 的每一步 action 都挂 grant_id,审计链可追溯。
3. **项目内 LLM 决定用例**:agent 下发高层任务(`mission_create(target, intent)`),具体跑哪些 test class 由项目内 LLM 从 TestCatalog 选出(required classes 是下限)。
4. **不破坏现有安全模型**:无 grant 的 agent 仍 HUMAN_REQUIRED;DESTRUCTIVE 仍不可达。

## 2. 已确认决策(brainstorm 2026-08-08)

| # | 问题 | 决策 |
|---|---|---|
| 1 | Grant 粒度 | **绑定 project**(engagement 边界) |
| 2 | 审批语义 | **grant 即审批者**(agent 的 approve/start 透传 grant_id,校验 scope⊆/risk/window) |
| 3 | Phase B 落地 | **新增 mission 工具 + LLM 规划器** |
| 4 | 风险上限 | **可配置至 INTRUSIVE**;DESTRUCTIVE 已 deny-list([risk.py](src/secopent/domain/cases/risk.py:67) 不可发布 + [engine.py](src/secopent/domain/policy/engine.py:15) 三层硬拒),grant 仅防御性排除 |

---

## 3. Phase A — EngagementGrant

### 3.1 新 domain:`domain/grants/models.py`

```python
class GrantStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"

@dataclass(frozen=True, slots=True)
class EngagementGrant:
    id: str
    project_id: str
    name: str
    include: tuple[str, ...]       # 授权目标集(URL/IP/域名/CIDR)
    exclude: tuple[str, ...]
    ports: tuple[int, ...]
    risk_caps: frozenset[RiskClass]  # PASSIVE/LOW/ACTIVE/INTRUSIVE;DESTRUCTIVE 拒绝
    valid_from: datetime
    valid_to: datetime
    created_by: str                # 必为 human
    created_at: datetime
    status: GrantStatus
    digest: str

    def create(...) -> EngagementGrant: ...
    def revoke(self) -> EngagementGrant: ...          # ACTIVE -> REVOKED
    def is_active_at(self, now: datetime) -> bool: ... # 窗口内且 ACTIVE(过期惰性转 EXPIRED)
    def covers_scope(self, snapshot: ScopeSnapshot) -> bool: ...
    def covers_risks(self, steps: Sequence[PlanStep]) -> bool: ...
```

**covers_scope 语义**(复用 [scope/models.py](src/secopent/domain/scope/models.py) 的 matching,不建新匹配器):
- assessment 的每个 include target:必须是 grant 某个 include 规则的匹配(target 用 `_target_matches` 语义:HTTP 规则剥 scheme 比 host、IP/CIDR 网络成员、域名/通配符)
- assessment 的 exclude:不做强制(grant 的 exclude 只用于授权边界描述)
- assessment ports ⊆ grant ports 才允许执行
- **不可能"授权 /24 扫到 /8"**:include 是精确包含,不是网络包含的父网自动放宽——每个 target 单独匹配

**covers_risks**:`all(step.risk in risk_caps for step in plan.steps)`。

**create() 校验**:
- `name.strip()` 非空
- `RiskClass.DESTRUCTIVE not in risk_caps`
- `valid_to > valid_from`
- `include` 非空(直接信任 ScopeDraft 级 normalize;grant 复用 `ScopeDraft._normalize_target` 语义做防御)

### 3.2 新 port + repo

- `application/ports/grants.py`:`GrantRepository` Protocol(generic,不入 SQLAlchemy)
  ```python
  def add(self, grant: EngagementGrant) -> None: ...
  def get(self, grant_id: str) -> EngagementGrant | None: ...
  def list_for_project(self, project_id: str) -> tuple[EngagementGrant, ...]: ...
  ```
- `infrastructure/repositories/sqlalchemy_grants.py`:`SqlAlchemyGrantRepository`
- ORM:`CoreEngagementGrant`(`core_grants` 表),alembic migration

### 3.3 `application/grants.py` — GrantService

```python
class GrantDecision(Protocol):
    allowed: bool
    reason: str

class GrantService:
    def create_human(self, *, project_id, name, include, exclude, ports,
                     risk_caps, valid_from, valid_to, actor_role) -> EngagementGrant:
        self._require_human(actor_role)      # 复用 assessments._require_human 语义或抽公共 helper
        ...
    def revoke(self, grant_id, *, actor_role) -> EngagementGrant: ...
    def authorize(self, grant_id, scope: ScopeSnapshot,
                  steps: Sequence[PlanStep], *, now) -> GrantDecision:
        # grant 存在 + ACTIVE + 窗口 + covers_scope + covers_risks
        ...
```

异常:`GrantNotFoundError`、`GrantInactiveError`、`GrantScopeMismatchError`、`GrantRiskNotApprovedError`(均 DomainError 子类)。

### 3.4 审批门改造(`application/assessments.py`)

```python
def approve(self, assessment_id, *, approved_by="human", approved_risks=None,
            approved_capabilities=None, scope_digest="", actor_role="human",
            grant_id: str | None = None) -> Assessment:
    if grant_id:
        decision = grant_service.authorize(grant_id, scope, plan.steps, now=utc_now())
        if not decision.allowed:
            raise AssessmentPermissionError(f"grant denied: {decision.reason}")
        approved_by = f"grant:{grant_id}"     # 审计链记的是 grant 身份
    else:
        self._require_human(actor_role)

def start(self, assessment_id, *, actor_role="human", grant_id=None) -> Assessment:
    # 同构:grant_id -> authorize(scope, plan.steps) -> 放行;否则 _require_human
```

⚠️ **注意**:`approve` 当前签名已有 `approved_by` 参数,`_require_human` 在 approve 内调用(assessments.py:75)。grant 路径不改变 `approved_by` 参数语义——**grant 路径下强制 `approved_by=f"grant:{grant_id}"`**,不可被调用方注入(在 `_authorize_via_grant` 内部覆盖)。

`GrantService` 注入:`AssessmentService` 构造函数加可选 `grant_service: GrantService | None = None`(None 时 grant_id 传入即报错,保证 degrades safe)。

### 3.5 MCP handler 去死代码(`interfaces/mcp/handlers.py`)

```python
def handler_plan_approve(runtime, *, assessment_id, approved_risks=None,
                         approved_capabilities=None, grant_id=None):
    ...
    return _guard("plan_approve", lambda: (
        _assessment_out(service.approve(
            assessment_id=assessment_id,
            approved_by="agent",                      # service 内被覆盖为 grant:<id>
            approved_risks=frozenset(RiskClass(r) for r in (approved_risks or [])),
            approved_capabilities=frozenset(approved_capabilities or []),
            scope_digest="",
            actor_role="agent",
            grant_id=grant_id,                        # ← 非 None 才放行
        )) if grant_id is not None
        else _human_required("plan_approve", assessment_id,
                             "agents need a grant to approve (see grant_list)")
    ))

def handler_assessment_start(runtime, *, assessment_id, grant_id=None):
    # 同构;grant_id -> service.start(actor_role="agent", grant_id=...)
    # 无 grant_id -> _human_required
```

- **新增只读** `handler_grant_list(project_id)`:返回该 project 的 ACTIVE grants(agent 可发现可用授权;不含 exclude 细节之外的敏感信息)
- **tool_registry 注册**:`plan_approve`/`assessment_start` 参数签名加 `grant_id`;新增 `grant_list`;`mission_create` 在 Phase B 注册
- 审计:`handlers` 里 approve/start 成功后由 service 层审计(现有 `_audit` 已存在);grant 路径的 payload 带 `grant_id`(复用现有 `_audit` 调用点或 service 内 `_audit_record`,实施时定)

### 3.6 持久化 + migration

- `core_grants` 表:`id, project_id, name, include(JSON), exclude(JSON), ports(JSON), risk_caps(JSON), valid_from, valid_to, created_by, created_at, status, digest`
- alembic migration(新 revision)
- `SqlAlchemyGrantRepository` 序列化/反序列化对齐 `sqlalchemy_grants.py` 现有模式

---

## 4. Phase B — Mission(项目内 LLM 决定用例)

### 4.1 新工具 `mission_create(target, intent, *, grant_id, project_id, risk_cap=None)`

Agent 一次调用完成全流程:

```
mission_create
  → grant_service.authorize(grant_id, scope_draft-ish target, risk_cap)
  → ScopeDraft(include=(target,), ...).freeze(snapshot_id, approved_by=f"grant:{grant_id}")
  → AssessmentService.create(project_id, scope_snapshot_id, mode=APPROVAL? 或 SCOPE_AUTOPILOT)
  → LLMPlanner(intent, catalog, asset_types).generate(assessment_id)
  → AssessmentService.approve(actor_role="agent", grant_id=...)   # plan 内的 risk ≤ risk_cap ≤ grant caps
  → AssessmentService.start(actor_role="agent", grant_id=...)
  → 返回 assessment 摘要(含 status=running)
```

### 4.2 `application/llm_planner.py` — LLM 规划器

```python
class LLMPlanner:
    def __init__(self, backend: ModelBackend, catalog: TestCatalog,
                 runner_map: dict[AssetType, str] | None = None): ...

    def generate(self, *, plan_id, assessment_id, asset_types,
                 intent: str, risk_cap: RiskClass | None) -> ExecutionPlan:
        required = set()      # catalog.required_for(asset_type) 逐个 union
        # ← 下限:required 必含
        llm_selected = self._llm_select_classes(intent, asset_types, risk_cap)
        selected = required | llm_selected
        steps = [... 每个 class 一个 PlanStep,runner 按 asset_type(复用 Planner 的 _DEFAULT_RUNNERS),risk/cwe/owasp 从 catalog 读 ...]
        return ExecutionPlan.create(...)
```

**LLM 选择协议**:
- prompt:intent + 每个候选 class 的 `(id, asset_type, risk, title/description)` + 指令"从列表选 N 个最相关的(test_class id),JSON 数组输出;不可选择列出的 class 之外的 id"
- 解析:JSON 数组 → 校验每个 id ∈ catalog 候选集(非法 id 丢弃)→ 过滤 `risk <= risk_cap`(若 risk_cap 给定;缺省用 grant 的 risk_caps 上限)
- LLM/null/解析失败 → **降级为仅 required**(确定性回退,同现有 Planner 语义),审计 `mission.plan_generated(model="null|ollama|remote", degraded=true)`

**LLM 后端复用**(Phase 3.4/3.5):`RemoteModelGateway`/`OllamaBackend` 已实现 `ModelBackend.complete(prompt)`,`load_backend_from_config` 按 `SECOPTENT_LLM_BACKEND` 配置选择;后端不可用 → backend=None → 降级路径。composition root 注入。

### 4.3 mission 的 scope/审批细节

- **scope**:mission 的 target 是简单标量(一个 IP/域名/URL)。`ScopeDraft` 需 `include` 非空,故 mission target 包装成 `include=(target,)`;MTTF 用户要求 agent 说"测 1.1.1.1"就测 1.1.1.1——scope 就是它
- **approval 模式**:`ExecutionMode.APPROVAL` 但由 grant 授权批准(不需要人点)。保留 `approved_by="grant:<id>"` 审计
- **port**:mission 不指定 ports 时默认 `(80, 443)`(匹配 ScopeDraft 默认);grant 的 ports 是上限

### 4.4 Mission 审计

```
mission.created                 payload: {grant_id, project_id, target, intent}
mission.plan_generated          payload: {model, classes: [...], degraded}
assessment.approved(via grant)  payload: {grant_id}
assessment.started(via grant)   payload: {grant_id}
```

全链可追溯:审计链签名、每步挂 grant_id + mission 上下文。

---

## 5. 规则与否决项

**规则(安全边界,全部强制)**:
1. 建 grant = human-only(复用 `_require_human` 语义;agent 建 grant 直接 DENY)
2. DESTRUCTIVE:grant 构造拒绝 + covers_risks + 既有三层执行拒
3. scope ⊆ 校验:assessment.include 每个 target 必须匹配 grant.include 某规则
4. 无 grant 的 agent approve/start → HUMAN_REQUIRED(行为完全不变)
5. 窗口:grant 过期(valid_to 过了或 REVOKED)→ 所有授权调用拒绝

**否决项(YAGNI)**:
- ❌ delegated approver 多角色(企业审批人排班)
- ❌ agent 生成任意 DSL 用例(新用例发布仍 human-only publish gate)
- ❌ 跨 project grant
- ❌ grant 自动续期
- ❌ mission 多 target 批量(本期单 target;多 target 由 agent 多次调用)

---

## 6. 文件清单

| 文件 | 变化 |
|---|---|
| `src/secopent/domain/grants/models.py` | 新建:EngagementGrant + GrantStatus |
| `src/secopent/domain/grants/errors.py` | 新建:Grant*Error |
| `src/secopent/application/ports/grants.py` | 新建:GrantRepository Protocol |
| `src/secopent/application/grants.py` | 新建:GrantService |
| `src/secopent/application/assessments.py` | 改:`approve`/`start` 加 `grant_id` 分支 |
| `src/secopent/infrastructure/db/grants_models.py` | 新建:CoreEngagementGrant ORM |
| `src/secopent/infrastructure/repositories/sqlalchemy_grants.py` | 新建:SqlAlchemyGrantRepository |
| `alembic/versions/xxx_add_core_grants.py` | 新建:migration |
| `src/secopent/interfaces/mcp/handlers.py` | 改:俩 handler 去死代码 + grant_id 参数 |
| `src/secopent/interfaces/mcp/tool_registry.py` | 改:注册 grant_list / mission_create |
| `src/secopent/interfaces/api/main.py` | 改:composition root 装配 GrantService/repo |
| `src/secopent/application/llm_planner.py` | 新建:LLMPlanner(Phase B) |
| `src/secopent/interfaces/mcp/handlers.py` | 改:handler_mission_create(Phase B) |
| `tests/domain/test_grants.py` | 新建 |
| `tests/application/test_grants_service.py` | 新建 |
| `tests/application/test_grant_approval_path.py` | 新建:审批门改造测试 |
| `tests/infrastructure/test_sqlalchemy_grants.py` | 新建 |
| `tests/interfaces/test_mcp_grant_handlers.py` | 新建:handler 改造测试 |
| `tests/application/test_llm_planner.py` | 新建(Phase B) |
| `tests/interfaces/test_mcp_mission.py` | 新建(Phase B) |
| `docs/deployment/grants.md` | 新建:operator 授权指引(Phase B 后) |
| `CHANGELOG.md` | 更新 |

---

## 7. 测试计划(TDD,先 RED)

**Phase A**:
1. `test_grants.py`:create 校验(DESTRUCTIVE 拒绝/空 name/窗口倒置)、revoke、window 过期惰性转 EXPIRED、covers_scope(⊆ 通过/越界拒绝/HTTP 规则 + 裸 IP/端口超界)、covers_risks
2. `test_grants_service.py`:create_human agent DENY / human 通过;authorize 各拒绝原因
3. `test_grant_approval_path.py`:agent+grant approve/start 通(挂 `approved_by="grant:<id>"`);agent 无 grant 拒绝;grant 过期/scope 越界拒绝;grant_service=None 时 grant_id 传入报错
4. `test_sqlalchemy_grants.py`:round-trip 持久化 + 重建
5. `test_mcp_grant_handlers.py`:plan_approve grant_id → 真实调用(不再是 HUMAN_REQUIRED);无 grant_id → HUMAN_REQUIRED;grant_list 只返回 ACTIVE

**Phase B**:
6. `test_llm_planner.py`:fake backend 返回合法 id → selected = required ∪ llm;非法 id 丢弃;risk_cap 过滤;backend null → 降级为 required;降级审计
7. `test_mcp_mission.py`:grant 存在 + target ⊆ → mission_create 返回 running assessment;grant 不存在/越界/过期 → MissionDeniedError

**回归**:现有 `test_execution_gates.py`(T8 全链)不改也须通过——grant 是 opt-in,无 grant_id 行为不变。

---

## 8. 里程碑

1. **M1(Phase A 完成)**:grant 全链路(domain→service→审批门→handler→repo→migration)+ handler 去死代码。**v0.6.0**
2. **M2(Phase B 完成)**:LLMPlanner + mission_create 工具 + 降级。**v0.6.1**
3. 每里程碑跑全门禁(ruff/mypy/forbidden linter/`pytest --cov-fail-under=80`)+ CHANGELOG + release

---

## 9. 风险与缓解

| 风险 | 缓解 |
|---|---|
| grant 越权(scope 包含性误判) | covers_scope 精确定义为"每个 target 单独匹配",复用已修复的 `_target_matches`(v8 Fix A);含测试钉住 |
| LLM 选择劣质用例 | required 下限 + risk_cap 过滤 + 降级路径;LLM 影响面限于"加类" |
| agent 滥用 grant 刷扫描 | grant 有时间窗 + revoke;rate 由既有 scope limits 控制 |
| 审批门回归 | T8 全链测试 + 新增 grant 路径测试双覆盖 |

---

## 10. 验收标准

1. [ ] agent 持 grant 可完成 plan_approve + assessment_start(审计含 grant_id)
2. [ ] agent 无 grant 调用同工具 → HUMAN_REQUIRED(行为不变)
3. [ ] agent 建 grant → DENY
4. [ ] scope 越界/过期/revoked grant → 明确拒绝文案
5. [ ] mission_create(target, intent) → LLM 选类生成 plan,required 恒在
6. [ ] LLM 不可用 → 确定性降级,mission 仍可完成
7. [ ] 全门禁绿 + 覆盖率 ≥80%