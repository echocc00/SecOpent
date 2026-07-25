# M3 模型驱动逻辑测试 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans.

**Goal:** 实现 AppModel + ModelBuilder 后端（OpenAPI/Postman/GraphQL/gRPC 导入 + LLM 起草 + 人校验 API）+ LogicTestGenerator 编排层（采纳 RESTler 跳步/乱序/重放 + Schemathesis 越界 + 自建不变量违反 + signature 幂等）+ ModelRegistry + DriftDetector，实现业务逻辑第二/三层确定性自动测试。

**Architecture:** AppModel 是版本化签名的形式描述（状态机+不变量+字段信任边界+角色能力+幂等性）。ModelBuilder 后端 API（M4 Web UI）支持有文档（OpenAPI/Postman/GraphQL/gRPC 半自动导入）和无文档（流量录制+LLM 起草）两路径。LogicTestGenerator 是编排层，从 AppModel 纯函数生成 5 类测试 Case（跳步/乱序/重放用 RESTler，越界用 Schemathesis，不变量违反自建），带 signature 幂等。LLM 仅第 1 步辅助起草，人校验签名，执行全程 LLM 无关。

**Tech Stack:** Python 3.11+, pydantic v2, PyYAML, httpx, prance (OpenAPI 解析), graphql-core, grpcio, Ed25519 (cryptography), RESTler, Schemathesis.

**DoD（对应主设计 §13 M3）:**
- 模型可建可签（AppModel + Ed25519）
- 5 类测试自动生成（跳步/乱序/重放/越界/不变量违反）
- signature 幂等（同模型重复跑同 signature）
- 漂移可检测（DriftDetector diff）

**依赖：** M0（Repository/Audit）+ M1（Observation/CoverageMatrix）+ M2（CaseRegistry/CaseEngine/oracle）

**参考：** 主设计 §4.6/§11.9/§11.10；ADR-005/012

---

## 0. 文件结构

```text
src/secopent/
  domain/
    appmodel/
      models.py          # AppModel, StateMachine, Transition, Invariant, Field, Role, Idempotency
      lifecycle.py       # DRAFT->LLM_PROPOSED->HUMAN_VALIDATED->SIGNED->PUBLISHED->SUPERSEDED
  application/
    model_builder.py     # ModelBuilder 后端 API（导入+LLM 起草+人校验）
    model_registry.py    # ModelRegistry（版本化+签名+生命周期）
    logic_generator.py   # LogicTestGenerator 编排层（RESTler/Schemathesis/自建不变量 + signature）
    drift_detector.py    # DriftDetector（OpenAPI/流量 diff）
  infrastructure/
    model_sources/
      openapi.py         # OpenAPI 3.0/3.1/Swagger 2.0 导入
      postman.py         # Postman v2.1 导入
      graphql.py         # GraphQL introspection schema 导入
      grpc_proto.py      # gRPC protobuf 导入
      traffic_record.py  # 无文档场景流量录制 + LLM 起草
    logic_strategies/
      restler_strategy.py    # 跳步/乱序/重放（调 RESTler Adapter）
      schemathesis_strategy.py  # 越界（调 Schemathesis Adapter）
      invariant_strategy.py  # 不变量违反（自建，无开源同类）
      orchestrator.py        # LogicTestGenerator 编排 + signature
tests/
  domain/test_appmodel.py
  application/test_model_builder.py, test_logic_generator.py, test_drift_detector.py
  infrastructure/test_openapi_import.py, test_invariant_strategy.py
```

---

## Task 1: AppModel Domain + 生命周期

**Files:** `domain/appmodel/models.py`, `domain/appmodel/lifecycle.py`, `tests/domain/test_appmodel.py`

- [ ] **Step 1: 测试** - AppModel（version/states/transitions/invariants/fields/roles/idempotency/digest/signature）；Transition（from/to/endpoint/params/idempotent）；Invariant（expr）；Field（name/type/range/trusted_source）；Role（id/capabilities）；生命周期状态机 DRAFT->LLM_PROPOSED->HUMAN_VALIDATED->SIGNED->PUBLISHED->SUPERSEDED；digest 用 M0 canonical_digest
- [ ] **Step 3: 实现** - frozen dataclass；生命周期 StrEnum；签名 Ed25519（cryptography）；SUPERSEDED 旧版不删
- [ ] **Step 5: 提交** `feat(appmodel): add app model domain and lifecycle`

关键代码：
```python
@dataclass(frozen=True, slots=True)
class Transition:
    id: str; from_state: str; to_state: str
    endpoint: str; params: tuple[str,...]; idempotent: bool

@dataclass(frozen=True, slots=True)
class Invariant:
    id: str; expr: str  # 如 "cart.total >= 0"

@dataclass(frozen=True, slots=True)
class Field:
    name: str; type: str; range: tuple[object, object] | None
    trusted_source: str  # "server" | "client"

@dataclass(frozen=True, slots=True)
class AppModel:
    version: str; app_id: str
    states: tuple[str,...]; transitions: tuple[Transition,...]
    invariants: tuple[Invariant,...]; fields: tuple[Field,...]
    roles: tuple[Role,...]; idempotency: dict[str, bool]
    out_of_scope_rules: tuple[str,...]  # 人声明不覆盖的复杂规则
    digest: str; signature: str | None
```

## Task 2: ModelBuilder 后端（有文档：OpenAPI/Postman/GraphQL/gRPC 导入）

**Files:** `infrastructure/model_sources/openapi.py`, `postman.py`, `graphql.py`, `grpc_proto.py`, `application/model_builder.py`, `tests/infrastructure/test_openapi_import.py`

- [ ] **Step 1: 测试** - OpenAPI 3.0/3.1/Swagger 2.0 解析 -> 端点+参数草稿；Postman v2.1 解析；GraphQL introspection schema；gRPC protobuf；导入产生 DRAFT 模型
- [ ] **Step 3: 实现** - OpenapiImport（prance 解析 paths/parameters/responses）；PostmanImport（item/request 解析）；GraphQL introspection query；gRPC protobuf reflection；ModelBuilder.import(source_type, data) -> DRAFT AppModel
- [ ] **Step 5: 提交** `feat(model-builder): add openapi postman graphql grpc import`

## Task 3: ModelBuilder 无文档路径（流量录制 + LLM 起草）

**Files:** `infrastructure/model_sources/traffic_record.py`, `tests/infrastructure/test_traffic_record.py`

- [ ] **Step 1: 测试** - 被动代理录制请求/响应流量 -> 聚类端点 -> 推断状态转移 -> LLM 起草状态机 -> DRAFT 模型；复杂状态机拆子模型
- [ ] **Step 3: 实现** - TrafficRecorder（代理捕获 HAR）；流量聚类（按路径+方法）；状态转移推断（响应字段->下一请求参数依赖）；LLM 起草（调 RemoteModelGateway，§12.11 约束）；拆子模型（按业务域）
- [ ] **Step 5: 提交** `feat(model-builder): add traffic recording draft path`

## Task 4: ModelBuilder 人校验 API

**Files:** `application/model_builder.py`（扩展），`tests/application/test_model_builder.py`

- [ ] **Step 1: 测试** - 人校验补不变量（LLM 推不出的业务规则）；标 trusted_source；定角色能力；Ed25519 签名；DRAFT->HUMAN_VALIDATED->SIGNED
- [ ] **Step 3: 实现** - ModelBuilder.validate(model_id, human_corrections) -> HUMAN_VALIDATED；sign(model_id, private_key) -> SIGNED；LLM 全程不裁决不签名
- [ ] **Step 5: 提交** `feat(model-builder): add human validation and signing`

## Task 5: LogicTestGenerator 编排层 + signature 幂等

**Files:** `application/logic_generator.py`, `infrastructure/logic_strategies/orchestrator.py`, `tests/application/test_logic_generator.py`

- [ ] **Step 1: 测试** - 从签名 AppModel 生成 5 类测试 Case（跳步/乱序/重放/越界/不变量违反）；每 Case 带 signature = sha256(app_model_digest + test_class + generation_strategy_version)；同模型重复跑同 signature；CoverageMatrix 按 signature 去重；AppModel 微改用 signature diff 算增量
- [ ] **Step 3: 实现** - LogicTestGenerator.generate(app_model) -> list[Case]（origin=model_generated）；调 RestlerStrategy/SchemathesisStrategy/InvariantStrategy；signature 字段；增量 diff（仅 changed signature 重生成）；generation_strategy_version 独立版本
- [ ] **Step 5: 提交** `feat(logic-gen): add 5 class generator with signature idempotency`

## Task 6: RESTler 策略（跳步/乱序/重放）

**Files:** `infrastructure/logic_strategies/restler_strategy.py`, `tests/infrastructure/test_restler_strategy.py`

- [ ] **Step 1: 测试** - 调 RESTler Adapter（M1 已加）从 AppModel 生成序列测试；跳步（A->C 跳 B）；乱序（C before A）；重放（pay 两次）；输出 Case（origin=model_generated, test_class=skip_step/out_of_order/replay）
- [ ] **Step 3: 实现** - RestlerStrategy.generate(app_model) -> Cases；从 transitions 生成 OpenAPI 喂 RESTler；RESTler 输出 -> Case（带 signature）
- [ ] **Step 5: 提交** `feat(logic-gen): add restler strategy for skip out of order replay`

## Task 7: Schemathesis 策略（越界）

**Files:** `infrastructure/logic_strategies/schemathesis_strategy.py`, `tests/infrastructure/test_schemathesis_strategy.py`

- [ ] **Step 1: 测试** - 调 Schemathesis Adapter 从 AppModel fields 生成 boundary 测试；越界（qty=-1/price=0.01/溢出）；输出 Case（test_class=boundary）
- [ ] **Step 3: 实现** - SchemathesisStrategy.generate(app_model) -> Cases；从 fields range 生成 property-based 测试；Schemathesis 输出 -> Case
- [ ] **Step 5: 提交** `feat(logic-gen): add schemathesis boundary strategy`

## Task 8: 不变量违反策略（自建，无开源同类）

**Files:** `infrastructure/logic_strategies/invariant_strategy.py`, `tests/infrastructure/test_invariant_strategy.py`

- [ ] **Step 1: 测试** - 从 AppModel invariants 生成违反测试；如 `cart.total >= 0` -> 生成 qty=-1 + 优惠券让 total 变负；输出 Case（test_class=invariant_violation）
- [ ] **Step 3: 实现** - InvariantStrategy.generate(app_model) -> Cases；解析 invariant expr；构造违反输入（约束求解简化版：枚举字段边界组合尝试违反）；输出 Case
- [ ] **Step 5: 提交** `feat(logic-gen): add invariant violation strategy`

## Task 9: ModelRegistry（版本化 + 发布 + 同步）

**Files:** `application/model_registry.py`, `tests/application/test_model_registry.py`

- [ ] **Step 1: 测试** - ModelRegistry.publish(model) -> PUBLISHED + 版本+digest；per-Assessment 快照；跨评估复用（同应用模型导入新 Assessment）；跨实例签名 bundle（复用 M1 UpdateManager）；SUPERSEDED 旧版不删
- [ ] **Step 3: 实现** - ModelRegistry CRUD + 生命周期；快照（app_model_snapshot_id）；bundle 导出导入（复用 UpdateManager）；Audit 全程
- [ ] **Step 5: 提交** `feat(model-registry): add versioned registry with bundle sync`

## Task 10: DriftDetector（漂移检测）

**Files:** `application/drift_detector.py`, `tests/application/test_drift_detector.py`

- [ ] **Step 1: 测试** - 重新导入 OpenAPI/Postman/爬取 -> diff 当前模型 -> 标记新增/移除/变更端点；CI 触发；漂移产生新 DRAFT；触发回归测试
- [ ] **Step 3: 实现** - DriftDetector.check(app_model_id) -> DriftReport；diff endpoints/states/transitions；新增端点标记"未建模"；CI 集成钩子；漂移触发 LogicTestGenerator 重生成 + 回归
- [ ] **Step 5: 提交** `feat(drift): add model drift detector`

## Task 11: 模型生成 Case 的特殊处理

**Files:** `application/logic_generator.py`（扩展），`tests/application/test_logic_generator_special.py`

- [ ] **Step 1: 测试** - model_generated Case 可自动通过 STATIC_CHECKED + VALIDATED（模型已签名）；Intrusive 类仍需人审；Passive/Low 可自动发布；复用 M2 CaseRegistry；out_of_scope_rules 标记不覆盖
- [ ] **Step 3: 实现** - LogicTestGenerator 标 Case.origin=model_generated；CaseService 快速通道（跳过 STATIC_CHECKED 重复，模型签名传递信任）；Intrusive 仍人审
- [ ] **Step 5: 提交** `feat(logic-gen): add model generated case fast path`

## Task 12: M3 质量门 + 文档

- [ ] ruff/mypy + pytest 全绿 + 5 类生成 signature 幂等验证
- [ ] `docs/architecture/model-driven-logic.md` + `docs/appmodel/schema.md`
- [ ] 提交 `docs(m3): close model driven logic baseline`

---

## M3 最终验收

- [ ] AppModel 可建可签（4 类导入 + 流量录制路径）
- [ ] 5 类测试自动生成（跳步/乱序/重放/越界/不变量违反）
- [ ] signature 幂等（同模型重复跑同 signature，CoverageMatrix 去重）
- [ ] DriftDetector 漂移可检测
- [ ] ModelRegistry 版本化 + bundle 同步
- [ ] model_generated Case 快速通道
- [ ] LLM 仅起草，人校验签名，执行全程 LLM 无关
- [ ] ruff/mypy/pytest 全绿

## 下一步

M3 通过后，写 M4 Agent 接口+编排+报告+Web Case Studio 详细计划。M4 依赖 M0-M3 全部就绪。
