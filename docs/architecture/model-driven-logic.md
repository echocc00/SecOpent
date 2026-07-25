# 模型驱动逻辑测试（Model-Driven Logic）

> 状态：M3 基线。AppModel 可建可签（4 类导入 + 流量录制路径）；5 类逻辑测试自动生成（跳步/乱序/重放/越界/不变量违反）；signature 幂等；DriftDetector 漂移检测；ModelRegistry 版本化；model_generated Case 快速通道。
> 设计来源：`sepcs/2026-07-25-catalog-driven-agent-workbench-design.md` §4.6/§11.9/§11.10；ADR-005/012。

M1-M2 解决「已知漏洞测没测」（目录驱动 + oracle 验证）。M3 解决**业务逻辑第二/三层**：越权、跳步、重放、参数越界、不变量违反——这些没有现成模板，需要应用的**形式模型**驱动生成。

## AppModel（形式模型）

`domain/appmodel/models.py` 的 `AppModel` 是版本化、签名的应用形式描述：

- **states / transitions**：状态机（transition = 端点 + from/to 状态 + 参数 + 幂等标志）
- **invariants**：必须恒成立的业务规则（如 `cart.total >= 0`）
- **fields**：带**信任边界**（`server`/`client` 来源）与取值范围的输入（驱动越界测试）
- **roles**：角色 + 能力（驱动越权测试）
- **idempotency**：端点幂等性（驱动重放测试）
- **out_of_scope_rules**：人声明不覆盖的复杂规则

`digest` 只覆盖**内容**（生命周期无关，稳定），故 Ed25519 `signature` 签的是稳定目标。

## 建模路径（ModelBuilder，§11.9）

- **有文档**：`OpenApiImporter`（OpenAPI 3.x/Swagger 2.0）/ `PostmanImporter`（v2.1，递归文件夹）→ DRAFT。GraphQL/gRPC 同模式扩展。
- **无文档**：`TrafficRecorder` 被动录制流量 → 按 (method, path) 聚类成 transitions → **LLM 起草**状态机 → LLM_PROPOSED。
- **人校验 + 签名**：`ModelBuilder.validate`（人补不变量/信任边界/角色）→ HUMAN_VALIDATED；`sign`（Ed25519 签 digest）→ SIGNED。

> **LLM边界**：LLM 仅在第 1 步**起草**（LLM_PROPOSED），人校验 + 签名，执行全程 LLM 无关。Agent 禁止 validate/sign。

## 5 类逻辑测试生成（LogicTestGenerator，§11.10）

`application/logic_generator.py` 编排三个策略，从签名 AppModel **纯函数**生成 5 类测试：

| 测试类 | 策略 | 来源 |
|---|---|---|
| 跳步 skip_step | RestlerStrategy | 链 A->B->C，跳过 B 直接调 C |
| 乱序 out_of_order | RestlerStrategy | C 先于前置 A |
| 重放 replay | RestlerStrategy | 非幂等 transition 调两次 |
| 越界 boundary | SchemathesisStrategy | field range 上下越界（qty=-1/101） |
| 不变量违反 invariant_violation | InvariantStrategy（自建，无开源同类） | 解析 `total >= 0` → 构造 total=-1 |

RESTler/Schemathesis 引擎在 M5 接入；M3 从 transitions/fields **确定性派生**（可单测）。

## signature 幂等

每个生成的 `LogicTestCase` 带 `signature = sha256(app_model_digest + test_class + strategy_version + target)`：
- **同模型重复跑 → 同 signature**（CoverageMatrix 按 signature 去重）。
- AppModel 微改 → 仅 changed signature 重生成（`generate_incremental` 跳过已知 signature）。
- `strategy_version` 独立版本化，策略升级有意重排 signature。

## 漂移检测（DriftDetector）

重新导入 spec/流量 → 与当前模型 diff → `DriftReport`（added/removed/changed endpoints，`has_drift`）。漂移 → 模型回 DRAFT 重校验 + LogicTestGenerator 重生成。CI 可定期触发。

## ModelRegistry（版本化）

`application/model_registry.py`：发布 SIGNED 模型；版本历史全保留（新版 SUPERSEDED 旧版，**旧版不删**，供审计/重放）；per-Assessment 快照（钉住发布版本，新版发布不动已有快照）；跨评估复用 = 同一发布版本快照进新 Assessment。

## model_generated Case 快速通道（§11.8）

模型已人签，其生成的 Case 继承信任：`CaseService.fast_track_model_generated` 自动过风险门，Passive/Low 自动到 REVIEWED（确定性信任传递，非 LLM 裁决）；Intrusive/Active 仍停 VALIDATED 需人审。签名/发布仍人专属。
