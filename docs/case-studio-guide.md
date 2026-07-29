# Case Studio 建模指南（Case Studio Guide）

> 面向操作手 / 建模者：把应用建模成 AppModel、人工校验、签名发布、生成逻辑测试、检测漂移。
> 状态：P3 §3.7。字段细节见 `docs/appmodel/schema.md`；页面布局见 `docs/web/case-studio.md`；跑评估见 `docs/user-manual.md`。

Case Studio 是 M3「模型驱动逻辑测试」的人机入口：人把应用的形式模型（AppModel）建出来、校验、签名，系统**确定性**地从签名模型生成逻辑测试。LLM 只在建模样阶段**提议**，绝不校验、签名或生成测试（LLM 边界）。

## 1. 核心概念

- **AppModel**：应用的声明式形式模型——状态机（states/transitions）、业务不变量（invariants）、带信任边界的字段（fields，`server`/`client`）、角色能力（roles）。字段全集见 `docs/appmodel/schema.md`。
- **digest**：模型**内容**的规范化 `sha256:` 摘要，构造时计算，不含 `status`/`signature`——故生命周期中稳定，是签名的目标。同内容 → 同 digest。
- **signature**：人对 `digest` 的 Ed25519 签名。**人签，LLM 永不签**。私钥由服务端 SecretStore 加密保管，前端/LLM 拿不到。
- **逻辑测试**：从 SIGNED 模型确定性派生的 5 类测试（见 §5），每个带幂等 signature。

## 2. 生命周期

```
DRAFT -> LLM_PROPOSED -> HUMAN_VALIDATED -> SIGNED -> PUBLISHED -> SUPERSEDED
```

- `DRAFT`：由文档导入（OpenAPI/Postman）产生。
- `LLM_PROPOSED`：导入时开 `use_llm`，LLM **提议**的 states/invariants 并入草稿；无 LLM 时也停在此态等人校验（可跳过 LLM 直达 `HUMAN_VALIDATED`）。
- `HUMAN_VALIDATED`：人补不变量 / 信任边界 / 角色后校验。
- `SIGNED`：人 Ed25519 签名——**生成测试的前提**。
- `PUBLISHED`：进 ModelRegistry（每评估快照）；新版把旧版置 `SUPERSEDED`，**旧版不删**。

转移由 `can_transition` 守卫；`SUPERSEDED` 为终态。乱序转移 → HTTP 409。

## 3. 建模（两种方式）

### 方式 A：导入规范（推荐）

`POST /appmodels/import`：

```json
{
  "source_type": "openapi",   // 或 "postman"
  "spec": { "...": "OpenAPI/Postman 文档 JSON" },
  "use_llm": true
}
```

- `source_type`：`openapi` / `postman`（确定性导入器，无 LLM）。
- 导入器先产出确定性 `DRAFT`（端点 → transitions）。
- `use_llm=true`：治理网关（RemoteModelGateway）让 LLM **提议**业务 states/invariants，并入草稿后注册为 `LLM_PROPOSED`，等人校验。LLM 不可用 / 返回不可解析 → 原样保留确定性草稿。
- `use_llm=false`：直接注册确定性 `DRAFT`。

### 方式 B：手写

`POST /appmodels`（`llm_proposed` 标志决定落 `DRAFT` 还是 `LLM_PROPOSED`），或 Web CaseStudio 页可视化编辑状态机图 / 不变量 / trust 边界 / 角色，底层同一 API。

编辑已存在模型：

- `PUT /appmodels/{app_id}/{version}`：原地改（仅 `DRAFT`/`HUMAN_VALIDATED`；已签名 → 用 revise）。
- `POST /appmodels/{app_id}/{version}/revise`（`new_version`）：从当前内容起一个新 `DRAFT` 版本（版本升级）。

## 4. 人工校验与签名

```
POST /appmodels/{app_id}/{version}/validate   {"actor_role": "human"}
POST /appmodels/{app_id}/{version}/sign       {"actor_role": "human", "key_id": "<可选>"}
```

- **校验 / 签名是人专属**：`actor_role="agent"` → 403（LLM 边界）。
- `sign` 用 `key_id` 指定的服务端签名密钥（缺省取最新未归档密钥）对 `digest` 签名；密钥列表见 `GET /signing-keys`。
- 错误码：404 未找到 / 403 agent 越权 / 409 乱序转移 / 422 校验失败（字段不变量违反）。

签名密钥管理（创建 / 轮换）见 `docs/deployment.md` §5。

## 5. 五类逻辑测试（原理）

`POST /appmodels/{app_id}/{version}/generate-tests` —— **要求模型已 SIGNED**（否则 409）。生成是签名模型的纯函数，**不经 LLM**：

| 测试类 | 含义 | 驱动来源 |
|---|---|---|
| `skip_step` | 跳过状态机必要步骤，看后端是否仍接受 | RESTler 序列策略 |
| `out_of_order` | 乱序执行转移，探竞态 / 状态校验缺失 | RESTler 序列策略 |
| `replay` | 重放**幂等**转移（`idempotent=true`），探重复扣款 / 重复提交 | RESTler 序列策略 |
| `boundary` | 字段 `range` 越界 / 类型边界值 | Schemathesis 边界策略 |
| `invariant_violation` | 构造违反业务不变量（如 `cart.total >= 0`）的输入 | 自建 Invariant 策略 |

**幂等 signature**：每个测试 `signature = sha256(app_model_digest | test_class | strategy_version | target)`。同模型 → 同 signature（CoverageMatrix 依此去重）；模型微改 → 只重生成变化的 signature（增量 diff，`generate_incremental`）。

生成的 `LogicTestCase` 被包成 `MODEL_GENERATED` 用例（单步 `logic.test`，风险类 ACTIVE），走用例快速通道：自动过风险门，ACTIVE 用例停在 `VALIDATED` **待人审**（不会自动执行）。

## 6. 漂移检测（drift）

应用会变，签名模型会过期。重新导入规范后做端点级 diff：

```
POST /appmodels/{app_id}/{version}/drift
{ "states": ["..."], "transitions": [ {"id","from_state","to_state","endpoint","params","idempotent"} ] }
```

返回 `DriftReport`：

- `added` / `removed`：新增 / 删除的端点。
- `changed`：`params` 或 `idempotent` 变化的端点。
- `has_drift`：任一非空即真。

**工作流**：检出 drift → 模型回 `DRAFT` 重新校验签名 → `generate-tests`（幂等 signature 只补变化部分）。CI 可定期跑 drift。

## 7. API 速查表

| 方法 路径 | 用途 | 备注 |
|---|---|---|
| `POST /appmodels` | 手写建模 | `llm_proposed` 定初态 |
| `POST /appmodels/import` | OpenAPI/Postman 导入 | `use_llm` 触发 LLM 提议 |
| `GET /appmodels` / `GET /appmodels/{app_id}/{version}` | 列表 / 详情 | |
| `PUT /appmodels/{app_id}/{version}` | 原地编辑 | 仅 DRAFT/HUMAN_VALIDATED |
| `POST /appmodels/{app_id}/{version}/revise` | 升版新 DRAFT | `new_version` |
| `POST /appmodels/{app_id}/{version}/validate` | 人工校验 | human-only |
| `POST /appmodels/{app_id}/{version}/sign` | 签名 | human-only，`key_id` 可选 |
| `POST /appmodels/{app_id}/{version}/generate-tests` | 生成逻辑测试 | 需 SIGNED |
| `POST /appmodels/{app_id}/{version}/drift` | 漂移 diff | 端点级 |
| `GET /signing-keys` / `POST /signing-keys` / `POST /signing-keys/{id}/rotate` | 签名密钥 | 创建 / 轮换 human-only |

错误码：404 未找到 · 403 agent 越权 · 409 乱序 / 未签名 · 422 校验失败。

## 8. 关键边界（务必理解）

- **LLM 只提议，不裁决**：LLM 可在导入时提议 states/invariants（落 `LLM_PROPOSED`）；**校验、签名、生成测试**均为确定性层 / 人专属。
- **签名是人专属**：`actor_role="agent"` 调 validate/sign/create-key/rotate 一律 403。
- **私钥不出服务端**：Ed25519 私钥加密存 SecretStore，前端只请求签名、永不持有私钥。
- **生成是确定性的**：同签名模型 → 同测试 signature，可去重、可增量、可复现。
