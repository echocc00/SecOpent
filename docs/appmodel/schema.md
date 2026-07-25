# AppModel Schema

> `domain/appmodel/models.py` — 版本化、签名的应用形式模型。本文档描述其字段、不变量与生命周期。

## 字段

| 字段 | 类型 | 说明 |
|---|---|---|
| `app_id` | str | 应用标识（必填，非空） |
| `version` | str | 模型版本（必填，非空） |
| `states` | tuple[str, ...] | 状态集（必填，非空） |
| `transitions` | tuple[Transition, ...] | 状态转移 |
| `invariants` | tuple[Invariant, ...] | 业务不变量 |
| `fields` | tuple[Field, ...] | 带信任边界的输入字段 |
| `roles` | tuple[Role, ...] | 角色与能力 |
| `idempotency` | tuple[tuple[str, bool], ...] | 端点幂等标志（不可变，替代可变 dict） |
| `out_of_scope_rules` | tuple[str, ...] | 人声明不覆盖的复杂规则 |
| `status` | AppModelStatus | 生命周期状态（默认 DRAFT） |
| `digest` | str | 内容规范化摘要（`sha256:`，构造时计算） |
| `signature` | str \| None | Ed25519 签名（签 digest；人签，LLM 不签） |

## 子结构

### Transition（状态转移）
| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | str | 转移 id（必填） |
| `from_state` / `to_state` | str | 起止状态（必填） |
| `endpoint` | str | 端点（如 `POST /checkout`，必填） |
| `params` | tuple[str, ...] | 参数名 |
| `idempotent` | bool | 是否幂等（驱动重放测试） |

### Invariant（不变量）
- `id`：标识；`expr`：规则表达式（如 `cart.total >= 0`）。InvariantStrategy 解析 `expr` 生成违反测试。

### Field（字段）
- `name` / `type`（必填）；`range`：`(low, high)` 可选（驱动越界测试）；`trusted_source`：`server` | `client`（信任边界，必填且受限）。

### Role（角色）
- `id`（必填）；`capabilities`：能力元组（驱动越权测试）。

## digest 与 signature

- `digest` 覆盖**内容**（app_id/version/states/transitions/invariants/fields/roles/idempotency/out_of_scope_rules），**不含** status/signature——故 digest 在生命周期中稳定，signature 签的是稳定目标。
- 同内容 → 同 digest；内容变 → digest 变。
- `signature` 由人通过 Ed25519 对 `digest` 签名；LLM 永不签名（LLM边界）。

## 生命周期（lifecycle.py）

```
DRAFT -> LLM_PROPOSED -> HUMAN_VALIDATED -> SIGNED -> PUBLISHED -> SUPERSEDED
```

- `DRAFT`：有文档导入产生；`LLM_PROPOSED`：无文档流量+LLM 起草产生（可 DRAFT 直达 HUMAN_VALIDATED，跳过 LLM）。
- `HUMAN_VALIDATED`：人校验补不变量/信任边界/角色。
- `SIGNED`：人 Ed25519 签名。
- `PUBLISHED`：进 ModelRegistry；新版 SUPERSEDED 旧版，**旧版不删**。
- `can_transition(src, dst)` 守卫转移顺序；SUPERSEDED 为终态。

## 校验不变量

- `app_id` / `version` 非空；`states` 非空。
- Transition：id/from_state/to_state/endpoint 非空。
- Invariant：id/expr 非空。
- Field：name/type 非空；trusted_source ∈ {server, client}。
- Role：id 非空。
- 违反抛 `DomainValidationError`。
