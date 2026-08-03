# Peer Agents（低信任发现源）

> 状态：P0 骨架。PeerAgentService + Harness + 注册表已落地；真实 backend（Strix P2、Shannon P3）接入后填充镜像摘要与 parser。
> 设计来源：`sepcs/2026-07-25-catalog-driven-agent-workbench-design.md` §5；ADR-014 / ADR-A4（外部 agent 采纳先例）。

Peer agent 是与工具 adapter 同级的**低信任发现源**，只产 `Observation`，不直接确认漏洞。所有输出经 normalize 双门禁（scope + catalog）后入 oracle 队列，由验证层裁决。

## 定位

- 与 adapter 同级：走相同的 harness 容器执行、digest-pin、scope 门禁链路
- 只产 Observation：peer agent 永不写 `ConfirmedFinding`，确认权归 oracle
- 低信任：默认 `untrusted` 信任级，需显式提升至 `adopted_external_agent` 才允许接入

## 数据流

```
PeerAgentService.launch
  → 注册表查找 + 信任级检查 + scope 门禁
  → Harness 容器执行（docker run, digest-pinned）
  → normalize 双门禁（scope 校验 + catalog 白名单）
  → Observation 入 oracle 队列
  → OracleEngine N/N 复证 → ConfirmedFinding / Refuted
```

## 信任级

承 ADR-014 / ADR-A4 先例，peer agent 分两级：

| 信任级 | 含义 | 准入条件 |
|---|---|---|
| `adopted_external_agent` | 经评审采纳的外部 agent | 注册表显式声明 + 镜像 digest 固定 |
| `untrusted` | 未采纳 / 实验性 | 仅沙箱运行，产出标记低置信度 |

未在注册表的 agent 一律拒绝启动。

## 预算控制

每个 peer run 受两类预算约束：

- **墙钟超时**：容器 `--timeout` 硬限，超限强制 kill
- **成本类预算**：LLM token / API 调用上限，超限标记 `BUDGET_EXCEEDED`

预算超限**不丢弃证据**：已收集的 Observation 保留并标记原因，供 oracle 参考。

## Emergency Stop 关系

- 容器标签 `secopent.peer_run=<id>` 支持定向 stop（单 agent 终止）
- 全局 EmergencyStop 覆盖标签 `secopent=execution`，一键停止所有执行容器（含 peer agent）
- EmergencyStop 优先级高于单独 stop，确保紧急场景无遗漏

## P0 边界

- ✅ PeerAgentService、Harness、注册表、信任级模型、scope 门禁
- ✅ PEER_IMAGE_CATALOG 骨架（空，等待 P2/P3 填充）
- ❌ 无真实 backend 接入（Strix P2、Shannon P3）
- ❌ 无镜像 digest（首次 pull 后回填）
- ❌ 无 parser 实现（各 agent 输出格式适配在对应 phase）
