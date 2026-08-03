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

---

## peer-worker 容器档（P2）

> ADR：`sepcs/2026-08-04-adr-peer-worker-container-profile.md`

peer agent（如 Strix）不能放入加固工具容器档——Strix 自身需要 Docker socket 驱动内部 sandbox，与加固档的 cap-drop ALL + 只读根冲突。因此引入**独立治理档"peer-worker"**：

- **digest 钉死**：PEER_IMAGE_CATALOG 记录镜像 digest，版本升级须同步改 Dockerfile + composition + ADR
- **资源限制**：`--memory=4096m --cpus=2`，防 LLM agent 失控
- **交换目录**：bind mount `/exchange`（input.json ↔ out/），host↔container 唯一数据通道
- **Docker socket 挂载**：供 Strix 内部 sandbox；第二层隔离由 Strix 自身提供
- **补偿控制**：应用层 scope 门禁不变、instruction 范围注入、墙钟/成本熔断、Emergency Stop 标签覆盖、非 root 用户运行

## Strix 接入（P2）

```
PeerAgentService.launch("strix")
  → PeerAgentRegistry 查找 strix descriptor（v1.4.1, adopted_external）
  → StrixBackend.build_invocation
      ├─ 写 /exchange/input.json（run_id + targets + instruction）
      └─ LLM key 仅走容器 env（不落盘）
  → ContainerPeerAgentHarness.execute（docker run, digest-pinned）
  → StrixBackend.parse_report（vulnerabilities.json → PeerAgentFinding）
  → normalize 双门禁（scope + catalog）→ Observation / Rejected
  → propose_replan_from_outcome（新资产 → PlanVersionProposal，人审）
```

关键文件：
- `src/secopent/infrastructure/peer_agents/strix_report.py` — vulnerabilities.json 解析 + CWE 归一
- `src/secopent/infrastructure/peer_agents/strix_backend.py` — invocation 构建 + report 收集
- `src/secopent/infrastructure/peer_agents/composition.py` — descriptor 注册 + service 工厂
- `src/secopent/application/peer_replan.py` — 响应式再规划提案

## Secret 路径

LLM API key **仅通过环境变量**进入 peer-worker 容器：

```
SECOPENT_PEER_LLM_KEY (或 LLM_API_KEY)
  → secret_lookup dict
  → StrixBackend.__init__
  → PeerInvocation.env["LLM_API_KEY"]
  → docker run --env LLM_API_KEY=...
```

key 不写入 input.json、不落盘、不进 CAS。缺失时 build_invocation 抛 KeyError（配置错误，不是运行时错误）。

## A/B 验收说明

A/B 价值验收脚手架位于 `tests/e2e_real/test_peer_strix_ab.py`：

- **跳过条件**：docker CLI 缺失 OR 无 LLM key env → 自动 skip，不阻塞 CI
- **输出**：`test-results/strix_ab.json`（baseline vs peer observation count + rejected + run status）
- **断言**：仅守护流程完整性（报告文件落盘），不断言价值数字
- **P3 衔接**：该 JSON 作为 P3 observation gate 的输入基线
