# ADR：peer-worker 容器档（Strix 接入偏离加固基线）

> **状态**：已决策
> **日期**：2026-08-04
> **关联**：P2 Strix Peer Agent Plan；`docs/architecture/peer-agents.md`；ADR-014 / ADR-A4（外部 agent 采纳先例）

## 1. 背景

SecOpent 工具 adapter 运行在**加固容器档**下（cap-drop ALL、只读根文件系统、无 Docker socket），确保扫描工具无法逃逸或修改宿主。但 Strix（usestrix/strix v1.4.x，Apache-2.0）自身依赖 Docker sandbox 执行其内部嵌套容器——这与加固容器档的"无 Docker socket + 只读根"约束直接冲突。

若强行将 Strix 塞入加固容器档，需剥离其 Docker sandbox 能力，等同于阉割 agent 核心功能；若允许加固容器挂载 Docker socket，则所有工具 adapter 均获得宿主容器控制权，违反最小权限原则。

因此需要一条有记录的架构偏离路径：**peer-worker 容器档**。

## 2. 决策与补偿控制

### 决策

新增"peer-worker"容器运行档，专供经评审采纳的外部 peer agent（当前仅 Strix）使用。该档位与加固工具容器档并行存在，不替代、不降级后者。

peer-worker 容器档特征：

| 属性 | 值 | 说明 |
|------|-----|------|
| 镜像引用 | digest 钉死（PEER_IMAGE_CATALOG） | 供应链完整性同工具容器 §8.1 |
| 资源限制 | `--memory=4096m --cpus=2` | 防 LLM agent 失控消耗 |
| 容器标签 | `secopent.peer_run=<run-id>` | Emergency Stop 可定向终止 |
| 交换目录 | bind mount `/exchange`（input.json ↔ out/） | host↔container 数据交换唯一通道 |
| Docker socket | 挂载 `/var/run/docker.sock` | Strix 内部 sandbox 必需；构成第二层隔离边界 |
| 网络 egress | M5 nftables 范围（同工具容器路线图） | 当前未实施，列为后续加固项 |
| LLM 凭证 | 仅通过容器 env 注入 | 不落盘、不进 input.json |

### 补偿控制

peer-worker 档偏离加固基线的风险由以下控制补偿：

1. **应用层 scope 门禁不变**：PeerAgentService.launch 对 targets 做 ScopeSnapshot 校验，越界目标拒绝启动（同 P0 契约）。
2. **instruction 范围注入**：entrypoint 接收的 input.json 含明确 instruction（"Test ONLY the provided targets..."），agent 行为受文本约束。
3. **墙钟 / 成本熔断**：容器 `--timeout` 硬限 + PeerAgentBudget.max_cost_units 软限，超限标记 BUDGET_EXCEEDED，保留已有证据。
4. **Emergency Stop 标签覆盖**：全局 EmergencyStop 覆盖 `secopent=execution` 标签一键停止所有执行容器（含 peer-worker）。
5. **镜像签名 + digest 钉死**：PEER_IMAGE_CATALOG 记录 digest，版本升级须同步改 Dockerfile + composition 常量 + 本 ADR。
6. **Docker socket 风险限定**：socket 挂载仅供 Strix 内部 sandbox 使用；Strix 自身作为安全研究工具，其 sandbox 设计目标是隔离而非扩权。peer-worker 容器以非 root 用户（UID 65532）运行，降低 socket 滥用面。
7. **网络 egress 限制**：列为 M5 nftables 加固范围，与工具容器路线图对齐。

## 3. 被否选项

| 选项 | 否决原因 |
|------|----------|
| ① Strix 直接跑宿主 | 隔离最差：agent 进程 + LLM 调用 + 可能的 payload 执行全在宿主上，无任何容器边界。比 peer-worker 档风险高一个数量级。 |
| ② 注册 Strix 自定义 local backend 免 Docker | agent shell 命令直接落宿主执行，等价于选项①的变体；且绕过 harness 的统一容器治理链路，审计链断裂。 |
| ③ Docker-in-Docker（dind） | 性能损耗大（storage driver 嵌套）、镜像拉取重复、root 权限需求更高；Strix 原生支持外部 Docker socket，无需 dind。 |
| ④ 改造加固容器档兼容 Docker socket | 破坏所有工具 adapter 的安全假设；一个 agent 的需求不应拉低全局安全水位。 |

## 4. 后续行动

- M5 nftables 实施后，为 peer-worker 容器补网络 egress 白名单。
- 若 peer-worker 档需容纳第二个 agent（Shannon P3），复审本 ADR 的补偿控制是否充分。
- 监控 Strix sandbox 的实际 Docker API 调用模式，评估是否需要 socket proxy 收窄权限面。
