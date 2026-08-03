# Strix / Shannon 分层集成设计（Peer Agent 层 + 知识移植 + 工程内化 + AttackChain）

> 日期：2026-08-04
> 状态：已批准（brainstorming 定稿），待实现计划
> 前置调研：`docs/research/ai-pentest-landscape-2026-08.md`、`docs/research/shannon-vs-strix-architecture.md`
> 关联决策：ADR-014（pentest-ai 采纳）、A4 spike（`sepcs/2026-07-27-a4-ptai-spike-findings.md`）、O4=B（知识层开源分层）
> 关联里程碑：M4（Asset Graph / Finding Correlation / MCP 工具注册表）

---

## 1. 背景与动机

SecOpent 是 catalog-driven、agent-native 的**授权**渗透测试工作台：LLM 只提议，确定性层（TestCatalog / CoverageMatrix / OracleEngine / PolicyEngine）裁决，人审批签发。当前执行能力以确定性工具适配器（nuclei/nmap/subfinder 等）+ case 引擎为主。

**能力盲区**（行业调研结论，见 research 文档）：
1. **自主发现**：业务逻辑漏洞、未知攻击面、跨漏洞攻击链——确定性模板工具的系统性盲区；AI 自主渗透 agent（Strix/Shannon/XBOW 类）恰以此为卖点
2. **漏洞链构建**：孤立漏洞列表 vs 已验证攻击路径——商业竞品（XBOW、Horizon3）的核心叙事，SecOpent 尚无此能力
3. **灰盒工程细节**：凭据预检、登录态复用、阶段失败回滚——Shannon 已有成熟模式

**互补性判断**：Strix/Shannon 强在"发现"，SecOpent 强在"裁决与治理"。前者的产出（未验证 findings）恰是后者最擅长治理的对象。A4 spike 已为此类集成定调：**外部自主 agent 作 peer（低信任发现源），非 oracle 后端；产出必经本项目 oracle N/N 确认**。

## 2. 已确认的决策（brainstorming 记录）

| # | 决策 | 选择 |
|---|------|------|
| D1 | 集成目标 | 全都要：发现能力 + 知识移植 + 工程模式，分层集成 |
| D2 | Shannon AGPL 处理 | 进程隔离调用（独立容器/CLI，仅文件与参数交互，不链接不复制代码） |
| D3 | 集成路径 | 三层混合：先立契约 → 知识/工程移植 → 运行时接入，按风险排序 |
| D4 | Strix 多 agent 编排 | 不移植编排机器；采纳两个思想（响应式再规划、专家化上下文）；Strix 编排完整运行于 peer 容器内 |
| D5 | 漏洞链 | AttackChain 作为 SecOpent 一等公民能力（P2b） |

## 3. 三项目对比摘要（决策依据）

| 维度 | Strix（46.9k★，Apache-2.0，Python） | Shannon（46.4k★，AGPL-3.0，TS） | SecOpent |
|------|-----------|-------------|---------------------|
| 编排 | LLM 动态 agent 图（root 编排 + spawn 专家子 agent） | Temporal 固定 DAG + git checkpoint/rollback | 规则 Planner + Job Lease（确定性） |
| 裁决 | LLM（验证 agent 也是 LLM） | LLM 产出 + 确定性 queue gate | OracleEngine N/N 独占（LLM 永不标记 Confirmed） |
| 范围控制 | Prompt 注入（弱） | 路径 deny 扩展（中） | PolicyEngine+ScopeEnforcer+EgressGuard+Permit（强） |
| 知识 | Markdown 技能手册 30+ 漏洞类（Apache-2.0 可引用） | 阶段 prompt 模板（固定 5 类） | TestCatalog/CoverageMatrix 策展 + case DSL |
| 执行沙箱 | Docker + Caido sidecar | Docker + repo 只读 + playwright | digest 钉死 + cap-drop + 只读根（最严） |
| 编排优劣势 | 响应式发现、专家化上下文、链式协作；但不可审计、覆盖无保证、成本高 | 可恢复（durable+回滚）、可预测；但覆盖面固定 5 类 | 可审计、覆盖构造性保证、成本有界；但缺响应式与自主发现 |

**编排对比结论**：两者优化目标互斥（发现自主性 vs 治理确定性）。Strix 编排机器不进 SecOpent 核心，但其两个思想确定性化吸收：
- **响应式再规划**：发现事件（新资产/确认漏洞/链补证需求）→ Planner 生成新 Plan Version → 人审 → 执行（衔接 M4 DoD "Agent 追加动作生成新 Plan Version"）
- **专家化上下文**：未来 SecOpent LLM 提议 agent 采用"一 agent 一任务 + 聚焦知识注入"（P1a 手册即素材），仅用于提议层

## 4. 总体架构

```
SecOpent 控制平面（不变，门禁一切）
│  Project / Scope / Permit / PolicyEngine / EgressGuard
│  Orchestrator / Job Lease（不引入 Temporal）
│
├─ [P0] PeerAgentPort（application/ports 新增）
│    ├─ PeerAgentDescriptor: name/version/license/trust_level/capabilities/cost_class
│    ├─ launch(PeerAgentRun) → 容器执行（digest 钉死、加固 flags 同源、egress 策略同源）
│    └─ collect(run) → PeerAgentReport{findings[]}（全部 untrusted）
│
├─ [P2] StrixAdapter（Apache-2.0，可较深集成）
├─ [P3] ShannonAdapter（AGPL 进程隔离防火墙）
│
├─ 确定性归一化：peer finding → CWE/OWASP 映射 → 必须命中本次 Assessment
│  TestCatalog 必修类 → 进 oracle 队列（目录外噪音拒收）
├─ OracleEngine（不变）：N/N + canary + OOB
├─ [P2b] ChainEngine：Asset Graph + Findings → 链假设 → 逐环补证
└─ Approval / 签名 / 报告（不变；报告新增攻击链首屏）
```

**核心不变式**：peer agent 与 nuclei/nmap 同级（Observation 来源）；Permit 增加两类预算（墙钟时长、LLM 成本类）；MCP 面不暴露 peer agent 的 shell/docker（不破 M4 规则）。

## 5. P0：PeerAgentPort 契约层（约 3-5 天，mock 可测）

| 层 | 交付 |
|----|------|
| domain | `domain/peer_agents/models.py`：PeerAgentDescriptor / PeerAgentRun / PeerAgentFinding（provenance：agent、run_id、raw_ref）；信任级 `adopted_external_agent`（沿用 A4 决策） |
| application | `application/peer_agents.py::PeerAgentService`：launch 前 Permit+Scope 校验、运行生命周期、预算熔断（时长/成本）、Emergency Stop（revoke permit + kill 容器） |
| infrastructure | `infrastructure/peer_agents/harness.py`：容器运行壳，复用 SubprocessContainerExecutor 加固 flags（digest 钉死/--user 65532/--cap-drop ALL/--read-only/tmpfs noexec/资源限制） |
| 归一化 | finding → CWE/OWASP 映射 + 目录过滤（未命中必修类 → 拒收并审计记录） |

**验收（契约测试，mock peer agent）**：
- [ ] launch → collect → 归一化 → oracle 队列端到端绿
- [ ] 未登记 agent / 信任级不符 → 拒跑
- [ ] finding 目标越出 scope → 拒收 + 审计
- [ ] 预算熔断触发 → 容器终止 + permit 标记
- [ ] Emergency Stop → revoke + kill

## 6. P1a：知识移植（Strix skills → 策展层；含链模板）

**来源**：`strix/skills/vulnerabilities/*.md`（30+ 手册：攻击面→侦察→利用，Apache-2.0）。**不整段复制**，转译为两种形态：

1. **case DSL 种子**：对照现有 5 个逻辑测试类，补齐缺类（JWT、SSRF、反序列化、竞态、原型链污染等首期 8-10 份高价值手册）→ case 骨架 → TestCatalog 必修映射（每条目 ≥1 fixture，覆盖率门禁把关）
2. **策展知识注入**：攻击面清单/侦察端点表结构化为知识条目，供 SecOpent LLM 提议环节消费（只影响提议，不影响裁决）
3. **链模板（新增，服务 P2b）**：已知攻击链模式策展入库（SSRF→云 metadata→凭据泄露；认证绕过+IDOR→水平越权；SQLi→拖库→撞库 等），映射 ATT&CK tactic

**合规**：NOTICE / LICENSE-THIRD-PARTY 增加 Strix (Apache-2.0) 归属；每移植条目标注 provenance。
**验收**：N 份手册移植（首期 8-10），每份 ≥1 fixture；覆盖率退化门禁绿；链模板 ≥5 条。

## 7. P1b：工程内化（Shannon 模式重写，零代码复制）

| 模式 | SecOpent 落点 | 验收 |
|------|---------------|------|
| 阶段级 checkpoint/rollback | Job Lease 生命周期加工作状态快照（工作目录 tar/git 快照），阶段失败自动回滚；衔接 Case Studio drift detection | 回滚单测 + 集成测试 |
| Preflight 凭据验证 + 登录态复用 | 灰盒前置：确定性登录验证（表单提交+响应断言，不用 LLM）+ session 状态持久化，认证类 case 复用 | Juice Shop 认证流真实通过 |
| Deliverables 文件契约 | 执行阶段产物统一目录/命名/schema（参考 deliverables 模式），服务审计与 LLM 提议上下文 | schema 契约测试 |

注：Shannon 的 queue gate 不重建——oracle N/N + CoverageService 是更强对应物。

## 8. P2：Strix peer agent（Linux 前置）

- **环境门禁**：Linux worker 可用（Windows 开发环境只跑 mock 契约测试——承 ptai spike 教训）
- **镜像**：官方或自制镜像 digest 钉死；LLM key 走 secrets store（不进 prompt/日志/evidence，M5 规则提前适用）
- **调用面**：`strix --target <in-scope 目标> --instruction "<范围与规则注入>"`；回收 `strix_runs/<run>/`
- **解析器**：Strix finding → CandidateFinding（severity/CWE/payload/evidence 引用）
- **响应式再规划接线**：Strix 报告的新资产/新发现 → 触发 Plan Version 追加流程（D4 决策①落地）

**验收（A/B 价值判据）**：三靶场（Juice Shop/crAPI/vulhub），"仅确定性工具" vs "+Strix"，对比 oracle 确认的增量发现数、误报率、单次成本（LLM 费用+时长）。增量 > 0 且成本可接受 → 放行 P3；否则停在 P2。

## 9. P2b：AttackChain 漏洞链构建（依赖 M4 Asset Graph / Finding Correlation）

**原则**：链 = 已确认事实之上的图推理；LLM/peer 只贡献假设，确认权只在 oracle（"LLM 永不标记 Confirmed"扩展到链级）。

- **Domain**：`domain/findings/attack_chain.py`——AttackChain = 有序 ChainLink[]；每环引用 ConfirmedFinding ID 或 PendingVerification；状态机 HYPOTHESIS → PARTIALLY_VERIFIED → CONFIRMED_CHAIN / REFUTED
- **三种假设源**：
  1. 确定性关联规则：Asset Graph × ConfirmedFindings 图匹配链模板（P1a③策展）
  2. LLM 提议（仅提议）：基于已确认发现提出链假设
  3. peer agent 报告中的链声称（untrusted，逐环映射）
- **补证闭环**：链中未确认环 → 自动生成验证任务进 oracle 队列（响应式再规划的第一真实触发源）；一环未确认 = 全链降级
- **复合严重度**：确定性规则（环严重度函数 + 触达资产价值升级），入 VerificationMethodRegistry 同层策展
- **报告**：CONFIRMED_CHAIN 首屏（路径图 + 逐环证据引用）；HYPOTHESIS_CHAIN 列"建议优先修复路径"章节

**验收**：靶场构造链式漏洞（Juice Shop 登录绕过→IDOR 组合），HYPOTHESIS → 全环补证 → CONFIRMED_CHAIN 全链路绿；断一环正确降级。

## 10. P3：Shannon peer agent（AGPL 防火墙 + 观察门）

- 独立容器（镜像 digest 钉死），交互面仅两个：CLI 参数进、`.shannon/deliverables/` 目录出；无代码导入、无链接、无共享卷越权
- Deliverables markdown 解析器 → CandidateFinding（白盒模式：repo 只读挂载）
- **观察门**：Shannon 仅覆盖 5 类（injection/xss/auth/ssrf/authz）且需源码，与 Strix 重叠度高——P2 验收后评估增量价值；不足则降级为"白盒场景备选 peer"或不做
- **AGPL 合规**：ADR 记录进程隔离证据 + 归属声明清单

**验收**：crAPI（有源码）白盒端到端过 oracle；AGPL 隔离 checklist 全绿。

## 11. YAGNI（明确不做）

- ❌ 引入 Temporal（Job Lease 够用）
- ❌ 移植 Strix 多 agent 编排机器（违背确定性编排哲学；编排留在 peer 容器内）
- ❌ 移植 Shannon permission system / pi harness（PolicyEngine/EgressGuard 更强）
- ❌ autofix（超出授权工作台定位）
- ❌ peer agent 直连 MCP 工具面（M4 "MCP 不暴露 shell/docker/python"不破）
- ❌ 重建 queue gate（oracle N/N + CoverageService 是更强对应物）

## 12. 风险与缓解

| 风险 | 缓解 |
|------|------|
| LLM 成本失控（自主 agent 单次扫描可达数十美元级） | P0 预算熔断（时长+成本类）；A/B 判据含成本维度；靶场先行 |
| Windows 开发环境依赖问题（ptai 教训） | 真实运行一律 Linux worker；Windows 仅 mock 契约测试 |
| peer 输出非结构化、解析脆弱 | 解析器契约测试 + 版本钉死；解析失败降级为 raw_ref 人审，不静默丢弃 |
| AGPL 意外传染 | 仅进程隔离交互；ADR 合规清单；代码审查禁引 Shannon 代码 |
| Strix 上游快速演进（发布节奏极快） | 镜像 digest 钉死；升级走知识层同款 staging→签名→激活流程 |
| peer 发现冲击 oracle 队列容量 | 归一化层目录过滤先行；oracle 队列限流 + 优先级（必修类 > 目录外拒收） |

## 13. 阶段顺序与依赖

```
P0 契约层 ──┬──> P2 Strix peer ──> P2b AttackChain（依赖 M4 Asset Graph/Correlation）
            │         └──> P3 Shannon（观察门，可选）
P1a 知识移植（含链模板）──┘
P1b 工程内化（独立并行，无依赖）
```

每阶段独立可验收；P2 → P3 设价值门；P2b 依赖 M4 基座，若 M4 未落地则 P2b 顺延。

## 14. 待实现计划阶段明确的事项

- PeerAgentPort 的 Python Protocol 签名细节与现有 ports 命名对齐
- Strix `--instruction` 范围注入的具体文案与防越权测试
- 链模板策展的首批清单与 ATT&CK 映射表
- 预算模型的 cost_class 定义（与 secrets/model gateway 的计费口径）
- Shannon deliverables schema 的实测样本采集
