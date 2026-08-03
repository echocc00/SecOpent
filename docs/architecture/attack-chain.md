# 攻击链（AttackChain）

> 状态：P2b 基线。ChainEngine + 三假设源 + 补证投影已落地；Asset Graph（M4）接入后升级资产价值判定。
> 设计来源：`specs/2026-08-04-strix-shannon-layered-integration-design.md` §9；ADR-004（oracle N/N，非 LLM 判定）。

攻击链是 ConfirmedFinding 之间的有序链接，表达"从 A 漏洞到 B 漏洞的攻击路径"。核心原则：**LLM/peer 只贡献 HYPOTHESIS，任何一环的确认权只在 oracle**；一环未确认 = 全链不得 CONFIRMED。

## 状态机

```
HYPOTHESIS ──(首环 oracle 确认)──→ PARTIALLY_VERIFIED
    │                                      │
    │                              (全环 oracle 确认)
    │                                      │
    └──────────────────────────────→ CONFIRMED_CHAIN
    
    任意状态 ──(oracle 证伪任一环)──→ REFUTED
```

| 状态 | 含义 | 条件 |
|---|---|---|
| HYPOTHESIS | 纯假设，无环被 oracle 确认 | 所有 link 均为 pending |
| PARTIALLY_VERIFIED | 部分验证，首环已确认但后续环待补证 | links[0] confirmed, 存在 pending |
| CONFIRMED | 已验证攻击链 | 所有 link 均为 confirmed |
| REFUTED | 已证伪 | oracle 判定任一环不成立 |

## 三种假设源

| 源 | 标识 | 信任级 | 说明 |
|---|---|---|---|
| 确定性模板匹配 | `template` | 高 | `chain_templates.default_chain_templates()` 中策展的已知攻击模式，CWE+asset 子序列匹配 |
| LLM 提议 | `llm_proposal` | 低 | LLM 根据 findings 上下文推断的链，仅提议不确认 |
| Peer agent 声称 | `peer_claim` | 低 | 外部 agent 报告的链关系，untrusted |

**关键约束**：无论哪种源创建的链，只有引用了 `FindingStatus.VALIDATED` finding 的 link 才算 confirmed。LLM/peer 声称一个 finding 已确认但该 finding 实际是 CANDIDATE → 该 link 保持 pending。

## 补证闭环

ChainEngine 对每条链中的 pending link 生成 `PendingVerificationTask`：

```
PendingVerificationTask:
  key: str              # 唯一任务键（用于去重和追踪）
  chain_id: str         # 所属链
  required_cwe: tuple   # 需要验证的 CWE 族
  asset_hint: str       # 目标资产提示
```

这些任务投影到 oracle 验证队列，形成**补证闭环**：

1. ChainEngine 产出假设链 + 补证任务
2. 补证任务进入 oracle 队列（与 reactive re-planning 共享调度）
3. Oracle 验证完成 → finding 升级为 VALIDATED
4. ChainEngine 重新评估 → 链状态推进（HYPOTHESIS → PARTIALLY_VERIFIED → CONFIRMED）

### 与响应式再规划的关系

补证任务是 `peer_replan.propose_replan_from_outcome` 之外的第二个真实触发源。Peer 发现新资产触发 plan version proposal；链补证触发现有资产的深度验证。两者共同构成"响应式再规划"的输入面：

- **peer_replan**: 广度扩展（新资产 → 新 scope）
- **chain_engine**: 深度扩展（已有资产 → 验证缺失环节）

两者产出的 proposal/task 都需经人工审批或自动策略裁决后才执行。

## LLM 边界声明

继承 ADR-004 核心原则并扩展到链级别：

- LLM 可以**提议**攻击链（hypothesis_source = llm_proposal）
- LLM **不能确认**任何链环——确认权只在 oracle
- LLM 声称某 finding 已确认但该 finding 非 VALIDATED → link 保持 pending
- 报告呈现时明确区分"已验证攻击链"与"建议优先修复路径"

## 复合严重度规则

```python
composite_severity(link_severities, *, asset_critical):
    top = max(link_severities)           # 取最高单环严重度
    if asset_critical:
        top = min(top + 1, CRITICAL)     # 关键资产升一级，CRITICAL 封顶
    return top
```

- 基础：max(各环严重度)
- 关键资产加成：+1 级（HIGH → CRITICAL, MEDIUM → HIGH, ...）
- 封顶：永远不超过 CRITICAL
- `asset_critical` 暂固定 False；Asset Graph（M4）落地后由图查询注入

## 文件结构

| 文件 | 职责 |
|---|---|
| `domain/findings/attack_chain.py` | AttackChain / ChainLink / ChainStatus / composite_severity |
| `domain/findings/chain_templates.py` | AttackChainTemplate / default_chain_templates / match_template |
| `application/chain_engine.py` | ChainEngine: 三假设源 + 补证投影 |
| `application/ports/chain_proposals.py` | ChainProposal / ChainProposalSource Protocol |
| `application/report_renderer.py` | render_chain_section: 报告攻击链章节 |
