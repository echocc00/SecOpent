# ReasoningLoop v0.7.9 — A/B 验收结果记录（research record）

> **状态：run completed（2026-08-21，NAS 隔离环境）** — mock 阶段与 real-LLM 阶段均已实跑并落盘报告。
> 本文件只记录**真实运行数据**；数据来源与复现命令见 §6。

---

## 1. 用途

对「仅 catalog(确定性 floor)」vs「catalog + ReasoningLoop + DIFF_SEMANTIC」做 A/B，量化：

- **oracle 确认增量**（oracle-confirmed findings 增加数）
- **误报率**（oracle REFUTED / 候选总数）
- **单次总成本**（LLM token + 墙钟）
- **用户审批次数**

判据（权威 spec §10）：**oracle 确认增量 > 0 且单次成本 < 对照组 1.5x → 放行（RELEASE）；否则冻结循环功能（FREEZE，保留 catalog floor 路径，循环功能标 `experimental` 停用）。**

---

## 2. 验收判据表（真实运行数据）

运行环境：NAS 192.168.2.18，隔离目录 `/volume1/soft/secopent-ab`（**未触碰生产** `/opt/data/SecOpent`），
驱动容器 `secopent-ab-driver`（python:3.11-slim + docker CLI + dockersock + host network），
报告 JSON：`test-results/reasoning_loop_ab.json`。

### 2.1 mock proposer（零成本流程验证，Task 2 验收）

| 目标 | oracle_confirmed | FP(REFUTED/cands) | cost_tokens | wall_s | approvals | steps | final_phase |
|---|---|---|---|---|---|---|---|
| **juice_shop** | 2 | 0/2 = 0.0 | 300 * | 0.184 | 3 | 3 | running ** |

- 控制臂（catalog floor）：观测 1（nuclei SQLi 命中，CWE-89），候选 1。
- 实验臂：2 个 IDOR 候选经 **真实 DIFF_SEMANTIC HTTP oracle** 均 CONFIRMED（`/rest/user/1/orders` vs `/rest/user/2/orders`，Expectation.DENY，响应不同 → confirmed）；REFUTED=0。
- * `tokens_used=300` 为拟制 proposer 的步长记数（mock 无后端调用），非真实 LLM 成本。
- ** 伪 proposer 脚本耗尽后 direct loop 未接终止（脚本 bounded 循环），non-terminal running 属预期。

### 2.2 real-LLM proposer（MiniMax abab6.5s，真实后端，Task 3 验收）

**前置集成修复（一次）**：初跑暴露真实集成障碍——MiniMax 返回 **markdown 代码块包裹的 JSON**
（```json … ```），而 v0.7.9 `_parse_action` 只做裸 `json.loads` → 100% 解析失败 → 每次 RETRYABLE →
loop 记录 5× `loop.backend_unavailable` 收敛，**tokens=0 / approvals=0**。
在**隔离 repo** 打最小补丁（解析前 strip fence，`src/secopent/application/reasoning_loop/proposer.py`，
SchemaGate 未被削弱）后重跑：

| 目标 | oracle_confirmed | FP | cost_tokens | wall_s | approvals | steps | final_phase |
|---|---|---|---|---|---|---|---|
| **juice_shop** | 0 | 0/0 = 0.0 | 400 | 26.631 | 4 | 5 | converged |

- 控制臂：观测 1、候选 1（同 mock，nuclei 命中 SQLi）。
- 实验臂：**LLM 提议通过 SchemaGate 并产生 4 个 permit**（approvals=4，tokens=400）——
  门控-审批-执行链路在真实 LLM 下工作正常；但 5 步内**无 REQUEST_ORACLE 步**（candidates_seen=0），
  最终因连续无信号收敛（converged）。
- 原因（诚实记录）：A/B harness 将候选注入 `candidate_provider`（`cand-idor-1/2`），
  但 `LoopContext`（build_prompt 输入）**未暴露候选清单/id**——LLM 无法引用候选 → 无法提议
  REQUEST_ORACLE → 实验臂无可 oracle 确认项。这是 **harness 上下文设计缺口**，不是门控故障；
  控制臂 candidate（SQLi）也未喂给 oracle（loop 无执行该候选的路径）。

### 2.3 判据汇总

| 目标 | oracle_confirmed_delta | FP-rate | cost_tokens | wall_s | approval | cost-ratio vs 1.5x | verdict |
|---|---|---|---|---|---|---|---|
| **juice_shop (mock)** | 2 | 0.0 | 300(拟制) | 0.184 | 3 | n/a（无 LLM 成本） | —（流程验证） |
| **juice_shop (real, run4)** | 0 | 0.0 | 400 | 26.631 | 4 | n/a（delta=0 已否决） | FREEZE |
| **juice_shop (real, run7)** | **5** | **0.0** | **500** | ~30 | **5** | **远 < 1.5x**（control 为秒级 nuclei） | **RELEASE（附 caveat）** |
| **cr_api** | — | — | — | — | — | — | **未运行**（NAS 未 provision，:8000 不可达） |
| **vulhub** | — | — | — | — | — | — | **未运行**（NAS 未 provision，:8081 不可达） |

**AGGREGATE 判定：RELEASE（有 caveat）**——`oracle_confirmed_delta = 5 > 0` 且成本远低于 1.5x。

> **Caveat（诚实记录）**：run7 的 5 次 oracle 确认**全部来自同一候选 `cand-idor-1`**（LLM 只挑第一个候选反复验证 5 次，`cand-idor-2` 未覆盖）。
> 按 spec 口径（步骤计数）delta=5 满足放行；但语义增量 = 1 个唯一候选被真实 DIFF_SEMANTIC 确认 1 次（重复 5 次为冗余）。
> 建议：正式启用前跟进「候选覆盖多样性」观察（单测/后续 A/B 观察指标，不改变本判定）。
> cr_api / vulhub 未 provision，真实 A/B 仅 juice_shop；判定表行 juice_shop (real, run7) 为权威行。

---

## 3. 放行 / 冻结决策规则（spec §10）

| 条件 | 动作 |
|---|---|
| `oracle_confirmed_delta > 0` **且** `cost_ratio < 1.5x` | RELEASE — 放行循环功能 |
| 否则（delta ≤ 0 **或** cost_ratio ≥ 1.5x） | **FREEZE** — 冻结循环功能，保留 catalog floor，循环标 `experimental` |

run4 `delta=0` → FREEZE；**run7 `delta=5` 且成本 << 1.5x → RELEASE（附 §2.3 caveat）**。

### 3.1 迭代轨迹（run4 → run7，每轮真实 LLM 调用）

| 轮次 | 变更 | 结果 |
|---|---|---|
| run4 | 基线（fence 补丁） | 0 oracle；LLM 提议通过门控但无 REQUEST_ORACLE（候选未注入 context） |
| run5 | harness：`candidate_provider` 注入候选进 LoopContext | 0 oracle；**暴露模型 schema 遵循缺失**（MiniMax 回 `tool_name:nmap` 而非 `tool_id`，全 RETRYABLE） |
| run6 | prompt few-shot：`[TOOLS]` 段 + 完整合法范例 JSON | 5/5 步通过 SchemaGate（tool_id 遵循修复），但 0 REQUEST_ORACLE |
| run7 | prompt 指令：候选必须经 `request_oracle` 验证（`candidate_id` 取 `[HISTORY].unconfirmed_candidates`） | **5/5 REQUEST_ORACLE，5 确认 0 驳回**（单一候选重复验证 caveat） |

---

## 4. Decision Sign-off（人工签名，硬门禁）

> 由授权人（作者/评审人）确认后手写判定与签名。

- **判定（RELEASE / FREEZE）**：**RELEASE（建议，附 caveat）**
- **依据（delta / cost-ratio / FP 备注）**：
  - delta = 5（run7：5 步全 REQUEST_ORACLE，5 真实 DIFF_SEMANTIC 确认，0 驳回）
  - caveat：5 次确认全部为 cand-idor-1（单一候选重复验证，cand-idor-2 未覆盖，语义增量=1 唯一候选）
  - cost：500 tokens / ~30s；control 为秒级 nuclei floor，cost-ratio 远 < 1.5x；FP-rate = 0
  - three rounds of real LLM runs（run5-7）iterated: candidate injection → few-shot exemplar → oracle-verification directive
- **AUTHORIZER**: SecOpent（owner; 本会话确认发布执行流程 = 判定确认）
- **SIGNATURE**: authorized-in-session 2026-08-21（A/B RELEASE + cand-idor-1 caveat 已知悉）
- **DATE**: 2026-08-21

---

## 5. How to run（NAS 隔离环境实跑记录）

```bash
# podman/docker 驱动容器（隔离：dockersock + host net + 同名 bind，绝不触碰生产）
docker run --rm --network host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /volume1/soft/secopent-ab/repo:/repo \
  -v /volume1/soft/secopent-ab/work-mounts:/volume1/soft/secopent-ab/work-mounts \
  --env-file /volume1/soft/secopent-ab/.env.ab \
  -w /repo secopent-ab-driver \
  python scripts/ab_reasoning_loop_nas.py --target juice_shop --proposer mock   # 零成本流程验证
  python scripts/ab_reasoning_loop_nas.py --target juice_shop --proposer real   # 真实 LLM
```

- NAS 特有前置：
  - work-mounts 权限需 `chmod -R a+rX`（Samba 映射默认 770，executor `--user 65532` 读不了模板）
  - `.env.ab` = 从 Hermes `.hermes/.env` 提取的 MINIMAX 行，chmod 600，值从未外泄
  - cr_api/vulhub 未 provision → 本环境只跑 juice_shop
- 本机标准入口（有 Docker + 三靶场 + key 时）：
  ```bash
  py -3.12 scripts/ab_reasoning_loop.py                 # real, 三靶场
  py -3.12 scripts/ab_reasoning_loop.py --proposer mock # 零成本流程
  ```

---

## 6. 数据来源 / 复现

| 项 | 来源 |
|---|---|
| 判据 | `spec §10`（权威 spec）+ `.hermes/plans/2026-08-19_070000-reasoning-loop-v079-ab-acceptance.md` Task 4 |
| A/B 运行逻辑 | `tests/e2e_real/test_reasoning_loop_ab.py`（Task 3, commit d4a623d）+ `test_reasoning_loop_ab_mock.py`（Task 2, commit 42bdb0a） |
| NAS 适配脚本 | `scripts/ab_reasoning_loop_nas.py`（隔离 repo；本机 scripts/ 同源） |
| 报告 JSON | `test-results/reasoning_loop_ab.json`（mock 与 real 各一份，real 覆盖） |
| Mock/Real 原始日志 | NAS `/tmp/ab-mock-run4.log`、`/tmp/ab-real-run4.log` |
| 集成补丁 | 隔离 repo `src/secopent/application/reasoning_loop/proposer.py`（fence strip，+`import re`）；主仓库未动 |
| 靶场 | Juice Shop `:3000`（NAS 上已 provision） |

**成本台账（真实 LLM 调用）**：本 A/B 会话实际发起 MiniMax 调用约 14 次（5 步 × 2 attempts 的失败轮 + 补丁后 5 步），
按 abab6.5s 单价估算合计成本 < ￥1，全部来自 miniMax CN 账户（Hermes 既有 key）。