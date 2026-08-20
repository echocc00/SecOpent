# ReasoningLoop v0.7.9 — A/B 验收结果记录（research record）

> **状态：pending A/B run** — 真实验收尚未执行。需要 Docker + 三靶场（Juice Shop / crAPI / vulhub）+ LLM key，在 Linux 主机上运行：
> ```
> py -3.12 -m pytest tests/e2e_real/test_reasoning_loop_ab.py
> ```
> 或批量脚本：
> ```
> py -3.12 scripts/ab_reasoning_loop.py
> ```
> 本文件是**脚手架/模板**：判据表 + 数据占位 + 决策签名栏。**不包含任何伪造的结果数字**——真实数据待验收运行后回填（后续 follow-up）。

---

## 1. 用途

对「仅 catalog（确定性 floor）」vs「catalog + ReasoningLoop + DIFF_SEMANTIC」在三靶场上做 A/B，量化：

- **oracle 确认增量**（oracle-confirmed findings 增加数）
- **误报率**（oracle REFUTED / 候选总数）
- **单次总成本**（LLM token + 墙钟）
- **用户审批次数**

判据（权威 spec §10）：**oracle 确认增量 > 0 且单次成本 < 对照组 1.5x → 放行（RELEASE）；否则冻结循环功能（FREEZE，保留 catalog floor 路径，循环功能标 `experimental` 停用）。**

---

## 2. 验收判据表（header）

| 目标 | oracle_confirmed_delta | FP-rate | cost_tokens | wall_seconds | approval_count | cost-ratio vs 1.5x | verdict |
|---|---|---|---|---|---|---|---|
| **juice_shop** | — | — | — | — | — | — | pending |
| **cr_api** | — | — | — | — | — | — | pending |
| **vulhub** | — | — | — | — | — | — | pending |
| **AGGREGATE** | — | — | — | — | — | — | **pending** |

> **注**：以上数据单元格在真实验收运行后回填（见 §1 运行命令）。当前 `pending`，**不是** FREEZE，更不是 RELEASE——是没有运行。

---

## 3. 放行 / 冻结决策规则（spec §10）

| 条件 | 动作 |
|---|---|
| `oracle_confirmed_delta > 0` **且** `cost_ratio < 1.5x`（单次成本 < 对照组 1.5 倍） | **RELEASE** — 放行循环功能，建议发版 + 更新 CHANGELOG |
| 否则（delta ≤ 0 **或** cost_ratio ≥ 1.5x） | **FREEZE** — 冻结循环功能，保留 catalog floor 路径，循环标 `experimental` 停用 |

**误报率（advisory，不改 CI 结果）**：`false_positive_rate = oracle REFUTED / candidates`。若实验组误报率较对照组升高 >1.5x（`FP-ratio > 1.5x`），即使增量 > 0 也**建议观察/复核**并记录到本报告，但**不改变 CI 判定**（A/B 是研究判断，非回归测试）。

> **A/B 不是 CI 门禁**：CI 只保证测试进程完整性与报告文件存在（`assert out_path.exists()`），不硬断价值数字。硬门禁是下方 §4 的**人工签名**。

---

## 4. Decision Sign-off（人工签名，硬门禁）

> 由授权人（作者/评审人）在真实运行并回填 §2 数据后，手写判定与签名。

- **判定（RELEASE / FREEZE）**：
- **依据（delta / cost-ratio / FP 备注）**：
- **AUTHORIZER**: ______
- **SIGNATURE**: ______
- **DATE**: ______

---

## 5. How to run

### 5.1 pytest A/B 主测试（真 LLM，三靶场）
```bash
py -3.12 -m pytest tests/e2e_real/test_reasoning_loop_ab.py
```
- 需要 Docker + 靶场可达 + LLM key（`SECOPENT_PEER_LLM_KEY` 或 `LLM_API_KEY`）；否则 skip。
- 报告落盘 `test-results/reasoning_loop_ab.json`。

### 5.2 批量脚本（operator / 人工工具，非 CI 门禁）
```bash
py -3.12 scripts/ab_reasoning_loop.py                        # real proposer, 三靶场
py -3.12 scripts/ab_reasoning_loop.py --proposer mock        # mock proposer（无成本，走通流程）
py -3.12 scripts/ab_reasoning_loop.py --dry-run              # 无 Docker 也可打印计划 + 判据表模板
py -3.12 scripts/ab_reasoning_loop.py --targets juice_shop cr_api --out test-results/ab.json
```
- 复用 `test_reasoning_loop_ab.py` 的 A/B 驱动 helper（不动 fixture），聚合 JSON + 打印判据表 + 计算 RELEASE/FREEZE 判定。
- 成功聚合 exit 0（即使判定 FREEZE——这是研究）；硬错误（无 docker / 靶场不可达 / 用错参数）非零退出。

---

## 6. 数据来源 / 复现

| 项 | 来源 |
|---|---|
| 判据 | `spec §10`（权威 spec）+ `.hermes/plans/2026-08-19_070000-reasoning-loop-v079-ab-acceptance.md` Task 4 |
| A/B 运行逻辑 | `tests/e2e_real/test_reasoning_loop_ab.py`（Task 3, commit d4a623d） |
| 批量脚本 | `scripts/ab_reasoning_loop.py` |
| 报告 JSON | `test-results/reasoning_loop_ab.json` |
| 靶场 | Juice Shop `:3000` / crAPI `:8000` / vulhub `:8081`（`tests/e2e_real/conftest.py` `_TARGETS`） |
