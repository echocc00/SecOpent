# M1 文档先行路线图

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** 把上一轮讨论里的 6 个方向“真实端到端 / 更多 Connector / 配置中心 / 调度 workflow / 重试与死信 / 连接器测试环境”全部落到仓库文档里，同时保证文档与实际代码一致。代码体量在 M1 阶段为 0，仅做文档修订与工程基纻修复。

**Architecture:** 文档保持 5 层结构（1）根 README 作为入口；（2） docs/ 下 4 篇主题文档；（3） docs/superpowers/specs/ 原设计规范保留；（4） docs/security/ 威胁模型；（5） docs/superpowers/plans/ 计划文件。

**Tech Stack:** Markdown, Mermaid (for diagrams), Python 3.12 (for `tests/test_docs_consistency.py`).

---

## 0. 现状对齐（M1 起点）

仓库现有文档状态：
- `README.md`：218 字节，仅一句“See docs/...design.md”。
- `docs/quickstart.md`：454 字节，5 行 docker compose 示例，未提及 Phase 0 / 6 个方向。
- `docs/security/threat-model.md`：1.1KB，仅 5 行信任边界。
- `docs/superpowers/specs/2026-07-24-security-assessment-operations-platform-design.md`：36.8KB、 20 节。
- `docs/superpowers/plans/2026-07-24-mvp-implementation-plan.md`：3.3KB。
- `docs/superpowers/plans/2026-07-24-next-development-roadmap.md`：15.9KB，不含 6 个方向。

本 M1 要求：
1. README 从 218 字节重写到 ≥3KB，覆盖 6 个方向 + 状态表 + 快照 + 后续链接。
2. 新增 4 篇 docs：`architecture.md` / `connectors.md` / `operations.md` / `roadmap.md`，每篇 ≥2KB。
3. 原设计规范与威胁模型保留，仅补“与 M1 文档的引用关系”。
4. 新增 `tests/test_docs_consistency.py`，扫描状态标记与路径引用。

预估总体量：新增 Markdown ≈0.05MB（<1% 仓库），代码变动限于 1 个测试文件 + 9 个文档。
---

## 1. 任务拆解（bite-sized）

### 阶段 0 – 工程基线对齐（0.5 day）
- [ ] **Task 0.1: 确认 7 个已知缺陷状态**
  - Files: `git status --short` + `git log --oneline`
  - 验收: `git status` 中修改文件 与 next-development-roadmap.md Phase 0 一致。
- [ ] **Task 0.2: 记录 README 当前字数**
  - 验收: 保存 `wc -c README.md` 输出。

### 阶段 1 – 根文档（README）（1 day）
- [ ] **Task 1.1: 重写 README 初稿**
  - Files: `README.md`（覆盖）
  - 步骤: 用 Python `io.open(..., encoding="utf-8", newline="\n")` 写入；覆盖 12 个块：一句话 / 状态表 / 6 个方向一句话 / 5 行快照 / 后续链接 / License。
  - 验收: `wc -c README.md` ≥3000。
- [ ] **Task 1.2: 状态表与 6 个方向全部出现**
  - 验收: `grep -E "^\| MVP " README.md` ≥1；`grep -E "^\| M1 " README.md` ≥1；`grep -cE "Shuffle|OpenCTI|Feishu|DingTalk|Cortex" README.md` ≥5。

### 阶段 2 – 架构 / 连接器 / 运维 / 路线图（2 days）
- [ ] **Task 2.1: 创建 `docs/architecture.md`**
  - Files: `docs/architecture.md`（新增）
  - 要求: Mermaid `graph TD` 结构图 + 业务数据流 + 8 条信任边界 + 6 个方向在架构中的位置表。
  - 验收: `wc -c docs/architecture.md` ≥2000；`grep -c mermaid docs/architecture.md` ≥1。
- [ ] **Task 2.2: 创建 `docs/connectors.md`**
  - Files: `docs/connectors.md`（新增）
  - 要求: 7 列表格 (Connector / 类别 / 状态 / 函数进入点 / 函数出口 / 验证资料 / 注释) 含 8 个连接器：MISP / Jira / Wazuh / Shuffle / OpenCTI / Feishu / DingTalk / Cortex；表后附“配置中心 / 调度 / 重试-死信”状态表。
  - 验收: `grep -cE "^\| " docs/connectors.md` ≥8；表中连接器名称出现 ≥8。
- [ ] **Task 2.3: 创建 `docs/operations.md`**
  - Files: `docs/operations.md`（新增）
  - 要求: 部署三套（compose / test stack / K8s TODO） + Connector 配置 + 调度 + 重试 + 可观测 + 升级回滚 + 安全，不少于 6 个 `##` 节。
  - 验收: `grep -c "^## " docs/operations.md` ≥6。
- [ ] **Task 2.4: 创建 `docs/roadmap.md`**
  - Files: `docs/roadmap.md`（新增）
  - 要求: 5 列表格（阶段 / 作业 / 交付物 / DoD / 状态）不少于 4 行；当前进度区 ≤5 行；Out of Scope 区 ≨8 行。
  - 验收: `grep -cE "^\| M" docs/roadmap.md` ≥4；`grep -c "Out of Scope" docs/roadmap.md` ≥1。
- [ ] **Task 2.5: 补 `quickstart.md` “After install” 6 点**
  - Files: `docs/quickstart.md`
  - 要求: 在 Tests 节后加 6 行：访问 /api/findings；docker compose logs api；跑 e2e_demo；查 architecture；查 connectors；查 operations。
  - 验收: `grep -c "After install" docs/quickstart.md` ≥1；6 项逐条出现。
- [ ] **Task 2.6: 补 `threat-model.md` 引用 architecture.md**
  - Files: `docs/security/threat-model.md`
  - 验收: `grep "docs/architecture.md" docs/security/threat-model.md` 命中。
- [ ] **Task 2.7: 补设计规范 `## M1 文档映射`**
  - Files: `docs/superpowers/specs/2026-07-24-security-assessment-operations-platform-design.md`
  - 验收: `grep -c "## M1 文档映射" docs/superpowers/specs/2026-07-24-security-assessment-operations-platform-design.md` ≥1。
- [ ] **Task 2.8: 修订 `next-development-roadmap.md`**
  - Files: `docs/superpowers/plans/2026-07-24-next-development-roadmap.md`
  - 要求: 文末加 `## M1 状态`，列出 5 篇新文档；原 6 个 Phase 保持不变。
  - 验收: `grep -c "## M1 状态" docs/superpowers/plans/2026-07-24-next-development-roadmap.md` ≥1。
- [ ] **Task 2.9: 修订 `mvp-implementation-plan.md` 状态为退出**
  - Files: `docs/superpowers/plans/2026-07-24-mvp-implementation-plan.md`
  - 要求: 首行加 `> Status: 已退出。`。
  - 验收: `head -3 docs/superpowers/plans/2026-07-24-mvp-implementation-plan.md | grep "已退出"` 命中。

### 阶段 3 – 一致性测试（0.5 day）
- [ ] **Task 3.1: 创建 `tests/test_docs_consistency.py`**
  - Files: `tests/test_docs_consistency.py`（新增，仅依赖标准库 + pathlib）
  - 要求: 7 项检查：README ≥3000；4 篇 docs 存在且 ≥2000；connectors.md 表中 8 个连接器名；roadmap.md 含 4 个 M 阶段；threat-model.md 引用 architecture.md；docs 中代码路径可读；状态字典不不一致。
  - 验收: `py -3.12 -m pytest tests/test_docs_consistency.py -v` 全绿。
- [ ] **Task 3.2: 全量测试绿**
  - 验收: `py -3.12 -m pytest -q` 仍然 ≥72 passed。

### 阶段 4 – 提交（0.5 day）
- [ ] **Task 4.1: `git status --short` 仅本 M1 文件**
  - 验收: 修改 + 新增文件不超过 11 个。
- [ ] **Task 4.2: `git add` + commit**
  - 验收: `git log --oneline -n 1` 显示 `docs(m1): ...`。
- [ ] **Task 4.3: 互引检查**
  - 验收: `m1-documentation-roadmap.md` 与 `next-development-roadmap.md` 互含 `M1`。
---

## 2. DoD (M1 验收定义)
- [ ] 18 个 Task 全部勾选。
- [ ] `py -3.12 -m pytest -q` 全绿（原 72 + 新增一致性测试）。
- [ ] `wc -c README.md` ≥3000。
- [ ] `wc -c docs/architecture.md docs/connectors.md docs/operations.md docs/roadmap.md` 每个 ≥2000。
- [ ] `git status --short` 中仅本 M1 列表文件。
- [ ] commit message 含 `docs(m1)`。
---

## 3. 风险与缓解
| 风险 | 控制手段 |
|---|---|
| README 写不到 3KB | 加限 12 个块，每块 ≥80 字 |
| connectors.md 表格起冲突 | 严格 7 列，不引入另行结构 |
| 中文丢字节 | Python `io.open(..., encoding="utf-8")` 加 `\uXXXX` 转义，不用 PowerShell 直接写中文 |
| 测试失败抦住 | 推出前跑 `py -3.12 -m pytest -q`，不走 finishing-a-development-branch |
---

## 4. 不在 M1 范围
- 任何 Python 代码依赖（Shuffle / OpenCTI / Feishu / DingTalk 等都不动）。
- docker-compose.test.yml（M3）。
- 推送远端仓库（M4）。
- 7 个 Phase 0 工程小修复（保留在 next-development-roadmap.md Phase 0）。
---

## 5. 与后续阶段接口
- M2 进入代码时，只需修改 `connectors.md` 表中“状态”列。
- M3 进入 docker-compose.test.yml 时，只需在 `operations.md` 增加 1 个 `## Test Stack` 节。
- M4 进入 finishing-a-development-branch 时，`roadmap.md` 是 DoD 参考，`test_docs_consistency.py` 是门槛。
---

## 6. 与上一轮 plan 的区别
- `next-development-roadmap.md`：**代码** 路线图，4 周到 1.0。
- `m1-documentation-roadmap.md`：**文档** 路线图，3-4 天到 M1 。

> 本计划不修改代码体量，不动 docker-compose、不动 CI。如需推进到 M2，请另开 M2 计划。
