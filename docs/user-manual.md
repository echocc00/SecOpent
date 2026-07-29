# 用户手册（User Manual）

> 面向操作手（operator）：安装、启动、跑一次完整授权评估、审批、查看 finding、生成报告。
> 状态：P3 §3.7。配套 `docs/deployment.md`（生产部署）、`docs/case-studio-guide.md`（建模）。

## 1. 安装

```bash
py -3.12 -m pip install -e ".[dev]"
py -3.12 -m pytest -q          # 验证安装（应全绿）
```

前端（可选，Web Case Studio）：

```bash
cd src/secopent/interfaces/web && npm install
```

## 2. 启动

**开发模式**（API :8000 + Vite dev :5173，前端经 /api 代理）：

```bash
# 终端 1：API
py -3.12 -m uvicorn secopent.interfaces.api.main:create_app --factory --port 8000
# 终端 2：前端
cd src/secopent/interfaces/web && npm run dev    # http://localhost:5173
```

**生产模式**（单命令，SPA + API 同 :8000）：

```bash
bash scripts/build_web.sh    # 见 docs/deployment.md
```

启动即种子默认 TestCatalog（OWASP WSTG + CIS 基线），计划生成开箱即用。

## 3. 跑一次完整评估

1. **新建项目**：Dashboard → New Assessment，或 `POST /projects`。
2. **定义并冻结 scope**：填 include（目标 URL/IP/域名，一行一个）、exclude、ports、限速（rps/concurrency/max_requests）→ Freeze（生成不可变 scope 快照 + digest）。
3. **生成计划**：选模式（Approval / Scope Autopilot）→ 生成计划（Planner 按 catalog 生成风险分层 DAG：recon → active → intrusive）。
4. **审批**：ApprovalCenter 看到待审批项 → 批准（选风险类 + 能力）或拒绝（填理由）。**审批是人专属**（LLM 边界）。
5. **执行**：批准后评估进入执行（编排器按计划跑适配器容器）。
6. **查看结果**：Findings 页（筛选 + 证据三层）、AssessmentDetail（DAG + 事件流 + Job）。

## 4. 审批

- ApprovalCenter → Pending 标签：待审批评估（含 plan digest + scope digest）。
- **批准**：选批准的风险类（passive/low/active/intrusive/destructive）+ 能力 → Approve。
- **拒绝**：填理由 → Reject（理由入审计链）。
- History 标签：已决策记录。

## 5. 查看 Finding

- Findings 页：按 severity / oracle 结论筛选，点行开抽屉。
- 证据三层：**RAW**（原始，受限）/ **REDACTED**（脱敏）/ **SUMMARY**（摘要）。RAW 永不覆盖（取证完整性）。
- **oracle 结论**（confirmed/refuted/inconclusive）由 oracle N/N 复现决定，**非 LLM**（LLM 边界）。

## 6. 生成报告

`POST /reports` {assessment_id, title, polish?}：

- 数据驱动渲染（executive summary / scope / method / findings / evidence / coverage matrix / appendix）。
- 数字来自确定性层（finding 数、覆盖率），**非 LLM 手写**。
- `polish=true`：LLM 润色 executive summary 叙事（加 `executive_summary_polished` 段，数字不变）。
- completeness gate：全段填充 + 零未验证 finding + 覆盖绿 + 证据 digest 齐。

## 7. CLI

```bash
secopent version                 # 版本
secopent doctor                  # 确定性核心健康检查
secopent backup --db <db> --out <dir>   # SQLite 一致性快照备份
```

## 8. 关键边界（务必理解）

- **LLM 只提议，不裁决**：LLM 可提议 AppModel / 草拟风险 / 润色报告；**确认 finding、定 severity、审批、签名、发布、改 scope** 均为确定性层/人专属。
- **scope 强制**：所有执行经 ScopeEnforcer（10 步链 + DNS rebinding 防御）；越界拒绝。
- **审计链**：所有关键动作入哈希链（+ 可选 HMAC），可验完整性。
