# Dev Model 总交接 v2（T1-T4 完成后）

> **日期**：2026-07-29
> **写给**：开发模型（执行方）
> **角色**：设计 + 验收方，只做设计/验收，不写业务代码
> **目的**：你接手知道**现在在哪、下一步做什么、全部剩余任务、每项怎么做、何时找我验收**
> **核查基线**：git 实证 + 测试复跑（938 passed / ruff / mypy 217 / 工作树 @ 570b436）
> **本文档替代** `2026-07-29-dev-handoff-master.md`（那份是 T1 前写的，已过时）

---

## 0. 你现在的起点（已实证）

```
已交付：M0-M4 + Phase A + P0 + P1(W1-W11) + P3 的 7/8 项 + 横切 T1-T4
tag：v1.1-web（2026-07-28）
HEAD：570b436 perf: adapter --parallel N
测试：938 passed / ruff clean / mypy strict 217 文件 0 错
前端：npm run build clean，主包 244.7 KB gzip
E2E：Playwright 11/11 绿（含安全闸 agent 403）
生产：FastAPI StaticFiles + /api 双挂载 + SPA fallback 实证可用
```

---

## 1. 已完成清单（勿重做）

### P3（7/8 项，§3.9 验收清单）
- ✅ §3.1 默认 catalog 种子（`d884dad`，main.py:132 启动 seed）
- ✅ §3.3 LLM 3 调用点 + 边界测试（`d6d1073`）
- ✅ §3.4 知识层真实内容（`7f661b2`，OSV sync + 真实 checker + 签名 bundle）
- ✅ §3.5 性能四项全完成：SQLite WAL（`637e3a9`）+ SSE 背压（`4322761`）+ DAG 虚拟化（`df9f5b9`）+ adapter --parallel（`570b436`）
- ✅ §3.6 Monaco 本地化（`a2e21f7`）-- **残留已决策：选 C 接受 671KB**（离线优先，CDN 违背 W11 决策；CodeMirror 重写留 P4）。**§3.6 关闭，无需再做**
- ✅ §3.7 4 份文档（`bb7427e`）
- ✅ §3.8 生产加固（`1e6c28f`）
- ❌ §3.2 端到端编排 -- **唯一未完成的 P3 项，即 T5**

### 横切（T1-T4）
- ✅ T1 SAST 入 CI（`dd97e85`，bandit+gitleaks+pip-audit）
- ✅ T2 SSE 背压（`4322761`）
- ✅ T3 DAG 虚拟化（`df9f5b9`）
- ✅ T4 adapter --parallel（`570b436`）

### P2
- ✅ P2-占位 5 端点（`df4c620`，drift/stop/retry/health/report）

---

## 2. 下一步：T5（§3.2 端到端编排，硬门禁）

**T5 是 v1.1-stable 唯一未完成的 P3 项，也是核心硬门禁。**

**详细执行计划**：[`sepcs/2026-07-29-t5-orchestration-execution-plan.md`](../sepcs/2026-07-29-t5-orchestration-execution-plan.md)

**T5 真实工作量**（实测发现，非纯写测试）：
1. **补 `AdapterStepRunner`** -- `StepRunner` 当前只有 Protocol（`orchestrator.py:50`）无具体实现。需补胶水：`PlanStep.runner`（适配器名）-> adapter docker 执行 -> Observations -> StepResult
2. **写 3 场景 e2e_real** -- Web（Juice Shop）/ API（httpbin）/ 云（docker.sock），经 `Orchestrator.run_to_completion` 全链路

**T5 计划文档含**：
- §1 真实接口（PlanStep 字段 / Orchestrator 签名 / FindingCorrelator/CoverageService 位置）
- §2 `AdapterStepRunner` 完整代码骨架 + TDD 顺序
- §3 三场景测试骨架（8 步全链路：scope->plan->orchestrator->findings->oracle->coverage->report->audit）
- §4 预期 8 个集成 bug + 修法（planner-adapter 参数契约 / Job.from_step / observations 持久化 / Observation schema / RescanVerifier 适配 / evidence 落盘 / CoverageService 签名 / 审计 hash 顺序）
- §5 今天怎么开始（起靶场 -> TDD StepRunner -> 场景 1 修 bug -> 场景 2/3）
- §6 必停验收闸

**预期工期**：1 周（含修集成 bug 3-4 天）

**T5 完成后停下找我验收**，我验 3 场景 + bug 修复后才继续 T6。

---

## 3. 全部剩余任务清单

### 🔴 Phase 1：v1.1-stable 收尾（T5 + 横切并行）

| # | 任务 | 工期 | 依赖 | 详细设计 | 验收 |
|---|---|---|---|---|---|
| **T5** | §3.2 端到端编排 | 1w | 无（当前任务） | t5-orchestration-execution-plan §2-5 | 3 场景 e2e_real 绿 |
| T6 | P2-F crAPI/vulhub 四域真实扫 | 1-2w | T5 共享靶场 | v1.1-stable-final §5 | 6 e2e_real 绿 |
| T7 | ① CI 加固（frontend/browser/e2e-real/nft job+全 mypy+cov80） | 2-3d | 无，可并行 | cross-cutting §① | CI 5+ job 全绿 |
| T8 | ⑦ 备份恢复（restore+SecretStore 备份+runbook） | 2-3d | 无，可并行 | cross-cutting §⑦ | backup/restore round-trip |
| T9 | ② 发布流程（version 真源+CHANGELOG+release.sh） | 2d | 无，可并行 | cross-cutting §② | release.sh 一键出 tag |
| T10 | **tag v1.1-stable** | - | T5-T9 | v1.1-stable-final §7 | §3.9 清单全过 |

### 🟡 Phase 2：P2-G（Linux/CI，~1-2 周）

| # | 任务 | 工期 | 依赖 | 文档 | 验收 |
|---|---|---|---|---|---|
| T11 | P2-G nftables scoped egress | 1-2w | Linux CI | v1.1-stable-final §6 | CI Linux 恶意 scope DROP |

### 🟢 Phase 3：持续/任意时机（不阻塞，~2 周可分散）

| # | 任务 | 工期 | 时机 | 文档 | 验收 |
|---|---|---|---|---|---|
| T12 | ⑧ 性能回归（pytest-benchmark+Lighthouse） | 3-4d | T2-T4 后立即（锁基线） | cross-cutting §⑧ | 4 基准+回归比对 |
| T13 | ⑤ 完整自审（self-pentest+threat model） | 4-5d | T1 后 | cross-cutting §⑤ | 自扫描 0 critical |
| T14 | ⑥ i18n（i18next+zh/en） | 1-2w | v1.1-stable 后 | cross-cutting §⑥ | zh/en 切换全 UI |

### 🔵 Phase 4：P4 V2（v1.1-stable 后，~4.5 月）

| # | 任务 | 工期 | 前置 | 文档 | 备注 |
|---|---|---|---|---|---|
| T15 | ④ 迁移脚本（alembic+PG） | 1w | P4 §8.2/8.4 前置 | cross-cutting §④ | ✅ 已详细 |
| T16 | ③ 遥测（structlog+Prometheus+OTel） | 1w | P4 §8.2 SLA 前置 | cross-cutting §③ | ✅ 已详细 |
| T17 | ⑨ Bundle 分发（GitHub registry） | 1w | P4 §8.3 前置 | cross-cutting §⑨ | ✅ 已详细 |
| T18 | P4 §8.1 远程 Worker | 1-1.5月 | T15-T17 | v1.1-stable-final §8.1 | ❌ 草稿，待我细化 |
| T19 | P4 §8.2 多租户 | 1-1.5月 | T18 | v1.1-stable-final §8.2 | ❌ 草稿，待我细化 |
| T20 | P4 §8.3 ToB | 1-1.5月 | T19 | v1.1-stable-final §8.3 | ❌ 草稿，待我细化 |
| T21 | P4 §8.4 集群化 | 0.5-1月 | T15-T19 | v1.1-stable-final §8.4 | ❌ 草稿，待我细化 |

**注意**：T18-T21 当前是方向草稿，v1.1-stable 后我会逐个细化到 Tier 1 再交接，**你现在不要动 P4**。

---

## 4. 设计文档索引

**主设计**（架构/边界/ADR）：
- `sepcs/2026-07-25-catalog-driven-agent-workbench-design.md`（1661 行，§1-§24）
- `sepcs/2026-07-25-decisions.md`（17 ADR）

**Phase 1 任务设计**：
- T5：`sepcs/2026-07-29-t5-orchestration-execution-plan.md`（当前任务，最详细）
- T6/T11：`sepcs/2026-07-28-v1.1-stable-final-and-p4-plan.md` §5/§6
- T7/T8/T9/T12/T13/T14：`sepcs/2026-07-29-cross-cutting-concerns-plan.md` §①②⑦⑧⑤⑥

**每个文档都含**：现状实证 + 缺口 + 设计（代码骨架/CI yaml/命令）+ 任务清单 + 验收标准 + commit 规范。

---

## 5. 执行规范

### 5.1 每个任务的标准流程
1. 读对应设计文档段（§4 索引）
2. TDD：先写测试（RED）-> 实现（GREEN）-> 重构
3. 质量门：`pytest -q` 全绿 + `ruff check .` + `mypy src/secopent`（全 217，非仅 domain/application）
4. 前端任务：`npm run build` clean
5. commit 格式 `<type>: <desc> (任务号)`（如 `feat(e2e): real orchestration (T5)`）
6. 完成后找我验收（贴 commit hash + 质量门输出）

### 5.2 不可违反的边界（设计 §12，14 测试守护）
- **LLM 只 propose 不 decide**：Finding 确认/severity/审批/签名/发布/覆盖/evidence/scope/Case 发布 -- LLM 不可定
- **actor_role 强制**：agent 调 sign/publish/approve/verdict/stop/signing-key-create -> 403
- **签名在后端**：前端不持 Ed25519 私钥
- **scope 在后端强制**：10-step chain，Deny 优先，Destructive 永拒
- **Evidence 三层**：RAW/REDACTED/SUMMARY，RAW 受限
- **domain/application 框架无关**：新代码在 interfaces/infrastructure 层

### 5.3 中国网络现实
- Docker Hub 阻断 -> daemon.json mirrors（docker.1panel.live + docker.m.daocloud.io）
- NVD 503 -> OSV.dev 为主
- LLM -> MiniMax（OpenAI 兼容，MINIMAX_API_KEY）

### 5.4 质量门命令
```bash
cd /f/claudepc/SecOpent
py -3.12 -m pytest -q                          # 938+ 全绿
py -3.12 -m ruff check .                       # clean
py -3.12 -m mypy src/secopent                  # 217 文件 0 错
cd src/secopent/interfaces/web && npm run build # 前端 clean
npx playwright test                             # 11/11 绿（前端改后）
py -3.12 -m pytest -m e2e_real                  # 真实 E2E（T5/T6 需 Docker 靶场）
```

---

## 6. 何时找我验收（必停闸）

**每个任务完成后**贴：commit hash + 质量门输出 + 该任务验收点（§3 表"验收"列）。

**关键验收闸**（必停）：
- **T5（§3.2）完成 -> 停**，我验 3 场景端到端 + 集成 bug 修复
- **T10（v1.1-stable）打 tag 前 -> 停**，我按 §3.9 清单全过才打 tag
- T11（P2-G）-> 我验 CI Linux 恶意 scope DROP
- P4 任何项 -> **先停**，我细化到 Tier 1 再开始

---

## 7. 环境准备（T5/T6 需 Docker 靶场）

```bash
# 起靶场（Juice Shop + httpbin，已有 compose）
cd /f/claudepc/SecOpent
docker compose -f scripts/provision/docker-compose.targets.yml up -d
# T6 补 crAPI 到同一 compose

curl -s http://localhost:3000 | head   # 确认 Juice Shop
curl -s http://localhost:8080/get      # 确认 httpbin

py -3.12 -m pytest -m e2e_real          # 跑真实 E2E
```

Docker 镜像拉不动：确认 Docker Desktop daemon.json 配了 mirrors，重启。

---

## 8. 待办：归档规划文档

4 份规划文档 untracked，建议你做一个 `docs:` commit 归档：
- `sepcs/2026-07-28-v1.1-stable-final-and-p4-plan.md`
- `sepcs/2026-07-29-cross-cutting-concerns-plan.md`
- `sepcs/2026-07-29-dev-handoff-master.md`（已被本文档替代，可归档为历史）
- `sepcs/2026-07-29-t5-orchestration-execution-plan.md`

```bash
cd /f/claudepc/SecOpent
git add sepcs/2026-07-28-v1.1-stable-final-and-p4-plan.md \
        sepcs/2026-07-29-cross-cutting-concerns-plan.md \
        sepcs/2026-07-29-dev-handoff-master.md \
        sepcs/2026-07-29-t5-orchestration-execution-plan.md \
        sepcs/2026-07-29-dev-handoff-v2.md
git commit -m "docs: archive v1.1-stable + cross-cutting + T5 planning docs"
```

---

## 9. 一句话总结

**现在**：v1.1-web + P3 7/8 + T1-T4，938 测试绿，§3.6 已关闭（接受 671KB）。
**今天先做**：T5 -- 起靶场 -> TDD `AdapterStepRunner` -> 3 场景 e2e_real -> 修 8 个预期集成 bug。
**T5 计划**：`sepcs/2026-07-29-t5-orchestration-execution-plan.md`（含代码骨架 + bug 修法）。
**v1.1-stable 路径**：T5 -> T6 -> T7/T8/T9 并行 -> T10 tag。
**做完找我**：贴 commit + 质量门，T5 完成必停验收。

*交接完。从 T5 开始。*
