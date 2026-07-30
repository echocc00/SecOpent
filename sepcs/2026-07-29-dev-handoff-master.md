# Dev Model 总交接：从当前进度到 v1.1-stable 及以后

> **日期**：2026-07-29
> **写给**：开发模型（执行方）
> **角色**：设计 + 验收方写本文档，只做设计/验收，不写业务代码
> **目的**：你接手后知道**现在在哪、今天先做什么、全部剩余任务、每项怎么做、何时找我验收**
> **核查基线**：本文档所有"已完成/未完成"均经 git 实证 + 测试复跑（922 passed / mypy 216 / ruff clean / 工作树 clean @ 7f661b2）

---

## 0. 你现在的起点（已实证）

```
已交付：M0-M4 + Phase A + P0 + P1(W1-W11) + P3 的 6/8 项
tag：v1.1-web（2026-07-28）
HEAD：7f661b2 feat(knowledge): real intel content...
测试：922 passed / ruff clean / mypy strict 216 文件 0 错
前端：npm run build clean，主包 244KB gzip
E2E：Playwright 11/11 绿（含安全闸 agent 403）
生产：FastAPI StaticFiles + /api 双挂载 + SPA fallback 实证可用
```

**P3 已完成的 6 项**（勿重做）：
- ✅ §3.1 默认 catalog 种子（`d884dad`，main.py:132 启动 seed）
- ✅ §3.3 LLM 3 调用点 + 边界测试（`d6d1073`，tests/security/test_llm_boundary_e2e.py 4 测试）
- ✅ §3.4 知识层真实内容（`7f661b2`，OSV sync CLI + 真实 checker + 签名 bundle）
- ✅ §3.6 Monaco chunk 优化（`a2e21f7`）
- ✅ §3.7 4 份文档（`bb7427e`）
- ✅ §3.8 生产加固（`1e6c28f`，密钥轮换 + 审计 HMAC + 日志 + backup CLI）
- ✅ P2-占位 5 端点（`df4c620`，drift/stop/retry/health/report）

**v1.1-stable 未打**，被 §3.2 + §3.5 剩余 阻断。

---

## 1. 今天怎么开始（执行顺序）

**第 1 步（今天，1 天）：⑤ SAST 入 CI** -- 最小投入、最高安全收益、不阻塞任何事。
**第 2 步（2-3 天）：§3.5 剩余 3 子项** -- 独立、明确、快。
**第 3 步（1 周）：§3.2 端到端编排** -- 硬门禁，起 Docker 靶场，必暴露集成 bug，预留修 bug 时间。
**第 4 步（1-2 周）：P2-F crAPI/vulhub** -- 与 §3.2 共享靶场，顺势做。
**第 5 步（并行）：① CI 加固 + ⑦ 备份恢复 + ② 发布流程** -- v1.1-stable 必修横切项。
**第 6 步：tag v1.1-stable** -- §3.9 + 横切 ①②⑦ 全过后找我验收打 tag。

**P2-G nftables** 需 Linux CI，可与上述并行或紧随。
**P4 V2** 等 v1.1-stable 后，我会先细化 P4 到 Tier 1 再交接。

---

## 2. 全部剩余任务清单（按执行顺序）

### 🔴 Phase 1：v1.1-stable 冲刺（~3-4 周）

| # | 任务 | 工期 | 依赖 | 详细设计文档 | 验收 |
|---|---|---|---|---|---|
| T1 | ⑤ SAST 入 CI（bandit+gitleaks+pip-audit+npm audit） | 1d | 无 | cross-cutting §⑤ | CI sast job 0 critical |
| T2 | §3.5 SSE 背压（asyncio.Queue+is_disconnected） | 1d | 无 | v1.1-stable §4.1 | 断开即清理，64 队列不 OOM |
| T3 | §3.5 DAG 虚拟化（onlyRenderVisibleElements+fitBounds） | 1d | 无 | v1.1-stable §4.2 | 100 节点 <1s |
| T4 | §3.5 adapter --parallel N（ThreadPool+JobService lease） | 1d | 无 | v1.1-stable §4.3 | 3 并发无竞态 |
| T5 | §3.2 端到端编排（3 场景全链路） | 1w+修 bug | T2-T4 | v1.1-stable §3 | 3 场景 e2e_real 绿 |
| T6 | P2-F crAPI/vulhub 四域真实扫 | 1-2w | T5 共享靶场 | v1.1-stable §5 | 6 e2e_real 绿 |
| T7 | ① CI 加固（frontend/browser/e2e-real/nft job+全 mypy+cov80） | 2-3d | 无 | cross-cutting §① | CI 5+ job 全绿 |
| T8 | ⑦ 备份恢复（restore+SecretStore 备份+runbook） | 2-3d | 无 | cross-cutting §⑦ | backup/restore round-trip |
| T9 | ② 发布流程（version 真源+CHANGELOG+release.sh） | 2d | 无 | cross-cutting §② | release.sh 一键出 tag |
| T10 | **tag v1.1-stable** | - | T1-T9 | v1.1-stable §7 | §3.9 清单全过 |

### 🟡 Phase 2：P2-G（可与 Phase 1 并行/紧随，~1-2 周）

| # | 任务 | 工期 | 依赖 | 文档 | 验收 |
|---|---|---|---|---|---|
| T11 | P2-G nftables scoped egress | 1-2w | Linux CI | v1.1-stable §6 | CI Linux 恶意 scope DROP |

### 🟢 Phase 3：持续/任意时机（不阻塞，~2 周可分散）

| # | 任务 | 工期 | 时机 | 文档 | 验收 |
|---|---|---|---|---|---|
| T12 | ⑧ 性能回归（pytest-benchmark+Lighthouse） | 3-4d | T2-T4 后立即（锁基线） | cross-cutting §⑧ | 4 基准+回归比对 |
| T13 | ⑤ 完整自审（self-pentest+threat model） | 4-5d | T1 后 | cross-cutting §⑤ | 自扫描 0 critical |
| T14 | ⑥ i18n（i18next+zh/en） | 1-2w | v1.1-stable 后 | cross-cutting §⑥ | zh/en 切换全 UI |

### 🔵 Phase 4：P4 V2（v1.1-stable 后，~4.5 月）

| # | 任务 | 工期 | 前置 | 文档 | 备注 |
|---|---|---|---|---|---|
| T15 | ④ 迁移脚本（alembic+PG） | 1w | P4 §8.2/8.4 前置 | cross-cutting §④ | 待我细化 |
| T16 | ③ 遥测（structlog+Prometheus+OTel） | 1w | P4 §8.2 SLA 前置 | cross-cutting §③ | 待我细化 |
| T17 | ⑨ Bundle 分发（GitHub registry） | 1w | P4 §8.3 前置 | cross-cutting §⑨ | 待我细化 |
| T18 | P4 §8.1 远程 Worker | 1-1.5月 | T15-T17 | v1.1-stable §8.1 | **草稿，待我细化到 Tier 1** |
| T19 | P4 §8.2 多租户 | 1-1.5月 | T18 | v1.1-stable §8.2 | **草稿** |
| T20 | P4 §8.3 ToB | 1-1.5月 | T19 | v1.1-stable §8.3 | **草稿** |
| T21 | P4 §8.4 集群化 | 0.5-1月 | T15-T19 | v1.1-stable §8.4 | **草稿** |

**注意**：T18-T21 当前是方向草稿（无代码骨架），v1.1-stable 后我会逐个细化到 Tier 1 再交接，**你现在不要动 P4**。

---

## 3. 每个任务怎么做（详细设计文档索引）

**主设计**（架构/边界/ADR）：
- `sepcs/2026-07-25-catalog-driven-agent-workbench-design.md`（1661 行，§1-§24）
- `sepcs/2026-07-25-decisions.md`（17 ADR）

**Phase 1 任务设计**：
- T2-T4（§3.5 剩余）：`sepcs/2026-07-28-v1.1-stable-final-and-p4-plan.md` §4（含代码骨架）
- T5（§3.2 编排）：同文档 §3（含测试骨架 + 3 场景 + 预期 bug）
- T6（P2-F）：同文档 §5（6 文件测试矩阵）
- T11（P2-G）：同文档 §6（nft 规则 + NftScopeEnforcer + CI yaml）
- T1/T7/T8/T9（横切 ①②⑤⑦）：`sepcs/2026-07-29-cross-cutting-concerns-plan.md` §①②⑤⑦
- T12/T13/T14（横切 ⑧⑤⑥）：同文档 §⑧⑤⑥

**每个文档都含**：现状实证 + 缺口 + 设计（代码骨架/CI yaml/命令）+ 任务清单 + 验收标准 + commit 规范。

---

## 4. 执行规范（务必遵守）

### 4.1 每个任务的标准流程
1. 读对应设计文档段（§3 索引）
2. TDD：先写测试（RED）-> 实现（GREEN）-> 重构
3. 质量门：`pytest -q` 全绿 + `ruff check .` + `mypy src/secopent`（全 216，非仅 domain/application）
4. 前端任务：`npm run build` clean
5. commit 按 `<type>: <desc> (任务号)` 格式（如 `feat(api): SSE backpressure (T2)`）
6. 完成后找我验收（贴 commit hash + 质量门输出）

### 4.2 不可违反的边界（设计 §12，已 14 测试守护）
- **LLM 只 propose 不 decide**：Finding 确认/severity/审批/签名/发布/覆盖/evidence 完整性/scope/Case 发布 -- LLM 不可定
- **actor_role 强制**：agent 调 sign/publish/approve/verdict/stop/signing-key-create -> 403
- **签名在后端**：前端不持 Ed25519 私钥
- **scope 在后端强制**：10-step chain，Deny 优先，Destructive 永拒
- **Evidence 三层**：RAW/REDACTED/SUMMARY，RAW 受限
- **domain/application 框架无关**：新代码在 interfaces/infrastructure 层

### 4.3 中国网络现实
- Docker Hub 阻断 -> daemon.json mirrors（docker.1panel.live + docker.m.daocloud.io）
- NVD 503 -> OSV.dev 为主
- LLM -> MiniMax（OpenAI 兼容，MINIMAX_API_KEY 环境变量）

### 4.4 质量门命令
```bash
cd /f/claudepc/SecOpent
py -3.12 -m pytest -q                          # 922+ 全绿
py -3.12 -m ruff check .                       # clean
py -3.12 -m mypy src/secopent                  # 216 文件 0 错
cd src/secopent/interfaces/web && npm run build # 前端 clean
npx playwright test                             # 11/11 绿（前端改后）
py -3.12 -m pytest -m e2e_real                  # 真实 E2E（需 Docker 靶场）
```

---

## 5. 何时找我验收

**每个任务完成后**贴：
1. commit hash
2. 质量门输出（pytest/ruff/mypy 行）
3. 该任务验收点（见 §2 表"验收"列）

**关键验收闸**（必停）：
- T5（§3.2）完成 -> 停，我验 3 场景端到端 + 集成 bug 修复
- T10（v1.1-stable）打 tag 前 -> 停，我按 §3.9 清单全过才打 tag
- T11（P2-G）-> 我验 CI Linux 恶意 scope DROP
- P4 任何项 -> **先停**，我细化到 Tier 1 再开始

---

## 6. 环境准备（T5/T6 需要 Docker 靶场）

```bash
# 起靶场（Juice Shop + httpbin，已有 compose）
cd /f/claudepc/SecOpent
docker compose -f scripts/provision/docker-compose.targets.yml up -d
# T6 补 crAPI 到同一 compose

# 验证靶标
curl -s http://localhost:3000 | head   # Juice Shop
curl -s http://localhost:8080/get      # httpbin

# 跑真实 E2E
py -3.12 -m pytest -m e2e_real
```

**Docker 镜像拉不动**：确认 Docker Desktop daemon.json 配了 mirrors，重启。

---

## 7. 一句话总结

**现在**：v1.1-web + P3 6/8，922 测试绿。
**今天先做**：T1（SAST 入 CI，1 天）+ T2（SSE 背压，1 天）。
**v1.1-stable 路径**：T1→T2→T3→T4→T5→T6→T7/T8/T9 并行→T10 tag。
**详细怎么做**：每个 T 对应 §3 索引的文档段，含代码骨架。
**做完找我**：贴 commit + 质量门，我验收。

*交接完。从 T1 开始。*
