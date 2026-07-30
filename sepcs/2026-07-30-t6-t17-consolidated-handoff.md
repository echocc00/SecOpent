# T6-T17 整合交接：详细设计与实现细节

> **日期**：2026-07-30
> **写给**：开发模型
> **角色**：设计 + 验收方
> **前置**：T5 已验收通过（commit bde4459，950 测试，HEAD @ bde4459）；v1.1-stable 未 tag
> **本文档整合** T6-T17 的详细设计指针，并更新 T5/T1 后的变化。每项均含详细设计文档引用 + 实现要点 + 验收。
> **设计已就绪**：12 项任务的设计分布在 2 份文档共 1081 行，本文档是导航 + 更新，不重复全文。

---

## 0. 设计文档索引（详细方案所在）

| 任务 | 详细设计文档 | 章节 |
|---|---|---|
| T6 P2-F crAPI/vulhub | `v1.1-stable-final-and-p4-plan.md` | §5（+ 本文档 §6 更新） |
| T7 ① CI 加固 | `cross-cutting-concerns-plan.md` | §① |
| T8 ⑦ 备份恢复 | `cross-cutting-concerns-plan.md` | §⑦ |
| T9 ② 发布流程 | `cross-cutting-concerns-plan.md` | §② |
| T10 tag v1.1-stable | `v1.1-stable-final-and-p4-plan.md` | §7 |
| T11 P2-G nftables | `v1.1-stable-final-and-p4-plan.md` | §6 |
| T12 ⑧ 性能回归 | `cross-cutting-concerns-plan.md` | §⑧ |
| T13 ⑤ 完整自审 | `cross-cutting-concerns-plan.md` | §⑤（+ 本文档 §13 更新） |
| T14 ⑥ i18n | `cross-cutting-concerns-plan.md` | §⑥ |
| T15 ④ 迁移脚本 | `cross-cutting-concerns-plan.md` | §④ |
| T16 ③ 遥测 | `cross-cutting-concerns-plan.md` | §③ |
| T17 ⑨ Bundle 分发 | `cross-cutting-concerns-plan.md` | §⑨ |

**每个文档章节都含**：现状实证 + 缺口 + 设计（代码骨架/CI yaml/命令）+ 任务清单 + 验收标准 + commit 规范。

---

## 1. 执行顺序与工期

### Phase 1：v1.1-stable 收尾（~2 周）
```
T6 P2-F（1-2w，长杆）──┬── T7 CI 加固（2-3d，并行）
                      ├── T8 备份恢复（2-3d，并行）
                      └── T9 发布流程（2d，并行）
                                    ↓
                              T10 tag v1.1-stable（闸门）
```

### Phase 2：v1.1-stable 后（~2-3 周，可与 P4 重叠）
```
T11 P2-G nftables（1-2w，需 Linux CI）
T12 性能回归（3-4d）── T13 自审（4-5d）── T14 i18n（1-2w）
```

### Phase 3：P4 前置（~3 周，v1.1-stable 后）
```
T15 迁移脚本（1w）┬─ T16 遥测（1w）┬─ T17 Bundle 分发（1w）
                  │                 │
                  └─ 可并行 ────────┘
```
**T15/T16/T17 是 P4 V2 前置**（多租户/PG/知识订阅），完成后才做 T18 远程 Worker（已出 Tier 1 设计）。

---

## 2. 通用执行规范（所有任务）

1. **读对应设计文档章节**（§0 索引）
2. **TDD**：RED -> GREEN -> 重构
3. **质量门**：`pytest -q`（950+ 全绿）+ `ruff check .` + `mypy src/secopent`（全 218）
4. **前端任务**：`npm run build` clean
5. **commit**：`<type>: <desc> (T#)`
6. **完成后找我验收**：贴 commit + 质量门 + 验收点
7. **不可违反边界**：LLM 只 propose / actor_role 强制 / 签名在后端 / scope 后端强制 / evidence 三层 / domain-application 框架无关

---

## 3. T6 P2-F crAPI/vulhub 四域真实扫（1-2 周）

### 详细设计
`v1.1-stable-final-and-p4-plan.md` §5（6 文件测试矩阵）。

### ⚠️ T5 后的更新（重要）
T5 已建立 `tests/e2e_real/test_orchestration.py`（3 场景：Web/API/Cloud，经 `Orchestrator.run_to_completion` 全链路）。**T6 不是从零写，而是扩展 T5 的模式到四域全覆盖**。

**T6 实际工作**：
1. **扩靶场**：`scripts/provision/docker-compose.targets.yml` 加 crAPI（+ postgres），与 T5 共享
2. **四域测试矩阵**（沿用 T5 的 `AdapterStepRunner + RealScanRunner + ScanContext` 模式）：

| 文件 | 域 | 靶标 | 适配器链 | 说明 |
|---|---|---|---|---|
| `test_web_juice_shop.py` | Web | Juice Shop | subfinder->httpx->nuclei->dalfox | T5 已覆盖 nuclei，T6 补 dalfox |
| `test_web_crapi.py` | API | crAPI | katana->nuclei | BOLA/BFLA |
| `test_api_httpbin.py` | API | httpbin | Schemathesis | 5 类突变（需接线 Schemathesis 适配器） |
| `test_network_local.py` | 网络 | 本机/metasploitable | nmap->naabu | 端口 finding |
| `test_cloud_docker.py` | 云 | docker.sock | checkov/trivy | T5 已覆盖 checkov，T6 补 trivy（需 DB 可达） |
| `test_asset_graph.py` | 资产 | Juice+httpbin | subfinder->httpx->katana | 资产图节点/边 |

3. **每个测试复用 T5 模式**：
```python
scan_runner = RealScanRunner(default_timeout=180)
step_runner = AdapterStepRunner(scan_runner, ScanContext(targets=(url,), ...))
orchestrator = Orchestrator(jobs, step_runner)
orchestrator.run_to_completion(owner="e2e", now=utc_now())
# -> FindingCorrelator -> RescanVerifier -> CoverageService -> ReportRenderer
```

### 验收
- [ ] `pytest -m e2e_real` 6 文件全绿（需 Docker 靶标 up）
- [ ] commit `feat(e2e): four-domain real scan coverage (T6 P2-F)`

---

## 4. T7 ① CI 加固（2-3 天，可并行）

### 详细设计
`cross-cutting-concerns-plan.md` §①（含完整 CI yaml）。

### 实现要点
1. 新增 4 个 CI job：`frontend` / `browser-e2e` / `e2e-real` / `egress-nftables`
2. 修 `type` job：`mypy src/secopent/domain src/secopent/application` -> `mypy src/secopent`（对齐本地 218）
3. 修 `test` job：`--cov-fail-under=70` -> `--cov-fail-under=80`
4. e2e-real job 用 services 起 juice_shop + httpbin

### 验收
- [ ] PR 触发 CI，5+ job 全绿
- [ ] commit `ci: harden pipeline - full mypy, frontend, e2e, cov 80% (T7)`

---

## 5. T8 ⑦ 备份恢复（2-3 天，可并行）

### 详细设计
`cross-cutting-concerns-plan.md` §⑦（含 restore CLI + runbook）。

### 实现要点
1. `cli/main.py` 加 `restore --db --from <backup.db>`（停服->替换->验 audit chain hash）
2. `backup` 扩 `--include-secrets`（导出加密 SecretStore，Fernet 主 key 不进备份）
3. `docs/ops/backup-restore.md` runbook（日常 cron + 恢复流程 + 月度演练）
4. `scripts/verify_backup.py`（恢复后 audit chain 完整 + signing keys 可验签）

### 验收
- [ ] backup -> restore round-trip，audit chain 可校验
- [ ] 恢复后旧签名可验
- [ ] commit `feat(ops): backup restore + secret backup + runbook (T8)`

---

## 6. T9 ② 发布流程（2 天，可并行）

### 详细设计
`cross-cutting-concerns-plan.md` §②（含 version 真源 + CHANGELOG + release.sh）。

### 实现要点
1. `secopent/__version__.py` + pyproject `dynamic`（version 单一真源）
2. `CHANGELOG.md`（Keep a Changelog 格式，回填 v1.0-p0 / v1.1-web）
3. `scripts/release.sh`（改 version + 改 CHANGELOG + commit + tag + gh release）
4. `.github/release.yml` Release 模板

### 验收
- [ ] `secopent version` 与 tag 一致
- [ ] `scripts/release.sh 1.1.0-stable` 一键出 tag + GitHub Release
- [ ] commit `build: version single-source + CHANGELOG + release script (T9)`

---

## 7. T10 tag v1.1-stable（闸门）

### 详细设计
`v1.1-stable-final-and-p4-plan.md` §7（§3.9 清单）。

### 验收清单（全过才 tag）
- [ ] T6 3+场景 e2e_real 绿
- [ ] T7 CI 5+ job 全绿 + mypy 全 + cov 80
- [ ] T8 backup/restore round-trip
- [ ] T9 release.sh 可用
- [ ] 全套 950+ 无回归 + ruff/mypy clean
- [ ] 文档更新（user-manual 含真实流程）
- [ ] `git tag v1.1-stable`

**T10 打 tag 前必停找我验收。**

---

## 8. T11 P2-G nftables Scoped Egress（1-2 周，需 Linux）

### 详细设计
`v1.1-stable-final-and-p4-plan.md` §6（含 nft 规则 + NftScopeEnforcer 代码骨架 + CI yaml）。

### 实现要点
1. `scripts/provision/egress.nft`（allowed_targets set + output chain DROP default）
2. `infrastructure/network/nft_scope.py`（`NftScopeEnforcer.apply_scope/revoke`，含 DNS rebinding 二次校验 + 元数据 IP 拒绝）
3. PolicyEngine 接线：scope 10-step chain 第 6 步后调 `apply_scope`
4. CI Linux job：`sudo nft -f egress.nft` + 恶意 scope（169.254.169.254）DROP 测试

### ⚠️ 环境约束
本机 Windows 不可验。走 CI Linux runner 或更大云主机（8.133.200.235 1.6GB RAM 太小）。

### 验收
- [ ] CI Linux：恶意 scope DROP + 审计拒绝事件
- [ ] 合法 scope 仅白名单 IP 可达
- [ ] commit `feat(security): nftables scoped egress (T11 P2-G)`

---

## 9. T12 ⑧ 性能回归（3-4 天）

### 详细设计
`cross-cutting-concerns-plan.md` §⑧（含 pytest-benchmark + Lighthouse）。

### ⚠️ T5 后的更新
T5 已建 `AdapterStepRunner` + 并发（T4）。T12 性能基准应包含：
- findings 列表 1000
- plan DAG 50 节点（T3 已虚拟化）
- audit chain 10000 事件 verify
- intel FTS5 搜索
- **新增**：AdapterStepRunner 并发 3 worker 时延（T4 并发基准）

### 实现要点
1. `pytest-benchmark` + `tests/perf/test_perf.py`（`@pytest.mark.perf`，默认 deselect）
2. `benchmarks/baseline.json` + CI 回归 > 20% 警告
3. Lighthouse CI（`@lhci/cli`）对 7 页
4. `perf` marker 加 pyproject addopts

### 验收
- [ ] `pytest -m perf` 4+基准绿
- [ ] CI 回归比对
- [ ] commit `test(perf): regression benchmarks + Lighthouse CI (T12)`

---

## 10. T13 ⑤ 完整自审（4-5 天）

### 详细设计
`cross-cutting-concerns-plan.md` §⑤。

### ⚠️ T1 后的更新（重要）
**T1 已完成 SAST 部分**：bandit + gitleaks + pip-audit + npm audit 全入 CI（commit dd97e85）。**T13 剩余仅**：
1. **运行态自渗透**：`tests/security/test_self_pentest.py`（`@pytest.mark.integration`）-- 用 nuclei 扫自己的 FastAPI：
   ```python
   def test_api_self_scan_no_critical():
       findings = run_adapter("nuclei", target="http://localhost:8000", severity="critical,high")
       assert not findings, f"自扫描发现: {findings}"
   ```
2. **威胁模型**：`docs/security/threat-model.md`（STRIDE），每 release 更新

### 验收
- [ ] 自扫描 0 critical/high finding
- [ ] threat-model.md 完成
- [ ] commit `security: self-pentest + threat model (T13)`

---

## 11. T14 ⑥ i18n（1-2 周）

### 详细设计
`cross-cutting-concerns-plan.md` §⑥（含 i18next + zh/en locale）。

### 实现要点
1. `npm i i18next react-i18next` + `src/locales/{zh,en}/common.json`
2. 7 页字符串抽取 -> `const { t } = useTranslation(); <h1>{t('dashboard')}</h1>`
3. Header 语言切换器（localStorage + Zustand）
4. 后端 `Accept-Language` -> 错误消息本地化（`messages.{zh,en}.py`）
5. 默认 zh-CN

### 验收
- [ ] zh/en 切换全 UI 翻译
- [ ] 后端错误按 Accept-Language
- [ ] commit `feat(i18n): zh/en localization (T14)`

---

## 12. T15 ④ 迁移脚本（1 周，P4 前置）

### 详细设计
`cross-cutting-concerns-plan.md` §④（含 alembic + PG 适配 + 迁移工具）。

### 实现要点
1. `alembic init alembic` + autogenerate baseline（基于现有 ORM）
2. `SECOPTENT_DB_URL` 环境切换（sqlite:/// 或 postgresql+psycopg://）
3. `Database` 工厂按 URL 选 engine
4. PG 全测试套件（`pytest --db=pg`）
5. `scripts/migrate_sqlite_to_pg.py`（读 SQLite -> 写 PG + hash 校验）
6. CI 加 PG service（postgres:15）双 DB 矩阵

### 验收
- [ ] `SECOPTENT_DB_URL=postgresql://...` 全套绿
- [ ] SQLite->PG 迁移后数据完整（finding/audit/case 计数一致）
- [ ] commit `feat(db): alembic migrations + PostgreSQL support (T15)`

---

## 13. T16 ③ 遥测（1 周，P4 前置）

### 详细设计
`cross-cutting-concerns-plan.md` §③（含 structlog + Prometheus + OTel）。

### 实现要点
1. `structlog` 接入（JSON 渲染，dev console），全应用层迁移
2. `prometheus_client` + `/metrics` 端点，5 类指标：
   - `secopent_assessments_total{status,tenant}`
   - `secopent_findings_total{severity,oracle_verdict,tenant}`
   - `secopent_oracle_verification_seconds`
   - `secopent_llm_tokens_total{tenant,kind}`
   - `secopent_adapter_run_seconds{adapter}`
3. OpenTelemetry auto-instrument（FastAPI + adapter span）
4. `docs/ops/grafana-dashboard.json`
5. 日志脱敏（复用 §3.8 Redactor）

### 验收
- [ ] `/metrics` 返回 Prometheus 格式
- [ ] 日志 JSON 含 tenant/request_id，敏感字段脱敏
- [ ] commit `feat(observability): structlog + prometheus + OTel (T16)`

---

## 14. T17 ⑨ Bundle 分发（1 周，P4 前置）

### 详细设计
`cross-cutting-concerns-plan.md` §⑨（含 GitHub registry + fetcher + 撤销）。

### 实现要点
1. `infrastructure/updates/github_bundle_fetcher.py`（下载 tar.zst + .sig，校验 Ed25519）
2. `POST /updates/sync` 接 fetch（source = `github:secopent/bundles:v2026.07`）
3. bundle registry repo（GitHub Releases 托管）
4. 撤销机制（registry 标记 revoked -> sync 拒绝激活）
5. 中国镜像文档（Gitee 或 CDN）

### 验收
- [ ] 实例 `sync github:secopent/bundles:v2026.07` -> fetch + verify + activate
- [ ] 撤销 bundle 拒绝激活
- [ ] commit `feat(updates): GitHub bundle registry + fetch + revoke (T17)`

---

## 15. 验收节奏汇总

| 任务 | 验收闸 | 何时停 |
|---|---|---|
| T6 | 6 e2e_real 绿 | 完成停 |
| T7 | CI 5+ job 全绿 | 完成停 |
| T8 | backup/restore round-trip | 完成停 |
| T9 | release.sh 可用 | 完成停 |
| **T10** | §3.9 清单全过 | **必停，打 tag 前验** |
| T11 | CI Linux 恶意 scope DROP | 完成停 |
| T12 | 4+ 基准 + 回归比对 | 完成停 |
| T13 | 自扫描 0 critical | 完成停 |
| T14 | zh/en 切换 | 完成停 |
| T15 | PG 全套绿 + 迁移 round-trip | 完成停 |
| T16 | /metrics + 脱敏日志 | 完成停 |
| T17 | sync + 撤销 | 完成停 |

**P4 T18-T21**：T18 已出 Tier 1 设计（`2026-07-30-t18-remote-worker-tier1-design.md`）；T19-T21 待我细化，**不要动**。

---

## 16. 一句话总结

**v1.1-stable 路径**：T6（长杆）+ T7/T8/T9（并行）-> T10 tag。
**stable 后**：T11（Linux）/ T12 / T13 / T14 持续。
**P4 前置**：T15 / T16 / T17（并行 3 周）-> T18 远程 Worker（设计已就绪）。

**每项详细设计**：见 §0 索引的文档章节。**T6/T13 有 T5/T1 后的更新**（见 §3/§10）。**质量门 + 边界**：见 §2。

*交接完。从 T6 开始（或 T7/T8/T9 并行）。*
