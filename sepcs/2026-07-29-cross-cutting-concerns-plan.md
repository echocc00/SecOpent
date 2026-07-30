# 9 项跨领域关切详细规划

> **日期**：2026-07-29
> **角色**：设计 + 验收（本文档由验收方写，dev model 执行）
> **状态**：9 项横切关现状已实证，逐项给出详细设计 + 任务 + 验收 + 时机
> **核查方法**：git 实证 + 代码检视（非假设）；每项标注【现状实证】

---

## 0. 总览

9 项关切非单一阶段任务，是横切 Sprint。按时机分三档：

| 时机 | 关切 | 理由 |
|---|---|---|
| **v1.1-stable 前必修** | ① CI 加固、② 发布流程、⑦ 备份恢复 runbook | "稳定版"必须可重现构建/发布/恢复 |
| **P4 V2 必修** | ③ 遥测、④ 迁移脚本、⑨ Bundle 分发 | 多租户/PG/知识订阅的前置 |
| **任意时机（持续）** | ⑤ 自审、⑥ i18n、⑧ 性能回归 | 质量/UX，可并行不阻塞 |

**总工期估算**：v1.1-stable 前 3 项 ~1 周；P4 3 项 ~3 周；持续 3 项 ~2 周（可分散）。

---

## ① CI/CD 加固【v1.1-stable 前，2-3 天】

### 现状实证
`.github/workflows/ci.yml` 4 job：
- `lint`：ruff + BOM 检查 ✅
- `type`：mypy **仅 `domain` + `application`**（本地查全 216 文件）❌ 范围不一致
- `test`：3.11+3.12 矩阵，cov 门 **70%**（规则要求 80%）❌
- `compose-smoke`：compileall ✅

**缺口**：无前端构建/lint、无 e2e_real job、无 browser job、无 nftables Linux job、无 release job、mypy 范围窄、cov 门低。

### 设计：补 5 job + 修 2 处
**新增 `.github/workflows/ci.yml` job**：
```yaml
  frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: "20" }
      - working-directory: src/secopent/interfaces/web
        run: |
          npm ci --legacy-peer-deps
          npx tsc -b
          npm run build
          npx playwright install --with-deps chromium

  browser-e2e:
    runs-on: ubuntu-latest
    needs: [frontend, test]
    steps:
      - uses: actions/checkout@v4
      - # 起 uvicorn + vite preview + npx playwright test

  e2e-real:
    runs-on: ubuntu-latest
    needs: [test]
    services:
      juice_shop: { image: bkimminich/juice-shop, ports: ["3000:3000"] }
      httpbin: { image: kennethreitz/httpbin, ports: ["8080:80"] }
    steps:
      - run: pytest -m e2e_real

  egress-nftables:  # P2-G 的 CI
    runs-on: ubuntu-latest
    steps:
      - run: sudo nft -f scripts/provision/egress.nft
      - run: pytest -m integration tests/integration/test_nft_scope.py
```

**修 2 处**：
1. `type` job：`mypy src/secopent/domain src/secopent/application` -> `mypy src/secopent`（对齐本地 216）
2. `test` job：`--cov-fail-under=70` -> `--cov-fail-under=80`

### 任务
- [ ] 新增 frontend / browser-e2e / e2e-real / egress-nftables 4 job
- [ ] mypy 范围对齐全 src/secopent
- [ ] cov 门 70 -> 80
- [ ] CI 全绿（含可选 job 用 condition 跳过慢 job）

### 验收
- PR 触发 CI，5+ job 全绿
- cov 报告 artifact 留档
- commit `ci: harden pipeline - full mypy, frontend, e2e, cov 80%`

---

## ② 发布流程【v1.1-stable 前，2 天】

### 现状实证
- `pyproject.toml` version = `0.1.0`（与 tag `v1.1-web` 不一致）❌
- 无 `CHANGELOG.md` ❌
- tag 手打（v0.1.0-m1..v1.1-web），无自动化 ❌
- 无 release notes 模板 ❌

### 设计
1. **版本单一真源**：`pyproject.toml` version 用 `dynamic`（从 `secopent/__version__.py` 读），`__version__.py` 由 tag 驱动：
   ```python
   # secopent/__version__.py
   __version__ = "1.1.0-web"  # 发布时脚本改
   ```
2. **CHANGELOG.md**（Keep a Changelog 格式）：
   ```markdown
   ## [Unreleased]
   ## [1.1.0-web] - 2026-07-28
   ### Added
   - Web Case Studio (7 pages + AppModel editor)
   ### Fixed
   - LLM boundary actor_role on approvals/verdict/signing-keys
   ```
3. **发布脚本** `scripts/release.sh`：
   ```bash
   #!/usr/bin/env bash
   set -euo pipefail
   VERSION="$1"
   # 1. 改 __version__.py
   # 2. 改 CHANGELOG.md（Unreleased -> [$VERSION] - date）
   # 3. git commit -m "release: v$VERSION"
   # 4. git tag v$VERSION
   # 5. git push --tags
   # 6. gh release create v$VERSION --notes-file <(awk changelog 段)
   ```
4. **GitHub Release**：tag 推送 -> `gh release create` 自动建 release，附 CHANGELOG 段 + dist 产物（前端 dist.zip）

### 任务
- [ ] `__version__.py` + pyproject dynamic
- [ ] `CHANGELOG.md`（回填 v1.0-p0 / v1.1-web）
- [ ] `scripts/release.sh`
- [ ] GitHub Release 模板（.github/release.yml）

### 验收
- `secopent version` 输出与 tag 一致
- `scripts/release.sh 1.1.0-stable` 一键出 tag + GitHub Release
- commit `build: version single-source + CHANGELOG + release script`

---

## ③ 遥测/可观测性【P4 V2，1 周】

### 现状实证
- pyproject **无** structlog/opentelemetry/prometheus/loguro ❌
- §3.8 称"结构化 JSON 日志"，但 deps 无 structlog -> 实际是 stdlib logging ❌
- 无 metrics 端点 ❌
- 无分布式追踪 ❌

### 设计（P4 多租户/SLA 前置）
1. **结构化日志**：引入 `structlog`，全应用层用 `structlog.get_logger()`：
   ```python
   structlog.configure(processors=[
       structlog.processors.add_log_level,
       structlog.processors.TimeStamper(fmt="iso"),
       structlog.processors.JSONRenderer(),  # 生产 JSON，dev console
   ])
   ```
   敏感字段脱敏（scope include/exclude、finding payload）-> 复用 §3.8 Redactor。
2. **Metrics**（Prometheus）：`/metrics` 端点，关键指标：
   - `secopent_assessments_total{status,tenant}`
   - `secopent_findings_total{severity,oracle_verdict,tenant}`
   - `secopent_oracle_verification_seconds`（histogram）
   - `secopent_llm_tokens_total{tenant,kind}`
   - `secopent_adapter_run_seconds{adapter}`
3. **追踪**（OpenTelemetry）：FastAPI auto-instrument + adapter 执行 span；P4 远程 worker 的跨进程 trace。
4. **SLA 仪表盘**：Grafana dashboard JSON（`docs/ops/grafana-dashboard.json`）。

### 任务
- [ ] structlog 接入 + 全应用层迁移
- [ ] prometheus_client + /metrics + 5 类指标
- [ ] OTel auto-instrument
- [ ] Grafana dashboard JSON
- [ ] 日志脱敏测试

### 验收
- `/metrics` 返回 Prometheus 格式
- 日志 JSON 含 tenant/request_id，敏感字段已脱敏
- commit `feat(observability): structlog + prometheus + OTel`

---

## ④ SQLite->PG 迁移脚本【P4 V2，1 周】

### 现状实证
- pyproject **无** alembic ❌
- 表由 SQLAlchemy metadata `create_all` 建（推测），无版本化迁移 ❌
- Repository Contract 已抽象（PG 可换），但无实际 PG 适配 + 无迁移工具 ❌

### 设计
1. **引入 Alembic**：`alembic init alembic`，autogenerate 初始迁移（基于现有 ORM models）。
2. **环境切换**：`SECOPTENT_DB_URL`（sqlite:///... 或 postgresql+psycopg://...），`Database` 工厂按 URL 选 engine。
3. **PG 适配验证**：`SqlAlchemy*Repository` 在 PG 上跑全测试套件（`pytest --db=pg`）。
4. **数据迁移**：`scripts/migrate_sqlite_to_pg.py`（读 SQLite -> 写 PG，按依赖顺序，含 hash 校验）。
5. **CI PG 矩阵**：CI test job 加 PG service（postgres:15），双 DB 跑套件。

### 任务
- [ ] alembic 初始化 + autogenerate baseline
- [ ] Database 工厂按 URL 选 engine
- [ ] PG 全套件测试通过
- [ ] `migrate_sqlite_to_pg.py` + round-trip 校验
- [ ] CI PG 矩阵

### 验收
- `SECOPTENT_DB_URL=postgresql://...` 起服务，全套绿
- SQLite->PG 迁移后数据完整（finding/audit/case 计数一致）
- commit `feat(db): alembic migrations + PostgreSQL support`

---

## ⑤ 工具自身安全审计【持续，1 周】

### 现状实证
`tests/security/` 9 文件（审计链篡改/紧急停止/加固/LLM 边界/许可重放/提示注入/远程模型/scope 强制/密钥隔离）-- **安全属性测试充分** ✅。
**缺口**：无工具自身 SAST、无依赖 CVE 扫描、无运行态渗透（对 FastAPI 应用本身做 OWASP 扫描）❌。

### 设计（三层）
1. **SAST**：`bandit`（Python）+ `gitleaks`（密钥）入 CI：
   ```yaml
   sast:
     runs-on: ubuntu-latest
     steps:
       - run: pip install bandit && bandit -r src/secopent -ll
       - uses: gitleaks/gitleaks-action@v2
   ```
2. **依赖扫描**：`pip-audit`（Python）+ `npm audit`（前端）入 CI，CVE 阻断。
3. **运行态自渗透**：`tests/security/test_self_pentest.py`（`@pytest.mark.integration`）- 用 nuclei 扫自己的 FastAPI：
   ```python
   def test_api_self_scan_no_critical():
       app_url = "http://localhost:8000"
       findings = run_adapter("nuclei", target=app_url, severity="critical,high")
       assert not findings, f"自扫描发现: {findings}"
   ```
4. **威胁模型复盘**：`docs/security/threat-model.md`（STRIDE），每 release 更新。

### 任务
- [ ] bandit + gitleaks + pip-audit + npm audit 入 CI
- [ ] self-pentest 测试（nuclei 扫自己）
- [ ] threat-model.md

### 验收
- CI sast/dep job 绿，0 critical CVE
- 自扫描 0 critical/high finding
- commit `security: SAST + dep scan + self-pentest + threat model`

---

## ⑥ i18n【持续，1-2 周】

### 现状实证
- 前端 **无** i18n 库（react-intl/i18next），无 useTranslation ❌
- UI 字符串中英混杂硬编码（如"仪表盘|Dashboard"、"批准|Approve"）❌
- 后端错误消息英文硬编码 ❌

### 设计
1. **前端 i18next**：`npm i i18next react-i18next`，抽字符串到 `src/locales/{zh,en}/common.json`：
   ```json
   // zh/common.json
   { "dashboard": "仪表盘", "approve": "批准", "reject": "拒绝" }
   ```
   组件：`const { t } = useTranslation(); <h1>{t('dashboard')}</h1>`
2. **语言切换**：Header 加语言切换器（zh/en），存 localStorage + Zustand。
3. **后端错误消息**：Pydantic 错误 + DomainError 消息抽到 `messages.{zh,en}.py`，按 `Accept-Language` header 选。
4. **默认 zh-CN**（用户主战场中国），en 完整覆盖。

### 任务
- [ ] i18next 接入 + 7 页字符串抽取
- [ ] zh/en locale 文件
- [ ] 语言切换器
- [ ] 后端 Accept-Language 错误本地化

### 验收
- 切换 zh/en，全 UI 翻译
- 后端错误按 Accept-Language 返回
- commit `feat(i18n): zh/en localization`

---

## ⑦ 备份恢复 runbook【v1.1-stable 前，2-3 天】

### 现状实证
- CLI `backup` 命令存在（`cli/main.py:27`），用 sqlite3 backup API（写时安全）✅
- **无 restore 命令** ❌
- 注释提及 SecretStore 备份但**未实现** ❌
- 无 ops runbook ❌

### 设计
1. **restore 命令**：`cli/main.py` 加 `restore --db --from <backup.db>`（停服 -> 替换 -> 验证 audit chain hash）。
2. **SecretStore 备份**：`backup` 扩展 `--include-secrets`，导出加密的 SecretStore（Fernet 主 key 单独管理，不进备份）。
3. **runbook** `docs/ops/backup-restore.md`：
   - 日常备份 cron：`0 2 * * * secopent backup --db /data/secopent.db --out /backup --include-secrets`
   - 恢复流程：停服 -> restore -> 验证 audit chain -> 起服
   - 演练：每月一次恢复演练（restore 到临时实例 + 跑 doctor）
4. **验证脚本**：`scripts/verify_backup.py`（恢复后 audit chain 完整 + signing keys 可验签）。

### 任务
- [ ] restore CLI 命令
- [ ] backup --include-secrets
- [ ] backup-restore.md runbook
- [ ] verify_backup.py

### 验收
- backup -> restore round-trip，audit chain 可校验
- 恢复后旧签名可验
- commit `feat(ops): backup restore + secret backup + runbook`

---

## ⑧ 性能回归测试【持续，3-4 天】

### 现状实证
- 无 `pytest-benchmark` / perf 测试 ❌
- `tests/integration/` 有 e2e_assessment/real_llm_gateway/subprocess_executor（功能非性能）❌
- §3.5 性能指标（1000 findings < 500ms 等）无持续回归保护 ❌

### 设计
1. **pytest-benchmark**：`tests/perf/test_perf.py`（`@pytest.mark.perf`，默认 deselect）：
   ```python
   @pytest.mark.perf
   def test_findings_list_1000(benchmark):
       seed_findings(1000)
       result = benchmark(lambda: client.get("/api/findings").json())
       assert result  # benchmark 记录时延
   ```
   覆盖：findings 列表 1000、plan DAG 50 节点、audit chain 10000 事件 verify、intel FTS5 搜索。
2. **基线 + 回归**：`benchmarks/baseline.json`（commit 时存），CI 比对回归 > 20% 警告。
3. **前端性能**：Lighthouse CI（`@lhci/cli`）对 7 页跑，分数 < 80 警告。
4. **marker**：`perf` 加 pyproject，`addopts` 排除（默认不跑慢）。

### 任务
- [ ] pytest-benchmark + 4 基准
- [ ] baseline.json + CI 回归比对
- [ ] Lighthouse CI 前端
- [ ] perf marker

### 验收
- `pytest -m perf` 4 基准绿
- CI 回归 > 20% 警告
- commit `test(perf): regression benchmarks + Lighthouse CI`

---

## ⑨ Update Bundle 分发【P4 V2，1 周】

### 现状实证
- `POST /updates/publish` 存在（签名 + 激活，human-only，LLM 边界强制）✅
- Bundle Ed25519 签名机制完整 ✅
- **缺口**：本地 staging+activation 有，但**无分发渠道**--bundle 如何从 curator 到实例？❌
- `BundleFetcher` Protocol 存在（httpx 在线 / 文件离线），但无官方分发源 ❌

### 设计
1. **官方 bundle registry**：GitHub Releases 托管（`secopent/bundles` repo 或本 repo 的 releases），每个 bundle 一个 release asset（`.tar.zst` + `.sig`）。
2. **BundleFetcher 实现**：`infrastructure/updates/github_bundle_fetcher.py`：
   ```python
   class GithubBundleFetcher:
       def fetch(self, source: str) -> tuple[bytes, bytes]:
           # source = "github:secopent/bundles:v2026.07"
           # 下载 tar.zst + .sig，校验 Ed25519
   ```
3. **`POST /updates/sync`**：指定 source -> fetch -> verify sig -> stage -> activate（已有 staging/activation，补 fetch）。
4. **策展流程**：curator 用 `POST /updates/publish` 本地签 -> 上传 GitHub Release -> 实例 `sync` 拉取。
5. **镜像**：中国实例走 Gitee 镜像或 CDN（GitHub 慢）。
6. **撤销**：bundle 撤销机制（registry 标记 revoked -> sync 拒绝激活）。

### 任务
- [ ] GithubBundleFetcher 实现
- [ ] `POST /updates/sync` 接 fetch
- [ ] bundle registry repo + 首发 intel bundle
- [ ] 撤销机制
- [ ] 中国镜像文档

### 验收
- 实例 `sync github:secopent/bundles:v2026.07` -> fetch + verify + activate
- 撤销 bundle 拒绝激活
- commit `feat(updates): GitHub bundle registry + fetch + revoke`

---

## 执行顺序与依赖

```
v1.1-stable 前（必修，~1 周）：
  ① CI 加固 ─┐
  ② 发布流程 ─┼──> v1.1-stable（含 ⑦ 备份恢复）
  ⑦ 备份恢复 ─┘

P4 V2（必修，~3 周）：
  ③ 遥测 ────────> 多租户 SLA
  ④ 迁移脚本 ────> PG 集群化
  ⑨ Bundle 分发 ─> 知识层订阅

持续（任意时机，~2 周可分散）：
  ⑤ 自审（建议 v1.1-stable 前做 SAST 部分）
  ⑥ i18n（建议 v1.1-stable 后）
  ⑧ 性能回归（建议 §3.5 完成后立即做，锁指标）
```

**建议插入点**：
- ①②⑦ 随 §3.2/§3.5 一起做，并入 v1.1-stable
- ⑤ SAST/dep 部分立即入 CI（1 天，安全收益高）
- ⑧ §3.5 性能做完立即锁基线
- ③④⑨ 进 P4 各方向前置
- ⑥ v1.1-stable 后

---

## 验收方节奏

1. ① CI 加固 -> 我验 5+ job 全绿 + mypy 全 + cov 80
2. ② 发布 -> 我验 `release.sh` 一键出 tag + GitHub Release
3. ⑦ 备份 -> 我验 backup/restore round-trip + audit chain
4. ⑤ SAST -> 我验 CI 0 critical
5. ⑧ 性能 -> 我验 4 基准 + 回归比对
6. ③④⑨ -> P4 各方向验收时一并
7. ⑥ i18n -> 我验 zh/en 切换

*9 项横切关切规划完。建议 ①②⑦⑤(SAST) 并入 v1.1-stable，③④⑨ 进 P4，⑥⑧ 持续。*
