# SecOpent 后续开发规划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** 把当前"领域骨架完成、但生产闭环缺口明显"的 SecOpent MVP 推进到"可在本地 Compose 启动并跑通 Engagement -> Run -> Finding -> Evidence -> Report -> Retest 真实闭环、且工程化基线（测试/类型/编码/CI）达标"的 1.0 Release-Ready 状态。

**Architecture:** 保持模块化单体 + 隔离 Worker 的结构。控制面（FastAPI）继续以 "Pydantic schema + Service + SQLAlchemy 模型 + 鉴权依赖" 形式落地；Worker 保持 Docker Adapter + 临时文件系统 + 对象存储的隔离执行；外部系统通过 Connector（httpx + ConnectorError）适配。本路线图不引入新范式，只补齐"接口-持久化-执行-观测"四段缺失。

**Tech Stack:** Python 3.11, FastAPI 0.115, SQLAlchemy 2.0, Alembic 1.14, Pydantic 2.10, psycopg 3, Redis 5, boto3, httpx, structlog, jinja2, Docker Adapter, MinIO/S3, GitHub Actions (CI).

---

## 0. 现状速览（2026-07-24 audit）

| 维度 | 已完成 | 缺口 / 风险 |
|---|---|---|
| 文档/策略 | 仓库策略、威胁模型 v0、设计规范、Quickstart | Quickstart 围栏带 U+0008 控制字符；设计规范使用 GBK 兼容乱码显示（UTF-8 字节正确）；MVP 实施计划文件仅占位 "test" |
| 数据模型 | Organization 模型、alembic/env.py、0001_initial 迁移覆盖 11 张核心表 | 仅 Organization 注册到 Base；其余模型为迁移 SQL，Service 用 in-memory dict，没有 ORM 模型 |
| 鉴权/策略 | TenantContext 中间件、RBAC (6 角色) + ABAC (2 规则) + local_principal 头注入 | 仍是"测试头"模式；无 OIDC；SessionLocal 在导入时绑定默认 sqlite:///memory:，不会跟随环境变量重建 |
| 核心服务 | ScopeService / AssetService / FindingService / ReportService / EvidenceService / RetestService / AuditService / RunService 全部以"dict 当数据库"形态存在并被 7 个测试覆盖 | 没有持久化，没有迁移自动应用，没有跨进程共享；证据/工单/报告/重测状态机只校验转换不校验执行 |
| API | 仅 GET /api/findings 与 /api/findings/internal 两条占位端点 | 真正的 CRUD 端点全部缺失；Swagger/OpenAPI 不暴露业务模型 |
| Worker | Worker.execute + parse_observations + upload_dir + fetch_snapshot + mint_run_token | Docker 子进程硬编码 --network=none，未签发真正短时 token；upload_dir 把目录里所有文件当 artifact 上传，没有白名单/类型判定 |
| Adapter | nmap / nuclei 两个 manifest + Dockerfile + run.sh + 解析器 | Dockerfile 用 alpine+nmap/nuclei 但版本未锁；run.sh 中 nmap -sV -oX /out/nmap.xml 缺目标参数（容器内拿不到 /in/input.json） |
| Connectors | MISP / Jira / Wazuh 三个 httpx 客户端 + Enrichment / Ingest / Export | WazuhIngest._severity 被重复定义（后定义覆盖前定义）；MispEnrichment.enrich 在每条 attribute 上 get_event 会触发 N 次远端调用；JiraClient 用 Basic Auth，没有 bearer/api_token 模式 |
| 部署/配置 | docker-compose (api/worker/postgres/redis/minio/minio-init)；Dockerfile.api/worker；.env.example | 缺健康检查（api 容器无 HEALTHCHECK）、缺 SECOPENT_WORKSPACE、缺 alembic 启动钩子、缺 minio-init 在重启后仍能幂等 |
| 编码卫生 | tests/test_encoding_hygiene.py + 编码规则文档 | 本次发现 6 个源文件带 UTF-8 BOM，alembic/versions/0001_initial.py 起始就是 BOM；docs/quickstart.md 围栏含 U+0008；scripts/_demo.log 带 BOM |
| 测试 | 72 passed (py3.12) | 全部使用内存 dict，没有覆盖持久化层；缺 ruff/mypy 钩子；缺 CI |
| 工具链 | pyproject 含 ruff/mypy 配置 | 系统未装 ruff/mypy；开发机默认 py3.8 跑不动 from __future__ 项目 |

证据：

- `git log` 显示 22 个 commit 全部在 2026-07-24 完成，单作者（Codex 本地代理）。
- `py -3.12 -m pytest -q` 在 7.46s 内通过 72/72；MISP enrichment unknown-type 用例耗时 2.4s，是唯一热点。
- `get_workspace_root` 已被调用但 `src/secopent/shared/__init__.py` / `utils/__init__.py` 带 BOM，AST 报 invalid character (Python <3.10 strict)。

---

## 1. 战略原则

1. **补齐持久化优先**：所有 Service 必须支持 SQL 持久化（不破坏 in-memory 既有测试）。
2. **契约不外扩**：本计划不引入新概念（不增加事件总线、不拆服务），只把已有骨架补成"业务可跑通"。
3. **可测试性即接口**：每一个新增端点/服务方法必须有单测；状态机转换必须有失败路径测试。
4. **修复优先于新功能**：BOM/控制字符/重复定义/Dockerfile 缺陷先于任何新端点。
5. **CI = 质量门禁**：ruff + mypy + pytest + docker compose smoke 必须全部通过。

---

## 2. 阶段拆解

### Phase 0 – 工程基线修复（0.5 day）

阻塞性修复，先保证 ① 代码 ② 测试 ③ 文档 三者都自洽，再谈功能。

- [ ] **Task 0.1: 清除源文件 BOM**
  - Files: `alembic/versions/0001_initial.py`, `src/secopent/shared/__init__.py`, `src/secopent/shared/utils/__init__.py`, `scripts/write_file.py`, `tests/test_repo_files.py`, `scripts/_demo.log`（如保留则不进入 git）
  - 验收: `python -c "import ast; ast.parse(open(p, encoding=\"utf-8\").read())"` 在 py3.8/3.11/3.12 都通过；`git diff` 只展示 `-\xef\xbb\xbf`。
- [ ] **Task 0.2: 修正 `docs/quickstart.md` 控制字符**
  - Files: `docs/quickstart.md`
  - 验收: 文件中无 U+0008；围栏代码块用 ```bash；`git diff` 仅清理 23 行。
- [ ] **Task 0.3: 删除/忽略 `scripts/_demo.log`**
  - Files: `.gitignore`, `scripts/_demo.log`
  - 验收: 跟踪文件清单不含 `_demo.log`；如需保留则移至 `scripts/_demo_output/` 并加日期戳。
- [ ] **Task 0.4: 修正 `WazuhIngest._severity` 重复定义**
  - Files: `src/secopent/connectors/wazuh/ingest.py`
  - 验收: 只保留含 INFO 兑底的那一份；增加 `test_wazuh_low_and_info_levels` 覆盖 level=0/1/2 路径。
- [ ] **Task 0.5: 修正 `adapters/*/run.sh` 目标参数缺失**
  - Files: `adapters/nmap/run.sh`, `adapters/nuclei/run.sh`
  - 验收: nmap `-iL /in/targets.txt` 或读取 TARGETS 环境；nuclei 已有 `-l /in/targets.txt`，需在 `adapters/manifest.yaml` 增加 `inputs: targets.txt`，并在 `run_adapter_container` 中复制 targets 列表到该文件。
- [ ] **Task 0.6: 修正 `SessionLocal` 在导入时绑定默认 URL**
  - Files: `src/secopent/app/db/session.py`
  - 验收: 改为 `@functools.lru_cache` + `get_engine()` 延迟创建；测试 `tests/test_db_session.py::test_get_session_yields_session` 仍绿。
- [ ] **Task 0.7: 把 MVP 计划文件补齐**
  - Files: `docs/superpowers/plans/2026-07-24-mvp-implementation-plan.md`
  - 验收: 文件从 4 字节扩到能复述已完成工作+剩余工作的 summary，与本文档的 §0 对齐。

### Phase 1 – 持久化与 API（3 days）

把"in-memory 骨架"变成"PostgreSQL + Alembic + 真正 HTTP API"。

- [ ] **Task 1.1: 注册剩余 ORM 模型**
  - Files: `src/secopent/app/db/models/{user,customer,workspace,engagement,scope,scope_snapshot,asset,observation,finding,evidence,report,retest,audit,run}.py`
  - 步骤: 每个模型 ① 写字段与关系 ② 继承 TenantMixin 或 Base ③ 与 0001 迁移一致 ④ 加 __init__/classmethod 工厂 ⑤ 单测 `tests/test_db_models.py`（≥10 用例）
- [ ] **Task 1.2: 重构服务层接受 Session**
  - Files: `src/secopent/app/{scope,assets,finding,evidence,report,retest,audit,run}/service.py`
  - 步骤: ① 在 get_session() 中获取 Session；② 服务方法签名加 `db: Session`；③ 旧测试改为 `@pytest.fixture` 注入内存 SQLite + Base.metadata.create_all；④ 状态机（Finding/Report/Retest）改为 SQLAlchemy 表达式；⑤ `tenant[:3] != actor[:3]` 替换为显式 `(org, customer, workspace)` 字段比对。
- [ ] **Task 1.3: 引入 Alembic 自动升级**
  - Files: `src/secopent/app/main.py`, `Dockerfile.api`
  - 步骤: `create_app()` 启动时检查 `SECOPENT_AUTO_MIGRATE=true` 并执行 `alembic upgrade head`；测试用 `monkeypatch` 关闭。
- [ ] **Task 1.4: 补齐 HTTP 路由（FastAPI APIRouter）**
  - Files: `src/secopent/app/api/{engagements,scopes,assets,runs,findings,evidence,reports,retests,audit,health}.py`
  - 端点矩阵:
    | 资源 | POST | GET | PATCH | DELETE |
    |---|---|---|---|---|
    | engagements | ✓ | list/get | – | – |
    | scopes | ✓ create | get | approve (snapshot) | – |
    | assets | upsert | list | – | – |
    | runs | request | list/get | approve/execute | cancel |
    | findings | create (from obs) | list/get | validate/publish | – |
    | evidence | append | list | – | – (append-only) |
    | reports | draft | get | publish | – |
    | retests | request | list | complete | – |
    | audit | – | query | – | – |
    | health | – | liveness/readiness | – | – |
  - 每个端点必须有单测（含 401/403/404/422）+ 至少 1 个 happy path。
- [ ] **Task 1.5: Worker 端真正短时 token + 输入白名单**
  - Files: `src/secopent/worker/{runtime,artifacts,signer}.py`
  - 步骤: `mint_run_token` 用 HMAC-SHA256 + `exp`；`upload_dir` 仅上传 `observations.jsonl` + 白名单（`nmap.xml` / `nuclei.jsonl`），其他文件 `log.warning` 并跳过。
- [ ] **Task 1.6: 真实对象存储 + docker compose smoke**
  - Files: `tests/test_docker_compose_smoke.py`
  - 步骤: `docker compose config` 验证语法；启动后 `curl /healthz` 200；alembic 升级无错误；最小 e2e `POST /engagements` -> `POST /runs`（PASSIVE）-> Worker 调 fake adapter -> `GET /findings` 返回 1 条。

### Phase 2 – Adapter & Connector 完善（2 days）

- [ ] **Task 2.1: Adapter 契约增强**
  - Files: `src/secopent/adapters/{contracts,manifest,runner}.py`, `adapters/{nmap,nuclei,amass,zap}/manifest.yaml`
  - 步骤: ① `AdapterManifest` 加 `risk_class`, `inputs`, `outputs`, `timeout_seconds`, `memory`；② `AdapterInput` 强制 `scope_snapshot_id` 与 `options` 校验；③ 新增 amass/zap 适配器 stub + 解析器（参照 nuclei 模式）。
- [ ] **Task 2.2: Adapter 容器安全**
  - Files: `src/secopent/adapters/runner.py`, `docker-compose.yml`
  - 步骤: 增加 `--read-only`, `--pids-limit`, `--memory`, `--cpus`；默认 `--user` 映射非 root；drop `--cap-add`。
- [ ] **Task 2.3: Connector 优化**
  - Files: `src/secopent/connectors/{misp,jira,wazuh}`
  - 步骤:
    - MispEnrichment: 改 `enrich` 为批量（1 次 search + N 次 event 改为并发 + cache）；提供 `bulk_enrich(observations)`。
    - JiraClient: 支持 `api_token` 模式（Bearer）与 OAuth 预留；JiraExport: 接受 JiraIssue dict 并可批量回传。
    - WazuhIngest: 修重复 _severity；增加分页 `after` 游标。
    - 三个 Connector 加 `ConnectorError` 重试策略（最多 3 次指数退避）在 `connectors/contracts/base.py`。
- [ ] **Task 2.4: 报告渲染升级**
  - Files: `src/secopent/app/reports/renderer.py`
  - 步骤: 引入 jinja2 模板 `src/secopent/app/reports/templates/{report.md.j2,executive_summary.md.j2}`；附 `render_html` 入口（pandoc 不强制）；evidence 引用从字符串升级为 `evidence_id -> SHA256 -> storage_uri`。

### Phase 3 – 观测 / 鉴权 / 多租户（2 days）

- [ ] **Task 3.1: 结构化日志 + 请求上下文**
  - Files: `src/secopent/app/main.py`, `src/secopent/shared/logging.py`
  - 步骤: 引入 `structlog`；中间件注入 `request_id` / `tenant` / `principal`；`-json` 输出。
- [ ] **Task 3.2: OIDC 接入（Phase 1.x）**
  - Files: `src/secopent/app/auth/{session.py,dependencies.py}`
  - 步骤: 在 `SECOPENT_AUTH_MODE=oidc` 时启用，验签 `Authorization: Bearer`（JWKS 缓存）；保留 `local` 模式以供测试。
- [ ] **Task 3.3: 审计 API + 导出**
  - Files: `src/secopent/app/audit/service.py`, `src/secopent/app/api/audit.py`
  - 步骤: `AuditService` 写入数据库；新增 `GET /api/audit?org=&from=&to=` + `format=csv`。
- [ ] **Task 3.4: Threat model 收口**
  - Files: `docs/security/threat-model.md`
  - 步骤: 把"Open items"全部升级为"Phase 1.x/2/2"具体行动；新增 STRIDE 表。

### Phase 4 – 工程质量与发布（1.5 day）

- [ ] **Task 4.1: ruff + mypy 钩子**
  - Files: `.pre-commit-config.yaml`, `pyproject.toml`
  - 步骤: ruff 已配；补 `select = ["E","F","I","B","UP","SIM"]`；mypy 加 `--strict`，先对 `src/secopent/shared` + `src/secopent/app/db` 启用。
- [ ] **Task 4.2: CI（GitHub Actions）**
  - Files: `.github/workflows/ci.yml`
  - 步骤: jobs = `lint`（ruff）/ `type`（mypy）/ `test-py3.11`（pytest）/ `test-py3.12`（pytest）/ `compose-smoke`（docker compose up -d + `curl /healthz` + `pytest -m smoke`）；失败不允许合并。
- [ ] **Task 4.3: 覆盖率门槛**
  - Files: `pyproject.toml`
  - 步骤: `pytest --cov=src --cov-fail-under=70`（逐步提到 80）；`tests/test_encoding_hygiene.py` 升级为扫描整个仓库（含 BOM/控制字符）而非仅示例字符串。
- [ ] **Task 4.4: README / Docs 重建**
  - Files: `README.md`, `docs/`
  - 步骤: 替换 README；新增 `docs/architecture.md`、`docs/operations.md`、`docs/adapters.md`；清理 4 字节的 mvp-implementation-plan.md 占位。
- [ ] **Task 4.5: 1.0 release**
  - 步骤: ① 全部 Phase 0–4 任务勾选；② `git tag -a v0.1.0`；③ GitHub Release notes；④ Docker image publish workflow（GHCR）。

---

## 3. 风险与缓解

| 风险 | 触发条件 | 缓解 |
|---|---|---|
| Service 改 SQL 会破坏现有 72 个测试 | 任务 1.2 | 抽 PersistenceBoundary Protocol，先以 in-memory 实现跑通，再加 SQL 实现，**不删除**旧测试 |
| Alembic 升级在测试环境偶发锁竞争 | 任务 1.3 | 测试用 NullPool + 每个用例创建新 engine；CI 用 postgres:16-alpine + 服务专占 |
| Adapter 容器安全强化导致 nmap 不可用 | 任务 2.2 | `--cap-add=NET_RAW` 白名单（仅 PASSIVE 之外允许）；CI 跑 `nmap --version` smoke |
| OIDC 引入拖延 MVP 验收 | 任务 3.2 | 延后到 1.0+0.1；1.0 仅保留 `local` + 文档化的 `oidc` 开关 |
| Docker 镜像无 healthcheck | 任务 1.6 | 显式 `HEALTHCHECK CMD curl -fsS http://localhost:8000/healthz` |

---

## 4. 验收定义（DoD for 1.0）

- [ ] `ruff check src tests` 0 errors, `mypy src` 0 errors (strict for shared/db)
- [ ] `pytest -q --cov=src --cov-fail-under=70` 全绿
- [ ] `docker compose up -d` 后 `curl -fsS http://localhost:8000/healthz` 200
- [ ] 端到端真实跑通：`POST /engagements` -> `POST /scopes` -> `POST /runs`（PASSIVE）-> Worker 调 `fake_adapter` -> `GET /findings` -> `POST /evidence` -> `POST /reports`（draft）-> `POST /reports/{id}/publish` -> `POST /retests` -> `GET /retests/{id}`
- [ ] `tests/test_encoding_hygiene.py` 扩展到扫描整个 `src` + `tests` + `docs`
- [ ] `docs/security/threat-model.md` 中"Open items"全部归档
- [ ] `git tag v0.1.0` 已发布，Release notes 链接到本计划

---

## 5. 不在本计划范围（Out of Scope, 1.0 之后）

- 多 Region 部署 / Kubernetes Worker Pool
- 自定义 UI（前端继续以 Swagger + curl 为准）
- AI 辅助报告（规范中已写"AI 仅作证据范围内的助理"），先不做
- Connector: OpenCTI / Cortex XSOAR / ServiceNow ITSM（按需追加）
- 多语言 i18n

---

## 6. 建议执行顺序

1. **本周（今天起）**: 完成 Phase 0 + Phase 1.1–1.3，让持久化与迁移落地
2. **下周**: Phase 1.4–1.6 + Phase 2.1–2.2
3. **第三周**: Phase 2.3–2.4 + Phase 3
4. **第四周**: Phase 4 收尾 + 1.0 发布

> 若用户希望优先做 Adapter 安全硬化而非持久化，可把 Phase 0 -> Phase 2.2 -> Phase 1 作为变体。
## Phase 1  Status

- 14 ORM models (Organization + User/Customer/Workspace/Engagement/Scope/ScopeSnapshot/Asset/Run/Observation/Finding/Evidence/Report/Retest/Remediation/AuditEvent) match 0001 migration columns 1:1
- 10 Persistence classes + 1 package (Finding/Asset/Run/Scope/Evidence/Report/Retest/Audit/Observation/ScopeSnapshot), Session-injected, all use TenantMixin
- 9 FastAPI APIRouters (engagements/scopes/assets/runs/findings/evidence/reports/retests/audit) + /healthz, Pydantic schemas for all bodies, X-Test-Principal header for tenant
- main._maybe_run_migrations() invokes `alembic upgrade head` when SECOPENT_AUTO_MIGRATE=true
- Worker HMAC-SHA256 run tokens (mint + verify) + 4-file artifact upload whitelist
- alembic.ini now has [loggers]/[formatters] sections so fileConfig does not crash
- tests/test_db_models (5) + test_persistence (7) + test_api_endpoints (9) + test_auto_migrate (2) + test_docker_smoke (4) + test_worker_signing_and_whitelist (7) = 34 new
- 115 passed in 14.62s (M1 79 + 36 Phase 1)
- Verification: 0001 migration tables all present in Base.metadata; sqlite in-memory create_all produces 15 tables; /healthz returns 200 after alembic upgrade; engagement -> finding round-trip works; cross-tenant GET returns 403

## M1 Status

- README: 4.7KB, contains MVP/M1 rows + 5 connector names (Shuffle/OpenCTI/Feishu/DingTalk/Cortex)
- docs/architecture.md: 3.8KB / 67 lines, contains mermaid diagram + 8 trust boundaries + 6-directions table
- docs/connectors.md: 2.2KB / 34 lines, 8 connector rows (MISP/Jira/Wazuh implemented; Shuffle/OpenCTI/Feishu/DingTalk/Cortex planned)
- docs/operations.md: 2.6KB / 65 lines, 7 sections
- docs/roadmap.md: 1.7KB / 27 lines, 5 milestones
- tests/test_docs_consistency.py: 7 tests, all green
- mvp-implementation-plan.md: marked as retired
