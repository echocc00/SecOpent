# 生产部署（Deployment）

> 面向运维 / 部署者：把 SecOpent 跑在生产——构建前端、配置、密钥管理、数据库、备份、日志审计。
> 状态：P3 §3.7。**环境预备**（Docker + 镜像 + 靶场 + Interactsh + LLM key）见 `docs/deployment/environment-setup.md`——本文不重复，专注服务本身的部署与运维。

## 1. 部署形态

- **开发**：API（uvicorn :8000）+ Vite dev（:5173，`/api/*` 代理到后端根）。
- **生产**：单进程单端口——uvicorn :8000 同时托管 SPA 与 API。当 `SECOPTENT_WEB_DIST` 指向构建产物时：
  - `/assets/*` 由 StaticFiles 直出哈希资源；
  - 其余非 API 路径回退 `index.html`（SPA 客户端路由）；
  - 同一套路由**同时**挂在根与 `/api` 下（前端直连 `/api/*`，无代理改写）；API 路由优先于 SPA 回退。

## 2. 构建与启动

```bash
bash scripts/build_web.sh
# 1) vite build 前端 -> src/secopent/interfaces/web/dist
# 2) export SECOPTENT_WEB_DIST=<...>/dist
# 3) uvicorn secopent.interfaces.api.main:create_app --factory --port 8000
```

启动副作用（`create_app`）：结构化日志初始化、种子默认 TestCatalog（OWASP WSTG + CIS，库空时）、创建默认签名密钥、装配 LLM 网关（有 `MINIMAX_API_KEY` 用 MiniMax，否则 NullModelBackend 降级到确定性路径）。

## 3. 配置参考（环境变量）

| 变量 | 默认 | 含义 |
|---|---|---|
| `SECOPTENT_WEB_DIST` | 空（不提供前端） | 构建产物目录；设置即启用 SPA 托管 |
| `SECOPTENT_LOG_FORMAT` | 空（console） | `json` → structlog JSON 结构化输出 |
| `MINIMAX_API_KEY` | 空（NullModelBackend） | MiniMax LLM key；设置即启用 LLM 提议 |
| `DEEPSEEK_API_KEY` / `DASHSCOPE_API_KEY` / `OPENAI_API_KEY` | 空 | 备选 LLM 提供方（在 `config/llm.yaml` 切换） |
| `HTTP_PROXY` | 空 | 出站代理 |

LLM 提供方选择与参数在 `config/llm.yaml`（endpoint / api_key_env / model / max_tokens / temperature）。**无 LLM key 时系统完全可用**——所有 LLM 辅助端点降级为确定性路径（LLM 只提议，缺失不影响核心）。

## 4. 数据库

- **默认**：`create_app()` 不传 engine 时绑定一个**临时 SQLite 文件**（`tempfile`）——进程退出即失。**当前无数据库路径环境变量**；持久化部署需自行注入 engine（`create_sqlite_engine(path)` 或 `create_postgres_engine(dsn)`）。
- **SQLite 调优**（`infrastructure/db/sqlite.py`，每连接生效）：`journal_mode=WAL` · `synchronous=NORMAL`（WAL 下持久且更快）· `journal_size_limit=64MB`（防长评估撑爆 WAL）· `foreign_keys=ON` · `busy_timeout=5000`。
- **PostgreSQL**：Repository 层后端无关（同一套 ORM 模型跑 SQLite/PG）；`create_postgres_engine(dsn)`（`postgresql+psycopg://...`，`pool_pre_ping`）。唯一 SQLite 专属点是 intel 仓库的 FTS5（PG 换全全文检索），已隔离；有 PG 契约测试证明切换无需领域 / 应用层改动。
- **多进程注意**：默认 temp SQLite + 内存 SecretStore（见 §5）均为单进程语义；多 worker / 集群需外接 PG + 持久化密钥后端（P4 方向）。

## 5. 密钥管理

**签名密钥**（Ed25519，签 AppModel digest）：

- 私钥加密存 SecretStore，服务端持有，前端 / LLM 永不接触。启动建默认密钥。
- `GET /signing-keys`（公开信息，含 `archived`）· `POST /signing-keys`（创建，human-only）· `POST /signing-keys/{key_id}/rotate`（轮换，human-only）。
- **轮换**：创建新密钥并把旧密钥置 `archived`——旧密钥**保留**（其公钥仍可验旧签名），新签名用新密钥。

**SecretStore**（引用式密钥）：

- 任务持 `secret_ref`，明文不落领域 / 库 / 日志 / 证据 / 报告；`resolve` 瞬时取值并审计（只记 ref，不记值）；`revoke` 任务结束删除。
- **现状**：`EncryptedFileBackend()` 默认**在内存中生成 Fernet key**（无 key 传入即 `Fernet.generate_key()`），存储亦在内存——**进程重启即失**。这是引用式参考实现；生产持久化应传入稳定 Fernet key（环境变量注入，**勿落 git**）并接 keyring/KMS 后端（同一 `SecretBackend` 协议）。

## 6. 备份与恢复

> **W2-C 更新**：`_build_secret_backend()` 现默认 `PersistentEncryptedFileBackend`（密文 + metadata 落盘 0600，跨重启可恢复）。Fernet 主密钥优先从 `SECOPTENT_SECRET_KEY` env 注入（KMS/operator 托管，永不落盘）；未设则读 `SECOPTENT_SECRET_KEY_PATH` 或 `./secret.key`（首启自动生成 0600）。`SECOPTENT_SECRET_BACKEND=memory` 显式 opt-in 纯内存（测试用）。生产应通过 env 注入 key。

```bash
# 备份（可选 --include-secrets --secrets <secrets.enc> 一并备份加密 SecretStore）
secopent backup --db <sqlite文件> --out <目录>
# -> <目录>/secopent-backup-<时间戳>.db（sqlite3 在线一致性快照，API 写入时也安全）

# 恢复（先验备份审计链 -> 留回滚点 .pre-restore-<ts> -> 原子替换 -> 复验）
secopent restore --db <sqlite文件> --from <备份文件>
```

- 备份是 SQLite 在线 backup（一致性快照）。`--include-secrets` 复制**加密** SecretStore；**Fernet 主密钥不进备份**，须另行托管（KMS/离线）。
- 恢复自带审计链校验与回滚点；`scripts/verify_backup.py` 可独立复核。详见 [`ops/backup-restore.md`](ops/backup-restore.md)（含月度演练）。
- `secopent version` / `secopent doctor`（确定性核心健康检查，应输出 `ok`）用于部署自检。

## 7. 日志、审计与可观测性

- **结构化日志**（`infrastructure/logging_setup.py`，structlog）：`SECOPTENT_LOG_FORMAT=json` 输出 JSON，每请求绑定 `request_id`/`tenant`（T16）。**敏感字段脱敏**：`password / secret / token / api_key / authorization / cookie / signature / private_key` 一律渲染为 `[REDACTED]`——密钥材料绝不进日志。
- **审计链**：所有关键动作入哈希链；可选 HMAC 密钥做防篡改升级（`application/audit.py`）。审计经 `/audit` 查询，可验完整性。
- **指标**：`GET /metrics` 输出 Prometheus 文本格式（评估/发现计数、oracle 与适配器时延、LLM token）。`docs/ops/grafana-dashboard.json` 提供配套 Grafana 面板。
- **追踪**：OpenTelemetry FastAPI 自动埋点（best-effort，未配置 exporter 时为 no-op）。

## 7a. 更新包分发（§⑨ / T17）

- **发布（curator）**：`POST /updates/publish`（human-only）本地签名并激活一个 intel bundle。
- **分发（registry）**：将 bundle 上传到 GitHub Releases，每个 release（tag）含三个 asset：`bundle.json`（bundle 文档）、`bundle.json.sig`（Ed25519  detached 签名）、`revocations.json`（`{"revoked": ["<tag>", ...]}` 撤销列表）。
- **拉取（实例）**：`POST /updates/sync`，body `{"source": "github:<owner>/<repo>:<tag>", "actor_role": "human"}`。流程：fetch → Ed25519 验签 → schema 校验 → 原子激活 → 审计。**撤销的 tag 返回 409 拒绝激活**。
- **中国镜像**：`GithubBundleFetcher(base_url=...)` 可指向 Gitee / CDN 镜像（替代 github.com），asset 路径约定不变（`<base>/<owner>/<repo>/releases/download/<tag>/<asset>`）。GitHub 直连慢/被阻断时配置镜像源。

## 8. 生产清单

- [ ] `SECOPTENT_WEB_DIST` 指向构建产物，`/health` 返回 `ok`
- [ ] `SECOPTENT_LOG_FORMAT=json` 接入日志管道，确认无明文敏感字段
- [ ] 数据库换持久路径或 PG（替换默认 temp SQLite）
- [ ] SecretStore 接稳定 Fernet key + 持久后端（如需跨重启保留密钥）
- [ ] Oracle 复证已接线（W3-A）：`SECOPTENT_NUCLEI_TEMPLATE_DIR` 指向复证用模板目录，`SECOPTENT_SCAN_TIMEOUT` 覆盖复证超时（与扫描同源；oracle 在 assessment correlation 后 best-effort 运行，失败不阻塞完成）
- [ ] OOB canary 复证生效（W4-C）：`SECOPTENT_INTERACTSH_SERVER_URL` 指向自建 interactsh-server（见 `scripts/provision/docker-compose.interactsh.yml`）；设置后用 `HttpInteractshTransport`，OOB 类发现（`oob_window_seconds>0`）经 canary 回调复证。未设则 OOB 降级为 Null（回退子串匹配）。生产 scan_kwargs 已嵌 `{{canary_oob_subdomain}}` 占位符；echo（`{{canary_token}}`）占位符待按方法粒度门控后启用
- [ ] 签名密钥轮换流程演练（rotate 后旧签可验、新签可用）
- [ ] `secopent backup` 定时 + 恢复 round-trip 验证
- [ ] 审计链启用 HMAC（防篡改要求时）
- [ ] 签名审计链持久化（H6，W3-C）：`SECOPTENT_AUDIT_KEY_PATH` 指向 0600 审计签名密钥文件（首启自动生成；跨重启签名链可复验）；签名事件落 `core_signed_audit_events` 表
- [ ] 网络命名空间隔离（W3-F/W4-B，Linux）：`NetnsIsolator` 已在 composition root 装配（`app.state.netns_isolator` + `make_nft_enforcer` factory），`start_assessment` 每次评估建独立 netns、nft 规则在 netns 内生效、评估结束（含异常）在 finally 销毁。非 Linux 开发机 `is_supported()` 为 False，enforcer 回退默认 netns（best-effort）。**剩余**：Docker 扫描容器进 netns 的 `--network` 接线需 Linux 环境（`ip netns exec` + Docker 网络工程），当前在非 Linux 开发机上不可真测；Linux 部署时应接通
- [ ] Peer-agent 接线（W4-A）：`SECOPTENT_PEER_AGENTS_ENABLED=1` + `LLM_API_KEY` 启用 `PeerAgentService`（`/peer-agents`、`/assessments/{id}/peer-runs` 路由）；当前用 `NullPeerAgentHarness` 降级（strix/shannon 镜像未 pin digest，launch 返回空结果）。真 backends 待镜像构建 + digest pinning 后，去掉 `harness=NullPeerAgentHarness()` 改用 factory 默认 `ContainerPeerAgentHarness`。peer run 审计经 `DatabaseAuditRecorder` 落库（session-per-call，singleton 安全）
- [ ] Docker / 镜像 digest-pin / 靶场 / Interactsh / LLM key 按 `environment-setup.md` 就绪
