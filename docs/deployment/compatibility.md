# 兼容性矩阵（Compatibility Matrix）

> 面向运维：确认你的主机/容器环境支持哪些 SecOpent 能力，以及能力缺失时如何降级。
> 起因：v0.4.0 在绿联 NAS（受限 Linux）升级事故，见 `docs/architecture/postmortems/v0.4.0-nas-netns-compatibility.md`。
> v0.5.1 起，能力探测 + 降级使受限环境不再阻断核心功能。

## 1. 主机能力维度

| 能力 | 需要什么 | 探测方式 | 缺失时的行为 |
|---|---|---|---|
| **netns 隔离**（每评估独立 network namespace + nft egress） | 标准 Linux iproute2（`ip netns add/del/attach`）+ Docker（sidecar） | 一次性 probe `ip netns add/del`（v0.5.1 F1，结果缓存） | 降级到默认 netns enforcer；审计 `netns.unavailable.degraded`；**评估照常执行**（v0.5.1 F2） |
| **nftables egress**（主机级 packets 拦截） | `nft` 二进制 + 权限 | — | best-effort：失败写 `egress.hardening_unavailable` 审计（v0.5.2，不再静默）+ 应用层 EgressGuard 继续 |
| **适配器容器**（nuclei 等） | Docker daemon + 镜像 | — | step 失败 → 评估 FAILED（核心依赖，不降级） |

## 2. 环境分类

| 环境类型 | 例子 | netns | 说明 |
|---|---|---|---|
| 标准 Linux（完整 iproute2） | 主流发行版、GitHub Actions ubuntu-latest | ✅ 可用 | 全特性 |
| **受限 Linux** | 绿联 UGREEN / 群晖 Synology / QNAP 等 NAS 定制内核 | ⚠️ 探测后自动降级 | 内核报 Linux 但 `ip netns` 不完整；v0.5.1 起自动识别并降级，不再阻断 |
| 非 Linux | Windows / macOS（开发） | ❌ 跳过 | netns 路径不执行；nft 为 no-op |

## 3. 强制关闭 netns

即便探测认为可用，也可显式关闭（出错排查 / 自动化 / 合规）：

```bash
export SECOPTENT_NETNS_ENABLED=0
```

关闭后行为与"受限 Linux"一致：走默认 netns enforcer + 降级审计。

## 4. 残留清理（仅当曾运行会创建 netns 的版本）

如果某次失败留下了 netns 残留（`/run/netns/secopent-*` 报 "Device or resource busy"）：

```bash
# 1. 先释放持有 ns 引用的 sidecar 容器（关键：busy 的直接原因）
docker rm -f $(docker ps -aq --filter name=secopent-netns-) 2>/dev/null
# 2. 再删 netns 文件
rm -f /run/netns/secopent-*
# 3. 确认清空
ip netns list | grep secopent || echo "clean"
```

v0.5.1 起 create() 部分失败会自清理，正常流程不再产生残留。

## 5. 数据库升级路径

- **v0.2.x → v0.3.0+（存量 DB）**：v0.5.1 起自动处理。`init_db`（启动时）若发现"有表但无 `alembic_version`"会自动 stamp 到 baseline；`secopent db upgrade`（停服迁移路径）同样自动 stamp。之后 `alembic upgrade head` 只应用增量迁移（如 `core_audit_outbox`）。
- 若使用 `SECOPTENT_DB_INIT=skip`（alembic 完全 out-of-band）：需要手动 `secopent db stamp --db <url>` 后再 `secopent db upgrade --db <url>`。
- 详见 `docs/deployment/upgrade.md`。

## 6. 排查

| 症状 | 原因 | 处理 |
|---|---|---|
| 评估 200 但卡 QUEUED、无 FAILED | v0.4.0 及更早的 netns 失败被后台任务吞掉 | 升级 v0.5.1（降级 + 自清理 + 能力探测）；清残留（§4） |
| 日志出现 `netns.unavailable.degraded` | 本机 netns 不可用，已降级 | 正常降级，无需处理；想确认可 `SECOPTENT_NETNS_ENABLED=0` 显式关闭 |
| 日志出现 `netns capability probe failed` | probe 探测到 ip netns 不可用 | 同上 |
| `alembic upgrade` 报 table already exists | 存量 DB 未 stamp | v0.5.1 自动处理；老版本手动 `secopent db stamp` |
| 日志出现 `egress.hardening_unavailable` | nft 不可用，网络层 egress 隔离降级（v0.5.2 起留审计，此前静默） | 修 NAS：`apt install nftables` + 内核 ≥5.x；或接受应用层 EgressGuard 降级 |
| `coverage_rate=0.0` + `status=failed` | v0.5.2 起"空执行"：0 个 plan step 成功 + 0 findings 判 FAILED，不再把"没扫成"伪装成"扫干净了" | 预期行为。诊断：看 `assessment.completed.empty_execution` 审计 + 各 step 的 `WORKER_UNAVAILABLE` 失败原因 |