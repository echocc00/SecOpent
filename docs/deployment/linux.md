# Linux 生产部署（Linux Deployment）

> 面向运维：在 Linux 服务器 / NAS 上部署 SecOpent 单机模式（app + Docker 适配器执行）。
> 配套 `docs/deployment.md`（通用）、`docs/ops/backup-restore.md`（备份）、`docs/deployment/upgrade.md`（升级）。

## 1. 前置

| 依赖 | 版本 | 安装 |
|---|---|---|
| Python | 3.11+（推荐 3.12） | `apt install python3 python3-pip python3-venv` |
| Docker Engine | 24+ | 见 Docker 官方文档（apt 源） |
| Docker Compose | v2+ | `apt install docker-compose-plugin` |
| Node.js | 20+（仅构建前端） | `apt install nodejs npm` 或 NodeSource |
| Git | 任意 | `apt install git` |
| nftables | 0.9+（可选，scope 隔离） | `apt install nftables` |

**Docker Hub 镜像（中国网络）**：`/etc/docker/daemon.json` 配 `registry-mirrors`（同 `environment-setup.md`）。

## 2. 部署方式（二选一）

### 方式 A：直接部署（Python venv，推荐单机）

```bash
git clone https://github.com/echocc00/SecOpent.git
cd SecOpent
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

# 构建前端
cd src/secopent/interfaces/web && npm ci --legacy-peer-deps && npm run build && cd -
export SECOPTENT_WEB_DIST="$PWD/src/secopent/interfaces/web/dist"

# 验证环境
python3 scripts/verify_env.py    # 应 ALL PASS

# 启动（前台）
python3 -m uvicorn secopent.interfaces.api.main:create_app --factory --host 0.0.0.0 --port 8000
```

访问 `http://<server>:8000`（SPA + API 单端口）。

### 方式 B：容器部署（Dockerfile）

```bash
docker build -t secopent:0.1.5 .
# 挂载 docker socket 让 app 跑适配器容器；持久化数据卷 + 密钥卷
docker run -d --name secopent \
  -p 8000:8000 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v secopent-data:/data \
  -v secopent-secrets:/secrets \
  -e SECOPTENT_DB_URL=sqlite:////data/secopent.db \
  -e SECOPTENT_SECRET_STORE_PATH=/secrets/store.enc \
  -e SECOPTENT_SECRET_KEY_PATH=/secrets/master.key \
  -e MINIMAX_API_KEY=sk-... \
  --restart unless-stopped \
  secopent:0.1.5
```

**注意**：容器内 app 经 docker socket 调用宿主 Docker daemon 跑适配器容器（适配器容器与 app 共享宿主网络，`host.docker.internal` 由 T7 的 `--add-host=host-gateway` 解析到宿主）。

## 3. systemd 常驻服务

`/etc/systemd/system/secopent.service`：
```ini
[Unit]
Description=SecOpent pentest workbench
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=secopent
WorkingDirectory=/opt/SecOpent
Environment="SECOPTENT_WEB_DIST=/opt/SecOpent/src/secopent/interfaces/web/dist"
Environment="SECOPTENT_DB_URL=sqlite:////opt/SecOpent/data/secopent.db"
Environment="SECOPTENT_SECRET_STORE_PATH=/etc/secopent/secrets/store.enc"
Environment="SECOPTENT_SECRET_KEY_PATH=/etc/secopent/secrets/master.key"
Environment="MINIMAX_API_KEY=sk-..."          # 或用 EnvironmentFile=/etc/secopent.env
Environment="SECOPTENT_MAX_PARALLEL_STEPS=1"  # NAS 弱 CPU 保守值；强主机可调 3-4
ExecStart=/opt/SecOpent/.venv/bin/python3 -m uvicorn secopent.interfaces.api.main:create_app --factory --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=5
# v0.1.5 NAS 硬化：资源上限防 OOM；优雅关闭窗口配合 lifespan drain（25s）；
# UMask=0077 让 SQLite WAL/.shm 与备份文件继承 0600。
MemoryMax=2G
CPUQuota=200%
TimeoutStopSec=30
UMask=0077

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /usr/sbin/nologin secopent
sudo chown -R secopent:secopent /opt/SecOpent
sudo install -d -m 700 -o secopent -g secopent /etc/secopent/secrets
sudo systemctl daemon-reload
sudo systemctl enable --now secopent
sudo systemctl status secopent
```

`TimeoutStopSec=30` 配合应用层优雅关闭：SIGTERM 后 SecOpent 用 25s 终止执行容器 + 等待在跑的 assessment 收尾（转 FAILED），剩余 5s 是 systemd SIGKILL 余量。强杀的 in-flight assessment 在下次启动时由 startup recovery 转 FAILED。

## 4. 数据持久化与权限

### 4.1 SQLite DB

- **路径**：生产用 `SECOPTENT_DB_URL=sqlite:////opt/SecOpent/data/secopent.db` 固化。
- **权限**：DB 文件含 findings/scope/审计链，`chmod 600` + `chown secopent:secopent`。应用启动时也会 best-effort `chmod 600`（v0.1.5）。WAL/.shm 侧车文件由 `UMask=0077` 继承 0600。
- **PostgreSQL**（可选，T15）：`SECOPTENT_DB_URL=postgresql+psycopg://user:pass@host/db`，alembic 迁移：`alembic upgrade head`。

### 4.2 SQLite 不可放网络文件系统（NFS/SMB）

**禁止**把 SQLite DB 放在 NFS/SMB/CIFS/sshfs 等网络文件系统上：WAL 文件锁在网络 FS 上不可靠，会**静默损坏**。SecOpent 启动时会检测 `/proc/mounts`，若 DB 路径在网络 FS 上则**拒绝启动**：

```
NetworkFilesystemError: SQLite database at /mnt/nfs/secopent.db is on a network
filesystem ('nfs'); WAL file locks are unreliable there and the DB will silently
corrupt. Use a local SSD path or set SECOPTENT_DB_URL to a PostgreSQL instance.
To override at your own risk set SECOPTENT_ALLOW_NFS_DB=1.
```

NAS 场景：把 DB 放在 NAS 的本地 SSD（不是共享卷）。若必须用网络存储，改用 PostgreSQL 后端。

### 4.3 SecretStore 持久化（签名密钥可复现）

默认 `EncryptedFileBackend` 是**纯内存**的（开发/测试用）--重启后签名密钥丢失，之前签的 Case/AppModel 无法验签。生产必须配持久化后端（v0.1.5）：

```bash
export SECOPTENT_SECRET_STORE_PATH=/etc/secopent/secrets/store.enc
export SECOPTENT_SECRET_KEY_PATH=/etc/secopent/secrets/master.key
```

- 首次启动自动生成 Fernet master key（`master.key`，0600）。
- 加密后的 secret 存 `store.enc`（0600）；写入即原子刷盘。
- 签名密钥的 public metadata 自动存到 `store.enc` 同目录的 `signing_keys.json`（0600）。
- `default` 签名密钥幂等创建：重启后复用已有 key，已签 Case 仍可验签。

**key 是托管物**：`master.key` 丢失 = 所有存储的 secret 不可恢复。独立备份（见 §10），不要和 `store.enc` 放一起。

## 5. nftables Scoped Egress（T11，Linux 原生可用）

Linux 上可启用网络层 scope 强制（Windows 只能单测）。NftScopeEnforcer 在 assessment 期间把 scope 白名单注入 `secopent_egress` table 的 `allowed_targets` set，结束 `revoke` 清空。

### 5.1 两种部署模式

**通用 NAS 主机（推荐）**：**不要**开机自动加载 egress 表。该表的 output chain **default-DROP 所有出站**（仅放行 DNS + established + scope 白名单），开机空壳加载会断 SSH/apt/Docker/SMB。让 NftScopeEnforcer 在 assessment 期间按需加载（或手动加载）。

**专用隔离主机**：可开机预装空壳表，让 enforcer 直接 `add element`。安装 systemd unit：
```bash
sudo cp scripts/provision/secopent-egress.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable secopent-egress   # 注意：仅专用隔离主机
```

### 5.2 手动加载 / 验证 / 卸载

```bash
# 加载（幂等：先 delete 旧表，ignore "table absent"，再 add）
sudo nft delete table inet secopent_egress 2>/dev/null; sudo nft -f scripts/provision/egress.nft
# 验证
sudo nft list table inet secopent_egress
# 卸载
sudo nft delete table inet secopent_egress
```

> `egress.nft` 已去掉 `flush ruleset`（v0.1.5）--旧版会清空宿主全部 nft 规则（含 NAS 防火墙），现在只管理自己的 `inet secopent_egress` table。

### 5.3 NAS 防火墙共存

`secopent_egress` 是独立 table，不与 NAS 自带的 iptables/nft 防火墙冲突（两者独立 chain）。前提是 `nft` 可执行（`secopent` 用户需 sudo 权限或加入能跑 nft 的组；生产建议用 PolicyKit 细粒度授权 `nft` 子命令）。

## 6. Docker 安全

### 6.1 docker socket = root 权限

SecOpent 通过 `/var/run/docker.sock` 驱动适配器容器。**能访问 docker socket = 拥有 root**（可挂载宿主 `/`）。`secopent` 用户加入 `docker` 组即可跑容器，但 docker 组等同 root。

加固选项（按推荐度排序）：

1. **Rootless Docker**（最佳）：以普通用户跑 Docker daemon，socket 不需 root。
   ```bash
   sudo apt install uidmap
   sudo -u secopent dockerd-rootless-setuptool.sh install
   ```
   SecOpent 指向 rootless socket（`DOCKER_HOST=unix:///run/user/$(id -u secopent)/docker.sock`）。

2. **docker socket proxy**（中等）：用 [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) 限制 socket 能力--只允许 `run`/`pull`，禁 `exec`/`mount`/`privileged`。
   ```bash
   docker run -d --name socket-proxy \
     -v /var/run/docker.sock:/var/run/docker.sock:ro \
     -e CONTAINERS=1 -e EXEC=0 -e POST=1 \
     tecnativa/docker-socket-proxy
   # SecOpent 通过 DOCKER_HOST=tcp://socket-proxy:2375 访问
   ```

3. **AppArmor/SELinux**：约束 docker CLI 能力（最弱，仅补充）。

适配器容器本身已加固（v0.1.4）：`--cap-drop ALL`、`--user 65532`、`--read-only`、digest pinning、`--ulimit nofile=65536`（v0.1.5）。

## 7. Docker 维护

### 7.1 容器日志 rotation

适配器容器默认 json-file 日志无 rotation，长期累积填盘。`/etc/docker/daemon.json`：
```json
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "registry-mirrors": ["https://<your-mirror>"]
}
```
改后 `sudo systemctl restart docker`。仅影响新容器。

### 7.2 镜像清理 cron

适配器镜像层 + 靶场镜像累积。每周清理：
```cron
0 3 * * 0  /usr/bin/docker image prune -f --filter "until=168h"
0 4 * * 0  /usr/bin/docker builder prune -f
```

## 8. NAS 硬件调优

| 项 | 建议 |
|---|---|
| CPU | N100/Celeron 等弱 CPU 用 `SECOPTENT_MAX_PARALLEL_STEPS=1`（默认）；8 核+ 可调 3-4 |
| 内存 | ≥8GB；systemd `MemoryMax=2G` 防止 app+适配器 OOM 全机 |
| 存储 | **DB + Docker data-root 必须在 SSD**（见下） |
| 适配器并发 | 默认串行；fuzzers（schemathesis/restler）已配 1g/1cpu + nofile=65536 |

### 8.1 SSD 强烈建议

NAS HDD 跑 Docker 镜像层 + SQLite = 极慢（镜像层解压、WAL fsync 都受 HDD 寻道拖累）。把 Docker data-root 指向 SSD：
```bash
# /etc/docker/daemon.json
{ "data-root": "/mnt/ssd/docker" }
# 迁移现有数据
sudo systemctl stop docker
sudo rsync -aP /var/lib/docker/ /mnt/ssd/docker/
sudo systemctl start docker
```
DB 文件同理放 SSD 路径（`SECOPTENT_DB_URL=sqlite:////mnt/ssd/secopent/data/secopent.db`）。

## 9. Interactsh OOB 回调（NAT 注意）

自托管 Interactsh（`scripts/provision/docker-compose.interactsh.yml`）用于 OOB 漏洞回调（DNS/HTTP interaction）。它需要**公网入站** 443/53 才能收到回调。

- **公网 IP / 端口转发**：在路由器/NAT 把公网 443/53 转发到 NAS 的 Interactsh 容器。
- **内网无公网 IP**：Interactsh 收不到回调，OOB 检测失效。改用官方公共 Interactsh 服务（`interactsh-client` 连 `oast.pro` 等），或在云主机跑 Interactsh server，NAS 只跑 client。

## 10. 备份与维护

### 10.1 每日备份 cron（T8）

```cron
# 每日 02:00 备份 DB + 加密 secret store
0 2 * * *  /opt/SecOpent/.venv/bin/python3 -m secopent.interfaces.cli backup \
    --db /opt/SecOpent/data/secopent.db \
    --out /backup/secopent \
    --include-secrets --secrets /etc/secopent/secrets/store.enc
```

备份文件自动 `chmod 600`（v0.1.5）。**Fernet master key 不在备份里**，独立托管（如离线 USB / 密码管理器）。

恢复演练见 `docs/ops/backup-restore.md`（每月一次）。

### 10.2 SQLite VACUUM 维护

findings + 审计链长期增长，定期 VACUUM 回收空间（需停 API，独占访问）：
```cron
# 每周 03:00 VACUUM（先停服务）
0 3 * * 6  systemctl stop secopent && \
    /opt/SecOpent/.venv/bin/python3 -m secopent.interfaces.cli vacuum \
        --db /opt/SecOpent/data/secopent.db && \
    systemctl start secopent
```

## 11. 日志

structlog 输出 JSON 到 stdout（systemd 自动归集到 journald）：
```bash
journalctl -u secopent -f          # 实时
journalctl -u secopent --since "1 hour ago" | jq .
```

Prometheus 指标：`http://<server>:8000/metrics`（T16）。

## 12. 反向代理（可选，HTTPS）

nginx 前置：
```nginx
server {
    listen 443 ssl http2;
    server_name secopent.example.com;
    ssl_certificate     /etc/ssl/secopent.crt;
    ssl_certificate_key /etc/ssl/secopent.key;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;          # SSE 不缓冲
        proxy_read_timeout 1h;        # 长连接
    }
}
```

## 13. Linux 上比 Windows 更顺的点

- **nftables（T11）运行时可用**：真实 scope 网络隔离
- **trivy 漏洞库**：若服务器网络通畅，trivy 云扫描可跑通
- **Docker 性能**：原生 Docker Engine 比 Docker Desktop 轻快
- **文件权限**：0600/0700 精细隔离密钥与数据

## 14. 验证清单

- [ ] `python3 scripts/verify_env.py` ALL PASS（含端口冲突检测）
- [ ] `curl http://localhost:8000/api/health` -> `{"status":"ok"}`
- [ ] `curl http://localhost:8000/` -> SPA 加载（生产单端口）
- [ ] `systemctl status secopent` active (running)
- [ ] `journalctl -u secopent` 无 ERROR / 无 NetworkFilesystemError
- [ ] DB 路径在本地 SSD（非 NFS/SMB）
- [ ] `SECOPTENT_SECRET_STORE_PATH` + `SECOPTENT_SECRET_KEY_PATH` 已设；`master.key` 已独立备份
- [ ] 重启后 `default` 签名密钥复用（已签 Case 仍可验签）
- [ ] SIGTERM 后 `journalctl` 见优雅关闭（无强杀 RUNNING 残留）
- [ ] 备份 cron 跑一次 + 恢复演练通过；VACUUM cron 跑一次
- [ ] （专用隔离主机）`systemctl status secopent-egress` active；通用 NAS 不 enable
