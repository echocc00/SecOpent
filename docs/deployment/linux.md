# Linux 生产部署（Linux Deployment）

> 面向运维：在 Linux 服务器上部署 SecOpent 单机模式（app + Docker 适配器执行）。
> 配套 `docs/deployment.md`（通用）、`docs/ops/backup-restore.md`（备份）。

## 1. 前置

| 依赖 | 版本 | 安装 |
|---|---|---|
| Python | 3.11+（推荐 3.12） | `apt install python3 python3-pip python3-venv` |
| Docker Engine | 24+ | 见 Docker 官方文档（apt 源） |
| Docker Compose | v2+ | `apt install docker-compose-plugin` |
| Node.js | 20+（仅构建前端） | `apt install nodejs npm` 或 NodeSource |
| Git | 任意 | `apt install git` |

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
docker build -t secopent:0.1.1 .
# 挂载 docker socket 让 app 跑适配器容器；持久化数据卷
docker run -d --name secopent \
  -p 8000:8000 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v secopent-data:/data \
  -e SECOPTENT_DB_URL=sqlite:////data/secopent.db \
  -e MINIMAX_API_KEY=sk-... \
  --restart unless-stopped \
  secopent:0.1.1
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
Environment="MINIMAX_API_KEY=sk-..."          # 或用 EnvironmentFile=/etc/secopent.env
ExecStart=/opt/SecOpent/.venv/bin/python3 -m uvicorn secopent.interfaces.api.main:create_app --factory --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /usr/sbin/nologin secopent
sudo chown -R secopent:secopent /opt/SecOpent
sudo systemctl daemon-reload
sudo systemctl enable --now secopent
sudo systemctl status secopent
```

## 4. 数据持久化与权限

- **SQLite DB**：默认临时路径；生产用 `SECOPTENT_DB_URL=sqlite:////opt/SecOpent/data/secopent.db` 固化。
- **文件权限**：DB 文件含 findings/scope/审计链，应 `chmod 600` + `chown secopent:secopent`。
- **PostgreSQL**（可选，T15）：`SECOPTENT_DB_URL=postgresql+psycopg://user:pass@host/db`，alembic 迁移：`alembic upgrade head`。

## 5. nftables Scoped Egress（T11，Linux 原生可用）

Linux 上可启用网络层 scope 强制（Windows 只能单测）：

```bash
sudo nft -f scripts/provision/egress.nft          # 装表
# PolicyEngine 评测启动时自动 apply_scope（注入白名单到 allowed_targets set）
# 评测结束自动 revoke
```

验证：
```bash
sudo nft list table inet secopent_egress
```

## 6. 备份 cron（T8）

```cron
# 每日 02:00 备份
0 2 * * *  /opt/SecOpent/.venv/bin/python3 -m secopent.interfaces.cli backup \
    --db /opt/SecOpent/data/secopent.db \
    --out /backup/secopent \
    --include-secrets --secrets /etc/secopent/secrets.enc
```

恢复演练见 `docs/ops/backup-restore.md`（每月一次）。

## 7. 日志

structlog 输出 JSON 到 stdout（systemd 自动归集到 journald）：
```bash
journalctl -u secopent -f          # 实时
journalctl -u secopent --since "1 hour ago" | jq .
```

Prometheus 指标：`http://<server>:8000/metrics`（T16）。

## 8. 反向代理（可选，HTTPS）

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

## 9. Linux 上比 Windows 更顺的点

- **nftables（T11）运行时可用**：真实 scope 网络隔离
- **trivy 漏洞库**：若服务器网络通畅，trivy 云扫描可跑通
- **Docker 性能**：原生 Docker Engine 比 Docker Desktop 轻快
- **文件权限**：0600/0700 精细隔离密钥与数据

## 10. 验证清单

- [ ] `python3 scripts/verify_env.py` ALL PASS
- [ ] `curl http://localhost:8000/api/health` -> `{"status":"ok"}`
- [ ] `curl http://localhost:8000/` -> SPA 加载（生产单端口）
- [ ] `systemctl status secopent` active (running)
- [ ] `journalctl -u secopent` 无 ERROR
- [ ] 备份 cron 跑一次 + 恢复演练通过
