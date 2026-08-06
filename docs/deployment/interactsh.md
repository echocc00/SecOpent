# 自托管 Interactsh OOB 服务（Self-hosted Interactsh OOB Server）

> 面向运维：部署并验证自托管 interactsh-server，为 SecOpent 的 OOB 漏洞回调复证
> （SSRF / blind SQLi / blind RCE / 反序列化）提供 DNS/HTTP/SMTP interaction 捕获。
> 配套 `docs/deployment/environment-setup.md`（本地环境）、`docs/deployment/linux.md`
> （生产部署 §9 NAT 注意）、`scripts/provision/docker-compose.interactsh.yml`（compose）。

## 1. 背景

SecOpent 的 oracle 层（W3-E / W4-C）通过 `InteractshClient` 分配一个 OOB 回调
子域（`<canary>.<correlation-domain>`），嵌入扫描探针；目标触发回连后，interactsh
server 捕获 DNS/HTTP/SMTP interaction，oracle 轮询 `/poll` 拿到记录，按 canary 过滤
确认漏洞成立。

- **配置了** `SECOPTENT_INTERACTSH_SERVER_URL` → `HttpInteractshTransport`（真实回调）
- **未配置** → `NullInteractshTransport`（OOB 永远 FAIL，oracle 回退 legacy 子串匹配）

代码侧已完成（W4-C T1-T4）：transport + env 门控 + composition root + 单测。
本指南只覆盖**运维部署 + 验证**。

## 2. 部署（compose）

compose 文件：`scripts/provision/docker-compose.interactsh.yml`，镜像
`projectdiscovery/interactsh-server:latest`，容器名 `secopent-interactsh`。

```bash
docker compose -f scripts/provision/docker-compose.interactsh.yml up -d
```

端口映射（compose 定义）：

| 宿主端口 | 容器端口 | 协议 | 用途 |
|---|---|---|---|
| 5300 | 53 | UDP/TCP | DNS（`*.oast.local` 解析） |
| 8081 | 80 | HTTP | 回调 + `/register` + `/poll` API |
| 8444 | 443 | HTTPS | 回调（见下方 HTTPS 说明） |
| 2525 | 2525 | TCP | SMTP 回调 |

`-domain oast.local`：OOB 子域为 `<correlation-id>.oast.local`。

### 2.1 DNS 配置（内网测试）

`*.oast.local` 需解析到运行 interactsh 的主机。两种方式：

1. **hosts 文件（单机）**：`127.0.0.1  oast.local` 加到
   `C:\Windows\System32\drivers\etc\hosts`（Windows）或 `/etc/hosts`（Linux/macOS）。
   注意 hosts 不支持通配符，仅 `oast.local` 本身生效；`<sub>.oast.local` 仍需 DNS。
2. **本地 DNS resolver**：dnsmasq / acme，把 `*.oast.local` 指向 `127.0.0.1`，系统
   resolver 指向 5300 端口。这是内网通配符解析的正解。

### 2.2 HTTPS 说明（重要）

interactsh-server 启动时尝试为 `*.oast.local` 申请公开 TLS 证书（certmagic /
Let's Encrypt），但 `oast.local` 不是公网可验证域名，**证书申请失败、HTTPS 禁用**
（见容器日志：`Could not generate certs for auto TLS, https will be disabled`）。
因此 8444 端口不可用，**OOB 回调走 HTTP（8081）**。公网部署时改 `-domain` 为真实
域名 + 公网 IP，HTTPS 才会启用。

## 3. 配置 SecOpent

设置环境变量指向 HTTP 端点：

```bash
# Windows (PowerShell, persistent)
setx SECOPTENT_INTERACTSH_SERVER_URL "http://localhost:8081"
# Git Bash session
export SECOPTENT_INTERACTSH_SERVER_URL="http://localhost:8081"
# Linux (systemd)
# 在 secopent.service 的 Environment= 加：
#   SECOPTENT_INTERACTSH_SERVER_URL=http://127.0.0.1:8081
```

> **端口订正**：`docs/architecture/handoff-roadmap.md` §2.4 写的是
> `http://localhost:8443`，实际 compose 映射的 HTTP 端口是 **8081**（8444 是 HTTPS，
> 内网不可用）。以本文档与 compose 文件为准。

`main.py:create_app()` 检测到该 env 非空 → 用 `HttpInteractshTransport`；否则
`NullInteractshTransport`（OOB 降级为 FAIL）。

## 4. 验证（operator）

按顺序执行；全绿即 OOB 通道可用。

### 4.1 容器与端口

```bash
docker ps --filter name=secopent-interactsh --format "{{.Names}} {{.Status}} {{.Ports}}"
# 期望: secopent-interactsh ... 0.0.0.0:5300->53/udp, 8081->80, 8444->443, 2525->2525
```

### 4.2 HTTP 端点存活

```bash
curl -s http://localhost:8081/ | head -1
# 期望: <h1> Interactsh Server </h1>
```

`GET /` 返回 Interactsh Server 落地页（200）即 server 就绪。

### 4.3 register / poll 端点存在

```bash
# 空 body 触发 400（协议要求 RSA 公钥），证明端点活跃
curl -s -X POST -H "Content-Type: application/json" -d '{}' http://localhost:8081/register
# 期望: {"error":"could not decode json body: EOF"} 或 "...could not read public Key..."
curl -s "http://localhost:8081/poll"
# 期望: {"error":"no id specified for poll"}
```

### 4.4 DNS 解析

```bash
# 需先配好 §2.1 DNS；用 interactsh 自带 DNS 端口 5300 直查
nslookup -port=5300 test.oast.local 127.0.0.1
# 或系统已指向 5300：
python3 -c "import socket; print(socket.gethostbyname('test.oast.local'))"
```

### 4.5 端到端 OOB 复证（集成测）

```bash
# 确保 SECOPTENT_INTERACTSH_SERVER_URL 已设 + 目标可达
py -3.12 -m pytest tests/infrastructure/test_oracle_oob_active.py -v
```

该测试用 `httpx.MockTransport` stub server，验证 transport 注册/轮询/collect 全链路。
真实 server 端到端回连验证随 `tests/e2e_real/`（Phase 2.6 CI）覆盖。

### 4.6 verify_env

```bash
py -3.12 scripts/verify_env.py
# interactsh 检查项应 PASS（镜像存在 + 容器可启）
```

## 5. 公网部署（后续）

内网测试用 `oast.local`；要捕获**公网目标的真实回连**，interactsh-server 必须有
公网入站 443/53：

1. 真实域名（如 `oast.example.com`）的 NS 记录指向运行 interactsh 的主机公网 IP。
2. compose `command` 改 `-domain oast.example.com`。
3. 路由器/NAT 把公网 53/443 转发到容器（5300→53、8444→443）。
4. 证书自动申请此时会成功（公网可验证），HTTPS 8444 启用，env 改
   `https://oast.example.com`。

无公网 IP 时，OOB 检测对公网目标失效；可改用官方公共 Interactsh 服务
（`interactsh-client` 连 `oast.pro`），或在云主机跑 server、NAS 只跑 client。

## 6. 故障排查

| 症状 | 原因 | 处理 |
|---|---|---|
| `GET /` 无响应 | 容器未起 / 端口冲突 | `docker ps`；改 compose 端口 |
| register 400 "could not read public Key" | 正常——server 要求 RSA 公钥 | 非 bug；用官方 client 或 SecOpent transport |
| 8444 HTTPS 503 / 超时 | `*.oast.local` 无法签发公网证书 | 内网用 8081 HTTP；公网部署见 §5 |
| OOB 回调不捕获 | DNS `*.oast.local` 未解析 | 配 §2.1 DNS；目标主机也需能解析 |
| `NullInteractshTransport` 生效 | env 未设 / 空字符串 | `echo $SECOPTENT_INTERACTSH_SERVER_URL` |

## 7. 相关文件

- `scripts/provision/docker-compose.interactsh.yml` — compose 定义
- `src/secopent/infrastructure/oracle/http_interactsh.py` — `HttpInteractshTransport`
- `src/secopent/infrastructure/oracle/null_interactsh.py` — `NullInteractshTransport`（降级）
- `src/secopent/infrastructure/oracle/interactsh.py` — `InteractshClient` / 协议
- `src/secopent/interfaces/api/main.py:464` — env 门控 + composition root
- `tests/infrastructure/test_http_interactsh.py` — transport 单测
- `tests/infrastructure/test_oracle_oob_active.py` — OOB canary 全链路（stub server）
- `tests/security/test_composition_root_interactsh.py` — composition root env 门控测
- `scripts/verify_env.py` — 环境自检（镜像 + 容器）
