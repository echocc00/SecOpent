# 升级指南（Upgrade Guide）

> 面向运维：在 Linux 上升级已安装的 SecOpent。覆盖 venv 直装 + 容器两种部署。
> 配套 `docs/deployment/linux.md`（部署）、`docs/ops/backup-restore.md`（备份）。

## 0. 升级前必读

**每次升级前**：
1. **读 CHANGELOG**：每条 release 顶部有 `Schema | Deps | Breaking` 标记，决定是否需要备份/迁移。
2. **备份数据库**：
   ```bash
   secopent backup --db /opt/SecOpent/data/secopent.db \
       --out /backup --include-secrets --secrets /etc/secopent/secrets.enc
   ```
3. **停服务**（仅 schema 迁移时必须；纯代码可热重启）：
   ```bash
   sudo systemctl stop secopent
   ```

## 1. CHANGELOG 标记说明

每个 release 顶部标注三项：
| 标记 | 含义 | 需要的动作 |
|---|---|---|
| `Schema: yes` | 含 alembic 迁移 | 停服 + `alembic upgrade head` + 重启 |
| `Schema: no` | 无 schema 变更 | 无需迁移，可直接重启 |
| `Deps: yes` | Python/npm 依赖变化 | `pip install -e ".[dev]"` + `npm install` |
| `Deps: no` | 依赖不变 | 跳过 install |
| `Breaking: yes` | 不兼容变更 | 读迁移说明，可能需手动处理 |
| `Breaking: no` | 兼容 | 直接升级 |

## 2. venv 直装升级

### 一键升级（推荐）
```bash
cd /opt/SecOpent
secopent upgrade
```
`secopent upgrade` 自动执行：`git pull` -> `pip install -e ".[dev]"` -> `npm install && npm run build` -> `alembic upgrade head` -> `doctor` 验证。

**选项**：
- `--dry-run`：只打印步骤不执行
- `--no-frontend`：跳过前端重建（纯后端 patch 用）
- `--no-migrate`：跳过 alembic（CHANGELOG 标 `Schema: no` 时用）

完成后手动重启：
```bash
sudo systemctl restart secopent
python3 scripts/verify_env.py    # 验证环境
```

### 手动分步（排查问题时用）
```bash
cd /opt/SecOpent

# 1. 拉代码
git pull --ff-only

# 2. Python 依赖（CHANGELOG 标 Deps: yes 时）
pip install -e ".[dev]"

# 3. 前端（CHANGELOG 标 Deps: yes 或有前端改动时）
cd src/secopent/interfaces/web && npm install --legacy-peer-deps && npm run build && cd -

# 4. DB 迁移（CHANGELOG 标 Schema: yes 时）
alembic upgrade head

# 5. 重启 + 验证
sudo systemctl restart secopent
secopent doctor
python3 scripts/verify_env.py
```

## 3. 容器部署升级

```bash
# 1. 拉新镜像
docker pull secopent:0.1.2

# 2. 备份（DB 在 volume 里，迁移前先备份）
docker exec secopent secopent backup --db /data/secopent.db --out /backup

# 3. 替换容器（DB volume 持久化，不丢数据）
docker stop secopent
docker rm secopent
docker run -d --name secopent \
    -p 8000:8000 \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v secopent-data:/data \
    -e SECOPTENT_DB_URL=sqlite:////data/secopent.db \
    -e MINIMAX_API_KEY=sk-... \
    --restart unless-stopped \
    secopent:0.1.2
```

**自动迁移**：镜像 CMD 已含 `alembic upgrade head`，容器启动时自动跑迁移（幂等，已是最新则 no-op）。无需手动迁移。

## 4. 按版本类型

### Patch（0.1.1 -> 0.1.2）
通常 `Schema: no | Deps: no | Breaking: no`。**纯代码，最轻**：
```bash
secopent upgrade --no-migrate      # 通常无 schema 变更
sudo systemctl restart secopent
```
**不需要动 Docker 镜像/靶场**。

### Minor（0.1.x -> 0.2.0）
可能 `Schema: yes | Deps: yes`。**先备份再升级**：
```bash
secopent backup --db ... --out /backup --include-secrets --secrets ...
sudo systemctl stop secopent
secopent upgrade                   # 含迁移
sudo systemctl start secopent
secopent doctor
```

### Major（0.x -> 1.0）
`Breaking: yes`。**读专门迁移文档**（届时发布），全备份，按文档处理不兼容变更。

## 5. Docker 环境何时需更新（与 app 升级独立）

**应用升级不要求更新 Docker 环境**，但以下情况需单独处理：

| 组件 | 何时更新 | 命令 |
|---|---|---|
| 适配器镜像（nuclei 等） | CHANGELOG 提到 image_catalog digest 变更（罕见） | `docker pull <new-digest>` |
| 靶场（Juice Shop/httpbin） | 你用练习靶场且想最新版（可选，非必须） | `docker compose -f scripts/provision/docker-compose.targets.yml pull` |
| Interactsh | 想升级 OOB 服务（可选） | `docker compose -f scripts/provision/docker-compose.interactsh.yml pull` |
| Docker Engine | 系统包升级（独立） | `apt upgrade docker.io` |
| daemon.json mirrors | 极少变 | 改完 `sudo systemctl restart docker` |

**关键**：靶场/Interactsh 是**基础设施**，不是应用一部分。扫真实授权目标根本不需要靶场。应用升级与它们无关。

## 6. 回滚

升级出问题需回滚：

**venv**：
```bash
cd /opt/SecOpent
git checkout v0.1.1          # 回退到上一 tag
pip install -e ".[dev]"
# 若迁移过 schema，需 alembic downgrade：
alembic downgrade -1         # 回退一个迁移版本（谨慎）
sudo systemctl restart secopent
# 或从备份恢复 DB：
secopent restore --db /opt/SecOpent/data/secopent.db --from /backup/secopent-backup-XXXX.db
```

**容器**：
```bash
docker stop secopent && docker rm secopent
docker run -d ... secopent:0.1.1    # 用旧镜像
# DB 若迁移过，旧镜像启动时 alembic 不会自动 downgrade -- 需手动恢复备份
```

**注意**：alembic downgrade 可能丢数据（新版本写入的字段）。**优先从备份恢复**而非 downgrade。

## 7. 升级验证清单

- [ ] `secopent doctor` 输出 `ok`
- [ ] `python3 scripts/verify_env.py` ALL PASS（镜像/靶标/interactsh/LLM）
- [ ] `curl http://localhost:8000/api/health` -> `{"status":"ok"}`
- [ ] `curl http://localhost:8000/` -> SPA 加载
- [ ] `journalctl -u secopent --since "5 min ago"` 无 ERROR
- [ ] 建一个测试评估，确认核心流程（建->批准->Start->findings）通

## 8. 自动化建议

- **cron 定期检查更新**：`0 6 * * * cd /opt/SecOpent && git fetch && git log HEAD..origin/master --oneline | head`（只通知不自动升）
- **不要自动升级**：升级需人工读 CHANGELOG + 备份，自动升级有数据风险
- **备份 cron**（T8 已建议）：`0 2 * * * secopent backup --db ... --out /backup`

## 9. 当前版本升级路径示例

从 v0.1.0 升到 v0.1.2（当前）：
- v0.1.0 -> v0.1.1：Linux 适配（`Schema: no | Deps: no`，纯代码+文档）
- v0.1.1 -> v0.1.2：P0 执行闭环（`Schema: no | Deps: no`，纯代码+新端点）

两步都是 patch，直接：
```bash
secopent upgrade --no-migrate
sudo systemctl restart secopent
```
