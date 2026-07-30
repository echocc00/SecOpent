# 备份与恢复运维手册（§3.8 / T8）

> 适用：SecOpent 单机部署（SQLite + 加密 SecretStore）。
> 目标：可重复、可验证的备份/恢复，确保审计链完整、签名密钥可恢复。

---

## 0. 备份包含什么

| 内容 | 命令/位置 | 是否含密钥明文 |
|---|---|---|
| SQLite 主库（评估/发现/审计链/Case/报告） | `secopent backup --db <db> --out <dir>` | 否（审计仅存引用） |
| 加密 SecretStore 导出 | `--include-secrets --secrets <secrets.enc>` | 否（已加密） |
| **Fernet 主密钥** | **环境变量 / KMS，运维线下保管** | **从不写入备份** |

> ⚠️ **核心原则**：备份里只有**密文**。Fernet 主密钥（解密 SecretStore 用）**绝不**进入备份目录——备份泄露 ≠ 机密泄露。主密钥须**另行托管**（KMS / 离线密码管理器 / 密钥分片），丢失则加密机密不可恢复。

---

## 1. 日常备份（建议每日 cron）

```bash
# 1a. 数据库一致性快照（在线安全，API 写入时也可跑）
secopent backup --db /var/lib/secopent/secopent.db --out /var/backups/secopent

# 1b. 连同加密 SecretStore 一起备份（主密钥仍不在内）
secopent backup --db /var/lib/secopent/secopent.db \
                --out /var/backups/secopent \
                --include-secrets --secrets /var/lib/secopent/secrets.enc
```

cron 示例（每日 02:17，错峰）：

```cron
17 2 * * * secopent backup --db /var/lib/secopent/secopent.db --out /var/backups/secopent --include-secrets --secrets /var/lib/secopent/secrets.enc >> /var/log/secopent-backup.log 2>&1
```

备份产物：`secopent-backup-<时间戳>.db` + `secrets-<时间戳>.enc`。建议保留最近 N 份并异地同步（rsync/对象存储）。

---

## 2. 恢复流程

```bash
# 1. 停服（恢复期间不可有写入；CLI 无法停止独立进程，需手动）
systemctl stop secopent        # 或停止 uvicorn 进程

# 2. 恢复（自动：先验备份链 -> 留回滚点 .pre-restore-<ts> -> 原子替换 -> 复验）
secopent restore --db /var/lib/secopent/secopent.db \
                 --from /var/backups/secopent/secopent-backup-<时间戳>.db

# 3. 独立复核审计链
python scripts/verify_backup.py /var/lib/secopent/secopent.db

# 4. 恢复加密 SecretStore（从对应的 secrets-<ts>.enc 拷回），并确保主密钥在环境/KMS 中
cp /var/backups/secopent/secrets-<时间戳>.enc /var/lib/secopent/secrets.enc

# 5. 起服
systemctl start secopent
```

`secopent restore` 的安全语义：
- **先验备份**：备份审计链无效则**拒绝恢复**（不碰当前库）。
- **回滚点**：覆盖前把当前库快照为 `<db>.pre-restore-<时间戳>`。
- **原子替换**：临时文件 + `os.replace`，无半截库。
- **复验 + 回滚**：替换后复验审计链，失败则自动回滚到回滚点。

---

## 3. 验证工具

```bash
# 审计链完整性（exit 0 = 完整，1 = 损坏）
python scripts/verify_backup.py <db-path>
```

`secopent restore` 内部即调用同一校验（`infrastructure/audit/chain_verify.py`）。

---

## 4. 恢复后签名可验

- **审计哈希链**：恢复后由 `verify_backup.py` 复算，完整即可信（每事件 `previous_hash` 链接 + `event_hash` 重算一致）。
- **签名密钥**：更新包/许可签名密钥（Ed25519）随加密 SecretStore 恢复；主密钥在环境/KMS 中即可解密，旧签名恢复后可验。

---

## 5. 月度恢复演练（必做）

1. 取最近一份备份到**隔离目录**。
2. `secopent restore --db <演练库> --from <备份>`。
3. `python scripts/verify_backup.py <演练库>` → 期望 `OK`。
4. 抽查事件计数/关键发现条数与生产一致。
5. 记录演练结果（时间/操作人/结论），归档。

> 未演练的备份等于没有备份。演练同时验证：备份可解、主密钥可解密 SecretStore、审计链完整。

---

## 6. 常见失败排查

| 现象 | 原因 | 处置 |
|---|---|---|
| `restore` 报 `backup audit chain INVALID` | 备份损坏/被篡改 | 换一份备份；排查备份链路完整性 |
| `verify_backup.py` 返回 1 | 库审计链断裂 | 用回滚点 `.pre-restore-*` 或更早备份恢复 |
| `--include-secrets requires --secrets` | 未提供加密 SecretStore 路径 | 补 `--secrets <secrets.enc>` |
| 恢复后机密解不出 | Fernet 主密钥缺失 | 从 KMS/离线托管恢复主密钥（备份里没有） |
