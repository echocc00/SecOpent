# A4 Spike 结论：ptai 真实集成（re-scoped）

> **状态**：A4 spike 完成，结论是**重新定位（re-scope）**——ptai 不适合作为 oracle 验证后端，真实 oracle N/N 已在 A3 用真实扫描复现交付。
> **日期**：2026-07-27

## 1. Spike 发现：ptai 的真实性质

`pip install ptai`（ptai 1.1.0，MIT，0xSteph，https://pentestai.xyz）：

> "Autonomous AI pentesting with 200+ tools, exploit chaining, PoC validation, and credential-safe MCP server"

**ptai 是一个自主 AI 渗透 agent**，不是验证库：
- 顶层模块是 `agents/`（ad / api_security / browser / cloud / credential_tester 等 agent），可执行文件 `ptai.exe` / `pentest-ai.exe`。
- 以 **MCP server + CLI** 形式提供，**没有** `ptai.verify(candidate)` 这类可嵌入的验证函数。
- 导入名不是 `ptai`（distribution 名 ≠ import 名），实际 import `agents.*`。
- 重依赖：`impacket`、`bloodhound`、`scapy`、`fastmcp`、`paramiko` 等。

## 2. 与设计假设的冲突

主设计 §9 / ADR-014 假设「采纳 pentest-ai 作 OracleEngine 验证后端，N/N 复证」。但 ptai 实际是**自主渗透 agent**（自己跑完整渗透），不是「对单个 Candidate 做 N/N 复证」的验证后端。二者性质不符：

- 设计要的：`oracle.verify(candidate) -> CONFIRMED/REFUTED`（对已知疑似漏洞做可复现验证）。
- ptai 提供：一个会自己规划+执行+利用的自主 agent（peer/替代渗透工具，非验证 oracle）。

## 3. 环境问题

- 完整依赖在本 **Windows** 环境装不上：`impacket` 安装触发 `OSError: ...Scripts/CheckLDAPStatus.py`（impacket 在 Windows 的 Scripts 安装问题），导致 `pip install ptai`（含依赖）失败。
- `--no-deps` 可装上 ptai 包本体，但缺依赖不可用（已卸载，保持环境干净）。
- `cryptography` 被升级到 49.0.0（Ed25519 仍正常，项目无损）。

## 4. 决策

1. **真实 oracle N/N 已在 A3 交付**：`tests/e2e_real/test_real_scans.py` 用 `RescanVerifier`（真实重扫复现）+ `OracleEngine` 对活跃 Juice Shop 真实确认 SQLi（N/N=5 复现，CONFIRMED）。这是可复现漏洞的合法 oracle，无需 ptai。
2. **ptai 重新定位为可选的未来 peer 渗透 agent**（非 oracle 后端）：若要集成，经 M4 MCP 工具注册表作为**采纳的外部 MCP**（标 trust level `adopted_external_mcp` / `untrusted`），让 agent 把 ptai 当工具调用——而不是当验证后端。
3. **ptai 真实集成需要 Linux 环境**（impacket/bloodhound/scapy 在 Linux 安装正常）。当前 Windows 开发环境不具备条件，列为后续（V1.1/V2）。
4. **oracle_ground_truth 真实化**：Juice Shop 已在 A3 e2e_real 真实确认；crAPI（多镜像 compose）/vulhub（特定 CVE 环境）需要 Docker 配给，列为后续配给后补真实回归（当前 mock 版 9 测试仍绿，保护 oracle 逻辑）。

## 5. 复现 spike 的命令

```bash
py -3.12 -m pip install ptai            # 失败：impacket Scripts/CheckLDAPStatus.py OSError
py -3.12 -m pip install ptai --no-deps  # 装上包本体但缺依赖不可用
py -3.12 -m pip show ptai               # 确认是 autonomous pentest agent + MCP server
py -3.12 -m pip show -f ptai            # 顶层模块是 agents/，可执行 ptai.exe/pentest-ai.exe
py -3.12 -m pip uninstall ptai -y       # 清理残缺安装
```

## 6. 后续（若启用 ptai，需 Linux）

- Linux 环境 `pip install ptai`（依赖正常）。
- 起 ptai MCP server，经 M4 MCP 工具注册表以 `adopted` trust level 接入（输出标 untrusted，不驱动确定性裁决）。
- ptai 作 peer 渗透 agent（自主扫描产出 finding），其 finding 仍须经本项目 oracle（真实复现）N/N 确认才入报告。
