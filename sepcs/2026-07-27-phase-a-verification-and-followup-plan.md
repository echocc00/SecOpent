# 阶段 A 验收 + 后续开发计划

> **日期**：2026-07-27
> **状态**：Phase A（本环境可达部分）完成，验证与设计一致性，规划后续
> **当前**：816 默认测试 + 2 e2e_real + 7 integration 全绿，ruff/mypy strict（176 文件）/verify_env 5/5 全绿

---

## 1. 验证报告：完成部分与设计的一致性

### 1.1 完全符合设计 ✅

| 项 | 设计要求 | 实现状态 | 证据 |
|---|---|---|---|
| 确定性脊柱九模块 | §6.2 LLM 无关 | ✅ | Planner/PolicyEngine/QualityGates/TestCatalog/CoverageMatrix/AppModel/LogicTestGenerator/VerificationMethodRegistry/OracleEngine 全在，`decide_outcome` 确定性 |
| LLM 边界（§4.9） | LLM 仅提议不裁决 | ✅ 零违规 | LLM 仅在 `RemoteModelGateway`（分级/脱敏/预算/限速/审计）+ AppModel 起草（LLM_PROPOSED 人审签名）；Finding 确认/severity/报告数字/覆盖判定全确定性 |
| oracle N/N（§9.2） | N 次复现才 Confirmed | ✅ | `OracleEngine.verify` 注入 `OracleVerifier` Protocol，N 次复现 + `decide_outcome`；A3 真实确认 Juice Shop SQLi（N=5 复现） |
| TestCatalog + CoverageMatrix（§4） | 目录驱动，agent 只加不减 | ✅ | M1 实现 + 覆盖门禁（0 uncovered 结题）+ 退化门禁选项 D |
| Adapter Pack 17 个（§8.2） | 四域 + digest 固定 + 安全 flags | ✅ | 17 adapter + `image_catalog.py` 10 digest 固定 + `SubprocessContainerExecutor`（nonroot/cap-drop/read-only） |
| Update Bundle（§10.4） | 签名+staging+激活+回滚 | ✅ | Ed25519 签名 + 原子激活 + rollback + 审计 |
| 14 安全条件（§16.2） | 全测试 | ✅ | 80 安全测试全绿 |
| Repository Contract（ADR-017） | SQLite+PG 双后端 | ✅ | Protocol 抽象，双后端，切换不触碰 domain/application |
| Audit hash chain（ADR-016） | M0 起步 + M5 完整 | ✅ | 签名 + rotation 续链 + GDPR 保留 + 篡改检测 |
| A6 LLM 接入（§12.11） | 远程大模型 + 分级/脱敏/预算/降级 | ✅ | MiniMax 真实接入，`RemoteModelGateway` 完整，SENSITIVE 脱敏发送前生效（实测验证） |
| A7 mypy strict | domain+application strict | ✅ **超额** | 全仓 176 文件 strict 0 错误（超越设计的 domain+application 目标） |
| A2 SubprocessContainerExecutor | docker run + digest + 安全 flags | ✅ | 真实跑 nuclei/nmap 等，digest 校验，4 集成测试绿 |

### 1.2 已知延后（设计内允许，文档化）⚠️

| 项 | 设计要求 | 当前状态 | 延后原因 | 后续 |
|---|---|---|---|---|
| A3 真实 E2E 三靶场 | Juice Shop/crAPI/httpbin | juice_shop 真实 SQLi 确认 ✅；httpbin 真扫 ✅；**crAPI 未做** | crAPI 多镜像 compose 配给复杂 | §2.3 补 crAPI |
| oracle ground-truth 靶场集 | Juice Shop/crAPI/vulhub | Juice Shop 真实 ✅；crAPI/vulhub mock 版 9 测试绿 | crAPI/vulhub 需 Docker 配给 | §2.3 补真实回归 |
| Scoped Egress 网络层 | §12.4 nftables/netns 阻 metadata | **option c**：app 层 `EgressGuard`（阻 169.254/127.0.0.0/8）+ bridge 网络 | Docker Desktop 网络限制，option c 先跑通 | §2.4 M5 强化到 nftables |
| A5 Web Case Studio | §13 M4 Web UI 7 页 | **未构建**（`interfaces/web` 不存在） | M4 只做 MCP/API/CLI，前端未做 | §2.2 Phase B 构建 |

### 1.3 需修正的设计偏离 ❌

**ADR-014（ptai 作 oracle 后端）-- 设计假设不成立**

| 维度 | 内容 |
|---|---|
| 设计假设 | ADR-014 + §9.2：「采纳 pentest-ai（ptai）作 OracleEngine 验证后端，N/N 复证」 |
| 真实情况 | A4 spike 发现：ptai 1.1.0 是**自主 AI 渗透 agent**（MCP server + CLI，200+ 工具），**不是** `ptai.verify()` 验证库。设计假设的 API 不存在 |
| 当前代码 | `infrastructure/oracle/ptai_adapter.py` 是**桩代码**（注入 fake module 单测，真实 ptai import 不可用）--本质是死代码 |
| 实际 oracle | A3 用 `RescanVerifier`（真实重扫复现）+ `OracleEngine`（N/N + decide_outcome）--这是合法 oracle（重扫确认可复现），无需 ptai |
| 影响 | oracle 功能完整可用（A3 真实验证）；但 ADR-014 文字与实现不符，`PtaiAdapter` 是死代码需清理 |
| 修正动作 | §2.1 修正 ADR-014 + 清理 PtaiAdapter |

### 1.4 验证结论

**核心设计（目录驱动 + 确定性脊柱 + LLM 边界 + oracle N/N + 四域 adapter）全部落地且与设计一致**。1 个设计假设（ptai）需修正，几个已知延后（crAPI/vulhub、scoped egress 网络层、Web UI）在设计允许范围内。Phase A 本环境可达部分**验收通过**。

---

## 2. 后续开发计划（优先级排序）

### 优先级 P0：设计修正 + 死代码清理（立即，1-2 天）

#### 2.1 修正 ADR-014 + 清理 PtaiAdapter
**问题**：ADR-014 假设 ptai 是验证库，实际是自主 agent。`PtaiAdapter` 是死代码。

**动作**：
1. 更新 `sepcs/2026-07-25-decisions.md` ADR-014：
   - Context 补充 A4 spike 发现（ptai 真实性质）
   - Decision 改为：「OracleEngine 用自建 `RescanVerifier`（真实重扫 N/N 复现），不采纳 ptai 作 oracle 后端；ptai 重定位为未来可选 peer agent（经 MCP 注册表以 trust level 接入）」
   - Consequences 补充：自建 oracle 已在 A3 真实验证；ptai 集成需 Linux 环境 + MCP trust level
2. 清理 `infrastructure/oracle/ptai_adapter.py`：
   - 选项 a（推荐）：**删除** PtaiAdapter（死代码），`OracleEngine` 用 `RescanVerifier` 作默认 verifier
   - 选项 b：保留为「未来 MCP peer agent 接入点」骨架，但标注「非 oracle 后端，待 V1.1/V2」
3. 更新主设计 §9.2 + §22.5（采纳清单去掉 ptai 作 oracle，改为 peer agent 候选）
4. 验证：816 测试无回归 + mypy/ruff clean

**验收**：ADR-014 修正、PtaiAdapter 清理或重标注、设计文档与实现一致

---

### 优先级 P1：补全真实 E2E + oracle 靶场（1-2 周）

#### 2.2 补 crAPI + vulhub 真实回归
**目标**：A3 的 3 靶场真实 E2E 补全（当前只有 juice_shop + httpbin 真实）

**动作**：
1. crAPI 配给：拉 crAPI 多镜像 compose（web/api/auth/db），启动 + 验证可达
2. crAPI 真实 E2E 测试：`tests/e2e_real/test_crapi_real.py`--真实扫 crAPI，oracle 确认 IDOR/认证类 finding
3. vulhub 配给：选 3-5 个 vulhub CVE 环境（如 CVE-2024-xxxx），docker-compose 起
4. vulhub 真实回归：`tests/oracle_ground_truth/test_vulhub_real.py`--oracle 对已知 CVE 真实确认
5. 修 parser 偏差（crAPI/vulhub 真实输出 vs fixture）

**验收**：crAPI 真实 E2E ≥1 Confirmed Finding；vulhub 3-5 CVE oracle 真实确认；e2e_real + oracle_ground_truth 真实版全绿

**依赖**：Docker 配给（本机已具备，crAPI/vulhub 镜像需拉）

---

### 优先级 P1：Web Case Studio 构建（Phase B 核心，2-4 周）

#### 2.3 构建 Web 前端
**现状**：`interfaces/web` 不存在，M4 只有 FastAPI API（OpenAPI）+ MCP + CLI

**决策需你定**（技术栈）：
- a. **HTMX + Jinja2 服务端渲染**（轻量，Python 栈，快速，够用）--推荐
- b. **React/Vue SPA**（重，前端工程化，体验好但工期长）
- c. **延后**（先用 CLI/API，Web 放 V2）

**动作**（按 a）：
1. 建 `interfaces/web/`：FastAPI 路由 + Jinja2 模板 + HTMX
2. 7 页：Dashboard / NewAssessment / AssessmentDetail / ApprovalCenter / Findings / CaseStudio / Updates
3. Case Studio 核心功能：AppModel 可视化建模（状态机图 + 不变量编辑 + 签名）+ Case YAML 编辑 + Dry Run
4. Playwright 浏览器测试：`tests/web/test_case_studio_browser.py`（7 页可达 + 关键交互）
5. 接 FastAPI API（M4 已有）+ MCP 工具注册表

**验收**：7 页浏览器可用，Case Studio 建模+签名+生成测试全流程通，Playwright 测试绿

**工期**：2-4 周（取决于技术栈）

---

### 优先级 P2：Scoped Egress 网络层强化（M5 收尾，1-2 周）

#### 2.4 nftables/netns 真实网络隔离
**现状**：option c（app 层 EgressGuard + bridge 网络），设计 §12.4 要网络层强制

**动作**：
1. `infrastructure/egress/scoped_egress_setup.py`：创建 Docker network + nftables 规则
2. nftables 阻：metadata（169.254.169.254）/ DB / Docker host / Scope 外 IP
3. `SubprocessContainerExecutor` 接 scoped-egress 网络（替换 bridge）
4. 测试：容器内访问 metadata 真实被阻（nftables 层，非 app 层）
5. 14 安全条件中的 egress 条目升级为网络层强制

**注意**：Docker Desktop（Windows）nftables 需 WSL2 内核支持，需测试。若不可用，Linux 部署时做。

**验收**：nftables 规则生效，metadata/DB/Docker host 网络层阻断，14 安全条件 egress 项网络层强制

---

### 优先级 P2：ptai 作 peer agent 接入（V1.1/V2，1-2 周）

#### 2.5 ptai 经 MCP 注册表作 peer agent
**目标**：ptai 重定位为可选 peer 渗透 agent（非 oracle），经 M4 MCP 注册表以 trust level 接入

**动作**：
1. Linux 环境装 ptai（impacket/bloodhound/scapy 在 Linux 正常）
2. ptai 作 MCP server 启动，注册到 M4 `McpToolRegistry`（标 `adopted_external_mcp` / untrusted）
3. agent 可调 ptai 工具（peer 渗透能力），输出经 oracle 复证才确认
4. 文档：ptai 是 peer agent，不是 oracle；输出 trust level untrusted

**验收**：ptai 在 Linux 跑，MCP 注册表接入，agent 可调，输出经 oracle 验证

**依赖**：Linux 环境（本 Windows 不行）

---

### 优先级 P3：Phase B 打磨（V1.1-stable，4-6 周）

#### 2.6 真实场景验证 + 反馈打磨
1. 拿授权目标做 1-2 次真实渗透，收集反馈
2. 性能/稳定性：大 Scope 并发、长任务、内存、超时、重试
3. 策展补全：TestCatalog 覆盖率从 V1 轻策展提到 80%+ WSTG
4. 文档 + 用户指南：安装/配置/使用/扩展
5. 错误处理 + 日志：真实场景异常路径、可观测性
6. CI/CD：GitHub Actions 多矩阵 + compose smoke + 覆盖率门禁

**验收**：真实渗透场景验证通过，性能稳定，策展 80%+，文档完整，CI 全绿

---

### 优先级 P4：V2 扩展（3-4 月）

#### 2.7 V2 已锁定项（§22.4）
1. 远程 Worker 分布式（§6.7 spec 已备，O1=B）
2. 竞态/角色逻辑测试（M3 余 2 类）
3. 多租户 SaaS / 团队协作 / 客户门户（ToB）
4. 合规审计增强（SOC2/ISO27001）

---

## 3. 推荐执行顺序

```
立即（1-2 天）：
  P0 §2.1 修正 ADR-014 + 清理 PtaiAdapter

短期（1-2 周）：
  P1 §2.2 补 crAPI/vulhub 真实 E2E
  P1 §2.3 Web Case Studio（需你定技术栈 a/b/c）

中期（1-2 周）：
  P2 §2.4 Scoped Egress 网络层强化
  P2 §2.5 ptai peer agent（需 Linux）

长期（4-6 周）：
  P3 §2.6 Phase B 打磨到 V1.1-stable

远期（3-4 月）：
  P4 §2.7 V2 扩展
```

## 4. 需你决策的点

1. **P0 §2.1 PtaiAdapter 处置**：删除（推荐，死代码）还是保留为 peer agent 骨架？
2. **P1 §2.3 Web 技术栈**：HTMX（推荐，轻量）/ React（重）/ 延后？
3. **P2 §2.5 ptai peer agent**：现在规划还是 V2 再做？（需 Linux 环境）
4. **下一步先做哪个**：P0 修正（快）还是 P1 补 E2E / 建 Web？

---

## 5. 当前可立即做的

**P0 §2.1（修正 ADR-014 + 清理 PtaiAdapter）** 是最该先做的：
- 设计与实现的一致性修正（诚实记录 ptai 真实性质）
- 清理死代码（PtaiAdapter 桩）
- 1-2 天完成，无外部依赖，纯文档+代码清理

要我现在开始 P0 §2.1 吗？还是你先定 §4 的决策点再统一推进？
