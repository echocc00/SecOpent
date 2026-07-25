# 目录驱动 Agent 渗透工作台设计规范

- **状态**：已批准（V1 全架构 A）
- **日期**：2026-07-25
- **取代**：`2026-07-24-security-assessment-operations-platform-design.md`、`2026-07-25-agent-native-pentest-workbench-design.md`
- **V1 范围**：全覆盖（Web/API + 网络主机 + 云容器 + 资产测绘）+ 模型驱动逻辑测试（V1 3 类：跳步/不变量违反/越界）+ 完整 Scoped Egress + Update Bundle + Case Studio 可视化（分布式 Worker 推 V2，见 §6.7）
- **单人工期估算**：4-6 月（含集成/调试/返工缓冲；初版 3-5 月偏乐观经 H1 修正 + O1/O3 缩范围 + 采纳 RESTler/Schemathesis/pentest-ai 复用，详见 §13）
- **用途约束**：仅用于合法授权渗透测试与防御性安全用途

---

## 1. 背景与推倒重来决策

### 1.1 推倒重来的原因

本项目已有两份设计：
- 07-24《开源安全评估与安全运营协同平台设计》：MSSP 多租户评估运营平台（Provider/Customer/Workspace、RBAC+ABAC、客户门户、Wazuh/MISP/OpenCTI 连接器、长期 SOC 方向）。已落地 14 ORM 模型 + 115 测试，但多租户机制对单兵场景是悬重资产。
- 07-25《Agent-native 渗透工作台设计》：单用户 Agent-native 方向（MCP-first、SQLite、DB Job Lease、冻结多租户）。方向正确但未吸收早期 curl 实测调研结论（MCP 生态采纳优先、OSV 主源、pentest-ai oracle 验证范式）。

两份设计共存导致文档碎片化、概念债务累积、无单一权威设计。本轮**推倒重来**：搁置 07-24 多租户遗产和 07-25 的 M0-M5 骨架，从当前需求出发做一份干净的系统设计，复用已有调研结论但不受旧代码约束。

### 1.2 核心决策清单（本轮确立）

| # | 决策 | 选项 |
|---|---|---|
| 1 | 产品定位 | Agent-native、单用户、全覆盖渗透工作台 |
| 2 | V1 覆盖 | 全覆盖（Web/API + 网络主机 + 云容器 + 资产测绘） |
| 3 | 架构脊柱 | 混合：框架铺路 + agent 驾驶 + Policy 刹车 + 人审批 |
| 4 | 覆盖责任方 | TestCatalog（产品 IP），agent 只加不减 |
| 5 | 验证责任方 | oracle N/N（确定性），LLM 永不裁决 |
| 6 | 质量责任方 | 确定性 Quality Gates，LLM 无关 |
| 7 | 业务逻辑覆盖 | 三层拆分，第二/三层模型驱动自动执行（V1 含） |
| 8 | 建模治理 | LLM proposes, human disposes, product executes；人签名 |
| 9 | MCP 策略 | 采纳优先（cve-mcp-server / mcp-security-hub）+ 自写编排 tool |
| 10 | 漏洞情报源 | OSV 主源（NVD 国内 503）+ KEV + EPSS |
| 11 | 知识层开源分层 | 聚合层 + CoverageMatrix MIT 开源；TestCatalog/AppModel/OracleEngine 产品 IP（O4=B） |
| 12 | 覆盖率退化门禁 | 选项 D：0 容忍 + override-with-reason |
| 13 | POC 格式 | Nuclei YAML 基础 + 验证扩展（采纳不重造） |
| 14 | V1 交付范围 | A 全架构（分布式 Worker 推 V2，O1=B；LogicTestGenerator V1 3 类，O3=B） |
| 15 | Audit 起步 | M0 起最小 Audit + hash chain（非 M5，外部评审 H2.1） |
| 16 | OOB 反连 | V1 自托管 Interactsh（国内公共 OOB 不稳，外部评审 H4） |
| 17 | Repository 抽象 | M0 起抽象 Repository Contract（非 SQLite-only，外部评审 H2.4） |
| 18 | LogicTestGenerator 幂等 | 输出带 signature（AppModel 内容哈希），重复跑去重（外部评审 M2） |
| 19 | Custom POC 晋升 | Community 审核 -> 可选晋升 TestCatalog（外部评审 M3） |
| 20 | Redaction 范围 | 延伸到 Report 渲染层；区分我方/目标 secret（外部评审 M7/M9） |
| 21 | MCP 供应链 | 采纳的 MCP 输出标 trust level + 供应链 mitigation（外部评审 M8） |
| 22 | OracleEngine | 采纳 pentest-ai（MIT）作 oracle，建 VerificationMethodRegistry 策展层（不造轮子） |
| 23 | LogicTestGenerator | 采纳 RESTler（跳步/乱序）+ Schemathesis（越界部分），自建不变量违反 + 编排层（不造轮子） |

---

## 2. 产品定位与边界

### 2.1 定位

面向授权渗透测试的、Agent-native、单用户、全覆盖渗透工作台。Agent 经 MCP 端到端编排侦察->扫描->验证->报告，确定性 Policy Engine 约束，人审批高风险。

- **目标用户**：个人渗透测试者 / 红队单兵
- **技术路线**：集成编排现有开源引擎（不自研扫描内核）；MCP 层采纳优先
- **部署**：Lite（2C2G 控制节点 + 远程 Worker）/ Standalone（4C8G 推荐同机全栈）

### 2.2 V1 覆盖边界（全覆盖）

| 域 | V1 覆盖 | V1 不做 |
|---|---|---|
| Web/API | 外网/Web 应用/API 安全测试、指纹、爬取、注入、认证、配置错误 | 无线/移动二进制 |
| 网络与主机 | 端口/服务/OS、漏洞脚本、弱 TLS、管理界面 | 自动提权/横向/持久化 |
| 云与容器 | AWS/阿里云配置审计、容器/IaC 扫描、K8s 基线 | 云 IAM 全链路、AD 全链路 |
| 资产测绘 | 子域、IP/CIDR、TLS、HTTP 可达、技术栈、关系图 | 大规模互联网测绘 |
| 横切 | 漏洞情报实时同步、自定义 POC、无害化验证、复测、报告 | 多租户 SaaS、插件市场、K8s 调度、AI 自动改目标 |

未来扩展只能作为独立 Capability Pack，仍受 Scope/Policy 约束。

---

## 3. 架构脊柱：三方分工

### 3.1 混合模型（非纯 agent，非纯框架）

| 谁 | 拥有 | 不拥有 |
|---|---|---|
| **框架（产品）** | 阶段序列（侦察->枚举->扫描->验证->报告）、覆盖契约、门禁、安全护栏 | 具体调哪个工具/参数/何时算"够" |
| **Agent** | 阶段内决策：选工具/参数/目标迭代、追查线索、提议新 Plan Version、写 POC 草稿、判误报 | 改 scope、绕门禁、执行未批准高风险、发布 POC、签发 Finding |
| **人** | 审批 scope、plan、Active/Intrusive 动作、超 autopilot 包络的 Plan Version、签 POC、终审 Finding | -- |
| **Policy Engine** | 每个动作前强制校验：scope/DNS/risk/capability/budget/time；Deny 优先；Destructive 永拒 | -- |

### 3.2 覆盖契约（保证全覆盖不靠 agent 自觉）

Phase 5 Report 的前置条件（框架硬卡，agent 无法绕过）：
- 资产测绘：每个 in-scope 域名有 IP/端口/服务/URL/技术栈节点
- Web/API：每个 Web 资产跑过 ≥1 指纹 + ≥1 漏扫
- 网络主机：每个 IP/端口跑过 ≥1 服务识别 + NSE
- 云/容器：若发现云/容器资产，跑过配置审计
- 验证：0 个未验证 Candidate（每个 Confirmed 都过 oracle N/N）
- 证据：每个 Confirmed Finding 有不可变 Evidence + 版本快照

### 3.3 不选极端的理由

- 纯 agent-driven（pentest-ai/PentestGPT 式）：覆盖靠 agent 自觉，全覆盖不可保证
- 纯框架驱动（reNgine/Faraday 式）：agent 退化为参数填写器，失去 agent-native 价值
- **混合框架脊柱**：框架保证覆盖+安全+可复现，agent 贡献推理和自适应

---

## 4. 目录驱动覆盖（核心差异化）

### 4.1 问题与修正

混合模型若覆盖契约只检查"每个资产跑过 ≥1 次扫描"（广度），不检查"已知漏洞类是否都覆盖"（深度），则深度覆盖依赖 LLM 知不知道某测试类--结果不稳定、不可控、无竞争力。

修正：**把"测什么"的知识从 LLM 移到产品内的版本化 TestCatalog**。

### 4.2 TestCatalog

产品自有的、版本化的"该测什么"知识库，独立于 LLM：
```
Web 应用资产 -必修-> OWASP Top 10 + CWE 映射的 Nuclei tag 集 + 配置错误 + 技术栈专属
API 资产    -必修-> REST/GraphQL/OpenAPI fuzz + 认证 + 参数污染 + 批量赋值
IP/端口资产  -必修-> 服务识别 + NSE 漏洞类 + 弱 TLS + 默认凭证
云账户资产   -必修-> CIS 基线（Prowler/ScoutSuite 检查项全集）
容器/K8s 资产-必修-> 镜像扫描（Trivy）+ kube-bench + IaC（checkov）
自定义 POC registry（签名、版本化）
```

来源：nuclei-templates（git pull）+ nmap NSE + Prowler/ScoutSuite + Trivy/kube-bench/checkov + 用户/社区自定义 POC，全部版本化，每次 Assessment 固定快照。

### 4.3 修正后的分工

| 谁 | 拥有 | 关键约束 |
|---|---|---|
| TestCatalog（产品） | "必测什么"的知识，版本化、LLM 无关 | 产品护城河，不是 LLM 职责 |
| 框架 | 按 catalog 对每个资产强制排课必修测试类 | 覆盖契约硬卡"0 个未执行必修类才能结题" |
| Agent | 只能 ADD：参数化、优先级、追查、提议自定义 POC、判误报、写报告叙述 | **不能 SUBTRACT 必修类** |
| Policy/人 | 同前 | -- |

### 4.4 覆盖率评估方法（不靠 LLM，靠权威框架映射）

把 TestCatalog 映射到权威参考框架，算覆盖率，每版 catalog 附带覆盖率报告：

| 域 | 参考框架 | 计量 |
|---|---|---|
| Web | OWASP WSTG v4.2（94 用例）+ OWASP Top 10 (2021) | 映射用例数/总数 |
| API | OWASP API Top 10 (2023) | 10 类全覆盖 |
| 网络/主机 | PTES + NIST SP 800-115 | 阶段/控制项覆盖 |
| 云 | CIS Benchmarks（per provider） | 检查项覆盖 |
| 容器/K8s | CIS Docker/Kubernetes Benchmark | 检查项覆盖 |
| 横切 | CWE 分类 | 类别映射 |

每个参考条目要求 catalog 有 ≥1 测试类映射，否则记为 known gap。覆盖率是 LLM 无关的、可审计的数字。

### 4.5 集成项目能力矩阵（诚实评估）

| 测试类 | 集成项目 | 覆盖度 | 能否满足 |
|---|---|---|---|
| 已知 CVE/漏洞 | nuclei-templates（~1 万模板） | 高 | ✅ |
| 配置错误/暴露面板 | nuclei + Prowler/ScoutSuite | 高 | ✅ |
| 云基线 | Prowler/ScoutSuite（CIS 全集） | 高 | ✅ |
| 容器/IaC/K8s | Trivy/kube-bench/checkov | 高 | ✅ |
| 服务/网络漏洞 | nmap NSE | 中高 | ✅ |
| Web 技术测试 | nuclei tags + 自定义 POC | 中（~70-85% WSTG） | ⚠️ 需自定义 POC 补 |
| 业务逻辑/认证链/上下文相关 | 模型驱动（见 §4.6） | 可确定覆盖 | ✅ 三层拆分 |
| 0-day/未知 | -- | 无产品能覆盖 | ❌ 超出范围 |

### 4.6 业务逻辑三层拆分

OWASP WSTG-BUSL 给方法论不给模板（端点和顺序是 this-app-specific）。

| 层 | 子类 | catalog 覆盖 | 执行方式 | 裁决 |
|---|---|---|---|---|
| 第一层 通用模式 | IDOR、参数篡改提权、MFA 跳过、弱凭证、功能级越权 | ✅ 必修类 | 框架自动执行模板 | oracle |
| 第二层 应用工作流 | 状态机跳步、金额/数量操纵、竞态、业务规则绕过、信任边界 | ✅ 方法论门禁 + **模型驱动自动执行** | 模型生成 7 类测试，框架自动跑 | oracle |
| 第三层 上下文相关 | 业务语境相关（转账在银行 vs 游戏语义不同） | ✅ 方法论门禁 + 模型驱动 | 同上 | oracle |

**第二/三层用模型驱动自动执行**（见 §11），不靠人 ad hoc。

### 4.7 诚实的边界保证

- **保证**：所有映射到参考框架的确定性测试类都被执行，0 漏跑；覆盖率可审计
- **不保证**：0-day/未知
- 产品承诺是"不漏已知测试类"，不是"找出所有漏洞"

### 4.8 全流程确定性质量门禁（LLM 无关）

| 阶段 | 确定性门禁 | LLM 角色（仅提议） |
|---|---|---|
| 侦察 | 资产图完整性清单 + DNS/HTTP 交叉验证 + 规范化去重 | 选 wordlist、判定"够不够"（清单硬卡） |
| 枚举 | per-asset 枚举清单 | -- |
| 扫描 | catalog 覆盖矩阵：0 个未执行必修类 | 参数化、优先级 |
| 验证 | oracle N/N 复现 + 不可变证据（SHA256） | 提议验证手法（oracle 裁决） |
| 聚合 | 确定性指纹去重 + CVSS 计算定级 | 可建议调 severity，人审 |
| 报告 | 固定模板 + 结构化记录自动生成 + 每声明->evidence_id + 每数字->查询 + 覆盖矩阵全绿 | 仅可选执行摘要润色，人审 |

### 4.9 LLM 禁区

- ❌ 标记 Finding Confirmed（只有 oracle 能）
- ❌ 定 severity（CVSS 计算）
- ❌ 报告数字（自动从 DB 算）
- ❌ 判定覆盖完成（覆盖矩阵算）
- ❌ 证据完整性（SHA256 校验）
- ❌ 改 scope / 绕门禁

---

## 5. 领域模型核心

### 5.1 核心实体

```
Project -> ScopeDraft -> ScopeSnapshot (immutable, sha256 digest)
   |
   +-> Assessment -> ExecutionPlan -> PlanStep -> Approval
              |                              |
              +-> Job -> ExecutionPermit (签名短时, 绑 Worker/Scope/Plan/Capability/预算)
                    |
                    +-> ToolRun / CaseRun -> AssetGraph + Observation + Evidence
                                                  |
                                                  +-> CandidateFinding -> Validation(oracle N/N) -> ConfirmedFinding -> Report
```

### 5.2 关键实体

- **ScopeSnapshot**：不可变 + digest；Deny 优先于 Allow；DNS 解析后二次校验防 rebinding
- **Assessment 固定全版本快照**：scope/plan/policy/intel/case_registry/tool_registry/catalog/app_model/engine 版本，历史任务不漂移
- **ToolDefinition / CaseDefinition**：版本化 registry，镜像 digest 固定，Agent 只能填 Schema 参数不能注入任意 CLI
- **AssetNode / AssetEdge**：关系表表达（Domain->IP->Port->Service->URL->Endpoint->Technology），不引入图数据库
- **Finding 流水线**：Tool Result -> Observation -> Candidate -> Validation(oracle N/N) -> Confirmed；版本匹配不直接确认
- **Evidence**：内容寻址 CAS（`sha256/<prefix>/<digest>`），RAW/REDACTED/SUMMARY 三层，脱敏生成新对象不覆盖
- **TestCatalog + CoverageMatrix**：版本化，per-Assessment 快照
- **AppModel**：版本化、签名、per-Assessment 快照
- **VerificationMethodRegistry**：漏洞类型 -> 验证方法，策展版本化
- **Vulnerability / AffectedProduct / ExploitationSignal / DetectionMapping**：情报实体，每字段保留 provenance
- **AuditEvent**：previous_event_hash / event_hash 链（篡改可检测）
- **SecretMetadata**：任务只用 `secret_ref`，明文不入库/Prompt/日志/Evidence/报告

### 5.3 与 07-25 的关键差异

- 砍掉 Provider/Customer/Workspace 多租户层级
- 四覆盖域作为一等 Adapter Pack（非"后续 Capability Pack"）
- 验证层显式采纳 pentest-ai oracle N/N 复证范式
- 新增 TestCatalog / CoverageMatrix / AppModel / VerificationMethodRegistry
- MCP 层采纳优先（非自写门面）

---

## 6. 架构分层

### 6.1 五层架构

```
+------------------------------------------------------------------+
| 接口层  MCP(自写编排tool + 采纳cve-mcp-server/mcp-security-hub)   |
|         CLI | Web(Case Studio/审批中心/Findings/报告) | OpenAPI   |
+------------------------------------------------------------------+
| 控制平面                                                          |
|  +- 编排子层 ---------------------------------------------------+ |
|  | Planner(确定性DAG) | Orchestrator(调度/Lease/重试/预算/幂等) | |
|  | Policy Engine(确定性:scope/DNS/risk/capability/budget/time; | |
|  |   Deny优先; Destructive永拒) | Approval/Autopilot(双模式)   | |
|  | * Quality Gates(确定性LLM无关:覆盖矩阵/oracle/去重/可追溯)  | |
|  +-------------------------------------------------------------+ |
|  +- 应用服务子层 -----------------------------------------------+ |
|  | Project|Scope|Assessment|Plan|Approval|AssetGraph|Finding   | |
|  | Evidence|Report|Retest|Audit                                 | |
|  +-------------------------------------------------------------+ |
+------------------------------------------------------------------+
| * 知识层（产品护城河，LLM 无关）                                  |
|   TestCatalog | CoverageMatrix(OWASP/CIS映射) | AppModel |       |
|   ModelRegistry | LogicTestGenerator(模型->7类测试) |            |
|   DriftDetector | Case Registry | Tool Registry |                |
|   VerificationMethodRegistry | Intel Store(OSV主源+KEV+EPSS)     |
+------------------------------------------------------------------+
| 执行平面                                                          |
|   Worker Agent(注册/心跳/Lease) | Executors(Container/Builtin)   |
|   Case Engine(YAML AST + Python Sandbox) | Tool Containers       |
|   Scoped Egress(HTTP proxy / TCP netns+nftables) | Permit(签名)  |
+------------------------------------------------------------------+
| 基础设施                                                          |
|   DB(SQLite WAL/PostgreSQL) | CAS(Local/S3,内容寻址证据) |       |
|   Secret Store(keyring/加密文件/KMS; secret_ref only) |          |
|   Signing(Ed25519) | Update Bundles(tar.zst+签名,intel/case/tool/| 
|   model/curation同构) | Audit(hash chain) | Telemetry            |
+------------------------------------------------------------------+
   * = 确定性脊柱，LLM 无关，结果质量的责任方
```

### 6.2 确定性脊柱（LLM 无关，质量责任方）

`Planner + Policy Engine + Quality Gates + TestCatalog + CoverageMatrix + AppModel + LogicTestGenerator + VerificationMethodRegistry + OracleEngine`

这九个模块是结果质量的责任方，全部确定性、可审计、可复现。LLM 关掉仍能跑出完整基线报告。

### 6.3 各层职责

| 层 | 职责 | 关键模块 |
|---|---|---|
| 接口层 | agent/人/脚本统一入口；MCP 采纳优先 | MCP Server、CLI、Web Case Studio、OpenAPI |
| 控制平面-编排 | 确定性脊柱：规划、调度、策略、门禁 | Planner、Orchestrator、Policy Engine、Approval/Autopilot、Quality Gates |
| 控制平面-应用服务 | 领域用例协调 | Project/Scope/Assessment/Asset/Finding/Evidence/Report/Retest/Audit |
| 知识层 | 产品护城河：测什么+怎么测+验什么 | TestCatalog、CoverageMatrix、AppModel、ModelRegistry、LogicTestGenerator、DriftDetector、Case/Tool Registry、VerificationMethodRegistry、Intel Store |
| 执行平面 | 隔离执行工具/用例 | Worker Agent、Executors、Case Engine、Tool Containers、Scoped Egress、Permit |
| 基础设施 | 持久化、证据、密钥、签名、更新、审计 | DB、CAS、Secret Store、Signing、Update Bundles、Audit、Telemetry |

### 6.4 关键流：一次 Assessment 穿过各层

1. MCP: agent 调 `assessment_start`
2. 控制平面-编排: Planner 从 TestCatalog（资产类型->必修类）+ AppModel（逻辑测试）生成确定性 DAG
3. 控制平面-编排: Policy Engine 校验 scope/risk；Active/Intrusive -> 人审批
4. 执行平面: Orchestrator 把 Job 租给 Worker；Worker 持 Permit 在容器+scoped egress 内跑工具/用例
5. 执行平面: Worker 返回 Observation + Evidence（写 CAS）
6. 知识层: CoverageMatrix 更新；Finding Correlation 确定性指纹去重
7. 控制平面-编排: Quality Gate -- oracle N/N 复证 Candidate；覆盖矩阵校验
8. 控制平面-编排: 覆盖矩阵全绿 + 0 未验证 -> 允许出报告
9. 控制平面-应用服务: Report 从结构化记录+证据渲染；LLM 仅可选润色摘要
10. 基础设施: Audit 全程 hash chain

### 6.5 依赖方向（clean architecture）

```
interfaces -> application -> domain(含知识层领域概念)
infrastructure / execution / integrations 通过 ports/contracts 接入
domain 不反向依赖基础设施（不导入 FastAPI/SQLAlchemy/Docker/MCP/httpx）
```

### 6.6 MCP 采纳策略

| MCP tool 来源 | 采纳方式 |
|---|---|
| 编排专有（recon/scan/get_result/make_poc/verify/assessment_*/approval_*） | 自写 |
| 漏洞情报（CVE 分诊/EPSS/KEV/补丁） | 采纳 cve-mcp-server |
| 底层扫描（nuclei/nmap，需直暴露给 agent 时） | 采纳 mcp-security-hub 的 Docker MCP 容器 |
| pentest-ai oracle 验证范式 | 参考实现，集成进 Quality Gates |

**采纳 MCP 供应链信任级（外部评审 M8）**：采纳的 MCP 输出**不信任**，统一标 `untrusted_external_mcp`，与 `untrusted_target_output` 同级处理。具体：

- cve-mcp-server 输出 -> 进 IntelStore 前经 schema 校验 + provenance 标注（与上游源同流程），不直接成 Finding
- mcp-security-hub 容器 -> 镜像 digest 固定 + Trivy 扫描 + 运行时 cap-drop ALL + scoped egress（与自建 Adapter 同安全约束）
- 采纳 MCP 的 Tool manifest 进 Tool Registry 前经审计（谁审核、版本、digest）
- **供应链 mitigation**：mcp-security-hub 被攻陷的 blast radius 限定在其容器内（无 Docker Socket、无宿主 FS、scoped egress、短时 Permit），agent 不直接信任其输出，经 OracleEngine 复证才确认

### 6.7 分布式执行模型（外部评审 H3 补全）

Lite（2C2G 控制节点）+ 远程 Worker + Standalone 的分布式执行此前未定义通信链。锁定如下：

| 维度 | V1 决策 |
|---|---|
| 控制节点 <-> Worker 协议 | **mTLS + HTTPS**（Worker 侧持证书，控制节点签发）；Job 消息走 JSON over HTTPS，不用 gRPC（减少依赖） |
| Worker 注册 | **反向连接**（Worker 主动连控制节点，非 mDNS/静态注册）--简化 NAT 穿透 |
| NAT 穿透 | Worker 主动出站连接，无需穿透；离线/内网场景 Worker 直连控制节点内网地址 |
| 心跳/健康 | Worker 注册后每 30s 心跳；3 次缺失标 unhealthy；Lease 过期的 Job 可重领 |
| Lease 落地 | **Redis（V1 引入）**--Lite 多远程 Worker 共享 SQLite 写 Lease 锁竞争严重（外部评审 H3），Redis 是工程量可控的解；单机 Standalone 可降级 DB Lease |
| Adapter 镜像分发 | 控制节点持 **Capability Registry**（Worker 能力清单：装了哪些 Adapter/镜像 digest）；Worker 心跳携带能力；Orchestrator 按 capability + digest 调度 |
| Evidence 数据回流 | Worker 写**本地临时 CAS** -> 上传控制节点 CAS（签名 URL）-> 控制节点校验 sha256 入库；Worker 不直写控制节点 DB |
| Permit 续租 | Permit 短时（默认 15min）+ nonce；Worker 执行中续租，断线 Permit 自动失效 |
| 断线重连 | Worker 重连后报告 Lease 状态；过期的 Job 已被重领则当前 Worker 放弃 |

> **决策（O1=B，2026-07-25 拍板）**：远程 Worker 推 V2。V1 仅 Standalone 单机执行 + DB Lease（无需 Redis）。本节设计作为 V2 spec 保留，V2 milestone 时落地。V1 Orchestrator 单机调度，不涉及 mTLS/反向连接/Capability Registry/Evidence 回流。

---

## 7. 知识层深设计

### 7.1 内部结构（四子层）

```
知识层
+-- 外部聚合子层（Aggregation）--自动同步，产品不著述只搬运
|   +- 引擎模板镜象：nuclei-templates / nmap NSE / Prowler / ScoutSuite / Trivy-DB / kube-bench / checkov
|   +- 情报 feeds：OSV / CISA KEV / EPSS / NVD(代理) / CWE / GitHub Advisory
+-- 策展子层（Curation）--产品 IP，人工+半自动维护
|   +- TestCatalog（资产类型 -> 必修测试类映射）
|   +- CoverageMatrix（OWASP WSTG/Top10/CIS/PTES 条目 -> 测试类映射 + 覆盖率报告）
|   +- Tool Registry（工具 manifest/schema/parser）
|   +- LogicTestGenerator 策略库（7 类测试生成算法）
|   +- VerificationMethodRegistry（漏洞类型 -> 验证方法）
+-- 社区/用户子层（Community）
|   +- Custom POC Registry（签名、审核、版本化）
|   +- AppModel Registry（per-app，用户签名）
+-- 参考框架子层（Reference）--缓慢更新
    +- OWASP WSTG/Top10、CIS Benchmarks、PTES、NIST 800-115、CWE
```

### 7.2 来源全景

| Registry | 来源 | 获取 | 频率 | 许可证 | 谁著述 |
|---|---|---|---|---|---|
| nuclei-templates | projectdiscovery/nuclei-templates | git pull | 每日 | MIT | 上游 PD |
| nmap NSE | nmap 发行版 | bundled | 跟版本 | GPL（独立进程） | 上游 |
| Prowler | prowler-cloud/prowler | git pull | 每周 | Apache-2.0 | 上游 |
| ScoutSuite | nccgroup/ScoutSuite | git pull | 每周 | GPL-2（独立进程） | 上游 |
| Trivy-DB | aquasecurity/trivy-db | git/OCI | 每日 | Apache-2.0 | 上游 |
| kube-bench / checkov | aquasec / bridgecrewio | git pull | 每月/每周 | Apache/MIT | 上游 |
| OSV | api.osv.dev | REST 增量 | 6h | CC-BY-4.0 | 上游 |
| CISA KEV | cisa.gov JSON | 下载 | 6h | 公共 | CISA |
| EPSS | first.org | CSV | 每日 | CC-BY-SA-4.0 | FIRST |
| NVD | nvd.nist.gov（国内代理） | REST 增量 | 6-12h | 公共 | NIST |
| CWE / GHSA | mitre / github | 下载/git | 每月/每日 | 公共/CC-BY | 上游 |
| TestCatalog 映射 | 产品策展 | 内部 | 月评审 | 产品 IP | 产品+社区 |
| CoverageMatrix 映射 | 产品策展 | 内部 | 月评审 | 产品 IP | 产品+社区 |
| Tool Registry | 产品策展 | 内部 | 跟工具版本 | 产品 IP | 产品 |
| LogicTestGenerator 策略 | 产品策展 | 内部 | 季评审 | 产品 IP | 产品 |
| VerificationMethodRegistry | 产品策展 | 内部 | 季评审 | 产品 IP | 产品 |
| Custom POC | 用户/社区 | 提交+审核+签名 | 持续 | 各异 | 社区 |
| AppModel | 用户 | 建模+签名 | per-app | 用户 | 用户 |
| OWASP/CIS/PTES 参考 | 权威组织 | 下载 | 年度 | 公共 | 上游组织 |

**关键洞察**：产品不著述模板（上游 nuclei/Prowler 团队的活），产品做聚合 + 映射 + 覆盖量化。单兵策展负担从"著述一万条规则"降到"维护映射表"。

### 7.3 维护更新机制

**自动同步（外部聚合子层）**：Update Manager 按各源频率增量拉取；git pull 记 commit SHA，REST 用 last_modified 游标；入 Staging DB -> 签名校验 -> schema/兼容检查 -> 变更预览 -> 原子激活 -> 保留旧快照可回滚。

**策展维护（策展子层）**：TestCatalog 评估新 nuclei tag 是否纳入必修；CoverageMatrix 在 OWASP WSTG 新版时重映射；Tool Registry 跟工具版本。策展变更走签名 bundle 发布，社区可 PR。

**质量保障**：每个 TestCatalog 映射条目要求 ≥1 fixture；CoverageMatrix 覆盖率作为发布门禁；策展变更需通过契约测试；社区贡献需审核+签名。

**知识层健康监控（KnowledgeHealthMonitor）**：

| 检测 | 告警条件 |
|---|---|
| 源停更 | nuclei-templates 超 7 天无新 commit |
| 策展滞后 | nuclei 新增 100 tag 但 TestCatalog 未映射 |
| 覆盖率退化 | 新版覆盖率 < 旧版 |
| 源失效 | OSV API 不可达 -> 降级缓存 + 告警 |
| 签名失效 | bundle 签名校验失败 |

### 7.4 保证最新 + 有竞争力

**保证最新**：自动增量同步 + 漂移检测告警 + 在线/离线签名 bundle 分发 + per-Assessment 版本快照。

**保证竞争力**：

| 维度 | 机制 |
|---|---|
| 聚合广度 | 7 引擎 + 6 情报源 + 4 参考框架 |
| 策展深度 | CoverageMatrix 把"聚合"变"可量化覆盖" |
| 逻辑测试独有 | AppModel + LogicTestGenerator，市面无确定性逻辑覆盖 |
| 社区飞轮 | Custom POC + AppModel 越用越丰富 |
| 可审计 | 覆盖率报告比黑盒"AI 渗透"有说服力 |
| 更新频率 | 自动同步不滞后上游 |

**诚实限制**：策展滞后窗口 1-4 周；竞争力依赖策展投入；单兵 vs 商业平台靠上游借力+自动化+社区弥补。

### 7.5 覆盖率退化门禁（选项 D）

作用于策展子层新版本发布。新版覆盖率 < 旧版 -> 阻止发布（或带理由 override）。

**触发场景**：上游模板移除、上游许可证变更、工具停更（Pocsuite3 已发生）、映射错误、误报清洗、OWASP 框架升级、产品主动收窄。

**影响**：发布决策、发布速度、用户信任、审计留痕、历史评估不受影响（钉旧快照）、竞争力定位、V1 特殊价值（上游变动告警器）。

**规则**：0 容忍为默认（覆盖率单调非降），但留 override 逃生口应对合理回退（上游许可证变更、工具停更、FP 清洗），每次 override 必须文档化理由 + 补救路线图 + 审计留痕。

### 7.6 开源分层决策（O4=B，2026-07-25 拍板）

- **聚合层 MIT 开源**：V1 主要用上游开源内容和 POC
- **CoverageMatrix MIT 开源**：OWASP/CIS 映射开源聚社区贡献 + 透明信任（用户可独立验证覆盖率声明）。映射是机械活、可派生，非真正 moat
- **TestCatalog 策展层产品 IP**：V1 轻策展，深度策展后置；社区可 PR 但合并归产品
- **AppModel / LogicTestGenerator / OracleEngine / VerificationMethodRegistry 产品 IP**：真正 moat，不开源
- **护城河转移**：从"框架映射"（可派生商品）转到 TestCatalog 策展 + AppModel 模型驱动 + oracle 验证 + 模型签名治理（独特，非 LLM 可补）

### 7.7 Custom POC 晋升流程（外部评审 M3）

§7.1 把 Custom POC 放 Community 子层、TestCatalog 在 Curation 子层，但 §4.2 又把"自定义 POC registry"列进 TestCatalog--澄清两者关系：

```
Custom POC（Community 子层，用户/社区提交）
  -> 审核（人审 + 签名 + fixture 校验 + 风险静态分析）
  -> PUBLISHED（进 Custom POC Registry，Community 子层）
  -> [可选] 晋升 TestCatalog（Curation 子层）
       触发：产品团队/社区评估该 POC 覆盖某 OWASP/CIS 必修测试类
       流程：PR + CoverageMatrix 映射 + 覆盖率退化门禁 + 签名
       结果：进 TestCatalog 必修类，后续 Assessment 强制排课
```

**关系锁定**：
- Custom POC Registry 是 Community 子层组件，存放所有审核签名的用户/社区 POC
- TestCatalog 是 Curation 子层组件，引用（reference）已晋升的 Custom POC，作为某必修测试类的实现之一
- 未晋升的 Custom POC 仍可被 agent 调用（ADD），但不在必修排课范围
- 晋升是单向的（Custom -> Catalog），不可回退（已用于历史 Assessment 快照）

---

## 8. 四域 Adapter Pack

### 8.1 统一契约（四域共用）

每个 Tool Adapter = `manifest.yaml + Dockerfile(digest固定,non-root,cap-drop ALL,no-new-privs) + parser + run.sh + fixtures + 契约测试`。

```yaml
id: projectdiscovery.nuclei
version: 1.0.0
adapter_api_version: v1
license: MIT
upstream: {name: nuclei, version: 3.11.0, digest: sha256:...}
risk_class: active_scan
coverage_domain: [web, api]
input_schema: schemas/input.json
output_schema: schemas/output.json   # 强制归一化为 Observation
network_policy: scoped_http
parser: src/parser.py
fixtures: [positive, negative, timeout, scope_deny, malformed]
permissions: [read_scope, write_artifact, emit_observation]
```

### 8.2 四域引擎矩阵

| 域 | 引擎 | 许可证 | 风险类 | V1 状态 |
|---|---|---|---|---|
| 资产测绘 | subfinder/naabu/httpx/katana/FingerprintHub/FingerprintX | MIT/开源 | Passive/Low | ✅ |
| | amass | Apache-2.0 | Passive | ⚠️ Standalone 可选 |
| Web/API | nuclei（核心）/katana/gauplus + 自定义 POC | MIT | Active | ✅ |
| | dalfox | MIT | Active | ✅ |
| | **RESTler**（状态ful API 序列测试，跳步/乱序） | MIT | Active | ✅ 决策 23 采纳 |
| | **Schemathesis**（API property/boundary，越界部分） | MIT | Active | ✅ 决策 23 采纳 |
| | ZAP | Apache-2.0 | Active | ⚠️ Standalone-only（重） |
| 网络主机 | nmap+NSE | GPL | Low/Active | ✅ 独立进程 |
| | nuclei TCP/dns/ssl | MIT | Active | ✅ |
| | masscan | MIT | Low | ⚠️ 条件性（大范围） |
| 云容器 | Prowler/Trivy/kube-bench/checkov | Apache/MIT | Passive | ✅ |
| | ScoutSuite | GPL-2 | Passive | ✅ 独立进程 |
| **横切-验证** | **pentest-ai / ptai**（oracle N/N 复证） | MIT | -- | ✅ 决策 22 采纳 |

GPL 工具（nmap/NSE/ScoutSuite）独立进程容器调用，不库嵌，主程序协议保持干净。

### 8.3 输出归一化（Faraday 式统一 Observation）

```python
Observation {
  external_id, asset_identity,
  source: {name, version, template_version},
  rule_id, rule_version,
  coverage_domain: enum,    # asset/web/network/cloud
  title, severity, confidence,
  cwe: [str], cve: [str], owasp: [str],   # 喂 CoverageMatrix
  evidence_artifact_ids: [str],
  raw: dict                 # 原始工具输出保留
}
```

Finding Correlation 按确定性指纹（资产+CWE/CVE+路径+参数）跨工具去重。版本匹配类结果只能成为 Observation/Candidate，不直接确认。

### 8.4 Scoped Egress 矩阵

| 域 | Egress 策略 | 阻断 |
|---|---|---|
| 资产测绘 | DNS（受控 resolver）+ HTTP/HTTPS 代理到 in-scope | 控制面/DB/Docker host/云 metadata/Scope 外 |
| Web/API | HTTP/HTTPS 代理 + 限速 + OOB（Interactsh） | 同上 + 超速率拒绝 |
| 网络/主机 | TCP/UDP 经 netns + nftables，仅 in-scope IP/端口 | 同上 + Scope 外端口 |
| 云/容器 | 云 API 只读（凭证 scoped-down）+ 镜像仓库 pull | 云 metadata IP（169.254.169.254）必阻 + 计算资源写入 |

所有域通用阻断：控制平面、数据库、Docker host、云 metadata、Scope 外目标、DNS rebinding（解析后二次校验）。

### 8.5 与 TestCatalog 映射

```
TestCatalog（知识层，"测什么"）
  +-- 资产类型 -> 必修测试类
       +-- 测试类 -> >=1 Tool Adapter（执行层，"怎么测"）
            +-- Adapter 输出 -> Observation -> CoverageMatrix 计数
```

Planner 按 TestCatalog 对每个资产强制排课 Adapter，agent 不能删减必修类。

### 8.6 V1 Adapter Pack 交付清单

| 域 | V1 必交 | 条件/Standalone | 后置 |
|---|---|---|---|
| 资产测绘 | subfinder/naabu/httpx/katana/FingerprintHub | masscan（大范围） | amass |
| Web/API | nuclei/katana/gauplus/dalfox/**RESTler**/**Schemathesis** + 自定义 POC | ZAP（Standalone-only） | -- |
| 网络主机 | nmap+NSE/nuclei-TCP | -- | -- |
| 云容器 | Prowler/Trivy/kube-bench/checkov/ScoutSuite | -- | -- |
| 横切-验证 | **pentest-ai（oracle）** | -- | -- |

dalfox 进 V1（低成本填 DOM/盲 XSS 缺口抬覆盖率）；**RESTler/Schemathesis 进 V1（决策 23，替代自建跳步/乱序/越界逻辑测试）**；**pentest-ai 进 V1（决策 22，替代自建 OracleEngine）**；ZAP Standalone-only（保 Lite 部署）；amass 后置（不抬覆盖率）；masscan 条件性（按 Scope 自动选）。

---

## 9. 验证子系统

### 9.1 验证流水线

```
Observation（工具产出，低信任）
  -> Candidate（疑似发现，待验证）
    -> Validation（oracle 尝试 N 次独立复现）
      -> Confirmed（N/N）| REFUTED（误报）| INCONCLUSIVE（部分，人审）
```

版本匹配类结果只能停 Candidate，必须 oracle 复现才确认。

### 9.2 oracle N/N 复证（核心，采纳 pentest-ai，决策 22）

**OracleEngine 采纳 pentest-ai（ptai，MIT，`pip install ptai`）**：不自建 oracle 引擎。ptai 已实现 N/N 复证 + 14 类漏洞 oracle + 证据胶囊可回放。我们建 **VerificationMethodRegistry**（漏洞类型 -> 验证方法的策展层，含 N 值/重跑策略/5xx 阈值）覆盖在 ptai 之上，ptai 按 registry 配置执行验证。

oracle 是确定性复现器，不是 LLM。对每个 Candidate：
1. 从 VerificationMethodRegistry 读该漏洞类型的验证方法（确定性，策展）
2. 生成 N 个全新 canary token（高熵随机，一次性）
3. 执行 N 次独立验证探针（经 Worker + scoped egress）
4. 每次检查 canary token 是否被回显（响应正文 / OOB 回调）
5. N/N 通过 -> Confirmed；任一失败 -> REFUTED；部分 -> INCONCLUSIVE

N 默认 3，可配置。**LLM 永远不能标记 Confirmed**--只有 oracle 能。

**oracle 精度量化（外部评审 H4）**：
- **N 作为 VerificationMethodRegistry 字段**：每条验证方法声明默认 N（SQLi 延时盲注 N=5 因网络抖动高；RCE echo canary N=3；OOB 类 N=3 + 最长等待窗口）
- **重跑策略**：默认**跨 Worker 重跑**（N 次分散到不同 Worker/不同时刻），消除同 Worker 时序抖动；无多 Worker 时降级同 Worker 但间隔 ≥2s
- **5xx vs 真没漏洞**：5xx/超时计为 INCONCLUSIVE 不计 REFUTED；仅确定性"token 未回显"计 REFUTED；连续 2 次 INCONCLUSIVE 升级人审
- **oracle ground-truth 靶场集**：oracle 自身需已知漏洞靶验证。V1 绑定 Juice Shop（Web 应用类）、crAPI（API 类）、vulhub（CVE 复现类）三类靶场作为 oracle 测试集；每次 oracle 升级在靶场集上回归，确保 oracle 不误判
- **N/N 失败处理**：REFUTED 进误报库（喂 RiskAnalyzer 学习）；INCONCLUSIVE 进人审队列

### 9.3 Canary Token 管理

每次验证尝试发唯一 token（高熵随机，一次性不重用）。token 嵌入探针（RCE 用 `echo <token>`，OOB 用 `<token>.oast.example.com`）。确认要求观察到 token 回显。防止静态/缓存响应误报。token 管理器独立模块，全审计。

### 9.4 OOB（Interactsh，V1 自托管）

Interactsh（ProjectDiscovery，MIT）客户端，Nuclei 原生集成。每次检查分配唯一回调域，DNS/HTTP/SMTP 回调。适用：SSRF、盲 SQLi、盲 XSS、盲 RCE、反序列化。

**V1 自托管（外部评审 H4）**：国内到公共 `interact.sh` / `oast.live` / `oast.fun` 连通性不稳（与 NVD 国内 503 同类问题），公共 OOB 高比例失败 -> 退化为半自动工作台。V1 **自托管 Interactsh**：
- 公网 VPS + 域名 NS 委托（或子域授权），Docker 部署 interactsh-server
- 控制节点内置 interactsh-client，分配唯一回调域
- 回调日志进 Audit，canary token 关联
- 离线/内网场景：目标内网 DNS 指向自托管 Interactsh 的内网地址（需客户配合）

自托管是工程量可控的解（一个 Docker 服务），避免 V1 因公共 OOB 不稳而退化。

### 9.5 无害化验证方法矩阵（策展，确定性）

| 漏洞类型 | 验证方法 | 无害化理由 |
|---|---|---|
| SQLi | 延时盲注、布尔盲注、DNS 外带 | 不改数据 |
| RCE/命令注入 | echo canary、sleep N、OOB nslookup | 非破坏命令 |
| SSRF | 回连自有 OOB 服务器 | 不触达内部 |
| XXE | OOB 回调 | 不外带文件 |
| XSS | headless 浏览器检 canary in DOM/alert | 仅检测 |
| 反序列化 | URLDNS/JRMP OOB 回调 | 不利用 |
| 文件读/遍历 | 只读 /etc/passwd、win.ini | 不读敏感数据 |
| 认证绕过 | 验证访问标记资源 | 不提权 |
| 路径穿越 | 读非敏感文件 | 不修改 |

### 9.6 三层 Evidence（内容寻址，不可变）

```
Evidence {
  id, finding_id, run_id, kind,
  storage_uri, sha256, content_type, size_bytes,
  captured_at, captured_by, redaction_status,
  layer: RAW | REDACTED | SUMMARY
}
kinds: raw_tool_output | screenshot | request_response | command_output |
       reproduction_steps | remediation_proof | retest_result | manual_note
```

- RAW：原始请求响应/工具输出（敏感，受限访问）
- REDACTED：脱敏（密钥/PII/内网 IP，自动+人审）
- SUMMARY：结构化摘要（喂报告）
- 脱敏生成新对象，不覆盖 RAW；三层独立、内容寻址（SHA-256）
- 每个 Confirmed Finding 必须有 ≥1 不可变 Evidence + 版本快照引用

**Redaction 自动化（外部评审 M7/M9）**：
- **regex 库**：内置 Secret 模式（API key/JWT/AWS key/私钥）+ PII（邮箱/身份证/手机号）+ 内网 IP 段；可配置扩展
- **两类 secret 区分**：**我方 secret**（凭证/Token，进 SecretStore 管理）vs **目标 secret**（目标系统 API 返回里 echo 的密钥，如配置泄漏接口返回的数据库口令）。两类都脱敏，但标记来源不同
- **误报处理**：自动脱敏标 `redaction_status: auto`，人审可 override 标 `confirmed`；误报率作为 RedactionEngine 指标
- **Redacted Evidence 独立存储 + 独立签名**：与 RAW 分离，权限不同（客户门户只读 REDACTED/SUMMARY）
- **Redaction 延伸到 Report 渲染层（M9）**：ReportRenderer 引用 Evidence 摘要时，必须再过 RedactionEngine--即使 Evidence 已脱敏，报告叙述里"目标系统的管理员口令是 X"这类引用也必须脱敏。Report 是 Redaction 的最后一道闸，不是 Evidence 的透传

### 9.7 验证安全护栏

- RCE 验证命令白名单（echo/sleep/nslookup/whoami 等非破坏）
- 每次验证超时 + 限速
- 默认只验证不利用；exploit 能力显式开启 + 人审批
- 验证探针同样过 scope 强制

### 9.8 LLM 边界

| LLM 禁止 | 谁裁决 |
|---|---|
| 标记 Confirmed | oracle（确定性） |
| 选验证方法 | VerificationMethodRegistry（策展） |
| 判定 N/N 通过 | oracle |
| LLM 可以 | INCONCLUSIVE 时建议人审方向；为新型漏洞起草验证方法（人审入库） |

---

## 10. 漏洞情报与更新

### 10.1 情报实体（4 类，每字段保留 provenance）

```
Vulnerability      canonical_id, alias[], 描述, CVSS, CWE[], 引用[], 时间
AffectedProduct    vendor/product/CPE/package/version_range/fixed_versions
ExploitationSignal KEV标志, EPSS分数, 公开利用, 勒索关联, 活跃利用
DetectionMapping   漏洞 -> Case Version, 检测类型, 风险, 可信度
```

情报负责"什么漏洞存在"，Case 负责"如何安全检测"--分离，更新 CVE 不等于自动安装执行能力。

### 10.2 数据源 + 频率 + 可达性（curl 实测）

| 来源 | 频率 | 国内可达 | 用途 | 备注 |
|---|---|---|---|---|
| OSV.dev | 6h | ✅ | 主源，聚合 NVD/GHSA/各生态 | 免费无 key |
| CISA KEV | 6h | ✅ | 在野利用 -> 优先级 | 当前 1653 条 |
| FIRST EPSS | 每日 | ✅ | 利用概率评分 | 优先级排序 |
| NVD API 2.0 | 6-12h | ❌ 503 | 补 CVSS 细节 | 走代理备用 |
| CWE | 月度 | ✅ | 弱点分类 | -- |
| GitHub Advisory | 每日 | ✅ | 生态映射 | -- |
| 厂商公告 | 6-24h | 按需 | 补 0-day/未入库 | 按需爬取或手工 |

OSV 主源是网络现实决定（NVD 国内被墙实测 503）。

### 10.3 同步架构

```
Update Manager 定时调度
  -> 每源按频率增量拉取（git pull 记 commit SHA / REST 用 last_modified 游标）
  -> 入 Staging DB
  -> 签名校验 + schema/兼容检查
  -> 变更预览（diff 旧版）
  -> 原子激活（切换指针，不原地改）
  -> 保留旧快照（可回滚）
```

与知识层策展 bundle、Case/Tool/Model bundle 同构，复用同一 Update Bundle 流水线。

### 10.4 Update Bundle（在线/离线同构）

```
bundle.tar.zst
  +- manifest.yaml（版本、来源、checksums、生成时间）
  +- signature.ed25519（产品签名密钥）
  +- intel.ndjson
  +- cases/
  +- tools/
  +- models/
  +- curation/（TestCatalog/CoverageMatrix 映射）
```

在线：Update Manager 拉取。离线：人工导入（客户内网无公网）。同一 bundle 同一流程：下载/导入 -> 签名/Hash 校验 -> Staging -> Schema/兼容/Case 检查 -> 预览 -> 原子激活 -> 旧快照保留 -> 可回滚。

### 10.5 激活策略（按内容类型）

| 内容 | 激活策略 |
|---|---|
| 纯情报（CVE/KEV/EPSS） | 自动应用 |
| Passive/Low Case | 安装后自动启用 |
| Active Case | 安装后等待启用 |
| Intrusive Case | 必须人审 |
| Python Plugin | 永不自动启用，人审+签名 |
| Tool digest 切换 | smoke test 前置 |
| 策展映射 | 走覆盖率退化门禁 |

### 10.6 版本快照（per-Assessment，可复现）

每个 Assessment 固定全版本快照：scope/plan/policy/intel/case_registry/tool_registry/catalog/app_model/engine 版本。历史任务不跟 latest 漂移。同快照 = 同结果。

### 10.7 Provenance（来源保留）

每个字段保留来源 + 拉取时间 + 源版本。内部优先级不能覆盖原始记录。CVSS 来自 NVD vs 厂商都保留，显示来源。LLM 不能改情报内容、不能绕过 provenance。

### 10.8 查询

Intel Store 支持 by CPE / CVE / keyword / CWE 查询。SQLite FTS5 或 PostgreSQL 全文索引，不引入 Elasticsearch。MCP 查询：自写 `intel_search` + 采纳 cve-mcp-server（28 工具 × 24 数据源）。

### 10.9 LLM 边界

| LLM 禁止 | 谁裁决 |
|---|---|
| 改情报内容 | 上游源 + Update Manager（确定性同步） |
| 绕过 provenance | 字段必带来源（schema 强制） |
| 标记利用优先级 | KEV/EPSS 计算（确定性） |
| LLM 可以 | 调查询接口；为新型漏洞起草 DetectionMapping（人审入库） |

---

## 11. 自定义 POC + 模型驱动逻辑测试

### 11.1 双层用例

| 类型 | 覆盖 | 特点 |
|---|---|---|
| YAML Case | ~90% 用例 | 声明式、AI 可生成、静态可分析、安全 |
| Python Plugin | ~10% 复杂场景 | 多步状态/加密/协议交互，沙箱隔离 |
| Composite | 组合 | 串联多个 Case |

### 11.2 YAML Case = Nuclei YAML 基础 + 验证扩展

以 Nuclei YAML 为基础格式（事实标准、10k+ 现成模板立即可用、AI 生态成熟），扩展三类验证钩子：`canary_token` 占位、`verification` 块（关联 VerificationMethodRegistry + 复现次数）、`classification` 喂覆盖率。基础语法兼容 Nuclei，现成模板零成本复用。

### 11.3 YAML DSL actions + 约束

支持：`dns.resolve, tcp.connect, tls.inspect, http.request, http.compare, oast.allocate, oast.wait, extract.regex/jsonpath/xpath, transform.base64/urlencode/hash, compare.text/numeric/timing, condition, foreach, retry, wait`。

约束：`foreach/retry/wait` 必须有硬上限；禁止递归/无限循环/Shell/动态 import/任意文件路径/动态创建 Scope 外目标；断言用内部 AST（不用 Python eval）。

### 11.4 Python Plugin Sandbox

只能通过 CaseContext SDK 获取声明式 Capability：`scoped_http, scoped_tcp, credential_ref, temp_fs, oast, emit_observation`。禁止 subprocess/os.system/Docker Socket/宿主文件系统/任意 Socket/数据库连接/动态 import。容器：`read-only, non-root, cap-drop ALL, no-new-privileges, 资源/超时限制, 无 Host Network, 无 Docker Socket`。

### 11.5 Case Registry 生命周期

```
YAML Case:
  DRAFT -> VALIDATED -> REVIEWED -> SIGNED -> PUBLISHED
        -> DISABLED / DEPRECATED

Python Plugin:
  DRAFT -> STATIC_CHECKED -> SANDBOX_TESTED -> REVIEWED -> SIGNED -> PUBLISHED
```

每个版本记录：作者、风险、目标类型、Schema、前置条件、步骤、断言、Evidence 要求、CWE/CVE/OWASP 映射、签名、最低引擎版本。

### 11.6 风险静态分析

| 模式 | 计算风险 |
|---|---|
| GET/HEAD | Low |
| 全面扫描/爬虫 | Active |
| 凭据/上传/时间差/OAST | Intrusive |
| Shell/无限循环/Scope 外目标 | 拒绝发布 |

声明风险不得低于计算风险。RiskAnalyzer 静态扫描，不达标阻止发布。

### 11.7 Fixture 要求

每个 Case 必备：Positive、Negative、Timeout、异常响应、重定向、Scope Deny、脱敏。Intrusive Case 还须：靶场、前后状态、清理步骤、最大影响说明。

### 11.8 Agent 与 Case 的关系

| Agent 可以 | Agent 禁止 |
|---|---|
| 生成 YAML Draft | 审核 Case |
| 跑 validate | 签名 Case |
| 跑 Dry Run（靶场） | 发布 Case |
| 为新漏洞起草 Case | 提高 Capability |
| 建议 fixture | 绕过风险静态分析 |

人审 + 签名是不可绕过的发布门禁。

### 11.9 模型驱动逻辑测试（第二/三层业务逻辑）

**模型**：版本化、签名的形式描述，含状态机 + 不变量 + 字段信任边界 + 角色能力 + 幂等性。

**建模动作（6 步，LLM 仅第 1 步辅助起草，人校验，执行全程 LLM 无关）**：

| 步 | 动作 | 谁做 | 产出 |
|---|---|---|---|
| 1 自动发现 | 爬取端点（katana）+ 解析 OpenAPI/Postman + 被动代理观察流量 -> LLM 起草 | 工具 + LLM 起草 | 模型草稿 |
| 2 人校验精修 | 在 Case Studio 审草稿、补不变量、标 trusted_source、定角色能力、Ed25519 签名 | 人 | 签名模型 |
| 3 模型快照 | 版本化 + per-Assessment 快照（digest） | 框架 | app_model_snapshot |
| 4 测试生成（确定性） | 框架从模型纯函数式生成 7 类测试 Case | 框架，无 LLM | N 个测试 Case |
| 5 执行 + oracle 验证 | 走同一执行平面，oracle N/N 复证，证据留痕 | 框架 | Candidate/Confirmed |
| 6 回归（持续验证） | 模型随应用版本化在 git；应用改了更新模型重跑；diff 模型版本；CI 集成 | 框架 + 人维护 | 持续回归报告 |

**模型来源（外部评审 M1 补全）**：两条路径，按是否有 API 文档分流：

| 路径 | 输入 | 流程 |
|---|---|---|
| **有文档（半自动导入）** | OpenAPI 3.0/3.1（优先）、Swagger 2.0（遗留系统）、Postman v2.1、GraphQL introspection schema、gRPC protobuf | 解析 -> 状态机/字段/端点草稿 -> LLM 补不变量/trust 边界建议 -> 人校验签 |
| **无文档（常态，流量录制）** | 被动代理录制的请求/响应流量（katana 爬取 + 代理观察） | 流量聚类 -> 推断端点/参数/状态转移 -> LLM 起草状态机 -> 人校验签 |

**复杂状态机处理**：单 LLM 起草不够时，拆分子模型（按业务域分解，如电商拆"结账/退款/账户"三个子模型），各自签名后组合。

**Case Studio V1 完整可视化建模**（A 全架构，M3 后端 + M4 Web UI）。

**V1 逻辑测试（决策 23，采纳 RESTler + Schemathesis，覆盖范围扩大）**：

| 测试类 | V1 实现 | 来源 |
|---|---|---|
| 跳步 | ✅ 采纳 RESTler（状态ful 序列测试，从 OpenAPI 推断依赖生成序列） | RESTler Adapter |
| 乱序 | ✅ 采纳 RESTler（序列乱序） | RESTler Adapter |
| 重放 | ✅ 采纳 RESTler（序列重放，partial） | RESTler Adapter |
| 越界 | ✅ 采纳 Schemathesis（property-based boundary） | Schemathesis Adapter |
| 不变量违反 | ✅ **自建**（无开源同类） | LogicTestGenerator |
| 竞态 | ❌ V2 | -- |
| 角色越权 | ❌ V2 | -- |

**V1 实际覆盖 5 类**（跳步/乱序/重放-partial/越界/不变量违反），优于原 O3=B 的 3 类--采纳 RESTler/Schemathesis 后覆盖范围反而扩大。LogicTestGenerator 是**编排层**：从 AppModel 生成测试 Case，协调 RESTler/Schemathesis/自建不变量测试执行，带 signature 幂等。一个电商结账模型 V1 自动生成 ~30-50 个确定性逻辑测试。

> 采纳理由：RESTler（微软，MIT）做状态ful API 序列测试成熟；Schemathesis（Python，MIT）做 property-based boundary 测试成熟；不变量违反无开源同类必须自建；LogicTestGenerator 编排层协调三者 + AppModel 策展。

**模型治理**：LLM proposes, human disposes, product executes。LLM 全程不裁决、不签名。模型一旦签名，后续生成/执行/验证全程 LLM 无关。

**模型同步/发布/更新**：
- 生命周期：DRAFT -> LLM_PROPOSED -> HUMAN_VALIDATED -> SIGNED -> PUBLISHED -> SUPERSEDED（旧版不删）
- 发布：人签名 -> 进 ModelRegistry -> 版本+digest -> per-Assessment 快照
- 更新：漂移检测（重新导入 OpenAPI/Postman/爬取 diff）-> 新 DRAFT -> 人校验签 -> 发布新版本 -> 旧版 SUPERSEDED -> 触发回归测试
- 同步分发：本地 ModelRegistry；跨评估复用（同应用模型导入新 Assessment）；跨实例/团队签名 bundle（走与情报/用例/工具相同的 Update Bundle 流水线）
- DriftDetector：定期/CI 触发的漂移检测

### 11.10 模型生成 Case 的特殊处理

LogicTestGenerator 从签名 AppModel 生成的 Case（`origin: model_generated`）：生成是纯函数，模型已签名 -> 可自动通过 STATIC_CHECKED + VALIDATED；Intrusive 类仍需人审；Passive/Low 类可自动发布（模型签名传递信任）；复用同一 Case Registry。

**幂等性 + signature（外部评审 M2）**：

- **每个生成 Case 带 `signature` 字段** = `sha256(app_model_digest + test_class + generation_strategy_version)`，重复跑同一 AppModel 必产生同 signature
- **CoverageMatrix 计数去重**：同 signature 的 Case 只计一次，避免重复跑导致覆盖率失真
- **AppModel 微改**：用 signature diff 算增量--仅 changed signature 对应的 Case 重生成，未变 signature 保留历史结果（CI 回归只跑变化的）
- **生成策略版本化**：`generation_strategy_version` 独立版本，LogicTestGenerator 算法升级时 bump，旧 Case 重新生成（避免算法升级后 signature 冲突）
- **"复杂业务规则不覆盖"判定**：AppModel 建模时人显式声明 `out_of_scope_rules`（如"理赔金额计算超出模型表达能力"），LogicTestGenerator 跳过这些规则并标记；CoverageMatrix 显示"已建模规则 N 条 / 声明超出范围 M 条"，用户签字确认 M 条不覆盖

### 11.11 与 TestCatalog / VerificationMethodRegistry 关系

```
TestCatalog（测试类）
  +-- 测试类 -> >=1 Case（Case Registry）
       +-- Case 的 verification.method -> VerificationMethodRegistry
            +-- OracleEngine 用该方法 N/N 复证
Case 的 classification.{cwe,cve,owasp} -> 喂 CoverageMatrix 计数
```

---

## 12. 数据模型 + 部署 + 安全

### 12.1 数据模型（核心表，按域分组）

```
项目/授权: projects, scope_drafts, scope_snapshots
评估/编排: assessments, execution_plans, plan_steps, approvals, jobs, execution_permits
知识层: test_catalog, coverage_matrix, case_definitions, case_versions, tool_definitions,
        app_models, app_model_versions, verification_method_registry
情报: intel_snapshots, vulnerabilities, vulnerability_aliases, affected_products,
      exploitation_signals, detection_mappings
资产/发现: asset_nodes, asset_edges, observations, candidates, findings
验证/证据: verification_attempts, canary_tokens, evidence_objects, finding_evidence
更新: update_bundles, bundle_activations
安全/审计: secret_metadata, audit_events
报告/复测: reports, report_versions, retests
```

### 12.2 存储策略

| 数据 | 存储 | 备注 |
|---|---|---|
| 业务数据 | SQLite WAL（Lite）/ PostgreSQL（Standalone） | Repository Contract 同时跑两者，业务代码不依赖 SQLite 专有逻辑 |
| 证据大文件 | CAS（Local/S3/MinIO），内容寻址 | 不存 DB BLOB |
| 全文检索 | SQLite FTS5 / PG full-text | 不引入 Elasticsearch |
| 模板/指纹 | git 仓库 + commit SHA 版本化 | 文件系统 |
| 情报 | SQLite/PG + FTS | 增量同步 |

### 12.3 部署模型（A 全架构）

```
Lite（2C2G 控制节点，V1 单机轻量执行）
  +- 控制平面 + MCP + CLI + Web Case Studio
  +- SQLite WAL + Local CAS / 外部 S3
  +- 情报索引 + Update Manager
  +- 轻量本地执行（远程 Worker 推 V2，见 §6.7）
  不跑: ZAP、大规模并发、Python Plugin 镜像构建、分布式 Worker
  目标内存: 0.8-1.4GB

Standalone（4C8G，推荐 8C16G）
  +- Lite 全部 +
  +- 本地工具容器 + 完整 Scoped Egress（netns+nftables+HTTP 代理+TCP）
  +- ZAP 可启用
  +- 完整 Adapter Pack 并发
  存储: 100GB SSD
```

- **Redis V2 引入**（V1 单机 DB Lease，无需 Redis；V2 远程 Worker 时引入）
- Docker Compose 多服务（api/worker/scheduler/db/cas/proxy）
- 离线部署：离线镜像仓库 + 离线 Update Bundle 导入 + 本地报告渲染

### 12.4 Scope 强制执行链（每次动作前）

```
Target Normalize -> Explicit Deny -> Include Match -> DNS Resolve
-> Resolved IP Recheck（防 rebinding）-> Port/URL -> Time Window
-> Risk -> Approval -> Budget -> Execution Permit
```

Deny 始终优先；DNS 解析后二次校验；API + 执行层双重校验；Scope 外地址在执行层网络层被拒。

### 12.5 Secret Store

任务只用 `secret_ref`，明文不入库。后端：OS Keyring / 本机加密文件 / 外部 KMS（Vault）。不进入 Prompt/Case/日志/Evidence/报告。执行时短时文件描述符/内存管道/Secret Mount 注入。任务完成撤销。凭证访问写审计。

### 12.6 Audit Hash Chain

```
AuditEvent { previous_event_hash, event_hash, ... }
```

链式哈希，篡改可检测（不宣称不可篡改存储）。记录 scope/plan/审批/secret 使用/工具用例/Policy Deny/Evidence 导出/用例发布/更新/远程模型/Finding/报告。日志结构化 JSON，带 trace_id/correlation_id/tenant/run_id。禁止记录 Secret/Token/Cookie/完整 Authorization/未脱敏 PII。

### 12.7 Emergency Stop

停止签发新 Permit；撤销未使用 Permit；终止活动容器；保留已产生 Evidence；写高优先级 Audit。

### 12.8 远程模型数据分级

```
数据分级: Public | Internal | Sensitive | Restricted | Secret
远程模型调用统一经: Data Classification -> Redaction -> Policy -> User Consent -> Audit
```

Secret 永不发送；Restricted 默认禁止；Sensitive 默认脱敏。本地模式不依赖 LLM 也能执行扫描。

### 12.9 Prompt Injection 防御

目标页面/Banner/工具输出/漏洞描述标记 `untrusted_target_output`。Agent 输出必须转结构化 Action，经 Schema/Scope/Policy/Approval/Registry。目标内容不能改策略/Scope/用例状态/Secret/审批。每个动作经 Policy Engine（确定性，不靠 LLM 自律）。

### 12.10 LLM 边界汇总（全设计收敛）

| LLM 可以（提议，人审） | LLM 禁止（裁决，确定性层） |
|---|---|
| 工具参数化（Schema 内） | Policy 决策 / Quality Gate 裁决 |
| 提议新 Plan Version | Finding 确认（只有 oracle） |
| 起草 AppModel | severity 定级（CVSS 计算） |
| 起草自定义 POC | 报告数字（DB 计算） |
| 起草验证方法 | 覆盖率判定（CoverageMatrix） |
| 报告摘要润色（人签） | 证据完整性（SHA256） |
| INCONCLUSIVE 建议人审方向 | scope 改动 / 用例发布 / Capability 提升 |

### 12.11 LLM 运营约束（外部评审 H5）

§12.8 给了数据分级，但没给运营值。补全：

| 维度 | V1 决策 |
|---|---|
| 模型来源 | **本地优先**（Ollama/vLLM 跑 7B-13B 用于参数化/起草）+ **远程可选**（Claude/GPT/Gemini API 用于复杂起草如 AppModel/POC）；本地模式不依赖远程也能跑（§12.8） |
| 每日 Token 预算 | 远程调用每日 Token 上限（默认 500K/天，可配）；超限告警 + 降级到本地 |
| 速率限制 | 远程调用默认 10 req/min；本地无限制 |
| Prompt size 上限 | 单次 ≤32K tokens；超长 Evidence/情报走 RAG 摘要而非全量塞 Prompt |
| 计费上限 | 月度计费上限（可配），超限自动停远程调用 + 告警 |
| 降级规则 | 远程不可达/超预算 -> 自动降级本地模型；本地不可用 -> 停 agent 编排，仅保留确定性 catalog 执行 |
| 告警阈值 | Token 用量 80% 预警、100% 降级；远程错误率 >20% 降级本地 |
| 谁设置 | 用户在配置文件设；运营值作为 DoD"agent 可端到端编排"（§15 第 1 条）能否跑通的硬约束 |

### 12.12 Audit 密钥与数据保留补全（外部评审 M6）

§12.6 的 hash chain 补全：

- **签名密钥管理**：Audit 签名密钥独立于 Update Bundle 密钥；OS Keyring 存储私钥；公钥随报告导出供第三方验证
- **Permit nonce/有效期**：Permit 带 nonce + 短时（默认 15min）；Audit 记录 Permit nonce，重放攻击可检测
- **Log rotation 续链**：rotation 时旧链尾哈希写入新链首（`previous_chain_tail_hash`），不直接断链；旧日志归档仍可验证
- **GDPR/数据保留冲突**：不可篡改 ≠ 不可删除。设计：法定删除请求时，删除 PII 明文但保留 hash + 删除审计记录（记录"删除了什么"但不留原文）；保留期策略可配（默认 90 天 Audit 滚动 + 1 年归档）

---

## 13. 分阶段交付（M0-M5，A 全架构）

| 里程碑 | 工作量 | 交付 | DoD |
|---|---|---|---|
| M0 地基+确定性脊柱骨架 | 5-7 天 | Domain 边界；Project/Scope/Assessment/Plan/Approval；PolicyEngine；**Repository Contract 抽象（SQLite WAL 实现，PG 接口预留）**；**最小 Audit 表 + hash chain 起步**；依赖守卫 | scope 硬拒绝；plan 可持久化；approval 跑空计划；Deny 优先；Domain 无框架依赖；**审计事件可追溯**；**Repository 同时支持 SQLite（PG 接口预留，M5 切 PG 不重构）** |
| M1 知识层+情报+四域 Adapter | 12-18 天 | TestCatalog；CoverageMatrix；IntelStore；UpdateManager；KnowledgeHealthMonitor；四域 Adapter Pack（含 dalfox、ZAP Standalone-only，每 Adapter 含 5 类 fixture） | 4 域工具可执行；输出归一化 Observation；覆盖矩阵可算；情报可查；**每 Adapter 契约测试通过** |
| M2 验证+用例引擎 | 8-12 天 | **采纳 pentest-ai 作 OracleEngine**（决策 22）+ VerificationMethodRegistry 策展层（N 字段）；CanaryTokenManager；**自托管 InteractshClient**；**oracle ground-truth 靶场集（Juice Shop/crAPI/vulhub）**；CaseEngine；**PythonPluginSandbox（gVisor 或 seccomp profile，M2 锁定方案）**；CaseRegistry；RiskAnalyzer；FixtureRunner | oracle N/N 生效；YAML Case 可执行可校验；Python 沙箱隔离；风险分析门禁；**oracle 自身可在靶场集上验证** |
| M3 模型驱动逻辑测试（后端） | 3-5 天 | AppModel schema；**ModelBuilder 后端**（OpenAPI/Postman/GraphQL/gRPC 导入 + LLM 起草 + 人校验 API，**非 Web UI**）；**LogicTestGenerator 编排层（决策 23：采纳 RESTler 跳步/乱序/重放 + Schemathesis 越界 + 自建不变量违反 + signature 幂等）**；ModelRegistry；DriftDetector | 模型可建可签；5 类测试自动生成（跳步/乱序/重放/越界/不变量违反）+ signature 幂等；漂移可检测 |
| M4 Agent 接口+编排+报告+Web Case Studio | 8-12 天 | MCP Server（自写+采纳，**采纳 MCP 标 trust level**）；CLI；**Web Case Studio 可视化建模 UI**；Planner；Orchestrator（**V1 单机 + DB Lease，分布式 Worker 推 V2 见 §6.7**）；FindingCorrelation；**ReportRenderer（含 Redaction 延伸）**；AssetGraph | agent 可端到端编排；覆盖矩阵门禁生效；报告数据驱动 + 脱敏；**Case Studio 可视化建模可用** |
| M5 安全加固+Beta | 10-15 天 | ScopeEnforcer；SecretStore；**AuditChain 完整（密钥管理 + Permit nonce + Log rotation 续链 + 数据保留策略）**；EmergencyStop；RemoteModelGateway（**含 §12.11 LLM 运营约束**）；PromptInjectionGuard；完整 Scoped Egress；**PostgreSQL Contract 切换验证**；E2E；CI；STRIDE 威胁建模 | 全安全条件通过；E2E 绿；Lite 2C2G 可跑；**PG Contract 通过**；**STRIDE 威胁模型归档** |

**总计**：45-68 工程日 + 集成/调试/返工缓冲 = **4-6 月**单人全职。初版 3-5 月偏乐观（H1）；O1=B（远程 Worker 推 V2）+ O3=B（3 类逻辑测试）+ 采纳 RESTler/Schemathesis/pentest-ai 复用（决策 22/23）共减 ~11-16 天。集成比例 ~88%，建 ~12%（仅 TestCatalog/CoverageMatrix/AppModel 策展/不变量违反/VerificationMethodRegistry 策展/版本钉死/脊柱 wiring）。

---

## 14. 风险与取舍

| 风险 | 原因 | 缓解 |
|---|---|---|
| 范围过大 | 全覆盖 V1 + 模型驱动 + 全架构 | 分阶段交付；M0-M5 严格 DoD；不缩小测试范围提前 Beta |
| 策展负担（单人） | 知识层需持续维护 | 上游借力 + 自动同步 + 社区 PR + 聚合层开源 |
| 模型质量上限 | AppModel 错则测试全废 | 人审签名 + DriftDetector + 诚实声明复杂业务规则不覆盖 |
| oracle 误判 | N/N 仍可能误报/漏报 | N 可调 + INCONCLUSIVE 人审 + Evidence 可追溯 |
| LLM 依赖回潮 | 边界模糊处 LLM 偷偷裁决 | LLM 边界明文 + 确定性脊柱 + 禁区审计 |
| 部署重 | 全架构多服务 + 分布式 Worker | Lite 2C2G 控制节点 + 远程 Worker 按需 |
| 知识层滞后 | 策展窗口 1-4 周 | 自动同步 + KnowledgeHealthMonitor 告警 |
| 单人工期 | 5-8 月（经 H1 修正，初版 3-5 月偏乐观） | 分阶段交付 + 严格 DoD + 不提前 Beta；O3 可选缩范围（7 类->3 类） |
| 安全边界未通过 | Scope/Permit/沙箱有漏洞 | M5 安全条件全过才 Beta；STRIDE 威胁建模 |

---

## 15. V1 完成定义（DoD）

- [ ] Agent 可通过 MCP 创建/规划/审批/执行 Assessment
- [ ] 框架铺路 + agent 驾驶 + Policy 刹车 + 人审批 四方分工生效
- [ ] TestCatalog 驱动覆盖，agent 只加不减
- [ ] CoverageMatrix 门禁：0 未执行必修类才能结题
- [ ] oracle N/N 验证：0 未验证 Candidate 才能出报告
- [ ] **oracle ground-truth 靶场集（Juice Shop/crAPI/vulhub）回归通过**（H4）
- [ ] 四域 Adapter Pack 交付（必交 + dalfox + ZAP Standalone-only，每 Adapter 5 类 fixture）
- [ ] AppModel 模型驱动逻辑测试（**V1 5 类：跳步/乱序/重放/越界/不变量违反**，采纳 RESTler+Schemathesis+自建 + signature 幂等 + Case Studio M3 后端/M4 Web UI；竞态/角色 V2）
- [ ] **AppModel 无文档流量录制路径**（M1）
- [ ] **自托管 Interactsh OOB**（H4）
- [ ] 漏洞情报 OSV 主源 + KEV + EPSS，签名 Bundle
- [ ] 自定义 POC：Nuclei YAML + Python 沙箱，人审签名
- [ ] **Custom POC 晋升 TestCatalog 流程**（M3）
- [ ] Scope 强制（10 步执行链 + DNS 二次校验 + 双校验）
- [ ] Secret 不入库/Prompt/日志/Evidence/报告
- [ ] **Audit M0 起步 + M5 完整（密钥管理 + Permit nonce + Log rotation 续链 + 数据保留）**（H2.1/M6）
- [ ] Audit hash chain 篡改可检测
- [ ] Emergency Stop 撤销 Permit + 终止容器
- [ ] 远程模型调用分级 + 脱敏 + 授权 + 审计
- [ ] **LLM 运营约束生效（预算/限速/降级/告警）**（H5）
- [ ] **Redaction 延伸到 Report 渲染层**（M7/M9）
- [ ] **采纳 MCP 输出标 trust level + 供应链 mitigation**（M8）
- [ ] LLM 边界全部生效（禁区明文）
- [ ] 完整 Scoped Egress + Update Bundle（远程 Worker 推 V2，见 §6.7）
- [ ] **Repository Contract 同时支持 SQLite/PG**（H2.4）
- [ ] Lite 2C2G 可跑，Standalone 4C8G 可跑
- [ ] 报告模板数据驱动 + 每声明->evidence + 每数字->查询 + 脱敏
- [ ] E2E（Juice Shop/crAPI/httpbin）全绿
- [ ] CI（ruff/mypy/pytest/compose smoke）全绿
- [ ] STRIDE 威胁模型归档（M5）

---

## 16. 关键取舍记录

1. **推倒重来而非渐进**：清理 07-24 多租户遗产和文档碎片，从需求出发干净设计
2. **混合框架脊柱而非纯 agent**：框架保证覆盖+安全+可复现，agent 贡献推理
3. **目录驱动覆盖而非 LLM 驱动**：TestCatalog 是护城河，agent 只加不减
4. **oracle N/N 验证而非 LLM 判定**：确定性复证，LLM 永不裁决
5. **模型驱动逻辑测试而非方法论门禁**：第二/三层业务逻辑确定性自动覆盖
6. **Nuclei YAML 基础+扩展而非自研 DSL**：采纳事实标准，10k+ 模板复用
7. **MCP 采纳优先而非全自写**：cve-mcp-server/mcp-security-hub 现成可用
8. **OSV 主源而非 NVD**：国内网络现实（NVD 503）
9. **聚合层开源 + 策展层产品 IP**：V1 轻策展，深度策展后置
10. **覆盖率退化门禁选项 D**：0 容忍 + override-with-reason
11. **A 全架构**：分布式 Worker + 完整 Scoped Egress + Update Bundle + Case Studio 可视化
12. **确定性脊柱九模块**：Planner/PolicyEngine/QualityGates/TestCatalog/CoverageMatrix/AppModel/LogicTestGenerator/VerificationMethodRegistry/OracleEngine，LLM 无关
13. **Audit M0 起步**（H2.1）：最小 Audit + hash chain 在 M0，非 M5；M5 只做完整密钥管理/续链/保留
14. **Repository 抽象 M0**（H2.4）：M0 起 Repository Contract，SQLite 实现 + PG 接口预留，避免 M5 切 PG 大重构
15. **OOB 自托管**（H4）：V1 自托管 Interactsh，国内公共 OOB 不稳
16. **oracle 靶场集**（H4）：Juice Shop/crAPI/vulhub 作为 oracle ground-truth，oracle 升级回归
17. **LogicTestGenerator 幂等**（M2）：输出带 signature（AppModel 哈希），重复跑去重，CoverageMatrix 计数不失真
18. **Custom POC 晋升流程**（M3）：Community -> 审核 -> 可选晋升 TestCatalog，单向不可回退
19. **Redaction 延伸 Report**（M7/M9）：Report 渲染层再过 RedactionEngine，区分我方/目标 secret
20. **MCP 供应链信任级**（M8）：采纳 MCP 输出标 untrusted，经 oracle 复证才确认；容器 digest 固定 + Trivy 扫
21. **LLM 运营约束**（H5）：本地优先 + 远程可选，预算/限速/降级/告警明文，超限自动降级本地
22. **LogicTestGenerator V1 3 类**（O3=B）：跳步+不变量违反+越界覆盖 80%，乱序/重放/竞态/角色 V2
23. **远程 Worker 推 V2**（O1=B）：V1 单机 Standalone + DB Lease，分布式基础设施推 V2，§6.7 spec 保留
24. **CoverageMatrix 开源**（O4=B）：MIT 开源聚社区+透明信任，moat 转到 TestCatalog/AppModel/oracle
25. **V1 市场实验定位**（19.6=B）：V1 验证差异化非盈利，V2 进 ToB；竞品差异化 mapping 见 §22
26. **OracleEngine 采纳 pentest-ai**（决策 22）：不自建 oracle，采纳 ptai（MIT）+ 建 VerificationMethodRegistry 策展层；集成不造轮子
27. **LogicTestGenerator 采纳 RESTler + Schemathesis**（决策 23）：跳步/乱序/重放用 RESTler，越界用 Schemathesis，自建不变量违反 + 编排层；V1 覆盖 5 类（优于原 O3=B 的 3 类）；集成不造轮子

---

## 17. 与旧设计的关系

| 旧文档 | 处置 |
|---|---|
| 2026-07-24-security-assessment-operations-platform-design.md | **取代**。多租户 MSSP 方向搁置，单用户 Agent-native 方向接管 |
| 2026-07-24-mvp-implementation-plan.md | 已退出（旧文档自带 Status） |
| 2026-07-24-m1-documentation-roadmap.md | 历史，不延续 |
| 2026-07-24-next-development-roadmap.md | 历史，Phase 0-4 代码遗产可参考但不直接复用（推倒重来） |
| 2026-07-25-agent-native-pentest-workbench-design.md | **取代**。方向对但未吸收调研结论，本轮重新设计 |
| 2026-07-25-agent-native-pentest-roadmap.md | **取代**。M0-M5 重新规划 |
| 2026-07-25-m0-domain-policy-baseline.md | **取代**。M0 重新定义 |

旧代码（14 ORM 模型 + 115 测试）不作为约束，但 nmap/nuclei 等 Adapter 解析器、MISP/Jira/Wazuh Connector 可作参考实现。

---

## 18. 后续

本设计经用户审阅确认后，进入 `writing-plans` 技能产出 M0 详细实现计划。M0 通过代码审查后，根据实际落地的 Repository/Policy/Digest/Error Model 编写 M1 详细计划，禁止跳到 MCP UI 或大规模工具接入。
## 19. 评审记录与改进建议（外部评审 · Codex 系统性评估）

- **评审日期**：2026-07-25
- **评审范围**：本设计文档全文（§1–§18）
- **评审方法**：CEO 视角 + 工程师视角（架构 / 数据流 / 边界 / 工时 / 文档）

### 19.1 总体定位

方向选择正确：
- 推倒重来（§1.1）合理——07-24 多租户 MSSP 与 07-25 Agent-native 并存的碎片化债务，重写是出路。
- 混合框架脊柱 + LLM 边界（§3.1、§4.9、§9.8、§10.9、§12.10）切中行业核心痛点。
- TestCatalog 目录驱动（§4.2、§4.3）是真正的差异化点——把"测什么"从 LLM 脑子里移到产品内。
- oracle N/N 复现（§9.2）走 pentest-ai 范式，是把 LLM 从裁决位降下来的关键设计。
- 三层 Evidence + 内容寻址（§9.6）解决渗透测试行业"证据不可复现"的普遍问题。

但**对范围**的判断有几处过度乐观，详见后续小节。

### 19.2 高风险项（实现前必须澄清）

#### H1. 工期预算严重低估 30-50%

§13 自称"34-53 人天（3-5 月）单人全职"。逐项拆解后严重偏离现实：

| 里程碑 | 设计预估 | 实际预估 | 偏差原因 |
|---|---|---|---|
| M1 四域 Adapter（§8.6）| 8-12 天（混入 M1 总时长）| 单独 12-18 天 | 每个 Adapter = `manifest.yaml + Dockerfile(digest 固定, non-root, cap-drop) + parser + run.sh + fixtures + 契约测试`（§8.1）。nuclei/dalfox/nmap/Prowler/Trivy/kube-bench/checkov 至少 7 个独立 Adapter，每个都要 fixtures（positive/negative/timeout/scope_deny/malformed 五种）|
| M2 Python Plugin Sandbox（§11.4）| 混入 M2 6-9 天 | 单独 5-8 天 | 沙箱隔离机制（gVisor/WASM/seccomp/container?）未指定，是研究级选择 |
| M3 LogicTestGenerator（§11.9，7 类逻辑测试）| 5-8 天 | 8-15 天 | "跳转/乱序/重放/竞态/越界/不变量违反/角色越权"7 类测试的生成算法是研究问题 |
| M3 AppModel Builder（§11.9，OpenAPI/Postman 导入 + LLM 起草 + 人校验 + 完整可视化）| 混入 M3 | 单独 8-12 天 | "完整可视化建模"在 M3 内做完不现实 |
| M5 STRIDE 威胁建模（§14 风险表最后一行）| 未排期 | 单独 5-7 天 | 全文只一句话提到，但实际工作等价于一次完整系统安全审计 |

**客观估算**：单人全职 **5-8 月**，且要有 buffer。文档应当**显式承认**这一区间，否则风险表（§14）"单人工期 3-5 月"是错估而非低估。

#### H2. 里程碑依赖错位（§13 与其他节多处冲突）

- §13 M0 DoD 列了"Plan 可持久化 / Approval 跑空计划 / Deny 优先"，但 **M5 才做 Audit Chain**（§13）。M0 已经有 Policy Deny 与 Approval 决策，没有审计链是合规缺口——必须 M0 就出最小 Audit 表 + 哈希链。
- §13 M3 DoD 列了"**完整** Case Studio 可视化建模"，但 §13 M4 才交付 Web Case Studio。两处对"Case Studio 完整度"口径不同，需明确：M3 是后端可视化，M4 是 Web 端？
- §13 M1 列 "IntelStore / UpdateManager / 四域 Adapter"，但 **RiskAnalyzer 在 M2**（§13），而 §8.2 表里 Adapter manifest 已有 `risk_class` 字段——Risk 数据源在哪？M1 的 Adapter 是不是没法带 risk 标签？
- §13 M0 列 "SQLite WAL Repository"，但 §12.2 又说"Repository Contract 同时跑 SQLite/PG"。M0 必须一开始就抽象 Repository，否则 M5 切 PG 会是大重构。

#### H3. 远程 Worker 通信链零定义（§12.3）

Lite（2C2G 控制节点）+ 远程 Worker + Standalone（4C8G 推荐 8C16G），**没说**：

- 控制节点 ↔ Worker 通信协议（mTLS / gRPC / HTTP2？）
- Worker 注册机制（mDNS？静态注册中心？反向连接？）
- 跨 NAT 穿透（WireGuard？Cloudflare Tunnel？SSH 反向隧道？）
- Worker 心跳 / 健康检查 / 断线重连
- Lease 落地位置（§12.3 说"DB Job Lease"，Lite=SQLite 时多 Worker 共享 SQLite 锁竞争？要不要先 Redis？）
- Adapter 镜像分发：需要 **Capability Registry + Heartbeat Payload**，全文未出现
- Evidence 数据回流：Worker 写本地 CAS 还是直传控制节点 CAS？

建议**单独成节 §6.7 分布式执行模型**，而不是塞在 §12.3。

#### H4. oracle N/N 与 OOB 的精确性未量化（§9.2、§9.4）

- **N 是多少**？没说。应作为 VerificationMethodRegistry 字段暴露。
- 重跑策略：同 Worker 重跑 vs 跨 Worker？时序抖动怎么处理？
- 5xx 服务端错误 vs 真没漏洞，区分阈值未定义。
- **国内到 interactsh.com / oast.live / oast.fun 的连通性本身不稳**（§10.2 标注 NVD 国内 503 是同类问题）。依赖公共 OOB 会高比例产生 INCONCLUSIVE → 退化为半自动工作台。是否考虑**自托管 Interactsh**？V1 没说。
- Oracle 自身需要 **Ground Truth 集**才能测试——网络/云容器/业务逻辑的 oracle 验证靶在哪？没有 → oracle 写完无法验证 oracle（递归问题）。

#### H5. LLM 选型 / 远程调用预算未定义（§12.8）

§12.8 给出 Secret / Restricted / Sensitive 分级，但 V1 实际：

- 用什么模型？本地（Ollama/vLLM 跑 7B/13B/70B）还是远程（OpenAI/Claude/Gemini API）？预算上限？
- 远程调用速率限制、Prompt size 上限、Token 计费上限？谁设置？告警阈值？
- §12.8 给的是"分级"，没给"分级的运营值"。运营值直接影响 DoD 中"agent 可端到端编排"（§15 第 1 条）能否真的跑通。

建议加 **§12.11 LLM 运营约束**（模型清单、每日 Token 上限、本地/远程自动降级规则）。

### 19.3 中优先级改进（影响落地体验但不会崩盘）

#### M1. AppModel 来源清单要明确（§11.9）

设计说"OpenAPI/Postman collection 半自动导入 + LLM 起草 + 人校验"，但没说：

- OpenAPI 3.0 / 3.1 / Swagger 2.0（很多遗留系统）/ AsyncAPI / Postman v2.1 / Insomnia / Stoplight Elements 哪个优先？
- **GraphQL introspection schema** 怎么办（越来越多 API 是 GraphQL）？
- gRPC + protobuf（也很常见）怎么办？
- **应用没有 API 文档**（这是常态）时 AppModel 怎么建？靠人工？靠流量录制？这条没覆盖。
- 单 LLM 起草对状态机很复杂的情况不够，怎么办？拆分子模型？人工拆解？

建议明确两条路径：**有文档走半自动导入；无文档走流量录制 + LLM 起草 + 人校验**。

#### M2. LogicTestGenerator 7 类测试的幂等性（§11.9、§11.10）

设计说"电商结算模型自动生成 ~40-60 个确定性逻辑测试"。但：

- 同一 AppModel 多次跑出的 60 个 Case 是否一致？
- 不一致的话 CoverageMatrix 怎么算？
- AppModel 微改后，全量重生成还是增量 diff？
- 7 类测试的"复杂业务规则不覆盖"声明（§14 风险表第 3 行）—— 谁判定"复杂"？判定流程？用户不签收怎么办？

建议让 LogicTestGenerator 输出带 `signature` 字段（基于 AppModel 内容哈希），重复跑能去重。否则 CoverageMatrix 计数会失真。

#### M3. Custom POC Registry vs TestCatalog 关系没说清（§7.1）

§7.1 把 Custom POC 放在 Community 子层，TestCatalog 在 Curation 子层。但 §4.2 TestCatalog 列表里写"自定义 POC registry（签名、版本化）"——这个"自定义 POC registry"是 TestCatalog 的子项还是平行的 Community 子层？用户提交 POC → 走 Community 审核 → 是否回写 TestCatalog？需要明确流程图：**Custom POC → 审核 → [可选] 晋升 TestCatalog**。

#### M4. CoverageMatrix 维护 SLA 没承诺（§4.4、§7.5）

每条 OWASP WSTG（94 条用例）/ OWASP API Top 10（10 类）/ CIS Benchmark（每 provider 数百项）/ PTES / NIST 800-115 都要映射到 ≥1 个 catalog 测试类。V1 上线后：

- WSTG 升 v4.3 时多久内完成映射？
- 新增 CIS Benchmark（厂商每年发）时 SLA？
- 谁来做？（单人 → 不可持续）

§14 风险表第 2 行写"上游借力 + 自动同步 + 社区 PR + 聚合层开源"是缓解，但**没承诺窗口**。建议加 §7.7 知识层维护 SLA 表。

#### M5. KnowledgeHealthMonitor 是 V2（§14 风险表）但 §7.5 覆盖率退化门禁依赖它

§7.5 提到"覆盖率退化门禁（选项 D：0 容忍 + override-with-reason）"，§13 M1 DoD 又写"KnowledgeHealthMonitor 告警"。但 §14 风险表最后写"V1 不做 KnowledgeHealthMonitor"。**V1 没有监控时退化门禁怎么 fire**？

要么：
- (a) 把 KnowledgeHealthMonitor 提前到 V1
- (b) 把 §7.5 门禁推迟到 KnowledgeHealthMonitor 上线后

二选一，否则有死循环。

#### M6. Audit Hash Chain 与数据保留的冲突（§12.6）

设计说"日志结构化 JSON，带 trace_id/correlation_id/tenant/run_id"。但：

- 私钥管理？私钥在哪？谁来 verify？
- 重放攻击：已签 Permit 是否带 nonce/有效期？全文未明确
- **Log rotation 后链头怎么办？** 直接断链？
- **GDPR/数据保留期**：不可篡改 vs 法定删除期冲突。设计没给答案。

#### M7. Evidence Redaction 自动化未设计（§9.6）

设计说"自动 + 人审"。但：

- 哪些字段是 Secret/PII？regex 库？误报率？
- 原始请求/响应包里目标泄漏的密钥（如对方 API 返回里 echo 了 key）怎么处理？这是"我们的 secret"还是"目标的 secret"？
- Redacted Evidence 是否独立存储 + 独立签名？

#### M8. MCP integration 的威胁面（§6.6）

- 采纳 `cve-mcp-server` / `mcp-security-hub` 后，**它们的输出信任级别是什么？**
- 它们的 Tool manifest 怎么进 Tool Registry？谁审计？
- 假设 `mcp-security-hub` 被攻陷，整个 agent 是否沦陷？mitigation？

#### M9. Secret 在 Report / 摘要中的脱漏路径（§9.6、§12.5）

§12.5 说 Secret 不入库/Prompt/日志/Evidence/报告。但如果 Report 引用"目标系统的管理员口令是 X"作为证据摘要呢？Redaction 必须延伸到 Report 渲染层。

#### M10. 报告模板的双语与定制（§15 DoD）

§15 写"报告模板数据驱动 + 每声明→evidence + 每数字→查询"。但：

- 格式？PDF/HTML/Markdown？单语还是中英双语？
- 客户 Logo / 品牌定制？
- 多客户格式模板？模板版本化？

V1 是否要做？

### 19.4 文档工程改进（实现前成本极低）

#### D1. 拆分文档

当前 ~1000 行 / 18 节，混合"设计规范 + 架构 + roadmap + DoD + 风险 + 决策记录"，违反单一职责。建议拆为 4 个文件：

1. `design-spec.md`（§1–§12，设计规范）
2. `architecture-detail.md`（带 Mermaid 图的层间时序、状态机、数据流）
3. `roadmap.md`（§13 + §15，里程碑 + DoD + 风险）
4. `decisions.md`（§1.2 + §16，每条 ADR 含 rejected options 与理由）

#### D2. 加 Mermaid 图（5 处最关键）

- §3 架构脊柱三方分工（状态机图）
- §6.4 一次 Assessment 完整流程序列图
- §10.3 Update Bundle 同步时序图
- §12.4 Scope 强制链 flowchart（10 步）
- §11.9 AppModel 生命周期状态机

#### D3. 加引用 / 资料链接

全文提到但没链接的概念：

- `pentest-ai oracle 验证范式` → 是哪篇 paper/repo？
- `Faraday 式统一 Observation` → Faraday 项目的 Observation 模型？
- `cve-mcp-server` / `mcp-security-hub` → 哪个 GitHub repo / 版本？
- `STRIDE 威胁建模` → 哪份文档？
- `OWASP WSTG v4.2 (94 用例)` → 具体章节列表？

#### D4. 补 ADR（Architecture Decision Records）

§16 列了 12 条关键取舍，但都是结论，缺"为什么不是另一个"。未来 6-12 个月回看会问"为啥不用 Burp Suite ActiveScan + 自写一层 orchestrator"。需要每条 ADR 含：

- Context（背景）
- Decision（决策）
- Consequences（成本与代价，包括隐性的）
- Rejected alternatives（被否决的方案 + 否决理由）

#### D5. 命名不一致

- "验证方法矩阵 / 无害化验证方法矩阵 / VerificationMethodRegistry" 三个名字描述同一物。
- "Case Studio (M3) / Web Case Studio (M4)" 口径不一。
- "Case Engine (M2) / Case Registry (M1)" — 是 Engine ⊂ Registry？
- "Adapter / Tool Adapter / Tool Registry" — Tool Registry 是 §6.1 知识层组件，但 §8.1 Adapter Pack 又没有 Tool Registry 入口。
- "模型" 一词 5 种含义：AppModel / ModelRegistry / LogicTestGenerator / 远程模型 / ModelBuilder。建议明确分类并在术语表锁定。

### 19.5 开放决策（用户拍板的策略性选择）

下面 4 条**不能由评审者代决**，每条直接影响 V1 形态：

| 编号 | 决策点 | 选项 A | 选项 B | 建议 |
|---|---|---|---|---|
| O1 | V1 远程 Worker 通信链是否进 V1 | Lite + 远程 Worker 通过 WireGuard / SSH 隧道 | V1 仅做单机 Standalone，远程 Worker 推迟 V2 | **B**：先 Standalone 跑通，远程 Worker 是 V2 清晰 milestone；否则 M5 工时 +50% |
| O2 | Interactsh OOB 是否自托管 | 公共 OOB 服务 + INCONCLUSIVE 容错 | 自托管 Interactsh（增加 Docker 服务）| **B**：国内网络现实，公共 OOB 高比例失败；自托管是工程量可控的解 |
| O3 | LogicTestGenerator 7 类生成算法 | 5-8 天实现生产级（7 类全自动）| V1 只做跳转/乱序/不变量违反 3 类（覆盖 70% 业务逻辑漏洞），其余 V2 | **B**：V1 必交付"业务逻辑测试可自动生成"，3 类 + 模板化已能 demo 差异化 |
| O4 | 知识层"开源分层"实际执行 | 聚合层 + 策展层都产品 IP（闭源）| 聚合层 + CoverageMatrix 开源（MIT），策展层产品 IP | **A**：单兵运营闭源策展层不可持续；开 CoverageMatrix 易吸引社区贡献 |

### 19.6 商业定位层面的提醒（CEO 视角，§1.2 决策 1）

设计**没回答一个核心问题**：**与 Burp Suite Pro / Caido / HexStrike AI / Nuclei Cloud / Pentest-Tools.com / PentestGPT / reNgine / Faraday 的逐项差异化 mapping**。

- **vs Burp Suite Pro**：Burp 覆盖 Web/API 90%（含你的设计里 70-85% WSTG），有 REST API + Extensions + ActiveScan。差异化是"目录驱动 + 自动 AppModel + 多域覆盖"，但**多域覆盖**对单兵目标用户真有必要吗？
- **vs Nuclei Cloud**：Nuclei Cloud 已是"目录驱动 + 模板"模式，差异在"业务逻辑自动生成"。
- **vs HexStrike AI / PentestGPT**：它们的"全 agent"是你 §3.3 反对的范式，混合框架脊柱差异化成立，但 LLM 时代的对手半年就能补这一层。

§2.1 说目标用户"个人渗透测试者 / 红队单兵"。**单兵场景的市场规模** vs **ToB 平台订阅**（MSSP、咨询公司、SOC）差一个数量级。建议**显式承认 V1 的市场实验性质**（证明差异化成立），并在 §2 加"如果 V2 进入 ToB 平台市场，需要哪些架构调整"。

### 19.7 推荐的落地路径

1. **先做 ADR 记录**（§1.2 的 14 条 + §16 的 12 条，每条 1 页，含 rejected alternatives）。D 系列建议。
2. **补 Mermaid 图**（§3、§6.4、§10.3、§12.4、§11.9 五张）。D2。
3. **重新估算工期**（承认 5-8 月单人全职），并相应**重新拆解 M0-M5 依赖关系**（H1+H2）。建议把 §13 拆为 6 个独立 roadmap 文件。
4. **锁定 H3-H5 的远程 Worker / oracle / LLM 三个子设计**——单独成节，不要塞在现有节里。
5. **回答 O1-O4 四个开放决策**——每条决定后改动 §12、§9.4、§11.9、§7 三处。

### 19.8 总评

**这份设计在结构上是我见过的渗透测试工具设计里最严谨的中文版本**——目录驱动 + 确定性脊柱 + oracle 范式 + LLM 边界清单 + 三层 Evidence + Audit Hash Chain，每一项都是行业真实痛点对症下药。

**主要风险不在"设计错"，而在"工作量低估 + 跨域抽象过粗"**：

- 工期 3-5 月是不现实的，按当前细节度单人 5-8 月。
- AppModel + LogicTestGenerator 是真正的差异化点，但也是工作量最大的黑盒，§11 是全文最薄的一节（只有细节表，没有算法细节），需要单独成 spec。
- 远程 Worker / oracle N=N / LLM 运营三件事的设计颗粒度不够，会在 M4-M5 集中爆发问题。
- 文档本身有 ~5 个关键概念图缺失 + 命名不一致 + ADR 缺失，会让 6 个月后回看时无法解释当初的选择。

**总体**：方向对、骨架好、问题在执行颗粒度。如果能把本文档从"设计稿"升级为"可执行规约"（图 + ADR + 重新拆解工期 + 锁定 H3-H5），这份设计就有资格作为 V1 起点。否则建议先把 H1-H5 + O1-O4 这 9 个点解决，再进 writing-plans。

---

*引用版本：本节针对 `2026-07-25-catalog-driven-agent-workbench-design.md`（V1 全架构方案 / 用户已确认）所写。所有小节编号与原文档一致。*

---

## 20. 评审吸收记录（2026-07-25）

针对 §19 外部评审，本节记录吸收/驳回/待决处置。设计文档已按"吸收"项修订。

### 20.1 已吸收（设计级修订，已落入正文）

| 评审项 | 处置 | 落入位置 |
|---|---|---|
| H1 工期低估 | ✅ 承认 5-8 月，重拆 M0-M5 | §13 里程碑表 + §14 风险表 + 头部工期 |
| H2.1 Audit 应在 M0 | ✅ M0 起最小 Audit + hash chain | §13 M0 DoD + §1.2 决策 15 + §16 取舍 13 |
| H2.2 Case Studio 拆分 | ✅ M3 后端建模 / M4 Web UI | §13 M3/M4 |
| H2.4 Repository 抽象 M0 | ✅ M0 起 Repository Contract | §13 M0 DoD + §1.2 决策 17 + §16 取舍 14 |
| H3 远程 Worker 零定义 | ✅ 补 §6.7 分布式执行模型 | §6.7（mTLS+反向连接+Redis Lease+Capability Registry+Evidence 回流） |
| H4 oracle 精度 | ✅ N 进 registry + 重跑策略 + 5xx 阈值 + 靶场集 | §9.2 + §9.4 + §13 M2 DoD + §16 取舍 15/16 |
| H4 OOB 自托管 | ✅ V1 自托管 Interactsh | §9.4 + §1.2 决策 16 |
| H5 LLM 运营未定义 | ✅ 补 §12.11 LLM 运营约束 | §12.11 |
| M1 AppModel 来源 | ✅ 两路径（有文档/无文档流量录制）+ 格式枚举 | §11.9 |
| M2 幂等性 | ✅ signature 字段 + 增量 diff | §11.10 + §1.2 决策 18 + §16 取舍 17 |
| M3 Custom POC vs TestCatalog | ✅ 补 §7.7 晋升流程 | §7.7 + §1.2 决策 19 + §16 取舍 18 |
| M6 Audit 密钥/保留 | ✅ 补 §12.12 密钥管理/nonce/续链/GDPR | §12.12 |
| M7 Redaction 自动化 | ✅ regex 库 + 两类 secret + 误报率 | §9.6 |
| M8 MCP 供应链 | ✅ trust level + 供应链 mitigation | §6.6 + §1.2 决策 21 + §16 取舍 20 |
| M9 Report 脱漏 | ✅ Redaction 延伸 Report 渲染层 | §9.6 + §1.2 决策 20 + §16 取舍 19 |
| D5 命名不一致 | ✅ 补 §21 术语表锁定 | §21 |

### 20.2 已驳回

| 评审项 | 驳回理由 |
|---|---|
| **M5 KnowledgeHealthMonitor 死循环** | 误读。§13 M1 已把 KnowledgeHealthMonitor 列为交付物，§14 无"V1 不做"表述。两者都在 V1，无死循环。评审此处 Fabricated |

### 20.3 已拍板（策略性决策，2026-07-25 用户确认）

| 评审项 | 决策 | 影响位置 |
|---|---|---|
| **O1 远程 Worker V1/V2** | **B：推 V2**。V1 单机 Standalone + DB Lease；§6.7 spec 保留作 V2 | §6.7 + §13 M4 + §12.3 Lite + §15 DoD + §16 取舍 23 |
| **O3 7 类 vs 3 类逻辑测试** | **B：V1 3 类**（跳步/不变量违反/越界，覆盖 80%）；乱序/重放/竞态/角色 V2 | §11.9 + §13 M3 + §15 DoD + §16 取舍 22 |
| **O4 CoverageMatrix 开源** | **B：MIT 开源**。聚合层 + CoverageMatrix 开源；TestCatalog/AppModel/OracleEngine 产品 IP | §7.6 + §1.2 决策 11 + §16 取舍 24 |
| **19.6 商业定位** | **B：显式定位**。V1 市场实验 + 竞品 mapping + V2 ToB 路径，见 §22 | §22 + §16 取舍 25 |

### 20.4 文档工程改进（低成本，未在本次吸收，建议 writing-plans 前补）

| 评审项 | 建议 | 状态 |
|---|---|---|
| D1 拆分文档 | 拆 design-spec/architecture-detail/roadmap/decisions 4 文件 | 待办 |
| D2 Mermaid 图 | §3/§6.4/§10.3/§12.4/§11.9 五张 | 待办 |
| D3 引用链接 | pentest-ai/Faraday/cve-mcp-server/STRIDE/WSTG 链接 | 待办 |
| D4 ADR | §16 每条补 Context/Decision/Consequences/Rejected alternatives | 待办 |

---

## 21. 术语表（外部评审 D5 命名锁定）

本文档"模型""Case""Adapter""Registry"等词多处混用，统一锁定：

### 21.1 模型类

| 术语 | 定义 | 所属层 |
|---|---|---|
| **AppModel** | 单个应用的形式描述（状态机+不变量+字段+角色+幂等），版本化签名 | 知识层-社区子层 |
| **ModelRegistry** | AppModel 的版本化存储（生命周期 DRAFT->...->PUBLISHED） | 知识层-社区子层 |
| **ModelBuilder** | 建模工具（自动发现+LLM 起草+人校验），M3 后端 API + M4 Web UI | 应用服务 |
| **LogicTestGenerator** | 从 AppModel 纯函数生成 7 类测试 Case 的算法库 | 知识层-策展子层 |
| **远程模型** | LLM 调用（本地 Ollama/vLLM 或远程 Claude/GPT API），运营约束见 §12.11 | 接口层/应用服务 |
| **DriftDetector** | AppModel 与应用实际（OpenAPI/流量）diff 检测 | 知识层 |

### 21.2 Case 类

| 术语 | 定义 |
|---|---|
| **Case** | 一个检测用例（YAML/Python/Composite），是 TestCatalog 测试类的具体实现 |
| **CaseDefinition** | Case 的元数据（作者/风险/Schema/签名），版本化 |
| **CaseRegistry** | Case 的版本化存储 + 生命周期管理（DRAFT->VALIDATED->REVIEWED->SIGNED->PUBLISHED） |
| **CaseEngine** | YAML DSL AST parser + interpreter（执行 Case） |
| **CaseContext** | Python Plugin 的 SDK，提供声明式 Capability（scoped_http/scoped_tcp/...） |
| **Case Studio** | 可视化建模 + Case 编辑 UI，M3 后端 API + M4 Web UI（不再用"Case Studio M3/M4"含混表述） |

### 21.3 Adapter / Tool 类

| 术语 | 定义 |
|---|---|
| **Tool Adapter** | 单个工具的封装（manifest+Dockerfile+parser+run.sh+fixtures），是执行单元 |
| **Adapter Pack** | 某覆盖域的 Tool Adapter 集合（资产测绘/Web-API/网络主机/云容器 四个 Pack） |
| **ToolDefinition** | Tool Adapter 的元数据（镜像 digest/risk_class/input_schema/...），版本化 |
| **Tool Registry** | ToolDefinition 的版本化存储（知识层-策展子层），与 Adapter Pack 关系：Registry 存定义，Pack 是按域分组的应用层概念 |
| **Tool Container** | Tool Adapter 运行时的隔离容器（digest 固定+non-root+cap-drop） |

### 21.4 验证类

| 术语 | 定义 |
|---|---|
| **VerificationMethodRegistry** | 漏洞类型 -> 验证方法的策展 registry（含 N 值/重跑策略/5xx 阈值），知识层-策展子层 |
| **OracleEngine** | 确定性复现器，调 Worker 跑 N 次探针，N/N 才 Confirmed |
| **无害化验证方法矩阵** | §9.5 表，是 VerificationMethodRegistry 的人读视图（不再作独立术语） |
| **CanaryTokenManager** | 唯一 token 生成/校验/审计 |
| **InteractshClient** | OOB 回调客户端，V1 自托管 |

### 21.5 知识层 / 覆盖类

| 术语 | 定义 |
|---|---|
| **TestCatalog** | "必测什么"知识库（资产类型 -> 必修测试类映射），知识层-策展子层 |
| **CoverageMatrix** | OWASP/CIS/PTES 框架条目 -> 测试类映射 + 覆盖率报告，知识层-策展子层 |
| **KnowledgeHealthMonitor** | 知识层健康监控（源停更/策展滞后/覆盖率退化/源失效/签名失效） |
| **Custom POC Registry** | 用户/社区 POC 存储，知识层-社区子层；可晋升 TestCatalog（见 §7.7） |

---

---

## 22. 商业定位与竞品差异化（外部评审 19.6，2026-07-25 拍板 B）

### 22.1 V1 市场实验定位

V1 = **市场实验**，验证差异化成立，非盈利产品。单兵市场比 ToB 平台小一个数量级，V1 目标是证明"目录驱动 + 模型驱动 + oracle"差异化可成立。V2 进 ToB 平台市场（见 §22.4）。

### 22.2 竞品差异化 mapping

| 竞品 | 它覆盖 | 我们的差异化 |
|---|---|---|
| **Burp Suite Pro** | Web/API 90%，REST/Extensions/ActiveScan，单域 | 目录驱动 + AppModel 业务逻辑自动生成 + **多域覆盖**（云/容器/网络，Burp 单域）+ oracle N/N 验证 |
| **Nuclei Cloud** | 已是目录+模板模式 | **业务逻辑自动生成**（Nuclei Cloud 无）+ oracle 验证 + 多域 |
| **HexStrike AI / PentestGPT** | 纯 agent 范式，LLM 裁决 | **确定性脊柱 + LLM 边界**（oracle 裁决非 LLM）+ 覆盖契约（不靠 agent 自觉） |
| **Faraday / DefectDojo** | 漏洞管理 + 归一化 | 执行 + 验证 + 模型驱动（它们偏管理非执行） |
| **reNgine** | Web Recon 编排 | 多域 + 模型驱动 + oracle（它们偏 Recon） |

### 22.3 护城河与可持续性

- **LLM 对手半年能补 hybrid spine**（评审尖锐指出）-> 差异化必须深，四层非 LLM 可补：
  1. TestCatalog 策展（产品 IP）
  2. AppModel 模型驱动（产品 IP）
  3. oracle N/N 验证（产品 IP）
  4. 模型签名治理（产品 IP）
- **CoverageMatrix 开源**（O4=B）聚社区 + 透明信任，但 moat 不在映射
- **单兵策展可持续性**：靠上游借力（nuclei/Prowler 团队著述）+ 社区 PR + CoverageMatrix 开源

### 22.4 V2 ToB 架构路径（预 mapping，V1 不做但预留）

V2 进 ToB 平台市场需要的架构调整：

| V2 能力 | V1 预留点 | 复用来源 |
|---|---|---|
| 多租户（Provider/Customer/Workspace） | Repository Contract 抽象 + Tenant Context 可加 | 07-24 设计可复用 |
| 团队协作（RBAC+ABAC+客户门户） | Domain 边界已为角色扩展预留 | 07-24 设计可复用 |
| 远程 Worker 分布式 | §6.7 spec 已备 | 本设计 §6.7 |
| 合规审计增强（SOC2/ISO27001） | Audit hash chain 已起步 | 本设计 §12.6 |
| 计费/合同 | 不预留 | 07-24 已排除，V2 评估 |

V1 的 Domain/Application/Infrastructure 边界 + Repository Contract 抽象已为 V2 多租户预留扩展点，V2 不需大重构。

### 22.5 开源同类采纳清单（集成不造轮子，2026-07-25 拍板）

回扣"集成不造轮子"原则。下列开源同类已采纳，避免自建：

| 开源同类 | 覆盖 | 采纳方式 | 替代的自建 |
|---|---|---|---|
| **pentest-ai / ptai**（MIT） | oracle N/N 复证 + 14 类漏洞 oracle + 证据胶囊 | Adapter/库，决策 22 | OracleEngine 自建 |
| **RESTler**（微软，MIT） | 状态ful API 序列测试（跳步/乱序/重放） | Adapter，决策 23 | LogicTestGenerator 跳步/乱序/重放自建 |
| **Schemathesis**（MIT） | property-based API boundary 测试（越界） | Adapter，决策 23 | LogicTestGenerator 越界自建 |
| **HexStrike AI**（MIT） | 150+ 工具 MCP 封装，12+ agent | MCP 工具采纳 | MCP 工具自写 |
| **cve-mcp-server**（MIT） | 28 工具 × 24 数据源漏洞情报 | MCP 采纳 | 情报 MCP 自写 |
| **mcp-security-hub**（MIT） | 38 个 Docker MCP（nuclei-mcp/nmap-mcp） | MCP 容器采纳 | 底层扫描 MCP 自写 |
| **Faraday** 归一化范式（GPL-3，参考） | 工具输出 -> 统一漏洞模型 | 范式采纳（§8.3 Observation） | 归一化自研 |
| **nuclei-templates**（MIT） | 10k+ 检测模板 | git pull 聚合 | POC 自写 |
| **ProjectDiscovery 工具链**（MIT） | subfinder/httpx/naabu/katana/nuclei | Adapter | 侦察引擎自研 |
| **Prowler/ScoutSuite/Trivy/kube-bench/checkov** | 云/容器/CIS 基线 | Adapter | 云容器引擎自研 |
| **Interactsh**（MIT） | OOB 反连 | 自托管客户端 | OOB 平台自建 |
| **MCP Python SDK**（官方） | MCP 协议 | 采纳 | 协议自实现 |

**真正自建且无开源同类的仅 6 项**（~12%）：TestCatalog + CoverageMatrix、AppModel 策展、不变量违反测试、VerificationMethodRegistry 策展、per-Assessment 版本钉死、确定性脊柱 wiring。集成比例 ~88%。

---

---

## 23. 文档结构（D1 拆分，4 文件）

本设计文档集分 4 个文件，单一职责：

| 文件 | 职责 | 受众 |
|---|---|---|
| `2026-07-25-catalog-driven-agent-workbench-design.md`（本文件） | 设计规范主体（§1-§22） | 全员 |
| `2026-07-25-architecture-detail.md` | 架构详图（6 张 Mermaid：三方分工/Assessment 流程/Update 同步/Scope 链/AppModel 状态机/确定性脊柱） | 架构师/实现者 |
| `2026-07-25-roadmap.md` | 路线图（M0-M5 里程碑 + 风险 + DoD + Out of Scope + V2 预留） | PM/实现者 |
| `2026-07-25-decisions.md` | ADR（17 条决策 rationale，含 Context/Decision/Consequences/Rejected alternatives） | 架构师/未来回看 |

主文件是权威源；其余 3 个是聚焦视图。所有文件互相引用，不重复内容。

---

## 24. 引用与参考资料（D3）

### 采纳的开源项目

| 项目 | 仓库 | 用途 |
|---|---|---|
| nuclei | https://github.com/projectdiscovery/nuclei | Web 漏扫核心引擎 |
| nuclei-templates | https://github.com/projectdiscovery/nuclei-templates | 10k+ 检测模板 |
| subfinder/httpx/naabu/katana | https://github.com/projectdiscovery | 资产测绘工具链 |
| Interactsh | https://github.com/projectdiscovery/interactsh | OOB 反连（V1 自托管） |
| nmap | https://nmap.org | 网络/主机扫描（独立进程） |
| Prowler | https://github.com/prowler-cloud/prowler | 云配置审计 |
| ScoutSuite | https://github.com/nccgroup/ScoutSuite | 多云审计（独立进程） |
| Trivy | https://github.com/aquasecurity/trivy | 容器/IaC 扫描 |
| kube-bench | https://github.com/aquasecurity/kube-bench | K8s CIS 基线 |
| checkov | https://github.com/bridgecrewio/checkov | IaC 扫描 |
| dalfox | https://github.com/hahwul/dalfox | XSS 专项扫描 |
| ZAP | https://github.com/zaproxy/zaproxy | Web 主动扫描（Standalone-only） |
| **pentest-ai (ptai)** | https://github.com/0xSteph/pentest-ai | **oracle N/N 验证（决策 22 采纳）** |
| **RESTler** | https://github.com/microsoft/restler-fuzzer | **状态ful API 序列测试（决策 23 采纳）** |
| **Schemathesis** | https://github.com/schemathesis/schemathesis | **API property-based 测试（决策 23 采纳）** |
| cve-mcp-server | https://github.com/mukul975/cve-mcp-server | 漏洞情报 MCP（采纳） |
| mcp-security-hub | https://github.com/FuzzingLabs/mcp-security-hub | 安全工具 Docker MCP（采纳） |
| HexStrike AI | https://github.com/0x4m4/hexstrike-ai | MCP 工具封装参考 |
| Faraday | https://github.com/infobyte/faraday | 归一化范式参考（GPL，不嵌入） |
| DefectDojo | https://github.com/DefectDojo/django-DefectDojo | 漏洞管理参考 |
| reNgine | https://github.com/yogeshojha/rengine | Recon 编排参考（GPL，不嵌入） |
| MCP Python SDK | https://github.com/modelcontextprotocol/python-sdk | MCP 协议实现 |

### 参考框架与情报源

| 框架/源 | 链接 | 用途 |
|---|---|---|
| OWASP WSTG v4.2 | https://owasp.org/www-project-web-security-testing-guide/ | Web 测试用例（94 项）映射 |
| OWASP Top 10 (2021) | https://owasp.org/Top10/ | Web 风险分类 |
| OWASP API Top 10 (2023) | https://owasp.org/API-Security/editions/2023/en/0x11-t10/ | API 风险分类 |
| CIS Benchmarks | https://www.cisecurity.org/cis-benchmarks | 云/容器/系统基线 |
| PTES | http://www.pentest-standard.org | 渗透测试执行标准 |
| NIST SP 800-115 | https://csrc.nist.gov/publications/detail/sp/800-115/final | 技术测试指南 |
| CWE | https://cwe.mitre.org | 弱点分类 |
| STRIDE | https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling | 威胁建模（M5） |
| OSV.dev | https://osv.dev | 漏洞情报主源 |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | 在野利用清单 |
| FIRST EPSS | https://www.first.org/epss | 利用概率评分 |
| NVD | https://nvd.nist.gov | CVSS 细节补充（代理备用） |
| GitHub Advisory | https://github.com/advisories | 生态漏洞 |
| MCP 协议 | https://modelcontextprotocol.io | Agent 调用协议 |

### 竞品（差异化参考，不集成）

| 竞品 | 链接 | 差异化（详见 §22） |
|---|---|---|
| Burp Suite Pro | https://portswigger.net/burp/pro | 商业闭源 Web-only；我们多域 + catalog + AppModel |
| Caido | https://caido.io | 商业闭源 Web-only |
| Nuclei Cloud | https://cloud.projectdiscovery.io | 托管 SaaS；我们自托管 + 业务逻辑自动生成 |
| PentestGPT | https://github.com/GreyDGL/PentestGPT | 纯 LLM 驱动；我们确定性脊柱 |
| Pentest-Tools.com | https://pentest-tools.com | 闭源 SaaS 不可集成 |

---

*本文档集（主设计 §1-§22 + 文档结构 §23 + 引用 §24 + 外部评审 §19 + 吸收记录 §20 + 术语表 §21 + 商业定位 §22）经用户审阅确认。所有策略决策已拍板（§20.3 + §1.2 决策 22/23）。配套文件：`2026-07-25-architecture-detail.md`（Mermaid 图）/ `2026-07-25-roadmap.md`（路线图）/ `2026-07-25-decisions.md`（ADR）。下一步进入 `writing-plans` 技能产出 M0 详细实现计划。*