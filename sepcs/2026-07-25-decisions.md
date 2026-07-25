# 架构决策记录（ADR）

> 配套主文档 `2026-07-25-catalog-driven-agent-workbench-design.md` 的决策 rationale。
> 每条 ADR 含 Context（背景）/ Decision（决策）/ Consequences（代价）/ Rejected alternatives（被否方案 + 理由）。
> 未来 6-12 月回看时，回答"为啥不用 X"。

---

## ADR-001：推倒重来而非渐进迁移

**Context**：07-24 MSSP 多租户设计（14 ORM 模型 + 115 测试）与 07-25 Agent-native 设计共存，文档碎片化、概念债务累积。07-24 多租户机制（Provider/Customer/Workspace/RBAC+ABAC/客户门户）对单兵场景是悬重资产。

**Decision**：推倒重来。搁置 07-24 多租户遗产和 07-25 M0-M5 骨架，从当前需求出发做干净设计，复用调研结论但不受旧代码约束。

**Consequences**：旧 115 测试不作约束（参考实现）；重新设计 Domain 模型；短期无代码可复用。换来：干净单用户核心、无多租户包袱、单一权威设计。

**Rejected**：
- *渐进迁移*：在 07-24 代码上叠加 agent-native。否决：多租户机制与单用户核心冲突，叠加只会加深债务。
- *fork 07-25*：07-25 方向对但未吸收 curl 调研结论（MCP 采纳/OSV 主源/pentest-ai oracle），fork 后仍需大改。

---

## ADR-002：混合框架脊柱而非纯 agent / 纯框架

**Context**：渗透编排有两种极端--纯 agent（pentest-ai/PentestGPT，LLM 裁决）覆盖靠 LLM 自觉；纯框架（reNgine/Faraday，agent 退化为参数填写器）失去 agent 价值。

**Decision**：混合框架脊柱。框架铺路（阶段+覆盖契约+门禁+安全）、agent 驾驶（阶段内决策）、Policy 刹车（确定性校验）、人审批（高风险）。

**Consequences**：四方分工需明确边界；覆盖契约硬卡结题；agent 只能 ADD 不能 SUBTRACT 必修类。换来：全覆盖可保证 + agent 推理价值 + 安全确定。

**Rejected**：
- *纯 agent-driven*：全覆盖不可保证（LLM 不知道的测试类就漏），结果不稳定。前几轮反复否定。
- *纯框架驱动*：agent 退化为参数填写器，失去 agent-native 差异化，与 reNgine/Faraday 同质。

---

## ADR-003：目录驱动覆盖而非 LLM 驱动

**Context**：混合模型若覆盖契约只查广度（每资产 ≥1 扫描）不查深度（已知漏洞类是否覆盖），深度覆盖依赖 LLM 知道某测试类--结果不稳定、不可控、无竞争力。

**Decision**：TestCatalog（产品 IP，版本化）驱动覆盖。框架按 catalog 对每资产强制排课必修类，agent 只能 ADD 不能 SUBTRACT。CoverageMatrix 映射 OWASP/CIS 算覆盖率。

**Consequences**：需策展 catalog（单兵负担靠上游借力 + 社区 PR）；覆盖契约门禁硬卡。换来：覆盖 LLM 无关、可审计、0 已知测试类漏跑。

**Rejected**：
- *LLM 驱动覆盖*：覆盖靠 LLM 自觉，不稳定不可控。正是用户前几轮否定的方向。
- *仅广度契约*：深度覆盖仍依赖 LLM，未解决问题。

---

## ADR-004：oracle N/N 验证而非 LLM 判定

**Context**：扫描器（nuclei/nmap）只报告不验证，版本匹配类结果大量误报。LLM 判定 Finding 不可信（幻觉）。

**Decision**：OracleEngine N/N 复证。每个 Candidate 必须 N 次独立复现（canary token 回显）才 Confirmed。采纳 pentest-ai（MIT）作 oracle 引擎，建 VerificationMethodRegistry 策展层。LLM 永不标记 Confirmed。

**Consequences**：需 oracle ground-truth 靶场集（Juice Shop/crAPI/vulhub）验证 oracle 自身；INCONCLUSIVE 升级人审。换来：发现可确定性验证、误报可剔除、证据可复现。

**Rejected**：
- *LLM 判定*：幻觉风险，不可审计。
- *仅工具 matcher*：nuclei matcher 是基础匹配，非 N/N 复证，误报率高。
- *自建 oracle*：pentest-ai 已实现（MIT），自建造轮子（ADR-015）。

---

## ADR-005：模型驱动逻辑测试而非方法论门禁

**Context**：业务逻辑漏洞（跳步/竞态/越界/不变量违反）WSTG-BUSL 给方法论不给模板，无通用模板。方法论门禁（人执行+签字）深度未知、不可复现、单兵不可持续。

**Decision**：AppModel 模型驱动。人建模应用工作流（状态机+不变量+字段信任边界+角色），LogicTestGenerator 从模型纯函数生成 5 类测试（采纳 RESTler 跳步/乱序/重放 + Schemathesis 越界 + 自建不变量违反），oracle 验证。

**Consequences**：建模成本 0.5-2 人日/应用（首次）；模型质量是上限；复杂业务规则声明不覆盖。换来：逻辑测试可量化（30-50 测试/模型）、可复现、可回归（持续验证）。

**Rejected**：
- *方法论门禁*：深度未知、不可复现、单兵不可持续。
- *纯自动推断（RESTler 自动）*：复杂业务规则 LLM/自动推断推不出，需人策展 AppModel 互补。

---

## ADR-006：Nuclei YAML 基础+扩展而非自研 DSL

**Context**：POC 格式有两种选择--采纳 Nuclei YAML（事实标准，10k+ 模板）或自研 DSL。

**Decision**：以 Nuclei YAML 为基础格式，扩展三类验证钩子（canary_token 占位 / verification 块 / classification 喂覆盖率）。基础语法兼容 Nuclei，现成模板零成本复用。

**Consequences**：扩展点需维护与 Nuclei 上游兼容；AI 生成 POC 走 Nuclei 生态。换来：10k+ 模板立即复用、AI 生态成熟、不自研 DSL。

**Rejected**：
- *自研 DSL*：重新发明轮子，失去 10k+ 模板和 AI 生态。
- *纯 Nuclei 无扩展*：无 canary/oracle/coverage 钩子，无法接确定性脊柱。

---

## ADR-007：MCP 采纳优先而非全自写

**Context**：MCP 安全生态 2026 已成熟（curl 实测）：cve-mcp-server（1.1k★，28 工具×24 数据源）、mcp-security-hub（749★，38 Docker MCP）、HexStrike AI（10.4k★，150+ 工具）。

**Decision**：MCP 采纳优先。编排专有 tool 自写；情报采纳 cve-mcp-server；底层扫描采纳 mcp-security-hub 容器。采纳的 MCP 输出标 untrusted，经 oracle 复证才确认。

**Consequences**：供应链风险（mcp-security-hub 被攻陷）需 mitigation（容器隔离+digest 固定+Trivy 扫+trust level）。换来：MCP 层不造轮子、社区生态复用。

**Rejected**：
- *全自写 MCP*：重复造轮子，丢失社区生态。
- *全采纳无 trust level*：供应链风险无 mitigation。

---

## ADR-008：OSV 主源而非 NVD 主源

**Context**：curl 实测 NVD API 2.0 从国内返回 503（Cloudflare 拦截）。OSV.dev 国内可达、免费无 key、聚合 NVD/GHSA/各生态数据。

**Decision**：OSV.dev 主源（6h 同步）+ CISA KEV（优先级）+ EPSS（利用概率）+ NVD（经代理补 CVSS 细节，备用）。

**Consequences**：CVSS 细节可能缺（OSV 聚合但不全），NVD 代理补；provenance 保留多源。换来：国内可达、不依赖被墙的 NVD。

**Rejected**：
- *NVD 主源*：国内 503 不可达。
- *仅 OSV 无 NVD*：CVSS 细节可能缺，需 NVD 代理补。

---

## ADR-009：聚合层 + CoverageMatrix 开源，核心策展产品 IP

**Context**：知识层开源策略需平衡社区贡献与 IP 保护。全闭源则单兵策展不可持续；全开源则失去 moat。

**Decision**：聚合层 MIT 开源（nuclei-templates/PD 工具链同源）+ CoverageMatrix MIT 开源（OWASP/CIS 映射，聚社区+透明信任）；TestCatalog 策展/AppModel/LogicTestGenerator/OracleEngine/VerificationMethodRegistry 产品 IP。

**Consequences**：CoverageMatrix 竞品可用，但 moat 转到 TestCatalog 策展 + AppModel + oracle（不可派生）。换来：社区 PR 减单兵负担 + 透明覆盖率建信任。

**Rejected**：
- *全闭源*：单兵策展不可持续，无社区贡献。
- *全开源*：失去核心 moat。
- *仅聚合层开源*：CoverageMatrix 单人维护仍是瓶颈。

---

## ADR-010：A 全架构 + O1/O3 缩范围，而非 B 中间路径 / Kali wrapper

**Context**：V1 范围三选项：A 全架构（3-5 月，重）、B 中间路径（1.5-3 月，简化基础设施）、C Kali wrapper（几周，退回 LLM 依赖）。

**Decision**：A 全架构 + O1=B（远程 Worker 推 V2）+ O3=B（逻辑测试采纳 RESTler/Schemathesis 后覆盖 5 类）。完整 Scoped Egress + Update Bundle + Case Studio 可视化。工期 4-6 月。

**Consequences**：单人工期 4-6 月；分布式 Worker 推 V2（§6.7 spec 保留）。换来：完整差异化（catalog+oracle+模型驱动+多域+agent-native）+ 不退回 LLM 依赖。

**Rejected**：
- *B 中间路径*：简化基础设施但保留确定性脊柱。被否：用户选 A 全架构（含完整 Scoped Egress/Update Bundle/Case Studio）。
- *C Kali wrapper*：退回纯 LLM 驱动，违背"不依赖 LLM"核心诉求。前几轮已否定。
- *A 全架构 + 远程 Worker 进 V1*：+5-8 天工期 + 运维负担，单兵常态 Standalone 够用，远程 Worker 推 V2（O1=B）。

---

## ADR-011：远程 Worker 推 V2（O1=B）

**Context**：A 全架构含分布式 Worker，但单兵常态 Standalone 4C8G 够用。远程 Worker 是利基需求（多视点/客户内网 DMZ）。

**Decision**：V1 仅 Standalone 单机执行 + DB Lease（无需 Redis）。§6.7 分布式执行模型设计保留作 V2 spec。

**Consequences**：V1 无多视点扫描；Lite 2C2G 退化为控制+轻量执行；大 Scope 并行受限单机。换来：V1 减 5-8 天工期 + 无分布式运维负担。

**Rejected**：
- *远程 Worker 进 V1*：多视点是利基，+5-8 天 + 运维重，不划算。除非常态客户内网/跨国目标。

---

## ADR-012：LogicTestGenerator 5 类（采纳 RESTler+Schemathesis），而非 7 类自建 / 3 类

**Context**：7 类逻辑测试（跳步/乱序/重放/竞态/越界/不变量/角色）自建研究风险高。RESTler（MIT）覆盖跳步/乱序/重放，Schemathesis（MIT）覆盖越界。

**Decision**：采纳 RESTler + Schemathesis 作 Adapter，自建不变量违反 + LogicTestGenerator 编排层。V1 覆盖 5 类（跳步/乱序/重放/越界/不变量违反），竞态/角色 V2。

**Consequences**：依赖 RESTler/Schemathesis 上游；不变量违反自建。换来：V1 覆盖 5 类（优于原 3 类）+ 不造轮子 + M3 减 2-3 天。

**Rejected**：
- *7 类自建*：研究风险高（竞态/角色建模），M3 8-15 天。
- *3 类自建（跳步/不变量/越界）*：采纳 RESTler/Schemathesis 后覆盖反而扩大到 5 类，自建 3 类是造轮子。

---

## ADR-013：CoverageMatrix 开源（O4=B）

**Context**：CoverageMatrix（OWASP/CIS 映射）是策展产物。闭源则单兵维护不可持续；开源则竞品可用。

**Decision**：CoverageMatrix MIT 开源。moat 转到 TestCatalog 策展 + AppModel + oracle（不可派生）。

**Consequences**：竞品可复用映射，但映射是机械活可派生，非真 moat。换来：社区 PR + 透明信任 + 单兵可持续。

**Rejected**：
- *CoverageMatrix 闭源*：单兵维护不可持续，无社区贡献。
- *TestCatalog 也开源*：TestCatalog 是真 moat（资产类型->必修类映射 + 策展判断），不开源。

---

## ADR-014：OracleEngine 采纳 pentest-ai，不自建

**Context**：pentest-ai（ptai，MIT，`pip install ptai`）已实现 oracle N/N 复证 + 14 类漏洞 oracle + 证据胶囊。

**Decision**：采纳 ptai 作 OracleEngine，建 VerificationMethodRegistry 策展层（漏洞类型->验证方法 + N 值 + 重跑策略 + 5xx 阈值）覆盖在 ptai 之上。

**Consequences**：依赖 ptai 上游；VerificationMethodRegistry 自建。换来：不自建 oracle 引擎 + M2 减 3-5 天 + ptai 证据胶囊复用。

**Rejected**：
- *自建 OracleEngine*：ptai 已实现（MIT），自建造轮子。
- *仅用 nuclei matcher*：非 N/N 复证，误报率高。

---

## ADR-015：V1 市场实验定位，非直接 ToB

**Context**：单兵市场比 ToB 平台小一个数量级。LLM 对手（HexStrike/PentestGPT）半年能补 hybrid spine。Burp/Nuclei Cloud 已统治 Web 扫描。

**Decision**：V1 = 市场实验，验证差异化（catalog+AppModel+oracle）成立，非盈利产品。V2 进 ToB 平台市场（多租户/团队/远程 Worker，07-24 模型可复用）。

**Consequences**：V1 不追求盈利；需竞品差异化 mapping 持续验证。换来：战略清晰、V2 路径预留、不盲跑。

**Rejected**：
- *直接 ToB*：单兵市场验证未做就跳 ToB，风险高。
- *V1 盈利定位*：单兵市场小，盈利不现实。

---

## ADR-016：Audit 起步 M0，而非 M5

**Context**：M0 已有 Policy Deny + Approval 决策，若 Audit 在 M5 才做，M0-M4 期间合规缺口。

**Decision**：M0 起最小 Audit 表 + hash chain 起步；M5 做完整（密钥管理 + Permit nonce + Log rotation 续链 + GDPR 数据保留）。

**Consequences**：M0 多 1-2 天。换来：全程审计可追溯、无合规缺口。

**Rejected**：
- *Audit M5 才做*：M0-M4 合规缺口，且 M5 补审计是大重构。

---

## ADR-017：Repository 抽象 M0，而非 SQLite-only

**Context**：M0 若 SQLite-only 不抽象 Repository，M5 切 PostgreSQL 是大重构。

**Decision**：M0 起 Repository Contract 抽象，SQLite WAL 实现 + PG 接口预留。业务代码不依赖 SQLite 专有逻辑。

**Consequences**：M0 多 1-2 天抽象成本。换来：M5 切 PG 不重构、V2 多租户可平滑升级 PG。

**Rejected**：
- *M0 SQLite-only*：M5 切 PG 大重构。
- *M0 直接 PG*：Lite 2C2G 跑 PG 过重，SQLite 是 Lite 默认。

---

*本文件 17 条 ADR 覆盖核心决策。§16 取舍记录是结论速查，本文件是 rationale 详述。*
