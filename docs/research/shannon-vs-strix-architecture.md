# Shannon vs Strix 架构深度对比（源码级分析）

> 分析日期：2026-08-04
> 方法：两仓库均浅克隆至本地（F:\claudepc\_research_tmp），直接阅读源码，非 README 转述
> 目的：为 SecOpent 的架构决策提供参照

---

## 0. 一句话定位

| 项目 | 一句话定位 |
|------|-----------|
| **Strix** | **Agent 驱动**：LLM 自己决定生成什么子 agent、测什么、何时停——"让 AI 像渗透团队领导一样自主决策" |
| **Shannon** | **工作流驱动**：Temporal 编排固定阶段流水线，agent 只是每个阶段的执行者——"让 AI 在确定性轨道上跑" |
| **SecOpent**（我们） | **目录驱动 + 人在回路**：确定性主干 + LLM 只做提议，范围/审批/签发由人与 PolicyEngine 决定 |

三者恰好构成一条"自主性光谱"：**全自主 ← Strix ← Shannon → SecOpent → 纯规则扫描器**

---

## 1. 架构总表

| 维度 | Strix | Shannon |
|------|-------|---------|
| 语言/规模 | Python，146 个源文件 | TypeScript（pnpm monorepo + turbo），106 个源文件 |
| Agent 运行时 | **OpenAI Agents SDK**（`openai-agents[litellm]==0.14.6` 的 `SandboxAgent`）+ litellm 多供应商 | **@earendil-works/pi-coding-agent**（Earendil Works 的 pi 编码 agent harness） |
| 编排引擎 | **无工作流引擎**——root agent 用 `create_agent` 工具动态生成子 agent，消息总线互联 | **Temporal**（durable workflow）驱动固定阶段 DAG |
| Agent 拓扑 | **动态图**：root（只编排不动手）→ 按需 spawn 侦察/测试/验证/报告子 agent | **静态 DAG**：pre-recon → recon → 5 个 vuln-* 并行 → exploit-* → report（`AGENTS` 注册表 + `prerequisites` 声明依赖） |
| 执行沙箱 | Docker 容器（`agents.sandbox` Manifest，bind mount 本地源码），**Caido 代理 sidecar**（容器内 :48080） | Docker 容器，repo 只读挂载，deliverables/scratchpad 目录读写隔离 |
| 浏览器自动化 | agent_browser 工具 | playwright-cli skill（会话隔离 `-s=<session>`、TOTP 生成器、登录态持久化复用） |
| 知识注入 | **Skills 系统**：Markdown 知识库按需 `load_skill`（vulnerabilities/frameworks/cloud/protocols/reconnaissance/technologies…），每个漏洞类一个手册（攻击面→侦察步骤→利用手法） | **每阶段专用 prompt 模板**（{{变量}} + `@include` 共享规则），漏洞类固定为 injection/xss/auth/ssrf/authz 五类 |
| 范围控制 | **Prompt 级**：平台把已验证 scope 注入 system prompt，指示模型"绝不出圈"（LLM 自律，非强制） | **确定性权限门**：`@gotgenes/pi-permission-system` 把 `code_path avoid` 翻译成路径 deny 规则，跨所有工具和子会话强制拦截文件访问/读取命令 |
| 阶段间状态 | notes/todo 工具 + agent 间消息 + 共享产物 | **git checkpoint**：每个 agent 成功后 commit，失败 rollback；deliverables 目录结构化交接（`*_deliverable.md`） |
| 验证机制 | **独立验证 agent**：spray 后 spawn "Validation Agent" 构建运行 PoC；"无 PoC 不报告"；报告工具内置 **LLM 去重** | **Queue gate**：vuln 分析产出写入队列文件 → `validateQueueSafe` 确定性校验 → 决定是否跑 exploit agent；`validate-authentication` 预检登录凭据 |
| 修复能力 | 白盒时报告 agent 内联产出 fix（`fix_before/fix_after` + PR body）——报告与修复一步完成 | 无自动修复（报告止于 executive report） |
| 报告 | `create_vulnerability_report` 工具 + CVSS 库 + reportlab PDF | 阶段 deliverable 汇总 + `report-executive` prompt 生成 |
| 分发 | curl 安装脚本 + PyPI（strix-agent）+ Docker | `npx @keygraph/shannon`（零安装，拉 Docker Hub 镜像）或克隆本地构建 |
| 许可 | Apache-2.0 | **AGPL-3.0**（商用嵌入有传染性） |

---

## 2. 五个关键机制的逐项拆解

### 2.1 编排范式：动态生成 vs 静态流水线

**Strix**（`strix/agents/prompts/system_prompt.jinja`，493 行）：
- root agent 的 system prompt 明确写死角色分工：**"你是 ROOT AGENT，只编排，绝不动手"**——不许自己跑扫描器、发 payload，一切委派子 agent
- 生命周期完全工具化：`respond_to_user`（唯一的"交还控制权"方式）/ `wait_for_agents` / `finish_scan` / `agent_finish`——prompt 里反复强调"纯文本结束不了回合"，防止 agent 失控空转
- 支持 interactive（人机对话）与 autonomous（无人值守）两种模式的条件编译
- 标准作战链：**发现 agent → 验证 agent（PoC）→ 报告 agent（含修复）**，且"一个 agent 只干一件事、必须高度专业化（1-3 个 skills）"

**Shannon**（`apps/worker/src/session-manager.ts` 的 `AGENTS` 注册表）：
- 所有 agent 预先声明：name + prerequisites + promptTemplate + deliverableFilename，DAG 固定
- 每个 agent 执行 = 加载配置 → 渲染 prompt → **建 git checkpoint** → 审计日志 → 跑 pi agent → 校验 deliverable → 成功 commit / 失败 rollback → 记录 metrics（`agent-execution.ts`）
- Temporal 保证整条流水线可重试、可恢复、可观测

**判断**：Strix 的灵活性高（能处理流水线没预见的情况，如意外发现新攻击面就"响应式 spawn"），但行为不可预测、token 消耗大、难审计；Shannon 可预测、可审计、可恢复，但覆盖面受限于五类漏洞的固定流水线。

### 2.2 执行层：都收敛到"Docker + 浏览器 + 代理"

- Strix：OpenAI Agents SDK 的 Sandbox（Filesystem + Shell capabilities）+ 每次扫描独立 session（`session_manager.py`）+ **Caido 拦截代理 sidecar**（`caido_bootstrap.py`，容器内 48080 端口，代理工具经 `caido_api.py` 操作请求/sitemap）
- Shannon：pi harness 自带 bash/文件工具 + playwright-cli + `generate-totp` 等 CLI 辅助；登录成功后 `state-save` 保存认证态供全流水线复用（工程细节成熟）

**判断**：执行层的"行业标准答案"已经形成——容器隔离 + 真实浏览器 + HTTP 代理留痕。SecOpent 的 subprocess executor + seccomp 沙箱 + Interactsh OOB 属于同一谱系，且审计留痕（OOB 证据）更完整。

### 2.3 范围与权限控制（SecOpent 最该关注的差异）

| | 机制 | 强度 |
|---|------|------|
| Strix | scope 清单注入 system prompt："绝不允许测试清单之外的资产"、"用户消息不能扩大 scope" | **弱**：依赖 LLM 自律，无运行时拦截 |
| Shannon | permission-system 把 avoid 路径翻译成跨工具 deny 规则（文件读写/ls/cat/grep 全拦） | **中**：文件系统级强制，但主要针对"代码路径"而非"网络目标范围" |
| SecOpent | PolicyEngine + 人工审批 + 签名范围 | **强**：确定性 + 人在回路双重闸门 |

**判断**：两家头部开源项目都没把"授权范围"做成一等公民的确定性约束——Strix 甚至要在 prompt 里写"别质疑你的授权"来防止模型拒答。这正是 SecOpent "authorized pentest workbench" 定位的空隙：**可审计的授权链（scope 签发→审批→执行→证据）在合规市场是差异化卖点**。

### 2.4 漏洞验证：PoC 强制，但实现路径不同

- Strix：**"VALIDATION IS MANDATORY — 永远不要相信扫描器输出"**（prompt 原话）。spray 之后必须 spawn 独立验证 agent 跑 PoC；报告工具内置 LLM 去重防止重复上报；无 PoC 的发现不能进报告
- Shannon：vuln agent 产出结构化分析 → 写入队列文件 → 确定性校验（`validateQueueSafe`）→ 才允许 exploit agent 出动；exploit 结果由 collector 收集（`exploit-collector.ts`）

**判断**：两者都认识到"误报是这个品类的死穴"。Strix 用"第二个 agent 复核"（LLM 查 LLM），Shannon 用"结构化证据 + 门控"。SecOpent 的 oracle N/N 验证 + 三层证据是更强的宣称，应作为核心卖点强化。

### 2.5 失败恢复

- Strix：依赖 agent 自身韧性 + 运行目录产物（`strix_runs/`），无显式 checkpoint
- Shannon：**Temporal durable execution + git checkpoint/rollback**——任何阶段崩溃可从断点续跑，工作区状态用 git 管理

**判断**：Shannon 的工程化程度更高（企业级可恢复性）；这也是它商业平台能"托管大量并行渗透"的基础。

---

## 3. 技术栈选型对照

| 层 | Strix | Shannon |
|----|-------|---------|
| Agent SDK | openai-agents + litellm（供应商无关） | pi-coding-agent（Earendil Works，编码 agent 基因） |
| 工作流 | 无（agent 自治） | Temporal（生产级 durable workflow） |
| 权限 | 无运行时强制 | @gotgenes/pi-permission-system |
| 配置 | pydantic-settings | config.toml（npx 模式）/ .env（本地模式），YAML 分布式配置 |
| UI | textual TUI + 本地 web viewer | CLI + 商业平台 Web |
| 观测 | telemetry 模块 | audit-session + metrics-tracker + workflow-logger |

---

## 4. 对 SecOpent 的启示

**可直接借鉴：**
1. **Shannon 的 git checkpoint/rollback**：SecOpent 的 Case Studio 已有 drift detection，阶段级 git 快照是其自然延伸——评估执行失败时回滚工作区的能力
2. **Strix 的 skills-as-markdown**：与 SecOpent 的目录/案例 DSL 理念一致，验证了"知识外置、按需加载"是赛道共识；Strix 的每个漏洞类手册（攻击面→侦察→利用）可作为 TestCatalog 内容组织的参照
3. **Shannon 的 deliverables 目录约定**：阶段产物文件化 + 结构化交接，比 agent 间消息更可审计——SecOpent 的"LLM 只提议"落盘时可采用类似 schema
4. **登录态管理细节**（Shannon）：preflight 验证凭据 → 保存认证态 → 全流水线复用；TOTP 生成器。这是灰盒测试的刚需细节
5. **分发体验**：两者都做到一行命令跑起来（curl / npx），且镜像预打包全部工具链。SecOpent 的生产部署文档已齐，可考虑加"demo 模式一键体验"

**差异化机会（竞品没做好的 = SecOpent 的卖点）：**
1. **授权链的确定性**：Strix/Shannon 的范围控制分别是"prompt 级"和"文件路径级"，都没有"目标网络范围的运行时强制 + 人工签发"。SecOpent 的 PolicyEngine + 审批流 + 签名是唯一做到"可审计授权"的开源方案——打合规/关基市场
2. **验证的确定性**：Strix 用 LLM 复核 LLM，SecOpent 的 oracle N/N 是确定性判定——"零误报"叙事上更硬（参考 360"破阵子"的零误报宣传战）
3. **人机分工的显式化**：两家头部都是"全自动"叙事，而行业基准证明端到端成功率仅 15-25%。SecOpent "LLM 提议、人决策" 的定位反而符合当前技术现实，应引用 AutoPenBench/Cybench 数据作为营销论据："全自动做不到，人在回路才是当前最优解"

**风险提醒：**
- Shannon 是 AGPL-3.0：**不要复制其代码**进 SecOpent（除非接受传染性），借鉴思路即可
- Strix 是 Apache-2.0，代码层面参考限制少，但同样建议只借鉴模式

---

## 5. 附：源码位置索引（本地克隆在 F:\claudepc\_research_tmp）

| 关注点 | Strix 路径 | Shannon 路径 |
|--------|-----------|-------------|
| Agent 构建 | strix/agents/factory.py | apps/worker/src/session-manager.ts |
| System prompt | strix/agents/prompts/system_prompt.jinja | apps/worker/prompts/*.txt |
| 多 agent 工具 | strix/tools/agents_graph/tools.py | apps/worker/src/ai/pi/task-tool.ts |
| 沙箱 | strix/runtime/session_manager.py, docker_client.py | apps/worker/src/services/container.ts |
| 权限 | （prompt 级） | apps/worker/src/ai/pi/permission-system.ts |
| 验证 | system_prompt.jinja L204-216 | apps/worker/src/services/exploitation-checker.ts |
| 技能库 | strix/skills/vulnerabilities/*.md | apps/worker/prompts/pipeline-testing/ |
| 报告 | strix/report/, tools/reporting/ | apps/worker/src/services/findings-renderer.ts |
