# 开源安全评估与安全运营协同平台设计

- **状态**：Design v0.1，待用户审阅
- **日期**：2026-07-24
- **许可证决策**：核心平台 Apache-2.0
- **产品入口**：安全服务商 / MSSP / 红队渗透测试交付
- **长期方向**：甲方安全运营、SOC、Purple Team 和持续风险闭环
- **仓库策略**：独立仓库，不 fork 任何单一上游安全平台

---

## 1. 文档目的与设计结论

### 1.1 目的

本文档将市场调研结论转化为可实现的产品设计。它说明：

1. 为什么选择安全服务商而不是直接从企业 SOC 开始；
2. 为什么采用“自有控制平面 + 外部工具 Worker”的组合架构；
3. 为什么核心数据模型必须区分 Asset、Observation、Finding、Evidence 和 Retest；
4. 如何在保持 Apache-2.0 的同时集成 GPL/AGPL/商业边界不同的安全工具；
5. 如何实现授权范围、审批、租户隔离和证据完整性；
6. 如何从 MSSP 渗透测试逐步扩展到甲方安全运营，而不在首期陷入 SIEM/EDR 重型建设。

### 1.2 一句话结论

本项目不是重新实现 Nuclei、Wazuh 或 DefectDojo，而是构建一个开源、可自托管、面向 MSSP 的 **Security Assessment-to-Operations Control Plane**：

```text
客户与项目
  -> 授权范围与审批
  -> 安全工具编排
  -> 资产与观察结果归一化
  -> 发现项确认与证据链
  -> 报告交付
  -> 整改与复测
  -> 与甲方 SOC / 情报 / ITSM 联动
```

### 1.3 推荐架构

采用以下组合：

- 核心：Apache-2.0 的模块化单体控制平面；
- 执行：隔离的容器化 Worker；
- 工具：通过 Adapter 接入 Nmap、Amass、Nuclei、reNgine、ZAP、OpenVAS、Caldera 等；
- 风险：采用比扫描器更稳定的统一 Finding 模型；
- 资产：跨项目、跨运行、跨工具复用；
- 证据：不可变对象存储 + SHA-256 哈希 + 审计事件；
- 租户：Provider -> Customer -> Workspace -> Engagement 层级隔离；
- 扩展：通过 Connector 连接 Wazuh、Security Onion、MISP、OpenCTI、Shuffle、Cortex、Jira 等；
- 部署：首期 Docker Compose，规模化后 Kubernetes Worker Pool。

---

## 2. 市场事实与设计依据

### 2.1 现有开源项目的能力分布

| 能力面 | 代表项目 | 已解决的问题 | 没有同时解决的问题 |
|---|---|---|---|
| 渗透测试项目协作 | [Reconmap](https://github.com/reconmap/reconmap)、[Faraday](https://docs.faradaysec.com/)、[Dradis CE](https://github.com/dradis/dradis-ce) | 项目、工具结果、笔记、报告和协作 | 深度 MSSP 多租户、SOC 持续联动、统一复测闭环 |
| 报告生成 | [SysReptor](https://github.com/Syslifters/sysreptor)、Dradis CE | 模板、Markdown/HTML/PDF、专业报告 | 工具编排、资产图谱、授权治理 |
| Web Recon | [reNgine](https://github.com/yogeshojha/rengine) | 子域、URL、指纹、漏洞和持续监控 | 服务交付、跨项目统一风险、客户门户 |
| 扫描引擎 | [Nuclei](https://github.com/projectdiscovery/nuclei)、[OWASP ZAP](https://www.zaproxy.org/)、[OpenVAS](https://github.com/greenbone/openvas-scanner) | 专项检测能力 | 客户、证据、复测和工作流编排 |
| 漏洞管理 | [DefectDojo](https://github.com/DefectDojo/django-DefectDojo)、[ArcherySec](https://github.com/archerysec/archerysec) | 导入、去重、风险接受、生命周期 | 以服务商交付为中心的授权/报告/客户流程 |
| SOC / NSM | [Wazuh](https://github.com/wazuh/wazuh)、[Security Onion](https://github.com/Security-Onion-Solutions/securityonion) | 终端、日志、网络、告警和狩猎 | 红队交付和跨客户服务运营 |
| 情报 | [MISP](https://github.com/MISP/MISP)、[OpenCTI](https://github.com/OpenCTI-Platform/opencti) | IOC、Feed、STIX 和关系图谱 | 测试项目、证据和报告闭环 |
| 自动化响应 | [Shuffle](https://github.com/Shuffle/Shuffle)、[Cortex](https://github.com/TheHive-Project/Cortex) | Playbook、Analyzer、Responder | 安全评估授权与交付模型 |
| 对抗仿真 | [Caldera](https://github.com/apache/caldera)、[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | ATT&CK 验证和检测测试 | MSSP 项目管理、证据、报告和客户整改 |

### 2.2 市场空白

现有项目的主要空白不是缺少工具，而是缺少横向连接：

1. **服务商多租户**：许多项目适合单个组织部署，不适合一个服务商管理几十个客户且保证强隔离；
2. **授权范围治理**：安全工具执行往往与项目范围、时间窗、审批和排除目标缺乏统一绑定；
3. **证据链**：原始工具输出、人工验证、报告条目和复测结果经常断裂；
4. **跨项目资产复用**：同一个客户资产在不同测试项目中的历史、风险和复测状态缺少统一视图；
5. **Assessment-to-SOC**：测试发现通常停留在 PDF，不会自动成为甲方的整改、检测验证或持续监控输入；
6. **可替换执行层**：不同工具的输入、输出、版本和错误处理缺少稳定的 Adapter 契约；
7. **可运营性**：任务失败、重试、超时、凭证、并发、网络出口和审计经常被当成脚本细节，而不是产品能力。

### 2.3 为什么先做 B，再扩展 A

先做 MSSP/红队有三个好处：

- 交付频率高，用户可以每天使用平台；
- 结果价值容易量化：项目周期、报告周期、人工整理时间、复测闭环率；
- 用户天然需要多客户、多项目和报告能力，这些能力将来仍然适用于企业安全团队。

直接从 A（企业 SOC）开始会马上进入：

- 海量日志存储；
- Agent 和终端生命周期；
- 检测规则工程；
- 告警降噪；
- 7x24 运营；
- 高可用和容量规划。

这会让项目在还没有稳定用户价值之前，就承担 SIEM/EDR 的工程复杂度。

---

## 3. 产品范围

### 3.1 MVP 必须实现

#### 组织与租户

- Provider Organization；
- Customer；
- Workspace；
- 用户、团队和角色；
- 客户门户用户；
- 租户级数据保留策略；
- 租户级风险策略；
- 租户级 API Token；
- 完整审计日志。

#### Engagement

支持以下测试类型：

- 外网渗透测试；
- Web 应用测试；
- API 安全测试；
- 内网渗透测试；
- 红队行动；
- 云安全评估；
- Purple Team 验证；
- 复测项目。

每个 Engagement 包含：

- 客户和 Workspace；
- 测试类型；
- 项目负责人；
- 项目成员；
- 时间窗；
- 方法论；
- 授权文件引用；
- Scope；
- 报告模板；
- 状态机；
- 风险政策；
- 发布记录。

#### Scope

Scope 是任何主动安全任务的前置条件。支持：

- 域名和子域；
- IPv4/IPv6/CIDR；
- URL 和 API；
- 云资源标识；
- 代码仓库；
- 允许目标；
- 排除目标；
- 禁止端口或路径；
- 是否允许主动扫描；
- 是否允许利用验证；
- 执行时间窗；
- 最大并发；
- 速率限制；
- 审批要求。

#### Asset

第一阶段支持：

- Domain；
- IP；
- Host；
- Port；
- Service；
- URL；
- Web Application；
- API Endpoint；
- Cloud Resource；
- Repository。

#### Run

每次工具执行必须有独立的 Run 记录：

- Adapter 名称和版本；
- Tool 版本；
- Template/Rule 版本；
- 输入参数哈希；
- Scope 快照；
- 审批记录；
- 执行用户；
- Worker 节点；
- 开始/结束时间；
- 状态；
- 退出码；
- stdout/stderr；
- 原始结果对象；
- 解析错误；
- 产物列表；
- 消耗的资源。

#### Observation / Finding / Evidence / Retest

必须严格区分四种对象：

```text
Observation：工具或人工看到的现象
Finding：已由分析人员确认、可交付的问题
Evidence：支撑 Finding 的不可变证据
Retest：在整改之后再次验证的过程和证据
```

### 3.2 MVP 不实现

- 自研扫描器；
- 自研 SIEM；
- 自研 EDR；
- 无审批的自动利用；
- 全功能威胁情报图谱；
- 数千节点级别日志平台；
- 计费和合同系统；
- 通用低代码自动化平台；
- 大型插件市场；
- 自研报告排版引擎的全部高级能力。

这些能力可以通过外部工具或后续连接器支持。

---

## 4. 领域模型

### 4.1 层级模型

```text
Organization
  └── Customer
        └── Workspace
              └── Engagement
                    ├── Scope
                    ├── Asset
                    ├── Run
                    ├── Observation
                    ├── Finding
                    ├── Evidence
                    ├── Report
                    ├── Remediation
                    └── Retest
```

### 4.2 Organization

代表安全服务商或企业主体。

关键字段：

```text
id
name
slug
status
default_timezone
default_retention_days
created_at
updated_at
```

### 4.3 Customer

代表服务商的客户。Customer 与 Organization 分开，是为了支持一个 Provider 管理多个客户，同时允许未来企业自己部署时不必改变模型。

关键字段：

```text
id
provider_organization_id
name
external_reference
industry
contact_policy
data_retention_days
default_report_template_id
created_at
```

### 4.4 Workspace

Workspace 是权限、资产和项目的常用隔离单元。一个客户可以有多个 Workspace，例如生产环境、测试环境或不同业务线。

关键字段：

```text
id
customer_id
name
timezone
risk_policy_id
status
```

### 4.5 Engagement

Engagement 代表一次交付或测试活动。它拥有自己的 Scope 快照、成员、任务、Finding、报告和复测记录。

状态建议：

```text
DRAFT
PENDING_AUTHORIZATION
AUTHORIZED
PLANNED
RUNNING
ANALYSIS
REPORTING
DELIVERED
REMEDIATION
RETESTING
CLOSED
CANCELLED
```

状态转换必须经过领域服务校验，而不是允许客户端任意修改字符串。

### 4.6 Scope

Scope 需要版本化。测试开始以后不能无痕地修改范围。

```text
Scope
  ├── version
  ├── allow_targets[]
  ├── deny_targets[]
  ├── allowed_actions[]
  ├── forbidden_actions[]
  ├── valid_from
  ├── valid_until
  ├── concurrency_limit
  ├── rate_limit
  ├── authorization_artifact_id
  └── approved_by
```

每个 Run 记录实际使用的 Scope 版本。这样可以回答：

> 这次任务是在什么授权范围、什么版本、由谁审批的情况下执行的？

### 4.7 Asset

Asset 是跨 Engagement 复用的客户资产，但在每个 Engagement 中可以有一个关联快照。

建议采用：

```text
Canonical Asset
  └── Engagement Asset Reference
```

这样既可以保留客户级资产历史，又不会让项目报告受到未来资产变更的影响。

Asset 合并必须使用规范化规则：

- 域名统一小写并去除末尾点；
- URL 规范化 scheme、host、port 和路径；
- IP 使用标准文本表示；
- IPv6 使用规范化格式；
- 云资源使用 provider + account + region + resource ID；
- 不同来源记录为多个 Observed Identity，而不是直接覆盖。

### 4.8 Observation

Observation 是低信任、可重复、带来源的事实。

```text
id
engagement_id
run_id
asset_id
source_type
source_name
source_version
rule_id
rule_version
raw_artifact_id
normalized_payload
confidence
observed_at
```

Observation 不应该直接进入客户报告，除非被提升为 Finding 或作为背景证据引用。

### 4.9 Finding

Finding 是平台交付和整改的主要对象。

```text
id
workspace_id
engagement_id
canonical_fingerprint
title
summary
technical_description
business_impact
severity
cvss_vector
confidence
status
first_seen_at
last_seen_at
owner_id
remediation_due_at
risk_acceptance_id
```

Finding 状态建议：

```text
DRAFT
CANDIDATE
VALIDATED
REPORTED
ACKNOWLEDGED
IN_REMEDIATION
READY_FOR_RETEST
FIXED
PARTIALLY_FIXED
NOT_FIXED
ACCEPTED_RISK
FALSE_POSITIVE
CLOSED
```

### 4.10 Evidence

Evidence 应当是追加式和不可变的。修订证据不覆盖旧对象，而是创建新 Evidence 并保留关联。

```text
id
finding_id
run_id
kind
storage_uri
sha256
content_type
size_bytes
captured_at
captured_by
redaction_status
```

支持的 kind：

- raw_tool_output；
- screenshot；
- request_response；
- command_output；
- manual_note；
- reproduction_steps；
- remediation_proof；
- retest_result。

### 4.11 Report

报告不是 Finding 的导出文件，而是具有版本和发布状态的交付对象。

```text
id
engagement_id
template_id
version
status
draft_uri
rendered_uri
published_at
published_by
sha256
```

报告状态：

```text
DRAFT
IN_REVIEW
APPROVED
PUBLISHED
REVOKED
```

### 4.12 Retest

Retest 关联原 Finding，但不修改原始 Evidence。

```text
id
finding_id
engagement_id
requested_by
assigned_to
method
started_at
completed_at
result
new_evidence_ids[]
reviewed_by
```

---

## 5. 组件架构

### 5.1 控制平面

控制平面负责所有持久化业务数据和策略判断：

- Identity；
- Organization；
- Customer；
- Workspace；
- Engagement；
- Scope；
- Asset；
- Observation；
- Finding；
- Evidence metadata；
- Report；
- Remediation；
- Retest；
- Audit。

首期采用模块化单体，而不是一开始拆成微服务。原因：

1. 领域模型还需要通过真实用户反馈迭代；
2. 过早微服务会放大部署、事务、一致性和调试成本；
3. 控制平面本身不是首期性能瓶颈，真正重的任务在 Worker；
4. 模块化边界清晰后，未来可以按证据、任务、连接器等实际瓶颈拆分。

### 5.2 Worker 平面

Worker 平面运行安全工具和解析任务。它与控制平面通过任务消息和标准化结果通信。

```text
Control Plane
  -> Run Requested
  -> Scope Snapshot
  -> Worker Queue
  -> Isolated Worker
  -> Artifact Store
  -> Observation Events
  -> Control Plane
```

Worker 不直接写核心业务表，只能：

- 获取一次性任务凭证；
- 读取已批准的输入；
- 写入临时工作目录；
- 上传原始产物；
- 返回标准化结果；
- 发送状态事件。

这样可以避免某个工具插件直接绕过业务规则修改 Finding、Scope 或权限数据。

### 5.3 Artifact Store

原始工具输出和证据文件不适合直接存 PostgreSQL。

采用：

- PostgreSQL 保存元数据、权限和关联关系；
- S3 兼容存储保存大文件；
- SHA-256 保存内容指纹；
- 对象 Key 不包含可猜测的租户敏感信息；
- 下载使用短期签名 URL；
- 每次访问写入审计事件；
- 删除受租户保留策略和审计策略控制。

### 5.4 Queue 与事件

首期可以使用 Redis/Celery 或 RabbitMQ。需要区分：

- Command：请求 Worker 做某事；
- Event：某件事已经发生；
- Query：读取当前状态。

示例事件：

```text
engagement.created
scope.approved
run.requested
run.started
run.output.uploaded
run.completed
observation.created
finding.validated
report.published
retest.completed
```

事件必须携带：

```text
event_id
occurred_at
tenant_context
actor
correlation_id
causation_id
schema_version
payload
```

### 5.5 外部 Connector

Connector 与 Adapter 不同：

- Adapter：执行安全工具并产生 Observation；
- Connector：与外部平台交换资产、Finding、Alert、Case 或情报。

建议连接器分为：

```text
Ingest Connector：从外部平台导入
Export Connector：向外部平台输出
Sync Connector：双向同步
Enrichment Connector：丰富资产和 Finding
```

首批 Connector：

- DefectDojo Import/Export；
- Jira；
- Wazuh；
- MISP；
- OpenCTI；
- 飞书/钉钉通知。

---

## 6. Adapter 契约

### 6.1 设计原因

如果把每个工具的命令、解析器和业务逻辑直接写进 API 服务，系统会出现：

- 工具升级影响核心服务；
- 解析器异常拖垮 Web 服务；
- 许可证混入核心仓库；
- 安全凭证扩散到大量代码；
- 无法对不同工具做独立测试；
- 不能在不同 Worker 节点运行不同工具集。

因此 Adapter 必须是边界清晰的可替换执行单元。

### 6.2 Adapter Manifest

每个 Adapter 提供 manifest：

```yaml
id: projectdiscovery.nuclei
version: 1.0.0
adapter_api_version: v1
license: Apache-2.0
upstream:
  name: nuclei
  url: https://github.com/projectdiscovery/nuclei
  version: 3.x
capabilities:
  - web_scan
  - api_scan
risk_class: active_scan
requires:
  - network_egress
input_schema: schemas/input.json
output_schema: schemas/output.json
permissions:
  - read_scope
  - write_artifact
  - emit_observation
```

### 6.3 Adapter 输入

```json
{
  "run_id": "run-123",
  "engagement_id": "eng-123",
  "scope_snapshot": {
    "scope_version": 4,
    "allow_targets": ["https://example.com"],
    "deny_targets": ["https://example.com/admin/backup"],
    "valid_until": "2026-07-24T18:00:00Z"
  },
  "targets": ["https://example.com"],
  "options": {
    "severity": ["medium", "high", "critical"]
  },
  "execution_policy": {
    "timeout_seconds": 3600,
    "max_concurrency": 5,
    "network_profile": "approved-egress"
  }
}
```

### 6.4 Adapter 输出

```json
{
  "run_id": "run-123",
  "status": "completed",
  "tool": {
    "name": "nuclei",
    "version": "3.x",
    "template_version": "2026-07-24"
  },
  "artifacts": [
    {
      "id": "artifact-123",
      "kind": "raw_tool_output",
      "sha256": "...",
      "storage_uri": "s3://..."
    }
  ],
  "observations": [
    {
      "external_id": "template-id:target:path",
      "asset_identity": "https://example.com",
      "rule_id": "template-id",
      "title": "Example observation",
      "severity": "high",
      "confidence": 0.8,
      "evidence_artifact_ids": ["artifact-123"],
      "raw": {}
    }
  ],
  "errors": []
}
```

### 6.5 Adapter 安全限制

Adapter 不能：

- 读取其他租户数据；
- 自行获取长期凭证；
- 修改 Scope；
- 直接发布 Finding；
- 绕过审批；
- 访问控制平面数据库；
- 把凭证写入 stdout/stderr；
- 未经策略允许访问任意网络。

---

## 7. 任务与授权执行流程

### 7.1 正常流程

```text
用户创建 Run
  -> API 校验 Engagement 状态
  -> 加载 Scope 当前版本
  -> 计算目标是否属于 allow 且不命中 deny
  -> 根据风险等级判断是否需要审批
  -> 生成 Scope Snapshot
  -> 写入 RunRequested
  -> 进入 Worker Queue
  -> Worker 再次执行 Scope 校验
  -> 启动隔离容器
  -> 保存 stdout/stderr 和原始产物
  -> 解析为 Observation
  -> 上传结果并发送 RunCompleted
  -> 分析人员确认 Finding
```

### 7.2 失败流程

需要区分：

- 输入非法；
- 超出范围；
- 未审批；
- Worker 不可用；
- 工具退出码非零；
- 网络超时；
- 解析失败；
- 证据上传失败；
- 任务被用户取消；
- 超出时间窗。

每种失败都应有：

- 用户可读错误；
- 内部诊断错误；
- 是否可重试；
- 重试次数；
- 是否需要人工处理；
- 是否产生部分结果；
- 是否已经产生需要保留的证据。

### 7.3 重试策略

不能对所有任务无脑重试。

| 错误 | 默认处理 |
|---|---|
| 输入校验失败 | 不重试，要求修改输入 |
| 超出 Scope | 不重试，记录安全事件 |
| 未审批 | 不执行，等待审批 |
| Worker 暂时不可用 | 指数退避重试 |
| 网络暂时超时 | 有上限地重试 |
| 工具参数错误 | 不重试，标记 Adapter 错误 |
| 解析失败 | 保留原始输出，进入人工解析队列 |
| 对象存储失败 | 重试上传，不允许静默丢失 |
| 用户取消 | 不自动重试 |

---

## 8. 多租户和安全设计

### 8.1 租户隔离

首期采用共享数据库、所有核心表带 `organization_id`/`customer_id` 的模式，并在应用层统一注入 Tenant Context。

关键原则：

- 任何查询必须经过 Tenant Context；
- 禁止通过客户端传入的 tenant_id 作为可信权限依据；
- 资源访问先解析用户身份，再解析角色，再解析资源所属 Workspace；
- 所有跨客户查询必须是后台明确授权的汇总查询；
- 客户门户使用独立权限模型；
- 导出、报告下载、原始证据访问都走审计。

规模化后可以增加：

- PostgreSQL Row Level Security；
- 客户级数据库；
- 客户级对象存储前缀或 Bucket；
- 客户级加密密钥；
- 独立 Worker Pool。

### 8.2 RBAC 与 ABAC

RBAC 解决“谁是什么角色”，ABAC 解决“这个角色在什么上下文可以访问什么”。

策略条件可包括：

```text
user.organization_id
user.customer_memberships
user.workspace_memberships
user.role
resource.customer_id
resource.workspace_id
resource.engagement_id
resource.status
action
```

例如：

- Pentester 可以在已分配的 Engagement 执行任务；
- 但不能修改 Scope；
- Reviewer 可以确认 Finding；
- Customer Viewer 只能读取已发布报告；
- 客户用户不能读取内部笔记和原始扫描输出。

### 8.3 凭证管理

首期不在数据库中明文保存工具凭证。

建议：

- 接入 Vault 或云 KMS；
- 凭证按 Customer/Workspace/Integration 隔离；
- Worker 仅获取短期 Token；
- 日志自动脱敏；
- 不允许把 Secret 放在命令行参数；
- 任务完成后立即撤销或过期；
- 凭证访问写审计。

### 8.4 审计

审计事件至少记录：

- 登录和认证失败；
- 角色变化；
- 客户和项目创建；
- Scope 创建、修改、审批和撤销；
- Run 请求、审批、启动、取消和完成；
- 原始证据读取和下载；
- Finding 风险和状态变化；
- 报告审核、发布和撤回；
- Connector Token 使用；
- 跨租户管理员操作。

---

## 9. API 领域划分

首期不追求大量 REST 端点，而是保持领域边界清晰。

建议资源：

```text
/auth
/organizations
/customers
/workspaces
/members
/engagements
/scopes
/assets
/runs
/observations
/findings
/evidence
/reports
/remediations
/retests
/adapters
/connectors
/audit-events
```

### 9.1 Command 与 Query 分离

例如：

```text
POST /engagements/{id}/runs
POST /runs/{id}/approve
POST /runs/{id}/cancel
POST /findings/{id}/validate
POST /findings/{id}/request-retest
POST /reports/{id}/publish
```

与：

```text
GET /engagements/{id}
GET /engagements/{id}/assets
GET /engagements/{id}/findings
GET /runs/{id}/artifacts
GET /reports/{id}/download
```

这样可以明确哪些请求会产生副作用，避免把“查看页面”与“执行安全动作”混在一起。

### 9.2 幂等性

以下操作必须支持幂等：

- 创建 Run；
- 上传 Artifact；
- 导入 Observation；
- 导入外部 Finding；
- 发布报告；
- Connector 同步；
- Webhook 接收。

使用：

```text
Idempotency-Key
external_id
source_system
source_version
content_hash
```

防止网络重试造成重复扫描、重复 Finding 或重复报告。

---

## 10. 报告与证据设计

### 10.1 报告生成原则

报告生成要做到：

- Finding 与证据可双向追溯；
- 报告版本不可覆盖；
- 发布后内容不可静默改变；
- 报告可以在不暴露内部笔记的情况下提供给客户；
- 内部版本和客户版本可以有不同字段；
- 报告中每个关键数字都可以回到数据源。

### 10.2 报告模板

模板应该定义：

- 封面；
- 管理层摘要；
- 范围；
- 方法论；
- 风险统计；
- Finding 章节；
- 修复建议；
- 资产附录；
- 证据展示；
- 复测结果；
- 保密声明。

报告渲染可以首期使用现有成熟方案或独立 Renderer，不建议一开始实现完整排版引擎。

### 10.3 敏感信息处理

报告和证据可能包含：

- 密钥；
- Token；
- 内网 IP；
- 用户数据；
- 个人信息；
- 内部域名；
- 请求头和 Cookie。

需要支持：

- 自动脱敏；
- 人工确认；
- 原始证据与发布证据分离；
- 下载权限；
- 水印；
- 报告过期；
- 报告撤回；
- 访问审计。

---

## 11. 与外部项目的整合边界

### 11.1 Reconmap

借鉴：

- 项目管理；
- 命令执行；
- 命令输出保存；
- 报告；
- CLI/MCP 方向。

整合方式：

- 作为可选外部执行和导入源；
- 或参考其工作流设计实现自己的 Adapter；
- 不把其内部数据库当作平台主数据库。

### 11.2 DefectDojo

借鉴：

- Finding 去重；
- 统一导入；
- 风险接受；
- 生命周期；
- Scanner Parser。

整合方式：

- 提供 DefectDojo Import/Export Connector；
- 将平台的 Validated Finding 映射到 DefectDojo；
- 支持从 DefectDojo 导入历史漏洞；
- 不让 DefectDojo 成为客户、Scope 和 Evidence 的唯一来源。

### 11.3 reNgine / Nuclei / Amass

定位为执行 Worker：

- reNgine：Web Recon；
- Amass：攻击面发现；
- Nuclei：模板化检测。

所有结果都先进入 Observation，不直接发布为 Finding。

### 11.4 Wazuh / Security Onion

定位为外部持续运营数据源：

- 将资产和已知风险同步到本平台；
- 将已确认 Finding、攻击技术和整改状态输出到甲方系统；
- 不在本平台复制完整日志和 PCAP；
- 不在本平台重做 SIEM 查询引擎。

### 11.5 MISP / OpenCTI

定位为情报 Enrichment：

- 将 IP、域名、Hash、URL 与情报匹配；
- 给 Observation 增加标签和可信度；
- 将红队行动产生的 IOC 以脱敏方式输出；
- 不默认把外部情报直接变成客户 Finding。

### 11.6 Shuffle / Cortex

定位为外部编排或分析执行：

- 将高危 Finding 触发通知和 ITSM 工单；
- 对 Observable 调用 Analyzer；
- 本平台保留自己的授权、审计和 Finding 生命周期；
- 不把外部 Playbook 当作本平台的隐式权限来源。

### 11.7 Caldera / Atomic Red Team

定位为 Purple Team：

- 创建 ATT&CK 技术验证任务；
- 关联客户检测能力；
- 保存执行结果和检测结果；
- 形成“测试技术 -> 是否告警 -> 是否响应”的报告。

---

## 12. 部署模型

### 12.1 单机自托管

首期目标是一个命令即可启动：

```text
docker compose up -d
```

组件：

```text
web
api
worker
scheduler
postgres
redis
object-storage
reverse-proxy
```

适用于：

- 个人安全研究员；
- 小型红队；
- 演示环境；
- 客户现场部署；
- 离线/内网测试。

### 12.2 企业部署

后续支持：

- Kubernetes；
- 独立 Worker Pool；
- 客户级命名空间；
- 独立对象存储；
- 外部 PostgreSQL；
- Vault/KMS；
- OIDC/SAML；
- 高可用 API；
- 审计日志外送；
- 网络出口控制。

### 12.3 离线部署

安全服务商可能在客户现场工作，因此要支持：

- 无公网运行；
- 本地镜像仓库；
- 离线 Adapter 包；
- 本地报告渲染；
- 受控导出；
- 导入/导出加密包；
- 离线许可证和版本元数据。

---

## 13. 可观测性和运维

每个 Run 都必须能回答：

- 当前状态是什么；
- 卡在哪里；
- 哪个 Worker 执行；
- 使用了什么版本；
- 失败原因是什么；
- 是否可以重试；
- 是否已经产生部分结果；
- 是否产生敏感证据；
- 是否触发了范围安全事件。

建议指标：

```text
run_success_total
run_failure_total
run_duration_seconds
run_retry_total
adapter_parse_error_total
scope_block_total
artifact_upload_failure_total
finding_dedup_total
report_generation_duration_seconds
connector_sync_lag_seconds
```

日志必须使用 JSON，并携带：

```text
trace_id
correlation_id
tenant_id
customer_id
workspace_id
engagement_id
run_id
adapter_id
```

禁止记录：

- Secret；
- Token；
- Cookie；
- 完整 Authorization Header；
- 未脱敏的个人信息。

---

## 14. 测试策略

### 14.1 单元测试

覆盖：

- Scope 匹配；
- 排除目标；
- CIDR 判断；
- URL 规范化；
- Asset 合并；
- Finding 指纹；
- 风险计算；
- 状态转换；
- RBAC/ABAC 策略；
- Evidence 哈希；
- Idempotency；
- 任务重试策略。

### 14.2 Adapter 契约测试

每个 Adapter 必须测试：

- 输入 Schema；
- Scope 阻断；
- 正常输出；
- 空输出；
- 部分输出；
- 工具非零退出码；
- malformed 输出；
- 超时；
- 取消；
- 凭证脱敏；
- 原始产物保存。

### 14.3 集成测试

至少有一条完整链路：

```text
创建 Customer
  -> 创建 Engagement
  -> 审批 Scope
  -> 执行 Nmap Adapter
  -> 导入 Asset
  -> 执行 Nuclei Adapter
  -> 创建 Observation
  -> 确认 Finding
  -> 上传 Evidence
  -> 生成 Report
  -> 创建 Remediation
  -> 完成 Retest
```

### 14.4 多租户安全测试

必须覆盖：

- 用户不能读取其他 Customer；
- Customer Viewer 不能读取内部 Evidence；
- Worker 不能读取其他租户任务；
- 下载 URL 不能跨租户；
- Connector Token 不能越权；
- 管理员操作有审计；
- 归档和删除符合保留策略。

### 14.5 编码与运行环境测试

结合本项目运行环境，还要验证：

- UTF-8 无 BOM；
- 中文报告不乱码；
- PowerShell 启动不依赖当前 cwd；
- CLI 从仓库根目录、测试目录和任意目录都能运行；
- Docker Compose 在干净环境启动；
- 报告导出不丢失非 ASCII 内容；
- 原始工具输出和规范化内容可互相追溯。

---

## 15. 许可证和供应链治理

### 15.1 核心仓库

核心平台采用 Apache-2.0，包含：

- 领域模型；
- API；
- Web UI；
- 权限和审计；
- Worker 协议；
- Adapter SDK；
- Connector SDK；
- Docker Compose；
- 官方文档。

### 15.2 Adapter 仓库

每个 Adapter 至少包含：

```text
adapter/
  manifest.yaml
  LICENSE
  NOTICE
  README.md
  schemas/
  src/
  tests/
  fixtures/
  Dockerfile
```

### 15.3 许可证清单

项目需要维护机器可读的依赖清单：

```text
component
source_url
version
license
license_file
redistribution_allowed
network_service_obligation
security_review_status
```

### 15.4 不允许的做法

- 把 GPL/AGPL 项目源码复制进 Apache-2.0 核心；
- 删除上游版权和许可证声明；
- 把扫描模板当作没有许可证的普通数据；
- 把商业版专属代码当成开源代码使用；
- 未核验许可证就发布镜像；
- 将商业服务的专有 Connector 混入核心仓库。

---

## 16. 分阶段交付计划

### Phase 0：领域验证和样本收集

目标：证明数据模型能承载真实结果。

工作：

- 收集 Nmap、Nuclei、Amass、ZAP、reNgine 输出样本；
- 定义 Asset/Observation/Finding 映射；
- 定义报告中 Finding 和 Evidence 的引用关系；
- 定义 Scope 版本和授权快照；
- 定义 Adapter manifest；
- 完成许可证清单；
- 完成最小威胁模型。

退出条件：

- 至少五类工具输出可以归一化；
- 同一问题可以去重；
- 原始输出可以追溯到 Finding；
- 复测可以产生新 Evidence 而不覆盖旧 Evidence。

### Phase 1：MSSP MVP

工作：

- 组织、客户、Workspace、用户和角色；
- Engagement 和 Scope；
- Run 和 Worker；
- Nmap、Amass、Nuclei Adapter；
- Asset、Observation、Finding；
- Evidence 对象存储；
- Markdown/HTML/PDF 报告；
- 基础客户门户；
- 审计事件。

退出条件：

```text
一个新用户可以从零创建客户、创建项目、审批范围、执行扫描、确认 Finding、生成报告并完成复测。
```

### Phase 2：服务商效率

工作：

- reNgine 和 ZAP；
- Finding 去重；
- 项目模板；
- 报告模板；
- 复测工作流；
- 客户整改任务；
- CLI；
- API Token；
- 任务审批；
- Worker 节点管理。

### Phase 3：甲方运营连接

工作：

- Wazuh Connector；
- MISP Connector；
- Jira/飞书/钉钉 Connector；
- OpenCTI Enrichment；
- Shuffle/Cortex Connector；
- Finding 与 Alert/Case 关联；
- ATT&CK/Purple Team；
- 资产风险趋势。

### Phase 4：规模化生态

工作：

- Kubernetes Worker Pool；
- 多区域执行；
- 客户级密钥；
- 外部身份集成；
- Adapter Registry；
- 社区插件；
- 离线部署；
- 企业支持和托管服务。

---

## 17. 成功指标

### 交付效率

- 项目创建到第一次可交付报告的时间；
- 工具结果整理时间减少比例；
- 自动填充报告的 Finding 比例；
- 复测从申请到完成的时间；
- 每个测试人员可并行管理的项目数。

### 数据质量

- 多工具 Observation 去重率；
- Observation 到 Finding 的人工确认准确率；
- Finding 到 Evidence 的关联完整率；
- Finding 到 Retest 的闭环率；
- 报告数字与数据库统计的一致性。

### 安全治理

- 越权访问测试通过率；
- 跨租户数据泄漏为零；
- 超范围 Run 阻断率 100%；
- 未审批高风险动作阻断率 100%；
- Secret 出现在日志中的事件为零；
- 证据哈希校验通过率 100%。

### 生态

- 新 Adapter 接入时间；
- Adapter 升级对核心的影响范围；
- Connector 同步失败可恢复率；
- 社区 Adapter 数量；
- 外部项目贡献和使用情况。

---

## 18. 主要风险与应对

| 风险 | 原因 | 应对 |
|---|---|---|
| 范围过大 | 同时做 MSSP、SIEM、SOAR、EDR | 首期只做 Assessment-to-Report-to-Retest |
| 数据模型反复重做 | 直接复制某个上游项目 | 先定义自己的 Canonical Model 和 Mapping 层 |
| Adapter 不稳定 | 工具输出和版本变化 | Manifest、版本锁定、Fixture、契约测试 |
| 越权执行 | Scope 只在前端检查 | API 和 Worker 双重校验，Scope Snapshot |
| 跨租户泄漏 | 只依赖客户端 tenant_id | 服务端 Tenant Context、策略和审计 |
| 许可证污染 | 直接复制 GPL/AGPL 源码 | 外部进程/容器、独立 Adapter、许可证清单 |
| 证据不可信 | 文件覆盖或丢失 | 追加式 Evidence、SHA-256、不可变对象、审计 |
| AI 误导 | 只根据模型生成文本 | AI 输出必须引用 Observation/Evidence，人工发布 |
| 部署过重 | 首期引入过多基础设施 | 模块化单体 + Docker Compose + 独立 Worker |
| 只做出工具集合 | 没有完整交付闭环 | 以 Engagement 生命周期和报告/复测验收 |

---

## 19. 首期仓库结构建议

```text
SecOpent/
├── LICENSE
├── NOTICE
├── README.md
├── REPOSITORY_STRATEGY.md
├── AGENTS.md
├── pyproject.toml
├── docker-compose.yml
├── docs/
│   ├── superpowers/
│   │   └── specs/
│   ├── architecture/
│   ├── security/
│   └── adapters/
├── src/
│   ├── app/
│   │   ├── api/
│   │   ├── auth/
│   │   ├── organizations/
│   │   ├── customers/
│   │   ├── workspaces/
│   │   ├── engagements/
│   │   ├── scopes/
│   │   ├── assets/
│   │   ├── runs/
│   │   ├── observations/
│   │   ├── findings/
│   │   ├── evidence/
│   │   ├── reports/
│   │   ├── remediations/
│   │   ├── retests/
│   │   ├── audit/
│   │   └── connectors/
│   ├── worker/
│   │   ├── runtime/
│   │   ├── scheduler/
│   │   └── adapters/
│   └── shared/
│       ├── events/
│       ├── policies/
│       ├── schemas/
│       └── storage/
├── adapters/
│   ├── nmap/
│   ├── amass/
│   ├── nuclei/
│   └── zap/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── adapter_contract/
│   ├── security/
│   └── fixtures/
└── scripts/
```

该结构不是要求一开始就拆成很多服务，而是提前把领域边界和 Worker 边界表达出来。

---

## 20. 最终设计决策清单

当前建议锁定：

1. 核心许可证：Apache-2.0；
2. 仓库策略：独立仓库；
3. 产品入口：MSSP/红队渗透测试交付；
4. 长期方向：甲方安全运营；
5. 架构：模块化单体控制平面 + 隔离 Worker；
6. 数据核心：Asset / Observation / Finding / Evidence / Retest；
7. 工具接入：Adapter，不直接 fork 上游；
8. 外部系统：Connector，不复制完整 SIEM/SOAR；
9. 部署：Docker Compose 起步，Kubernetes Worker Pool 后置；
10. 安全边界：Scope、审批、双重校验、租户隔离、凭证隔离、审计；
11. 报告：版本化、可追溯、证据引用、发布审批；
12. AI：仅作证据约束下的辅助，不能默认扩大范围或执行高风险动作；
13. 首期成功标准：完整打通“客户 -> 授权 -> 执行 -> Finding -> 证据 -> 报告 -> 复测”。

本设计在用户审阅并确认后，才进入实现计划和代码阶段。
## M1 文件映射

本于单位管项。。未用。。。。。

| 新元 | 管项 | 未用 |
|---|---|---|
| 1 | docs/architecture.md | 转到信任边界区参“第全”。 |
| 2 | docs/connectors.md | 8 个连接器。配置。调度。重访/每信。 |
| 3 | docs/operations.md | 部置/调度/重访-每信。 |
| 4 | docs/roadmap.md | 5 个单位。阶段。 |
| 5 | tests/test_docs_consistency.py | 7 个一度。 |
