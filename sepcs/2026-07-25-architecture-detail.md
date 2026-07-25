# 架构详图（Mermaid）

> 配套主文档 `2026-07-25-catalog-driven-agent-workbench-design.md` 的可视化视图。
> 本文件收录 D2 的 5 张关键图：三方分工、Assessment 流程、Update Bundle 同步、Scope 强制链、AppModel 生命周期。
> 仅用于合法授权渗透测试与防御性安全用途。

---

## 1. 三方分工（§3 架构脊柱）

框架铺路、agent 驾驶、Policy 刹车、人审批。覆盖契约硬卡结题。

```mermaid
flowchart TB
    subgraph 框架[框架 - 产品]
        F1[阶段序列: 侦察->枚举->扫描->验证->报告]
        F2[覆盖契约: 0 未执行必修类才能结题]
        F3[门禁 + 安全护栏]
    end
    subgraph Agent[Agent - 阶段内决策]
        A1[选工具/参数/目标迭代]
        A2[追查线索/判误报]
        A3[提议新 Plan Version]
        A4[写 POC 草稿]
    end
    subgraph 人[人 - 审批]
        H1[审批 scope/plan]
        H2[审批 Active/Intrusive 动作]
        H3[签 POC/终审 Finding]
    end
    subgraph Policy[Policy Engine - 每动作强制]
        P1[scope/DNS/risk/capability/budget/time]
        P2[Deny 优先 / Destructive 永拒]
    end

    F1 --> A1
    A1 --> P1
    A2 --> P1
    A3 --> H2
    A4 --> H3
    P1 -->|允许| EXE[执行]
    P1 -->|拒绝| BLK[阻断 + 审计]
    H2 -->|批准| EXE
    EXE --> RES[Observation + Evidence]
    RES --> VERIFY[oracle N/N 验证]
    VERIFY --> F2
    F2 -->|全绿| H3
    F2 -->|未绿| A1
```

**关键约束**：Agent 只能 ADD（参数化/追查/提议 POC），不能 SUBTRACT 必修类；Policy Engine 确定性裁决，不靠 LLM 自律；人审是不可绕过的发布/高风险门禁。

---

## 2. 一次 Assessment 完整流程（§6.4）

```mermaid
sequenceDiagram
    participant Agent
    participant MCP
    participant Planner
    participant Policy as PolicyEngine
    participant Worker
    participant Knowledge as KnowledgeLayer
    participant Oracle as OracleEngine
    participant Report as ReportRenderer

    Agent->>MCP: assessment_start(project, scope, mode)
    MCP->>Planner: 生成确定性 DAG
    Planner->>Knowledge: 查 TestCatalog(资产类型->必修类) + AppModel(逻辑测试)
    Knowledge-->>Planner: 必修测试类 + 模型生成测试
    Planner->>Policy: 校验 scope/risk
    alt Active/Intrusive
        Policy-->>Agent: 需人审批
        Agent->>Policy: 人审批通过
    end
    Policy->>Worker: 派发 Job + 签名 Permit
    Worker->>Worker: 容器 + scoped egress 执行工具/用例
    Worker->>Knowledge: 返回 Observation + Evidence(CAS)
    Knowledge->>Knowledge: CoverageMatrix 更新 + Finding 指纹去重
    Worker->>Oracle: Candidate 提交 N/N 复证
    Oracle->>Oracle: 从 VerificationMethodRegistry 读方法
    Oracle->>Worker: N 次独立探针(canary token)
    Oracle-->>Knowledge: Confirmed / REFUTED / INCONCLUSIVE
    loop 覆盖矩阵未全绿
        Knowledge-->>Planner: 缺失必修类
        Planner->>Worker: 补排课
    end
    Knowledge->>Report: 覆盖矩阵全绿 + 0 未验证
    Report->>Report: 模板渲染 + Redaction 延伸
    Report-->>Agent: 报告 + 证据引用
```

---

## 3. Update Bundle 同步时序（§10.3）

```mermaid
sequenceDiagram
    participant Sched as UpdateManager
    participant Src as 上游源
    participant Stage as StagingDB
    participant Verify as 签名/Schema校验
    participant Preview as 变更预览
    participant Active as 原子激活
    participant Snap as 旧快照
    participant Health as KnowledgeHealthMonitor

    Sched->>Src: 增量拉取(git pull 记 SHA / REST last_modified 游标)
    Src-->>Stage: 入 Staging DB
    Stage->>Verify: 签名校验 + schema/兼容检查
    alt 校验失败
        Verify-->>Health: 告警(签名失效/schema 不兼容)
        Verify-->>Sched: 拒绝 + 保留旧版
    else 校验通过
        Verify->>Preview: diff 旧版
        Preview->>Active: 原子激活(切换指针,不原地改)
        Active->>Snap: 保留旧快照(可回滚)
        Active-->>Health: 激活成功
    end
    Note over Sched,Health: 五类 bundle 同构: intel/case/tool/model/curation
```

---

## 4. Scope 强制执行链（§12.4，10 步）

Deny 始终优先；DNS 解析后二次校验防 rebinding；API + 执行层双重校验。

```mermaid
flowchart TD
    A[1. Target Normalize] --> B{2. Explicit Deny?}
    B -->|命中 deny| BLK[阻断 + 安全审计]
    B -->|未命中| C{3. Include Match?}
    C -->|不匹配| BLK
    C -->|匹配| D[4. DNS Resolve]
    D --> E{5. Resolved IP Recheck}
    E -->|IP 出 scope/防 rebinding| BLK
    E -->|IP 在 scope| F{6. Port/URL 校验}
    F -->|越界| BLK
    F -->|在界| G{7. Time Window}
    G -->|超窗| BLK
    G -->|在窗| H{8. Risk 校验}
    H -->|Destructive| BLK
    H -->|Passive/Low/Active/Intrusive| I{9. Approval}
    I -->|Active/Intrusive 未批准| WAIT[待人审批]
    I -->|已批准/Passive/Low 自动| J{10. Budget}
    J -->|超预算| BLK
    J -->|预算内| PERMIT[签发 Execution Permit]
    WAIT -->|人批准| J
```

---

## 5. AppModel 生命周期状态机（§11.9）

LLM proposes, human disposes, product executes。LLM 仅第 1 步辅助起草，人校验签名，执行全程 LLM 无关。

```mermaid
stateDiagram-v2
    [*] --> DRAFT: 自动发现(katana+OpenAPI/Postman/流量录制) + LLM 起草
    DRAFT --> LLM_PROPOSED: LLM 起草完成
    LLM_PROPOSED --> HUMAN_VALIDATED: 人校验(补不变量/标 trusted_source/定角色)
    HUMAN_VALIDATED --> SIGNED: Ed25519 签名
    SIGNED --> PUBLISHED: 进 ModelRegistry(版本+digest)
    PUBLISHED --> SUPERSEDED: 漂移检测 -> 新版本发布
    PUBLISHED --> 历史: per-Assessment 快照(不漂移)
    SUPERSEDED --> 历史: 旧版不删(可复现)
    历史 --> [*]

    note right of SIGNED
        签名后全程 LLM 无关:
        测试生成(纯函数) + 执行 + oracle 验证
    end note
    note right of PUBLISHED
        LogicTestGenerator 从签名模型生成 5 类测试:
        跳步/乱序/重放(RESTler) + 越界(Schemathesis) + 不变量违反(自建)
    end note
```

---

## 6. 确定性脊柱九模块（§6.2）

LLM 无关，结果质量的责任方。LLM 关掉仍能跑出完整基线报告。

```mermaid
flowchart LR
    subgraph 编排[编排子层]
        PL[Planner]
        PE[PolicyEngine]
        QG[QualityGates]
    end
    subgraph 知识[知识层]
        TC[TestCatalog]
        CM[CoverageMatrix]
        AM[AppModel]
        LTG[LogicTestGenerator]
        VMR[VerificationMethodRegistry]
    end
    subgraph 验证[验证]
        OE[OracleEngine 采纳pentest-ai]
    end

    PL -->|排课| TC
    TC -->|必修类| CM
    PL -->|模型测试| AM
    AM --> LTG
    LTG -->|Case| OE
    VMR -->|方法| OE
    OE -->|Confirmed/Refuted| QG
    QG -->|覆盖矩阵门禁| PE
    PE -->|允许/阻断| EXE[执行平面]
```

---

*本文件配合主文档使用。所有图编号对应主文档章节号。*
