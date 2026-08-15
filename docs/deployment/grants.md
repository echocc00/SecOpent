# Engagement Grants(预授权)操作指引

> 面向运维:如何让 agent(Hermes 等)在你的授权边界内**自主** approve/start 评估,而不需要每次都人工审批。
> 版本:v0.6.3+。设计文档:`docs/superpowers/specs/2026-08-08-engagement-grant-mission-design.md`。

## 1. 概念

**EngagementGrant(授权契据)** = 你(人)对某个 project 的一次性预授权,声明:

- **范围**(scope):允许打哪些目标(URL/IP/域名/CIDR)+ 端口
- **风险上限**(risk_caps):允许到哪个风险等级(PASSIVE/LOW/ACTIVE/INTRUSIVE)
- **有效期**(valid window):从哪到哪
- **状态**:ACTIVE / REVOKED / 过期

有了 grant,agent 可以:

1. `grant_list(project_id)` — 查这个项目有哪些可用授权(agent 自己先看)
2. `plan_approve(assessment_id, grant_id=...)` — 在授权边界内的 plan 自动批准(审计记 `grant:<id>`)
3. `assessment_start(assessment_id, grant_id=...)` — 触发真实扫描(同样的边界校验)

**没有 grant 的 agent 行为完全不变**:仍收到 HUMAN_REQUIRED,必须人工在 UI 审批。

## 2. 核心安全保证(为什么这不等同于"放开")

| 保证 | 实现 |
|---|---|
| 建 grant 只能是人 | `GrantService.create_human` 拒绝 agent(复用 `_require_human`) |
| 打不到边界外 | 每个 assessment 目标都必须在 grant 的 scope 内(`covers_scope` 精确定义)——**授权 /24 ≠ 能扫 /8** |
| 高风险动作被卡 | plan 步骤的 risk 必须 ⊆ grant 的 risk_caps;DESTRUCTIVE 在任何路径下都不可达(代码 deny-list + 构造拒绝 + 执行层三层) |
| 过期/吊销即失效 | `start` 时重新校验 grant——批准后 grant 被吊销,启动也会拒绝 |
| 全链可审计 | 每一次 grant 批准的 approve/start,审计链记录 `grant:<id>`;查得到"哪个授权、谁建的、什么时候" |

## 3. MCP 工具面

| 工具 | 谁能调 | 行为 |
|---|---|---|
| `grant_list(project_id)` | agent ✓ | 列出该项目的 ACTIVE grants(边界、risk caps、过期时间) |
| `plan_approve(..., grant_id)` | agent(带 grant)| 边界内放行,记录 `grant:<id>`;无 grant → HUMAN_REQUIRED |
| `assessment_start(..., grant_id)` | agent(带 grant)| 边界内触发真实执行;无 grant → HUMAN_REQUIRED |

创建/吊销 grant 不走 MCP(见 §4)。

## 4. 创建与吊销(管理员)

当前通过 CLI 或直接调用 `GrantService`(UI 集成待 Phase B)。示例(CLI REPL 或测试脚本):

```python
from secopent.application.grants import GrantService
from secopent.domain.scope.models import ScopeDraft, ScopeLimits
from secopent.domain.policy.models import RiskClass
from secopent.infrastructure.db.session import Database
from secopent.infrastructure.repositories.sqlalchemy_grants import SqlAlchemyGrantRepository

db = Database.from_env()
with db.unit_of_work() as uow:
    scope = ScopeDraft(
        project_id="proj-xxxx",
        include=("http://8.133.200.235/",),   # 授权目标
        exclude=(), ports=(80, 443),
        limits=ScopeLimits(5.0, 3, 50_000),
    ).freeze(snapshot_id="grant-scope-1", approved_by="operator")

    svc = GrantService(SqlAlchemyGrantRepository(uow.session))
    grant = svc.create_human(
        project_id="proj-xxxx",
        name="ECS 生产扫描 8 月授权",
        scope=scope,
        risk_caps=frozenset({RiskClass.PASSIVE, RiskClass.LOW, RiskClass.ACTIVE}),
        valid_from=datetime(2026, 8, 8, tzinfo=utc),
        valid_to=datetime(2026, 9, 8, tzinfo=utc),
        actor_role="human",   # ← 必须 "human",agent 直接 DENY
    )
    print("grant id:", grant.id)
    uow.session.commit()
```

吊销(同样 human-only):

```python
with db.unit_of_work() as uow:
    revoked = GrantService(SqlAlchemyGrantRepository(uow.session)).revoke(
        grant.id, actor_role="human"
    )
    uow.session.commit()
```

吊销后:现有 approve 可能还持有 APPROVED 状态,但**下一次 start 会被拒绝**(start 重新校验 grant)。

## 5. 安全建议

1. **最短授权窗口**:按 engagement 定 valid_to,别开"永久 grant"
2. **最窄 scope**:只列本次要打的目标;不要顺手包含整个网段
3. **风险上限从低开始**:先 PASSIVE/LOW,确需要再升 ACTIVE;INTRUSIVE 慎开
4. **审计抽查**:`GET /audit/chain` 可查 `grant:<id>` 批准记录,确认 agent 行为跟你授权的一致
5. **不共享凭据**:grant 绑定 project;新客户开新 project 新 grant

## 6. RAQ

- **agent 能自己建 grant 吗?** 不能。`create_human` 强制 `actor_role="human"`,agent 调用即 DENY。
- **guard 过期后正在跑的评估会停吗?** 不会中断已运行(Approved→Running 的已放行);revoke 只影响未来的 approve/start。
- **executor 在 agent-grant 启动时走完整安全链吗?** 是。`assessment_start` 走 `start_scheduler` 触发与 HTTP `/start` 完全相同的 `_run_assessment_daemon`(permit/nft/egress 全链)。