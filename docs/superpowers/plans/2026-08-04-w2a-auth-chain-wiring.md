# W2-A Authorization Chain + Composition Root Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 把"已建未接线"的授权链组件（PermitSigner/Verifier、EmergencyStop、ScopeEnforcer、AuditChain、PromptInjectionGuard、EgressGuard）接进生产执行路径，让"签名 ExecutionPermit + 紧急停止 + 10 步范围门禁 + 签名审计"在运行时真正成立。

**Architecture:** 在 `create_app` composition root 实例化全部安全组件并存入 `app.state`；`start_assessment` 路由签发 permit 并传入执行；`execute_assessment` 在入口检查 EmergencyStop、验证 permit、记录 nonce、对每个 plan 目标调 ScopeEnforcer.check；AuditChain 签名事件并记录 permit nonce 供重放检测。不改 domain 模型，只接线 application/infrastructure/interfaces 层。

**Tech Stack:** Python 3.12, FastAPI app.state DI, dataclasses, Ed25519 (cryptography), pytest, ruff, mypy strict.

**Spec:** `docs/superpowers/specs/2026-08-04-strix-shannon-layered-integration-design.md`（承继）；本计划对应验收报告 §四 第二波 Task 4-6（C2/C3/H1）。

**计划拆分说明（writing-plans scope check）：** 第二波"接线"共 7 项（C2/C3/H1-H5），按子系统拆 3 个计划。本文件是 **Plan A（关键路径：授权链 + composition root）**。其余两个独立计划：

| 计划 | 范围 | 触发条件 |
|------|------|----------|
| **Plan B W2-B 执行沙箱加固** | H2 nftables 接线 + H3 seccomp 诚实化 | 本计划 DoD 通过 |
| **Plan C W2-C 密钥持久化 + 验证 canary** | H4 SecretStore 持久化 + H5 canary token 接线 | 独立并行，可随时立项 |

---

## 现状映射（来自前置调研，无猜测）

| 组件 | 代码位置 | 当前接线状态 |
|------|----------|--------------|
| `PermitSigner.issue` | `infrastructure/permits/permit_signer.py:31,37` | 生产零调用 |
| `PermitVerifier.verify` | `infrastructure/permits/permit_signer.py:50,56` | 仅 tests 引用 |
| `EmergencyStop` | `application/emergency_stop.py:48` | 仅 `/stop` 端点临时构造，不进 app.state |
| `NullPermitRevoker` | `infrastructure/safety/emergency_infra.py:60` | `revoke_unused` 硬编码返回 0 |
| `ScopeEnforcer.check` | `application/scope_enforcer.py:165` | 生产零调用；第10步读 `context.permit_valid`（默认 True） |
| `AuditChain` | `application/audit_chain.py:36` | 生产零实例化；执行路径用 `AuditService`（无签名） |
| `execute_assessment` | `application/execution.py:62` | 不检查 permit / is_triggered / scope / egress |
| `create_app` | `interfaces/api/main.py:239` | 不实例化上述任何组件 |

执行调用链：`POST /assessments/{id}/start` (`assessments.py:234`) → `execute_assessment` (`execution.py:62`) → `Orchestrator.run_to_completion`。

---

## 文件结构

| 文件 | 职责 | 动作 |
|------|------|------|
| `src/secopent/infrastructure/safety/permit_revoker.py` | `InMemoryPermitRevoker`（真实撤销存储） | 新建 |
| `src/secopent/application/execution.py` | 接线 permit/emergency/scope/audit | 修改 |
| `src/secopent/application/emergency_stop.py` | `PermitRevoker` Protocol 已存在；无改 | 不改 |
| `src/secopent/application/scope_enforcer.py` | 第10步语义注释（permit_valid 由 verifier 决定） | 修改（注释） |
| `src/secopent/interfaces/api/routers/assessments.py` | `start_assessment` 签发 permit + 传执行参数 | 修改 |
| `src/secopent/interfaces/api/main.py` | composition root 实例化全部安全组件 | 修改 |
| `src/secopent/application/ports/security.py` | 新增 `SecurityComponents` 聚合端口（传 execute 的参数包） | 新建 |
| `tests/security/test_permit_revoker.py` | InMemoryPermitRevoker 单测 | 新建 |
| `tests/security/test_execution_gates.py` | execute 路径门禁集成测试 | 新建 |
| `tests/security/test_composition_root.py` | app.state 装配断言 | 新建 |
| `tests/integration/test_auth_chain_e2e.py` | 端到端：签发→验证→执行→审计→紧急停止 | 新建 |

---

## Task 1：InMemoryPermitRevoker -- 真实撤销存储

替换 `NullPermitRevoker`（返回 0）为真实实现：登记已签发 permit，`revoke_unused` 标记未使用者为已撤销，`is_revoked(nonce)` 供 verifier 查询。

- [ ] **1.1 写失败测试** `tests/security/test_permit_revoker.py`：

```python
# tests/security/test_permit_revoker.py
"""InMemoryPermitRevoker: real permit revocation store (W2-A Task 1)."""
from __future__ import annotations

from secopent.infrastructure.safety.permit_revoker import InMemoryPermitRevoker


def test_revoke_unused_marks_issued_unused_permits_revoked() -> None:
    revoker = InMemoryPermitRevoker()
    revoker.record_issued("nonce-A", used=False)
    revoker.record_issued("nonce-B", used=True)

    revoked = revoker.revoke_unused()

    assert revoked == 1
    assert revoker.is_revoked("nonce-A")
    assert not revoker.is_revoked("nonce-B")


def test_revoke_unused_returns_zero_when_nothing_pending() -> None:
    assert InMemoryPermitRevoker().revoke_unused() == 0


def test_record_used_marks_issued_permit_used() -> None:
    revoker = InMemoryPermitRevoker()
    revoker.record_issued("nonce-C", used=False)
    revoker.record_used("nonce-C")
    assert revoker.revoke_unused() == 0
```

- [ ] **1.2 运行测试确认失败** `py -3.12 -m pytest tests/security/test_permit_revoker.py -q`（ImportError，模块不存在）。

- [ ] **1.3 实现** `src/secopent/infrastructure/safety/permit_revoker.py`：

```python
# src/secopent/infrastructure/safety/permit_revoker.py
"""In-memory permit revocation store (W2-A Task 1).

Replaces NullPermitRevoker (which returned 0). EmergencyStop.trigger calls
revoke_unused() to invalidate issued-but-unused permits within their TTL
window. Production may later swap this for a DB-backed store; the Protocol
in application/emergency_stop.py stays stable.
"""
from __future__ import annotations

from secopent.application.emergency_stop import PermitRevoker


class InMemoryPermitRevoker(PermitRevoker):
    def __init__(self) -> None:
        self._issued: dict[str, bool] = {}  # nonce -> used?
        self._revoked: set[str] = set()

    def record_issued(self, nonce: str, *, used: bool = False) -> None:
        if nonce not in self._revoked:
            self._issued[nonce] = used

    def record_used(self, nonce: str) -> None:
        if nonce in self._issued:
            self._issued[nonce] = True

    def is_revoked(self, nonce: str) -> bool:
        return nonce in self._revoked

    def revoke_unused(self) -> int:
        pending = [n for n, used in self._issued.items() if not used]
        for nonce in pending:
            self._revoked.add(nonce)
            self._issued.pop(nonce, None)
        return len(pending)
```

- [ ] **1.4 运行测试确认通过** `py -3.12 -m pytest tests/security/test_permit_revoker.py -q`。

- [ ] **1.5 提交** `git add -A && git commit -m "feat(safety): InMemoryPermitRevoker real revocation store (W2-A T1)"`。

---

## Task 2：execute_assessment 入口门禁 -- EmergencyStop 检查

`execute_assessment` 入口检查 `emergency_stop.is_triggered`，触发则拒绝执行（mark FAILED + 审计）。

- [ ] **2.1 写失败测试** `tests/security/test_execution_gates.py`：

```python
# tests/security/test_execution_gates.py
"""execute_assessment security gates (W2-A Task 2-4)."""
from __future__ import annotations

import pytest

from secopent.application.emergency_stop import EmergencyStop
from secopent.infrastructure.safety.permit_revoker import InMemoryPermitRevoker
from secopent.infrastructure.safety.emergency_infra import (
    DockerContainerTerminator,
    NullContainerTerminator,
)
from secopent.application.audit import AuditService


def _make_emergency_stop() -> EmergencyStop:
    return EmergencyStop(
        permit_revoker=InMemoryPermitRevoker(),
        container_terminator=NullContainerTerminator(),
        audit=AuditService(repository=None),  # type: ignore[arg-type]
    )


def test_execute_refuses_when_emergency_stop_triggered(
    assessment_factory, execution_deps, monkeypatch
) -> None:
    stop = _make_emergency_stop()
    stop.trigger(actor="ops", reason="manual")

    with pytest.raises(Exception, match="EMERGENCY_STOP"):
        assessment_factory.start_and_execute(emergency_stop=stop, **execution_deps)
```

> 注：`assessment_factory`、`execution_deps`、`NullContainerTerminator` 在 Task 2.2 中补到 conftest；若 `NullContainerTerminator` 不存在则在该文件内定义一个 no-op 实现（仅测试用）。

- [ ] **2.2 运行确认失败**（`execute_assessment` 无 `emergency_stop` 参数）。

- [ ] **2.3 实现**：在 `src/secopent/application/execution.py` `execute_assessment` 签名增加 `emergency_stop: EmergencyStop | None = None`，入口处加门禁：

```python
# execution.py，execute_assessment 函数体开头（mark_running 之前）
if emergency_stop is not None and emergency_stop.is_triggered:
    service.mark_failed(
        assessment_id, reason="EMERGENCY_STOP_TRIGGERED",
        failure_class=FailureClass.POLICY,
    )
    audit.record("assessment.blocked.emergency_stop", assessment_id=assessment_id)
    return
```

同步在 `start_assessment` 路由（`assessments.py:234`）调用 `execute_assessment` 处传入 `emergency_stop=request.app.state.emergency_stop`。

- [ ] **2.4 运行测试** `py -3.12 -m pytest tests/security/test_execution_gates.py -q`。

- [ ] **2.5 提交** `git commit -m "feat(executor): emergency stop gate in execute_assessment (W2-A T2)"`。

---

## Task 3：Permit 签发 -- start_assessment 签发 ExecutionPermit

`start_assessment` 签发 permit（PermitSigner.issue），传入 `execute_assessment`。

- [ ] **3.1 写失败测试** `tests/security/test_execution_gates.py` 追加：

```python
def test_start_assessment_signs_permit_with_scope_and_plan_digest(
    assessment_factory, execution_deps, permit_signer
) -> None:
    run = assessment_factory.start_and_execute(
        permit_signer=permit_signer, **execution_deps
    )

    assert run.permit is not None
    assert run.permit.signature  # non-empty Ed25519 signature
    assert run.permit.scope_digest == run.scope.digest
    assert run.permit.plan_digest == run.plan.digest
    assert run.permit.worker_id == "adapter-executor"
```

- [ ] **3.2 运行确认失败**。

- [ ] **3.3 实现**：
  - `execute_assessment` 签名增加 `permit_signer: PermitSigner | None = None`、`permit_verifier: PermitVerifier | None = None`、`audit_chain: AuditChain | None = None`。
  - 在 `mark_running` 后、dispatch 前，若 `permit_signer` 提供，则构造 `ExecutionPermit(job_id=assessment_id, worker_id="adapter-executor", scope_digest=scope.digest, plan_digest=plan.digest, capabilities=..., budget=..., issued_at=utc_now(), expires_at=issued_at+timedelta(seconds=900), nonce=secrets.token_urlsafe(16))`，调 `permit_signer.issue(permit)`，存入局部变量。
  - `start_assessment` 路由从 `app.state.permit_signer` 取实例传入。

- [ ] **3.4 运行测试** `py -3.12 -m pytest tests/security/test_execution_gates.py -q`。

- [ ] **3.5 提交** `git commit -m "feat(executor): sign ExecutionPermit at assessment start (W2-A T3)"`。

---

## Task 4：Permit 验证 + ScopeEnforcer 真实调用

`execute_assessment` 验证 permit（PermitVerifier.verify + nonce 重放检测），对每个 plan 目标调 `ScopeEnforcer.check`，第 10 步 `permit_valid` 由 verifier 结果决定。

- [ ] **4.1 写失败测试** `tests/security/test_execution_gates.py` 追加：

```python
def test_replayed_permit_nonce_rejected(
    assessment_factory, execution_deps, permit_signer, permit_verifier, audit_chain
) -> None:
    # First execution records the nonce in audit_chain.
    assessment_factory.start_and_execute(
        permit_signer=permit_signer, permit_verifier=permit_verifier,
        audit_chain=audit_chain, **execution_deps,
    )
    # Reusing the same nonce must raise PermitReplayed.
    with pytest.raises(PermitReplayed):
        assessment_factory.start_and_execute(
            permit_signer=permit_signer, permit_verifier=permit_verifier,
            audit_chain=audit_chain, reuse_nonce=True, **execution_deps,
        )


def test_out_of_scope_target_denied_by_scope_enforcer(
    assessment_factory, execution_deps, permit_signer, permit_verifier,
    audit_chain, scope_enforcer
) -> None:
    assessment_factory.add_out_of_scope_target()  # plan target not in scope
    result = assessment_factory.start_and_execute(
        permit_signer=permit_signer, permit_verifier=permit_verifier,
        audit_chain=audit_chain, scope_enforcer=scope_enforcer, **execution_deps,
    )
    assert result.failed_jobs == 1
    assert "SCOPE_VIOLATION" in result.failure_reasons
```

- [ ] **4.2 运行确认失败**。

- [ ] **4.3 实现** `execution.py`：
  - permit 签发后、dispatch 前：若 `permit_verifier` 提供，调 `permit_verifier.verify(permit, now=utc_now(), used_nonces=audit_chain.permit_nonces() if audit_chain else frozenset(), expected_worker="adapter-executor")`；异常 → `mark_failed(POLICY)` + 审计 + return。
  - 记录 nonce：`audit_chain.record_permit_nonce(actor="system", job_id=assessment_id, permit_nonce=permit.nonce)`。
  - 构造 `permit_valid = True`（verify 通过即 True）。
  - plan 目标循环：对每个 `job.target` 构造 `EnforcementContext(budget_remaining=budget, permit_valid=permit_valid, ...)`，调 `scope_enforcer.check(target, scope, ctx)`；`deny` → 标记 job FAILED(`SCOPE_VIOLATION`)。
  - `scope_enforcer.py:165` 第 10 步加注释：`permit_valid` 由调用方经 `PermitVerifier.verify` 决定，不再默认 True。

- [ ] **4.4 运行测试** `py -3.12 -m pytest tests/security/test_execution_gates.py -q`。

- [ ] **4.5 提交** `git commit -m "feat(executor): verify permit + enforce scope per target (W2-A T4)"`。

---

## Task 5：AuditChain 签名事件 + permit nonce 记录

`execute_assessment` 用 `AuditChain` 记录签名事件（assessment.started/blocked/completed）+ permit nonce，替换裸 `AuditService.record`。

- [ ] **5.1 写失败测试** `tests/security/test_execution_gates.py` 追加：

```python
def test_execution_appends_signed_audit_events_and_permit_nonce(
    assessment_factory, execution_deps, permit_signer, permit_verifier,
    audit_chain
) -> None:
    assessment_factory.start_and_execute(
        permit_signer=permit_signer, permit_verifier=permit_verifier,
        audit_chain=audit_chain, **execution_deps,
    )

    events = audit_chain.events()
    actions = [e.action for e in events]
    assert "assessment.started" in actions
    assert "assessment.completed" in actions
    assert audit_chain.permit_nonces()  # non-empty
    assert audit_chain.verify() is True  # hash chain + signatures valid
```

- [ ] **5.2 运行确认失败**。

- [ ] **5.3 实现** `execution.py`：
  - `audit.record("assessment.started", ...)` 替换为 `audit_chain.record(actor="system", action="assessment.started", resource_type="assessment", resource_id=assessment_id, payload={...})`（若 `audit_chain` 提供；否则回退 `audit.record`）。
  - 同理 `assessment.completed` / `assessment.blocked.emergency_stop`。
  - permit nonce 记录已在 Task 4.3 完成。
  - `AuditChain.events()` 访问器：在 `audit_chain.py` 加 `def events(self) -> list[SignedAuditEvent]: return list(self._events)`。

> **DB 签名持久化（H6）延后**：本任务仅做内存签名链 + nonce 重放检测。签名事件落库（DB schema 加 signature 列 + SqlAlchemyAuditRepository 写签名）是 W2-C 范围，避免本计划过大。当前 `verify_db_audit_chain`（`chain_verify.py:28`）只验 hash，与内存 `AuditChain.verify()` 并行不冲突。

- [ ] **5.4 运行测试** `py -3.12 -m pytest tests/security/test_execution_gates.py -q`。

- [ ] **5.5 提交** `git commit -m "feat(audit): signed AuditChain events + permit nonce in execution (W2-A T5)"`。

---

## Task 6：Composition root -- create_app 装配全部安全组件

`create_app` 实例化 PermitSigner/Verifier、EmergencyStop、AuditChain、ScopeEnforcer、PromptInjectionGuard、EgressGuard，存入 `app.state`，注入 `start_assessment` 路由。

- [ ] **6.1 写失败测试** `tests/security/test_composition_root.py`：

```python
# tests/security/test_composition_root.py
"""Composition root assembles all security components (W2-A T6)."""
from __future__ import annotations

from secopent.interfaces.api.main import create_app
from secopent.application.emergency_stop import EmergencyStop
from secopent.application.audit_chain import AuditChain
from secopent.application.scope_enforcer import ScopeEnforcer
from secopent.infrastructure.permits.permit_signer import PermitSigner, PermitVerifier


def test_create_app_assembles_security_components_in_state(tmp_path) -> None:
    app = create_app(db_path=str(tmp_path / "t.db"))

    assert isinstance(app.state.emergency_stop, EmergencyStop)
    assert not isinstance(
        app.state.emergency_stop._permit_revoker,
        type(None),
    )
    assert app.state.permit_signer is not None
    assert isinstance(app.state.permit_verifier, PermitVerifier)
    assert isinstance(app.state.audit_chain, AuditChain)
    assert isinstance(app.state.scope_enforcer, ScopeEnforcer)
```

- [ ] **6.2 运行确认失败**（`app.state` 无这些属性）。

- [ ] **6.3 实现** `interfaces/api/main.py` `create_app`：
  - 在现有 `app.state.signing_keys`（line 297）之后追加：

```python
# Security components (W2-A T6)
from secopent.infrastructure.permits.permit_signer import PermitSigner, PermitVerifier
from secopent.infrastructure.safety.permit_revoker import InMemoryPermitRevoker
from secopent.infrastructure.safety.emergency_infra import DockerContainerTerminator
from secopent.application.emergency_stop import EmergencyStop
from secopent.application.audit_chain import AuditChain
from secopent.application.scope_enforcer import ScopeEnforcer
from secopent.application.audit import AuditSigner  # 或现有签名器

permit_signer = PermitSigner(private_key=signing_keys.ed25519_private())
permit_revoker = InMemoryPermitRevoker()
app.state.permit_signer = permit_signer
app.state.permit_verifier = PermitVerifier(public_key_bytes=permit_signer.public_key_bytes())
app.state.permit_revoker = permit_revoker
app.state.emergency_stop = EmergencyStop(
    permit_revoker=permit_revoker,
    container_terminator=DockerContainerTerminator(),
    audit=AuditService(repository=SqlAlchemyAuditRepository(session_factory)),
)
app.state.audit_chain = AuditChain(signer=AuditSigner(...))
app.state.scope_enforcer = ScopeEnforcer()
```

  - `start_assessment` 路由（`assessments.py:234`）从 `request.app.state` 取这些组件传入 `execute_assessment`。

> 实现者注意：`AuditSigner` / `signing_keys.ed25519_private()` 的确切取值路径以现有 `SigningKeyService` API 为准（`main.py:297-303`）；若签名服务不直接暴露私钥，则 `PermitSigner` 用独立 Ed25519 密钥对（生成一次，公钥存配置），并在 ADR 记录密钥来源。

- [ ] **6.4 运行测试** `py -3.12 -m pytest tests/security/test_composition_root.py -q`。

- [ ] **6.5 提交** `git commit -m "feat(app): composition root assembles security components (W2-A T6)"`。

---

## Task 7：PromptInjectionGuard + EgressGuard 接线

`PromptInjectionGuard` 接入 LLM 调用点（RemoteModelGateway），`EgressGuard`（应用层）作为执行前预检。

- [ ] **7.1 写失败测试** `tests/security/test_execution_gates.py` 追加：

```python
def test_prompt_injection_guard_blocks_malicious_llm_input(
    app_with_gateway, malicious_prompt
) -> None:
    result = app_with_gateway.gateway.complete(malicious_prompt)
    assert result.blocked is True
    assert "prompt_injection" in result.reason


def test_egress_guard_precheck_denies_cloud_metadata_target(
    assessment_factory, execution_deps, egress_guard
) -> None:
    assessment_factory.add_target("169.254.169.254")  # cloud metadata
    result = assessment_factory.start_and_execute(
        egress_guard=egress_guard, **execution_deps
    )
    assert "EGRESS_DENIED" in result.failure_reasons
```

- [ ] **7.2 运行确认失败**。

- [ ] **7.3 实现**：
  - `RemoteModelGateway`（`infrastructure/llm/`）`complete()` 前调 `prompt_injection_guard.check(input)`；命中 → 返回 blocked 结果 + 审计。
  - `execute_assessment` 在 plan 目标循环中，对每个目标调 `egress_guard.check(target_ip)`（DNS 解析后）；deny → 标记 job FAILED(`EGRESS_DENIED`)。
  - `create_app` 实例化两者存 `app.state`，注入执行路径。
  - 注：`EgressGuard` 应用层预检是 W2-A 范围；**内核级 nftables 接线是 W2-B 范围**（`_network_mode` 改造 + `NftScopeEnforcer.apply_scope`），本任务只接应用层。

- [ ] **7.4 运行测试** `py -3.12 -m pytest tests/security/test_execution_gates.py -q`。

- [ ] **7.5 提交** `git commit -m "feat(security): wire PromptInjectionGuard + EgressGuard app-layer (W2-A T7)"`。

---

## Task 8：端到端集成测试 + 质量门禁

完整链路：签发 permit → 验证 → 执行（scope/egress 门禁）→ 签名审计 → 紧急停止阻断新 assessment。

- [ ] **8.1 写端到端测试** `tests/integration/test_auth_chain_e2e.py`：

```python
# tests/integration/test_auth_chain_e2e.py
"""End-to-end authorization chain (W2-A T8)."""
from __future__ import annotations

import pytest


@pytest.mark.integration
def test_full_auth_chain_sign_verify_audit_and_emergency_stop(
    api_client, db_session, juice_shop_target
) -> None:
    # 1. Start assessment -> permit signed, executed, signed audit appended.
    r = api_client.post(f"/assessments/{juice_shop_target.assessment_id}/start")
    assert r.status_code == 202
    api_client.wait_for_completion(juice_shop_target.assessment_id)

    audit = api_client.get(f"/assessments/{juice_shop_target.assessment_id}/audit")
    assert any(e["action"] == "assessment.completed" for e in audit.json()["events"])
    assert audit.json()["signature_chain_valid"] is True

    # 2. Trigger emergency stop.
    api_client.post("/emergency-stop", json={"actor": "ops", "reason": "test"})

    # 3. New assessment refused.
    r2 = api_client.post(f"/assessments/{juice_shop_target.assessment_id}/start")
    assert r2.status_code in (409, 503)
    assert "EMERGENCY_STOP" in r2.json()["detail"]
```

- [ ] **8.2 运行全套** `py -3.12 -m pytest -q`（应仍 1158+ passed，新增测试全绿）。

- [ ] **8.3 质量门禁**：
  - `ruff check .` 绿
  - `mypy src/secopent` 绿
  - `bandit -r src/secopent -ll` 绿
  - 覆盖率不退化（`pytest --cov=src --cov-fail-under=80`）

- [ ] **8.4 提交** `git commit -m "test(integration): end-to-end auth chain + emergency stop (W2-A T8)"`。

- [ ] **8.5 架构文档** 更新 `docs/architecture/core-boundaries.md` 或新建 `docs/architecture/security-wiring.md`，记录授权链接线点 + composition root 清单。

---

## Self-Review

**Spec coverage**：
- C2 Permit 接线 → Task 3（签发）+ Task 4（验证）+ Task 5（nonce）✓
- C3 EmergencyStop → Task 1（真实 revoker）+ Task 2（入口门禁）+ Task 8（E2E）✓
- H1 M5 hardening 装配 → Task 6（composition root）+ Task 7（PIG/EgressGuard）✓
- ScopeEnforcer 第10步真实化 → Task 4.3 ✓

**Placeholder 扫描**：无 TBD/TODO。Task 6.3 对 `AuditSigner` / `signing_keys.ed25519_private()` 路径标注"以现有 API 为准"并给降级方案（独立密钥对 + ADR），非占位符。Task 8.1 的 `api_client`/`juice_shop_target` fixture 引用现有 `tests/integration/conftest.py` 模式。

**Type 一致性**：
- `execute_assessment` 新增参数：`emergency_stop`、`permit_signer`、`permit_verifier`、`audit_chain`、`scope_enforcer`、`egress_guard`、`prompt_injection_guard`（均 Optional，默认 None 保持向后兼容）✓
- `InMemoryPermitRevoker` 实现 `PermitRevoker` Protocol（`revoke_unused` 签名匹配）✓
- `PermitSigner.issue(permit) -> ExecutionPermit`、`PermitVerifier.verify(permit, *, now, used_nonces, expected_worker) -> None` 与 Task 3/4 调用一致 ✓

**风险**：
- `execute_assessment` 签名扩展影响调用方（`start_assessment` 路由 + 现有测试 + scripts）。所有新参数默认 None，现有测试不传则走旧路径（向后兼容）。
- `DockerContainerTerminator` 在无 Docker 环境（Windows dev）会失败；测试用 `NullContainerTerminator`（Task 2.1 注释），生产用真实实现。
- AuditChain 内存链不跨进程；后台执行线程与请求线程的 AuditChain 实例需通过 `app.state` 共享同一实例（Task 6 已确保）。

---

## Execution Handoff

1. **Subagent-Driven（推荐）**：每个 Task 派 fresh subagent，task 间复审
2. **Inline Execution**：在本会话内逐 task 执行

确认后即可开工。Plan B（沙箱）和 Plan C（密钥+canary）待本计划 DoD 通过后立项。
