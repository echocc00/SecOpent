# W3-C: AuditChain 落库（H6） -- Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 持久化签名审计链到 DB，使防篡改证据跨进程重启存活（H6）。当前 `AuditChain._events` 纯内存，重启即失--签名哈希链的 tamper-evidence 蒸发。

**Architecture:** AuditChain（application）通过 `SignedAuditEventStore` port（Optional）持久化：`__init__` 时若提供 store 则 `load_all()` 重建 `_events`/`_tail`/`_counter`/`_redactions`；`record()` 时若提供 store 则 `append(signed)`。SqlAlchemy 实现（infrastructure）用新 `core_signed_audit_events` 表（AuditEvent 字段 + `signature` + autoincrement `seq` 保序）。composition root 把 `Database` 包成 store 注入 AuditChain。同 W2-A/W3-A 的 Optional 注入模式，向后兼容（store=None -> 纯内存，测试用）。

**Tech Stack:** Python 3.12、SQLAlchemy 2.x、`py -3.12 -m pytest`、ruff/mypy strict/bandit -ll、coverage ≥80%。

---

## 现状

- `application/audit_chain.py::AuditChain`：`_events: list[SignedAuditEvent]` 纯内存；`record()` 签名后 append；`verify()` 校验链+签名；`permit_nonces()`/`export()`/`redact_pii()` 读 `_events`。
- `SignedAuditEvent = AuditEvent + signature: str`。
- `CoreAuditEvent` ORM（`core_audit_events` 表）：AuditService 的可查询日志，**无 signature 列**--是 M0 哈希链，非签名链。H6 不动它（服务不同：可查询 vs 防篡改）。
- AuditChain 在 composition root `AuditChain(AuditKeyManager())` 构造，无 store。

## File Structure

- 新增 `src/secopent/application/ports/audit_chain.py` -- `SignedAuditEventStore` Protocol
- 新增 `src/secopent/infrastructure/db/signed_audit_models.py` -- `CoreSignedAuditEvent` ORM
- 新增 `src/secopent/infrastructure/repositories/sqlalchemy_audit_chain.py` -- `SqlAlchemySignedAuditEventStore`
- 改 `src/secopent/application/audit_chain.py` -- Optional store 注入 + load/append + redactions 重派生
- 改 `src/secopent/infrastructure/db/session.py` -- 注册 signed_audit_models
- 改 `src/secopent/interfaces/api/main.py` -- composition root 注入 store
- 新增 `tests/application/test_audit_chain_persistence.py`
- 新增 `tests/infrastructure/test_signed_audit_store.py`

## Task T1: SignedAuditEventStore port + AuditChain load/append

### T1.1 写失败测试
新建 `tests/application/test_audit_chain_persistence.py`：用 fake store 测 `__init__` load + `record` append + verify 跨实例存活 + redactions 重派生。

```python
from __future__ import annotations
from secopent.application.audit_chain import AuditChain, SignedAuditEvent
from secopent.application.ports.audit_chain import SignedAuditEventStore
from secopent.infrastructure.audit.key_manager import AuditKeyManager


class _FakeStore:
    def __init__(self) -> None:
        self.rows: list[SignedAuditEvent] = []
    def append(self, signed: SignedAuditEvent) -> None:
        self.rows.append(signed)
    def load_all(self) -> tuple[SignedAuditEvent, ...]:
        return tuple(self.rows)


def test_init_loads_existing_events_from_store() -> None:
    store = _FakeStore()
    chain1 = AuditChain(AuditKeyManager(), store=store)
    chain1.record(actor="a", action="x", resource_type="r", resource_id="1", payload={})
    chain1.record(actor="a", action="y", resource_type="r", resource_id="2", payload={})
    assert len(store.rows) == 2

    # New chain over the same store sees the prior events.
    chain2 = AuditChain(AuditKeyManager(), store=store)
    assert len(chain2.events()) == 2
    assert chain2.verify() is True
    assert {e.action for e in chain2.events()} == {"x", "y"}


def test_record_appends_to_store() -> None:
    store = _FakeStore()
    chain = AuditChain(AuditKeyManager(), store=store)
    chain.record(actor="a", action="x", resource_type="r", resource_id="1", payload={})
    assert len(store.rows) == 1
    assert store.rows[0].event.action == "x"
    assert store.rows[0].signature  # non-empty


def test_counter_continues_after_load() -> None:
    store = _FakeStore()
    chain1 = AuditChain(AuditKeyManager(), store=store)
    chain1.record(actor="a", action="x", resource_type="r", resource_id="1", payload={})
    chain2 = AuditChain(AuditKeyManager(), store=store)
    signed = chain2.record(actor="a", action="y", resource_type="r", resource_id="2", payload={})
    # Counter continues from loaded length (evt-2, not evt-1).
    assert signed.event.id == "evt-2"
    assert chain2.verify() is True


def test_redactions_rederived_on_load() -> None:
    store = _FakeStore()
    chain1 = AuditChain(AuditKeyManager(), store=store)
    signed = chain1.record(
        actor="a", action="scan", resource_type="r", resource_id="1",
        payload={"email": "u@x", "note": "ok"},
    )
    chain1.redact_pii(signed.event.id, keys=frozenset({"email"}))

    chain2 = AuditChain(AuditKeyManager(), store=store)
    exported = chain2.export(redacted=True)
    assert exported[0].payload["email"] == "[REDACTED:gdpr]"
```

### T1.2 运行 RED
`py -3.12 -m pytest tests/application/test_audit_chain_persistence.py -q` -> ModuleNotFoundError（ports.audit_chain 不存在；AuditChain 无 store 参数）。

### T1.3 实现
1. 新建 `src/secopent/application/ports/audit_chain.py`：
```python
from __future__ import annotations
from typing import Protocol, runtime_checkable
from ..audit_chain import SignedAuditEvent


@runtime_checkable
class SignedAuditEventStore(Protocol):
    def append(self, signed: SignedAuditEvent) -> None: ...
    def load_all(self) -> tuple[SignedAuditEvent, ...]: ...
```
2. 改 `audit_chain.py`：`__init__(self, signer, *, store: SignedAuditEventStore | None = None)`。若 store：`load_all()` 重建 `_events`/`_tail`/`_counter`；从 `gdpr.redacted` 事件重派生 `_redactions`。`record()` 末尾 `if self._store: self._store.append(signed)`。

### T1.4 GREEN + gates + 提交
`refactor(audit): AuditChain loads/appends via SignedAuditEventStore port (W3-C T1)`

## Task T2: CoreSignedAuditEvent ORM + 注册

新建 `infrastructure/db/signed_audit_models.py`：`CoreSignedAuditEvent(CoreBase)`（seq autoincrement PK + AuditEvent 字段 + signature）。注册到 `session.py` import 块。测试：表建出来（`create_all` 后 `inspect`）。

`feat(infra): CoreSignedAuditEvent ORM table (W3-C T2)`

## Task T3: SqlAlchemySignedAuditEventStore

新建 `infrastructure/repositories/sqlalchemy_audit_chain.py`：`__init__(database: Database)`；`append` 开 session `add`+commit；`load_all` 开 session `order_by(seq)` 读，datetime naive 重附加 UTC。测试：round-trip（add 几条，load_all 顺序+签名+字段一致）+ 跨 session 存活。

`feat(infra): SqlAlchemySignedAuditEventStore (W3-C T3)`

## Task T4: composition root 注入 store

`main.py` create_app：`app.state.db` 之后构造 `SqlAlchemySignedAuditEventStore(db)`，传给 `AuditChain(AuditKeyManager(), store=store)`。测试：`app.state.audit_chain` 重启后事件存活（create_app + record + 新 create_app 同 engine + 事件在）。

`feat(app): wire signed audit chain store into composition root (W3-C T4)`

## Task T5: E2E + 质量门禁 + 文档

E2E：跨 AuditChain 实例（同 store）链完整性 + permit_nonces 跨重启可查。全量 ruff/mypy/bandit/coverage。docs：`docs/architecture/verification.md` 或 audit 相关文档加 H6 段。

`test(audit): signed chain persistence E2E + docs + quality gate (W3-C T5)`

---

## Self-Review

- **Spec coverage**：签名链跨重启存活（H6）。✓
- **向后兼容**：store Optional，默认 None 纯内存（现有测试不变）。✓
- **DDD 边界**：AuditChain 依赖 `SignedAuditEventStore` port，不导入 infrastructure。✓
- **顺序保证**：ORM `seq` autoincrement，`load_all` order_by seq。✓
- **redactions**：从 `gdpr.redacted` 事件重派生，跨重启 export 仍脱敏。✓
- **已知局限**：`append` 每事件开一个 session（高频审计有开销）；批量是后续优化。redact_pii 的 `_redactions` 重派生依赖事件 payload 结构。
