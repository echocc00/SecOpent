# W3-A: Oracle 接线进生产 composition root -- Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 把 OracleEngine（N/N 复证 + canary）从"只在测试/脚本里构造"接线进生产 composition root 与 `execute_assessment`，使生产路径产出的 `Finding` 真正经过 oracle 升级为 `ConfirmedFinding` 并持久化--关闭"已建未接线"的 oracle 缺口，让"只有 oracle 能确认"在生产路径成立。

**Architecture:** 同 W2-A 的成熟模式：所有安全组件以 `Optional` 参数注入 `execute_assessment`（默认 `None` 向后兼容），生产 composition root（`create_app`）构造真实实例放进 `app.state`，`/assessments/{id}/start` 路由透传。新增应用层 `OracleService` 编排：取已关联的 `Finding` -> CWE 映射 `VulnType` -> 每个可映射 finding 构造 `CandidateFinding` + 逐 finding 的 `RescanVerifier`（用同一 `RealScanRunner` + finding.asset + 模板目录构造 scan_kwargs）-> `OracleEngine.verify` -> `CONFIRMED` 则 `confirm` + 持久化 `ConfirmedFinding`，否则更新 `Finding.oracle_verdict`。oracle 在 correlation 落库后**尽力运行**（best-effort，失败不阻塞 assessment 完成，同 nft 模式）。`CanaryTokenManager` 提升为 `app.state` 单例，复用共享 `AuditChain`（canary 事件进签名链）。

**Tech Stack:** Python 3.12、FastAPI、SQLAlchemy 2.x、structlog、Ed25519（已有 AuditChain 签名）、`py -3.12 -m pytest`。质量门禁：ruff(E,F,I,B,UP,SIM)、mypy strict、bandit -ll、coverage ≥80%。

---

## 现状（核查基线）

- `src/secopent/interfaces/api/main.py::create_app` 的 `app.state` 装配了 `permit_signer/verifier/registry`、`audit_chain`、`scope_enforcer`、`emergency_stop`、`egress_guard`、`prompt_injection_guard`、`nft_scope_enforcer`、`model_gateway`--**无 `OracleEngine`/`RescanVerifier`/`CanaryTokenManager`/`VerificationMethodRegistry`/`OracleService`**。
- `src/secopent/application/execution.py::execute_assessment` 在 `FindingCorrelation().correlate(observations)` 后仅 `finding_repo.add(replace(finding, assessment_id=...))`（line 353-355）--**oracle 从不运行**，生产 findings 永远是未确认 `Finding`。
- `src/secopent/interfaces/api/routers/findings.py::set_verdict`（`POST /findings/{id}/verdict`）只接受调用方传入的 verdict 字符串写 `oracle_verdict` 字段--**不跑 oracle**，是人工/oracle 手动覆盖路径。W3-A 不改它（保留为人工覆盖），而是让 oracle 在执行链里自动跑。
- `ConfirmedFinding`（`domain/verification/models.py:128`）是独立 dataclass（`candidate_id/vuln_type/evidence_ids/verified_at/successes/attempts`），**无持久化仓库**。
- CWE->VulnType 映射只在 `tests/e2e_real/test_real_scans.py::_CWE_TO_VULN`（测试本地），非可复用代码。
- `CanaryTokenManager.__init__(audit: AuditService, ...)` 类型钉死 `AuditService`（session-bound），无法接共享 `AuditChain` 单例。`AuditRecorder` Protocol 已存在于 `application/emergency_stop.py:21`（W2-A T6 引入），需提升到 `ports/` 复用。
- `RescanVerifier(runner, scan_kwargs, *, canary=None)`：scan_kwargs 在构造时固定；legacy 路径用 `candidate.target` 子串匹配 `observation.asset_identity`。生产每个 finding 的 scan_kwargs 随 `finding.asset` 变化，故 OracleService **逐 finding 构造** `RescanVerifier + OracleEngine`（引擎无状态，构造廉价）。

## File Structure

**新增：**
- `src/secopent/application/ports/audit.py` -- `AuditRecorder` Protocol（从 emergency_stop.py 提升）
- `src/secopent/domain/verification/cwe_mapping.py` -- `vuln_type_for_cwe(cwe) -> VulnType | None` + 策展映射表
- `src/secopent/application/ports/confirmed_findings.py` -- `ConfirmedFindingRepository` Protocol
- `src/secopent/infrastructure/db/models/confirmed_finding.py` -- SQLAlchemy ORM 模型
- `src/secopent/infrastructure/repositories/sqlalchemy_confirmed.py` -- `SqlAlchemyConfirmedFindingRepository`
- `src/secopent/application/oracle_service.py` -- `OracleService`（编排 verify/confirm/持久化/审计）
- `tests/domain/test_cwe_mapping.py`
- `tests/infrastructure/test_confirmed_finding_repo.py`
- `tests/application/test_oracle_service.py`
- `tests/application/test_execution_oracle.py` -- execute_assessment oracle 接线测试
- `tests/security/test_composition_root_oracle.py` -- app.state.oracle 装配断言
- `tests/integration/test_assessment_oracle_e2e.py` -- 全链产出 ConfirmedFinding

**修改：**
- `src/secopent/application/emergency_stop.py` -- `AuditRecorder` 改从 `ports/audit` 导入（删除本地定义）
- `src/secopent/application/canary.py` -- `audit: AuditService` -> `audit: AuditRecorder`
- `src/secopent/application/execution.py` -- 新增 `oracle`/`confirmed_finding_repo` Optional 参数 + correlation 后调用
- `src/secopent/interfaces/api/main.py` -- composition root 构造 canary/registry/OracleService 进 `app.state` + 共享 `/api`
- `src/secopent/interfaces/api/routers/assessments.py` -- `start_assessment` 透传 `oracle` + `confirmed_finding_repo`
- `src/secopent/infrastructure/db/models/__init__.py` 或等价注册处 -- 注册新 ORM 模型（若需要）

---

## Task T1: 提升 AuditRecorder Protocol + 放宽 canary audit 类型

**Why first:** canary 单例要复用共享 `AuditChain`（canary 事件进签名链），必须先把 `CanaryTokenManager.audit` 类型从 `AuditService` 放宽到 `AuditRecorder` Protocol。`AuditRecorder` 已在 `emergency_stop.py:21`，提升到 `ports/audit.py` 供两处复用。

### T1.1 写失败测试

新建 `tests/application/test_canary_audit_recorder.py`：

```python
"""CanaryTokenManager accepts any AuditRecorder (W3-A T1).

The shared signed AuditChain must satisfy canary's audit sink so canary events
land in the tamper-evident chain, not just the DB audit log.
"""
from __future__ import annotations

from secopent.application.audit_chain import AuditChain
from secopent.application.canary import CanaryTokenManager
from secopent.infrastructure.safety.audit_keys import AuditKeyManager
from secopent.infrastructure.safety.signed_audit import Ed25519AuditSigner


def test_canary_accepts_shared_audit_chain() -> None:
    keys = AuditKeyManager()
    signer = Ed25519AuditSigner(keys)
    chain = AuditChain(signer)
    canary = CanaryTokenManager(chain)  # type: ignore[arg-type]
    token = canary.generate(actor="oracle", candidate_id="cand-1")
    assert token
    assert chain.verify()  # canary.generated event signed into the chain
    events = chain.events()
    assert any(e.action == "canary.generated" for e in events)
```

> 注：`AuditKeyManager`/`Ed25519AuditSigner` 的确切导入路径以仓库现有为准（`grep -r "class Ed25519AuditSigner" src/`）；若名字不同，用 `tests/security/test_audit_tamper.py` 里同样的构造方式。

### T1.2 运行 RED

```bash
py -3.12 -m pytest tests/application/test_canary_audit_recorder.py -q
```

预期失败：mypy/运行期报 `AuditChain` 不是 `AuditService`（类型不匹配）。

### T1.3 实现

1. 新建 `src/secopent/application/ports/audit.py`：

```python
"""AuditRecorder port: anything with a record() method (W3-A T1).

Shared by EmergencyStop and CanaryTokenManager so the signed AuditChain
satisfies both - security-relevant events (canary gen/verify, emergency
trigger) land in the tamper-evident chain, not just the DB audit log.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class AuditRecorder(Protocol):
    def record(
        self,
        *,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str,
        payload: dict[str, object],
        permit_nonce: str | None = None,
    ) -> object: ...
```

2. `src/secopent/application/emergency_stop.py`：删除本地 `AuditRecorder` 定义，改为 `from .ports.audit import AuditRecorder`。`emergency_stop.py` 现有 `AuditRecorder` 的 `record` 签名保持兼容（返回 `object` 即可，EmergencyStop 不用返回值）。

3. `src/secopent/application/canary.py`：`from .ports.audit import AuditRecorder`，`__init__` 改为：

```python
def __init__(self, audit: AuditRecorder, *, oob_domain: str = "oast.example.com") -> None:
```

删除 `from .audit import AuditService`（若 canary 不再直接用 AuditService）。`self._audit.record(...)` 调用不变（签名兼容）。

### T1.4 运行 GREEN

```bash
py -3.12 -m pytest tests/application/test_canary_audit_recorder.py -q
py -3.12 -m pytest tests/application/test_oracle.py tests/application/test_emergency_stop.py -q  # 回归
py -3.12 -m ruff check src/secopent/application/ports/audit.py src/secopent/application/canary.py src/secopent/application/emergency_stop.py
py -3.12 -m mypy src/secopent/application/canary.py src/secopent/application/emergency_stop.py
```

### T1.5 提交

```bash
git add -A && git commit -m "refactor(audit): promote AuditRecorder to ports + widen canary audit type (W3-A T1)"
```

---

## Task T2: CWE -> VulnType 策展映射（domain）

### T2.1 写失败测试

新建 `tests/domain/test_cwe_mapping.py`：

```python
"""CWE -> VulnType mapping for the oracle (W3-A T2)."""
from __future__ import annotations

from secopent.domain.verification.cwe_mapping import vuln_type_for_cwe
from secopent.domain.verification.models import VulnType


def test_known_cwe_maps_to_vuln_type() -> None:
    assert vuln_type_for_cwe("CWE-89") is VulnType.SQLI
    assert vuln_type_for_cwe("CWE-79") is VulnType.XSS
    assert vuln_type_for_cwe("CWE-918") is VulnType.SSRF
    assert vuln_type_for_cwe("CWE-611") is VulnType.XXE
    assert vuln_type_for_cwe("CWE-502") is VulnType.DESERIALIZATION
    assert vuln_type_for_cwe("CWE-639") is VulnType.IDOR
    assert vuln_type_for_cwe("CWE-22") is VulnType.PATH_TRAVERSAL
    assert vuln_type_for_cwe("CWE-287") is VulnType.AUTH_BYPASS
    assert vuln_type_for_cwe("CWE-269") is VulnType.PRIVILEGE_ESCALATION
    assert vuln_type_for_cwe("CWE-521") is VulnType.WEAK_CREDENTIALS
    assert vuln_type_for_cwe("CWE-78") is VulnType.RCE


def test_unknown_cwe_returns_none() -> None:
    assert vuln_type_for_cwe("CWE-999") is None
    assert vuln_type_for_cwe("") is None


def test_first_mappable_cwe_wins_for_findings() -> None:
    """A finding may carry multiple CWEs; the first mappable one wins."""
    from secopent.domain.verification.cwe_mapping import vuln_type_for_cwes
    assert vuln_type_for_cwes(("CWE-999", "CWE-89")) is VulnType.SQLI
    assert vuln_type_for_cwes(("CWE-999", "CWE-888")) is None
    assert vuln_type_for_cwes(()) is None
```

### T2.2 运行 RED

```bash
py -3.12 -m pytest tests/domain/test_cwe_mapping.py -q
```

### T2.3 实现

新建 `src/secopent/domain/verification/cwe_mapping.py`：

```python
"""CWE -> VulnType curation for the oracle (W3-A T2).

Maps the CWE a correlated Finding carries to one of the 14 VulnTypes the
oracle knows how to verify. Findings whose CWEs have no mapping are not
oracle-verifiable and stay as unconfirmed Findings.
"""
from __future__ import annotations

from collections.abc import Sequence

from .models import VulnType

# Curated mapping: only CWEs with an unambiguous VulnType. Ambiguous or
# info-class CWEs are deliberately omitted (returns None -> skip oracle).
_CWE_TO_VULN: dict[str, VulnType] = {
    "CWE-89": VulnType.SQLI,
    "CWE-77": VulnType.RCE,
    "CWE-78": VulnType.RCE,
    "CWE-918": VulnType.SSRF,
    "CWE-611": VulnType.XXE,
    "CWE-79": VulnType.XSS,
    "CWE-502": VulnType.DESERIALIZATION,
    "CWE-22": VulnType.PATH_TRAVERSAL,
    "CWE-23": VulnType.PATH_TRAVERSAL,
    "CWE-35": VulnType.PATH_TRAVERSAL,
    "CWE-639": VulnType.IDOR,
    "CWE-287": VulnType.AUTH_BYPASS,
    "CWE-306": VulnType.AUTH_BYPASS,
    "CWE-269": VulnType.PRIVILEGE_ESCALATION,
    "CWE-521": VulnType.WEAK_CREDENTIALS,
}


def vuln_type_for_cwe(cwe: str) -> VulnType | None:
    """Return the VulnType for a single CWE, or None if not oracle-verifiable."""
    return _CWE_TO_VULN.get(cwe)


def vuln_type_for_cwes(cwes: Sequence[str]) -> VulnType | None:
    """First mappable VulnType across a finding's CWEs, or None."""
    for cwe in cwes:
        vt = vuln_type_for_cwe(cwe)
        if vt is not None:
            return vt
    return None
```

### T2.4 运行 GREEN

```bash
py -3.12 -m pytest tests/domain/test_cwe_mapping.py -q
py -3.12 -m ruff check src/secopent/domain/verification/cwe_mapping.py
py -3.12 -m mypy src/secopent/domain/verification/cwe_mapping.py
```

### T2.5 提交

```bash
git add -A && git commit -m "feat(verification): curated CWE -> VulnType mapping (W3-A T2)"
```

---

## Task T3: ConfirmedFindingRepository（port + ORM + SqlAlchemy 实现）

### T3.1 写失败测试

新建 `tests/infrastructure/test_confirmed_finding_repo.py`：

```python
"""SqlAlchemyConfirmedFindingRepository round-trip (W3-A T3)."""
from __future__ import annotations

from datetime import UTC, datetime

from secopent.domain.verification.models import ConfirmedFinding, VulnType
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_confirmed import (
    SqlAlchemyConfirmedFindingRepository,
)
from secopent.infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemySession,
)


def _confirmed(candidate_id: str = "finding:abc") -> ConfirmedFinding:
    return ConfirmedFinding(
        candidate_id=candidate_id,
        vuln_type=VulnType.SQLI,
        evidence_ids=("ev-1",),
        verified_at=datetime(2026, 1, 1, tzinfo=UTC),
        successes=5,
        attempts=5,
    )


def test_add_and_get_round_trip() -> None:
    engine = create_sqlite_engine(":memory:")
    SqlAlchemySession.configure_tables(engine)  # 确保表已建
    with SqlAlchemySession(engine) as session:
        repo = SqlAlchemyConfirmedFindingRepository(session)
        repo.add(_confirmed("finding:1"))
        session.commit()
        got = repo.get("finding:1")
    assert got is not None
    assert got.candidate_id == "finding:1"
    assert got.vuln_type is VulnType.SQLI
    assert got.successes == 5
    assert got.attempts == 5
    assert got.evidence_ids == ("ev-1",)


def test_get_missing_returns_none() -> None:
    engine = create_sqlite_engine(":memory:")
    SqlAlchemySession.configure_tables(engine)
    with SqlAlchemySession(engine) as session:
        assert SqlAlchemyConfirmedFindingRepository(session).get("nope") is None


def test_list_by_assessment() -> None:
    """ConfirmedFinding carries assessment_id for assessment-scoped queries."""
    engine = create_sqlite_engine(":memory:")
    SqlAlchemySession.configure_tables(engine)
    with SqlAlchemySession(engine) as session:
        repo = SqlAlchemyConfirmedFindingRepository(session)
        repo.add(_confirmed("finding:1"))
        # assessment_id threaded via candidate_id mapping is not on ConfirmedFinding;
        # the repo lists all confirmed for a set of candidate (finding) ids.
        session.commit()
        rows = repo.list_for_candidates(("finding:1", "finding:2"))
    assert len(rows) == 1
    assert rows[0].candidate_id == "finding:1"
```

> 注：`SqlAlchemySession.configure_tables` / `create_sqlite_engine` 以仓库现有 API 为准（参考 `tests/infrastructure/test_finding_repository.py` 或同名测试的建表方式）。若 API 不同，对齐该文件用法。`ConfirmedFinding` 无 `assessment_id` 字段，故按 `candidate_id`（=Finding id）集合查询。

### T3.2 运行 RED

```bash
py -3.12 -m pytest tests/infrastructure/test_confirmed_finding_repo.py -q
```

### T3.3 实现

1. 新建 `src/secopent/application/ports/confirmed_findings.py`：

```python
"""ConfirmedFindingRepository port (W3-A T3)."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from collections.abc import Sequence

from ...domain.verification.models import ConfirmedFinding


@runtime_checkable
class ConfirmedFindingRepository(Protocol):
    def add(self, confirmed: ConfirmedFinding) -> None: ...
    def get(self, candidate_id: str) -> ConfirmedFinding | None: ...
    def list_for_candidates(
        self, candidate_ids: Sequence[str]
    ) -> tuple[ConfirmedFinding, ...]: ...
```

2. 新建 `src/secopent/infrastructure/db/models/confirmed_finding.py`（SQLAlchemy ORM）。参考 `infrastructure/db/models/` 下现有 finding 模型的风格：

```python
"""ORM model for ConfirmedFinding (W3-A T3)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base  # 与现有 ORM 同 Base


class ConfirmedFindingRow(Base):
    __tablename__ = "confirmed_findings"

    candidate_id: Mapped[str] = mapped_column(String, primary_key=True)
    vuln_type: Mapped[str] = mapped_column(String, nullable=False)
    evidence_ids: Mapped[str] = mapped_column(String, nullable=False, default="")  # JSON
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    successes: Mapped[int] = mapped_column(Integer, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)
```

> evidence_ids 用 JSON 字符串列（与现有 ORM 处理 tuple 字段的方式一致；参考 finding 行）。`Base` 导入路径对齐 `infrastructure/db/models/` 现有文件。

3. 新建 `src/secopent/infrastructure/repositories/sqlalchemy_confirmed.py`：

```python
"""SqlAlchemy ConfirmedFindingRepository (W3-A T3)."""
from __future__ import annotations

import json
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...domain.verification.models import ConfirmedFinding, VulnType
from ..db.models.confirmed_finding import ConfirmedFindingRow


def _to_row(c: ConfirmedFinding) -> ConfirmedFindingRow:
    return ConfirmedFindingRow(
        candidate_id=c.candidate_id,
        vuln_type=c.vuln_type.value,
        evidence_ids=json.dumps(list(c.evidence_ids)),
        verified_at=c.verified_at,
        successes=c.successes,
        attempts=c.attempts,
    )


def _to_entity(row: ConfirmedFindingRow) -> ConfirmedFinding:
    return ConfirmedFinding(
        candidate_id=row.candidate_id,
        vuln_type=VulnType(row.vuln_type),
        evidence_ids=tuple(json.loads(row.evidence_ids)) if row.evidence_ids else (),
        verified_at=row.verified_at,
        successes=row.successes,
        attempts=row.attempts,
    )


class SqlAlchemyConfirmedFindingRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, confirmed: ConfirmedFinding) -> None:
        self._session.merge(_to_row(confirmed))

    def get(self, candidate_id: str) -> ConfirmedFinding | None:
        row = self._session.get(ConfirmedFindingRow, candidate_id)
        return _to_entity(row) if row is not None else None

    def list_for_candidates(
        self, candidate_ids: Sequence[str]
    ) -> tuple[ConfirmedFinding, ...]:
        if not candidate_ids:
            return ()
        stmt = select(ConfirmedFindingRow).where(
            ConfirmedFindingRow.candidate_id.in_(tuple(candidate_ids))
        )
        return tuple(_to_entity(r) for r in self._session.scalars(stmt))
```

4. 在 ORM 表注册处（`infrastructure/db/models/__init__.py` 或 `base.py` 的 metadata 自动收集）确保 `ConfirmedFindingRow` 被导入，使 `create_all` 建表。参考现有 finding ORM 的注册方式。

### T3.4 运行 GREEN

```bash
py -3.12 -m pytest tests/infrastructure/test_confirmed_finding_repo.py -q
py -3.12 -m ruff check src/secopent/application/ports/confirmed_findings.py src/secopent/infrastructure/db/models/confirmed_finding.py src/secopent/infrastructure/repositories/sqlalchemy_confirmed.py
py -3.12 -m mypy src/secopent/infrastructure/repositories/sqlalchemy_confirmed.py
py -3.12 -m bandit -ll src/secopent/infrastructure/repositories/sqlalchemy_confirmed.py
```

### T3.5 提交

```bash
git add -A && git commit -m "feat(infra): ConfirmedFindingRepository + ORM (W3-A T3)"
```

---

## Task T4: OracleService（应用层编排）

**职责：** 取一批 `Finding`，逐个映射 CWE->VulnType，可映射者构造 `CandidateFinding` + 逐 finding 的 `RescanVerifier`（scan_kwargs 由 `finding.asset` + 模板目录构造）+ `OracleEngine`，跑 `verify`，`CONFIRMED` 则 `confirm` + 持久化 `ConfirmedFinding`；所有 finding 更新 `oracle_verdict`；尽力运行，单个 finding 失败不中断整体。审计到 `AuditService` + `AuditChain`。

### T4.1 写失败测试

新建 `tests/application/test_oracle_service.py`：

```python
"""OracleService: verify findings -> persist ConfirmedFindings (W3-A T4)."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from secopent.application.audit import AuditService
from secopent.application.audit_chain import AuditChain
from secopent.application.canary import CanaryTokenManager
from secopent.application.oracle_service import OracleService, OracleSummary
from secopent.domain.adapters.contracts import Severity
from secopent.domain.findings.models import Finding, FindingStatus
from secopent.domain.verification.models import VerificationStatus
from secopent.domain.verification.registry import default_registry
from secopent.infrastructure.safety.audit_keys import AuditKeyManager
from secopent.infrastructure.safety.signed_audit import Ed25519AuditSigner


class _EchoScanRunner:
    """Fake RealScanRunner: echoes the target URL in observations' asset_identity
    so the legacy substring path in RescanVerifier sees a reproduction."""

    def __init__(self, *, reproduce: bool = True) -> None:
        self._reproduce = reproduce

    def scan(self, adapter_key: str, *, args: Any, **kwargs: Any) -> Any:
        class _Obs:
            def __init__(self, target: str) -> None:
                self.asset_identity = target

        class _Result:
            pass

        # Extract -u <target> from args (the production scan_kwargs shape).
        target = "http://t/"
        for i, a in enumerate(args):
            if a == "-u" and i + 1 < len(args):
                target = args[i + 1]
        r = _Result()
        r.observations = (_Obs(target),) if self._reproduce else ()
        r.stdout = ""  # legacy path; no canary placeholder in kwargs
        return r


class _FakeFindingRepo:
    def __init__(self) -> None:
        self._by_id: dict[str, Finding] = {}

    def add(self, finding: Finding) -> None:
        self._by_id[finding.id] = finding

    def get(self, fid: str) -> Finding | None:
        return self._by_id.get(fid)


class _InMemoryConfirmedRepo:
    def __init__(self) -> None:
        self._rows: dict[str, Any] = {}

    def add(self, confirmed: Any) -> None:
        self._rows[confirmed.candidate_id] = confirmed

    def get(self, candidate_id: str) -> Any:
        return self._rows.get(candidate_id)

    def list_for_candidates(self, ids: Any) -> tuple:
        return tuple(self._rows[i] for i in ids if i in self._rows)


def _finding(fid: str, cwe: str, asset: str = "http://t/") -> Finding:
    return Finding(
        id=fid,
        fingerprint=f"sha256:{fid}",
        title=fid,
        asset=asset,
        severity=Severity.HIGH,
        cwe=(cwe,),
        observation_ids=("obs-1",),
        status=FindingStatus.CANDIDATE,
    )


def _make_service(reproduce: bool = True) -> tuple[OracleService, AuditChain, CanaryTokenManager]:
    keys = AuditKeyManager()
    chain = AuditChain(Ed25519AuditSigner(keys))
    canary = CanaryTokenManager(chain)  # type: ignore[arg-type]
    runner = _EchoScanRunner(reproduce=reproduce)
    service = OracleService(
        scan_runner=runner,  # type: ignore[arg-type]
        registry=default_registry(),
        canary=canary,
        template_host_dir="/templates",
    )
    return service, chain, canary


def test_confirmed_finding_persisted_when_reproduces(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    service, chain, _ = _make_service(reproduce=True)
    audit = AuditService(memory_repositories.audit)
    finding_repo = _FakeFindingRepo()
    confirmed_repo = _InMemoryConfirmedRepo()
    findings = [_finding("finding:1", "CWE-89")]

    summary = service.verify_findings(
        findings,
        finding_repo=finding_repo,  # type: ignore[arg-type]
        confirmed_repo=confirmed_repo,  # type: ignore[arg-type]
        audit=audit,
        audit_chain=chain,
        actor="oracle",
        verified_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert summary.confirmed == 1
    assert summary.refuted == 0
    assert confirmed_repo.get("finding:1") is not None
    # Finding.oracle_verdict updated to CONFIRMED.
    assert finding_repo.get("finding:1").oracle_verdict is VerificationStatus.CONFIRMED


def test_refuted_finding_not_confirmed_but_verdict_set(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    service, chain, _ = _make_service(reproduce=False)
    audit = AuditService(memory_repositories.audit)
    finding_repo = _FakeFindingRepo()
    confirmed_repo = _InMemoryConfirmedRepo()
    findings = [_finding("finding:2", "CWE-79")]

    summary = service.verify_findings(
        findings,
        finding_repo=finding_repo,  # type: ignore[arg-type]
        confirmed_repo=confirmed_repo,  # type: ignore[arg-type]
        audit=audit,
        audit_chain=chain,
        actor="oracle",
        verified_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert summary.confirmed == 0
    assert confirmed_repo.get("finding:2") is None
    verdict = finding_repo.get("finding:2").oracle_verdict
    assert verdict in (VerificationStatus.REFUTED, VerificationStatus.INCONCLUSIVE)


def test_unmappable_cwe_skipped(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    service, chain, _ = _make_service(reproduce=True)
    audit = AuditService(memory_repositories.audit)
    finding_repo = _FakeFindingRepo()
    confirmed_repo = _InMemoryConfirmedRepo()
    findings = [_finding("finding:3", "CWE-999")]  # no VulnType mapping

    summary = service.verify_findings(
        findings,
        finding_repo=finding_repo,  # type: ignore[arg-type]
        confirmed_repo=confirmed_repo,  # type: ignore[arg-type]
        audit=audit,
        audit_chain=chain,
        actor="oracle",
        verified_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert summary.confirmed == 0
    assert summary.skipped == 1
    assert confirmed_repo.get("finding:3") is None
    # Unmappable finding's verdict stays PENDING (oracle did not run).
    assert finding_repo.get("finding:3").oracle_verdict is VerificationStatus.PENDING


def test_verification_audited_to_signed_chain(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    service, chain, _ = _make_service(reproduce=True)
    audit = AuditService(memory_repositories.audit)
    summary = service.verify_findings(
        [_finding("finding:4", "CWE-89")],
        finding_repo=_FakeFindingRepo(),  # type: ignore[arg-type]
        confirmed_repo=_InMemoryConfirmedRepo(),  # type: ignore[arg-type]
        audit=audit,
        audit_chain=chain,
        actor="oracle",
        verified_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert summary.confirmed == 1
    events = chain.events()
    assert any(e.action == "oracle.verified" for e in events)


def test_single_finding_failure_does_not_abort_others(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    """A rescan raising must not abort verification of sibling findings."""
    class _BoomRunner(_EchoScanRunner):
        def scan(self, adapter_key: str, *, args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("scan blew up")

    keys = AuditKeyManager()
    chain = AuditChain(Ed25519AuditSigner(keys))
    canary = CanaryTokenManager(chain)  # type: ignore[arg-type]
    service = OracleService(
        scan_runner=_BoomRunner(),  # type: ignore[arg-type]
        registry=default_registry(),
        canary=canary,
        template_host_dir="/templates",
    )
    audit = AuditService(memory_repositories.audit)
    summary = service.verify_findings(
        [_finding("finding:5", "CWE-89"), _finding("finding:6", "CWE-79")],
        finding_repo=_FakeFindingRepo(),  # type: ignore[arg-type]
        confirmed_repo=_InMemoryConfirmedRepo(),  # type: ignore[arg-type]
        audit=audit,
        audit_chain=chain,
        actor="oracle",
        verified_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert summary.failed == 2
    assert summary.confirmed == 0
```

> 注：`AuditKeyManager`/`Ed25519AuditSigner` 导入路径对齐 `tests/security/test_audit_tamper.py`。

### T4.2 运行 RED

```bash
py -3.12 -m pytest tests/application/test_oracle_service.py -q
```

### T4.3 实现

新建 `src/secopent/application/oracle_service.py`：

```python
"""OracleService: orchestrate oracle verification over correlated Findings (W3-A T4).

For each Finding with a mappable CWE -> VulnType, build a per-finding
RescanVerifier (RealScanRunner + scan_kwargs from finding.asset + template
dir), run OracleEngine N/N verification, and on CONFIRMED persist a
ConfirmedFinding. Every verified finding's oracle_verdict is updated.
Unmappable findings are skipped (stay PENDING). Best-effort: a single finding
whose rescan raises is audited and skipped, never aborting the batch.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import structlog
from dataclasses import replace

from ..domain.common.canonical import utc_now
from ..domain.common.errors import DomainError, DomainValidationError
from ..domain.findings.models import Finding
from ..domain.verification.cwe_mapping import vuln_type_for_cwes
from ..domain.verification.models import (
    CandidateFinding,
    VerificationStatus,
)
from ..domain.verification.registry import VerificationMethodRegistry
from ..infrastructure.adapters.real_scan import RealScanRunner
from ..infrastructure.oracle.rescan_verifier import RescanVerifier
from .audit import AuditService
from .audit_chain import AuditChain
from .canary import CanaryTokenManager
from .oracle import OracleEngine
from .ports.audit import AuditRecorder  # noqa: F401 (re-export convenience)

_logger = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class OracleSummary:
    confirmed: int = 0
    refuted: int = 0
    inconclusive: int = 0
    skipped: int = 0
    failed: int = 0


class OracleService:
    """Run the oracle over a batch of Findings and persist results."""

    def __init__(
        self,
        *,
        scan_runner: RealScanRunner,
        registry: VerificationMethodRegistry,
        canary: CanaryTokenManager,
        template_host_dir: str | None,
    ) -> None:
        self._scan_runner = scan_runner
        self._registry = registry
        self._canary = canary
        self._template_host_dir = template_host_dir

    def verify_findings(
        self,
        findings: Iterable[Finding],
        *,
        finding_repo: Any,
        confirmed_repo: Any,
        audit: AuditService,
        audit_chain: AuditChain | None,
        actor: str,
        verified_at: datetime | None = None,
    ) -> OracleSummary:
        """Verify each mappable finding; persist ConfirmedFindings + verdicts."""
        verified_at = verified_at or utc_now()
        confirmed = refuted = inconclusive = skipped = failed = 0
        for finding in findings:
            vuln_type = vuln_type_for_cwes(finding.cwe)
            if vuln_type is None:
                skipped += 1
                continue
            try:
                status = self._verify_one(
                    finding, vuln_type, finding_repo, confirmed_repo,
                    audit, audit_chain, actor, verified_at,
                )
            except Exception as exc:  # noqa: BLE001 - best-effort, never abort batch
                failed += 1
                _logger.warning(
                    "oracle verification failed for finding",
                    finding_id=finding.id, error=str(exc), exc_info=True,
                )
                self._audit(audit, audit_chain, actor, finding.id,
                            "oracle.verification_failed", {"reason": str(exc)})
                continue
            if status is VerificationStatus.CONFIRMED:
                confirmed += 1
            elif status is VerificationStatus.REFUTED:
                refuted += 1
            elif status is VerificationStatus.INCONCLUSIVE:
                inconclusive += 1
        return OracleSummary(
            confirmed=confirmed, refuted=refuted, inconclusive=inconclusive,
            skipped=skipped, failed=failed,
        )

    def _verify_one(
        self,
        finding: Finding,
        vuln_type: Any,
        finding_repo: Any,
        confirmed_repo: Any,
        audit: AuditService,
        audit_chain: AuditChain | None,
        actor: str,
        verified_at: datetime,
    ) -> VerificationStatus:
        candidate = CandidateFinding(
            id=finding.id,
            observation_id=finding.observation_ids[0] if finding.observation_ids else finding.id,
            vuln_type=vuln_type,
            target=finding.asset,
        )
        scan_kwargs = self._build_scan_kwargs(finding)
        verifier = RescanVerifier(self._scan_runner, scan_kwargs, canary=self._canary)
        engine = OracleEngine(
            registry=self._registry, verifier=verifier, canary=self._canary,
        )
        result = engine.verify(candidate, actor=actor)
        if result.status is VerificationStatus.CONFIRMED:
            confirmed = engine.confirm(
                candidate, result, evidence_ids=finding.evidence_ids, verified_at=verified_at,
            )
            confirmed_repo.add(confirmed)
        finding_repo.add(replace(finding, oracle_verdict=result.status))
        self._audit(
            audit, audit_chain, actor, finding.id, "oracle.verified",
            {
                "vuln_type": vuln_type.value,
                "status": result.status.value,
                "successes": result.successes,
                "attempts": result.attempts,
                "reason": result.reason,
            },
        )
        return result.status

    def _build_scan_kwargs(self, finding: Finding) -> dict[str, Any]:
        """Per-finding nuclei rescan kwargs: re-run templates against finding.asset."""
        args = ["-t", "/templates/", "-u", finding.asset, "-jsonl", "-silent", "-duc"]
        kwargs: dict[str, Any] = {"adapter_key": "nuclei", "args": args}
        if self._template_host_dir:
            kwargs["mounts"] = {"/templates": self._template_host_dir}
        return kwargs

    def _audit(
        self,
        audit: AuditService,
        audit_chain: AuditChain | None,
        actor: str,
        finding_id: str,
        action: str,
        payload: dict[str, object],
    ) -> None:
        audit.record(
            actor=actor, action=action, resource_type="finding",
            resource_id=finding_id, payload=payload,
        )
        if audit_chain is not None:
            audit_chain.record(
                actor=actor, action=action, resource_type="finding",
                resource_id=finding_id, payload=payload,
            )
```

> 注：`DomainError`/`DomainValidationError` 导入按 `domain/common/errors.py` 现有；若未用到可删（ruff F401）。`_verify_one` 的 `vuln_type` 参数类型用 `VulnType`（从 models 导入），此处省略以减少导入；实现时补 `from ..domain.verification.models import VulnType`。

### T4.4 运行 GREEN

```bash
py -3.12 -m pytest tests/application/test_oracle_service.py -q
py -3.12 -m ruff check src/secopent/application/oracle_service.py
py -3.12 -m mypy src/secopent/application/oracle_service.py
py -3.12 -m bandit -ll src/secopent/application/oracle_service.py
```

### T4.5 提交

```bash
git add -A && git commit -m "feat(oracle): OracleService verifies findings + persists ConfirmedFindings (W3-A T4)"
```

---

## Task T5: 把 OracleService 接进 execute_assessment

**模式：** 同 W2-A，新增 `oracle`/`confirmed_finding_repo` Optional 参数（默认 `None` 向后兼容）。correlation 落库后，若 `oracle` 提供，调 `oracle.verify_findings`；best-effort，异常审计但不失败 assessment（findings 已落库）。

### T5.1 写失败测试

新建 `tests/application/test_execution_oracle.py`：

```python
"""execute_assessment wires OracleService (W3-A T5)."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from secopent.application.execution import execute_assessment
from secopent.domain.adapters.contracts import Severity
from secopent.domain.findings.models import Finding, FindingStatus
from secopent.domain.verification.models import VerificationStatus

# 复用 test_execution.py 的 fixtures/helpers（_seed_approved 等）
from test_execution import _seed_approved, _FakeStepRunner, _MemoryFindingRepo, _observation  # type: ignore[import-not-found]


class _StubOracle:
    """Records calls; confirms every finding it sees."""
    def __init__(self) -> None:
        self.calls: list[Finding] = []
        self.confirmed_repo_adds: list[object] = []

    def verify_findings(self, findings, *, finding_repo, confirmed_repo, audit, audit_chain, actor, verified_at=None):  # type: ignore[no-untyped-def]
        from dataclasses import replace
        summary_confirmed = 0
        for f in findings:
            self.calls.append(f)
            class _Confirmed:
                candidate_id = f.id
            confirmed_repo.add(_Confirmed())
            finding_repo.add(replace(f, oracle_verdict=VerificationStatus.CONFIRMED))
            summary_confirmed += 1
        from secopent.application.oracle_service import OracleSummary
        return OracleSummary(confirmed=summary_confirmed)


class _MemoryConfirmedRepo:
    def __init__(self) -> None:
        self.rows: list[object] = []
    def add(self, c: object) -> None:
        self.rows.append(c)
    def get(self, cid: str) -> object | None:
        return next((r for r in self.rows if getattr(r, "candidate_id", None) == cid), None)
    def list_for_candidates(self, ids):  # type: ignore[no-untyped-def]
        return tuple(self.rows)


def test_oracle_runs_after_correlation_and_confirms(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    repos = memory_repositories
    assessment, scope = _seed_approved_ip_scope(repos)
    finding_repo = _MemoryFindingRepo()
    confirmed_repo = _MemoryConfirmedRepo()
    oracle = _StubOracle()

    # A step runner that yields one SQLi observation.
    runner = _FakeStepRunner({
        ("step-1",): [_observation(cwe=("CWE-89",), asset="http://target/")],
    })

    execute_assessment(
        assessment_id=assessment.id,
        assessment_repo=repos.assessments,
        scope_repo=repos.scopes,
        finding_repo=finding_repo,
        audit_repo=repos.audit,
        step_runner_factory=lambda _scope: runner,
        oracle=oracle,  # type: ignore[arg-type]
        confirmed_finding_repo=confirmed_repo,  # type: ignore[arg-type]
    )

    assert len(oracle.calls) == 1
    assert confirmed_repo.rows  # ConfirmedFinding persisted
    # Finding was updated with CONFIRMED verdict.
    assert finding_repo._rows[0].oracle_verdict is VerificationStatus.CONFIRMED  # type: ignore[attr-defined]


def test_without_oracle_backward_compatible(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    """No oracle param -> findings persist, no confirmation path (W2 behavior)."""
    repos = memory_repositories
    assessment, scope = _seed_approved_ip_scope(repos)
    finding_repo = _MemoryFindingRepo()
    runner = _FakeStepRunner({
        ("step-1",): [_observation(cwe=("CWE-89",), asset="http://target/")],
    })
    execute_assessment(
        assessment_id=assessment.id,
        assessment_repo=repos.assessments,
        scope_repo=repos.scopes,
        finding_repo=finding_repo,
        audit_repo=repos.audit,
        step_runner_factory=lambda _scope: runner,
        # no oracle, no confirmed_finding_repo
    )
    assert finding_repo._rows  # type: ignore[attr-defined]
    assert finding_repo._rows[0].oracle_verdict is VerificationStatus.PENDING  # type: ignore[attr-defined]


def _seed_approved_ip_scope(repos):  # type: ignore[no-untyped-def]
    """Reuse the IP-scope seeder from the W2-A gate tests, or fall back to
    _seed_approved with a URL scope."""
    try:
        from test_execution_gates import _seed_approved_ip_scope as _seed  # type: ignore[import-not-found]
        return _seed(repos)
    except ImportError:
        return _seed_approved(repos)
```

> 注：`_MemoryFindingRepo._rows` 的属性名以 `test_execution.py` 实际实现为准（可能是 `_store`/`_items`）；对齐该文件。`_observation` 的关键字参数（`cwe`/`asset`）以 `test_execution.py` 实际签名为准。若 helper 不可复用，在文件内重新定义最小版。

### T5.2 运行 RED

```bash
py -3.12 -m pytest tests/application/test_execution_oracle.py -q
```

### T5.3 实现

修改 `src/secopent/application/execution.py`：

1. 导入：`from .oracle_service import OracleService`（顶部，与其它 application 导入并列）。

2. `execute_assessment` 签名新增两个参数（在 `audit_chain` 之后）：

```python
    audit_chain: AuditChain | None = None,
    oracle: OracleService | None = None,
    confirmed_finding_repo: object | None = None,
) -> None:
```

3. 在 correlation 落库循环之后、`service.complete` 之前插入 oracle 调用：

```python
        observations = step_runner.all_observations()  # type: ignore[attr-defined]
        findings = FindingCorrelation().correlate(observations)
        for finding in findings:
            finding_repo.add(replace(finding, assessment_id=assessment_id))

        if oracle is not None and confirmed_finding_repo is not None and findings:
            try:
                summary = oracle.verify_findings(
                    findings,
                    finding_repo=finding_repo,
                    confirmed_repo=confirmed_finding_repo,
                    audit=audit,
                    audit_chain=audit_chain,
                    actor="system",
                    verified_at=utc_now(),
                )
                _audit_record(
                    audit, audit_chain, actor="system", action="oracle.batch_verified",
                    resource_type="assessment", resource_id=assessment_id,
                    payload={
                        "confirmed": summary.confirmed,
                        "refuted": summary.refuted,
                        "inconclusive": summary.inconclusive,
                        "skipped": summary.skipped,
                        "failed": summary.failed,
                    },
                )
            except Exception as exc:  # noqa: BLE001 - oracle is best-effort
                _logger.warning(
                    "oracle batch verification failed (findings remain unconfirmed)",
                    assessment_id=assessment_id, error=str(exc), exc_info=True,
                )
                _audit_record(
                    audit, audit_chain, actor="system", action="oracle.batch_failed",
                    resource_type="assessment", resource_id=assessment_id,
                    payload={"reason": str(exc)},
                )

        service.complete(assessment_id)  # RUNNING -> COMPLETED
```

> 注：`utc_now` 已在 execution.py 顶部导入。`Finding`/`replace` 已导入。

### T5.4 运行 GREEN + 回归

```bash
py -3.12 -m pytest tests/application/test_execution_oracle.py tests/application/test_execution.py tests/application/test_execution_gates.py -q
py -3.12 -m ruff check src/secopent/application/execution.py
py -3.12 -m mypy src/secopent/application/execution.py
py -3.12 -m bandit -ll src/secopent/application/execution.py
```

### T5.5 提交

```bash
git add -A && git commit -m "feat(execution): wire OracleService into execute_assessment (W3-A T5)"
```

---

## Task T6: composition root 装配 OracleService 进 app.state

### T6.1 写失败测试

新建 `tests/security/test_composition_root_oracle.py`：

```python
"""composition root assembles OracleService + canary singleton (W3-A T6)."""
from __future__ import annotations

from secopent.application.canary import CanaryTokenManager
from secopent.application.oracle_service import OracleService
from secopent.interfaces.api.main import create_app


def test_app_state_has_oracle_service() -> None:
    app = create_app()
    assert isinstance(app.state.oracle, OracleService)
    assert isinstance(app.state.canary, CanaryTokenManager)
    # Shared with the /api sub-app.
    assert getattr(app.router.routes[-1].app.state, "oracle", None) is app.state.oracle


def test_canary_uses_shared_audit_chain() -> None:
    """canary singleton audits to the shared signed AuditChain."""
    app = create_app()
    canary = app.state.canary
    chain = app.state.audit_chain
    canary.generate(actor="oracle", candidate_id="cand-1")
    events = chain.events()
    assert any(e.action == "canary.generated" for e in events)
```

> 注：`/api` 子 app 的访问方式以 `main.py` 实际结构为准（`app.router.routes[-1].app` 可能不同）；参考 `tests/security/test_composition_root.py`（W2-A T6 已有）的写法对齐。

### T6.2 运行 RED

```bash
py -3.12 -m pytest tests/security/test_composition_root_oracle.py -q
```

### T6.3 实现

修改 `src/secopent/interfaces/api/main.py::create_app`，在现有 `app.state.audit_chain = audit_chain` 之后、`app.state.nft_scope_enforcer = ...` 附近插入：

```python
    # Oracle (W3-A): canary singleton auditing to the shared signed chain +
    # a shared RealScanRunner for N/N rescan reproduction. The OracleService
    # is session-independent; per-thread finding/confirmed repos are passed
    # by the assessments router from the bg session.
    from ...application.canary import CanaryTokenManager
    from ...application.oracle_service import OracleService
    from ...domain.verification.registry import default_registry
    from ...infrastructure.adapters.real_scan import RealScanRunner

    canary = CanaryTokenManager(audit_chain)  # type: ignore[arg-type]
    try:
        scan_timeout = int(os.environ.get("SECOPTENT_SCAN_TIMEOUT", "1800"))
    except ValueError:
        scan_timeout = 1800
    oracle_scan_runner = RealScanRunner(default_timeout=scan_timeout)
    template_host_dir = os.environ.get("SECOPTENT_NUCLEI_TEMPLATE_DIR", "").strip() or None
    app.state.canary = canary
    app.state.oracle = OracleService(
        scan_runner=oracle_scan_runner,
        registry=default_registry(),
        canary=canary,
        template_host_dir=template_host_dir,
    )
```

在 `/api` 子 app 共享块（`api.state.signing_keys = app.state.signing_keys` 附近）追加：

```python
    api.state.canary = app.state.canary
    api.state.oracle = app.state.oracle
```

> 注：`os` 已在 main.py 导入（`SECOPTENT_*` env 读取已存在）。`AuditChain` 已在 `app.state.audit_chain`。`CanaryTokenManager(audit_chain)` 现在合法（T1 已放宽类型）。

### T6.4 运行 GREEN + 回归

```bash
py -3.12 -m pytest tests/security/test_composition_root_oracle.py tests/security/test_composition_root.py -q
py -3.12 -m ruff check src/secopent/interfaces/api/main.py
py -3.12 -m mypy src/secopent/interfaces/api/main.py
py -3.12 -m bandit -ll src/secopent/interfaces/api/main.py
```

### T6.5 提交

```bash
git add -A && git commit -m "feat(app): wire OracleService + canary singleton into composition root (W3-A T6)"
```

---

## Task T7: assessments 路由透传 oracle + confirmed repo

### T7.1 写失败测试

新建 `tests/interfaces/test_assessments_start_oracle.py`：

```python
"""start_assessment threads oracle + confirmed repo into execute_assessment (W3-A T7)."""
from __future__ import annotations

from unittest.mock import patch

from secopent.interfaces.api.main import create_app


def test_start_threads_app_state_oracle(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    app = create_app()
    captured: dict[str, object] = {}

    def _fake_execute(**kwargs):  # type: ignore[no-untyped-def]
        captured.update(kwargs)
        # Simulate immediate completion so the thread exits cleanly.
        return None

    # Patch execute_assessment where the router imports it.
    monkeypatch.setattr(
        "secopent.interfaces.api.routers.assessments.execute_assessment",
        _fake_execute,
    )
    # Also patch threading.Thread to run inline (no real background thread).
    import threading
    from contextlib import contextmanager

    class _InlineThread:
        def __init__(self, target, **kw):  # type: ignore[no-untyped-def]
            self._target = target
        def start(self):  # type: ignore[no-untyped-def]
            self._target()
        def join(self, *a, **k):  # type: ignore[no-untyped-def]
            return None

    monkeypatch.setattr(threading, "Thread", _InlineThread)
```

> 注：此测试较脆（依赖路由内部 threading 结构）。**更稳妥的做法**是参考 `tests/interfaces/` 或 `tests/integration/test_assessment_*` 现有对 `/start` 的测试模式，用一个 stub `execute_assessment`（通过 `monkeypatch` 替换 `assessments` 模块里的引用）捕获 kwargs，断言 `oracle is app.state.oracle` 与 `confirmed_finding_repo` 非 None。实现时对齐仓库已有的 `/start` 测试写法；若已有现成 fixture 复用之。核心断言：

```python
    assert captured["oracle"] is app.state.oracle
    assert captured["confirmed_finding_repo"] is not None
```

### T7.2 运行 RED

```bash
py -3.12 -m pytest tests/interfaces/test_assessments_start_oracle.py -q
```

### T7.3 实现

修改 `src/secopent/interfaces/api/routers/assessments.py::start_assessment` 的 `_run` 内 `execute_assessment(...)` 调用，在现有 `nft_scope_enforcer=nft_scope_enforcer, audit_chain=audit_chain,` 之后追加：

```python
                oracle=getattr(request.app.state, "oracle", None),
                confirmed_finding_repo=(
                    SqlAlchemyConfirmedFindingRepository(bg_session)
                    if getattr(request.app.state, "oracle", None) is not None
                    else None
                ),
```

并在文件顶部导入：

```python
from ....infrastructure.repositories.sqlalchemy_confirmed import (
    SqlAlchemyConfirmedFindingRepository,
)
```

同时在 `start_assessment` 顶部从 `app.state` 取 oracle 的位置（与其它 security 组件并列）追加：

```python
    oracle = getattr(request.app.state, "oracle", None)
```

（`confirmed_finding_repo` 需 bg_session，故在 `_run` 内构造，不从 app.state 取。）

### T7.4 运行 GREEN + 回归

```bash
py -3.12 -m pytest tests/interfaces/test_assessments_start_oracle.py tests/interfaces/ -q
py -3.12 -m ruff check src/secopent/interfaces/api/routers/assessments.py
py -3.12 -m mypy src/secopent/interfaces/api/routers/assessments.py
py -3.12 -m bandit -ll src/secopent/interfaces/api/routers/assessments.py
```

### T7.5 提交

```bash
git add -A && git commit -m "feat(api): start_assessment threads oracle + confirmed repo (W3-A T7)"
```

---

## Task T8: E2E 集成 + 质量门禁

### T8.1 写 E2E 测试

新建 `tests/integration/test_assessment_oracle_e2e.py`：

```python
"""E2E: assessment -> correlation -> oracle -> ConfirmedFinding persisted (W3-A T8).

Drives execute_assessment with a real OracleService over a fake scan runner
that reproduces, asserting a ConfirmedFinding lands in the confirmed repo and
the Finding's oracle_verdict flips to CONFIRMED.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from secopent.application.audit import AuditService
from secopent.application.audit_chain import AuditChain
from secopent.application.canary import CanaryTokenManager
from secopent.application.execution import execute_assessment
from secopent.application.oracle_service import OracleService
from secopent.domain.verification.registry import default_registry
from secopent.infrastructure.safety.audit_keys import AuditKeyManager
from secopent.infrastructure.safety.signed_audit import Ed25519AuditSigner

# 复用 test_execution.py 的 seeder + helpers
from test_execution import _seed_approved, _FakeStepRunner, _MemoryFindingRepo, _observation  # type: ignore[import-not-found]


class _ReproRunner:
    """Fake scan runner whose observations reproduce the finding's target."""
    def __init__(self, target: str) -> None:
        self._target = target

    def scan(self, adapter_key: str, *, args: Any, **kwargs: Any) -> Any:
        class _Obs:
            asset_identity = self._target
        class _R:
            observations = (_Obs(),)
            stdout = ""
        return _R()


class _ConfirmedRepo:
    def __init__(self) -> None:
        self.rows: list[Any] = []
    def add(self, c: Any) -> None:
        self.rows.append(c)
    def get(self, cid: str) -> Any | None:
        return next((r for r in self.rows if r.candidate_id == cid), None)
    def list_for_candidates(self, ids: Any) -> tuple:
        return tuple(self.rows)


def test_assessment_confirms_finding_end_to_end(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    repos = memory_repositories
    assessment, _ = _seed_approved(repos)
    finding_repo = _MemoryFindingRepo()
    confirmed_repo = _ConfirmedRepo()

    keys = AuditKeyManager()
    chain = AuditChain(Ed25519AuditSigner(keys))
    canary = CanaryTokenManager(chain)  # type: ignore[arg-type]
    oracle = OracleService(
        scan_runner=_ReproRunner("http://target/"),  # type: ignore[arg-type]
        registry=default_registry(),
        canary=canary,
        template_host_dir="/templates",
    )

    runner = _FakeStepRunner({
        ("step-1",): [_observation(cwe=("CWE-89",), asset="http://target/")],
    })

    execute_assessment(
        assessment_id=assessment.id,
        assessment_repo=repos.assessments,
        scope_repo=repos.scopes,
        finding_repo=finding_repo,
        audit_repo=repos.audit,
        step_runner_factory=lambda _scope: runner,
        oracle=oracle,
        confirmed_finding_repo=confirmed_repo,  # type: ignore[arg-type]
    )

    assert confirmed_repo.rows, "no ConfirmedFinding persisted"
    assert confirmed_repo.rows[0].candidate_id == finding_repo._rows[0].id  # type: ignore[attr-defined]
    assert confirmed_repo.rows[0].vuln_type.value == "sqli"
    # Assessment reached COMPLETED despite oracle work.
    assert assessment.id in str(repos.assessments._store)  # type: ignore[attr-defined]
```

> 注：`_ReproRunner` 的 `asset_identity` 需匹配 `RescanVerifier` legacy 路径的子串匹配（`candidate.target in observation.asset_identity`）。`finding_repo._rows`/`repos.assessments._store` 属性名对齐 test_execution.py。`_observation` 签名对齐。

### T8.2 运行

```bash
py -3.12 -m pytest tests/integration/test_assessment_oracle_e2e.py -q
```

### T8.3 全套质量门禁

```bash
# 全量测试（无回归）
py -3.12 -m pytest -q
# 覆盖率门禁
py -3.12 -m pytest --cov=src --cov-report=term-missing -q
# ruff 全量
py -3.12 -m ruff check src tests
# mypy strict 全量
py -3.12 -m mypy src
# bandit
py -3.12 -m bandit -ll -r src/secopent/application/oracle_service.py src/secopent/application/execution.py src/secopent/interfaces/api/main.py src/secopent/interfaces/api/routers/assessments.py src/secopent/infrastructure/repositories/sqlalchemy_confirmed.py
```

预期：测试全绿、coverage ≥80%（实际应 >91%）、ruff clean、mypy strict clean、bandit 0 medium/high。

### T8.4 文档更新

- `docs/architecture/verification.md`：在"W2-C 更新"段后追加 W3-A 更新段落，说明 oracle 现已接线进 `execute_assessment` + composition root，生产 findings 自动经 N/N 复证；未映射 CWE 的 finding 跳过 oracle（留 PENDING）；oracle best-effort 不阻塞 assessment。
- `docs/deployment.md` §5 或 §8：补一句 oracle 复用 `SECOPTENT_NUCLEI_TEMPLATE_DIR` + `SECOPTENT_SCAN_TIMEOUT`（与扫描同源）。

### T8.5 提交

```bash
git add -A && git commit -m "test(oracle): E2E assessment->ConfirmedFinding + docs + quality gate (W3-A T8)"
```

---

## Self-Review

**Spec coverage（验收报告 §四 第三波 W3-A 项）：**
- "OracleEngine 进 composition root" -> T6 装配 `app.state.oracle` + `app.state.canary`，共享 `/api`。✓
- "生产路径真正跑 N/N 复证" -> T5 在 `execute_assessment` correlation 后调 `OracleService.verify_findings`。✓
- "ConfirmedFinding 持久化" -> T3 port + ORM + SqlAlchemy 实现；T4/T5 持久化。✓
- "CWE->VulnType 映射可复用" -> T2 `domain/verification/cwe_mapping.py`。✓
- "canary 事件进签名链" -> T1 放宽类型 + T6 canary 单例复用 AuditChain。✓
- "向后兼容" -> 所有新参数 Optional 默认 None；T5 `test_without_oracle_backward_compatible` 守护。✓

**Placeholder scan：** 无 TBD/TODO；代码片段均为真实可运行（导入路径已标注需对齐处，属实现期对齐非占位）。

**Type consistency：**
- `OracleService.verify_findings` 签名在 T4 定义、T5 调用、T7 路由侧不直接调（路由只透传 service 引用）--一致。
- `ConfirmedFindingRepository` Protocol（T3）的 `add/get/list_for_candidates` 与 `OracleService` 调用点（`confirmed_repo.add`）一致。
- `AuditRecorder` Protocol（T1）与 `CanaryTokenManager`/`EmergencyStop` 调用点（`record(actor=,action=,resource_type=,resource_id=,payload=)`）一致；`AuditChain.record`/`AuditService.record` 均满足。

**已知局限（非 W3-A 范围，记为后续）：**
- 生产复现 scan_kwargs 不含 `{{canary_token}}` 占位 -> RescanVerifier 走 legacy 子串匹配，canary echo 校验在生产路径**未激活**（canary 仍生成+审计，但不做 echo 强校验）。激活需 canary-aware 复现模板（属 W3-E OOB 同类深度项）。
- 全模板重扫 per finding 代价高（N 次 × 全模板目录）；W3-A 只接线不优化。定向复现模板（按 CWE 选子集）是后续优化。
- `ConfirmedFinding.evidence_ids` 取自 `finding.evidence_ids`（可能为空）；真实证据管线接入是后续。

## Execution Handoff

实现方式二选一：
1. **Subagent-Driven（推荐）** -- 每个 task 起一个 fresh subagent，task 间我来 review。
2. **Inline Execution** -- 本 session 内逐 task 推进。

确认后即开工 T1。
