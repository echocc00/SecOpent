# M0 地基与确定性脊柱骨架 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立 Domain/Application/Infrastructure 边界，实现 Project、不可变 Scope、Assessment/Plan/Approval、确定性 Policy Engine、SQLite WAL Repository Contract、最小 Audit hash chain，为后续里程碑提供确定性脊柱地基。

**Architecture:** 使用 dataclass Domain（frozen, slots）、Application ports（Protocol）、SQLAlchemy Infrastructure。Digest 使用规范 JSON + SHA-256。Domain 不依赖任何框架（FastAPI/SQLAlchemy/MCP/httpx/Docker 禁止导入）。Audit hash chain（previous_hash + event_hash）M0 起步，Ed25519 签名推 M5。Repository Contract 抽象 M0 起步，SQLite WAL 实现 + PostgreSQL 接口预留。

**Tech Stack:** Python 3.11+, dataclasses, enum.StrEnum, ipaddress, urllib.parse, hashlib, cryptography, SQLAlchemy 2.0, SQLite WAL, pytest, mypy, ruff.

**DoD（对应主设计文档 §13 M0）:**
- scope 硬拒绝（Scope 外 IP/域名/端口/URL 被拒）
- plan 可持久化
- approval 可运行空计划
- Deny 优先于 Allow，Destructive 永拒
- Domain 无框架依赖（test_architecture_boundaries 强制）
- 审计事件可追溯（hash chain）
- Repository 同时支持 SQLite（PG 接口预留，M5 切 PG 不重构）

**参考文档:**
- 主设计：`2026-07-25-catalog-driven-agent-workbench-design.md` §5/§6/§12
- 架构图：`2026-07-25-architecture-detail.md`（Scope 链 + 确定性脊柱）
- ADR：`2026-07-25-decisions.md` ADR-016（Audit M0）/ ADR-017（Repository 抽象 M0）

---

## 0. 文件结构

```text
src/secopent/
  domain/
    __init__.py
    common/
      __init__.py
      canonical.py       # canonical_json, canonical_digest, utc_now
      errors.py          # DomainError, DomainValidationError
    projects/
      __init__.py
      models.py          # Project, ProjectStatus
    scope/
      __init__.py
      models.py          # ScopeDraft, ScopeSnapshot, ScopeLimits
      normalize.py       # normalize_domain/ip_or_network/url/port
    policy/
      __init__.py
      models.py          # RiskClass, ExecutionMode, PolicyDecision, ActionRequest
      engine.py          # evaluate()
    assessments/
      __init__.py
      models.py          # Assessment, ExecutionPlan, PlanStep, Approval, AssessmentStatus
    audit/
      __init__.py
      models.py          # AuditEvent (hash chain)
  application/
    __init__.py
    ports/
      __init__.py
      repositories.py    # Project/Scope/Assessment/Audit Repository Protocols
    projects.py          # ProjectService
    scopes.py            # ScopeService
    assessments.py       # AssessmentService
    audit.py             # AuditService
  infrastructure/
    __init__.py
    db/
      __init__.py
      core_models.py     # CoreBase + ORM 模型
      sqlite.py          # create_sqlite_engine (WAL/foreign_keys/busy_timeout)
    repositories/
      __init__.py
      sqlalchemy_core.py # SqlAlchemy 实现
tests/
  domain/
    test_canonical.py
    test_projects.py
    test_scope.py
    test_normalize.py
    test_policy.py
    test_assessments.py
    test_audit.py
  application/
    test_scope_service.py
    test_assessment_service.py
    test_audit_service.py
  infrastructure/
    test_sqlite_wal.py
    test_core_repository_contract.py
  test_architecture_boundaries.py
pyproject.toml
README.md
docs/architecture/core-boundaries.md
```

M0 不修改 Adapter、Connector、报告模板、Web UI、MCP。M0 不引入 FastAPI、MCP SDK、Docker、httpx。

---

## Task 1: 包边界和依赖守卫

**Files:**
- Create: `src/secopent/domain/__init__.py`
- Create: `src/secopent/application/__init__.py`
- Create: `src/secopent/infrastructure/__init__.py`
- Create: `tests/test_architecture_boundaries.py`

- [ ] **Step 1: 写失败测试**

```python
# tests/test_architecture_boundaries.py
from __future__ import annotations
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "secopent"
FORBIDDEN = {"fastapi", "sqlalchemy", "httpx", "docker", "mcp", "cryptography"}


def test_domain_does_not_import_frameworks() -> None:
    domain = ROOT / "domain"
    assert domain.is_dir(), "domain package is missing"
    violations: list[str] = []
    for path in domain.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [item.name.split(".")[0] for item in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".")[0]]
            for name in names:
                if name in FORBIDDEN:
                    violations.append(f"{path.relative_to(ROOT)} imports {name}")
    assert violations == [], "domain must not import frameworks: " + ", ".join(violations)


def test_application_does_not_import_frameworks() -> None:
    app = ROOT / "application"
    assert app.is_dir(), "application package is missing"
    violations: list[str] = []
    for path in app.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [item.name.split(".")[0] for item in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".")[0]]
            for name in names:
                if name in FORBIDDEN:
                    violations.append(f"{path.relative_to(ROOT)} imports {name}")
    assert violations == [], "application must not import frameworks: " + ", ".join(violations)
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/test_architecture_boundaries.py`

Expected: FAIL，`domain package is missing`。

- [ ] **Step 3: 创建最小包**

```python
# src/secopent/domain/__init__.py
"""Framework-independent domain model for SecOpent."""

# src/secopent/application/__init__.py
"""Application use cases and ports."""

# src/secopent/infrastructure/__init__.py
"""Infrastructure adapters for application ports."""
```

创建文件结构中所有目录的 `__init__.py`（domain/common、domain/projects、domain/scope、domain/policy、domain/assessments、domain/audit、application/ports、infrastructure/db、infrastructure/repositories）。

- [ ] **Step 4: 运行 GREEN**

Run: `py -3.12 -m pytest -q tests/test_architecture_boundaries.py`

Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/domain src/secopent/application src/secopent/infrastructure tests/test_architecture_boundaries.py
git commit -m "refactor(core): establish domain application infrastructure boundaries"
```

---

## Task 2: 规范 JSON、Digest 和 Domain Error

**Files:**
- Create: `src/secopent/domain/common/canonical.py`
- Create: `src/secopent/domain/common/errors.py`
- Test: `tests/domain/test_canonical.py`

- [ ] **Step 1: 写失败测试**

```python
# tests/domain/test_canonical.py
from __future__ import annotations
from datetime import datetime
import pytest
from secopent.domain.common.canonical import canonical_digest, canonical_json, utc_now
from secopent.domain.common.errors import DomainValidationError


def test_digest_ignores_dict_insertion_order() -> None:
    left = {"b": [2, 1], "a": "é"}
    right = {"a": "é", "b": [2, 1]}
    assert canonical_json(left) == '{"a":"é","b":[2,1]}'
    assert canonical_digest(left) == canonical_digest(right)


def test_rejects_naive_datetime() -> None:
    with pytest.raises(DomainValidationError, match="timezone-aware"):
        canonical_json({"at": datetime(2026, 7, 25)})


def test_utc_now_is_aware() -> None:
    assert utc_now().tzinfo is not None


def test_digest_prefix() -> None:
    assert canonical_digest({"x": 1}).startswith("sha256:")
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/domain/test_canonical.py`

Expected: import FAIL。

- [ ] **Step 3: 实现**

```python
# src/secopent/domain/common/errors.py
from __future__ import annotations


class DomainError(Exception):
    """Base deterministic domain error."""


class DomainValidationError(DomainError, ValueError):
    """Input cannot be normalized safely."""
```

```python
# src/secopent/domain/common/canonical.py
from __future__ import annotations
import hashlib
import json
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from .errors import DomainValidationError


def utc_now() -> datetime:
    return datetime.now(UTC)


def _default(value: object) -> object:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise DomainValidationError("datetime must be timezone-aware")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, (tuple, list)):
        return list(value)
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    raise DomainValidationError(f"unsupported canonical value: {type(value).__name__}")


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        default=_default,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def canonical_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
```

- [ ] **Step 4: 运行 GREEN**

Run: `py -3.12 -m pytest -q tests/domain/test_canonical.py`

Expected: 4 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/domain/common tests/domain/test_canonical.py
git commit -m "feat(core): add canonical domain digests"
```

---

## Task 3: Project Domain

**Files:**
- Create: `src/secopent/domain/projects/models.py`
- Test: `tests/domain/test_projects.py`

- [ ] **Step 1: 写失败测试**

```python
# tests/domain/test_projects.py
from __future__ import annotations
import pytest
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.projects.models import Project, ProjectStatus


def test_project_create_normalizes_name() -> None:
    project = Project.create(project_id="project-1", name="  Lab Assessment  ")
    assert project.name == "Lab Assessment"
    assert project.status is ProjectStatus.ACTIVE
    assert project.created_at.tzinfo is not None


def test_project_rejects_empty_name() -> None:
    with pytest.raises(DomainValidationError, match="name"):
        Project.create(project_id="project-1", name="   ")


def test_project_rejects_empty_id() -> None:
    with pytest.raises(DomainValidationError, match="id"):
        Project.create(project_id="  ", name="Lab")


def test_project_status_values() -> None:
    assert ProjectStatus.ACTIVE.value == "active"
    assert ProjectStatus.ARCHIVED.value == "archived"
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/domain/test_projects.py`

Expected: import FAIL。

- [ ] **Step 3: 实现**

```python
# src/secopent/domain/projects/models.py
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from ..common.canonical import utc_now
from ..common.errors import DomainValidationError


class ProjectStatus(StrEnum):
    ACTIVE = "active"
    ARCHIVED = "archived"


@dataclass(frozen=True, slots=True)
class Project:
    id: str
    name: str
    status: ProjectStatus
    created_at: datetime

    @classmethod
    def create(cls, *, project_id: str, name: str) -> Project:
        normalized_id = project_id.strip()
        normalized_name = name.strip()
        if not normalized_id:
            raise DomainValidationError("project id must not be empty")
        if not normalized_name:
            raise DomainValidationError("project name must not be empty")
        return cls(normalized_id, normalized_name, ProjectStatus.ACTIVE, utc_now())
```

- [ ] **Step 4: 运行 GREEN**

Run: `py -3.12 -m pytest -q tests/domain/test_projects.py`

Expected: 4 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/domain/projects tests/domain/test_projects.py
git commit -m "feat(core): add project domain"
```

---

## Task 4: Scope 规范化

**Files:**
- Create: `src/secopent/domain/scope/normalize.py`
- Test: `tests/domain/test_normalize.py`

- [ ] **Step 1: 写失败测试**

```python
# tests/domain/test_normalize.py
from __future__ import annotations
import pytest
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.scope.normalize import (
    normalize_domain,
    normalize_ip_or_network,
    normalize_port,
    normalize_url,
)


def test_normalize_domain_lowercases_and_strips_dot() -> None:
    assert normalize_domain("Example.Test.") == "example.test"


def test_normalize_domain_wildcard() -> None:
    assert normalize_domain("*.Example.Test") == "*.example.test"


def test_normalize_domain_rejects_empty_label() -> None:
    with pytest.raises(DomainValidationError):
        normalize_domain("example..test")


def test_normalize_ip_or_network() -> None:
    assert normalize_ip_or_network("192.0.2.1") == "192.0.2.1"
    assert normalize_ip_or_network("192.0.2.0/28") == "192.0.2.0/28"


def test_normalize_ip_rejects_invalid() -> None:
    with pytest.raises(DomainValidationError):
        normalize_ip_or_network("999.999.999.999")


def test_normalize_url_default_port_dropped() -> None:
    assert normalize_url("HTTPS://Example.Test:443/api/") == "https://example.test/api/"


def test_normalize_url_rejects_non_http() -> None:
    with pytest.raises(DomainValidationError):
        normalize_url("ftp://example.test")


def test_normalize_port_range() -> None:
    assert normalize_port(443) == 443
    with pytest.raises(DomainValidationError):
        normalize_port(0)
    with pytest.raises(DomainValidationError):
        normalize_port(70000)
    with pytest.raises(DomainValidationError):
        normalize_port(True)  # type: ignore[arg-type]
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/domain/test_normalize.py`

Expected: import FAIL。

- [ ] **Step 3: 实现**

```python
# src/secopent/domain/scope/normalize.py
from __future__ import annotations
import ipaddress
import posixpath
from urllib.parse import SplitResult, urlsplit, urlunsplit
from ..common.errors import DomainValidationError


def normalize_domain(value: str) -> str:
    domain = value.strip().rstrip(".").lower()
    wildcard = domain.startswith("*.")
    raw = domain[2:] if wildcard else domain
    try:
        encoded = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DomainValidationError("invalid domain") from exc
    if not encoded or any(not label for label in encoded.split(".")):
        raise DomainValidationError("invalid domain")
    return ("*." if wildcard else "") + encoded


def normalize_ip_or_network(value: str) -> str:
    try:
        if "/" in value:
            return str(ipaddress.ip_network(value.strip(), strict=False))
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise DomainValidationError("invalid IP or CIDR") from exc


def normalize_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise DomainValidationError("URL must use http or https")
    host = normalize_domain(parsed.hostname)
    port = parsed.port
    if port == (443 if scheme == "https" else 80):
        port = None
    netloc = host if port is None else f"{host}:{port}"
    path = posixpath.normpath("/" + parsed.path.lstrip("/"))
    if parsed.path.endswith("/") and not path.endswith("/"):
        path += "/"
    return urlunsplit(SplitResult(scheme, netloc, path, parsed.query, ""))


def normalize_port(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise DomainValidationError("port must be between 1 and 65535")
    return value
```

- [ ] **Step 4: 运行 GREEN**

Run: `py -3.12 -m pytest -q tests/domain/test_normalize.py`

Expected: 8 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/domain/scope/normalize.py tests/domain/test_normalize.py
git commit -m "feat(core): add scope target normalization"
```

---

## Task 5: ScopeDraft + ScopeSnapshot（不可变，Deny 优先）

**Files:**
- Create: `src/secopent/domain/scope/models.py`
- Test: `tests/domain/test_scope.py`

- [ ] **Step 1: 写失败测试**

```python
# tests/domain/test_scope.py
from __future__ import annotations
import pytest
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.scope.models import ScopeDraft, ScopeLimits


def test_scope_freeze_normalizes_and_prioritizes_deny() -> None:
    draft = ScopeDraft(
        project_id="project-1",
        include=("HTTPS://Example.Test:443/api", "192.0.2.0/28"),
        exclude=("https://example.test/api/admin", "192.0.2.7"),
        ports=(443, 8443),
        limits=ScopeLimits(requests_per_second=5, concurrency=3, max_requests=1000),
    )
    snapshot = draft.freeze(snapshot_id="scope-1", approved_by="user-1")
    assert snapshot.includes_url("https://example.test/api/users")
    assert not snapshot.includes_url("https://example.test/api/admin/delete")
    assert snapshot.includes_ip("192.0.2.5")
    assert not snapshot.includes_ip("192.0.2.7")
    assert snapshot.includes_port(443)
    assert not snapshot.includes_port(22)
    assert snapshot.digest.startswith("sha256:")


def test_scope_rejects_invalid_port() -> None:
    with pytest.raises(DomainValidationError):
        ScopeDraft(project_id="p", include=("https://example.test",), ports=(0,))


def test_scope_rejects_empty_include() -> None:
    with pytest.raises(DomainValidationError):
        ScopeDraft(project_id="p", include=())


def test_scope_limits_must_be_positive() -> None:
    with pytest.raises(DomainValidationError):
        ScopeLimits(requests_per_second=0, concurrency=1, max_requests=100)


def test_scope_snapshot_immutable() -> None:
    draft = ScopeDraft(project_id="p", include=("https://example.test",))
    snapshot = draft.freeze(snapshot_id="s", approved_by="u")
    with pytest.raises(Exception):
        snapshot.include = ("other",)  # type: ignore[misc]
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/domain/test_scope.py`

Expected: import FAIL。

- [ ] **Step 3: 实现**

```python
# src/secopent/domain/scope/models.py
from __future__ import annotations
import ipaddress
from dataclasses import asdict, dataclass
from datetime import datetime
from urllib.parse import urlsplit
from ..common.canonical import canonical_digest, utc_now
from ..common.errors import DomainValidationError
from .normalize import normalize_domain, normalize_ip_or_network, normalize_port, normalize_url


@dataclass(frozen=True, slots=True)
class ScopeLimits:
    requests_per_second: float
    concurrency: int
    max_requests: int

    def __post_init__(self) -> None:
        if self.requests_per_second <= 0 or self.concurrency < 1 or self.max_requests < 1:
            raise DomainValidationError("scope limits must be positive")


@dataclass(frozen=True, slots=True)
class ScopeSnapshot:
    id: str
    project_id: str
    include: tuple[str, ...]
    exclude: tuple[str, ...]
    ports: tuple[int, ...]
    limits: ScopeLimits
    approved_by: str
    approved_at: datetime
    digest: str

    def _domain_matches(self, rule: str, domain: str) -> bool:
        if rule.startswith("*."):
            suffix = rule[2:]
            return domain.endswith("." + suffix) and domain != suffix
        return domain == rule

    def _target_matches(self, rule: str, value: str) -> bool:
        if rule.startswith(("http://", "https://")):
            return value.startswith(("http://", "https://")) and normalize_url(value).startswith(rule)
        try:
            network = ipaddress.ip_network(rule, strict=False)
        except ValueError:
            return self._domain_matches(rule, normalize_domain(value))
        try:
            return ipaddress.ip_address(value) in network
        except ValueError:
            return False

    def includes_ip(self, value: str) -> bool:
        normalized = normalize_ip_or_network(value)
        if "/" in normalized:
            raise DomainValidationError("target must be a single IP")
        return (
            not any(self._target_matches(rule, normalized) for rule in self.exclude)
            and any(self._target_matches(rule, normalized) for rule in self.include)
        )

    def includes_domain(self, value: str) -> bool:
        normalized = normalize_domain(value)
        return (
            not any(self._target_matches(rule, normalized) for rule in self.exclude)
            and any(self._target_matches(rule, normalized) for rule in self.include)
        )

    def includes_url(self, value: str) -> bool:
        normalized = normalize_url(value)
        host = urlsplit(normalized).hostname or ""

        def matches(rule: str) -> bool:
            if rule.startswith(("http://", "https://")):
                return normalized.startswith(rule)
            return self._target_matches(rule, host)

        return not any(matches(rule) for rule in self.exclude) and any(
            matches(rule) for rule in self.include
        )

    def includes_port(self, value: int) -> bool:
        return normalize_port(value) in self.ports


@dataclass(frozen=True, slots=True)
class ScopeDraft:
    project_id: str
    include: tuple[str, ...]
    exclude: tuple[str, ...] = ()
    ports: tuple[int, ...] = (80, 443)
    limits: ScopeLimits = ScopeLimits(5.0, 3, 50_000)

    def __post_init__(self) -> None:
        if not self.project_id.strip() or not self.include:
            raise DomainValidationError("project and include targets are required")
        tuple(normalize_port(port) for port in self.ports)

    @staticmethod
    def _normalize_target(value: str) -> str:
        if value.strip().lower().startswith(("http://", "https://")):
            return normalize_url(value)
        try:
            return normalize_ip_or_network(value)
        except DomainValidationError:
            return normalize_domain(value)

    def freeze(self, *, snapshot_id: str, approved_by: str) -> ScopeSnapshot:
        approved_at = utc_now()
        include = tuple(sorted({self._normalize_target(item) for item in self.include}))
        exclude = tuple(sorted({self._normalize_target(item) for item in self.exclude}))
        ports = tuple(sorted({normalize_port(port) for port in self.ports}))
        payload = {
            "id": snapshot_id,
            "project_id": self.project_id,
            "include": include,
            "exclude": exclude,
            "ports": ports,
            "limits": asdict(self.limits),
            "approved_by": approved_by,
            "approved_at": approved_at,
        }
        return ScopeSnapshot(
            snapshot_id, self.project_id, include, exclude, ports,
            self.limits, approved_by, approved_at, canonical_digest(payload),
        )
```

- [ ] **Step 4: 运行 GREEN**

Run: `py -3.12 -m pytest -q tests/domain/test_scope.py`

Expected: 5 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/domain/scope/models.py tests/domain/test_scope.py
git commit -m "feat(core): add immutable scope snapshots with deny priority"
```

---

## Task 6: 确定性 Policy Engine（Deny 优先，Destructive 永拒）

**Files:**
- Create: `src/secopent/domain/policy/models.py`
- Create: `src/secopent/domain/policy/engine.py`
- Test: `tests/domain/test_policy.py`

- [ ] **Step 1: 写失败测试**

```python
# tests/domain/test_policy.py
from __future__ import annotations
import pytest
from secopent.domain.policy.engine import ActionRequest, evaluate
from secopent.domain.policy.models import ExecutionMode, RiskClass
from secopent.domain.scope.models import ScopeDraft


@pytest.fixture
def scope_snapshot():
    draft = ScopeDraft(
        project_id="p",
        include=("https://example.test", "192.0.2.0/28"),
        ports=(443,),
    )
    return draft.freeze(snapshot_id="s", approved_by="u")


def test_policy_denies_scope_outside_target(scope_snapshot) -> None:
    decision = evaluate(
        ActionRequest(target="https://outside.test/", port=443, risk=RiskClass.LOW, capability="scoped_http"),
        scope=scope_snapshot,
        mode=ExecutionMode.SCOPE_AUTOPILOT,
        approved_risks=frozenset(RiskClass),
        approved_capabilities=frozenset({"scoped_http"}),
    )
    assert (decision.allowed, decision.reason) == (False, "SCOPE_DENIED")


def test_policy_denies_destructive_even_if_in_scope(scope_snapshot) -> None:
    decision = evaluate(
        ActionRequest(target="https://example.test/", port=443, risk=RiskClass.DESTRUCTIVE, capability="delete_data"),
        scope=scope_snapshot,
        mode=ExecutionMode.SCOPE_AUTOPILOT,
        approved_risks=frozenset(RiskClass),
        approved_capabilities=frozenset({"delete_data"}),
    )
    assert decision.reason == "DESTRUCTIVE_ACTION_DENIED"


def test_policy_active_requires_capability(scope_snapshot) -> None:
    decision = evaluate(
        ActionRequest(target="https://example.test/", port=443, risk=RiskClass.ACTIVE, capability="web_crawl"),
        scope=scope_snapshot,
        mode=ExecutionMode.APPROVAL,
        approved_risks=frozenset({RiskClass.LOW, RiskClass.ACTIVE}),
        approved_capabilities=frozenset(),
    )
    assert decision.reason == "CAPABILITY_NOT_APPROVED"


def test_policy_risk_not_approved(scope_snapshot) -> None:
    decision = evaluate(
        ActionRequest(target="https://example.test/", port=443, risk=RiskClass.ACTIVE, capability="web_crawl"),
        scope=scope_snapshot,
        mode=ExecutionMode.APPROVAL,
        approved_risks=frozenset({RiskClass.LOW}),
        approved_capabilities=frozenset({"web_crawl"}),
    )
    assert decision.reason == "RISK_NOT_APPROVED"


def test_policy_allows_low_in_scope(scope_snapshot) -> None:
    decision = evaluate(
        ActionRequest(target="https://example.test/", port=443, risk=RiskClass.LOW, capability="scoped_http"),
        scope=scope_snapshot,
        mode=ExecutionMode.APPROVAL,
        approved_risks=frozenset({RiskClass.LOW}),
        approved_capabilities=frozenset({"scoped_http"}),
    )
    assert (decision.allowed, decision.reason) == (True, "ALLOWED")
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/domain/test_policy.py`

Expected: import FAIL。

- [ ] **Step 3: 实现**

```python
# src/secopent/domain/policy/models.py
from __future__ import annotations
from dataclasses import dataclass
from enum import StrEnum


class RiskClass(StrEnum):
    PASSIVE = "passive"
    LOW = "low"
    ACTIVE = "active"
    INTRUSIVE = "intrusive"
    DESTRUCTIVE = "destructive"


class ExecutionMode(StrEnum):
    APPROVAL = "approval"
    SCOPE_AUTOPILOT = "scope_autopilot"


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True, slots=True)
class ActionRequest:
    target: str
    port: int
    risk: RiskClass
    capability: str
```

```python
# src/secopent/domain/policy/engine.py
from __future__ import annotations
from ..scope.models import ScopeSnapshot
from .models import ActionRequest, ExecutionMode, PolicyDecision, RiskClass


def evaluate(
    request: ActionRequest,
    *,
    scope: ScopeSnapshot,
    mode: ExecutionMode,
    approved_risks: frozenset[RiskClass],
    approved_capabilities: frozenset[str],
) -> PolicyDecision:
    if request.risk is RiskClass.DESTRUCTIVE:
        return PolicyDecision(False, "DESTRUCTIVE_ACTION_DENIED")
    if not scope.includes_port(request.port) or not scope.includes_url(request.target):
        return PolicyDecision(False, "SCOPE_DENIED")
    if request.risk not in approved_risks:
        return PolicyDecision(False, "RISK_NOT_APPROVED")
    if request.risk in {RiskClass.ACTIVE, RiskClass.INTRUSIVE} and request.capability not in approved_capabilities:
        return PolicyDecision(False, "CAPABILITY_NOT_APPROVED")
    return PolicyDecision(True, "ALLOWED")
```

- [ ] **Step 4: 运行 GREEN**

Run: `py -3.12 -m pytest -q tests/domain/test_policy.py`

Expected: 5 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/domain/policy tests/domain/test_policy.py
git commit -m "feat(core): enforce deterministic assessment policy"
```

---

## Task 7: Assessment、Plan、Approval（DAG + digest + 状态机）

**Files:**
- Create: `src/secopent/domain/assessments/models.py`
- Test: `tests/domain/test_assessments.py`

- [ ] **Step 1: 写失败测试**

```python
# tests/domain/test_assessments.py
from __future__ import annotations
import pytest
from secopent.domain.assessments.models import (
    Assessment, AssessmentStatus, Approval, ExecutionPlan, PlanStep,
)
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.policy.models import ExecutionMode, RiskClass


def _step(key: str, **kwargs) -> PlanStep:
    defaults = {"runner": "builtin:dns", "risk": RiskClass.LOW, "parameters": {}, "dependencies": ()}
    defaults.update(kwargs)
    return PlanStep(key=key, **defaults)


def test_plan_digest_changes_with_parameters() -> None:
    one = ExecutionPlan.create(plan_id="p1", assessment_id="a1", version=1,
        steps=(_step("dns"),))
    two = ExecutionPlan.create(plan_id="p2", assessment_id="a1", version=1,
        steps=(_step("dns", parameters={"timeout": 5}),))
    assert one.digest != two.digest


def test_plan_rejects_duplicate_keys() -> None:
    with pytest.raises(DomainValidationError, match="unique"):
        ExecutionPlan.create(plan_id="p", assessment_id="a", version=1,
            steps=(_step("dns"), _step("dns")))


def test_plan_rejects_cycle() -> None:
    with pytest.raises(DomainValidationError, match="cycle"):
        ExecutionPlan.create(plan_id="p", assessment_id="a", version=1,
            steps=(_step("a", dependencies=("b",)), _step("b", dependencies=("a",))))


def test_plan_rejects_missing_dependency() -> None:
    with pytest.raises(DomainValidationError, match="dependency does not exist"):
        ExecutionPlan.create(plan_id="p", assessment_id="a", version=1,
            steps=(_step("a", dependencies=("missing",)),))


def test_approval_requires_digests() -> None:
    with pytest.raises(DomainValidationError, match="digest"):
        Approval.create(approval_id="x", assessment_id="a", plan_digest="",
            scope_digest="", mode=ExecutionMode.APPROVAL,
            approved_risks=frozenset({RiskClass.LOW}),
            approved_capabilities=frozenset(), approved_by="u")


def test_assessment_cannot_start_without_approval() -> None:
    assessment = Assessment.create(assessment_id="a", project_id="p",
        scope_snapshot_id="s", mode=ExecutionMode.APPROVAL)
    with pytest.raises(DomainValidationError, match="approval"):
        assessment.start(plan_id="plan", approval_id=None)


def test_assessment_start_moves_to_queued() -> None:
    assessment = Assessment.create(assessment_id="a", project_id="p",
        scope_snapshot_id="s", mode=ExecutionMode.APPROVAL)
    started = assessment.start(plan_id="plan", approval_id="appr-1")
    assert started.status is AssessmentStatus.QUEUED
    assert started.active_plan_id == "plan"
    assert started.approval_id == "appr-1"


def test_assessment_rejects_empty_ids() -> None:
    with pytest.raises(DomainValidationError, match="identifiers"):
        Assessment.create(assessment_id="", project_id="p", scope_snapshot_id="s",
            mode=ExecutionMode.APPROVAL)
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/domain/test_assessments.py`

Expected: import FAIL。

- [ ] **Step 3: 实现**

```python
# src/secopent/domain/assessments/models.py
from __future__ import annotations
from dataclasses import dataclass, replace
from enum import StrEnum
from ..common.canonical import canonical_digest
from ..common.errors import DomainValidationError
from ..policy.models import ExecutionMode, RiskClass


class AssessmentStatus(StrEnum):
    DRAFT = "draft"
    PLANNED = "planned"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class PlanStep:
    key: str
    runner: str
    risk: RiskClass
    parameters: dict[str, object]
    dependencies: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    id: str
    assessment_id: str
    version: int
    steps: tuple[PlanStep, ...]
    digest: str

    @classmethod
    def create(cls, *, plan_id: str, assessment_id: str, version: int,
               steps: tuple[PlanStep, ...]) -> ExecutionPlan:
        if version < 1:
            raise DomainValidationError("plan version must be positive")
        keys = [s.key for s in steps]
        if len(keys) != len(set(keys)):
            raise DomainValidationError("plan step keys must be unique")
        known = set(keys)
        if any(set(s.dependencies) - known for s in steps):
            raise DomainValidationError("plan dependency does not exist")
        graph = {s.key: s.dependencies for s in steps}
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(key: str) -> None:
            if key in visiting:
                raise DomainValidationError("plan dependency cycle")
            if key in visited:
                return
            visiting.add(key)
            for dep in graph[key]:
                visit(dep)
            visiting.remove(key)
            visited.add(key)

        for key in keys:
            visit(key)
        payload = {"assessment_id": assessment_id, "version": version, "steps": steps}
        return cls(plan_id, assessment_id, version, tuple(steps), canonical_digest(payload))


@dataclass(frozen=True, slots=True)
class Approval:
    id: str
    assessment_id: str
    plan_digest: str
    scope_digest: str
    mode: ExecutionMode
    approved_risks: frozenset[RiskClass]
    approved_capabilities: frozenset[str]
    approved_by: str
    digest: str

    @classmethod
    def create(cls, *, approval_id: str, assessment_id: str, plan_digest: str,
               scope_digest: str, mode: ExecutionMode,
               approved_risks: frozenset[RiskClass], approved_capabilities: frozenset[str],
               approved_by: str) -> Approval:
        if not plan_digest or not scope_digest:
            raise DomainValidationError("approval requires plan and scope digest")
        payload = {
            "assessment_id": assessment_id,
            "plan_digest": plan_digest,
            "scope_digest": scope_digest,
            "mode": mode,
            "approved_risks": approved_risks,
            "approved_capabilities": approved_capabilities,
            "approved_by": approved_by,
        }
        return cls(approval_id, assessment_id, plan_digest, scope_digest, mode,
                   frozenset(approved_risks), frozenset(approved_capabilities),
                   approved_by, canonical_digest(payload))


@dataclass(frozen=True, slots=True)
class Assessment:
    id: str
    project_id: str
    scope_snapshot_id: str
    mode: ExecutionMode
    status: AssessmentStatus
    active_plan_id: str | None = None
    approval_id: str | None = None

    @classmethod
    def create(cls, *, assessment_id: str, project_id: str, scope_snapshot_id: str,
               mode: ExecutionMode) -> Assessment:
        if not all((assessment_id, project_id, scope_snapshot_id)):
            raise DomainValidationError("assessment identifiers are required")
        return cls(assessment_id, project_id, scope_snapshot_id, mode, AssessmentStatus.DRAFT)

    def start(self, *, plan_id: str, approval_id: str | None) -> Assessment:
        if not approval_id:
            raise DomainValidationError("assessment requires approval")
        if self.status not in {AssessmentStatus.DRAFT, AssessmentStatus.APPROVED}:
            raise DomainValidationError("assessment cannot start from current status")
        return replace(self, status=AssessmentStatus.QUEUED,
                       active_plan_id=plan_id, approval_id=approval_id)
```

- [ ] **Step 4: 运行 GREEN**

Run: `py -3.12 -m pytest -q tests/domain/test_assessments.py`

Expected: 8 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/domain/assessments tests/domain/test_assessments.py
git commit -m "feat(core): add assessment plans and approvals"
```

---

## Task 8: Audit Event（hash chain 起步）

**Files:**
- Create: `src/secopent/domain/audit/models.py`
- Test: `tests/domain/test_audit.py`

- [ ] **Step 1: 写失败测试**

```python
# tests/domain/test_audit.py
from __future__ import annotations
import pytest
from secopent.domain.audit.models import AuditEvent
from secopent.domain.common.errors import DomainValidationError


def test_audit_first_event_uses_genesis_previous() -> None:
    event = AuditEvent.create(
        event_id="e1",
        actor="user-1",
        action="scope.approved",
        resource_type="scope_snapshot",
        resource_id="s1",
        payload={"approved_by": "user-1"},
        previous_hash="0" * 64,
    )
    assert event.event_hash.startswith("sha256:")
    assert event.previous_hash == "0" * 64


def test_audit_chain_links_hashes() -> None:
    first = AuditEvent.create(
        event_id="e1", actor="u", action="a", resource_type="r", resource_id="r1",
        payload={}, previous_hash="0" * 64,
    )
    second = AuditEvent.create(
        event_id="e2", actor="u", action="b", resource_type="r", resource_id="r2",
        payload={}, previous_hash=first.event_hash.removeprefix("sha256:"),
    )
    assert second.previous_hash == first.event_hash.removeprefix("sha256:")


def test_audit_rejects_empty_fields() -> None:
    with pytest.raises(DomainValidationError):
        AuditEvent.create(
            event_id="", actor="u", action="a", resource_type="r", resource_id="r1",
            payload={}, previous_hash="0" * 64,
        )


def test_audit_rejects_secret_in_payload() -> None:
    with pytest.raises(DomainValidationError, match="secret"):
        AuditEvent.create(
            event_id="e1", actor="u", action="a", resource_type="r", resource_id="r1",
            payload={"password": "hunter2"}, previous_hash="0" * 64,
        )


def test_audit_detects_tamper() -> None:
    first = AuditEvent.create(
        event_id="e1", actor="u", action="a", resource_type="r", resource_id="r1",
        payload={}, previous_hash="0" * 64,
    )
    second = AuditEvent.create(
        event_id="e2", actor="u", action="b", resource_type="r", resource_id="r2",
        payload={}, previous_hash=first.event_hash.removeprefix("sha256:"),
    )
    assert AuditEvent.verify_chain([first, second]) is True
    tampered = AuditEvent(
        id=second.id, actor=second.actor, action="tampered", resource_type=second.resource_type,
        resource_id=second.resource_id, payload=second.payload, previous_hash=second.previous_hash,
        event_hash=second.event_hash, occurred_at=second.occurred_at,
    )
    assert AuditEvent.verify_chain([first, tampered]) is False
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/domain/test_audit.py`

Expected: import FAIL。

- [ ] **Step 3: 实现**

```python
# src/secopent/domain/audit/models.py
from __future__ import annotations
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from ..common.canonical import canonical_json, utc_now
from ..common.errors import DomainValidationError

GENESIS_HASH = "0" * 64
_SECRET_KEYS = {"password", "secret", "token", "authorization", "api_key", "cookie"}


@dataclass(frozen=True, slots=True)
class AuditEvent:
    id: str
    actor: str
    action: str
    resource_type: str
    resource_id: str
    payload: dict[str, object]
    previous_hash: str
    event_hash: str
    occurred_at: datetime

    @classmethod
    def create(cls, *, event_id: str, actor: str, action: str, resource_type: str,
               resource_id: str, payload: dict[str, object], previous_hash: str) -> AuditEvent:
        if not all((event_id, actor, action, resource_type, resource_id)):
            raise DomainValidationError("audit event fields must not be empty")
        _check_no_secret(payload)
        occurred_at = utc_now()
        body = {
            "id": event_id,
            "actor": actor,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "payload": payload,
            "previous_hash": previous_hash,
            "occurred_at": occurred_at,
        }
        event_hash = "sha256:" + hashlib.sha256(
            canonical_json(body).encode("utf-8")
        ).hexdigest()
        return cls(event_id, actor, action, resource_type, resource_id, payload,
                   previous_hash, event_hash, occurred_at)

    @staticmethod
    def verify_chain(events: list[AuditEvent]) -> bool:
        previous = GENESIS_HASH
        for event in events:
            expected_prev = previous.removeprefix("sha256:") if previous.startswith("sha256:") else previous
            if event.previous_hash != expected_prev:
                return False
            body = {
                "id": event.id,
                "actor": event.actor,
                "action": event.action,
                "resource_type": event.resource_type,
                "resource_id": event.resource_id,
                "payload": event.payload,
                "previous_hash": event.previous_hash,
                "occurred_at": event.occurred_at,
            }
            recomputed = "sha256:" + hashlib.sha256(
                canonical_json(body).encode("utf-8")
            ).hexdigest()
            if recomputed != event.event_hash:
                return False
            previous = event.event_hash.removeprefix("sha256:")
        return True


def _check_no_secret(payload: dict[str, object]) -> None:
    for key in payload:
        if key.lower() in _SECRET_KEYS:
            raise DomainValidationError(f"secret key '{key}' must not appear in audit payload")
```

- [ ] **Step 4: 运行 GREEN**

Run: `py -3.12 -m pytest -q tests/domain/test_audit.py`

Expected: 5 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/domain/audit tests/domain/test_audit.py
git commit -m "feat(core): add audit hash chain with tamper detection"
```

---

## Task 9: Application Ports 与 Use Cases

**Files:**
- Create: `src/secopent/application/ports/repositories.py`
- Create: `src/secopent/application/projects.py`
- Create: `src/secopent/application/scopes.py`
- Create: `src/secopent/application/assessments.py`
- Create: `src/secopent/application/audit.py`
- Test: `tests/application/test_scope_service.py`
- Test: `tests/application/test_assessment_service.py`
- Test: `tests/application/test_audit_service.py`

- [ ] **Step 1: 写失败测试**

```python
# tests/application/test_scope_service.py
from __future__ import annotations
from secopent.application.scopes import ScopeService
from secopent.application.audit import AuditService


def test_freeze_scope_persists_snapshot_and_audits(memory_repositories):
    snapshot = ScopeService(memory_repositories.scopes, AuditService(memory_repositories.audit)).freeze(
        project_id="p", include=("https://example.test",), exclude=(),
        ports=(443,), approved_by="u",
    )
    assert memory_repositories.scopes.get_snapshot(snapshot.id) == snapshot
    events = memory_repositories.audit.list_events()
    assert len(events) == 1
    assert events[0].action == "scope.frozen"
```

```python
# tests/application/test_assessment_service.py
from __future__ import annotations
from secopent.application.assessments import AssessmentService
from secopent.domain.policy.models import ExecutionMode


def test_create_assessment_persists(memory_repositories):
    service = AssessmentService(memory_repositories.assessments)
    assessment = service.create(project_id="p", scope_snapshot_id="s", mode=ExecutionMode.APPROVAL)
    assert memory_repositories.assessments.get(assessment.id) == assessment


def test_attach_plan_moves_to_awaiting_approval(memory_repositories):
    service = AssessmentService(memory_repositories.assessments)
    assessment = service.create(project_id="p", scope_snapshot_id="s", mode=ExecutionMode.APPROVAL)
    result = service.attach_plan(assessment.id, steps=())
    assert result.status.value == "awaiting_approval"
```

```python
# tests/application/test_audit_service.py
from __future__ import annotations
import pytest
from secopent.application.audit import AuditService


def test_audit_service_chains_events(memory_repositories):
    service = AuditService(memory_repositories.audit)
    service.record(actor="u", action="a", resource_type="r", resource_id="r1", payload={})
    service.record(actor="u", action="b", resource_type="r", resource_id="r2", payload={})
    events = memory_repositories.audit.list_events()
    assert len(events) == 2
    assert AuditService.verify(events) is True


def test_audit_service_rejects_secret(memory_repositories):
    service = AuditService(memory_repositories.audit)
    with pytest.raises(Exception):
        service.record(actor="u", action="a", resource_type="r", resource_id="r1",
                       payload={"password": "x"})
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/application`

Expected: import FAIL。

- [ ] **Step 3: 实现 Ports 和服务**

```python
# src/secopent/application/ports/repositories.py
from __future__ import annotations
from typing import Protocol
from ...domain.assessments.models import Assessment, ExecutionPlan, Approval
from ...domain.audit.models import AuditEvent
from ...domain.projects.models import Project
from ...domain.scope.models import ScopeSnapshot


class ProjectRepository(Protocol):
    def add(self, project: Project) -> None: ...
    def get(self, project_id: str) -> Project | None: ...


class ScopeRepository(Protocol):
    def add_snapshot(self, snapshot: ScopeSnapshot) -> None: ...
    def get_snapshot(self, snapshot_id: str) -> ScopeSnapshot | None: ...


class AssessmentRepository(Protocol):
    def add(self, assessment: Assessment) -> None: ...
    def get(self, assessment_id: str) -> Assessment | None: ...
    def save_plan(self, plan: ExecutionPlan) -> None: ...
    def get_plan(self, plan_id: str) -> ExecutionPlan | None: ...
    def save_approval(self, approval: Approval) -> None: ...


class AuditRepository(Protocol):
    def add(self, event: AuditEvent) -> None: ...
    def list_events(self) -> list[AuditEvent]: ...
    def last_hash(self) -> str: ...
```

```python
# src/secopent/application/audit.py
from __future__ import annotations
from ..domain.audit.models import AuditEvent, GENESIS_HASH
from .ports.repositories import AuditRepository


class AuditService:
    def __init__(self, repo: AuditRepository) -> None:
        self._repo = repo

    def record(self, *, actor: str, action: str, resource_type: str,
               resource_id: str, payload: dict[str, object]) -> AuditEvent:
        previous = self._repo.last_hash() or GENESIS_HASH
        event = AuditEvent.create(
            event_id=f"evt-{len(self._repo.list_events()) + 1}",
            actor=actor, action=action, resource_type=resource_type,
            resource_id=resource_id, payload=payload, previous_hash=previous,
        )
        self._repo.add(event)
        return event

    @staticmethod
    def verify(events: list[AuditEvent]) -> bool:
        return AuditEvent.verify_chain(events)
```

```python
# src/secopent/application/projects.py
from __future__ import annotations
import uuid
from ..domain.projects.models import Project
from .ports.repositories import ProjectRepository


class ProjectService:
    def __init__(self, repo: ProjectRepository) -> None:
        self._repo = repo

    def create(self, *, name: str) -> Project:
        project = Project.create(project_id=f"proj-{uuid.uuid4().hex[:12]}", name=name)
        self._repo.add(project)
        return project
```

```python
# src/secopent/application/scopes.py
from __future__ import annotations
import uuid
from ..domain.scope.models import ScopeDraft, ScopeSnapshot
from .audit import AuditService
from .ports.repositories import ScopeRepository


class ScopeService:
    def __init__(self, repo: ScopeRepository, audit: AuditService) -> None:
        self._repo = repo
        self._audit = audit

    def freeze(self, *, project_id: str, include: tuple[str, ...],
               exclude: tuple[str, ...] = (), ports: tuple[int, ...] = (443,),
               approved_by: str) -> ScopeSnapshot:
        draft = ScopeDraft(project_id=project_id, include=include, exclude=exclude, ports=ports)
        snapshot = draft.freeze(snapshot_id=f"scope-{uuid.uuid4().hex[:12]}", approved_by=approved_by)
        self._repo.add_snapshot(snapshot)
        self._audit.record(
            actor=approved_by, action="scope.frozen",
            resource_type="scope_snapshot", resource_id=snapshot.id,
            payload={"project_id": project_id, "digest": snapshot.digest},
        )
        return snapshot
```

```python
# src/secopent/application/assessments.py
from __future__ import annotations
import uuid
from dataclasses import replace
from ..domain.assessments.models import Assessment, AssessmentStatus, ExecutionPlan, PlanStep
from ..domain.policy.models import ExecutionMode
from .ports.repositories import AssessmentRepository


class AssessmentService:
    def __init__(self, repo: AssessmentRepository) -> None:
        self._repo = repo

    def create(self, *, project_id: str, scope_snapshot_id: str,
               mode: ExecutionMode) -> Assessment:
        assessment = Assessment.create(
            assessment_id=f"asm-{uuid.uuid4().hex[:12]}",
            project_id=project_id, scope_snapshot_id=scope_snapshot_id, mode=mode,
        )
        self._repo.add(assessment)
        return assessment

    def attach_plan(self, assessment_id: str, steps: tuple[PlanStep, ...]) -> Assessment:
        assessment = self._repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        plan = ExecutionPlan.create(
            plan_id=f"plan-{uuid.uuid4().hex[:12]}",
            assessment_id=assessment_id, version=1, steps=steps,
        )
        self._repo.save_plan(plan)
        updated = replace(assessment, status=AssessmentStatus.AWAITING_APPROVAL, active_plan_id=plan.id)
        self._repo.add(updated)
        return updated
```

测试 fixture（`tests/application/conftest.py`）：

```python
# tests/application/conftest.py
from __future__ import annotations
from dataclasses import dataclass, field
import pytest
from secopent.domain.assessments.models import Assessment, ExecutionPlan, Approval
from secopent.domain.audit.models import AuditEvent, GENESIS_HASH
from secopent.domain.projects.models import Project
from secopent.domain.scope.models import ScopeSnapshot


@dataclass
class MemoryProjectRepo:
    items: dict[str, Project] = field(default_factory=dict)
    def add(self, p: Project) -> None: self.items[p.id] = p
    def get(self, pid: str) -> Project | None: return self.items.get(pid)


@dataclass
class MemoryScopeRepo:
    items: dict[str, ScopeSnapshot] = field(default_factory=dict)
    def add_snapshot(self, s: ScopeSnapshot) -> None: self.items[s.id] = s
    def get_snapshot(self, sid: str) -> ScopeSnapshot | None: return self.items.get(sid)


@dataclass
class MemoryAssessmentRepo:
    items: dict[str, Assessment] = field(default_factory=dict)
    plans: dict[str, ExecutionPlan] = field(default_factory=dict)
    def add(self, a: Assessment) -> None: self.items[a.id] = a
    def get(self, aid: str) -> Assessment | None: return self.items.get(aid)
    def save_plan(self, p: ExecutionPlan) -> None: self.plans[p.id] = p
    def get_plan(self, pid: str) -> ExecutionPlan | None: return self.plans.get(pid)
    def save_approval(self, a: Approval) -> None: ...


@dataclass
class MemoryAuditRepo:
    events: list[AuditEvent] = field(default_factory=list)
    def add(self, e: AuditEvent) -> None: self.events.append(e)
    def list_events(self) -> list[AuditEvent]: return list(self.events)
    def last_hash(self) -> str:
        return self.events[-1].event_hash.removeprefix("sha256:") if self.events else GENESIS_HASH


@dataclass
class MemoryRepos:
    projects: MemoryProjectRepo = field(default_factory=MemoryProjectRepo)
    scopes: MemoryScopeRepo = field(default_factory=MemoryScopeRepo)
    assessments: MemoryAssessmentRepo = field(default_factory=MemoryAssessmentRepo)
    audit: MemoryAuditRepo = field(default_factory=MemoryAuditRepo)


@pytest.fixture
def memory_repositories() -> MemoryRepos:
    return MemoryRepos()
```

- [ ] **Step 4: 运行 GREEN**

Run: `py -3.12 -m pytest -q tests/application tests/domain`

Expected: 全部 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/application tests/application
git commit -m "feat(core): add project scope assessment audit use cases"
```

---

## Task 10: SQLite WAL Repository Contract

**Files:**
- Create: `src/secopent/infrastructure/db/core_models.py`
- Create: `src/secopent/infrastructure/db/sqlite.py`
- Test: `tests/infrastructure/test_sqlite_wal.py`

- [ ] **Step 1: 写失败测试**

```python
# tests/infrastructure/test_sqlite_wal.py
from __future__ import annotations
from pathlib import Path
from sqlalchemy import text
from secopent.infrastructure.db.sqlite import create_sqlite_engine


def test_sqlite_enables_wal_and_foreign_keys(tmp_path: Path) -> None:
    engine = create_sqlite_engine(tmp_path / "secopent.db")
    with engine.connect() as connection:
        assert connection.execute(text("PRAGMA journal_mode")).scalar_one().lower() == "wal"
        assert connection.execute(text("PRAGMA foreign_keys")).scalar_one() == 1
        assert connection.execute(text("PRAGMA busy_timeout")).scalar_one() == 5000


def test_sqlite_engine_is_reusable(tmp_path: Path) -> None:
    engine = create_sqlite_engine(tmp_path / "secopent.db")
    with engine.connect() as c1:
        c1.execute(text("CREATE TABLE t (x INTEGER)"))
        c1.commit()
    with engine.connect() as c2:
        c2.execute(text("INSERT INTO t VALUES (1)"))
        c2.commit()
    with engine.connect() as c3:
        assert c3.execute(text("SELECT x FROM t")).scalar_one() == 1
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/infrastructure/test_sqlite_wal.py`

Expected: import FAIL。

- [ ] **Step 3: 实现数据库**

```python
# src/secopent/infrastructure/db/sqlite.py
from __future__ import annotations
from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine


def create_sqlite_engine(path: Path) -> Engine:
    engine = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False, "timeout": 5.0},
        future=True,
    )

    @event.listens_for(engine, "connect")
    def configure(dbapi_connection, _record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()

    return engine
```

```python
# src/secopent/infrastructure/db/core_models.py
from __future__ import annotations
from datetime import datetime
from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class CoreBase(DeclarativeBase):
    pass


class CoreProject(CoreBase):
    __tablename__ = "core_projects"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CoreScopeSnapshot(CoreBase):
    __tablename__ = "core_scope_snapshots"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("core_projects.id"), nullable=False)
    include: Mapped[list] = mapped_column(JSON, nullable=False)
    exclude: Mapped[list] = mapped_column(JSON, nullable=False)
    ports: Mapped[list] = mapped_column(JSON, nullable=False)
    limits: Mapped[dict] = mapped_column(JSON, nullable=False)
    approved_by: Mapped[str] = mapped_column(String(64), nullable=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    digest: Mapped[str] = mapped_column(String(80), nullable=False, index=True)


class CoreAssessment(CoreBase):
    __tablename__ = "core_assessments"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("core_projects.id"), nullable=False)
    scope_snapshot_id: Mapped[str] = mapped_column(ForeignKey("core_scope_snapshots.id"), nullable=False)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    active_plan_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approval_id: Mapped[str | None] = mapped_column(String(64), nullable=True)


class CoreExecutionPlan(CoreBase):
    __tablename__ = "core_execution_plans"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("core_assessments.id"), nullable=False)
    version: Mapped[int] = mapped_column(nullable=False)
    steps: Mapped[list] = mapped_column(JSON, nullable=False)
    digest: Mapped[str] = mapped_column(String(80), nullable=False, index=True)


class CoreApproval(CoreBase):
    __tablename__ = "core_approvals"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("core_assessments.id"), nullable=False)
    plan_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    scope_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    approved_risks: Mapped[list] = mapped_column(JSON, nullable=False)
    approved_capabilities: Mapped[list] = mapped_column(JSON, nullable=False)
    approved_by: Mapped[str] = mapped_column(String(64), nullable=False)
    digest: Mapped[str] = mapped_column(String(80), nullable=False, index=True)


class CoreAuditEvent(CoreBase):
    __tablename__ = "core_audit_events"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
```

- [ ] **Step 4: 运行 GREEN**

Run: `py -3.12 -m pytest -q tests/infrastructure/test_sqlite_wal.py`

Expected: 2 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/infrastructure/db tests/infrastructure/test_sqlite_wal.py
git commit -m "feat(core): persist baseline in sqlite wal"
```

---

## Task 11: SQLAlchemy Repository Contract

**Files:**
- Create: `src/secopent/infrastructure/repositories/sqlalchemy_core.py`
- Test: `tests/infrastructure/test_core_repository_contract.py`

- [ ] **Step 1: 写失败测试**

```python
# tests/infrastructure/test_core_repository_contract.py
from __future__ import annotations
from datetime import datetime
import pytest
from sqlalchemy.orm import Session
from secopent.domain.assessments.models import Assessment
from secopent.domain.policy.models import ExecutionMode
from secopent.domain.scope.models import ScopeDraft
from secopent.infrastructure.db.core_models import CoreBase
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAuditRepository, SqlAlchemyScopeRepository, SqlAlchemyAssessmentRepository,
)


@pytest.fixture
def sqlite_session(tmp_path):
    engine = create_sqlite_engine(tmp_path / "secopent.db")
    CoreBase.metadata.create_all(engine)
    session = Session(engine)
    yield session
    session.close()


def test_scope_repository_round_trip(sqlite_session):
    draft = ScopeDraft(project_id="p", include=("https://example.test",))
    snapshot = draft.freeze(snapshot_id="scope-1", approved_by="u")
    repo = SqlAlchemyScopeRepository(sqlite_session)
    repo.add_snapshot(snapshot)
    sqlite_session.commit()
    assert repo.get_snapshot("scope-1") == snapshot


def test_scope_repository_returns_none_for_missing(sqlite_session):
    repo = SqlAlchemyScopeRepository(sqlite_session)
    assert repo.get_snapshot("missing") is None


def test_audit_repository_chains(sqlite_session):
    repo = SqlAlchemyAuditRepository(sqlite_session)
    repo.add(_make_event(repo, "e1", "a"))
    repo.add(_make_event(repo, "e2", "b"))
    sqlite_session.commit()
    events = repo.list_events()
    assert len(events) == 2
    assert repo.last_hash() == events[-1].event_hash.removeprefix("sha256:")


def test_assessment_repository_round_trip(sqlite_session):
    repo = SqlAlchemyAssessmentRepository(sqlite_session)
    assessment = Assessment.create(assessment_id="a1", project_id="p",
        scope_snapshot_id="s", mode=ExecutionMode.APPROVAL)
    repo.add(assessment)
    sqlite_session.commit()
    assert repo.get("a1") == assessment


def _make_event(repo, event_id, action):
    from secopent.domain.audit.models import AuditEvent
    previous = repo.last_hash() or "0" * 64
    return AuditEvent.create(
        event_id=event_id, actor="u", action=action, resource_type="r",
        resource_id="r1", payload={}, previous_hash=previous,
    )
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/infrastructure/test_core_repository_contract.py`

Expected: import FAIL。

- [ ] **Step 3: 实现 Repository**

```python
# src/secopent/infrastructure/repositories/sqlalchemy_core.py
from __future__ import annotations
from datetime import UTC, datetime
from sqlalchemy import select
from sqlalchemy.orm import Session
from ...domain.assessments.models import Assessment, AssessmentStatus, ExecutionPlan, Approval
from ...domain.audit.models import AuditEvent, GENESIS_HASH
from ...domain.policy.models import ExecutionMode, RiskClass
from ...domain.scope.models import ScopeLimits, ScopeSnapshot
from ..db.core_models import (
    CoreApproval, CoreAssessment, CoreAuditEvent, CoreExecutionPlan, CoreScopeSnapshot,
)


def _to_snapshot(row: CoreScopeSnapshot) -> ScopeSnapshot:
    return ScopeSnapshot(
        id=row.id, project_id=row.project_id,
        include=tuple(row.include), exclude=tuple(row.exclude),
        ports=tuple(row.ports),
        limits=ScopeLimits(**row.limits),
        approved_by=row.approved_by, approved_at=row.approved_at, digest=row.digest,
    )


def _from_snapshot(snapshot: ScopeSnapshot) -> CoreScopeSnapshot:
    return CoreScopeSnapshot(
        id=snapshot.id, project_id=snapshot.project_id,
        include=list(snapshot.include), exclude=list(snapshot.exclude),
        ports=list(snapshot.ports),
        limits={
            "requests_per_second": snapshot.limits.requests_per_second,
            "concurrency": snapshot.limits.concurrency,
            "max_requests": snapshot.limits.max_requests,
        },
        approved_by=snapshot.approved_by, approved_at=snapshot.approved_at, digest=snapshot.digest,
    )


class SqlAlchemyScopeRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add_snapshot(self, snapshot: ScopeSnapshot) -> None:
        self._session.add(_from_snapshot(snapshot))

    def get_snapshot(self, snapshot_id: str) -> ScopeSnapshot | None:
        row = self._session.get(CoreScopeSnapshot, snapshot_id)
        return _to_snapshot(row) if row else None


class SqlAlchemyAuditRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, event: AuditEvent) -> None:
        self._session.add(CoreAuditEvent(
            id=event.id, actor=event.actor, action=event.action,
            resource_type=event.resource_type, resource_id=event.resource_id,
            payload=event.payload, previous_hash=event.previous_hash,
            event_hash=event.event_hash, occurred_at=event.occurred_at,
        ))

    def list_events(self) -> list[AuditEvent]:
        rows = self._session.execute(
            select(CoreAuditEvent).order_by(CoreAuditEvent.occurred_at)
        ).scalars().all()
        return [
            AuditEvent(
                id=r.id, actor=r.actor, action=r.action, resource_type=r.resource_type,
                resource_id=r.resource_id, payload=r.payload, previous_hash=r.previous_hash,
                event_hash=r.event_hash, occurred_at=r.occurred_at,
            )
            for r in rows
        ]

    def last_hash(self) -> str:
        rows = self._session.execute(
            select(CoreAuditEvent).order_by(CoreAuditEvent.occurred_at.desc()).limit(1)
        ).scalars().all()
        return rows[0].event_hash.removeprefix("sha256:") if rows else GENESIS_HASH


class SqlAlchemyAssessmentRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, assessment: Assessment) -> None:
        self._session.merge(CoreAssessment(
            id=assessment.id, project_id=assessment.project_id,
            scope_snapshot_id=assessment.scope_snapshot_id,
            mode=assessment.mode.value, status=assessment.status.value,
            active_plan_id=assessment.active_plan_id, approval_id=assessment.approval_id,
        ))

    def get(self, assessment_id: str) -> Assessment | None:
        row = self._session.get(CoreAssessment, assessment_id)
        if not row:
            return None
        return Assessment(
            id=row.id, project_id=row.project_id, scope_snapshot_id=row.scope_snapshot_id,
            mode=ExecutionMode(row.mode), status=AssessmentStatus(row.status),
            active_plan_id=row.active_plan_id, approval_id=row.approval_id,
        )

    def save_plan(self, plan: ExecutionPlan) -> None:
        self._session.add(CoreExecutionPlan(
            id=plan.id, assessment_id=plan.assessment_id, version=plan.version,
            steps=[{"key": s.key, "runner": s.runner, "risk": s.risk.value,
                     "parameters": s.parameters, "dependencies": list(s.dependencies)}
                   for s in plan.steps],
            digest=plan.digest,
        ))

    def get_plan(self, plan_id: str) -> ExecutionPlan | None:
        row = self._session.get(CoreExecutionPlan, plan_id)
        if not row:
            return None
        from ...domain.assessments.models import PlanStep
        steps = tuple(PlanStep(
            key=s["key"], runner=s["runner"], risk=RiskClass(s["risk"]),
            parameters=s["parameters"], dependencies=tuple(s["dependencies"]),
        ) for s in row.steps)
        return ExecutionPlan(
            id=row.id, assessment_id=row.assessment_id, version=row.version,
            steps=steps, digest=row.digest,
        )

    def save_approval(self, approval: Approval) -> None:
        self._session.add(CoreApproval(
            id=approval.id, assessment_id=approval.assessment_id,
            plan_digest=approval.plan_digest, scope_digest=approval.scope_digest,
            mode=approval.mode.value,
            approved_risks=[r.value for r in approval.approved_risks],
            approved_capabilities=list(approval.approved_capabilities),
            approved_by=approval.approved_by, digest=approval.digest,
        ))
```

- [ ] **Step 4: 运行 GREEN 和并发测试**

Run: `py -3.12 -m pytest -q tests/infrastructure tests/application tests/domain`

Expected: 全部 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/infrastructure/repositories tests/infrastructure/test_core_repository_contract.py
git commit -m "feat(core): add sqlalchemy repository contract"
```

---

## Task 12: M0 质量门和文档同步

**Files:**
- Modify: `pyproject.toml`
- Modify: `README.md`
- Create: `docs/architecture/core-boundaries.md`

- [ ] **Step 1: 写失败的文档测试**

```python
# tests/test_docs_consistency.py（新增或追加）
from __future__ import annotations
from pathlib import Path


def test_readme_points_to_catalog_driven_design() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    assert "catalog-driven-agent-workbench-design.md" in readme
    assert "M0" in readme


def test_core_boundaries_doc_exists() -> None:
    assert Path("docs/architecture/core-boundaries.md").is_file()
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/test_docs_consistency.py`

Expected: FAIL，README 未引用新设计。

- [ ] **Step 3: 更新配置和文档**

```toml
# pyproject.toml（新增或修改 [tool.ruff.lint] 和 [[tool.mypy.overrides]]）
[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "SIM"]

[[tool.mypy.overrides]]
module = ["secopent.domain.*", "secopent.application.*"]
strict = true
```

```markdown
<!-- docs/architecture/core-boundaries.md -->
# 核心边界（M0）

## 依赖方向
interfaces -> application -> domain
infrastructure / execution / integrations 通过 ports/contracts 接入
domain 不反向依赖基础设施（不导入 FastAPI/SQLAlchemy/Docker/MCP/httpx/cryptography）

## M0 表
- core_projects
- core_scope_snapshots
- core_assessments
- core_execution_plans
- core_approvals
- core_audit_events

## 禁止依赖
- domain: 无任何框架
- application: 无任何框架（仅 Protocol + Domain）
- infrastructure: 可依赖 SQLAlchemy 等基础设施库

## Repository Contract
M0 起抽象 Repository Protocol，SQLite WAL 实现 + PostgreSQL 接口预留。
M5 切 PG 时无需改 domain/application，仅新增 SqlAlchemy+PG 实现。
```

```markdown
<!-- README.md（覆盖）-->
# SecOpent

目录驱动 Agent 渗透工作台。详见 `sepcs/2026-07-25-catalog-driven-agent-workbench-design.md`。

## 状态
- M0 地基与确定性脊柱骨架（进行中）

## 快速开始
```bash
py -3.12 -m pytest -q
```
```

- [ ] **Step 4: 运行完整质量门**

```bash
py -3.12 -m pytest -q
py -3.12 -m compileall -q src tests
py -3.12 -m ruff check src tests
py -3.12 -m mypy src/secopent/domain src/secopent/application
git diff --check
```

Expected: pytest 0 failed；compileall exit 0；ruff/mypy 0 errors；diff check 无输出。

- [ ] **Step 5: 跨 CWD 回归**

```bash
py -3.12 -m pytest -q tests/domain tests/application tests/infrastructure
cd tests && py -3.12 -m pytest -q domain application infrastructure && cd ..
```

Expected: 三组 PASS。

- [ ] **Step 6: 提交收口**

```bash
git add pyproject.toml README.md docs tests/test_docs_consistency.py
git commit -m "docs(core): close m0 foundation baseline"
```

---

## M0 最终验收

- [ ] Domain 无框架依赖（test_architecture_boundaries 通过）
- [ ] Project、Scope、Assessment、Plan、Approval 有严格类型（mypy strict 通过）
- [ ] Scope、Plan、Approval digest 稳定（canonical_digest 测试通过）
- [ ] Deny 优先于 Allow，Destructive 永久拒绝（policy 测试通过）
- [ ] Audit hash chain 篡改可检测（audit verify_chain 测试通过）
- [ ] SQLite WAL/foreign_keys/busy_timeout 生效（sqlite 测试通过）
- [ ] Repository Contract 同 digest 幂等、不同 digest 冲突（contract 测试通过）
- [ ] 旧测试无回归（若有）
- [ ] 新测试逐项 RED -> GREEN
- [ ] ruff/mypy/compileall/diff check 通过
- [ ] README、core-boundaries 文档一致

## 下一步

M0 通过代码审查后，读取实际落地的 ScopeSnapshot、PolicyDecision、ExecutionPlan、Approval、AuditEvent、Repository Protocol 和 Error Model，再编写 M1 知识层+情报+四域 Adapter 详细计划。禁止在 M0 提前实现 MCP、Python Plugin、漏洞情报、Web 控制台、Adapter Pack。

M1 关键依赖（M0 须稳定输出）：
- ScopeSnapshot（Adapter Pack 的 scope 强制基础）
- PolicyDecision + RiskClass（Adapter risk_class 校验）
- Repository Contract（TestCatalog/IntelStore 持久化基础）
- AuditEvent hash chain（全程审计基础）
