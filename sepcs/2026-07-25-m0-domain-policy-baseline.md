# M0 Domain and Policy Baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立新 Domain/Application/Infrastructure 基线，实现 Project、不可变 Scope、Assessment/Plan/Approval、确定性 Policy 和 SQLite WAL，同时保持旧测试通过。

**Architecture:** 使用 dataclass Domain、Application ports 和 SQLAlchemy Infrastructure。Digest 使用规范 JSON + SHA-256；Domain 不依赖框架。旧 `app` 通过只读兼容层映射，M0 不删除旧表和 API。

**Tech Stack:** Python 3.11/3.12, dataclasses, enum, ipaddress, urllib.parse, hashlib, SQLAlchemy 2, SQLite WAL, pytest, mypy, ruff.

---

## 1. 文件结构

```text
src/secopent/domain/
  common/{canonical.py,errors.py}
  projects/models.py
  scope/{models.py,normalize.py}
  policy/{models.py,engine.py}
  assessments/models.py
src/secopent/application/
  ports/repositories.py
  projects.py
  scopes.py
  assessments.py
src/secopent/infrastructure/
  db/{core_models.py,sqlite.py}
  repositories/sqlalchemy_core.py
  compatibility/legacy.py
tests/domain/
tests/application/
tests/infrastructure/
tests/test_architecture_boundaries.py
```

M0 不修改 Adapter、Connector、报告模板或旧 Phase 2 临时脚本。

### Task 1: 包边界和依赖守卫

**Files:**
- Create: `src/secopent/domain/__init__.py`
- Create: `src/secopent/application/__init__.py`
- Create: `src/secopent/infrastructure/__init__.py`
- Create: `tests/test_architecture_boundaries.py`

- [ ] **Step 1: 写失败测试**

```python
from __future__ import annotations
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "secopent"
FORBIDDEN = {"fastapi", "sqlalchemy", "httpx", "docker", "mcp"}

def test_domain_does_not_import_frameworks():
    domain = ROOT / "domain"
    assert domain.is_dir(), "new domain package is missing"
    violations = []
    for path in domain.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [item.name.split(".")[0] for item in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".")[0]]
            for name in names:
                if name in FORBIDDEN:
                    violations.append(f"{path.relative_to(ROOT)} imports {name}")
    assert violations == []
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/test_architecture_boundaries.py`

Expected: FAIL，`new domain package is missing`。

- [ ] **Step 3: 创建最小包**

```python
# domain/__init__.py
"""Framework-independent domain model for SecOpent."""
# application/__init__.py
"""Application use cases and ports."""
# infrastructure/__init__.py
"""Infrastructure adapters for application ports."""
```

创建文件结构中所有目录的 `__init__.py`。

- [ ] **Step 4: 运行 GREEN**

Run: `py -3.12 -m pytest -q tests/test_architecture_boundaries.py tests/test_python_syntax.py`

Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/domain src/secopent/application src/secopent/infrastructure tests/test_architecture_boundaries.py
git commit -m "refactor(core): establish domain application boundaries"
```

### Task 2: 规范 JSON、Digest 和 Domain Error

**Files:**
- Create: `src/secopent/domain/common/canonical.py`
- Create: `src/secopent/domain/common/errors.py`
- Test: `tests/domain/test_canonical.py`

- [ ] **Step 1: 写失败测试**

```python
from datetime import datetime
import pytest
from secopent.domain.common.canonical import canonical_digest, canonical_json, utc_now
from secopent.domain.common.errors import DomainValidationError

def test_digest_ignores_dict_insertion_order():
    left = {"b": [2, 1], "a": "é"}
    right = {"a": "é", "b": [2, 1]}
    assert canonical_json(left) == '{"a":"é","b":[2,1]}'
    assert canonical_digest(left) == canonical_digest(right)

def test_rejects_naive_datetime():
    with pytest.raises(DomainValidationError, match="timezone-aware"):
        canonical_json({"at": datetime(2026, 7, 25)})

def test_utc_now_is_aware():
    assert utc_now().tzinfo is not None
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/domain/test_canonical.py`

Expected: import FAIL。

- [ ] **Step 3: 实现**

```python
# errors.py
class DomainError(Exception):
    """Base deterministic domain error."""
class DomainValidationError(DomainError, ValueError):
    """Input cannot be normalized safely."""
```

```python
# canonical.py
import hashlib, json
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from .errors import DomainValidationError

def utc_now(): return datetime.now(UTC)
def _default(value):
    if is_dataclass(value): return asdict(value)
    if isinstance(value, Enum): return value.value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise DomainValidationError("datetime must be timezone-aware")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, (tuple, set, frozenset)):
        return sorted(value) if not isinstance(value, tuple) else list(value)
    raise DomainValidationError(f"unsupported canonical value: {type(value).__name__}")
def canonical_json(value):
    return json.dumps(value, default=_default, ensure_ascii=False,
                      sort_keys=True, separators=(",", ":"), allow_nan=False)
def canonical_digest(value):
    return "sha256:" + hashlib.sha256(canonical_json(value).encode()).hexdigest()
```

- [ ] **Step 4: 运行 GREEN**

Run: `py -3.12 -m pytest -q tests/domain/test_canonical.py`

Expected: 3 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/domain/common tests/domain/test_canonical.py
git commit -m "feat(core): add canonical domain digests"
```

### Task 3: Project Domain

**Files:**
- Create: `src/secopent/domain/projects/models.py`
- Test: `tests/domain/test_projects.py`

- [ ] **Step 1: 写失败测试**

```python
import pytest
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.projects.models import Project, ProjectStatus

def test_project_create_normalizes_name():
    project = Project.create(project_id="project-1", name="  Lab Assessment  ")
    assert project.name == "Lab Assessment"
    assert project.status is ProjectStatus.ACTIVE
    assert project.created_at.tzinfo is not None

def test_project_rejects_empty_name():
    with pytest.raises(DomainValidationError, match="name"):
        Project.create(project_id="project-1", name="   ")
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/domain/test_projects.py`

Expected: import FAIL。

- [ ] **Step 3: 实现**

```python
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
    def create(cls, *, project_id, name):
        normalized = name.strip()
        if not project_id.strip() or not normalized:
            raise DomainValidationError("project id and name must not be empty")
        return cls(project_id, normalized, ProjectStatus.ACTIVE, utc_now())
```

- [ ] **Step 4: 运行 GREEN**

Run: `py -3.12 -m pytest -q tests/domain/test_projects.py`

Expected: 2 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/domain/projects tests/domain/test_projects.py
git commit -m "feat(core): add project domain"
```

### Task 4: Scope 规范化与不可变 Snapshot

**Files:**
- Create: `src/secopent/domain/scope/models.py`
- Create: `src/secopent/domain/scope/normalize.py`
- Test: `tests/domain/test_scope.py`

- [ ] **Step 1: 写失败测试**

```python
import pytest
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.scope.models import ScopeDraft, ScopeLimits

def test_scope_freeze_normalizes_and_prioritizes_deny():
    draft = ScopeDraft(
        project_id="project-1",
        include=("HTTPS://Example.Test:443/api", "192.0.2.0/28"),
        exclude=("https://example.test/api/admin", "192.0.2.7"),
        ports=(443, 8443),
        limits=ScopeLimits(5, 3, 1000),
    )
    snapshot = draft.freeze(snapshot_id="scope-1", approved_by="user-1")
    assert snapshot.includes_url("https://example.test/api/users")
    assert not snapshot.includes_url("https://example.test/api/admin/delete")
    assert snapshot.includes_ip("192.0.2.5")
    assert not snapshot.includes_ip("192.0.2.7")
    assert snapshot.digest.startswith("sha256:")

def test_scope_rejects_invalid_port_and_empty_include():
    with pytest.raises(DomainValidationError):
        ScopeDraft(project_id="p", include=(), ports=(0,))
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/domain/test_scope.py`

Expected: import FAIL。

- [ ] **Step 3: 实现公开接口**

将以下代码写入 `normalize.py`：

```python
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
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise DomainValidationError("URL must use http or https")
    host = normalize_domain(parsed.hostname)
    port = parsed.port
    if port == (443 if parsed.scheme.lower() == "https" else 80):
        port = None
    netloc = host if port is None else f"{host}:{port}"
    path = posixpath.normpath("/" + parsed.path.lstrip("/"))
    if parsed.path.endswith("/") and not path.endswith("/"):
        path += "/"
    return urlunsplit(SplitResult(parsed.scheme.lower(), netloc, path, parsed.query, ""))


def normalize_port(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise DomainValidationError("port must be between 1 and 65535")
    return value
```

将以下代码写入 `models.py`：

```python
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

    def __post_init__(self):
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
        return (not any(self._target_matches(rule, normalized) for rule in self.exclude)
                and any(self._target_matches(rule, normalized) for rule in self.include))

    def includes_domain(self, value: str) -> bool:
        normalized = normalize_domain(value)
        return (not any(self._target_matches(rule, normalized) for rule in self.exclude)
                and any(self._target_matches(rule, normalized) for rule in self.include))

    def includes_url(self, value: str) -> bool:
        normalized = normalize_url(value)
        host = urlsplit(normalized).hostname or ""
        def matches(rule):
            return normalized.startswith(rule) if rule.startswith(("http://", "https://")) \
                else self._target_matches(rule, host)
        return not any(matches(rule) for rule in self.exclude) and any(
            matches(rule) for rule in self.include)

    def includes_port(self, value: int) -> bool:
        return normalize_port(value) in self.ports


@dataclass(frozen=True, slots=True)
class ScopeDraft:
    project_id: str
    include: tuple[str, ...]
    exclude: tuple[str, ...] = ()
    ports: tuple[int, ...] = (80, 443)
    limits: ScopeLimits = ScopeLimits(5.0, 3, 50_000)

    def __post_init__(self):
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
        payload = {"id": snapshot_id, "project_id": self.project_id,
                   "include": include, "exclude": exclude, "ports": ports,
                   "limits": asdict(self.limits), "approved_by": approved_by,
                   "approved_at": approved_at}
        return ScopeSnapshot(snapshot_id, self.project_id, include, exclude, ports,
                             self.limits, approved_by, approved_at,
                             canonical_digest(payload))
```

Deny 必须先于 Allow；DNS I/O 不进入 Domain。

- [ ] **Step 4: 运行 GREEN**

Run: `py -3.12 -m pytest -q tests/domain/test_scope.py tests/test_scope.py`

Expected: 新旧测试全部 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/domain/scope tests/domain/test_scope.py
git commit -m "feat(core): add immutable scope snapshots"
```

### Task 5: 确定性 Policy Engine

**Files:**
- Create: `src/secopent/domain/policy/models.py`
- Create: `src/secopent/domain/policy/engine.py`
- Test: `tests/domain/test_policy.py`

- [ ] **Step 1: 写失败测试**

```python
from secopent.domain.policy.engine import ActionRequest, evaluate
from secopent.domain.policy.models import ExecutionMode, RiskClass

def test_policy_denies_scope_before_approval(scope_snapshot):
    decision = evaluate(
        ActionRequest("https://outside.test/", 443, RiskClass.LOW, "scoped_http"),
        scope=scope_snapshot,
        mode=ExecutionMode.SCOPE_AUTOPILOT,
        approved_risks=frozenset(RiskClass),
        approved_capabilities=frozenset({"scoped_http"}),
    )
    assert (decision.allowed, decision.reason) == (False, "SCOPE_DENIED")

def test_active_requires_capability(scope_snapshot):
    decision = evaluate(
        ActionRequest("https://example.test/api", 443, RiskClass.ACTIVE, "web_crawl"),
        scope=scope_snapshot,
        mode=ExecutionMode.APPROVAL,
        approved_risks=frozenset({RiskClass.LOW, RiskClass.ACTIVE}),
        approved_capabilities=frozenset(),
    )
    assert decision.reason == "CAPABILITY_NOT_APPROVED"

def test_destructive_is_never_allowed(scope_snapshot):
    decision = evaluate(
        ActionRequest("https://example.test/api", 443, RiskClass.DESTRUCTIVE, "delete_data"),
        scope=scope_snapshot,
        mode=ExecutionMode.SCOPE_AUTOPILOT,
        approved_risks=frozenset(RiskClass),
        approved_capabilities=frozenset({"delete_data"}),
    )
    assert decision.reason == "DESTRUCTIVE_ACTION_DENIED"
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/domain/test_policy.py`

Expected: import FAIL。

- [ ] **Step 3: 实现固定决策顺序**

```python
class RiskClass(StrEnum):
    PASSIVE="passive"; LOW="low"; ACTIVE="active"
    INTRUSIVE="intrusive"; DESTRUCTIVE="destructive"
class ExecutionMode(StrEnum):
    APPROVAL="approval"; SCOPE_AUTOPILOT="scope_autopilot"
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

def evaluate(request, *, scope, mode, approved_risks, approved_capabilities):
    if request.risk is RiskClass.DESTRUCTIVE:
        return PolicyDecision(False, "DESTRUCTIVE_ACTION_DENIED")
    if not scope.includes_port(request.port) or not scope.includes_url(request.target):
        return PolicyDecision(False, "SCOPE_DENIED")
    if request.risk not in approved_risks:
        return PolicyDecision(False, "RISK_NOT_APPROVED")
    if request.risk in {RiskClass.ACTIVE, RiskClass.INTRUSIVE}             and request.capability not in approved_capabilities:
        return PolicyDecision(False, "CAPABILITY_NOT_APPROVED")
    return PolicyDecision(True, "ALLOWED")
```

Policy 不调用网络或数据库。

- [ ] **Step 4: 运行 GREEN**

Run: `py -3.12 -m pytest -q tests/domain/test_policy.py tests/domain/test_scope.py`

Expected: 全部 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/domain/policy tests/domain/test_policy.py
git commit -m "feat(core): enforce deterministic assessment policy"
```

### Task 6: Assessment、Plan 和 Approval

**Files:**
- Create: `src/secopent/domain/assessments/models.py`
- Test: `tests/domain/test_assessments.py`

- [ ] **Step 1: 写失败测试**

```python
import pytest
from secopent.domain.assessments.models import Approval, Assessment, ExecutionPlan, PlanStep
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.policy.models import ExecutionMode, RiskClass

def test_plan_digest_changes_with_parameters():
    one = ExecutionPlan.create(plan_id="p1", assessment_id="a1", version=1,
        steps=(PlanStep("dns", "builtin:dns", RiskClass.LOW, {}, ()),))
    two = ExecutionPlan.create(plan_id="p2", assessment_id="a1", version=1,
        steps=(PlanStep("dns", "builtin:dns", RiskClass.LOW, {"timeout": 5}, ()),))
    assert one.digest != two.digest

def test_approval_requires_plan_and_scope_digest():
    with pytest.raises(DomainValidationError, match="digest"):
        Approval.create(approval_id="x", assessment_id="a", plan_digest="",
            scope_digest="", mode=ExecutionMode.APPROVAL,
            approved_risks=frozenset({RiskClass.LOW}),
            approved_capabilities=frozenset(), approved_by="u")

def test_assessment_cannot_start_without_approval():
    assessment = Assessment.create(assessment_id="a", project_id="p",
        scope_snapshot_id="s", mode=ExecutionMode.APPROVAL)
    with pytest.raises(DomainValidationError, match="approval"):
        assessment.start(plan_id="plan", approval_id=None)
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/domain/test_assessments.py`

Expected: import FAIL。

- [ ] **Step 3: 实现严格类型和状态转换**

```python
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from ..common.canonical import canonical_digest
from ..common.errors import DomainValidationError
from ..policy.models import ExecutionMode, RiskClass


class AssessmentStatus(StrEnum):
    DRAFT="draft"; PLANNED="planned"; AWAITING_APPROVAL="awaiting_approval"
    APPROVED="approved"; QUEUED="queued"; RUNNING="running"; PAUSED="paused"
    COMPLETED="completed"; PARTIAL="partial"; FAILED="failed"; CANCELLED="cancelled"


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
    def create(cls, *, plan_id, assessment_id, version, steps):
        if version < 1:
            raise DomainValidationError("plan version must be positive")
        keys = [step.key for step in steps]
        if len(keys) != len(set(keys)):
            raise DomainValidationError("plan step keys must be unique")
        known = set(keys)
        if any(set(step.dependencies) - known for step in steps):
            raise DomainValidationError("plan dependency does not exist")
        graph = {step.key: step.dependencies for step in steps}
        visiting, visited = set(), set()
        def visit(key):
            if key in visiting:
                raise DomainValidationError("plan dependency cycle")
            if key in visited:
                return
            visiting.add(key)
            for dependency in graph[key]:
                visit(dependency)
            visiting.remove(key); visited.add(key)
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
    def create(cls, *, approval_id, assessment_id, plan_digest, scope_digest,
               mode, approved_risks, approved_capabilities, approved_by):
        if not plan_digest or not scope_digest:
            raise DomainValidationError("approval requires plan and scope digest")
        payload = {"assessment_id": assessment_id, "plan_digest": plan_digest,
                   "scope_digest": scope_digest, "mode": mode,
                   "approved_risks": approved_risks,
                   "approved_capabilities": approved_capabilities,
                   "approved_by": approved_by}
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
    def create(cls, *, assessment_id, project_id, scope_snapshot_id, mode):
        if not all((assessment_id, project_id, scope_snapshot_id)):
            raise DomainValidationError("assessment identifiers are required")
        return cls(assessment_id, project_id, scope_snapshot_id, mode,
                   AssessmentStatus.DRAFT)

    def start(self, *, plan_id: str, approval_id: str | None):
        if not approval_id:
            raise DomainValidationError("assessment requires approval")
        if self.status not in {AssessmentStatus.DRAFT, AssessmentStatus.APPROVED}:
            raise DomainValidationError("assessment cannot start from current status")
        return replace(self, status=AssessmentStatus.QUEUED,
                       active_plan_id=plan_id, approval_id=approval_id)
```

所有状态转换返回新对象，禁止原地修改。

- [ ] **Step 4: 运行 GREEN**

Run: `py -3.12 -m pytest -q tests/domain/test_assessments.py`

Expected: 上述 3 项及 DAG 循环、重复 key 共至少 5 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/domain/assessments tests/domain/test_assessments.py
git commit -m "feat(core): add assessment plans and approvals"
```

### Task 7: Application Ports 与 Use Cases

**Files:**
- Create: `src/secopent/application/ports/repositories.py`
- Create: `src/secopent/application/projects.py`
- Create: `src/secopent/application/scopes.py`
- Create: `src/secopent/application/assessments.py`
- Test: `tests/application/test_scope_service.py`
- Test: `tests/application/test_assessment_service.py`

- [ ] **Step 1: 写失败测试**

```python
from secopent.application.assessments import AssessmentService
from secopent.application.scopes import ScopeService
from secopent.domain.policy.models import ExecutionMode

def test_freeze_scope_persists_snapshot(memory_repositories):
    snapshot = ScopeService(memory_repositories.scopes).freeze(
        project_id="p", include=("https://example.test",), exclude=(),
        ports=(443,), approved_by="u")
    assert memory_repositories.scopes.get_snapshot(snapshot.id) == snapshot

def test_attach_plan_moves_to_awaiting_approval(memory_repositories):
    service = AssessmentService(memory_repositories.assessments)
    assessment = service.create(project_id="p", scope_snapshot_id="s",
                                mode=ExecutionMode.APPROVAL)
    result = service.attach_plan(assessment.id, steps=())
    assert result.status.value == "awaiting_approval"
```

测试内用 dict 实现最小内存 Repository fixture。

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/application`

Expected: import FAIL。

- [ ] **Step 3: 定义 Ports 和服务**

```python
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
```

Application 负责 UUID、Repository 协调和 Domain 调用；Domain 不做 I/O。缺失实体抛 `ApplicationNotFoundError`，digest 不匹配抛 `ApplicationConflictError`。

- [ ] **Step 4: 运行 GREEN**

Run: `py -3.12 -m pytest -q tests/application tests/domain`

Expected: 全部 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/application tests/application
git commit -m "feat(core): add project scope assessment use cases"
```

### Task 8: SQLite WAL Repository Contract

**Files:**
- Create: `src/secopent/infrastructure/db/core_models.py`
- Create: `src/secopent/infrastructure/db/sqlite.py`
- Create: `src/secopent/infrastructure/repositories/sqlalchemy_core.py`
- Test: `tests/infrastructure/test_sqlite_wal.py`
- Test: `tests/infrastructure/test_core_repository_contract.py`

- [ ] **Step 1: 写失败测试**

```python
from sqlalchemy import text
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_core import SqlAlchemyScopeRepository

def test_sqlite_enables_wal_and_foreign_keys(tmp_path):
    engine = create_sqlite_engine(tmp_path / "secopent.db")
    with engine.connect() as connection:
        assert connection.execute(text("PRAGMA journal_mode")).scalar_one().lower() == "wal"
        assert connection.execute(text("PRAGMA foreign_keys")).scalar_one() == 1

def test_scope_repository_round_trip(sqlite_session, scope_snapshot):
    repo = SqlAlchemyScopeRepository(sqlite_session)
    repo.add_snapshot(scope_snapshot)
    sqlite_session.commit()
    assert repo.get_snapshot(scope_snapshot.id) == scope_snapshot
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/infrastructure/test_sqlite_wal.py tests/infrastructure/test_core_repository_contract.py`

Expected: import FAIL。

- [ ] **Step 3: 实现数据库**

使用独立 `CoreBase` 建 `core_projects/core_scope_snapshots/core_assessments/core_execution_plans/core_approvals`。JSON 保存 canonical JSON，digest 唯一索引。

```python
def create_sqlite_engine(path: Path) -> Engine:
    engine = create_engine(f"sqlite:///{path}",
        connect_args={"check_same_thread": False, "timeout": 5.0}, future=True)
    @event.listens_for(engine, "connect")
    def configure(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()
    return engine
```

Repository 对同 ID/同 digest 幂等，对同 ID/不同 digest 抛 `ApplicationConflictError`。

- [ ] **Step 4: 运行 GREEN 和并发测试**

增加两个 Session 读、一个短事务写的测试，不使用 sleep 同步。

Run: `py -3.12 -m pytest -q tests/infrastructure tests/application tests/domain`

Expected: 全部 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/infrastructure tests/infrastructure
git commit -m "feat(core): persist baseline in sqlite wal"
```

### Task 9: 旧模型只读兼容映射

**Files:**
- Create: `src/secopent/infrastructure/compatibility/legacy.py`
- Test: `tests/infrastructure/test_legacy_mapping.py`

- [ ] **Step 1: 写失败测试**

```python
from secopent.infrastructure.compatibility.legacy import engagement_to_project, run_to_assessment

def test_engagement_maps_without_mutation():
    source = {"id": "e-1", "name": "Legacy Lab", "status": "ACTIVE"}
    before = dict(source)
    assert engagement_to_project(source).name == "Legacy Lab"
    assert source == before

def test_run_requires_scope_snapshot():
    source = {"id": "r-1", "engagement_id": "e-1", "scope_snapshot_id": "s-1"}
    assessment = run_to_assessment(source)
    assert (assessment.project_id, assessment.scope_snapshot_id) == ("e-1", "s-1")
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/infrastructure/test_legacy_mapping.py`

Expected: import FAIL。

- [ ] **Step 3: 实现映射**

```python
def engagement_to_project(record: Mapping[str, object]) -> Project:
    return Project(id=str(record["id"]), name=str(record["name"]).strip(),
        status=ProjectStatus.ACTIVE, created_at=_legacy_timestamp(record.get("created_at")))

def run_to_assessment(record: Mapping[str, object]) -> Assessment:
    scope_id = str(record.get("scope_snapshot_id") or "").strip()
    if not scope_id:
        raise DomainValidationError("legacy run requires scope_snapshot_id")
    return Assessment.create(assessment_id=str(record["id"]),
        project_id=str(record["engagement_id"]), scope_snapshot_id=scope_id,
        mode=ExecutionMode.APPROVAL)
```

兼容层只读，不写回旧模型，新 Domain 不导入兼容层。

- [ ] **Step 4: 运行 GREEN 和旧回归**

Run: `py -3.12 -m pytest -q tests/infrastructure/test_legacy_mapping.py tests/test_e2e_demo.py tests/test_persistence.py`

Expected: 全部 PASS。

- [ ] **Step 5: 提交**

```bash
git add src/secopent/infrastructure/compatibility tests/infrastructure/test_legacy_mapping.py
git commit -m "refactor(core): map legacy records to new domain"
```

### Task 10: M0 质量门和文档同步

**Files:**
- Modify: `pyproject.toml`
- Modify: `README.md`
- Modify: `docs/roadmap.md`
- Create: `docs/architecture/core-boundaries.md`
- Modify: `tests/test_docs_consistency.py`

- [ ] **Step 1: 写失败的文档测试**

```python
def test_readme_points_to_agent_native_design_and_m0_plan():
    readme = Path("README.md").read_text(encoding="utf-8")
    assert "agent-native-pentest-workbench-design.md" in readme
    assert "2026-07-25-m0-domain-policy-baseline.md" in readme
```

- [ ] **Step 2: 运行 RED**

Run: `py -3.12 -m pytest -q tests/test_docs_consistency.py`

Expected: FAIL，README 未引用新设计/计划。

- [ ] **Step 3: 更新配置和文档**

```toml
[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "SIM"]
[[tool.mypy.overrides]]
module = ["secopent.domain.*", "secopent.application.*"]
strict = true
```

`core-boundaries.md` 记录依赖方向、ports、M0 表、兼容层和禁止依赖。修复 `docs/roadmap.md` 乱码；README 将“路线图未启动”替换为 Agent-native M0 状态。

- [ ] **Step 4: 运行完整质量门**

```powershell
py -3.12 -m pytest -q
py -3.12 -m compileall -q src tests adapters
py -3.12 -m ruff check src tests
py -3.12 -m mypy src/secopent/domain src/secopent/application
git diff --check
```

Expected: pytest 0 failed；compileall exit 0；ruff/mypy 0 errors；diff check 无输出。

- [ ] **Step 5: 跨 CWD 回归**

```powershell
py -3.12 -m pytest -q tests/domain tests/application tests/infrastructure
Push-Location tests; py -3.12 -m pytest -q domain application infrastructure; Pop-Location
Push-Location $HOME; py -3.12 -m pytest -q F:\codex\SecOpent	ests	est_workspace_root.py; Pop-Location
```

Expected: 三组 PASS。

- [ ] **Step 6: 提交收口**

```bash
git add pyproject.toml README.md docs tests/test_docs_consistency.py
git commit -m "docs(core): close m0 domain policy baseline"
```

## 2. M0 最终验收

- [ ] Domain 无框架依赖；
- [ ] Project、Scope、Assessment、Plan、Approval 有严格类型；
- [ ] Scope、Plan、Approval digest 稳定；
- [ ] Deny 优先于 Allow，Destructive 永久拒绝；
- [ ] Approval/Autopilot 共用 Policy；
- [ ] SQLite WAL/foreign keys/busy timeout 生效；
- [ ] Repository 同 digest 幂等、不同 digest 冲突；
- [ ] 旧模型映射只读；
- [ ] 旧 142 测试无回归；
- [ ] 新测试逐项 RED -> GREEN；
- [ ] ruff/mypy/compileall/diff check 通过；
- [ ] README、roadmap、架构文档一致。

## 3. 下一步

M0 通过代码审查后，读取实际落地的 ScopeSnapshot、PolicyDecision、ExecutionPlan、Approval、Repository Protocol 和 Error Model，再编写 M1 Worker/Tool Execution 详细计划。禁止在 M0 提前实现 MCP、Python Plugin、漏洞情报或 Web 控制台。
