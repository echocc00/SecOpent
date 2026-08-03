# P1b 工程内化 Implementation Plan（Shannon 模式重写，零代码复制）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 把 Shannon 的三个工程模式重写为 SecOpent 内部能力：① 阶段级工作状态快照与失败回滚；② 灰盒测试 preflight 凭据验证 + 登录态复用；③ 执行阶段产物（deliverables）文件契约。

**Architecture:** 全部落在确定性层：快照是 Job 生命周期的 tar 归档（evidence_store 同款 CAS 落盘），preflight 是 case 引擎执行前的确定性断言步骤（不用 LLM），deliverables 是 schema 化目录约定 + 校验器。不复制任何 Shannon 代码（AGPL），仅模式重写（spec §7 / 设计决策 D2）。

**Tech Stack:** Python 3.12, tarfile, pytest；无新框架依赖。

**Spec:** `docs/superpowers/specs/2026-08-04-strix-shannon-layered-integration-design.md` §7

**前置：** 无（独立并行）。与 P0 无耦合。

---

## 文件结构

| 文件 | 职责 | 动作 |
|------|------|------|
| `src/secopent/application/checkpoint.py` | CheckpointService：阶段快照/回滚 | 新建 |
| `src/secopent/infrastructure/safety/workspace_snapshot.py` | tar 快照 IO（创建/恢复/列表） | 新建 |
| `src/secopent/application/preflight.py` | 凭据预检 + 登录态持久化端口 | 新建 |
| `src/secopent/domain/cases/preflight.py` | PreflightSpec domain 模型（凭据类型/TOTP 标志） | 新建 |
| `src/secopent/application/deliverables.py` | Deliverables 目录契约 + 校验器 | 新建 |
| `tests/application/test_checkpoint_service.py` | 快照/回滚单测 | 新建 |
| `tests/application/test_preflight.py` | preflight 单测（fake http 端口） | 新建 |
| `tests/application/test_deliverables.py` | 契约校验单测 | 新建 |
| `docs/architecture/checkpoint-preflight.md` | 架构文档 | 新建 |
| `README.md` | Reference docs 链接 | 修改 |

---

## Task 1：工作区快照 IO（infrastructure）

- [ ] **1.1 写失败测试** `tests/infrastructure/test_workspace_snapshot.py`：

```python
# tests/infrastructure/test_workspace_snapshot.py
"""Workspace snapshot IO (P1b Task 1) - tar-based, deterministic."""
from __future__ import annotations

from pathlib import Path

from secopent.infrastructure.safety.workspace_snapshot import (
    WorkspaceSnapshotStore,
    SnapshotMissing,
)


class TestSnapshotRoundtrip:
    def test_create_and_restore_restores_file_contents(self, tmp_path: Path) -> None:
        workdir = tmp_path / "work"
        (workdir / "sub").mkdir(parents=True)
        (workdir / "a.txt").write_text("v1", encoding="utf-8")
        (workdir / "sub" / "b.txt").write_text("v2", encoding="utf-8")
        store = WorkspaceSnapshotStore(root=tmp_path / "snapshots")

        snap_id = store.create("job-1", "phase-recon", workdir)

        # 修改工作区后恢复，应回到快照状态
        (workdir / "a.txt").write_text("TAMPERED", encoding="utf-8")
        (workdir / "sub" / "b.txt").unlink()
        store.restore(snap_id, workdir)
        assert (workdir / "a.txt").read_text(encoding="utf-8") == "v1"
        assert (workdir / "sub" / "b.txt").read_text(encoding="utf-8") == "v2"

    def test_restore_unknown_snapshot_raises(self, tmp_path: Path) -> None:
        import pytest

        store = WorkspaceSnapshotStore(root=tmp_path / "snapshots")
        with pytest.raises(SnapshotMissing):
            store.restore("nope", tmp_path)

    def test_list_returns_snapshots_for_job(self, tmp_path: Path) -> None:
        workdir = tmp_path / "work"
        workdir.mkdir()
        (workdir / "f.txt").write_text("x", encoding="utf-8")
        store = WorkspaceSnapshotStore(root=tmp_path / "snapshots")
        store.create("job-1", "phase-a", workdir)
        store.create("job-1", "phase-b", workdir)
        store.create("job-2", "phase-a", workdir)
        phases = [s.phase for s in store.list_for_job("job-1")]
        assert phases == ["phase-a", "phase-b"]

    def test_create_excludes_snapshot_dir_and_vcs(self, tmp_path: Path) -> None:
        workdir = tmp_path / "work"
        (workdir / ".git").mkdir(parents=True)
        (workdir / ".git" / "HEAD").write_text("ref", encoding="utf-8")
        (workdir / "keep.txt").write_text("k", encoding="utf-8")
        store = WorkspaceSnapshotStore(root=tmp_path / "snapshots")
        snap_id = store.create("job-1", "phase-a", workdir)
        # 恢复到新目录验证 .git 未被打包
        target = tmp_path / "restored"
        target.mkdir()
        store.restore(snap_id, target)
        assert not (target / ".git").exists()
        assert (target / "keep.txt").exists()
```

- [ ] **1.2 运行确认失败** → 1.3 **实现** `src/secopent/infrastructure/safety/workspace_snapshot.py`：

```python
# src/secopent/infrastructure/safety/workspace_snapshot.py
"""Workspace snapshots: phase-level tar archives for rollback (spec §7).

Inspired by Shannon's git checkpoint/rollback pattern, rewritten on plain
tar archives (no git dependency in the execution workspace, no AGPL code).
Snapshots exclude VCS metadata; restore wipes the target dir's contents
before extracting so removed files do not survive.
"""
from __future__ import annotations

import tarfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from ...domain.common.errors import DomainError

_EXCLUDED_DIRS = {".git", ".hg", ".svn", "__pycache__", ".shannon"}


class SnapshotMissing(DomainError):
    """The snapshot id does not exist in the store."""


@dataclass(frozen=True, slots=True)
class SnapshotRef:
    id: str
    job_id: str
    phase: str
    path: Path


class WorkspaceSnapshotStore:
    """Tar-based snapshot store rooted at ``root`` (one .tar.gz per snapshot)."""

    def __init__(self, *, root: Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def create(self, job_id: str, phase: str, workdir: Path) -> str:
        snap_id = f"snap-{job_id}-{phase}-{uuid.uuid4().hex[:8]}"
        archive = self._root / f"{snap_id}.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for child in sorted(workdir.iterdir()):
                if child.name in _EXCLUDED_DIRS:
                    continue
                tar.add(child, arcname=child.name)
        return snap_id

    def restore(self, snap_id: str, workdir: Path) -> None:
        archive = self._root / f"{snap_id}.tar.gz"
        if not archive.exists():
            raise SnapshotMissing(f"snapshot not found: {snap_id}")
        workdir.mkdir(parents=True, exist_ok=True)
        for child in workdir.iterdir():
            _remove(child)
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(workdir, filter="data")  # noqa: S202 - filtered

    def list_for_job(self, job_id: str) -> tuple[SnapshotRef, ...]:
        refs: list[SnapshotRef] = []
        for archive in sorted(self._root.glob("snap-*.tar.gz")):
            parts = archive.stem.split("-")
            # snap-<job...>-<phase...>-<rand>: job may contain '-', so match by prefix
            if archive.stem.startswith(f"snap-{job_id}-"):
                phase = "-".join(parts[1 + len(job_id.split("-")):-1])
                refs.append(SnapshotRef(
                    id=archive.stem, job_id=job_id, phase=phase, path=archive,
                ))
        return tuple(refs)


def _remove(child: Path) -> None:
    if child.is_dir():
        import shutil

        shutil.rmtree(child)
    else:
        child.unlink()
```

- [ ] **1.4 运行确认通过** → **1.5 提交**：`feat(infra): tar-based workspace snapshot store (P1b Task 1)`

---

## Task 2：CheckpointService（Job 生命周期接线）

- [ ] **2.1 写失败测试** `tests/application/test_checkpoint_service.py`：

```python
# tests/application/test_checkpoint_service.py
"""CheckpointService: phase snapshot + rollback on failure (P1b Task 2)."""
from __future__ import annotations

from pathlib import Path

import pytest

from secopent.application.checkpoint import (
    CheckpointService,
    PhaseFailedError,
)
from secopent.infrastructure.safety.workspace_snapshot import (
    WorkspaceSnapshotStore,
)


def _service(tmp_path: Path) -> CheckpointService:
    return CheckpointService(
        snapshots=WorkspaceSnapshotStore(root=tmp_path / "snaps"),
    )


class TestCheckpointPhase:
    def test_successful_phase_commits_and_returns_none(self, tmp_path) -> None:
        service = _service(tmp_path)
        workdir = tmp_path / "work"
        workdir.mkdir()
        (workdir / "f.txt").write_text("ok", encoding="utf-8")

        result = service.run_phase(
            job_id="job-1", phase="recon", workdir=workdir,
            action=lambda wdir: None,
        )
        assert result.rolled_back is False
        assert result.snapshot_id  # 快照已记录

    def test_failed_phase_rolls_back_workspace(self, tmp_path) -> None:
        service = _service(tmp_path)
        workdir = tmp_path / "work"
        workdir.mkdir()
        (workdir / "f.txt").write_text("before", encoding="utf-8")

        def break_phase(wdir: Path) -> None:
            (wdir / "f.txt").write_text("CORRUPTED", encoding="utf-8")
            raise ValueError("phase exploded")

        with pytest.raises(PhaseFailedError):
            service.run_phase(
                job_id="job-1", phase="exploit", workdir=workdir,
                action=break_phase,
            )
        assert (workdir / "f.txt").read_text(encoding="utf-8") == "before"

    def test_original_exception_is_chained(self, tmp_path) -> None:
        service = _service(tmp_path)
        workdir = tmp_path / "work"
        workdir.mkdir()

        def boom(wdir: Path) -> None:
            raise KeyError("root cause")

        with pytest.raises(PhaseFailedError) as excinfo:
            service.run_phase(
                job_id="job-1", phase="x", workdir=workdir, action=boom,
            )
        assert isinstance(excinfo.value.__cause__, KeyError)
```

- [ ] **2.2 运行确认失败** → 2.3 **实现** `src/secopent/application/checkpoint.py`：

```python
# src/secopent/application/checkpoint.py
"""CheckpointService: phase-level snapshot/rollback for job execution (§7).

Wraps one phase of job execution: snapshot BEFORE, run the action, and on
any exception restore the snapshot and re-raise as PhaseFailedError (with
the original chained). Successful phases keep their snapshot as the next
phase's rollback point (list retained; pruning is ops policy).

Deterministic layer - no LLM involvement (LLM边界).
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..domain.common.errors import DomainError
from ..infrastructure.safety.workspace_snapshot import WorkspaceSnapshotStore


class PhaseFailedError(DomainError):
    """A phase raised; the workspace was rolled back to the phase start."""


@dataclass(frozen=True, slots=True)
class PhaseResult:
    snapshot_id: str
    rolled_back: bool


class CheckpointService:
    """Snapshot-run-rollback wrapper around phase actions."""

    def __init__(self, *, snapshots: WorkspaceSnapshotStore) -> None:
        self._snapshots = snapshots

    def run_phase(
        self,
        *,
        job_id: str,
        phase: str,
        workdir: Path,
        action: Callable[[Path], None],
    ) -> PhaseResult:
        snapshot_id = self._snapshots.create(job_id, phase, workdir)
        try:
            action(workdir)
        except Exception as exc:
            self._snapshots.restore(snapshot_id, workdir)
            raise PhaseFailedError(
                f"phase '{phase}' of job '{job_id}' failed; workspace "
                f"rolled back to snapshot {snapshot_id}"
            ) from exc
        return PhaseResult(snapshot_id=snapshot_id, rolled_back=False)
```

- [ ] **2.4 运行确认通过** → **2.5 提交**：`feat(app): CheckpointService phase snapshot+rollback (P1b Task 2)`

---

## Task 3：PreflightSpec domain 模型

- [ ] **3.1 写失败测试** `tests/domain/test_preflight_spec.py`：

```python
# tests/domain/test_preflight_spec.py
"""PreflightSpec domain model (P1b Task 3)."""
from __future__ import annotations

import pytest

from secopent.domain.cases.preflight import (
    PreflightSpec,
    CredentialKind,
)
from secopent.domain.common.errors import DomainValidationError


class TestPreflightSpec:
    def test_builds_with_form_credentials(self) -> None:
        spec = PreflightSpec(
            login_url="http://host.docker.internal:3000/#/login",
            credential_kind=CredentialKind.FORM,
            username_field="email",
            password_field="password",
            success_marker="myAccount",
        )
        assert spec.requires_totp is False

    def test_requires_login_url(self) -> None:
        with pytest.raises(DomainValidationError):
            PreflightSpec(
                login_url="",
                credential_kind=CredentialKind.FORM,
                username_field="u",
                password_field="p",
                success_marker="ok",
            )

    def test_totp_requires_secret_reference(self) -> None:
        with pytest.raises(DomainValidationError):
            PreflightSpec(
                login_url="http://t/login",
                credential_kind=CredentialKind.FORM,
                username_field="u",
                password_field="p",
                success_marker="ok",
                requires_totp=True,
                totp_secret_ref="",  # 引用 secrets store 的键名，不能为空
            )
```

- [ ] **3.2 运行确认失败** → 3.3 **实现** `src/secopent/domain/cases/preflight.py`：

```python
# src/secopent/domain/cases/preflight.py
"""PreflightSpec: deterministic gray-box credential pre-check (§7).

Modeled on Shannon's validate-authentication + state-save pattern, rewritten:
before any authenticated case runs, the platform verifies the credentials
work (deterministic form submit + success marker assertion - no LLM) and
persists the authenticated session for case reuse. Secrets themselves live
in the secret store; this spec only carries FIELD NAMES and a secret-store
reference (never secret values - M5 rule).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..common.errors import DomainValidationError


class CredentialKind(StrEnum):
    FORM = "form"
    API_TOKEN = "api_token"
    BEARER = "bearer"


@dataclass(frozen=True, slots=True)
class PreflightSpec:
    """What the preflight check needs to verify credentials deterministically."""

    login_url: str
    credential_kind: CredentialKind
    username_field: str
    password_field: str
    success_marker: str  # substring/selector expected ONLY on successful auth
    requires_totp: bool = False
    totp_secret_ref: str = ""  # secret-store key name, not the secret
    session_state_ref: str = "default"  # key under which session is reused

    def __post_init__(self) -> None:
        if not self.login_url:
            raise DomainValidationError(
                "PreflightSpec.login_url must be non-empty"
            )
        if not self.success_marker:
            raise DomainValidationError(
                "PreflightSpec.success_marker must be non-empty"
            )
        if self.requires_totp and not self.totp_secret_ref:
            raise DomainValidationError(
                "PreflightSpec.totp_secret_ref required when requires_totp"
            )
```

- [ ] **3.4 运行确认通过** → **3.5 提交**：`feat(domain): PreflightSpec for gray-box credential checks (P1b Task 3)`

---

## Task 4：PreflightService（确定性验证 + 会话复用端口）

- [ ] **4.1 写失败测试** `tests/application/test_preflight.py`：

```python
# tests/application/test_preflight.py
"""PreflightService (P1b Task 4): deterministic credential verification."""
from __future__ import annotations

import pytest

from secopent.application.preflight import (
    AuthDriver,
    PreflightOutcome,
    PreflightService,
)
from secopent.domain.cases.preflight import CredentialKind, PreflightSpec


class FakeAuthDriver:
    """Records login attempts; returns canned results."""

    def __init__(self, *, succeeds: bool, page_text: str = "welcome myAccount") -> None:
        self.succeeds = succeeds
        self.page_text = page_text
        self.attempts: list[str] = []
        self.saved_states: list[str] = []

    def submit_login(self, spec: PreflightSpec, username: str, password: str,
                     totp: str | None) -> str:
        self.attempts.append(spec.login_url)
        if not self.succeeds:
            return "Invalid credentials"
        return self.page_text

    def save_session(self, spec: PreflightSpec) -> None:
        self.saved_states.append(spec.session_state_ref)


def _spec() -> PreflightSpec:
    return PreflightSpec(
        login_url="http://host.docker.internal:3000/#/login",
        credential_kind=CredentialKind.FORM,
        username_field="email",
        password_field="password",
        success_marker="myAccount",
    )


class TestPreflight:
    def test_success_when_marker_present(self) -> None:
        driver = FakeAuthDriver(succeeds=True)
        service = PreflightService(driver=driver)
        outcome = service.verify(
            spec=_spec(), username="u@example.com", password="pw", secret_lookup={},
        )
        assert outcome is PreflightOutcome.SUCCESS
        assert driver.saved_states == ["default"]  # 登录态已保存供复用

    def test_failure_when_marker_absent(self) -> None:
        driver = FakeAuthDriver(succeeds=False)
        service = PreflightService(driver=driver)
        outcome = service.verify(
            spec=_spec(), username="u", password="bad", secret_lookup={},
        )
        assert outcome is PreflightOutcome.FAILURE
        assert driver.saved_states == []  # 失败不保存会话

    def test_totp_code_fetched_from_secret_lookup(self) -> None:
        from secopent.domain.cases.preflight import PreflightSpec as PS

        spec = PS(
            login_url="http://t/login", credential_kind=CredentialKind.FORM,
            username_field="u", password_field="p", success_marker="ok",
            requires_totp=True, totp_secret_ref="vault://target/totp",
        )
        driver = FakeAuthDriver(succeeds=True, page_text="ok")
        service = PreflightService(driver=driver)
        outcome = service.verify(
            spec=spec, username="u", password="p",
            secret_lookup={"vault://target/totp": "JBSWY3DPEHPK3PXP"},
        )
        assert outcome is PreflightOutcome.SUCCESS

    def test_missing_totp_secret_is_error_not_failure(self) -> None:
        from secopent.domain.cases.preflight import PreflightSpec as PS

        spec = PS(
            login_url="http://t/login", credential_kind=CredentialKind.FORM,
            username_field="u", password_field="p", success_marker="ok",
            requires_totp=True, totp_secret_ref="vault://target/totp",
        )
        service = PreflightService(driver=FakeAuthDriver(succeeds=True))
        with pytest.raises(KeyError):
            service.verify(spec=spec, username="u", password="p", secret_lookup={})

    def test_exactly_one_attempt_no_retry(self) -> None:
        # Shannon 规则：任何拒绝 = 认证错误，不重试
        driver = FakeAuthDriver(succeeds=False)
        service = PreflightService(driver=driver)
        service.verify(spec=_spec(), username="u", password="p", secret_lookup={})
        assert len(driver.attempts) == 1
```

- [ ] **4.2 运行确认失败** → 4.3 **实现** `src/secopent/application/preflight.py`：

```python
# src/secopent/application/preflight.py
"""PreflightService: deterministic credential verification (spec §7).

One attempt, no retry (any rejection = auth error, mirroring the proven
Shannon rule). On success the driver persists the authenticated session so
authenticated cases reuse it instead of logging in again. TOTP codes are
generated from the secret-store value (RFC 6238) at verify time.

The AuthDriver Protocol is inline so the application layer stays free of
browser/http coupling (real driver = P2 wiring or case-engine adapter).
"""
from __future__ import annotations

from enum import StrEnum
from typing import Protocol, runtime_checkable

from ..domain.cases.preflight import PreflightSpec


class PreflightOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"


@runtime_checkable
class AuthDriver(Protocol):
    def submit_login(
        self,
        spec: PreflightSpec,
        username: str,
        password: str,
        totp: str | None,
    ) -> str:
        """Submit credentials once; return the response page/body text."""
        ...

    def save_session(self, spec: PreflightSpec) -> None:
        """Persist the authenticated session for case reuse."""
        ...


def _totp_now(secret_b32: str) -> str:
    """RFC 6238 6-digit code (30s step, sha1) - stdlib only."""
    import hmac
    import hashlib
    import struct
    import time
    import base64

    key = base64.b32decode(secret_b32, casefold=True)
    counter = int(time.time() // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 1_000_000:06d}"


class PreflightService:
    """Verify gray-box credentials deterministically before case execution."""

    def __init__(self, *, driver: AuthDriver) -> None:
        self._driver = driver

    def verify(
        self,
        *,
        spec: PreflightSpec,
        username: str,
        password: str,
        secret_lookup: dict[str, str],
    ) -> PreflightOutcome:
        totp: str | None = None
        if spec.requires_totp:
            secret = secret_lookup[spec.totp_secret_ref]  # KeyError 上抛（配置错误≠认证失败）
            totp = _totp_now(secret)
        page = self._driver.submit_login(spec, username, password, totp)
        if spec.success_marker not in page:
            return PreflightOutcome.FAILURE
        self._driver.save_session(spec)
        return PreflightOutcome.SUCCESS
```

- [ ] **4.4 运行确认通过** → **4.5 提交**：`feat(app): deterministic preflight credential verification (P1b Task 4)`

---

## Task 5：Deliverables 文件契约

- [ ] **5.1 写失败测试** `tests/application/test_deliverables.py`：

```python
# tests/application/test_deliverables.py
"""Deliverables directory contract (P1b Task 5)."""
from __future__ import annotations

from pathlib import Path

import pytest

from secopent.application.deliverables import (
    DeliverablesLayout,
    DeliverableValidationError,
    read_deliverable,
    validate_layout,
    write_deliverable,
)


class TestLayout:
    def test_phase_paths_are_deterministic(self, tmp_path: Path) -> None:
        layout = DeliverablesLayout(root=tmp_path)
        assert layout.deliverable_path("recon") == tmp_path / "deliverables" / "recon_deliverable.md"
        assert layout.scratchpad_dir() == tmp_path / "scratchpad"

    def test_write_then_read_roundtrip(self, tmp_path: Path) -> None:
        layout = DeliverablesLayout(root=tmp_path)
        write_deliverable(layout, "recon", "# Recon\n- endpoint /api\n")
        assert read_deliverable(layout, "recon").startswith("# Recon")

    def test_validate_rejects_missing_required_phase(self, tmp_path: Path) -> None:
        layout = DeliverablesLayout(root=tmp_path)
        write_deliverable(layout, "recon", "x")
        with pytest.raises(DeliverableValidationError):
            validate_layout(layout, required_phases=("recon", "report"))

    def test_validate_rejects_empty_deliverable(self, tmp_path: Path) -> None:
        layout = DeliverablesLayout(root=tmp_path)
        write_deliverable(layout, "recon", "   \n")
        with pytest.raises(DeliverableValidationError):
            validate_layout(layout, required_phases=("recon",))

    def test_validate_accepts_complete_layout(self, tmp_path: Path) -> None:
        layout = DeliverablesLayout(root=tmp_path)
        write_deliverable(layout, "recon", "content")
        write_deliverable(layout, "report", "content")
        validate_layout(layout, required_phases=("recon", "report"))  # no raise
```

- [ ] **5.2 运行确认失败** → 5.3 **实现** `src/secopent/application/deliverables.py`：

```python
# src/secopent/application/deliverables.py
"""Deliverables contract: structured phase outputs on disk (spec §7).

Adopts Shannon's deliverables convention (rewritten): every execution phase
writes ONE markdown deliverable at a deterministic path
(``deliverables/<phase>_deliverable.md``) plus a scratchpad dir for
intermediate artifacts. Deterministic paths make phase handoffs auditable
and give LLM proposal steps structured context without scraping logs.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ..domain.common.errors import DomainError


class DeliverableValidationError(DomainError):
    """A required deliverable is missing or empty."""


@dataclass(frozen=True, slots=True)
class DeliverablesLayout:
    root: Path

    def deliverable_path(self, phase: str) -> Path:
        return Path(self.root) / "deliverables" / f"{phase}_deliverable.md"

    def scratchpad_dir(self) -> Path:
        return Path(self.root) / "scratchpad"


def write_deliverable(layout: DeliverablesLayout, phase: str, content: str) -> None:
    path = layout.deliverable_path(phase)
    path.parent.mkdir(parents=True, exist_ok=True)
    layout.scratchpad_dir().mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def read_deliverable(layout: DeliverablesLayout, phase: str) -> str:
    return layout.deliverable_path(phase).read_text(encoding="utf-8")


def validate_layout(
    layout: DeliverablesLayout, *, required_phases: Iterable[str]
) -> None:
    for phase in required_phases:
        path = layout.deliverable_path(phase)
        if not path.exists():
            raise DeliverableValidationError(
                f"missing deliverable for phase '{phase}': {path}"
            )
        if not path.read_text(encoding="utf-8").strip():
            raise DeliverableValidationError(
                f"empty deliverable for phase '{phase}': {path}"
            )
```

- [ ] **5.4 运行确认通过** → **5.5 提交**：`feat(app): deliverables directory contract (P1b Task 5)`

---

## Task 6：架构文档 + 质量门

- [ ] **6.1 新建** `docs/architecture/checkpoint-preflight.md`：三项能力的定位、与 Job Lease/drift detection 的衔接、preflight 的 secret 边界（只引用不携带）、模式来源声明（"借鉴 Shannon 模式，独立重写，无代码复制，AGPL 合规"）。
- [ ] **6.2 修改** `README.md` Reference docs 追加链接。
- [ ] **6.3 全量质量门**：`py -3.12 -m pytest -q` + `ruff check src tests` + `mypy src` + `git diff --check`。
- [ ] **6.4 提交**：`docs: checkpoint/preflight/deliverables architecture (P1b)`

---

## DoD

- [ ] 阶段失败 → 工作区自动回滚到阶段开始状态（Task 2 集成语义）
- [ ] 快照排除 VCS/缓存目录；恢复先清空目标目录
- [ ] preflight：成功保存会话、失败不保存、恰好一次尝试、TOTP 缺失报配置错误而非认证失败
- [ ] deliverables：确定性路径、空文件/缺失阶段拒绝
- [ ] 全量测试 + lint + type 绿；边界测试不破坏（application 无框架导入）
- [ ] 独立提交序列

## 已知注意

- `run_phase` 的 `action` 是同步 callable；真实 case 引擎接线在后续里程碑（本计划交付可注入的能力单元）。
- tar 恢复使用 `filter="data"` 防路径穿越（Python 3.12 tarfile 安全接口）。
