# W2-C Secret Persistence + Verification Canary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 修两个"已建未接线/名不副实"的缺口：H4 SecretStore 真持久化（当前 `EncryptedFileBackend` 是内存 dict，重启丢密钥）；H5 canary token 真接线（当前 `RescanVerifier.reproduce` 忽略 `canary_token` 参数，`CanaryTokenManager.embed/verify_echo` 已实现但零调用）。

**Architecture:** H4：把 `PersistentEncryptedFileBackend` 提为默认 backend（带安全的默认路径 + env key 注入），`EncryptedFileBackend` 保留为显式 opt-in 的纯内存测试 backend；`SecretStore._metadata` 持久化到同一 store。H5：`CanaryTokenManager` 注入 `RescanVerifier.__init__`；`reproduce` 深拷贝 `_scan_kwargs`、用 `canary.embed` 替换 `{{canary_token}}` 占位、scan 后用 `canary.verify_echo` 校验回声，未回声即降级为 INCONCLUSIVE（非 CONFIRMED）。不改 domain 模型，只接线 application/infrastructure 层。

**Tech Stack:** Python 3.12, Fernet (cryptography), dataclasses, pytest, ruff, mypy strict。

**Spec:** 承继 `docs/superpowers/specs/2026-08-04-strix-shannon-layered-integration-design.md`；本计划对应验收报告 §四 第二波 Task 9-10（H4/H5）。

**计划拆分说明：** 第二波"接线"3 个计划（A 授权链 / B 沙箱 / C 密钥+canary）的最后一个。A、B 已交付。本计划独立，可随时立项。

---

## 现状映射（来自前置调研，无猜测）

| 组件 | 代码位置 | 当前状态 |
|------|----------|----------|
| `EncryptedFileBackend` | `infrastructure/secrets/encrypted_file_backend.py:13` | `__init__(key=None)`，`_store: dict[str,str]` 内存，`Fernet.generate_key()` 随机；无文件持久化 |
| `PersistentEncryptedFileBackend` | `infrastructure/secrets/persistent_file_backend.py:34` | `__init__(store_path, key_path)`，`_load_or_create_key`（读或生成+0600 写），`_flush` 写 JSON 0600。**已正确持久化**，但仅当两个 env 都设时才用 |
| `SecretBackend` Protocol | `application/secret_store.py:26` | `put/get/delete`；定义在 application 层（非 ports/，W2-A 同类问题） |
| `SecretStore._metadata` | `application/secret_store.py:43` | `dict[str, SecretMetadata]` 内存态，重启丢失（backend 密文还在但 metadata 丢） |
| `_build_secret_backend()` | `interfaces/api/main.py:147` | 两 env 都设 -> Persistent，否则 `EncryptedFileBackend()` 无参（内存） |
| `OracleEngine.verify` | `application/oracle.py:68` | 生成 `token = canary.generate(actor, candidate_id)`，传 `verifier.reproduce(canary_token=token)`。**生成+传递正确** |
| `RescanVerifier.reproduce` | `infrastructure/oracle/rescan_verifier.py:34` | `result = self._runner.scan(**self._scan_kwargs)`（构造时固化），**canary_token 被接收但完全忽略**；仅子串匹配 target vs asset_identity |
| `CanaryTokenManager` | `application/canary.py:46` | `generate/embed/oob_subdomain/verify_echo` 全实现；`CANARY_PLACEHOLDER = "{{canary_token}}"`。**embed/verify_echo 零调用** |
| `RealScanRunner.scan` | `infrastructure/adapters/real_scan.py:129` | `scan(adapter_key, *, args: list[str], ...)`；canary 可注入 args |

---

## 文件结构

| 文件 | 职责 | 动作 |
|------|------|------|
| `src/secopent/infrastructure/secrets/encrypted_file_backend.py` | 内存 backend（测试/显式 opt-in） | 修改（docstring 明确"非持久化"） |
| `src/secopent/infrastructure/secrets/persistent_file_backend.py` | 持久化 backend | 修改（支持 env key 注入 + 默认路径） |
| `src/secopent/application/secret_store.py` | SecretStore | 修改（_metadata 持久化 + Protocol 迁 ports） |
| `src/secopent/application/ports/secrets.py` | SecretBackend Protocol | 新建（从 secret_store.py 迁出） |
| `src/secopent/interfaces/api/main.py` | composition root | 修改（默认用 Persistent + key 注入） |
| `src/secopent/infrastructure/oracle/rescan_verifier.py` | RescanVerifier | 修改（注入 canary + embed + verify_echo） |
| `src/secopent/application/oracle.py` | OracleEngine | 修改（向 RescanVerifier 注入 canary） |
| `src/secopent/application/canary.py` | CanaryTokenManager | 不改（API 已就绪） |
| `tests/infrastructure/test_persistent_secret_backend.py` | 持久化 backend 单测 | 新建 |
| `tests/infrastructure/test_rescan_verifier_canary.py` | canary 接线单测 | 新建 |
| `tests/security/test_secret_persistence.py` | 跨重启持久化集成 | 新建 |
| `tests/oracle_ground_truth/test_canary_echo.py` | canary echo OOB 集成 | 新建 |

---

## Task 1：PersistentEncryptedFileBackend 支持 env key 注入 + 安全默认路径

当前 `_load_or_create_key` 自动生成 key 落盘（持久但非显式注入）。生产应从 `SECOPTENT_SECRET_KEY`（base64 Fernet key）注入；未设时回落到自动生成（dev）。

- [ ] **1.1 写失败测试** `tests/infrastructure/test_persistent_secret_backend.py`：

```python
# tests/infrastructure/test_persistent_secret_backend.py
"""PersistentEncryptedFileBackend: real file persistence + env key (W2-C T1)."""
from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet

from secopent.infrastructure.secrets.persistent_file_backend import (
    PersistentEncryptedFileBackend,
)


def test_put_get_survives_restart(tmp_path: Path) -> None:
    store = tmp_path / "secrets.json"
    key = tmp_path / "key"
    backend = PersistentEncryptedFileBackend(store, key)
    backend.put("secret:abc", "plaintext-value")

    # New instance pointing at the same files = "after restart".
    reloaded = PersistentEncryptedFileBackend(store, key)
    assert reloaded.get("secret:abc") == "plaintext-value"


def test_key_injected_from_env(tmp_path: Path, monkeypatch) -> None:
    explicit = Fernet.generate_key()
    monkeypatch.setenv("SECOPTENT_SECRET_KEY", explicit.decode())
    backend = PersistentEncryptedFileBackend(
        tmp_path / "secrets.json", tmp_path / "key", env_key="SECOPTENT_SECRET_KEY",
    )
    assert backend.key_bytes() == explicit


def test_key_file_chmod_0600(tmp_path: Path) -> None:
    key = tmp_path / "key"
    PersistentEncryptedFileBackend(tmp_path / "secrets.json", key)
    assert (key.stat().st_mode & 0o777) == 0o600
```

- [ ] **1.2 运行确认失败**（`key_bytes()` 不存在；`env_key` 参数不存在）。

- [ ] **1.3 实现** `persistent_file_backend.py`：
  - `__init__` 增加 `env_key: str | None = None` 参数。
  - `_load_or_create_key()`：若 `env_key` 设且 `os.environ[env_key]` 非空 -> 用该 key（不落盘，由 operator/KMS 管理）；否则现逻辑（读文件或生成 + 0600 写）。
  - 新增 `key_bytes() -> bytes`（返回当前 Fernet key 原始字节，供测试/导出公钥）。

- [ ] **1.4 运行测试确认通过** `py -3.12 -m pytest tests/infrastructure/test_persistent_secret_backend.py -q`。

- [ ] **1.5 提交** `git commit -m "feat(secrets): env key injection + key_bytes for PersistentEncryptedFileBackend (W2-C T1)"`。

---

## Task 2：SecretBackend Protocol 迁到 application/ports + _metadata 持久化

`SecretBackend` Protocol 当前在 `application/secret_store.py`（混在实现里）。迁到 `application/ports/secrets.py` 与 W2-A 的 ports 模式一致。`SecretStore._metadata` 持久化到 backend（新增 `metadata` namespace）。

- [ ] **2.1 写失败测试** `tests/security/test_secret_persistence.py`：

```python
def test_secret_metadata_survives_restart(tmp_path) -> None:
    """SecretStore metadata (ref -> SecretMetadata) persists across restart."""
    from secopent.application.secret_store import SecretStore
    from secopent.infrastructure.secrets.persistent_file_backend import (
        PersistentEncryptedFileBackend,
    )
    from secopent.domain.common.canonical import utc_now

    store_path = tmp_path / "secrets.json"
    key_path = tmp_path / "key"
    backend = PersistentEncryptedFileBackend(store_path, key_path)
    store = SecretStore(backend)
    md = store.register("llm_api_key", "sk-xxx", now=utc_now())

    # Reload = after restart.
    reloaded_backend = PersistentEncryptedFileBackend(store_path, key_path)
    reloaded = SecretStore(reloaded_backend)
    assert reloaded.resolve(md.secret_ref) == "sk-xxx"
    assert reloaded.metadata(md.secret_ref).name == "llm_api_key"
```

- [ ] **2.2 运行确认失败**（`metadata()` 不存在；metadata 不持久）。

- [ ] **2.3 实现**：
  - 新建 `application/ports/secrets.py`，迁 `SecretBackend` Protocol（`put/get/delete`）。
  - `secret_store.py`：`from .ports.secrets import SecretBackend`；`SecretStore.__init__` 用 backend 存 metadata（key 如 `meta:<ref>`，值 JSON-serialized SecretMetadata）。
  - 新增 `metadata(secret_ref) -> SecretMetadata | None`（从 backend 读 + 反序列化）。
  - `register` 时同时 `backend.put(f"meta:{ref}", metadata_json)`。

- [ ] **2.4 运行测试** `py -3.12 -m pytest tests/security/test_secret_persistence.py -q`。

- [ ] **2.5 提交** `git commit -m "feat(secrets): persist SecretStore metadata + port migration (W2-C T2)"`。

---

## Task 3：composition root 默认用 PersistentEncryptedFileBackend

`_build_secret_backend()` 当前默认 `EncryptedFileBackend()`（内存）。改为默认 `PersistentEncryptedFileBackend`（安全默认路径 + env key），仅在显式请求时回落到内存。

- [ ] **3.1 写失败测试** `tests/security/test_composition_root.py` 追加：

```python
def test_create_app_uses_persistent_secret_backend_by_default(tmp_path) -> None:
    from secopent.infrastructure.secrets.persistent_file_backend import (
        PersistentEncryptedFileBackend,
    )
    engine = create_sqlite_engine(tmp_path / "t.db")
    app = create_app(engine=engine)
    # SecretStore is reachable via signing_keys; its backend must be persistent.
    backend = app.state.signing_keys._secret_store._backend
    assert isinstance(backend, PersistentEncryptedFileBackend)
```

- [ ] **3.2 运行确认失败**（默认是 EncryptedFileBackend）。

- [ ] **3.3 实现** `main.py` `_build_secret_backend()`：
  - 默认用 `PersistentEncryptedFileBackend`，路径：`SECOPTENT_SECRET_STORE_PATH` 或 `Path.cwd() / "secrets.json"`；key：`SECOPTENT_SECRET_KEY` env 或 `Path.cwd() / "secret.key"`（0600）。
  - `SECOPTENT_SECRET_BACKEND=memory` 显式 opt-in 内存（仅测试）。
  - 文档：`docs/deployment.md` 记录生产应通过 env 注入 key（KMS/age-encrypted）。

- [ ] **3.4 运行测试** `py -3.12 -m pytest tests/security/test_composition_root.py -q`。

- [ ] **3.5 提交** `git commit -m "feat(app): default to persistent secret backend (W2-C T3)"`。

---

## Task 4：RescanVerifier 注入 CanaryTokenManager + embed + verify_echo

核心 H5 修复：`reproduce` 不再忽略 `canary_token`。

- [ ] **4.1 写失败测试** `tests/infrastructure/test_rescan_verifier_canary.py`：

```python
# tests/infrastructure/test_rescan_verifier_canary.py
"""RescanVerifier canary token wiring (W2-C T4)."""
from __future__ import annotations

from secopent.application.canary import CanaryTokenManager, CANARY_PLACEHOLDER
from secopent.infrastructure.oracle.rescan_verifier import RescanVerifier


class _FakeRunner:
    """Returns a canned scan result; captures the args it was called with."""
    def __init__(self, stdout: str) -> None:
        self._stdout = stdout
        self.captured_args: list[str] = []

    def scan(self, adapter_key: str, *, args: list[str], **kwargs):  # noqa: ANN001
        self.captured_args = list(args)
        class _Result:
            stdout = self._stdout
            stderr = ""
            exit_code = 0
        return _Result()  # type: ignore[return-value]


def test_canary_token_embedded_into_scan_args() -> None:
    runner = _FakeRunner(stdout="ok")
    canary = CanaryTokenManager.__new__(CanaryTokenManager)  # bypass audit dep
    canary._issued = set()  # type: ignore[attr-defined]
    verifier = RescanVerifier(
        runner=runner,  # type: ignore[arg-type]
        scan_kwargs={"adapter_key": "nuclei", "args": ["-u", f"http://t/{CANARY_PLACEHOLDER}"]},
        canary=canary,
    )
    # ... call reproduce with a candidate; assert runner.captured_args contains
    # the embedded token (not the placeholder) ...
```

> 注：`CanaryTokenManager.__init__` 依赖 `AuditService`；测试用 `__new__` 绕过或注入一个 null audit。实现时若 `CanaryTokenManager` 难以构造，可加一个 `_NullCanaryAudit`。

- [ ] **4.2 运行确认失败**（`RescanVerifier.__init__` 无 `canary` 参数）。

- [ ] **4.3 实现** `rescan_verifier.py`：
  - `__init__(self, runner, scan_kwargs, *, canary: CanaryTokenManager | None = None)`。
  - `reproduce(candidate, method, *, canary_token)`：深拷贝 `self._scan_kwargs`；对其中含 `CANARY_PLACEHOLDER` 的字符串调 `self._canary.embed(template, canary_token)` 替换；`scan` 后若有 `self._canary` 且 token 非空 -> 调 `self._canary.verify_echo(result.stdout, canary_token, actor="oracle")`；**未回声 = 不确认**（返回 `INCONCLUSIVE` 或 `FAILURE`，非 `SUCCESS`）。
  - 现有子串匹配保留作 fallback（canary 未注入时）。

- [ ] **4.4 运行测试** `py -3.12 -m pytest tests/infrastructure/test_rescan_verifier_canary.py -q`。

- [ ] **4.5 提交** `git commit -m "feat(oracle): wire canary token into RescanVerifier (W2-C T4)"`。

---

## Task 5：OracleEngine 向 RescanVerifier 注入 canary + scan_kwargs 模板化

`OracleEngine` 构造 `RescanVerifier` 时传入 `CanaryTokenManager`；`VerificationMethod` 的 scan_kwargs 模板使用 `{{canary_token}}` 占位。

- [ ] **5.1 写失败测试** `tests/oracle_ground_truth/test_canary_echo.py`：

```python
def test_oracle_confirm_requires_canary_echo(memory_repositories_oracle) -> None:
    """A candidate whose rescan doesn't echo the canary is NOT confirmed,
    even if the target string appears in the observation."""
    # Build a candidate + a RescanVerifier whose runner returns stdout WITHOUT
    # the canary token. OracleEngine.verify -> NOT Confirmed.
    ...
```

- [ ] **5.2 运行确认失败**。

- [ ] **5.3 实现** `oracle.py`：
  - `OracleEngine.__init__` 已有 `canary: CanaryTokenManager`；构造 `RescanVerifier` 时传 `canary=self._canary`。
  - 确认 `VerificationMethodRegistry` 中模板 scan_kwargs 含 `{{canary_token}}`（在 payload/header/OOB URL 处）。

- [ ] **5.4 运行测试** + 现有 oracle 测试。

- [ ] **5.5 提交** `git commit -m "feat(oracle): OracleEngine injects canary into RescanVerifier (W2-C T5)"`。

---

## Task 6：端到端 + 质量门禁

- [ ] **6.1 集成测试**：完整验证链路 -- candidate -> OracleEngine.verify -> RescanVerifier 嵌 canary -> scan -> echo 校验 -> CONFIRMED/INCONCLUSIVE；以及 SecretStore 跨重启 resolve。

- [ ] **6.2 质量门禁**：
  - `ruff check .`（改动文件 clean）
  - `mypy src/secopent` strict clean
  - `bandit -r src/secopent -ll` exit 0
  - `pytest --cov=src --cov-fail-under=80`（覆盖率不退化，当前 91%+）
  - 全套 `pytest -q` 绿

- [ ] **6.3 提交** `git commit -m "test(oracle): end-to-end canary echo + secret persistence (W2-C T6)"`。

- [ ] **6.4 文档** 更新 `docs/architecture/verification.md`（canary 接线）+ `docs/deployment.md`（secret key 注入）。

---

## Self-Review

**Spec coverage**：
- H4 SecretStore 持久化 -> T1（backend env key）+ T2（metadata 持久化）+ T3（默认 Persistent）✓
- H5 canary 接线 -> T4（RescanVerifier embed+verify_echo）+ T5（OracleEngine 注入）✓

**Placeholder 扫描**：无 TBD。T4.1 测试骨架标注"实现时若 CanaryTokenManager 难构造可加 _NullCanaryAudit"——是降级方案非占位。T5.3 "确认模板含 {{canary_token}}"需核查 `VerificationMethodRegistry` 现状（若模板未含占位，需追加模板编辑任务）。

**Type 一致性**：
- `RescanVerifier.__init__` 新增 `canary: CanaryTokenManager | None`；`OracleEngine` 传 `canary=self._canary` ✓
- `PersistentEncryptedFileBackend.__init__` 新增 `env_key: str | None = None`；`main.py` 传 `env_key="SECOPTENT_SECRET_KEY"` ✓
- `SecretBackend` Protocol 迁 ports 后，`EncryptedFileBackend`/`PersistentEncryptedFileBackend` 仍结构满足 ✓

**风险**：
- H5 改 `reproduce` 的确认语义（canary 未回声 -> 不确认）。现有 oracle 测试可能依赖"子串匹配即 SUCCESS"旧行为 -> 需在 T5.4 修正测试（让测试 scan 返回含 canary 的 stdout，或显式标 INCONCLUSIVE）。这是预期行为变更，非回归。
- `CanaryTokenManager.__init__` 依赖 `AuditService`（`application/audit.py`）；`RescanVerifier` 在 infrastructure，导入 `CanaryTokenManager`（application）方向合法（infra -> app 依赖方向 OK，与 W2-A `AuditChain` 一致）。但 `canary.py` 若导入 infrastructure 则违规——核查后 `canary.py` 仅依赖 `domain.common.errors` + `application.audit`，安全。
- `PersistentEncryptedFileBackend` 作默认后，`Path.cwd() / "secrets.json"` 在测试可能污染——T3 测试用 `tmp_path` + env 隔离。

---

## Execution Handoff

1. **Subagent-Driven（推荐）**：每 Task 派 fresh subagent
2. **Inline Execution**：本会话内逐 task

确认后开工。第二波（A+B+C）全部交付后，"已建未接线"清单清零，授权链 + 沙箱 + 密钥 + 验证在运行时全部成立。
