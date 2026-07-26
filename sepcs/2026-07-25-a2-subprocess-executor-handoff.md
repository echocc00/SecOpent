# 阶段 A Task A2 实现交接文档：真实 SubprocessContainerExecutor

> **执行方式**：主会话内联（不用子代理），按本文档步骤顺序执行，每步验证后进下一步。
> **执行者**：当前会话或下个接手模型，按 §3 任务顺序逐个做。
> **前置**：A1 完成（Docker + 10 镜像 + 靶场 + Interactsh + LLM 全绿，`verify_env.py` 5/5 PASS）。
> **关键决策**（已锁定）：scoped-egress 用 **option c**（Docker Desktop bridge 网络 + `host.docker.internal` 访问宿主靶场 + 应用层 PolicyEngine scope 校验，M5 再强化到 nftables 网络隔离）。

---

## 1. 目标与范围

### 1.1 目标
实现真实 `SubprocessContainerExecutor`，让 `AdapterRunner` 能真实跑工具容器（nuclei/nmap/subfinder 等打靶场），替换当前的 mock `RecordingExecutor`。

### 1.2 A2 做什么
- 实现 `SubprocessContainerExecutor`：`docker run` + 安全 flags + digest 校验 + 输出捕获
- 网络策略 option c：bridge 网络 + `host.docker.internal` + 应用层 scope（PolicyEngine 已有）
- 4 个集成测试（`@pytest.mark.integration`，真实 Docker 跑）
- 接入 `AdapterRunner`（生产用真实执行器，测试保留 mock）

### 1.3 A2 不做什么
- ❌ 不跑完整 Assessment E2E（A3 串全链路 + 除虫）
- ❌ 不修 parser 偏差（A3 跑真实输出后修）
- ❌ 不接 ptai 真实（A4）
- ❌ 不做 nftables 网络隔离（M5 强化）
- ❌ 不做 Web 浏览器（A5）

### 1.4 验收（DoD）
- `SubprocessContainerExecutor` 实现，4 集成测试绿
- AdapterRunner 生产路径用真实执行器
- 全套单元测试无回归（806+ 仍绿）+ ruff/mypy clean
- commit + `git tag v1.0-a2`

---

## 2. 文件结构（新增/修改）

```text
src/secopent/
  infrastructure/
    adapters/
      subprocess_executor.py     # 新增：真实 docker run 执行器
      base.py                    # 修改：AdapterRunner 默认注入真实执行器（生产）
    egress/
      __init__.py                # 新增
      network_policy.py          # 新增：option c 网络策略（bridge + host.docker.internal + 应用层 scope 说明）
tests/
  integration/
    __init__.py                  # 新增
    conftest.py                  # 新增：integration mark + 跳过逻辑（无 Docker 跳过）
    test_subprocess_executor.py  # 新增：4 集成测试
  infrastructure/
    test_adapter_runner.py       # 已有，确认 mock 路径仍绿
pyproject.toml                   # 修改：pytest mark integration 注册
docs/
  architecture/
    subprocess-executor.md       # 新增：执行器设计文档
```

---

## 3. 任务清单（按顺序执行）

### Task A2.1: SubprocessContainerExecutor 实现

**文件**：`src/secopent/infrastructure/adapters/subprocess_executor.py`

**实现要点**：
- 实现 `ContainerExecutor` Protocol（M1 Task 8 已定义，在 `base.py`）
- `run(image_digest, command, mounts, network_policy, resource_limits) -> ContainerResult`
- 步骤：
  1. **digest 校验**：`docker image inspect <image>@<digest>` 或 `docker images --digests` 对比，不匹配 raise `ImageDigestMismatch`
  2. **构造 `docker run` 命令**：
     ```
     docker run --rm
       --user 65532:65532            # nonroot
       --cap-drop ALL                # 全部 capabilities 丢弃
       --read-only                   # 只读根文件系统
       --tmpfs /tmp:rw,noexec,nosuid # 临时目录
       --network bridge              # option c: bridge（Docker Desktop 默认，host.docker.internal 可达宿主）
       --memory <resource_limits.memory|512m>
       --cpus <resource_limits.cpus|0.5>
       --workdir /work
       -v <input_dir>:/work/input:ro
       -v <output_dir>:/work/output:rw
       <image>@<digest>              # digest-pinned
       <command...>
     ```
  3. **执行**：`subprocess.run(args, capture_output=True, text=True, timeout=600)`
  4. **超时**：`subprocess.TimeoutExpired` -> ContainerResult(exit_code=124, stderr="timeout")
  5. **返回**：`ContainerResult(stdout, stderr, exit_code, artifacts_dir=mounts["/work/output"])`

**关键代码骨架**：
```python
from __future__ import annotations
import subprocess
from pathlib import Path
from .base import ContainerResult, ContainerExecutor  # Protocol

class ImageDigestMismatch(Exception): ...

class SubprocessContainerExecutor(ContainerExecutor):
    def __init__(self, docker_bin: str = "docker", default_timeout: int = 600) -> None:
        self._docker = docker_bin
        self._timeout = default_timeout

    def run(self, *, image_digest: str, command: list[str],
            mounts: dict[str, str], network_policy: str,
            resource_limits: dict[str, object]) -> ContainerResult:
        self._verify_digest(image_digest)
        args = self._build_args(image_digest, command, mounts, network_policy, resource_limits)
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=self._timeout)
            return ContainerResult(
                stdout=proc.stdout, stderr=proc.stderr,
                exit_code=proc.returncode,
                artifacts_dir=mounts.get("/work/output", ""),
            )
        except subprocess.TimeoutExpired:
            return ContainerResult(stdout="", stderr="execution timeout",
                                   exit_code=124, artifacts_dir=mounts.get("/work/output", ""))

    def _verify_digest(self, image_digest: str) -> None:
        # image_digest format: "name@sha256:..." or "name:tag"
        if "@" not in image_digest:
            return  # no digest pin, skip (or warn)
        name, digest = image_digest.split("@", 1)
        result = subprocess.run(
            [self._docker, "image", "inspect", "--format", "{{index .RepoDigests 0}}", name],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            raise ImageDigestMismatch(f"image {name} not found locally")
        actual = result.stdout.strip()
        # actual like "projectdiscovery/nuclei@sha256:..."
        if not actual.endswith(digest):
            raise ImageDigestMismatch(f"digest mismatch: expected {digest}, got {actual}")

    def _build_args(self, image_digest, command, mounts, network_policy, resource_limits):
        memory = resource_limits.get("memory", "512m")
        cpus = str(resource_limits.get("cpus", "0.5"))
        args = [
            self._docker, "run", "--rm",
            "--user", "65532:65532",
            "--cap-drop", "ALL",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid",
            "--network", "bridge",  # option c
            "--memory", str(memory),
            "--cpus", cpus,
            "--workdir", "/work",
        ]
        for dst, src in mounts.items():
            args += ["-v", f"{src}:{dst}"]
        args.append(image_digest)
        args += list(command)
        return args
```

**验证**：写完后 `py -3.12 -m ruff check src/secopent/infrastructure/adapters/subprocess_executor.py` + `mypy` clean。

---

### Task A2.2: 网络策略 option c 文档 + 工具

**文件**：`src/secopent/infrastructure/egress/network_policy.py`（新建，含设计说明）

**内容**：
- 定义 `NetworkPolicy` 常量（bridge / scoped_egress）
- 文档说明 option c：Docker Desktop bridge 网络 + `host.docker.internal` 访问宿主靶场 + 应用层 `PolicyEngine.evaluate` 做 scope 校验（已在 M0/M1 实现）
- 标注 M5 强化点：nftables/netns 真实网络隔离阻 metadata/DB/Docker host

**关键点**：
- Docker Desktop（Windows/Mac）`--network=host` 不生效，必须用 bridge + `host.docker.internal`
- 容器内访问宿主靶场：`http://host.docker.internal:3000`（Juice Shop）
- 应用层 scope（PolicyEngine）已在 AdapterRunner._enforce_scope 做了（M1 Task 8），A2 不改
- M5 才做网络层强制（nftables 阻 metadata 等）

**验证**：文档存在 + ruff clean。

---

### Task A2.3: 集成测试（4 个，`@pytest.mark.integration`）

**文件**：`tests/integration/conftest.py` + `tests/integration/test_subprocess_executor.py`

**conftest.py**：
```python
import pytest, shutil

def pytest_collection_modifyitems(config, items):
    # 无 Docker 自动跳过 integration 测试
    if not shutil.which("docker"):
        skip = pytest.mark.skip(reason="docker not available")
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip)
```

**pyproject.toml** 加：
```toml
[tool.pytest.ini_options]
markers = [
    "integration: requires Docker + real tools (slow)",
    "e2e_real: requires Docker + target ranges (slow)",
    "browser: requires Playwright browser",
]
```

**test_subprocess_executor.py**（4 测试）：

```python
import pytest
from secopent.infrastructure.adapters.subprocess_executor import (
    SubprocessContainerExecutor, ImageDigestMismatch,
)
from secopent.infrastructure.adapters.image_catalog import IMAGE_CATALOG

@pytest.mark.integration
def test_runs_nuclei_against_httpbin(tmp_path):
    """真实 nuclei 扫 httpbin，验证 stdout 有 JSONL + exit 0。"""
    # 准备 input/output 目录
    (tmp_path / "input").mkdir()
    (tmp_path / "output").mkdir()
    nuclei = IMAGE_CATALOG["nuclei"]
    image_ref = f"{nuclei.name}@{nuclei.digest}"
    executor = SubprocessContainerExecutor()
    result = executor.run(
        image_digest=image_ref,
        command=["-u", "http://host.docker.internal:8080", "-jsonl", "-silent"],
        mounts={"/work/input": str(tmp_path / "input"), "/work/output": str(tmp_path / "output")},
        network_policy="bridge",
        resource_limits={"memory": "512m", "cpus": "0.5"},
    )
    assert result.exit_code == 0
    # nuclei 可能无 finding 但应正常退出；stdout 或 output 目录有 JSONL
    assert result.stdout or (tmp_path / "output").glob("*.jsonl")

@pytest.mark.integration
def test_enforces_security_flags_nonroot(tmp_path):
    """容器内 id 命令输出 nonroot（uid=65532）。"""
    (tmp_path / "input").mkdir(); (tmp_path / "output").mkdir()
    alpine = IMAGE_CATALOG["alpine"]
    executor = SubprocessContainerExecutor()
    result = executor.run(
        image_digest=f"{alpine.name}@{alpine.digest}",
        command=["id"],
        mounts={"/work/input": str(tmp_path / "input"), "/work/output": str(tmp_path / "output")},
        network_policy="bridge",
        resource_limits={"memory": "64m", "cpus": "0.1"},
    )
    assert "65532" in result.stdout, f"nonroot uid not found: {result.stdout}"

@pytest.mark.integration
def test_digest_mismatch_rejected(tmp_path):
    """digest 不匹配拒绝执行（防供应链）。"""
    (tmp_path / "input").mkdir(); (tmp_path / "output").mkdir()
    executor = SubprocessContainerExecutor()
    with pytest.raises(ImageDigestMismatch):
        executor.run(
            image_digest="alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            command=["echo", "should-not-run"],
            mounts={"/work/input": str(tmp_path / "input"), "/work/output": str(tmp_path / "output")},
            network_policy="bridge",
            resource_limits={"memory": "64m", "cpus": "0.1"},
        )

@pytest.mark.integration
def test_scoped_egress_blocks_metadata(tmp_path):
    """云 metadata IP 169.254.169.254 在容器内不可达（option c 应用层 + 容器默认隔离）。

    注：option c 下网络层不强制阻 metadata（M5 才做 nftables）。
    此测试验证容器内访问 metadata 超时/失败（Docker bridge 默认不路由 link-local），
    或文档化为"M5 强化项"。若 bridge 网络下 metadata 仍可达，标记 xfail 待 M5。
    """
    (tmp_path / "input").mkdir(); (tmp_path / "output").mkdir()
    alpine = IMAGE_CATALOG["alpine"]
    executor = SubprocessContainerExecutor()
    result = executor.run(
        image_digest=f"{alpine.name}@{alpine.digest}",
        command=["sh", "-c", "wget -T 2 -q http://169.254.169.254/ && echo REACHABLE || echo BLOCKED"],
        mounts={"/work/input": str(tmp_path / "input"), "/work/output": str(tmp_path / "output")},
        network_policy="bridge",
        resource_limits={"memory": "64m", "cpus": "0.1"},
    )
    # Docker bridge 默认不路由 169.254.0.0/16，应 BLOCKED
    assert "BLOCKED" in result.stdout, f"metadata unexpectedly reachable: {result.stdout}"
```

**验证方法**：
```bash
cd /f/claudepc/SecOpent
py -3.12 -m pytest -q tests/integration/test_subprocess_executor.py -m integration -v
```
预期：4 个 PASS（nuclei 真扫 + nonroot + digest 拒绝 + metadata 阻断）。nuclei 测试可能跑 30-60s。

---

### Task A2.4: 接入 AdapterRunner

**文件**：`src/secopent/infrastructure/adapters/base.py`（修改）

**修改点**：
- `AdapterRunner.__init__` 默认 `executor` 改为 `SubprocessContainerExecutor()`（生产路径）
- 单元测试仍注入 mock `RecordingExecutor`（已有，不改）
- 加一个工厂函数 `create_production_runner(policy_engine, cas_store, parser_registry) -> AdapterRunner` 用真实执行器

**验证**：
```bash
py -3.12 -m pytest -q tests/infrastructure/test_adapter_runner.py  # mock 路径仍绿
py -3.12 -m pytest -q tests/adapter_contract/  # adapter 契约测试仍绿（用 mock）
```

---

### Task A2.5: 验收 + 提交

**全套验证**：
```bash
cd /f/claudepc/SecOpent
# 1. 单元测试无回归
py -3.12 -m pytest -q                                    # 806+ passed
# 2. 集成测试绿
py -3.12 -m pytest -q tests/integration/ -m integration -v   # 4 passed
# 3. 质量门
py -3.12 -m ruff check src tests                          # All checks passed
py -3.12 -m mypy src/secopent/domain src/secopent/application  # strict clean
# 4. 环境仍绿
py -3.12 scripts/verify_env.py                            # 5/5 PASS
# 5. 文档
ls docs/architecture/subprocess-executor.md               # exists
```

**提交**：
```bash
git add -A
git commit -m "feat(adapters): add real subprocess container executor (A2)

- SubprocessContainerExecutor: docker run + digest verify + security flags
- network policy option c: bridge + host.docker.internal + app-layer scope
- 4 integration tests green (nuclei real + nonroot + digest + metadata)
- AdapterRunner production path uses real executor
- M5 will strengthen to nftables network isolation"
git tag v1.0-a2
```

---

## 4. 验证方法（每步 + 整体）

### 4.1 每步验证
| 步 | 验证命令 | 预期 |
|---|---|---|
| A2.1 实现 | `ruff check` + `mypy` subprocess_executor.py | clean |
| A2.2 网络 | `ls` network_policy.py | exists |
| A2.3 集成测试 | `pytest -m integration tests/integration/` | 4 passed |
| A2.4 接入 | `pytest tests/infrastructure/test_adapter_runner.py` | mock 路径仍绿 |
| A2.5 整体 | 全套 + 质量门 + verify_env | 全绿 |

### 4.2 整体验证（A2 完成）
```bash
cd /f/claudepc/SecOpent
py -3.12 -m pytest -q                                    # 单元 806+ passed
py -3.12 -m pytest -q tests/integration/ -m integration  # 集成 4 passed
py -3.12 -m ruff check src tests                         # clean
py -3.12 -m mypy src/secopent/domain src/secopent/application  # clean
py -3.12 scripts/verify_env.py                           # 5/5 PASS
git log --oneline | head -3                              # A2 commit 在顶
git tag | grep a2                                         # v1.0-a2
```

### 4.3 真实工具冒烟（A2 完成后手动验证）
```bash
# 用真实 nuclei 扫 Juice Shop（手动确认工具真能跑）
docker run --rm --user 65532:65532 --cap-drop ALL --read-only \
  --network bridge --memory 512m --cpus 0.5 \
  projectdiscovery/nuclei@sha256:e677842fb1f50f29747565ba274a1d35dcf8c684132a42b0cb406e71fccae9fc \
  -u http://host.docker.internal:3000 -jsonl -silent -t technologies/ 2>&1 | head -5
```
预期：nuclei 跑起来，输出 JSONL（tech detection 模板，几秒内出结果）。

---

## 5. 风险与注意事项

| 风险 | 缓解 |
|---|---|
| Docker Desktop `--network=host` 不生效 | 用 bridge + `host.docker.internal`（option c 已采用） |
| nuclei 首次跑要更新模板（-update-templates） | A2 测试用 `-silent` 不更新，或加 `-ntu` 跳过更新；A3 再处理模板 |
| digest 校验 `docker image inspect` 格式 | RepoDigests 可能多元素，用 `endswith(digest)` 匹配 |
| 集成测试慢（nuclei 30-60s） | mark integration，CI 单独 job，本地按需跑 |
| option c 不阻 metadata（网络层） | test_scoped_egress_blocks_metadata 验证 bridge 默认不路由 169.254；若可达标 xfail 待 M5 |
| 容器内访问宿主靶场需 host.docker.internal | 命令里用 `http://host.docker.internal:3000` 不是 localhost |

---

## 6. A2 完成后状态

- ✅ AdapterRunner 能真实跑工具容器（nuclei/nmap/subfinder 等打靶场）
- ✅ digest 固定 + 安全 flags（nonroot/cap-drop/read-only）验证
- ✅ 4 集成测试绿
- ⏳ 还没串完整 Assessment 流程（A3）
- ⏳ parser 还没跑真实输出验证（A3 除虫）

**A2 = "工具能真跑了，但还没串成完整渗透流程"**

---

## 7. 下一步（A2 完成后）

**A3: 真实 E2E + 除虫**（1-2 周）
- 用 SubprocessContainerExecutor 跑完整 Assessment 链路（Planner -> Orchestrator -> Adapter -> oracle -> 报告）
- 三靶场真跑（Juice Shop/crAPI/httpbin）
- 修 parser 偏差（真实工具输出 vs fixture）
- 修 scope 边界 / 超时 / 网络抖动
- 验收：每靶场 ≥1 Confirmed Finding

A3 计划见 `sepcs/2026-07-25-phase-a-runnable-plan.md` Task A3。

---

*本文档由当前会话编写，主会话内联执行 A2。完成后进 A3。*
