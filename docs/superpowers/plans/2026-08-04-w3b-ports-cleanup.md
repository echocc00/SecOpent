# W3-B: 端口清洁 -- Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 把 `InMemoryPeerRunRepository`（具体实现）从 `application/ports/peer_runs.py` 迁到 `infrastructure/peer_agents/in_memory_peer_runs.py`，让 `application/ports/` 只剩 Protocol/DTO，不含具体实现。同 W2-A 把 `InMemoryPermitRevoker` 放 `infrastructure/safety/` 的做法。

**Architecture:** 纯重构，无行为变更。`ports/peer_runs.py` 当前只含 `InMemoryPeerRunRepository` 一个类（`PeerRunRepository` Protocol 在 `ports/repositories.py`）。迁移后删除 `ports/peer_runs.py`，更新 3 个测试导入点。现有 peer 测试（`test_peer_agents_service.py::TestInMemoryPeerRunRepository` 等）作为回归守护。

**Tech Stack:** Python 3.12、`py -3.12 -m pytest`、ruff、mypy strict。

---

## 现状

- `src/secopent/application/ports/peer_runs.py`：仅含 `InMemoryPeerRunRepository`（dict-backed，满足 `PeerRunRepository` Protocol）。
- `PeerRunRepository` Protocol 在 `src/secopent/application/ports/repositories.py:118`。
- 导入 `InMemoryPeerRunRepository` 的源文件：**无**（`application/peer_agents.py` 与 `infrastructure/peer_agents/composition.py` 只导入 Protocol）。
- 导入它的测试：`tests/application/test_peer_agents_service.py`、`tests/e2e_real/test_peer_strix_ab.py`、`tests/infrastructure/test_peer_composition.py`。

## File Structure

- 新增 `src/secopent/infrastructure/peer_agents/in_memory_peer_runs.py`
- 删除 `src/secopent/application/ports/peer_runs.py`
- 改 3 个测试文件的导入

## Task T1: 迁移 InMemoryPeerRunRepository 到 infrastructure

1. 新建 `src/secopent/infrastructure/peer_agents/in_memory_peer_runs.py`，把 `InMemoryPeerRunRepository` 类（含其 docstring）原样搬入，更新导入路径（`from ...domain.peer_agents.models import PeerAgentRun`）。
2. 删除 `src/secopent/application/ports/peer_runs.py`。
3. 更新 3 个测试文件的导入：
   - `tests/application/test_peer_agents_service.py:12`
   - `tests/e2e_real/test_peer_strix_ab.py:124`
   - `tests/infrastructure/test_peer_composition.py:39, 94`
   - `from secopent.application.ports.peer_runs import InMemoryPeerRunRepository` -> `from secopent.infrastructure.peer_agents.in_memory_peer_runs import InMemoryPeerRunRepository`
4. 回归：`py -3.12 -m pytest tests/application/test_peer_agents_service.py tests/infrastructure/test_peer_composition.py -q`（e2e_real 跳过，无 Docker）。
5. ruff + mypy。
6. 提交：`refactor(peer): move InMemoryPeerRunRepository out of ports/ to infrastructure (W3-B T1)`

## Self-Review

- **Spec coverage**：ports/ 不再含具体实现。✓
- **无行为变更**：类原样搬迁，仅导入路径变。✓
- **回归守护**：现有 peer 测试覆盖 `InMemoryPeerRunRepository` 的 add/save/get 行为。✓
