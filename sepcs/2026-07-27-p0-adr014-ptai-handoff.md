# P0 交接：修正 ADR-014 + 清理 PtaiAdapter

> **执行者**：开发模型（主会话内联或子代理）
> **工期**：1-2 天
> **前置**：无（纯文档 + 代码清理，无外部依赖）
> **目标**：让设计与实现一致--ADR-014 假设 ptai 是验证库，实际是自主 agent；PtaiAdapter 是死代码。

---

## 1. 背景

### 1.1 设计假设（ADR-014 原文）
```
## ADR-014：OracleEngine 采纳 pentest-ai，不自建
Context：pentest-ai（ptai，MIT，pip install ptai）已实现 oracle N/N 复证 + 14 类漏洞 oracle + 证据胶囊。
Decision：采纳 ptai 作 OracleEngine，建 VerificationMethodRegistry 策展层覆盖在 ptai 之上。
```

### 1.2 真实情况（A4 spike 证实）
- ptai 1.1.0 是**自主 AI 渗透 agent**（MCP server + CLI，200+ 工具，exploit chaining）
- **没有** `ptai.verify(target, vuln_type, canary_token, n)` 验证 API
- 导入名不是 `ptai`（distribution 名 ≠ import 名），实际 `agents.*`
- 重依赖（impacket/bloodhound/scapy）在 Windows 装不上；Linux 可装
- 完整 spike 结论见 `sepcs/2026-07-27-a4-ptai-spike-findings.md`

### 1.3 当前代码状态
- `src/secopent/infrastructure/oracle/ptai_adapter.py`：60 行，包装一个**不存在的** `ptai.verify()` API
  - `_import_ptai()` 懒导入（real ptai 不可用，pragma: no cover）
  - `PtaiAdapter.reproduce()` 调 `ptai.verify(target=..., vuln_type=..., canary_token=..., n=1)` -- 这个 API 不存在
  - 仅用注入的 fake `_PtaiModule` 单测（`tests/infrastructure/test_ptai_adapter.py`）
- **真实 oracle**：A3 用 `RescanVerifier`（真实重扫复现）+ `OracleEngine`（N/N + decide_outcome）--已真实验证 Juice Shop SQLi

### 1.4 结论
`PtaiAdapter` 是**死代码**（真实 ptai 没有 `verify()` API，懒导入永不成功）。oracle 功能完整（RescanVerifier）。需修正 ADR-014 + 清理死代码。

---

## 2. 执行步骤

### Step 1: 修正 ADR-014（`sepcs/2026-07-25-decisions.md`）

**找到** ADR-014 段落（`## ADR-014：OracleEngine 采纳 pentest-ai，不自建`），**整段替换**为：

```markdown
## ADR-014：OracleEngine 自建 RescanVerifier，ptai 重定位为 peer agent

**Context**：设计初版假设 pentest-ai（ptai）是验证库（`ptai.verify()`），可作 OracleEngine 后端。A4 spike（2026-07-27）证实 ptai 1.1.0 是**自主 AI 渗透 agent**（MCP server + CLI，200+ 工具），不是验证库，没有 `verify()` API。其重依赖（impacket/bloodhound/scapy）在 Windows 装不上。详见 `sepcs/2026-07-27-a4-ptai-spike-findings.md`。

**Decision**：OracleEngine 用**自建 RescanVerifier**（真实重扫 N/N 复现，已在 A3 真实验证 Juice Shop SQLi）。ptai **不**作 oracle 后端，重定位为未来可选的 **peer 渗透 agent**（经 M4 MCP 注册表以 trust level `adopted_external_mcp` 接入，agent 把 ptai 当工具调用，输出经 oracle 复证才确认）。ptai 真实集成需 Linux 环境（V1.1/V2）。

**Consequences**：oracle 自建（无 ptai 依赖，RescanVerifier 已验证）；ptai 集成推迟到 Linux 环境 + MCP peer agent 接入。换来：oracle 不依赖外部 agent，确定性可控；ptai 作为增强能力（peer agent）而非核心验证。

**Rejected**：
- *原 ADR-014（采纳 ptai 作 oracle 后端）*：ptai 不是验证库，API 假设不成立（A4 spike 证伪）。
- *强制装 ptai 作 oracle*：Windows 装不上；即使 Linux 装上，ptai 是自主 agent 非验证库，性质不符。
- *仅用 nuclei matcher（非 N/N）*：误报率高，不满足确定性验证要求。
```

### Step 2: 删除 PtaiAdapter 死代码

**删除文件**：
- `src/secopent/infrastructure/oracle/ptai_adapter.py`
- `tests/infrastructure/test_ptai_adapter.py`（若存在）

**检查引用**：执行
```bash
cd /f/claudepc/SecOpent
grep -rn "PtaiAdapter\|ptai_adapter\|_import_ptai\|_PtaiModule" src/ tests/
```
预期：除了已删除的文件，不应有其他引用。若有（如 oracle.py 的 import 或测试 fixture），一并清理：
- `src/secopent/application/oracle.py` 的 docstring 提到 "pentest-ai adapter" -- 改为 "RescanVerifier"（描述实际用的 verifier）
- 任何测试 fixture 注入 PtaiAdapter 的地方 -- 改为 RescanVerifier 或 fake

### Step 3: 确认 RescanVerifier 是 OracleEngine 默认

**检查** `src/secopent/application/oracle.py`：
- `OracleEngine.__init__` 接受 `verifier: OracleVerifier` Protocol
- 确认生产路径默认用 `RescanVerifier`（若没有默认，加一个工厂函数 `create_default_oracle()` 返回带 RescanVerifier 的 OracleEngine）
- 确认 A3 e2e_real 测试用 RescanVerifier（`tests/e2e_real/`）

**检查 RescanVerifier 位置**：
```bash
grep -rn "class RescanVerifier\|RescanVerifier" src/ tests/
```
若 RescanVerifier 在 tests/ 而非 src/，考虑移到 `src/secopent/infrastructure/oracle/rescan_verifier.py`（生产代码）。

### Step 4: 更新主设计文档

**`sepcs/2026-07-25-catalog-driven-agent-workbench-design.md`**：

1. **§9.2 oracle N/N 复证**：把 "采纳 pentest-ai（ptai，MIT，pip install ptai）" 改为 "自建 RescanVerifier（真实重扫 N/N 复现），ptai 重定位为 peer agent（见 ADR-014 修正）"

2. **§22.5 开源同类采纳清单**：pentest-ai 行的"采纳方式"从 "Adapter/库，决策 22 采纳" 改为 "**重定位为 peer agent**（MCP 注册表接入，需 Linux，V1.1/V2）"

3. **§1.2 核心决策清单**：决策 22 "OracleEngine" 从 "采纳 pentest-ai（MIT）作 oracle" 改为 "自建 RescanVerifier（N/N 复现），ptai 重定位 peer agent"

4. **§16 取舍记录**：第 26 条 "OracleEngine 采纳 pentest-ai" 改为 "OracleEngine 自建 RescanVerifier（A4 spike 证伪 ptai 假设，ADR-014 修正）"

5. **§20.3 已拍板**：O3 行无 ptai，跳过

### Step 5: 验证

```bash
cd /f/claudepc/SecOpent
# 1. 测试无回归（PtaiAdapter 删除后，其测试也删，总数应减）
py -3.12 -m pytest -q                    # 应仍全绿（减去 ptai_adapter 测试数）
# 2. e2e_real 仍绿（RescanVerifier 真实 oracle）
py -3.12 -m pytest -q tests/e2e_real/ -m e2e_real
# 3. 质量门
py -3.12 -m ruff check src tests
py -3.12 -m mypy src/secopent            # strict 0 错误
# 4. 无残留引用
grep -rn "ptai_adapter\|PtaiAdapter" src/ tests/   # 应无输出
# 5. 环境仍绿
py -3.12 scripts/verify_env.py
```

### Step 6: 提交

```bash
cd /f/claudepc/SecOpent
git add -A
git commit -m "fix(oracle): correct ADR-014 - ptai is peer agent not oracle backend (P0)

- ADR-014 revised: ptai is autonomous agent, not verify library (A4 spike)
- OracleEngine uses self-built RescanVerifier (real rescan N/N, A3 verified)
- Delete dead PtaiAdapter (wrapped non-existent ptai.verify() API)
- Update design §9.2/§22.5/§1.2/§16 to match implementation
- ptai repositioned as future peer agent (MCP, Linux, V1.1/V2)"
git tag v1.0-p0
```

---

## 3. 验收标准

- [ ] ADR-014 修正（自建 RescanVerifier，ptai 重定位 peer agent）
- [ ] PtaiAdapter + 其测试删除，无残留引用
- [ ] OracleEngine 默认用 RescanVerifier（生产路径）
- [ ] 设计文档 §9.2/§22.5/§1.2/§16 与实现一致
- [ ] 全套测试绿（无回归）+ ruff/mypy clean
- [ ] e2e_real 仍绿（真实 oracle 工作正常）
- [ ] `git tag v1.0-p0`

---

## 4. 注意事项

- **不要删 RescanVerifier**：它是真实 oracle 后端，A3 已验证
- **不要动 OracleEngine/decide_outcome**：确定性逻辑正确，只换 verifier 后端
- **ptai 不废弃**：重定位为 peer agent，未来 Linux 环境经 MCP 接入（文档记录，代码本次删桩）
- **若 RescanVerifier 在 tests/ 而非 src/**：本次顺手移到 `src/secopent/infrastructure/oracle/rescan_verifier.py`（它是生产 oracle 后端，不该在 tests/）

---

*P0 完成后，设计与实现完全一致，可进 P1（Web Case Studio React）。*
