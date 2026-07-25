# 验证层（Verification / Oracle）

> 状态：M2 基线。OracleEngine 采纳 pentest-ai + VerificationMethodRegistry 策展；N/N 复证、canary token、自托管 Interactsh OOB、靶场回归（mock，真实靶场 M5）。
> 设计来源：`sepcs/2026-07-25-catalog-driven-agent-workbench-design.md` §9；ADR-004（oracle N/N，非 LLM 判定）。

验证层把低信任的 `Observation` 升级为确认的 `ConfirmedFinding`。核心原则：**只有 oracle 能确认漏洞，LLM 永不标记 Confirmed**（LLM边界）。

## N/N 复证

一个 `CandidateFinding` 通过 N 次**独立复现**验证，达到 N/N 成功才确认：

| 漏洞类 | N | 方法 |
|---|---|---|
| SQLi（延时） | 5 | 独立延时复现 |
| RCE（echo） | 3 | 回显复现 |
| SSRF / XXE / 反序列化 | 3 | OOB 回调 + 30s 窗口 |
| XSS / 文件读 / 认证绕过 / 路径穿越 / IDOR / 参数篡改 / MFA 跳过 / 弱凭证 / 越权 | 3 | echo/差异复现 |

确定性裁决规则（`domain/verification/models.py::decide_outcome`）：
- `successes >= N` → **CONFIRMED**
- attempts 用尽且 `inconclusive >= 5xx 阈值(默认2)` → **INCONCLUSIVE**（升级人审）
- attempts 用尽否则 → **REFUTED**
- 否则 → **PENDING**

**5xx 计 INCONCLUSIVE 不计 REFUTED**：目标抖动/服务器错误是「不确定」，不是「证伪」。

## VerificationMethodRegistry（策展层）

`domain/verification/registry.py` 是覆盖在 oracle 引擎之上的策展层：每类漏洞的 N 值、retry 策略（默认 cross-worker，单 worker 间隔 2s 降级）、5xx 阈值、OOB 窗口。`default_registry()` 预置 14 类漏洞方法。

## Canary Token（确认凭证）

`application/canary.py::CanaryTokenManager` 每次验证发**唯一、一次性、高熵** token（`secrets.token_urlsafe`），嵌入探针（echo 命令或 OOB 子域 `<token>.oast.example.com`）。确认要求**精确回显**——证明观察到的效果是注入的探针，而非巧合响应。token 不重用；每次生成/校验全审计（审计中 token 脱敏，不落原文）。

## 自托管 Interactsh OOB（ADR H4）

国内公共 OOB 不稳，故自托管 Interactsh。`infrastructure/oracle/interactsh.py::InteractshClient` 把 canary token 作回调域最左 label，按 label 关联回调；一个 correlation 域可服务多个并发验证。真实 interactsh-server（Docker）在 M5 E2E；M2 用注入的 `InteractshTransport` mock 测试。

## pentest-ai 采纳（ADR-014）

OracleEngine 通过 `OracleVerifier` 端口调用后端；`infrastructure/oracle/ptai_adapter.py::PtaiAdapter` 包装 pentest-ai（`pip install ptai`，MIT）。ptai 为可选运行时依赖，惰性导入，未安装处用注入 mock 测试（真实执行 M5）。

## 靶场回归（ground-truth）

`tests/oracle_ground_truth/` 对三类靶场做 oracle 回归，确保升级 oracle 不误判：
- **Juice Shop**（Web 应用类）：SQLi/XSS 在场→CONFIRM，干净→REFUTE
- **crAPI**（API 类）：IDOR/认证绕过 在场→CONFIRM，加固→REFUTE
- **vulhub**（CVE 复现类）：RCE/反序列化 在漏洞环境→CONFIRM，补丁环境→REFUTE

真实靶场（docker-compose）在 M5；M2 用 `GroundTruthVerifier` 模拟靶场 ground truth 回归 oracle 决策逻辑。
