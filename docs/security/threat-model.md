# STRIDE 威胁模型

> 状态：**v1.1.0-stable**（T13 复审更新）。覆盖 SecOpent 全组件。**每次发布复审更新**
> （`scripts/release.sh`），并在新增能力/适配器/安全事件后补充对应 STRIDE 行。
> 参考：主设计 §12（安全）/§16.2（14 安全条件）；`tests/security/test_security_conditions.py` 全绿。

## 持续安全验证门禁

| 门禁 | 类型 | 触发 | 位置 |
|---|---|---|---|
| bandit（`-ll`） | 静态 SAST | CI `sast` job | T1（dd97e85） |
| gitleaks | 密钥扫描 | CI `sast` job | `.gitleaks.toml` |
| pip-audit / npm audit | 依赖 CVE | CI `deps` job | T1 |
| 运行态自渗透 | 动态（nuclei 扫自身 API，0 critical/high） | `SECOPTENT_SELF_PENTEST=1`，CI security job | `tests/security/test_self_pentest.py`（T13） |
| 架构边界守卫 | 框架无关性（domain/application 禁 fastapi/sqlalchemy） | 默认套件 | `tests/test_architecture_boundaries.py` |
| 14 安全条件 | 确定性脊柱 + LLM 边界 | 默认套件 | `tests/security/test_security_conditions.py` |

## 资产与信任边界

- **确定性脊柱**（PolicyEngine / TestCatalog / CoverageMatrix / OracleEngine / Planner / 签名）：高信任，LLM 不可裁决。
- **目标输出**（网页/Banner/工具输出/漏洞描述）：**不可信**，经 PromptInjectionGuard 隔离。
- **外部 MCP / 远程 LLM**：低信任，标 trust level，输出不驱动确定性决策。
- **执行环境**（容器/插件）：敌对，沙箱 + scoped egress 隔离。

## STRIDE 分析

### S — Spoofing（仿冒）
| 威胁 | 缓解 |
|---|---|
| 伪造 ExecutionPermit | Ed25519 签名 + 短时（15min）+ nonce 防重放 + worker 绑定（条件 5） |
| 仿冒审计事件 | AuditChain Ed25519 签名 + 哈希链（条件 12） |
| 仿冒更新 bundle | Ed25519 bundle 签名验证，错误签名拒绝（条件 13） |
| 仿冒 AppModel/Case | Ed25519 人签，agent 禁签（LLM边界） |

### T — Tampering（篡改）
| 威胁 | 缓解 |
|---|---|
| 篡改审计日志 | 哈希链 + 签名，断裂可检测（条件 12） |
| 篡改 Scope/Plan | PolicyEngine + Approval 绑定 plan_digest/scope_digest；PromptInjection 不能改 Plan（条件 8） |
| 篡改 manifest/模型 | canonical_digest 内容摘要 |
| 篡改证据 | CAS 内容寻址 sha256 + Evidence 三层 |

### R — Repudiation（抵赖）
| 威胁 | 缓解 |
|---|---|
| 操作者否认操作 | AuditChain 全程留痕（actor/action/资源），签名 + 哈希链 |
| 否认 permit 使用 | permit nonce 记入审计，重放可检测（条件 5/12） |
| 否认 GDPR 删除 | 删除本身记入审计链（redact_pii 留痕） |

### I — Information Disclosure（信息泄露）
| 威胁 | 缓解 |
|---|---|
| Secret 泄露到日志/Evidence/MCP/Prompt | SecretStore 引用制，明文不入库/日志/证据/报告（条件 7） |
| 报告泄露 secret/PII | RedactionEngine 在渲染层再过（M2/M4） |
| 远程 LLM 泄露敏感数据 | RemoteModelGateway 分级 + 脱敏 + Secret 永不发送（条件 10） |
| 工具访问云 Metadata/DB | 应用层 EgressGuard + 网络层 nftables scoped egress（T11）双阻 169.254.0.0/16、127.0.0.0/8（条件 6） |
| API 错误泄露内部细节 | 运行态自渗透检测 5xx/traceback 泄露，0 critical/high 才通过（T13） |
| 备份泄露机密 | 备份仅含密文；Fernet 主密钥不进备份、线下托管（T8 runbook） |

### D — Denial of Service（拒绝服务）
| 威胁 | 缓解 |
|---|---|
| 无限循环/递归用例 | DSL foreach/retry/wait 硬上限；沙箱静态拒绝（条件 9） |
| 资源耗尽 | 容器资源限制（cpu/mem/pids/timeout）+ 预算门 |
| LLM 预算耗尽 | RemoteModelGateway 日预算/限速/超限降级本地（§12.11） |
| 失控任务 | EmergencyStop 全局停止 + 撤销 permit + 终止容器（条件 11） |
| DNS rebinding 到内网 | ScopeEnforcer/EgressGuard 解析后二次校验 + NftScopeEnforcer 解析双检（T11），网络层默认 DROP（条件 2） |

### E — Elevation of Privilege（提权）
| 威胁 | 缓解 |
|---|---|
| Agent 执行任意 Shell | MCP 禁注册 shell/docker_run/execute_python（条件 3） |
| 未批准 Active/Intrusive 执行 | PolicyEngine 风险/能力门 + Approval（条件 4） |
| 插件逃逸沙箱 | seccomp + read-only + non-root + cap-drop ALL + 禁 Docker Socket（条件 9） |
| Agent 自我提权（改 scope/case/审批） | PromptInjectionGuard 保护资源集 + LLM 不裁决（条件 8） |
| Scope 外执行 | ScopeEnforcer 10 步链 + EgressGuard 双校验（条件 1/2） |

## 验收

14 条强制安全条件（§16.2）全部由 `tests/security/test_security_conditions.py` 覆盖并通过。
确定性脊柱与 LLM 边界由 `tests/test_architecture_boundaries.py`（框架守卫）+ 各领域测试保证。

## Open Items（后续跟进）

- 远程 Worker 分布式的竞态/角色逻辑测试（§22.4，T18 Tier 1 设计已就绪）
- 多租户隔离与客户门户（T19；T16 遥测已含 tenant 标签）
- 网络层强制目前仅 Linux（nftables，T11 已在 Linux CI 验证）；Windows/macOS 开发机依赖应用层 EgressGuard + Docker 默认不路由 link-local
- 自渗透当前为针对性模板（5xx/错误泄露）；后续引入更广的离线 nuclei-templates 集
- trivy 镜像扫描依赖漏洞库下载（受限网络不可用）；云域以 checkov 离线规则兜底

### 已解决（v1.1.0-stable）

- 真实靶场（Juice Shop/httpbin/crAPI）docker-compose 编排回归 — T5/T6 已落地（`tests/e2e_real/`）
- nftables scoped egress 网络层强制 — T11 已落地（`scripts/provision/egress.nft` + `NftScopeEnforcer`）
- 静态 SAST 门禁（bandit/gitleaks/pip-audit/npm audit）— T1 已入 CI
