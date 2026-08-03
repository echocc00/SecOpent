# ADR: Shannon AGPL-3.0 合规策略

**日期**: 2026-08-04
**状态**: Accepted
**关联 Spec**: `docs/superpowers/specs/2026-08-04-strix-shannon-layered-integration-design.md` §10

## Context

Keygraph Shannon 是一款白盒渗透测试 agent，以 AGPL-3.0 许可发布。SecOpent 需要将其作为 peer agent 接入以补充 Strix 的黑盒能力，但 AGPL-3.0 的 copyleft 条款对代码链接/分发有严格约束。必须确保 SecOpent 的商业 IP 不受 AGPL 传染。

## Decision (D2): 进程隔离调用

Shannon 以独立容器镜像运行，与 SecOpent 之间仅通过以下界面交互：

- **入**: CLI 参数 + 环境变量（LLM key、目标 URL）
- **出**: `.shannon/deliverables/` 目录下的 markdown 文件

不导入、不链接、不复制 Shannon 源码到 SecOpent 代码树。AGPL 防火墙在进程级别建立。

## Compliance Checklist

| # | 要求 | 实施证据 |
|---|------|----------|
| 1 | 无 import/链接/代码复制 | `tests/security/test_no_agpl_code.py` grep-guard 断言 `src/` 下无 "Copyright (C) 2025 Keygraph"；CI 每次提交验证 |
| 2 | 交互面仅 CLI/env + deliverables 文件 | `ShannonBackend.build_invocation()` 仅写 env + mounts；`parse_report()` 仅读 `.shannon/deliverables/*.md` |
| 3 | 镜像独立容器运行，digest 钉死 | `image_catalog.py` 中 shannon 条目预留 digest 字段；首次拉取后钉死；运行时走 `SubprocessContainerExecutor` 硬隔离 |
| 4 | 归属声明 | Keygraph Shannon, AGPL-3.0, https://keygraph.io — 记录于 descriptor `license="AGPL-3.0"` 及本 ADR |
| 5 | 分发形态说明 | SecOpent 不分发 Shannon 二进制/镜像本体；部署方自行从 Docker Hub 拉取 `keygraph/shannon`，拉取行为不构成我方分发 |
| 6 | 修改开源义务 | 若未来修改 Shannon 本体则必须以 AGPL-3.0 开源该修改；当前无此行为，纯黑盒调用 |

## Rejected Options

### Vendor 其代码（否决）

将 Shannon 源码纳入 SecOpent 仓库并编译/链接。AGPL-3.0 copyleft 将传染整个 SecOpent 产品 IP，违反 O4=B（保护核心商业 IP）。

### 仅借鉴不运行（否决）

研究 Shannon 方法论但不实际集成。损失白盒增量价值——Shannon 的代码审计能力是 Strix 黑盒扫描的正交补充，放弃意味着放弃发现率提升。

## Consequences

- **正面**: 白盒+黑盒双引擎覆盖；AGPL 风险被进程隔离完全阻断；合规守卫自动化（grep test）
- **负面**: 部署复杂度增加（需额外拉取镜像）；观察门评估依赖真实环境数据
- **风险**: Shannon 上游若变更 deliverables 格式，解析器需跟进更新（宽容解析 + fixture 回归缓解）
