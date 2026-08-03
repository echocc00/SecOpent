# Checkpoint / Preflight / Deliverables（P1b）

## 定位

三项工程能力补齐 SecOpent 的 Job 生命周期：

- **WorkspaceSnapshotStore**：阶段级 tar 归档，支持 create/restore/list；排除 VCS/缓存目录；恢复前清空目标目录保证文件删除也能回放。
- **CheckpointService**：把快照包成 phase wrapper——执行前打点、异常时回滚、成功保留作为下一阶段回滚点。
- **PreflightSpec + PreflightService**：灰盒用例执行前的确定性凭据预检（form submit + success marker），成功后保存会话供后续复用；TOTP 由 secret-store 引用在 verify 时生成（不携带明文）。
- **DeliverablesLayout**：每阶段一个 `deliverables/<phase>_deliverable.md`，加 `scratchpad/` 中间产物目录；validator 拒绝缺失或空白。

## 与 Job Lease / Drift Detection 的衔接

- Checkpoint 是 drift detector 的回滚后端：检测到漂移后调用 `restore(snap_id, workdir)` 即可回到最近安全点。
- Preflight 是 case engine 的前置钩子：未通过 preflight 的用例不进入 LLM 提案阶段（节省 token，避免无效执行）。
- Deliverables 是 stage handoff 的契约载体：LLM proposal step 读取上一阶段 deliverable 而非解析日志。

## Secret 边界

- `PreflightSpec` 仅持有字段名 + secret-store 引用键（`totp_secret_ref`），从不持有密码/TOTP seed 本身（M5 规则）。
- 真实 secret 值由调用方通过 `secret_lookup: dict[str, str]` 注入；缺失抛 `KeyError`（配置错误 ≠ 认证失败）。
- 会话持久化端口 (`AuthDriver.save_session`) 只存 cookie/token 引用，不序列化密码。

## 模式来源声明

本计划的 checkpoint/rollback、preflight 验证、deliverables 目录约定三项模式借鉴自 Shannon 项目的设计思路，但全部代码独立重写：

- 不使用 git 做快照（tar.gz 替代，无 VCS 依赖）；
- 不复制任何 Shannon 源代码（AGPL 合规）；
- 应用层保持 framework-free（仅 stdlib + domain），便于测试与移植。

参见设计文档 `docs/superpowers/specs/2026-08-04-strix-shannon-layered-integration-design.md` §7。

## 已知约束

- `run_phase.action` 当前为同步 callable；异步/case-engine 接线在 P2。
- tar 恢复使用 `filter="data"`（Python 3.12+）防止路径穿越。
- TOTP 实现为 RFC 6238 30s/SHA1/6-digit，仅用于预检；生产环境如需时间窗口容差再扩展。
