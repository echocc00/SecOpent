# SubprocessContainerExecutor（真实容器执行器）

> 状态：Phase A Task A2 完成。`AdapterRunner` 现可真实跑工具容器（nuclei/nmap/subfinder 等打靶场），替换 M1 的 mock。
> 代码：`src/secopent/infrastructure/adapters/subprocess_executor.py`；网络策略 `egress/network_policy.py`；集成测试 `tests/integration/test_subprocess_executor.py`。

## 职责

实现 M1 定义的 `ContainerExecutor` Protocol（`adapters/base.py`），用真实 `docker run` 跑 digest 钉死的工具镜像，捕获 stdout/stderr/exit_code/artifacts。

## 执行流程

1. **digest 校验**：`docker image inspect <name@digest>`。镜像不在钉死 digest 上 → `ImageDigestMismatch`（供应链防御）。tag-only 引用（无 `@digest`）跳过校验。
2. **构造 `docker run`**（§8.4 加固 flags）：
   ```
   docker run --rm
     --user 65532:65532            # non-root
     --cap-drop ALL                # 丢弃全部 capabilities
     --read-only                   # 只读根文件系统
     --tmpfs /tmp:rw,noexec,nosuid # 可写临时目录
     --env HOME=/tmp               # non-root 工具在只读根下的可写 HOME（nuclei 写配置到 $HOME/.config）
     --network bridge              # option c
     --memory <limits>             # 资源限制
     --cpus <limits>
     --workdir /work
     -v <host>:<container> ...     # 挂载 input/output
     <image>@<digest>              # digest 钉死
     <command...>                  # 工具参数
   ```
3. **执行**：`subprocess.run(args, capture_output=True, text=True, timeout)`（list 参数、无 shell，避免注入与 MSYS 路径转换）。
4. **超时**：`TimeoutExpired` → `ContainerResult(exit_code=124)`（timeout(1) 约定），不抛异常，AdapterRunner 记为非 COMPLETED。

## 安全保证（执行器强制）

| 保证 | 机制 |
|---|---|
| 供应链（digest 钉死） | `docker image inspect <name@digest>`，不匹配拒绝执行 |
| non-root | `--user 65532:65532` |
| 无 capabilities | `--cap-drop ALL` |
| 只读根 | `--read-only` + noexec/nosuid tmpfs |
| 资源限制 | `--memory` / `--cpus` |
| 网络 | option c bridge + 应用层 scope；M5 强化 nftables |

## 网络策略 option c

Docker Desktop（Windows/Mac）`--network=host` 不生效，故用 **bridge** + `host.docker.internal` 访问宿主靶场（如 `http://host.docker.internal:3000` Juice Shop / `:8080` httpbin，**不是 localhost**）。**Scope 在应用层强制**（`PolicyEngine` / `ScopeEnforcer` / `EgressGuard`，M0/M5 已实现）：AdapterRunner 在容器运行前拒绝越界目标，egress guard 阻断云 metadata（169.254.169.254）/loopback/DB/Docker host。Docker bridge 默认不路由 link-local（169.254.0.0/16），集成测试已验证 metadata 不可达。**M5 强化**：nftables/netns 网络层强制隔离。

## 集成测试（4 个，`@pytest.mark.integration`，无 Docker 自动跳过）

1. **nuclei 真扫 httpbin**：nuclei 镜像不内置模板、且本网络无法从 GitHub 下载模板，故测试**自建最小模板挂载**（`-t /templates/httpbin-status.yaml`），`-duc` 跳过更新，验证 exit 0 + JSONL 输出。
2. **non-root**：alpine `id` 输出含 uid 65532。
3. **digest 拒绝**：`alpine@sha256:000...0` → `ImageDigestMismatch`（执行前拒绝）。
4. **metadata 阻断**：alpine 访问 169.254.169.254 → `BLOCKED`（bridge 不路由 link-local）。

## 接入 AdapterRunner

- `AdapterRunner(executor=None)` 默认用 `SubprocessContainerExecutor`（生产路径）；单测注入 mock（不改）。
- `create_production_runner(policy_engine, cas_store, parser_registry)` 工厂用真实执行器。
- **A2 范围注记**：生产路径的 manifest 镜像引用（IMAGE_CATALOG）与 command 格式经 runner 的完整接线在 **A3** 完成；A2 提供执行器 + 工厂 + 集成测试。

## 已知约束 / 后续

- nuclei 模板：本环境无法从 GitHub 下载（网络限制）；A3 用挂载模板目录或镜像源解决真实扫描的模板供给。
- 网络隔离：option c 为应用层 scope；网络层 nftables 隔离在 M5。
- A3：用本执行器串完整 Assessment 链路（Planner→Orchestrator→Adapter→oracle→报告），三靶场真跑 + 修 parser 偏差。
