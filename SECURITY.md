# Security Policy

## Supported Versions

下表列出了 echocc00 各项目当前受安全更新支持的版本。

| Project | Latest | Supported |
|---|---|---|
| SecSight  | v0.5.1  | ✅ |
| VidSlice  | v0.7.10 | ✅ |
| SecOpent  | v1.1.1-stable | ✅ |
| NetSage   | v0.1.1  | ✅ |
| opencut002 | v0.6.5-cli / v0.6.5-saas | ✅ |

更早的版本不再接收安全补丁,请升级到最新 release。

## Reporting a Vulnerability

如果你在任一 echocc00 项目中发现安全漏洞,**请不要** 通过公开 Issue / Discussion / Pull Request 报告。

### 通过以下渠道私下报告

1. **GitHub Private Vulnerability Reporting**(推荐)
   - 进入对应仓库首页 → **Security** tab → **Advisories** → **Report a vulnerability**
   - 或访问 `https://github.com/echocc00/<repo>/security/advisories/new`
2. **Email**:`security@echocc00.dev` *(邮箱未启用占位 — 启用前请使用 GitHub 渠道)*
3. **加密通信**(高严重度建议):PGP 公钥见下文

### 报告应包含

- 项目名与受影响版本
- 漏洞描述(攻击场景、影响范围)
- 复现步骤(尽量给出 PoC)
- 影响评估(CVSS 估算 / OWASP Top 10 类别)
- 是否已公开 / 是否被利用
- 你的联系方式(可选,便于后续沟通)

## Response Timeline

| 阶段 | 承诺时间 |
|---|---|
| 首次响应 | 收到报告后 **48 小时内** |
| 严重度评估 | 首次响应后 **3 个工作日内** |
| 修复发布 | 关键/高危 **≤ 14 天**;中危 **≤ 30 天**;低危 **≤ 90 天** |
| 公开披露 | 修复发布后 **90 天**或经与报告者协商 |

## Scope

### 在范围内

- 项目核心代码(本仓库内全部代码)
- Docker / docker-compose 部署相关配置
- 暴露端口与默认凭据问题
- 与上游依赖(Wazuh / Suricata / NetBox / Containerlab 等)的集成安全
- RAG / LLM 注入 / 提示词越权

### 不在范围内

- 上游开源项目本身的漏洞(请直接报告给上游)
- 已知的、被 CVE 数据库收录的依赖漏洞
- 社工攻击 / 物理攻击
- 需要用户主动安装恶意软件的攻击

## Recognition

负责任的漏洞报告者将在:
- 项目 CHANGELOG 中致谢
- 仓库 SECURITY Hall of Fame 列表(如本仓库未来设立)

不接受金钱奖励,但可获:
- 优先获得新功能/补丁的提前体验
- 公开致谢(如果你希望匿名也可)

## Security Best Practices for Users

部署这些项目时建议:

1. **使用最新 release**(每个项目都打了 Apache-2.0 标签)
2. **不要使用默认凭据**(修改 Wazuh / OpenSearch / Shuffle 默认账号)
3. **隔离部署**(AGPL/GPL 组件进程隔离,不链接到主体代码)
4. **网络分段**(生产环境部署在独立网段,避免暴露公网)
5. **启用审计日志**(所有变更/告警必须落审计哈希链)
6. **及时更新依赖**:`pip install --upgrade` / `npm update`

## License

本项目采用 Apache-2.0 License。Security Policy 是 License 的补充,不构成额外法律承诺。

---

<sub>Last updated: 2026-08-23 · Maintained by [@echocc00](https://github.com/echocc00)</sub>