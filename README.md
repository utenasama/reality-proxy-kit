# Reality Proxy Kit

用 Codex skill 和独立 CLI 搭建、诊断、备份与维护 VLESS + REALITY + Vision 代理。支持单 VPS 直出，以及入口 + SS2022 落地的两跳拓扑。管理面板和 HTTPS 订阅是可选扩展。

**当前是开发候选，尚无可安装发行版。** 不要在生产 VPS 上执行本仓库的候选安装流程。公网 VPS、真实 ACME 续期、Shadowrocket 和完整生命周期验收尚未完成；状态见 [验收记录](docs/acceptance.md)。CLI 会拒绝 production 环境部署。

- [完整设计与首版范围](docs/design.md)
- [开发候选使用指南](docs/getting-started.md)
- [域名、DNS 和自建 TLS 网站](docs/website.md)
- [账户、迁移、备份恢复](docs/operations.md)
- [兼容内核构建](patches/reality/README.md)
- [Codex skill](skills/deploy-reality-proxy/SKILL.md)
- [许可与来源](THIRD_PARTY_NOTICES.md)

核心模式没有面板依赖，输出本地节点、二维码和客户端配置；面板模式以 3x-ui 原生数据为账户权威。管理员界面只通过 SSH 隧道访问。通用 VLESS URI、二维码和 URI 订阅不指定 `fp` / `fingerprint`，节点订阅与客户端分流规则分开维护。

目标服务端为 **Ubuntu 24.04 amd64、systemd、公共 IPv4**。链式必须明确指定每条路线的落地，落地故障不会回退入口直出。第一跳和第二跳将来可分别扩展，但不会自动追随“更新协议”。内核升级不属于本版维护命令。

原创工具、文档和模板使用 MIT；REALITY 兼容补丁与相关修改源码保留 MPL-2.0。第三方组件各自沿用上游许可。

## English

Reality Proxy Kit is a Codex skill and standalone controller CLI for explicit VLESS REALITY Vision deployments: one VPS, or an entry server with one or more independently selected SS2022 exits. The core can run without a panel; 3x-ui and HTTPS subscriptions are optional.

This repository is a **development candidate, not an accepted installable release**. Production installation is blocked pending the acceptance gates. Ubuntu 24.04 amd64 is the target server platform. See the Chinese guides and [acceptance status](docs/acceptance.md). Original code/docs are MIT; modified REALITY/Xray sources retain MPL-2.0 and all third-party notices.
