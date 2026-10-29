# 候选依赖核查（2026-10-29）

这份记录是发布前来源/通告核查，不是独立安全审计，也不代表完整集成验收。

- 初始参考 Xray v26.10.10 已被上游撤回。新的候选固定到 v26.10.21 提交 `1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`，使用 Go 1.27.3，并采用该版本对应 REALITY 提交 `83f621788ca88b83179810b12baa7ae518aacb83`。[上游紧急安全更新说明](https://github.com/XTLS/Xray-core/releases/tag/v26.10.21)
- 旧面板 v3.8.5 位于公开通告的受影响范围，因此新项目候选改为固定 v3.11.0。审核了本工具使用的账户 API、入站 API、原生字段与数据库读取列的差异，保留隔离集成门槛。[数据库导入通告](https://github.com/MHSanaei/3x-ui/security/advisories/GHSA-fqw4-8j9p-5r3v)、[登录限速通告](https://github.com/MHSanaei/3x-ui/security/advisories/GHSA-73xj-vvj7-fp4p)、[v3.11.0 发行](https://github.com/MHSanaei/3x-ui/releases/tag/v3.11.0)
- sing-box v1.14.2 的固定上游 SHA-256 沿用已核验发行清单；本次公开仓库通告查询检出了旧 SOCKS 认证问题，首版使用 SS2022 入站，仍需持续核查依赖与真实行为。[sing-box 公告](https://github.com/SagerNet/sing-box/security/advisories/GHSA-r5hm-mp3j-285g)
- 新候选内核同时包含旧 X25519 兼容、基于实际 VLESS 身份的路由匹配，以及归一化 UUID 重复拒绝。原生面板写入不能绕过服务端重复身份检查；已知认证 UUID 被重新使用本质上仍是同一凭据，不是新身份。不得用重新使用旧凭据来模拟账户轮换。
- 各程序固定来源与哈希；部署禁止 production 环境，禁止既有实例升级内核。没有替换原项目生产程序或改变生产兼容开关。

发布时还要完成原生面板并发/恢复测试、完整依赖复核及公网/手机客户端门槛。结果以 `acceptance.md` 和 `manifests/acceptance.json` 为准。
