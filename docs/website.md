# 域名、DNS 与本机 TLS 网站

远端 TLS target 不要求拥有该站域名；应选择自己有权访问、长期可用、TLS 1.3 与 H2 行为适合 REALITY 的站点，并实测 SNI、证书、连通性。不要通过任意“自动推荐域名”脚本定期更换 target。

自建网站需要自己控制的域名。先比较注册商的续费价格、转移规则、账号安全和 DNS 能力，再由用户自行购买；本项目不代购，也不绑定服务商。注册后启用账号双因素认证和续费提醒，保存域名管理权。

## 从购买到解析

1. 在注册商官网注册自己的账户，搜索尚未注册的英文域名。首版清单接受普通 ASCII 域名；先避开国际化域名、溢价域名和需要额外资质的后缀。
2. 核对首年与续费价格、币种、自动续费和转移条件。购买域名即可，搭建本系统不要求另外购买注册商的网站托管或付费 TLS 证书。
3. 由本人填写真实注册资料并完成支付、邮箱验证。启用双因素认证、域名转移锁和可用的隐私保护，另存账户恢复码；skill 不接管支付或注册商凭据。
4. 确定由哪个 DNS 服务商托管解析。使用注册商默认 DNS 时，在其 DNS 面板编辑；使用外部 DNS 时，先按对方给出的值修改域名 nameserver，再到外部 DNS 面板编辑记录。
5. 为网站选择固定名称，例如 `www.example.net`。在所属域 `example.net` 的 DNS 面板创建类型 A、名称 `www`、值为入口公网 IPv4 的记录；要使用根域时，名称通常填写 `@`，以服务商界面说明为准。
6. 在本项目清单中填写完整的 `web.domain`，例如 `www.example.net`，不要包含 `https://`、路径或端口。本机 REALITY target 的 SNI 使用同一名称；远端 target 的 SNI 使用所选远端站点名称。

## 部署与证书

1. 为网站创建 A 记录，指向入口 VPS 公网 IPv4。只有实际配置并测试 IPv6 入口时才添加 AAAA。
2. 使用普通 DNS 解析，先不启用会终止 TLS 的 CDN 代理。HTTP-01 验证需公网 80，业务需公网 443；服务商安全组也需允许。
3. 等 DNS 生效后，分别核对权威 DNS 和公开解析结果。存在错误 AAAA 时，即使 A 正确也可能签发或访问失败。
4. 设置清单 `web.enabled: true`、`web.domain`、`web.acme_email`，静态目录可选 `web.static_dir`。默认使用本项目原创中性静态页。不要放入源码、密钥、数据库、`.git`、环境变量或动态后台。
5. 测试部署 `environment: test` 使用 Certbot 实际签发；`lab` 只生成七天自签证书供隔离测试，不可当作公网证书验收。

本机 target 设置 `reality.target_mode: local`，并将 `web.domain` 包含在 `reality.server_names` 中。入口 Xray 监听公网 443，失败认证回落到 loopback Nginx 8444，传递 PROXY protocol。Nginx 后端不可对公网开放。

远端 target 与本机网站共用 443 时，网站域名不能与 REALITY SNI 重叠。Nginx stream 根据 SNI 将连接送到本机网站或 loopback Xray 9443，未知 SNI 关闭连接。它不在 REALITY 前终止 TLS。远端 target 的 `xver` 保持 0，不能向普通远端站点发送 PROXY protocol。

网站和代理参数是不同的配置项。更换网站内容不应重新生成账号、入口密钥、路线号或自动更换 REALITY target。更换域名/SNI 属于明确迁移，会影响客户端。

证书首次通过 standalone HTTP-01 申请，再切换到 webroot 续期。部署 hook 将续期证书复制到专用目录，测试 Nginx 配置并 reload。验收时执行 `certbot renew --dry-run`，再核对外部证书链、到期时间、H1/H2 和重载结果；仅启用 timer 不等于续期已经通过。

已有 TLS 网站目前作为远端 target 使用；自动接管已有 Nginx、反代或证书目录不在空白机安装范围内。请在独立测试机验证后再设计迁移。

官方资料：[REALITY](https://github.com/XTLS/REALITY)、[Certbot](https://eff-certbot.readthedocs.io/en/stable/using.html)、[Nginx ssl_preread](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html)。
