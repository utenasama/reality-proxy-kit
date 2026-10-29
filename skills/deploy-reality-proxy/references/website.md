# 网站与共享入口

按工具包 `docs/website.md` 指导购买域名、设置 A/可选 AAAA、关闭会终止 REALITY TLS 的 CDN 代理、验证 DNS、签发和续期。购买需要用户直接授权/操作，不从“搭代理”推导采购权限。

本机 target：Xray 公网 443 → PROXY protocol → Nginx loopback 8444。远端 target 且带网站：Nginx stream 公网 443 按 SNI → 网站 8444 或 Xray 9443，网站域名和 REALITY SNI 不能重叠；远端 target 使用 xver=0。

检查 HTTPS、H1/H2、真实来源、未知 SNI、分片 ClientHello 和新旧指纹。仅验证 Nginx 语法不足以宣布共享入口已通过。

静态模板可以替换成用户提供的合法静态文件。不要复制未知许可素材、论坛全文或个人原有站点品牌。不公开管理、DB、密钥、环境文件。安装网站不得隐式改 SNI/target 或重新生成身份。
