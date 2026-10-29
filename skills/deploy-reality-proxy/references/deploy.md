# 部署选择

默认先满足核心代理；面板和订阅只有用户需要时启用。现成的网页入口不意味着管理员 API 可以公网开放。

| 选择 | 含义 |
| --- | --- |
| single + core | 一 VPS，Xray VLESS/REALITY/Vision 入口直出，本地节点文件 |
| chain + core | 相同入口，经 SS2022 进入明确落地，本地节点文件 |
| panel | 可选 3x-ui 原生账户和授权管理，SSH 隧道访问 |
| subscriptions | panel + HTTPS 网站之上的原生订阅过滤扩展 |
| remote target | 指定可达的远端 TLS 网站，target 与 SNI 明确配置 |
| local target | 用户域名 + 入口本机静态 TLS 网站，loopback 回落 |

读取工具包 `docs/getting-started.md` 与所选 examples。先 `init`、`plan`、`render`，再对明确目标 `apply`。不能把示例保留地址、虚构 machine_id 或未核验 SSH 公钥当作真实输入。

路线 ID 和 1..65535 数字绑定含义；废弃后不重用。账号稳定 ID 独立于可轮换 UUID/订阅令牌。新落地需要独立 SS2022 32-byte key。未知、未授权、停用路线默认拒绝。

验收至少包括实际出口、HTTPS/TCP、基础 UDP、错误身份/路线、私网与 IPv6 目的拒绝、域名在最终落地解析、落地中断不回退。设备本地已解析出的 IP 不等于服务端收到域名，不宣称设备级全流量防泄漏。
