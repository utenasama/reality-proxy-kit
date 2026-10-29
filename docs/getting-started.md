# 开发候选使用指南

本指南供独立测试 VPS 使用，production 环境仍被拒绝。完整支持目标和未通过项目见 [验收记录](acceptance.md)。安装操作会管理所选空白 VPS 的防火墙、systemd 服务及专用 Nginx 配置，不适合已有业务机器。

## 控制端

需要 Python 3.12+、OpenSSH、Git；macOS、Linux 为目标控制端，Windows 走 WSL。保持此源码目录完整；当前 CLI 使用仓库内的版本清单和模板，不应只复制 Python 文件。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/rpk --help
```

开发版 skill 可复制 `skills/deploy-reality-proxy/` 到 `~/.codex/skills/`。它独立携带决策参考，并要求定位指定版本的工具源码；不依赖作者私有项目。skill 本身不会自动批准购买 VPS、域名或操作未指定主机。

## 私有清单

将 `examples/single.json` 或 `examples/chain.json` 复制至 `private/deployment.json`。示例保留地址不能直接部署。按实际情况填写公网 IPv4、可选入口 IPv6、远端 target/SNI 或本机网站域名。

每台机器添加 `ssh`，使用已经通过服务商控制台或其他可信渠道核验的主机公钥和 machine ID。`ssh-keyscan` 仅能收集公钥，不能证明它可信。

```json
{
  "ssh": {
    "address": "203.0.113.10",
    "user": "root",
    "port": 22,
    "key_file": "keys/test-vps",
    "known_hosts": "known_hosts",
    "machine_id": "00000000000000000000000000000000"
  }
}
```

路径相对清单位置解析。`machine_id` 必须替换为该测试机 `/etc/machine-id` 的实际内容；示例值不是默认允许身份。使用普通用户时必须具备非交互 sudo。防火墙保留这里声明的 SSH 端口和已建立连接；不要填错。

## 初始化、计划、渲染

```sh
.venv/bin/rpk init --spec private/deployment.json --state private/state.json --account alice
.venv/bin/rpk plan --spec private/deployment.json --state private/state.json
```

`init` 只生成私有身份，已有状态不会覆盖。`plan` 不连接主机，不显示凭据。按照 [构建说明](../patches/reality/README.md) 得到兼容内核后，渲染候选：

```sh
.venv/bin/rpk render --spec private/deployment.json --state private/state.json \
  --core build/core-candidate/xray-linux-amd64 \
  --core-manifest build/core-candidate/build-manifest.json \
  --receipts private/receipts.json --output private/release-001
```

编译器核对仓库内审核清单、二进制哈希和拓扑；输出包含真实凭据，权限为私有。每次用新目录，审查 `plan.json` 后执行已经授权的测试部署。

```sh
.venv/bin/rpk apply --spec private/deployment.json --state private/state.json \
  --bundle private/release-001 --receipts private/receipts.json \
  --backup-dir private/backups --key private/recovery-key/backup.key
```

执行前检查所有主机，再按落地、入口顺序部署。保存 receipts 后，后续候选必须带上它们，防止旧计划覆盖新状态。重复同一候选应返回 unchanged，且仍检查进程健康。文件回滚不能撤销系统包安装、证书签发或已提交的面板 API 事务；失败时停止重试，按诊断报告核查。

## 客户端交付

```sh
.venv/bin/rpk export --spec private/deployment.json --state private/state.json \
  --account alice --output private/alice-export-001
```

生成 `nodes.txt`、SVG 二维码、Mihomo 节点片段、逐节点 Xray 客户端配置。节点含凭据，不能提交、公开分享或贴入 issue。Mihomo 文件只有节点；不要用它覆盖已有完整分流配置。导出 Xray 配置只监听本机 SOCKS 17808，不自动接管系统代理。

## 面板与订阅

清单明确设置 `management: panel`。`subscriptions: true` 还必须启用 HTTPS 网站。管理员通过本机 SSH 隧道连接远端 `127.0.0.1:54321`，访问 `http://127.0.0.1:本地端口/admin/`；管理员密码保存在私有状态，不输出到终端。

面板原生订阅只监听 `127.0.0.1:2096`，过滤器监听 `127.0.0.1:2097`，公网仅开放 HTTPS `/s/令牌`、`/m/令牌`、`/x/令牌`。令牌从当前面板账户取得。新账户默认没有路线授权时不会获得节点。勿使用面板一键更新内核。

部署命令成功只证明报告列出的配置/服务检查；必须再做出口、TCP/UDP、认证负例、私网拒绝和客户端验收。
