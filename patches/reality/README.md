# 旧 X25519 兼容补丁

基线为 Xray `1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`、REALITY `83f621788ca88b83179810b12baa7ae518aacb83`、Go 1.27.3。

REALITY 补丁仅在 `UTENASAMA_REALITY_LEGACY_X25519=1` 时允许符合条件的旧 X25519 ClientHello 继续原有认证；它不关闭 REALITY 认证，也不包含流量观察扩展。通用 URI 不强制指定指纹。

`../xray/` 另有一个 MPL-2.0 路由身份补丁：`RPK_VLESS_IDENTITY_ROUTING=1` 时，VLESS 路由的 user matcher 使用规范化认证 UUID，而非可重复的面板名称；原生统计仍使用原 email。这样删除账户后同名新建不会继承旧 ACL。关闭该开关保持上游行为，但本工具生成的身份规则会拒绝业务；安装/诊断必须检查此开关。

```sh
python3 scripts/build_core.py --go /你安装的/go1.27.3/bin/go \
  --work-dir build/core-candidate --host-binary
```

使用全新构建目录。脚本读取固定提交、检查补丁锚点、执行兼容及相关 Xray 测试、生成 linux/amd64 二进制、构建清单与对应修改源码包。`--host-binary` 额外生成本机测试用二进制。不会安装或连接 VPS。

`xray-modified-source.tar.gz` 内含修改后的 Xray、完整修改 REALITY 源码、Go vendor 依赖及其保留的声明、模块来源记录、补丁和构建脚本。在其中的 `xray/` 使用相同工具链、`CGO_ENABLED=0 GOOS=linux GOARCH=amd64` 和脚本记录的 flags 可构建；vendor 支持离线依赖。发布必须同时提供对应源码，不仅链接未修改的上游。

本目录 `.go` 补丁沿用 MPL-2.0；REALITY 的 Go 来源代码保留 LICENSE-Go，完整许可位于 `../../licenses/`。构建机器及二进制/源码哈希见 `manifests/core-candidate.json`。候选构建不是发布验收。

升级前必须核对：上游是否仍需补丁、兼容开关语义、新旧握手、错误认证、Xray 与面板交互、实际进程哈希/环境、回退路径、许可与源码。任何一项未通过均不切换。禁止面板一键更新或官方安装脚本直接覆盖兼容内核。
