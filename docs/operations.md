# 账户、维护与恢复

核心模式以控制端私有状态为权威，账户命令先备份、再修改状态，之后需要 render/apply 才改变服务端。面板模式每次从原生面板读当前账户和授权，通过原生 API 修改；旧控制端账户列表不得覆盖在线数据库。两种模式都可能重启入口，已有连接会断开。

```sh
.venv/bin/rpk account grant alice --routes route-a \
  --spec private/deployment.json --state private/state.json \
  --backup-dir private/backups --key private/recovery-key/backup.key
```

同一入口支持 `add`、`enable`、`disable`、`delete`、`rotate`、`grant`。`grant --routes` 不跟路线表示撤销全部授权；省略 `--routes` 的 add 按当前所有启用路线授权。账号稳定 ID 保留，rotate 更新 UUID 和订阅令牌，需刷新客户端资料。原生 UI 单独轮换 UUID 会失去旧 UUID 的路线授权；使用 CLI rotate 可同步保留授权。面板中保留 `rpk:id:` 账户 comment，避免丢失稳定身份；面板原生限额/有效期等额外功能不在本项目首版工作流承诺内。

面板 API 不是多调用数据库事务；运行 CLI 修改时请保持单一管理员操作。每次修改检查快照版本，先撤销目标账户路线，再改变原生账户，最后发布授权。中途失败时先 snapshot/diagnose，核对实际状态再恢复，不能盲重试或从旧状态覆盖。并发 UI 操作的完整验收仍是发布门槛。

## 诊断

```sh
.venv/bin/rpk diagnose --spec private/deployment.json --state private/state.json \
  --output private/diagnostic-001.json
```

报告包含托管状态、服务、磁盘/实际进程内核哈希、兼容开关和漂移数量，不包含账户、链接或完整访问日志。检查失败不自动换内核、不扩大监听、不放宽授权。网络验收需另外测试实际出口、TCP、UDP、错误凭据、错误路线、私网域名及落地中断。

## 备份恢复

```sh
.venv/bin/rpk backup --live --spec private/deployment.json --state private/state.json \
  --backup-dir private/backups --key private/recovery-key/backup.key
.venv/bin/rpk restore --archive private/backups/具体备份.rpk \
  --key private/recovery-key/backup.key --output private/restored-001
```

AES-256-GCM 认证加密，格式版本固定。错误密钥、篡改、截断、成员路径和完整性异常会拒绝。密钥与归档放在不同目录，另存一份离线副本；项目不托管、不找回。备份包含机器清单、稳定身份、密钥；在线面板备份还包含 SQLite 一致快照、静态网站和证书。SSH 私钥和域名账户访问权另外保存。

恢复只写入新的控制端目录。检查恢复资料后，修改 SSH 目标为明确指定的空白候选，保留逻辑节点 ID 和账号/路线/入口身份。面板恢复 render 时指定 `--restore-db 新恢复目录/panel.db`。网站目录可指向恢复出的 `site/`。TLS 可按教程重新签发；需要迁移证书的切换，须先把恢复文件安装到候选并独立验证。不可把旧数据库覆盖到活跃面板。

## 拓扑与管理模式变更

修改前备份，给候选清单保留所有旧路线记录。旧路线可 `enabled: false`，但 route ID、number、exit 不可重新解释或重复使用。增加落地必须增加独立 link key；移除落地前先禁用对应路线。链式失败不直出、不换其他落地。

核心模式 `rpk topology --new-spec ... --output ...` 创建保留身份的候选状态；单机转链式时，禁用旧 direct 路线，新增链式路线，显式给账户授权新路线。该命令不会自动改动服务器。

`rpk adopt --new-spec ... --output ...` 为核心转面板生成候选状态；对应 render 必须带 `--adopt` 和当前 receipts。部署时停止旧核心服务，导入原有账号与路线，完成检查后转交原生面板。不能接管任意已有 3x-ui，也不提供通用面板转核心命令。

面板模式先用 `rpk refresh --spec ... --state ... --output 新状态文件` 取得原生状态快照；以新状态 render，旧快照会被执行前检查拒绝。面板 `topology` 同样从在线状态创建候选。面板拓扑在线迁移、从空白机恢复与接管必须完成生命周期实测后才可发布。未验收前请使用独立候选，不把命令存在视为生产迁移保证。

## 升级

本版没有 upgrade 命令。禁止面板一键更新或官方脚本覆盖兼容内核。升级需另行审查上游兼容、安全修复、工具链、重新构建及连接测试；系统安全更新不因此整体停用。
