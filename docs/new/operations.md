# Photon 日常操作

本文整理当前实现下最常用的运行、检查和恢复路径。它面向 operator：先让节点安全跑起来，再知道出问题时从哪里看。

命令示例默认使用已安装到 PATH 的 `photon`。固定双实例安装中，管理节点使用
`photon-admin`；它由安装脚本的 `--admin` 开关安装，并自动选择 `/etc/photon/admin`
下的配置和数据库，不需要手工传环境变量。

## 配置选择

默认配置路径是 `/etc/photon/config.yaml`。多节点实验时应显式指定：

```bash
PHOTON_CONFIG=/tmp/photon-a/config.yaml photon advanced sync status
```

如果用 `sudo` 排查系统数据面，注意保留环境变量：

```bash
sudo -E env PHOTON_CONFIG=/tmp/photon-a/config.yaml photon debug links
```

否则 root 进程可能读取 `/etc/photon/config.yaml` 或另一个状态库，导致 debug 输出和你以为的节点不一致。

## 初始化信任链

推荐把 root admin、一级管理 Zone 和普通节点分开。

Root admin 只管理 `.`：

```bash
photon-admin gossip root init
photon-admin gossip root pubkey
```

一级管理 Zone 先生成 key 和 join request：

```bash
PHOTON_CONFIG=/tmp/photon-catofes/config.yaml photon gossip keygen /tmp/catofes.key.json
PHOTON_CONFIG=/tmp/photon-catofes/config.yaml photon gossip join request catofes. /tmp/catofes.key.json
```

把 request 交给 root admin 签发：

```bash
photon-admin gossip delegate issue --permissions write,delegate,allocate-ip <request-payload>
```

再把 bundle 交回管理 Zone：

```bash
PHOTON_CONFIG=/tmp/photon-catofes/config.yaml photon gossip join accept <bundle-payload> /tmp/catofes.key.json
PHOTON_CONFIG=/tmp/photon-catofes/config.yaml photon debug verify catofes.
```

普通节点重复同样流程，只是 delegation 由 `catofes.` 管理节点签发，而不是 root admin 直接签发。

当前 CLI 支持复制粘贴 base64 payload；需要落盘时也兼容旧 JSON 文件路径。

`root init` 创建的 root authority 默认拥有当前所有内建权限，包括 `delegate`、`write` 和 `allocate-ip`。route announcement 使用通用 `write`；子 Zone 默认只获得 `write,delegate`。如果一个管理 Zone需要分配 IPAM pool/assignment，应在 `delegate issue` 时显式加 `--permissions write,delegate,allocate-ip`。已有 delegation 可由父 Zone 管理端原地升级：

```bash
photon-admin gossip delegate grant catofes. allocate-ip catofes-authority.b64
```

父管理端在线参与 gossip 时，子节点同步到新版父 Zone snapshot 后，会验证父 delegation、epoch 和本地 identity key，并只刷新自己缓存的 authority 与直接 parent proof；本 Zone 的 records、子 delegation、revocation 和 history 不会被远端 snapshot 覆盖。这个刷新与父 snapshot 原子提交，不会暴露“父 delegation 已更新、本地 authority 仍是旧 epoch”的半更新状态。daemon 启动时也会根据已缓存的父 delegation 执行同样的刷新，使升级前已经形成的半更新状态自动恢复。

bundle 仍可用于父管理端离线、gossip 不可达或需要显式交付的场景：

```bash
PHOTON_CONFIG=/tmp/photon-catofes/config.yaml photon gossip join accept catofes-authority.b64
```

旧版本中若存在只拥有 `write:route`、`write:service` 或 `write:wireguard`、却没有通用 `write` 的 authority，父 Zone 应先补发包含 `write` 的 authority。普通节点和 root 的默认 authority 原本已经包含 `write`，无需迁移；保留同一签名 key 时，authority refresh 后既有 route、service 和 WireGuard records 会按新的通用写权限重新通过验证。

首次 `join accept` 仍需要传入 `key.json`；已经加入的管理端接受 authority refresh bundle 时可以省略 key，CLI 会使用本地 state meta 中的 `zone_private_key` 校验并保留原有本地状态。

如果 root admin 保持离线，它写入的 root Zone records 不会自动进入在线 gossip 网络。可以把 root Zone signed snapshot 导出成文件，再交给在线管理端导入：

```bash
photon-admin route ipam pool create --direct . 2a0d:2905::/32 --delegated-to .
photon-admin route ipam pool create --direct . 2a0d:2905::/58 --delegated-to catofes.
photon-admin advanced recovery export-zone . root-zone.b64

PHOTON_CONFIG=/tmp/photon-catofes/config.yaml photon advanced recovery import-zone root-zone.b64
```

`delegated_to` 是精确 owner，不是向下继承开关。第一条 `delegated_to=.` 只让 root 拥有 `/32`；第二条才让 `catofes.` 精确拥有 `/58`，从而可以继续切子池或发布 assignment。子 Zone 不能直接使用 ancestor 的 self pool；缺少显式覆盖 pool 时，CLI 会以 `ipam_pool_owner_mismatch` 或 `ipam_assignment_pool_mismatch` 早失败。

`export-zone` / `import-zone` 搬运的是已签名 Zone snapshot，不搬运 root 私钥；导入端仍会按 trusted root、delegation chain 和 record signature 做验证。`import-zone` 会优先通过本机 daemon control socket 导入，输出里出现 `via daemon` 表示写入已经进入在线 daemon 的内存状态和 DB。如果目标节点没有 daemon 或你想显式跳过 control socket，加 `--direct` 直接写本地 DB。

排查本机视角时用 `photon route ipam mine` 查看分配给 `managed_zone` 的 assignment 和本 Zone 精确拥有/发布的 pool；排查单个地址或前缀时用 `photon route ipam get <addr-or-prefix>`，必要时加 `--json` 取得 pool chain、best pool、assignment、route 和诊断码。

## 启动 Daemon

推荐长期运行入口是 `photon daemon`：

```bash
PHOTON_CONFIG=/etc/photon/config.yaml photon daemon
```

临时排障时可以指定较短 interval，靠事件触发同步：

```bash
PHOTON_CONFIG=/tmp/photon-a/config.yaml photon daemon --interval 60
```

优雅关闭：

```bash
# 通过 control socket 关闭
photon daemon --shutdown

# 或向进程发送 SIGTERM
kill -TERM <pid>
```

使用 systemd 时直接运行：

```bash
systemctl stop photon.service
systemctl restart photon.service
```

示例 unit 会在异常退出后重启；正常停止不重启；停止超时为 30 秒。

daemon 做这些事：

- 监听 UDP gossip。
- 发布本节点 endpoint 和 transport records。
- 处理 object pull。
- 接收 control socket 上的本机写入请求。
- 执行 IPsec、routing、firewall、health reconcile。
- 提供 Observer API/UI。

崩溃重启后，daemon 从 BoltDB 恢复并重新 reconcile；未完成的同步会自动重试。BIRD 默认使用 `shutdown_policy: persist` 跨 Photon 重启保留，实验环境可设为 `stop`。详细生命周期见 [Daemon 设计与实现](daemon.md#53-状态持久化停止与崩溃恢复)。同机运行节点与管理身份时，分别使用 `photon.service` / `photon-admin.service` 和 `photon` / `photon-admin` 命令，隔离要求见[同机双实例](daemon.md#52-同机双实例)。

CLI 写操作会优先尝试 running daemon 的 control socket；daemon 不在线时，部分命令会回退为直接写本地状态。你也可以显式加 `--direct` 跳过 control socket 探测，直接写本地 DB。

## --direct 离线写入

支持 `--direct` 的命令包括：`record put`、`delegate issue`、`delegate grant`、`delegate revoke`、`join accept`、`route announce`/`withdraw`、IPAM pool/assignment 写命令，以及 `advanced recovery import-zone`、`advanced recovery purge-revoked --apply`、`advanced recovery cleanup-ipsec`。

使用场景：

- 节点还没有 daemon，但需要先写入初始 delegation、route、IPAM 等记录。
- 明确知道 daemon 不在线，且不想等待 control socket 探测超时。
- 恢复场景下需要直接操作本地 DB。

使用 `--direct` 时不会触发 daemon 的 runtime reconcile（例如不会立即刷新路由或 IPsec）。写入只持久化 signed record，等 daemon 启动后才会 apply 数据面。因此不要用它绕过正在运行的 daemon 去“热改”状态。

示例：

```bash
# daemon 不在线时直接签发 delegation
photon-admin gossip delegate issue --direct --permissions write,delegate <request-payload>

# 直接接受 join bundle
PHOTON_CONFIG=/tmp/photon-catofes/config.yaml photon gossip join accept --direct <bundle-payload> /tmp/catofes.key.json

# 直接写 record
PHOTON_CONFIG=/tmp/photon-a/config.yaml photon gossip record put --direct node-a.catofes. endpoints/udp '{"endpoints": [...]}' json

# 离线导入 root Zone snapshot
PHOTON_CONFIG=/tmp/photon-catofes/config.yaml photon advanced recovery import-zone --direct root-zone.b64
```

**注意**：使用 `--direct` 前必须确认没有 daemon 正在管理同一份状态文件或相同的 IPsec/XFRM 对象，否则可能产生并发写或数据面状态不一致。

## 手动同步

长期运行用 daemon。排障时可用手动同步命令。`serve/once` 会独立打开本地状态和监听端口，应在对应节点的 daemon 停止时使用；`once` 不会向在线 daemon 发送同步请求。

查看同步状态：

```bash
PHOTON_CONFIG=/tmp/photon-a/config.yaml photon advanced sync status --verbose
```

对某个 peer 执行一次同步：

```bash
PHOTON_CONFIG=/tmp/photon-a/config.yaml photon advanced sync once node-b.catofes.
```

启动用于协议调试的被动 Gossip 服务（UDP 同步和 TCP 对象拉取）：

```bash
PHOTON_CONFIG=/tmp/photon-b/config.yaml photon advanced sync serve
```

常驻同步统一使用 daemon（原 `advanced sync run` 入口已移除）：

```bash
PHOTON_CONFIG=/tmp/photon-a/config.yaml photon daemon --interval 5
```

`advanced sync once` 如果输出 pending zones，通常表示对端已返回摘要，但还有对象需要继续拉取；再跑一轮或交给 daemon 后台收敛。

## 常用 Debug

基础状态：

```bash
photon advanced sync status --verbose
photon gossip zone show node-b.catofes.
photon gossip record list node-b.catofes. --filter identity
photon debug verify node-b.catofes.
```

Gossip 和 peer：

```bash
photon debug peer node-b.catofes.
photon debug peers
photon debug zone node-b.catofes.
photon debug zone node-b.catofes. --json --history
photon debug records node-b.catofes. --prefix endpoints/
photon debug endpoints
photon debug admission
photon debug revoke-impact node-b.catofes.
```

数据面：

```bash
photon debug links
photon debug routing routes
photon debug routing routes 10.42.0.0/24
photon debug routing status
photon debug routing bird status
photon debug routing bird route
photon debug routing ip route
photon debug firewall
photon firewall show --verbose
photon health
photon health --sort rtt --verbose
photon debug rotate-port
```

通过 control socket 查询单条 record（默认输出面向人的文本）：

```bash
photon gossip record get <zone> <key> --verbose
```

需要完整 JSON、签名、hash 或历史版本时使用 debug：

```bash
photon debug record <zone> <key> --history 10
```

底层数据库：

```bash
photon debug db stats
photon debug db dump
```

`debug` 命令通常会优先读取 daemon 的 committed StateStore view；daemon 不在线时读取本地状态文件和最近一次 runtime snapshot。

## 开启 Debug Log

临时打开：

```bash
PHOTON_LOG_LEVEL=debug PHOTON_CONFIG=/tmp/photon-a/config.yaml photon daemon
```

或写入配置：

```yaml
log:
  level: debug
  mode: stderr+file
  file: /var/log/photon.log
```

debug log 常见字段包括 peer、message type、zone/record 数量、字节数、耗时、reject reason、object pull、relay、quota、IPsec reconcile action 等。

常见 reject reason：

- `unknown_peer`：对端不在 bootstrap 或 verified peer 集合中。
- `addr_mismatch`：peer ID 与来源地址不匹配。
- `message_too_large`：UDP datagram 超过预算。
- `replay`：nonce/timestamp 防重放拒绝。
- `quota`：peer 触发 byte/object rate limit。
- `verify_failed`：Zone trust chain 或 record 签名验证失败。
- `unsupported_wire_version`：wire version 不兼容。

Daemon 使用结构化日志，关键事件如下：

| 组件 | 事件 | 含义 |
|------|------|------|
| `daemon` | `started` | Daemon 启动，包含 peer_id、addr、interval |
| `sync` | `zone_applied` | Zone snapshot 被成功应用 |
| `sync` | `zone_apply_failed` | Zone snapshot 应用失败（含 reject reason） |
| `sync` | `hinted_sync_started` | 收到 announce hint 后启动 sync session |
| `sync` | `send_failed` | 发送 UDP 消息失败 |
| `sync` | `event_dropped` | Sync event 因队列满被丢弃 |
| `ipsec` | `vici_lifecycle_event` | StrongSwan 生命周期事件 |
| `ipsec` | `reconcile_failed` | IPsec reconcile 失败 |
| `routing` | `reconcile_failed` | Routing reconcile 失败 |
| `firewall` | `no_backend_available` | 无可用防火墙后端 |
| `endpoint` | `publish_failed` | 端点发布失败 |
| `endpoint` | `reflector_failed` | 公网地址反射器查询失败 |
| `auto_join` | `adopted` | 该节点被父 zone 采纳 |
| `auto_join` | `adopt_failed` | 采纳失败（含原因） |
| `state` | `save` | 状态文件保存（含 records 数） |

## Observer

配置 `observer:` 后，daemon 会启动只读 HTTP/API 控制台。默认建议绑定 loopback：

```yaml
observer:
  listen: 127.0.0.1:8080
```

启动 daemon 后访问：

```text
http://127.0.0.1:8080/
```

Observer 适合看当前节点的 zones、peers、links、routes、BIRD、health 和 events。它是只读入口；写操作仍通过 CLI/control socket。

如果要看 health 历史曲线，需要配置本地 spool：

```yaml
health:
  metrics:
    local_spool_path: /var/lib/photon/health-spool
```

## IPsec / StrongSwan 排障

先从 Photon 自己的视角看：

```bash
PHOTON_CONFIG=/etc/photon/config.yaml photon debug links
PHOTON_CONFIG=/etc/photon/config.yaml photon debug endpoints
```

再看系统状态：

```bash
swanctl --list-sas
ip xfrm state
ip xfrm policy
ip link show type xfrm
```

如果使用 netns：

```bash
ip netns exec photon ip link
ip netns exec photon ip route
ip netns exec photon ip -6 route
```

排查时按层分开：

- IKE/CHILD_SA 是否 established。
- XFRM state/policy 和 XFRM interface 是否在预期 namespace。
- tunnel address 和 peer route 是否存在。
- BIRD/Babel 是否看到邻居和路由。
- firewall 是否放行 ingress/forward/output。

不要只凭 `swanctl --list-sas` 判断数据面已经通了。SA established 只说明协商成功，不说明内层 tunnel route、namespace placement 或 firewall 都正确。

## Routing / BIRD 排障

先看 Photon read model：

```bash
photon debug routing routes
photon debug routing routes 10.42.0.0/24
photon debug routing status
photon debug routing bird interface
photon debug routing bird filter
photon debug routing bird route
photon debug routing ip route --netns photontesth2
photon debug links
```

再看 BIRD：

```bash
birdc -s /var/lib/photon/bird/bird-default.ctl show status
birdc -s /var/lib/photon/bird/bird-default.ctl show protocols
birdc -s /var/lib/photon/bird/bird-default.ctl show route all
```

实际 control socket 路径取决于 `routing.instances[].control_socket`，未配置时在 `<data_dir>/bird/` 下。

## Firewall 排障

Photon 视角：

```bash
photon debug firewall
```

系统视角：

```bash
nft list ruleset
iptables -S
iptables -t nat -S
```

如果 firewall instance 绑定 netns，要在对应 namespace 中查看：

```bash
ip netns exec photon nft list ruleset
ip netns exec photon iptables -S
```

Photon 只应管理带 owner 边界的规则。发现规则残留时，先确认它是否是 Photon-owned，再决定是否用 recovery 或手工清理。

## 恢复操作

从 peer 显式拉回某个 Zone：

```bash
photon advanced recovery pull-zone node-b.catofes. --from node-b.catofes.
```

拉回某个 Zone 及祖先链：

```bash
photon advanced recovery pull-chain node-b.catofes. --from node-b.catofes.
```

清理本机 Photon 管理的 IPsec 链路：

```bash
sudo -E env PHOTON_CONFIG=/etc/photon/config.yaml photon advanced recovery cleanup-ipsec

# 明确跳过 daemon 探测
sudo -E env PHOTON_CONFIG=/etc/photon/config.yaml photon advanced recovery cleanup-ipsec --direct
```

`cleanup-ipsec` 会优先走 daemon；daemon 不在线时直接读取本地状态并调用配置的 IPsec/XFRM driver。加 `--direct` 可显式跳过 control socket 探测。它会拒绝清理无法验证为 Photon-owned 的 link。

## 关键路径与注意事项

关键文件路径（默认 `<data_dir>` 由 `PHOTON_CONFIG` 或 `config.yaml` 中的 `data_dir` 决定）：

- 状态数据库：`<data_dir>/photon.db`（BoltDB，含 Network、meta）
- Control socket：root 为 `/run/photon/photon.sock`；非 root 为 `<data_dir>/photon.sock`；`PHOTON_CONTROL_SOCKET` 可覆盖
- 配置文件：`<data_dir>/config.yaml`
- BIRD 配置：`<data_dir>/bird-<instance>.conf`

运行注意事项：

- **daemon 是单 writer**：不要同时运行多个 `photon daemon` 实例操作同一个 state 文件。
- **reload**：`reload` 命令会重新加载配置和状态文件，但不允许切换 `state_path`、control socket 路径或 identity key。
- **root init 不能通过 daemon 执行**：root zone 初始化需要在 daemon 启动前以 recovery/direct 方式执行。
- **状态文件外部修改**：daemon 事件循环会检测磁盘状态文件是否被外部修改，检测到变化后自动加载并触发 reconcile。

## 常见问题入口

**看不到 peer**

先查：

```bash
photon advanced sync status --verbose
photon debug endpoints
photon debug peer <peer-id>
```

重点确认 `peer_id`、bootstrap 地址、`publish_endpoints`、endpoint discovery mode、trusted root，以及命令是否读了正确的 `PHOTON_CONFIG`。

**record 没传播**

先确认本地是否写入、签名是否有效：

```bash
photon gossip record list <zone> --filter <key-or-value>
photon debug verify <zone>
```

再看同步状态和 debug log。大对象或 UDP 受限环境下，object pull / UDP chunk fallback 可能是关键路径。

**IPsec 记录发布了但不建链**

检查三件事：

- 本机是否有 `overlays[]` link group。
- 远端 `ipsec/profile`、`ipsec/addresses`、`ipsec/ports`、`ipsec/transport-key`、`ipsec/overlays/<id>` 是否都在 verified active state。
- 本机 connect/deny policy、address family、path mode、accept intent 是否匹配。

**sudo 后输出不对**

优先检查环境：

```bash
env | rg 'PHOTON_CONFIG|PHOTON_STATE|PHOTON_CONTROL_SOCKET'
sudo -E env | rg 'PHOTON_CONFIG|PHOTON_STATE|PHOTON_CONTROL_SOCKET'
```

很多“状态不一致”其实是 root 进程读了另一个 config 或另一个 state path。

## 推荐阅读顺序

先读：

1. `docs/new/overall.md`
2. `docs/new/config.md`
3. `docs/new/operations.md`
4. `docs/new/testing.md`

再按问题进入模块文档：gossip、transport、routing、firewall、health、observer。
