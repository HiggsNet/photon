# Photon 配置结构

Photon 默认读取 `/etc/photon/config.yaml`。本地开发或同一机器多节点运行时，通常用 `PHOTON_CONFIG=/path/to/config.yaml` 指定配置文件。

配置文件描述的是**本机 daemon 如何运行**，不是全网数据库本身。会进入 gossip 的内容必须由本节点签名成 Zone record；本地配置只决定是否发布这些 record，以及如何把 verified active state 收敛成本机 runtime 状态。

完整注释模板见仓库根目录的 `config.example.yaml`。本文只整理主要结构和边界。

## 读取规则

当前配置加载器使用严格 YAML 字段校验。写错字段名会直接报错，不会静默忽略。

几个读取规则需要注意：

- `PHOTON_CONFIG` 覆盖默认配置路径。
- `PHOTON_STATE` 覆盖最终状态数据库路径，优先级高于配置里的 `state_path`。排障时要确认它没有指向另一个节点。
- `PHOTON_CONTROL_SOCKET` 覆盖 control socket 路径，优先级高于由运行身份和 `data_dir` 推导的默认值。
- `PHOTON_CONTROL_SOCKET_SCOPE=data-dir` 强制从 `data_dir` 推导 control socket；主要用于 root 身份下的隔离测试，避免连接 `/run/photon/photon.sock`。
- `PHOTON_LOG_LEVEL` 临时覆盖配置里的 `log.level`，常用于排障。
- `trusted_root_public_key` 也兼容 `root_public_key` / `trusted_root_key`。
- gossip 身份、bootstrap、同步限额和 endpoint discovery 必须写在 `gossip:` 下。
- 一些列表字段仍兼容旧的逗号分隔字符串，但新配置应使用 YAML list。
- duration 字段使用 Go duration 写法，例如 `5s`、`10m`、`1h`。

默认状态目录是 `/etc/photon`，默认数据库是 `<data_dir>/photon.db`。配置里的 `state_path` 可以显式指定数据库文件路径；`PHOTON_STATE` 又能覆盖 `state_path`。如果没有显式配置文件，程序会使用内置默认值；真正部署建议始终写明 `data_dir`、`trusted_root_public_key`、`gossip.peer_id` 和必要的 `gossip.bootstrap`。

## 最小节点配置

一个只跑 gossip/daemon 的普通节点大致需要：

```yaml
data_dir: /etc/photon
trusted_root_public_key: <base64-ed25519-public-key>

gossip:
  peer_id: node-a.catofes.
  listen_addr: "[::]:33434"
  bootstrap:
    - id: node-b.catofes.
      addr: 203.0.113.20:33434
  init:
    managed_zone: node-a.catofes.
    key_path: /etc/photon/identity.key.json
```

字段含义：

- `trusted_root_public_key`：本机信任根。普通节点必须配置，避免误信任本地残留状态。
- `gossip.init.managed_zone`：本节点负责写入的 Zone，普通节点通常就是自己的 FQDN。
- `gossip.init.key_path`：本节点写 record 用的 ED25519 私钥路径。私钥不写进 YAML。
- `gossip.peer_id`：gossip peer ID。现代配置建议等于 `gossip.init.managed_zone`。
- `gossip.listen_addr`：本地 UDP gossip 监听地址，默认 `[::]:33434`，通常同时接收 IPv4 和 IPv6。
- `gossip.bootstrap`：启动时允许联系的已知 peer。运行中还会从 verified endpoint record 更新 peer 地址。

## Gossip 与发现

Gossip 相关配置控制 UDP 消息大小、对象同步和 endpoint 发布。

常用字段：

```yaml
gossip:
  advertise_addrs:
    - 203.0.113.10:33434

  # max_datagram_bytes: 1200
  # max_sync_zones: 16
  # max_sync_records: 1024

  # endpoint_discovery: all
  # publish_endpoints: true

  # reflectors: auto
  # reflector_interval: 5m
  # reflector_timeout: 3s

  # endpoint_ttl: 3h
  # endpoint_refresh: 30m
  # endpoint_grace: 10m
  # endpoint_source_order:
  #   - advertise
  #   - bootstrap
  #   - reflector
  #   - interface
  # filter_private_ipv4: true
```

字段说明：

- `gossip.advertise_addrs`：管理员显式发布的 gossip endpoint，优先级高于 reflector 和接口扫描；它不是 IPsec endpoint，IPsec 地址使用 `ipsec.announce_addrs` / `ipsec.announce_dns`。
- `gossip.max_datagram_bytes`：单个 gossip UDP datagram 的最大字节预算。公网环境不应依赖 IP fragmentation，大对象和大 snapshot 应通过 object pull 收敛。
- `gossip.max_sync_zones` / `gossip.max_sync_records`：单次 announce/snapshot 携带的 Zone 和 record 数量上限。
- `gossip.endpoint_discovery`：endpoint 发现模式，可设为 `all`、`loopback_only` 或 `advertise_only`。如果未设置且 bootstrap 都是 loopback，daemon 会自动按 `loopback_only` 处理，避免本地 smoke 发布无关接口地址。
- `gossip.publish_endpoints`：是否发布本节点 signed endpoint record。`false` 适合 outbound-only 或 NAT/CGNAT 节点；禁用发布后，本节点仍可主动连接 bootstrap 或已知 peer。
- `gossip.reflectors` / `gossip.reflector_interval` / `gossip.reflector_timeout`：公网 IP reflector 来源、刷新间隔和单次请求超时。`reflectors: auto` 使用内置列表；`off` / `none` 禁用公网 reflector。
- `gossip.endpoint_ttl` / `gossip.endpoint_refresh` / `gossip.endpoint_grace`：signed endpoint record 的可用窗口、地址集合不变时的低频续租间隔，以及 endpoint 变化后继续保留旧地址的窗口。
- `gossip.endpoint_source_order`：出站连接候选地址的来源优先级，常见值是 `advertise`、`bootstrap`、`reflector`、`interface`。
- `gossip.filter_private_ipv4`：是否过滤接口扫描得到的 RFC1918 IPv4，默认 `true`。私网实验需要发布内网地址时再设为 `false`。

## 日志

日志默认输出到 stderr。daemon 部署时可以复制到文件或 syslog：

```yaml
log:
  level: info
  mode: stderr+file
  file: /var/log/photon.log
```

支持级别是 `debug`、`info`、`warn`、`error`。`PHOTON_LOG_LEVEL=debug` 可以临时覆盖配置，常用于排查 gossip、object pull、relay、IPsec reconcile 和限流原因。

## Netns

`netns` 声明本机会使用的 network namespace。overlay、routing 和 firewall 都通过名字引用这里的定义。

```yaml
netns:
  default:
    name: photon
    # kind defaults to name; create defaults to true.
    # Set create: false to reuse an existing netns.
    # Declaring forwarding enables transit; omit it to disable transit.
    forwarding:
      allow_prefixes:
        - 10.42.0.0/16
  # edge:
  #   name: edge
```

`default` 是 overlay link group、routing instance 和非 host firewall instance 的默认 netns。其他名字，例如 `edge`，与 `default` 并列声明，供 `overlays[].netns`、`routing.instances[].netns` 和 `firewall.instances[].netns` 引用。

`kind` 默认为 `name`，命名 netns 的 `create` 默认为 `true`；只有显式写 `create: false` 时才复用已有 namespace。`forwarding` 属于 netns，并由该 netns 中的 BIRD 与 firewall 共同消费；声明该段即默认 `transit: true`，省略时等同于 `transit: false`。如有需要仍可显式写 `transit: false` 覆盖。`transit: false` 只禁止本节点充当 XFRM-to-XFRM mesh 中继；Photon 仍会按运行需要开启内核 IPv4/IPv6 forwarding。`allow_prefixes` / `deny_prefixes` 限制允许中继和继续宣告的授权前缀。

## IPsec Provider

`ipsec:` 配置本机 IPsec provider。它本身不等于“加入 mesh”；只有配置了使用 `provider: strongswan` 的 `overlays[]` 后，daemon 才会发布本节点 signed `ipsec/*` records。

```yaml
ipsec:
  role: both
  # driver: strongswan
  vici_socket: /run/charon.vici

  port_mode: fixed
  # port_previous_grace: 2h

  announce_addrs:
    - 203.0.113.10
    - 2001:db8::10
  announce_dns:
    - vpn-a.example.com
  announce_dns_reconnect_after: 5m
  announce_gossip_endpoints: true
```

主要字段：

- `role`：`out`、`in`、`both`。表达本节点 IPsec 连接意图；默认 `both`。
- `driver`：`strongswan` 或 `dry-run`。默认 `strongswan`；无 root/VICI/XFRM 的开发环境用 `dry-run`。
- `vici_socket`：StrongSwan VICI socket 路径。Photon 进程不直接管理 charon；仓库提供的 `photon.service` 会拉起并等待 `strongswan.service`，其他启动方式需要另行启动 charon。
- `port_mode`：`fixed` 或 `range`。`range` 需要配置至少包含 4 个端口的 `port_range`；每个 generation 使用一组不重叠的 IKE/NAT-T 相邻端口，rotate 时前进 2 个端口。
- `port_rotate_interval`：range 模式下 advertised port 的轮换周期；为 0 时不主动轮换。
- `port_previous_grace`：旧 advertised port 保留窗口，必须覆盖 overlay rotate retention。
- `announce_addrs` / `announce_dns`：IPsec 专用地址或 DNS 发布来源，独立于 `gossip.advertise_addrs`。`announce_addrs` 只接受不带端口的 IPv4/IPv6 地址；IKE/NAT-T 端口由 `port_mode` / `port_range` 单独发布。
- `announce_dns_reconnect_after`：默认 `5m`。主动拨号端发现当前 SA 的本地地址已不在自身 `announce_dns` 解析结果中，并且超过该时间未收到入站包时，重建连接；设为 `0` 禁用。DNS 解析失败或 NAT 导致地址作用域不可比较时不会重建。
- `announce_gossip_endpoints`：是否把 gossip endpoint discovery 的地址也作为 IPsec 地址候选来源，默认 true。

## Overlay Link Policy

`overlays[]` 是本机 mesh policy。它决定本节点想和哪些 peer 建链、用哪个 provider、放入哪个 netns。它不直接进入 gossip。

```yaml
overlays:
  - id: ipsec-main
    provider: strongswan
    netns: default
    default_path_mode: family-redundant
    # max_peers: 256
    # max_links_per_peer: 2

    tunnel_address:
      mode: derived-pool
      family: ipv6
      pool: fd00:4242::/64

    # reconcile:
    #   interval: 1m
    #   rotate_retention: 1h
    #   backoff:
    #     initial: 1s
    #     max: 1m

    connect:
      - "strongswan://*.catofes.?role=both&family=dual&source=manual-dns,discovery&mode=family-redundant"
    deny:
      - "strongswan://*.lab.catofes."
```

字段说明：

- `id` / `name`：overlay link group 标识。`id` 是推荐字段，并会用于发布 `ipsec/overlays/<id>` intent；`name` 作为兼容别名。两端要进入同一个 overlay，必须配置相同的 `id`，否则 planner 会认为缺少对应 overlay intent。
- `provider`：数据面 provider，当前主线是 `strongswan`。只有配置了使用 `strongswan` 的 overlay 后，daemon 才会发布本节点 signed `ipsec/*` records。
- `netns`：引用顶层 `netns` 中声明的名字；省略时使用 `netns.default`。
- `default_path_mode`：远端候选地址的建链模式，常用 `family-redundant`，按 IPv4/IPv6 family 选 contact point；`exhaustive` 会保留更多候选。
- `address_source_order`：本 group 选择对端地址时的来源优先级，例如 `manual-address`、`manual-dns`、`discovery`、`reflector`。
- `max_peers` / `max_links_per_peer`：限制本 group 参与的 peer 数量和每个 peer 的 link 数量。
- `tunnel_address`：隧道接口地址分配方式。IPv6 默认 `derived-link-local`；显式地址池优先用 `derived-pool`。`sequential-pool` 只适合旧配置迁移或测试。
- `reconcile.interval`：周期安全扫频，用于 SA 观察和恢复；它不是每次变更的唯一触发，daemon 也会按 state/config/VICI 事件触发 reconcile。
- `reconcile.rotate_retention`：staged rotate 成功后，本地继续保留旧 generation 的窗口。
- `reconcile.backoff`：provider apply 失败后的重试退避，不是正常 reconcile 频率。
- `connect` / `deny`：本机 mesh policy 规则，只影响本节点想和哪些 peer 建链，不公开给远端。

### MeshPolicy URI 规则

`connect` / `deny` 使用 URI 风格的规则，保持配置简单且容易审计：

```yaml
overlays:
  - id: ipsec-main
    provider: strongswan
    connect:
      - "strongswan://*.catofes.?role=both&family=dual&source=manual-dns,discovery&mode=family-redundant"
      - "strongswan://edge.catofes.?role=both&family=dual"
    deny:
      - "strongswan://*.lab.catofes."
```

第一版支持的 predicate：

- **zone glob / exact**：例如 `*.catofes.` 或 `edge.catofes.`。
- **`role`**：远端 `ipsec/profile` 中声明的角色，取值为 `out`、`in`、`both`。
- **`family`**：`ipv4`、`ipv6`、`dual`，用于过滤地址族。
- **`source`**：地址来源，例如 `manual-address`、`manual-dns`、`discovery`、`reflector`、`local`。
- **`mode`**：path mode，例如 `family-redundant`、`exhaustive`。
- **`max_peers`**：正整数，限制本 group 匹配的 peer 数量。
- **`tag` / `role` 作为 label selector**：预留，待本地 peer label/tag 来源接入后启用；当前默认示例使用 zone glob / exact。

规则评估顺序：

1. 先处理 `deny`；命中 deny 的 peer 直接排除。
2. 再按 `connect` 规则顺序匹配；第一个命中的规则决定该 peer 是否被选中。
3. 正则表达式不是第一版默认能力；glob/suffix/label 更容易审计。

## Routing 与 IPAM

Routing 采用 per-netns BIRD/Babel 模型。一个 netns 对应一个 BIRD 实例，同一 netns 内的 overlay 共享 Babel 邻居和路由表。

```yaml
ipam:
  announce:
    - non-shared
    # - tag:edge.c

routing:
  instances:
    - id: main
      # netns: default
      provider: bird
      mode: managed
      shutdown_policy: persist
      table: main
      metric_base: 100
      metric_staged: 1200
      metric_draining: 2400
      rtt_cost: 1024
      rtt_min: 10ms
      rtt_max: 500ms
      rtt_decay: 12
      hello_interval: 4s
      update_interval: 16s
      interface_pattern: phx*
```

字段说明：

- `routing.instances[].netns` 引用顶层 `netns`；省略时使用 `netns.default`。
- `provider` 当前只支持 `bird`。
- `mode` 可为 `managed`、`external`、`disabled`。
- `disabled`：设为 `true` 时保留配置块但停止 reconcile。
- `shutdown_policy` 可为 `persist` 或 `stop`，默认 `persist`。`managed` BIRD 由 Photon 启动和配置，但默认不会随 Photon daemon 退出而停止；daemon 重启后通过 pid/control socket adopt 现有 BIRD，减少 Babel 邻居和路由静默期。只有显式设置 `stop` 时，daemon 优雅退出才会停止该 BIRD 实例。
- `table`：BIRD 主路由表名。
- `metric_base` / `metric_staged` / `metric_draining`：Babel 路由 metric 基值，默认 `100` / `1200` / `2400`，分别用于正常、staged rotate、draining 状态。默认间距大于最大 RTT penalty，避免低延迟的旧 tunnel 反转轮换优先级。
- `rtt_cost`：mesh 接口的最大 RTT 附加 cost，默认 `1024`。配合默认 `rtt_min=10ms`、`rtt_max=500ms` 和 `rxcost=100`，relay 的总 RTT 每降低约 `48ms` 即可抵消多一跳的基础 cost；必须小于 `65535`。
- `rtt_min` / `rtt_max`：RTT 附加 cost 的线性区间，默认 `10ms` / `500ms`。低于 min 不加 cost，高于 max 使用完整 `rtt_cost`。
- `rtt_decay`：BIRD RTT 指数移动平均的衰减因子，范围 `1..256`，默认 `12`；数值越小，保留历史越久、对短时抖动越不敏感。
- `hello_interval`：Babel Hello 周期，默认 `4s`，同时影响邻居故障检测速度。
- `update_interval`：周期性全量路由更新间隔，默认 `16s`，即默认 Hello 周期的 4 倍；路由变化仍通过 triggered update 传播，不会等待下一次周期更新。
- Photon 始终为 Babel protocol 生成 `randomize router id`。全局 32-bit BIRD router ID 仍保持稳定；Babel 每次协议实例启动时只随机化其 64-bit origin ID 的高 32 位，避免 sequence number 重置后的 announce 被邻居当作旧更新。
- 上述时长字段接受 Go duration 格式，精度至少为 `1ms` 且必须为整毫秒；ETX/RTT 参数只用于 mesh 接口，upstream veth 仅使用 Hello/Update 间隔。
- `interface_pattern`：匹配本 instance 内 XFRM tunnel interface 的模式，默认 `phx*`。
- 未指定 `control_socket`、`pid_file`、`config_file` 时，默认写到 `<data_dir>/bird/`。
- `upstream` 可让 Photon 创建 veth，把 routing instance 的 mesh netns 接到主网络或另一个 namespace。启用 `upstream` 后 `create_veth` 默认 true；`mesh.*` 描述 routing instance netns 端，`external.*` 描述 host/upstream 网络端，`external.netns` 省略或为空表示 init/main host netns。
- `upstream.mode: static` 是默认模式；Photon 会在 mesh 侧把本节点 assigned prefix 指向 `mesh.interface`，并在 external/host 侧把远端授权 mesh 前缀指向 `external.interface`，使用本节点非 shared assigned prefix 的首个可用地址作为 route source；shared/Anycast prefix 不配置到 veth。
- 默认接口名前缀按角色分离：StrongSwan/XFRM 使用 `phx*`，WireGuard device 使用 `phw*`，WG 路径 GRE 使用 `phg*`，veth 使用 `phv*`；默认 upstream 两端为 `phv2host` / `phv2mesh`。
- `ipam.announce` 选择由 daemon 持续发布的本节点 assignment。支持 `all`、`non-shared`、`shared`、`tag:<tag>` 和 `assignment:<CIDR>`。
- 未匹配的 assignment 不由配置管理，可由 `photon route announce/withdraw` 或服务控制；配置 reconcile 只撤销自己以 `controller:auto` 创建的记录。
- 旧字段 `ipam.auto_announce_assigned_ips: true` 仍兼容，含义是自动管理全部本地 assignment；不能与 `ipam.announce` 同时使用。

## Firewall

Firewall 配置按 instance 声明。instance 可以绑定某个 netns，也可以绑定 host。

```yaml
firewall:
  instances:
    - id: photon
      # netns: default
      mode: managed
      backend: auto
      default_policy: drop
      xfrm_tunnel_pattern: phx*

    - id: host-ipsec
      host: true
      mode: managed
      backend: auto
```

字段说明：

- `backend` 可为 `auto`、`nft`、`iptables`、`none`。
- `mode` 可为 `managed`、`external`、`disabled`。
- `disabled`：设为 `true` 时保留配置块但停止 reconcile。
- 非 host instance 的 `netns` 引用顶层 `netns`；省略时使用 `netns.default`。
- netns instance 默认匹配 `phx*` XFRM tunnel interface。
- upstream 接口名只配置在 `routing.instances[].upstream.mesh.interface`；firewall 按同一 netns 消费该精确名字，不提供独立的 upstream pattern。
- host instance 用于 ingress、IKE/NAT-T 端口和 range 模式 redirect grace。
- host instance 的 `listen_addrs`：用于 host ingress 和 DNAT/redirect 规则的监听地址，默认使用 `gossip.advertise_addrs`。
- `host_ports`：控制是否管理 host IKE/NAT-T 端口规则（`ike`、`natt`）。
- `redirect_grace`：range 模式下是否管理 advertised port 到 charon 的 DNAT/redirect 规则。

Firewall 规则是本机 runtime 状态，不进入 gossip。

## Health

`health:` 块存在时默认启用，除非写 `disabled: true`。

```yaml
health:
  interval: 5s
  timeout: 1s
  burst: 3
  loss_window: 20
  jitter: 500ms
  max_concurrent_probes: 8
  fail_threshold_consecutive: 3
  loss_threshold: "0.2"
  down_loss_threshold: "0.6"
  recover_consecutive: 5
  metrics:
    # Metrics persistence is disabled unless explicitly enabled.
    enabled: false
    local_spool_path: /var/lib/photon/health-spool
    local_spool_max_age: 6h
    remote_write_url: http://victoriametrics:8428/api/v1/write
    remote_write_queue_capacity: 1024
```

字段说明：

- `interval` / `timeout` / `burst`：探测间隔、单次超时和连续探测次数。
- `loss_window`：滑动窗口保留的 burst 数；窗口内 sent/received/lost 和 loss ratio 按真实 ICMP 包数累计。
- `jitter`：RTT 抖动阈值，用于判断链路质量。
- `max_concurrent_probes`：同时进行的探测数量上限。
- `fail_threshold_consecutive` / `recover_consecutive`：连续失败/恢复多少次后切换状态。
- `loss_threshold` / `down_loss_threshold`：判定 degraded / down 的丢包率阈值。
- `metrics.enabled`：显式设为 `true` 才启用本地 health metrics spool 和 remote write；默认关闭。`metrics.disabled: true` 也可显式关闭。
- `metrics.local_spool_path`：本地历史样本路径，Observer 的 health series API 从这里读取。
- `metrics.local_spool_max_age`：本地样本保留时长。
- `metrics.remote_write_url` / `remote_write_queue_capacity`：可选的远程 metrics 推送 endpoint 和队列容量。

Health 结果用于本机 debug、observer、metrics 和 rotate/cutover gate。当前第一版不会把 health 直接写入 gossip active state。

## Observer

`observer:` 块存在时默认启用，除非写 `disabled: true`。默认监听 `127.0.0.1:8080`。

```yaml
observer:
  listen: 127.0.0.1:8080
  ui_path: ""
  event_buffer_seconds: 0
```

字段说明：

- `listen`：HTTP 监听地址，默认 `127.0.0.1:8080`。
- `ui_path`：自定义 UI 静态文件路径；为空时使用内置 UI。
- `event_buffer_seconds`：SSE 事件回放缓冲的保留时长（秒），供 `GET /api/v1/events/recent` 与 UI Events 页使用；`0` 表示关闭缓冲（不保留历史事件）。
- `disabled`：设为 `true` 时关闭 observer。

Observer 是只读 HTTP/API 控制台，建议默认绑定 loopback，再由 SSH tunnel、反向代理或内网 ACL 暴露。

## Peer Lifecycle

`peer_lifecycle` 控制本机如何看待长期未同步、未观测到的 peer，以及何时清理 Photon-owned runtime 资源。它不删除 gossip 数据库里的 Zone records，也不会向全网同步“删除 peer”的状态。

```yaml
peer_lifecycle:
  stale_after: 15m
  offline_after: 12h
  cleanup_after: 48h
  keep_sa_while_stale: true
```

字段说明：

- `stale_after`：超过这个时间未同步/未观测到 peer 后，本机把它标记为 `stale`，用于 status/debug 投影；在到达 `cleanup_after` 前仍保留已有 SA。
- `offline_after`：超过这个时间后，本机把 peer 标记为 `offline`，用于 status/debug 投影；实际资源清理由 `cleanup_after` 触发。
- `cleanup_after`：peer 从最后一次成功同步/观测起超过该时间后，本机拆除 Photon-owned IPsec SA/XFRM interface，并让 routing/firewall 随本地链路状态收敛。用于判断的 Gossip checkpoint 会保留，daemon 直接以其最后活动时间抑制旧 Zone records 重建链路；之后一次成功 gossip sync 刷新该时间后自然恢复，不另存 cleanup marker。
- `keep_sa_while_stale`：兼容现有配置的策略字段；当前执行面在 `cleanup_after` 前始终保留已有 SA，默认值为 `true`。

约束是 `stale_after < offline_after < cleanup_after`。检查在 daemon 启动、状态更新以及周期 sync timer 上执行。被撤销的 peer 会立即走 deny-first 数据面清理；其 checkpoint 中的运行提示会被清空并标记 revoked，直到显式 purge 删除。revocation tombstone 本身是 signed state，会继续通过 gossip 同步和保留用于验证/审计。

## 常见配置边界

- `gossip.advertise_addrs` 是带端口的 gossip endpoint；`ipsec.announce_addrs` / `ipsec.announce_dns` 只发布 IPsec 地址或 DNS 名，IPsec 端口单独配置。
- `ipsec:` 只配置 provider；`overlays[]` 才是是否参与 mesh 建链的开关。
- `netns` 是本机 runtime 归属，不进入 gossip。
- `overlays[].connect/deny` 是本机策略，不进入 gossip。
- `routing`、`firewall`、`health`、`observer` 都是本机 runtime/观测模块；它们消费 verified state，但不改变 trust chain。
