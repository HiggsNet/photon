# Transport-IPsec：StrongSwan / IKEv2 链路控制面

## 这个模块解决什么问题

Transport 模块负责把"哪些节点应该互联"变成真实的数据面链路——也就是把控制面的状态翻译成真正的加密隧道。

当前唯一的 transport 实现是 **StrongSwan/IKEv2 + XFRM interface**。它做这些事情：

- 根据已验证的 peer 能力记录和本地策略，规划出需要建立的 IPsec 链路（LinkPlanner）。
- 通过 VICI 协议控制 StrongSwan/charon，加载私钥和 IKE connection，发起或接受 CHILD_SA。
- 管理 XFRM interface 的完整生命周期：在 charon 所在的 netns 创建 → move 到 overlay netns → 分配 tunnel address → 启用。
- 持续观测 SA 状态，把链路推进到 `up`，或在失败时 repair/backoff。
- 当 peer 被撤销、transport key 变更或配置删除时，按可审计顺序清理 connection、SA 和 XFRM interface。
- 支持端口/地址切换时新旧链路并行（staged rotate），以及 `role=both` 场景下 primary 不可达时的 secondary 接管（bidirectional takeover）。

WireGuard 是后续可选的轻量 transport，应复用同一套高层 mesh policy 和 signed record 思路，但底层 driver、key 管理和端口 rotate 能力会独立说明。本文只覆盖 StrongSwan/IPsec 路线。

## 整体分层

Transport 处于"全网事实层"和"本机执行层"之间。核心工作由 **IPsec reconcile 循环** 驱动，而不是由 driver 直接产出 LinkInstance：

```text
输入侧
──────
Gossip verified active state           ← peer 的 ipsec/* records
       +
Local config (overlays, netns, ...)    ← 本机策略
       │
       ▼
LinkPlanner                            ← 纯函数：输出 Desired []TransportLinkSpec + Roles
       │
       ▼
ReconcileLinkInstances                 ← 状态机核心
      ├─ 读：持久化的 LinkInstance（stateFile.LinkInstances）
      ├─ 读：实际 SA / XFRM interface 状态（来自 driver.ListSAs / InspectLink）
      └─ 输出：ReconcileAction[] + 更新后的 LinkInstance
       │
       ▼
ApplyReconcileAction                   ← 按 action + spec 调用 driver
       │
       ▼
StrongSwanDriver + SystemXFRMDriver    ← VICI + iproute2 实际建/拆/修链路
       │
       ▼
LinkInstance（写回持久化）              ← 本机 runtime 状态锚点
       │
       ▼
Routing / Firewall / Health 消费       ← phx* interface + tunnel address
```

关键点：

- **LinkPlanner 是纯函数**，输入是 gossip state、本地策略和当前时间，输出是 `TransportLinkSpec` 列表以及每个 link 的 `InitiatorRole`，不碰系统网络。
- **ReconcileLinkInstances 是模块管理核心**：它对比 desired spec、持久化的 `LinkInstance` 和实际 driver 状态，决定 create / update / repair / teardown / rotate / adopt / noop。对应实现见 `pkg/transport/ipsec/instance.go`。
- **Driver 层只执行动作**：`ApplyReconcileAction` 按 `ReconcileAction` 和 `TransportLinkSpec` 调用 VICI / iproute2，不做策略判断。
- **LinkInstance 是 reconcile 的持久化状态锚点**：它既是 reconcile 的输入（上次状态），也是输出（本次结果）。 daemon 重启后靠它恢复链路状态、继续 rotate 阶段、遵守 backoff，并借助 `ResourceOwner` 做所有权审计， teardown 时避免误删非本管理器资源。

## 输入来自哪里

### Gossip 中的 signed records（远端节点发布，通过 Zone trust chain 验证后才可用）

| Record | 作用 |
|--------|------|
| `ipsec/profile` | 节点能力声明：provider、IKE identity、role（out/in/both）、地址族、path mode、NAT hint |
| `ipsec/addresses` | 候选地址列表，每个来源（manual-address/manual-dns/discovery/reflector/local）、优先级、TTL |
| `ipsec/ports` | 当前端口 generation、IKE/NAT-T 端口（local=本地绑定, advertised=对外公告, observed=外部观测选填）、previous grace 窗口 |
| `ipsec/transport-key` | 独立于 Zone signing key 的 IPsec 传输密钥；持久化到本地 state meta，防止 daemon 重启后 fingerprint 抖动 |
| `ipsec/overlays/<overlay_id>` | 节点级 IPsec 能力用于某个 overlay/path 的意图声明；planner 必须同时满足三层条件：远端 profile 完整可信 + 本地 connect 选中 + 远端发布了兼容同一 overlay_id/path_key 和 tunnel address 策略的 intent |

### Record 示例

以下示例使用当前字段名（注意 `ipsec/profile` 用 `role`，旧文档中的 `accept` 已废弃）：

#### `ipsec/profile`

```json
{
  "version": 1,
  "enabled": true,
  "provider": "strongswan",
  "ike_identity": "node-a.catofes.",
  "transport_key_fingerprint": "b2:...",
  "role": "both",
  "address_families": ["ipv6", "ipv4"],
  "path_modes": ["family-redundant"],
  "nat": {
    "hint": "unknown",
    "inbound_reachable": "unknown"
  },
  "updated_at": 1717171717
}
```

#### `ipsec/addresses`

```json
{
  "version": 1,
  "addresses": [
    {
      "id": "manual-v6",
      "source": "manual-address",
      "address": "2001:db8::10",
      "family": "ipv6",
      "priority": 100,
      "reachability": "public",
      "ttl_seconds": 3600
    },
    {
      "id": "reflector-v4",
      "source": "reflector",
      "address": "203.0.113.10",
      "family": "ipv4",
      "priority": 60,
      "reachability": "nat-observed",
      "ttl_seconds": 600
    }
  ],
  "updated_at": 1717171717
}
```

#### `ipsec/ports`

```json
{
  "version": 1,
  "mode": "range",
  "range": {"from": 30000, "to": 30999},
  "current": {
    "generation": 42,
    "ike": {"local": 30412, "advertised": 30412, "observed": 30412},
    "natt": {"local": 30413, "advertised": 30413, "observed": 30413},
    "valid_until": 1717175317
  },
  "previous": [
    {
      "generation": 41,
      "ike": {"advertised": 30100},
      "natt": {"advertised": 30101},
      "valid_until": 1717172017
    }
  ],
  "updated_at": 1717171717
}
```

#### `ipsec/transport-key`

```json
{
  "version": 1,
  "kind": "raw-public-key",
  "algorithm": "ed25519",
  "public_key": "base64...",
  "fingerprint": "b2:...",
  "not_before": 1717170000,
  "not_after": 1722440400,
  "updated_at": 1717171717
}
```

#### `ipsec/overlays/<overlay_id>`

```json
{
  "version": 1,
  "overlay_id": "ipsec-main",
  "provider": "strongswan",
  "path_keys": ["default"],
  "tunnel_address": {
    "mode": "derived-link-local",
    "family": "ipv6"
  },
  "updated_at": 1717171717
}
```

### 本机配置（config.yaml，不进入 gossip）

```yaml
ipsec:
  role: both                        # 本机角色：out / in / both
  driver: strongswan                # 或 dry-run（非 root 开发/CI）
  vici_socket: /run/charon.vici

netns:
  default:
    name: photon

overlays:
  - id: ipsec-main
    name: ipsec-main
    provider: strongswan
    netns: default
    connect:
      - "strongswan://*.catofes.?role=both&family=dual&source=manual-dns,discovery&mode=family-redundant"
    deny:
      - "strongswan://*.lab.catofes."
```

`role` 决定本节点在 mesh 中的角色：

| 本机 \ 远端 | `out` | `in` | `both` |
|-------------|-------|------|--------|
| `out` | 不建链 | 主动拨远端 | 主动拨远端 |
| `in` | 不建链 | 只响应（无法建链） | 只响应（等待对方建链） |
| `both` | 只响应（等待对方建链） | 主动拨远端 | 字典序小的一方主动拨，另一方响应 |

这里有三层容易混淆：

- `ipsec.role` 是本机发布到 `ipsec/profile` 的能力声明，也决定本机 planner 的本机角色。
- 远端 `ipsec/profile.role` 是远端发布的能力声明，planner 用“本机 role + 远端 role”推导本机 `InitiatorRole`。
- `overlays[].connect` URI 里的 `role=...` 是本机策略过滤条件，只匹配远端 profile 的 `role`；它不改写本机 `ipsec.role`，也不改写远端 record。

因此示例中的 `role=both` 表示“这个 overlay 只选择远端声明为 `both` 的 peer”。如果希望本机也连接 `role=in` 的远端，需要增加一条 connect rule，或去掉该过滤条件。

### 系统运行时

- charon VICI socket：`list-sas` 返回当前 SA 列表，供 reconcile 判断是否需要 create/adopt/repair/teardown。
- VICI event（`child-updown` / `ike-updown`）：SA 变化的低延迟通知，只标记 IPsec dirty 进入 reconcile，不直接创建或删除资源。
- 系统 netns 和 link 状态：XFRM interface 是否存在、在哪个 netns、是否有地址。

## 输出影响什么

| 影响面 | 具体内容 |
|--------|----------|
| **StrongSwan charon** | `load-key` 加载 transport private key → `load-conn` 加载 IKE connection → `initiate` 发起 CHILD_SA → `terminate` / `unload-conn` 做撤销清理 |
| **XFRM interface** | 在 charon netns（通常是 host）创建 → move 到 overlay netns → set addrgenmode none → up → 分配 tunnel address（derived-link-local + derived-pool IPv4/ IPv6） |
| **LinkInstance（持久化）** | 每条逻辑链路一个，记录 desired spec hash、实际状态、XFRM if_id、IKE/CHILD_SA 名称、endpoint、owner、failure count、backoff、rotate phase 和最近错误 |
| **Routing 模块** | 暴露 `phx*` XFRM interface 给 BIRD/Babel 发现邻居；IPv4 tunnel address 作为 Babel interface address |
| **Firewall 模块** | XFRM interface 和 tunnel address 进入对应 netns 后，firewall 按 interface pattern 生成 forward/input 规则 |
| **Health 模块** | `LinkInstance.ActualState` 决定链路是否可用，影响健康探测；后续可作为 cutover gate 的输入 |

## 核心架构

### LinkPlanner — 链路规划

输入：verified active state（peer 的 ipsec records）+ 本地 `LinkGroupSpec`（connect/deny rules）。

输出：`[]TransportLinkSpec` + `[]SkipReason`。每一条 spec 描述"应该和谁在哪个 overlay 用哪个 provider 建立一条怎样的链路"。

Planner 会逐项检查：
- 远端所有节点级 IPsec record 是否完整（profile + addresses + ports + transport-key + overlay intent）
- profile 中的 `role` 与本机是否兼容
- overlay intent 中的 provider/path_key/tunnel_address 策略是否匹配
- 地址族、path mode、地址来源是否支持
- 是否有可用的 ContactPoint（AddressCandidate + PortAdvertisement 组合）
- NAT 后是否缺少可验证公网证据
- connect/deny rule 是否匹配
- 是否处于 revocation/tombstone 状态

缺少任何一项都会输出结构化 skip reason（如 `missing_overlay_intent`、`overlay_intent_mismatch`、`no_contact_point`），而不是静默跳过。

### TransportLinkSpec — 链路的"desired state"

```go
type TransportLinkSpec struct {
    LocalZone       ZonePath
    PeerZone        ZonePath
    OverlayID       string
    Provider        string          // strongswan
    LinkID          string
    PathKey         string
    TransportID     string          // StrongSwan connection name
    PathMode        string
    IKEIdentity     string
    AuthRef         string
    ContactPoints   []ContactPoint
    XFRMIfID        uint32
    InterfaceName   string          // phx<8hex>
    LocalTunnelAddr netip.Addr
    PeerTunnelAddr  netip.Addr
    LocalAddress    string
    LocalIKEPort    uint16
    Generation      uint64
    AddressEpoch    uint64
    NetNS           string
    InitiatorRole   string          // primary / secondary-standby / secondary-takeover / ""
}
```

身份派生规则（两端一致，不随 rotate generation 改变）：

| ID | 派生方式 | 用途 |
|----|---------|------|
| `LinkID` | `hash(sorted(local_zone, peer_zone), overlay_id, path_key)` | 逻辑链路稳定主键 |
| `RuntimeConnectionID` | `short(hash(LinkID, generation, provider, "runtime"))` | StrongSwan connection 名 |
| `ChildSAName` | `RuntimeConnectionID + "-child"` | CHILD_SA 名 |
| `XFRMIfID` | `uint32(hash(LinkID, generation, provider, "xfrm-if-id"))` | XFRM if_id |
| `InterfaceName` | `phx<8hex>` 从 `XFRMIfID` 派生 | Linux interface 名 |
| `OwnerToken` | `hash("photon.ipsec.owner.v2", LinkID, RuntimeConnectionID, "owner-token")` | 清理时的归属校验 |

Tunnel address 也从 `LinkID` 派生：`derive(LinkID, address_epoch, mode, pool, role)`。`role` 为 sorted peer pair 中的 `lower`/`higher`；`address_epoch=0` 为普通稳定地址，staged generation 使用 `address_epoch=<generation>` 避免新旧 interface 地址冲突。

### LinkInstance — 链路的"actual state"

每条链路对应一个持久化的 `LinkInstance`，连接 desired 和 actual：

```go
type LinkInstance struct {
    ID              string
    GroupID         string
    PeerZone        ZonePath
    TransportKind   string
    LinkID          string
    PathKey         string
    TransportID     string
    DesiredSpecHash string
    ActualState     string       // up / connecting / degraded / error / removing
    InterfaceName   string
    XFRMIfID        uint32
    LocalTunnelAddr netip.Addr
    PeerTunnelAddr  netip.Addr
    IKEName         string
    ChildSAName     string
    Endpoint        string
    SelectedContact ContactPoint
    RemoteGeneration uint64
    FailureCount    int
    BackoffUntil    int64
    LastTransition  int64
    LastFailure     error
    Owner           ResourceOwner
    // rotate 相关
    RotatePhase           string   // idle / preparing / testing_new / dual_running / cutover / rollback / cleanup
    StagedGeneration      uint64
    StagedIKEName         string
    StagedChildSAName     string
    StagedInterfaceName   string
    StagedXFRMIfID        uint32
    StagedLocalTunnelAddr netip.Addr
    StagedPeerTunnelAddr  netip.Addr
    RotateDeadline        int64
    // takeover 相关
    InitiatorRole      string
    TakeoverPhase      string
    TakeoverStartedAt  int64
    TakeoverUntil      int64
    LastTakeoverError  string
    ObservedInitiator  string
}
```

### Reconcile 主循环

一次完整的 IPsec reconcile 由 `reconcileIPsecLinks`（`app/photon/ipsec_reconcile.go`）驱动。
`TransportLinkSpec` 不是直接“变成 interface”：它先是 desired state，再与持久化 state 和
真实 SA/XFRM observation 比较，产出 `ReconcileAction` 操作图，最后才由 driver 落成系统资源。

```text
已验证的 active NetworkState                 本机 config + LinkGroup + 本机 transport key
（peer ipsec/profile/addresses/ports/key/intent）       （connect/deny、netns、backoff、rotate policy）
                 \                                           /
                  +---- ipsec.PlanTransportLinks ------------+
                                |
                                |  desired LinkPlan
                                |  - []TransportLinkSpec：希望存在的 IKE/XFRM 链路
                                |  - Roles / Skipped：角色与不能建链的原因
                                v
                    injectIPsecKeyMaterial
                                |
                                |  desired spec 补齐本机私钥；planner 本身不读私钥
                                v
持久化 LinkInstances --------> ReconcileLinkInstances <-------- VICI ListSAs + XFRM InspectLink
（上轮状态、owner、backoff、          |                            （实际 IKE/CHILD SA、
 rotate/takeover）                    |                             interface/flags/address）
                                      |
                                      |  对比 desired / persisted / observed / revocation
                                      |  输出：next LinkInstances + []ReconcileAction
                                      v
                       Action graph（按 link/rotate phase 顺序执行）
                         | create/update/repair/adopt/noop
                         | teardown
                         | prepare_rotate/commit_rotate/rollback/cleanup_rotate
                         v
                    ipsec.ApplyReconcileAction
                         |
          +--------------+------------------+
          |                                 |
          v                                 v
 StrongSwanDriver                       SystemXFRMDriver
 VICI: load-key/load-conn/             host: ip link add type xfrm if_id
 initiate/terminate/unload-conn        -> move to target netns -> up
                                       -> assign derived tunnel address
          |                                 |
          +--------------+------------------+
                         v
          mark action success/failure + maintain existing XFRM interfaces
                         v
          commit LinkInstances + IPsecReconcileState + save state
                         v
          routing / firewall / health consume phx* interface and runtime state
```

对象职责：

| 对象 | 是什么 | 不做什么 |
|---|---|---|
| `TransportLinkSpec` | 某条逻辑 link 的 desired 配置：peer、endpoint、IKE identity、XFRM if_id、interface、地址、generation | 不操作系统，不代表已建立 |
| `LinkInstance` | 上轮/本轮的持久化 runtime 锚点：实际 state、SA/XFRM 名称、owner、backoff、rotate/takeover | 不自行决定策略或调用 VICI |
| `SAState` / `InspectLink` | 本轮真实观测：charon 是否有匹配 SA、XFRM interface 是否真的存在且可用 | 不修改 desired state |
| `ReconcileAction` | 三类输入比较后得到的操作节点，含 action、spec、instance 和原因 | 不做策略规划，不直接执行命令 |
| `ApplyReconcileAction` | 把 action 分派给 VICI/XFRM driver 的执行器 | 不重新决定 create/repair/rotate/teardown |

典型 `create` 操作图：

```text
desired spec
  -> EnsureNamespace(target netns)
  -> LoadPrivateKey(transport ID)                 [若本机 key 尚未加载]
  -> LoadConnection(IKE/CHILD configuration)
  -> EnsureInterface(XFRM if_id)
       host-born XFRM -> move target netns -> addrgenmode none -> link up
  -> AssignAddress(derived local tunnel address)
  -> InitiateChild                                [仅本机应主动发起时]
  -> instance=connecting
  -> 下次 ListSAs/InspectLink 观测成功后 instance=up 或 adopt
```

`teardown` 是反向且带 owner guard 的操作图：

```text
owner + Photon resource marker verified
  -> TerminateSA
  -> UnloadConnection
  -> UnloadPrivateKey（无其他引用时）
  -> Delete staged/current XFRM interface
  -> remove LinkInstance
```

#### 每轮执行的 7 个步骤

1. **规划 desired links**
   调用 `ipsec.PlanTransportLinks`，输入当前 `NetworkState`、本机 `ManagedZone` 和 `LinkGroups`，得到 `LinkPlan`。
   输出包括：
   - `Desired []TransportLinkSpec`：本轮期望建立的链路；
   - `Skipped []PlanSkip`：被跳过的 peer 及原因（用于诊断）；
   - `Roles map[string]string`：每个 instance/transport 的 initiator role，用于 `both` 角色场景下的 secondary-standby / secondary-takeover 决策。

2. **注入本机密钥材料**
   调用 `injectIPsecKeyMaterial` 把本机持久化的 `IPsecTransportKey` 填入 desired specs，这样 planner 本身不需要访问私钥。

3. **采集实际 SA 状态**
   调用 `ipsecDriver.ListSAs(ctx)` 通过 VICI 拿到当前 StrongSwan 的 IKE/CHILD_SA 列表。

4. **校验 XFRM interface 真实存在**
   调用 `filterSAsWithMissingXFRMLinks`：
   - 如果 xfrm driver 实现了 `XFRMLinkInspector`，逐个 `InspectLink` 检查 interface 是否存在且参数匹配；
   - 否则回退到 `FilterSAsWithMissingLinks`。
   这一步能发现“SA 还在但 interface 被外部清理”的异常，并把缺失的 link 标记到 instance 状态里。

5. **运行 reconcile 状态机**
   调用 `ipsec.ReconcileLinkInstances`，输入 `Desired`、`Instances`、`SAs`、`Revoked`、`Roles`、`GroupBackoff`、`GroupRotateRetention`、`RotateCutoverReady`。
   输出：
   - `Actions []ReconcileAction`：要执行的具体动作；
   - `Instances map[string]LinkInstance`：更新后的 instance 状态（尚未持久化）。

   常见的 action 类型：
   - `create` — 新的 desired link，本地无 instance；
   - `adopt` — desired 与现有 SA 匹配，直接采纳 driver 状态；
   - `update` — desired spec hash 变了，或 identity/endpoint 不匹配；
   - `repair` — link 处于 `degraded`/`error` 且 backoff 已到期；
   - `noop` — 已经 up 且 desired 没变；
   - `teardown` — 不再 desired（peer revoked、配置删除、record 过期）；
   - `prepare_rotate` / `commit_rotate` / `rollback_rotate` / `cleanup_rotate` — staged rotate 各阶段。

6. **执行 actions**
   遍历 `Actions`，对每个需要实际改系统的动作：
   - 根据 action 和对应 overlay 找到目标 netns；
   - 调用 `ipsec.ApplyReconcileAction`，由它再调用 `StrongSwanDriver` / `XFRMDriver`；
   - 如果执行失败，立即标记 instance 为失败状态、增加 backoff、把 `result.Instances` 写回内存并 `saveState()`，然后返回错误，避免同一轮继续执行后续可能依赖的动作；
   - 如果成功，标记 instance 为成功状态。

7. **持久化结果**
   把 `result.Instances` 通过 `StateStore.CommitIfRevision()` 写回 `LinkInstances`，更新 `IPsecReconcile` 摘要（desired 数量、actions、skipped、last error），并从 committed snapshot 落盘。

> **注意**：reconcile 是单线程顺序执行的。任何一步出错都会提前返回，但已经把截至目前的 instance 状态保存下来，下一轮可以基于最新的持久化状态继续推进。

#### Apply 顺序与 staged 边界

`ApplyReconcileAction` 对 create/update/repair 会按固定顺序调用 driver：

1. `EnsureNamespace(target netns)`
2. `LoadKey(transport key)`
3. `LoadConnection(IKE connection)`
4. `EnsureInterface`（host 创建 XFRM interface → move → up → `addrgenmode none`）
5. `AssignAddress(tunnel address)`
6. `InitiateChild`（对 outbound initiator）或等待对端触发

Staged connection 的 apply 有两个额外边界：复用已加载的 transport key，不重复 `load-key`；加载 staged connection 前会先 `unload-conn` 对应 base config，避免 StrongSwan 把 rotation 报文匹配到旧 connection 名下。这个 unload 只卸载配置，不等于 teardown 已建立的 base SA。

### Staged Rotate（4.4+）

当远端 `ipsec/ports.current.generation` 变化时，进入 staged rotate 状态机：

```text
Idle → Preparing（加载独立 staged connection/SA/XFRM interface）
     → TestingNew（观测 staged SA 是否 established）
         → DualRunning（新旧两条链路并行，保留窗口默认 1h）
             → Draining（staged 健康且 Babel neighbor 就绪；new 使用正常 cost，old 调高为 draining cost）
                 → Cutover（保留到期且 staged 接口已学到 Babel route 后 promote staged）
                 → DualRunning（staged 健康或邻居回退，恢复 old 优先）
             → Rollback（staged SA 在规定时限内未建立，清理 staged 保留旧链路）
```

staged generation 使用独立的 `TransportID`、XFRM `if_id` 和 interface name，dual_running/draining 期间 overlay netns 同时有两个 `phx*` interface。BIRD 为具体 runtime interface 生成优先于通配规则的精确 policy：验证阶段 old=`metric_base`、staged=`metric_staged`；迁流量阶段 old=`metric_draining`、staged=`metric_base`。

### Bidirectional Takeover（4.5）

双方 `role=both` 时，字典序小的一方 primary 主动拨号，secondary 为 standby。若 primary 持续不可达（超过失败阈值 + takeover delay），secondary 可临时接管主动拨号：

- secondary 启动时先以 `start_action=none` 加载 responder connection、私钥并创建 XFRM interface，但不调用 `initiate`
- daemon 启动后的 2min grace 内禁止 takeover；之后仍需连续至少两次、持续 2min 确认没有匹配 SA
- takeover 有 lease（默认 5min）和 cooldown（默认 2min）
- 已有匹配 SA 时优先 adopt，不再纠结谁先拨
- revocation、profile/transport-key mismatch 禁止 takeover（信任失败不是连通性失败）
- 同 runtime 的重复 SA 全部稳定 2min 后，primary/secondary 都可按 IKE unique ID 精确 GC；primary 保留最老的 outbound SA，secondary 保留最老的 inbound SA，双方选择同一条 canonical SA

## XFRM interface 生命周期

这是排障时最容易出错的环节。

### 正确形态（当前实现）

```
host netns:                        overlay netns (photon):
  charon / VICI                       moved XFRM interface phx...
  XFRM state/policy (by StrongSwan)   tunnel address on phx...
  XFRM interface 创建位置              BIRD/Babel + overlay routes
```

**创建顺序：**
1. `EnsureNamespace` — 确保 target overlay netns 存在
2. `ip link add <iface> type xfrm if_id <id>` — 在 charon netns（host）创建
3. `ip link set <iface> netns <target>` — move 到 overlay netns
4. 在 target netns 执行 `ip link set dev <iface> addrgenmode none`
5. `ip link set dev <iface> up`
6. `ip addr replace <prefix> dev <iface>` — 分配 tunnel address

**为什么 interface 要先出生在 host：** charon 安装的 XFRM state/policy 在 host netns，XFRM interface 如果在 overlay netns 创建，流量虽然在 interface 上可见但匹配不到 state/policy，导致 TX dropped。StrongSwan 的 route-based VPN 设计也说明 XFRM interface 可以 move 到其它 netns，目标 netns 只看到 interface 看不到 SA key/state。

### 删除顺序

`TeardownTransportLink` 的可审计顺序：
1. `terminate` IKE_SA/CHILD_SA（需要时可 `flush`）
2. `unload-conn` 从 charon 卸载 connection
3. 通过 `LinkInstance.Owner` 校验后，删除 XFRM interface（先查 target netns，再查 host 残留）
4. 删除本地持久化 `LinkInstance`

## 哪些状态进入 gossip，哪些只是本机 runtime

### 进入 gossip 的 signed records（全网可见，Zone authority 签名）

- `ipsec/profile` — 节点能力声明
- `ipsec/addresses` — 候选地址/DNS
- `ipsec/ports` — 端口公告（current + previous grace）
- `ipsec/transport-key` — 独立传输密钥
- `ipsec/overlays/<overlay_id>` — overlay 参与意图

### 本机 runtime 状态（不进入 gossip）

- `LinkInstance` — 链路 reconciled 结果（desired hash、实际状态、backoff、rotate phase）
- `LinkGroupSpec` / connect-rule — connect/deny rule、netns、tunnel_address 策略
- VICI SA snapshot 和 VICI event — charon 运行态观测
- `ContactPoint` 展开结果 — DNS/discovery 解析地址
- initiator role / takeover state
- apply plan 和失败记录

## 出错时 operator 应该看什么

### 首选诊断命令

```
photon debug links
```

输出包含每条链路的：
- transport_id、peer zone
- `LinkInstance` status（up / connecting / degraded / error）
- skip reason（如果 planner 跳过了某个 peer）
- rotate phase + generation + deadline
- initiator role + takeover phase
- backoff 剩余时间、最后 error、failure 计数
- VICI SA 信息：identity、endpoint、reqid、if_id
- tunnel address（link-local 带 interface scope）

### 常见问题排查

| 现象 | 排查方向 |
|------|----------|
| planner 输出 `missing_overlay_intent` | 远端没有发布 `ipsec/overlays/<overlay_id>`，或本地的 overlay id 与远端不匹配 |
| planner 输出 `overlay_intent_mismatch` | 远端 overlay intent 中的 provider/path_key/tunnel_address 与本机不兼容 |
| `standby_responder_prepare` | secondary 正在准备 responder connection、密钥和 XFRM interface，不会主动 initiate |
| `takeover_startup_grace` | daemon 刚启动，2min 保护期内禁止 secondary takeover |
| `takeover_delay_active` | secondary 在 takeover delay 冷却期内，等待超时后再接管 |
| link 卡在 `connecting` 超过 3 分钟 | VICI socket 不可达、IKE 协商失败、NAT-T 端口不通、远端 charon 未运行 |
| link 反复在 connecting/error 间翻转 | 检查 `LinkInstance` 展示中的 last_failure 和 backoff；可能是 endpoint/ports 不可达 |
| XFRM interface 有 TX dropped | XFRM state/policy 在 host，interface 在 overlay netns——确认 host-born 路径正确 |
| revocation 后 SA 被反复拉起 | owner token 不匹配、残留 `LinkInstance` 未清理、或 teardown 没有成功删除 connection |
| `dual_running` 不进入 `draining` | staged interface 尚未通过健康探测，或尚未形成 Babel neighbor |
| `draining` 不推进 cutover | 先看 retention 窗口和 last rotate error，再确认 staged interface 有 Babel neighbor 且已从该接口学到 route；健康或 neighbor 回退会恢复为 `dual_running` |
| SA 已 established 但 `LinkInstance` 仍是 `connecting` | reconcile 未触发，或 VICI `list-sas` 没有观测到匹配的 SA（检查 child name/reqid/if_id 是否匹配） |

### 辅助观测手段

**VICI SA 状态（人工对照）：**
```sh
swanctl --list-sas
```
检查 IKE identity、CHILD_SA 的 reqid/if_id、endpoint、established 时间。

**XFRM state/policy（host netns）：**
```sh
ip xfrm state
ip xfrm policy
```
确认 charon 安装的 SA 和策略对端期望通过 XFRM interface 的流量。

**XFRM interface 位置：**
```sh
# host netns
ip link show type xfrm

# 目标 overlay netns
ip netns exec <name> ip link show type xfrm
ip netns exec <name> ip addr show dev phx*
ip netns exec <name> ip route show dev phx*
```
确认 interface 在正确的 overlay netns，有正确地址，且状态为 UP。

**daemon 日志：**
结构化 key=value 日志包含 VICI call 超时、action/skip 摘要和脱敏后的 key material。在日志中搜索 `transport`、`ipsec`、`link`、`reconcile` 等关键词。

### 重要边界

- **StrongSwan/charon 是本机 runtime driver，它的失败不改变 signed state 的真实性。** charon 崩溃、VICI socket 断开、XFRM module 缺失，不代表 peer 不可信。先确认 gossip 已验证的 peer `ipsec/*` records 是否正常，再排查 driver 层。
- **NAT hint 只是提示，不是安全事实。** 两端都在 NAT 后且无可验证公网 ContactPoint 时，链路进入 `degraded`，debug 输出明确不可达原因。
- **rotate 分两层理解：** 入口端口公告层（`ipsec/ports.current/previous`）告诉远端优先连哪个端口；XFRM 数据面预备层（staged generation）在底层并行搭建新链路。前者即使写入了 previous，也不代表本机 charon 已在监听两个端口。
- **LinkInstance 被 teardown 成功后 daemon 会删除持久化记录。** 因此后续 state change 或 restart 不会再看到 `removing` 状态，也不会重复执行清理。
