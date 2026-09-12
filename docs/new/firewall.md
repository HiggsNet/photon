# Photon Firewall 设计与实现

> **本文档状态：2026-07**
> 描述 Photon firewall 子系统的当前实现：`pkg/firewall` 的 planner 与 backend driver、`app/photon` 中的 reconcile 集成，以及 `photon debug firewall` 等诊断命令。
> 本文以当前代码为准；文中会显式标注已实现行为与原设计的差异或待完善项。原 Phase 6.3 设计文档已并入本文（差异与后续方向见第 8 节），不再单独保留。

Firewall 是 Photon overlay data-plane 的安全边界执行器。它把已通过 Zone trust chain 验证的 IPAM、route announcement、revocation state 和本地配置策略，收敛成 Linux 防火墙规则。它**不是**通用主机防火墙，不管理 SSH、Docker、Kubernetes 等发行版默认规则。

完整配置字段见 [config.md](config.md)，daemon reconcile 调度见 [daemon.md](daemon.md)，IPsec 端口与链路细节见 [transport-ipsec.md](transport-ipsec.md)。

---

## 目录

1. [范围与定位](#1-范围与定位)
2. [核心概念](#2-核心概念)
3. [配置模型](#3-配置模型)
4. [规则生成（Planner）](#4-规则生成planner)
5. [Backend 驱动](#5-backend-驱动)
6. [Reconcile 流程](#6-reconcile-流程)
7. [Debug 与诊断](#7-debug-与诊断)
8. [已知限制与实现缺口](#8-已知限制与实现缺口)

---

## 1. 范围与定位

### 1.1 职责边界

| 层面 | 做什么 | 不做什么 |
|---|---|---|
| overlay/data-plane netns | 默认 drop 未授权流量；放行 mesh 授权前缀、BIRD/Babel 控制流量、本地显式服务 | 不管理 host 全局防火墙、不处理 underlay 入口 |
| host netns | 仅管理 Photon 必须的最小入口：当前为 IKE/NAT-T allow 与端口 rotate 的 DNAT/redirect grace；WireGuard 仅有 planner 预留 | 不接管 Docker、Kubernetes、发行版默认规则 |
| reconcile 语义 | `managed` instance 的 Photon-owned 对象会在启动和状态变化时重新生成；`external` 只读 | 当前不是内容级 no-op：nft 会整表替换，iptables 会切换 generation；停止、禁用、切换为 external 或移除实例时不会自动清理旧对象（见第 8 节） |

### 1.2 命名空间边界

```text
host netns
  ├─ Photon-owned host ingress allow (当前为 IKE/NAT-T；WG 尚未接入配置)
  ├─ optional old/current port redirect grace
  └─ non-Photon firewall rules stay untouched

overlay netns (e.g. photon)
  ├─ XFRM tunnel interfaces: phx*
  ├─ BIRD/Babel instance
  ├─ optional veth upstream: phv* (default phv2host)
  └─ Photon-owned input/forward/output policy
```

Firewall 跟随 netns 隔离边界：一个 netns 对应一个 firewall instance。host 单独作为一个特殊 instance。主策略放在 overlay netns，是因为 overlay 的路由和业务前缀已经按 netns 隔离，防火墙跟随该边界最自然；host 上可能已有管理员、发行版或容器运行时管理的防火墙，因此 host 侧只保留 Photon 必须拥有的最小入口。端口 rotate / NAT-T 入口规则无法完全留在 overlay netns，只能作为 host 上明确的独立 plan 处理。

---

## 2. 核心概念

### 2.1 Owner

Photon 所有防火墙对象通过 `Owner` 标记，以便与管理员规则区分：

```go
// pkg/firewall/types.go
type Owner struct {
    Manager     string // 始终为 "photon"
    InstanceID  string // host 为 "host"，overlay 为实际 netns 名
    OwnerPrefix string // 默认 "photon"
    Generation  uint64 // desired-state generation
    Token       string // prefix + scope + id 的 sha256 前 12 位
}
```

- 命名前缀决定 table/chain/set 名称。overlay 实例默认表名为 `photon_<netns>`，如 `photon_h2`；host 实例为 `photon_host`。
- `Token` 由 `OwnerToken(spec)` 生成，用于稳定识别同一实例的历史对象。

### 2.2 Instance

一个 instance 对应一个 firewall 管理边界：

| 字段 | 含义 |
|---|---|
| `ID` | 配置里的实例标识 |
| `NetNS` | 实际 netns 名，或 `"host"` |
| `IsHost` | 是否为 host 实例；`host: true` 与 `netns` 互斥 |
| `Mode` | `managed` / `external` / `disabled` |
| `Backend` | `auto` / `nft` / `iptables` / `none` |
| `DefaultPolicy` | `drop` 或 `accept`，默认 `drop` |
| `OwnerPrefix` | 命名前缀，默认 `photon` |

Instance scope（用于 owner 和命名）以实际 netns 名为准，而不是配置里的 `id`。例如 `id: host-ipsec, host: true` 归属到 `photon_host`。

### 2.3 Mode

- `managed`：Photon 拥有并管理该 netns 的防火墙规则。
- `external`：Photon 只在 debug 中展示该 instance，不参与 reconcile、endpoint ACL enforcement 或 driver apply；不会修改现有规则。
- `disabled`：不参与后续 reconcile；如果该实例以前启用过，当前实现不会自动删除其旧规则。

### 2.4 ForwardingPolicy

Firewall 与 BIRD 共享同一份 `ForwardingPolicy`，避免“路由允许但防火墙阻断”或相反：

```go
// pkg/firewall/types.go
type ForwardingPolicy struct {
    Transit       bool
    AllowPrefixes []netip.Prefix
    DenyPrefixes  []netip.Prefix
    AllowPeers    []string // zone globs or exact，当前未实际使用
    DenyPeers     []string // 当前未实际使用
    MetricHint    uint
}
```

- `Transit=false`：overlay forward chain 显式 drop XFRM→XFRM 流量。
- `Transit=true`：按 `AllowPrefixes`/`DenyPrefixes` 过滤后的 mesh 前缀允许 XFRM→XFRM transit。

> **注意**：当前代码只使用 `AllowPrefixes`/`DenyPrefixes`，`AllowPeers`/`DenyPeers` 字段存在但**未实际参与过滤**。

### 2.5 接口角色

Planner 按接口角色分别处理流量：

- `xfrm_tunnel`：mesh peer 之间的数据面接口；nft 优先使用本 netns 当前 ready 的精确接口名集合，没有 runtime 输出时才回退到 `xfrm_tunnel_pattern`（默认 `phx*`）。iptables 为避免接口对笛卡尔积，直接按该 pattern 匹配 XFRM 接口。
- `upstream_veth`：overlay netns 与 host/主网络之间的出入口。接口名只来自同 netns 的 `routing.instances[].upstream.mesh.interface`，默认 `phv2host`；firewall 不维护第二份 upstream 名字。
- `loopback`：本机服务。
- underlay 接口不在 overlay netns 内处理；host 入口见第 4.4 节。

跨 upstream veth 的流量必须有显式规则（见第 4.3 节 forward chain）：默认不把 mesh 学到的路由直接暴露给主网络。

---

## 3. 配置模型

### 3.1 最小配置示例

```yaml
netns:
  default:
    kind: name
    name: photon

firewall:
  instances:
    - id: photon
      netns: default
      default_policy: drop

    - id: host-ipsec
      host: true
      host_ports:
        ike: true
        natt: true
      redirect_grace:
        enabled: true
```

### 3.2 字段说明

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `id` | string | 必填 | 实例标识 |
| `netns` | string | `"default"` | 引用的 `netns` 段名字；非 host 实例必填 |
| `host` | bool | false | 是否为 host 实例；与 `netns` 互斥 |
| `enabled` / `disabled` | bool | true | 是否启用该 instance |
| `mode` | string | `managed` | `managed` / `external` / `disabled` |
| `backend` | string | `auto` | `auto` / `nft` / `iptables` / `none` |
| `default_policy` | string | `drop` | `drop` / `accept` |
| `priority.filter` | string | `filter` | nft input/forward/output base-chain priority |
| `priority.prerouting` | string | `dstnat` | nft NAT prerouting base-chain priority |
| `priority.postrouting` | string | `srcnat` | nft NAT postrouting base-chain priority |
| `owner_prefix` | string | `photon` | 命名前缀 |
| `xfrm_tunnel_pattern` | string | `phx*` | nft 尚无 live interface 时的回退模式；iptables 始终用它避免接口组合展开 |
| `local_services` | list | `[]` | overlay 内显式开放的服务 |
| `host_ports.ike` | bool | 见下文 | host UDP 500 入口 |
| `host_ports.natt` | bool | 见下文 | host UDP 4500 入口 |
| `host_ports.wg` | bool | 未接入 | planner/type 中有预留，但当前 YAML schema 不接受该字段 |
| `redirect_grace.enabled` | bool | 见下文 | 端口 rotate 期间的 DNAT/redirect grace |
| `listen_addrs` | string list | `[]` | host 规则绑定的本地目的地址 |
| `nft_hooks.<point>` | string list | `[]` | 编入 managed nft table 的原生 rule body |
| `iptables_hooks.ipv4.<point>` | string list | `[]` | 编入 `iptables` managed generation 的原生参数表达式 |
| `iptables_hooks.ipv6.<point>` | string list | `[]` | 编入 `ip6tables` managed generation 的原生参数表达式 |

### 3.3 nft base-chain priority

`priority` 只影响 nft backend；iptables 的 built-in chain 没有等价的 base-chain priority。三个字段都必须使用其固定的 nft 基准名，并可附加带空格的整数偏移：

```yaml
priority:
  filter: "filter - 1"
  prerouting: "dstnat - 1"
  postrouting: "srcnat + 1"
```

省略时分别默认为 `filter`、`dstnat`、`srcnat`。`prerouting` 不能写成 `raw - 1`，`postrouting` 不能写成 `dstnat`：前者必须保持 DNAT/REDIRECT 阶段，后者必须保持 SNAT/MASQUERADE 阶段。配置解析只接受固定基准加偏移，拒绝任意 nft 表达式。

### 3.4 host 实例默认值

当 `ipsec.port_mode=range` 时，host 实例会自动启用 `host_ports.ike` 和 `host_ports.natt`，并启用 `redirect_grace`，以便端口范围模式正常工作。这些默认值可被显式配置覆盖。

```go
// app/photon/firewall_config.go:189-214
rangeMode := isHost && ipsecCfg.PortMode == ipsec.PortModeRange
if rangeMode {
    hostPorts.IKE = true
    hostPorts.NATT = true
}
// ... 可被 yi.HostPorts.* 覆盖

if rangeMode {
    redirectGrace.Enabled = true
}
// ... 可被 yi.RedirectGrace.* 覆盖
```

### 3.5 local_services

显式开放 overlay netns 内的服务：

```yaml
local_services:
  - proto: tcp
    port: 8080
    sources:
      - 10.42.0.0/16
```

- `sources` 为空时，允许来源为所有 mesh 授权前缀。
- 只支持 `tcp` 或 `udp`。

### 3.6 Backend-native inline hooks

`nft_hooks` 和 `iptables_hooks` 把单条 backend 原生 rule body 直接编入 Photon 管理的 table/generation。两套语法不是可移植 DSL；同一配置可同时提供两套等价规则，实际只渲染最终选中 backend 的配置。

```yaml
firewall:
  instances:
    - id: photon
      backend: auto
      nft_hooks:
        pre_input:
          - 'ip saddr 10.20.0.0/16 tcp dport 22 accept'
        post_forward:
          - 'counter log prefix "photon-forward "'
      iptables_hooks:
        ipv4:
          pre_input:
            - '-s 10.20.0.0/16 -p tcp --dport 22 -j ACCEPT'
            - '-s 10.30.0.0/16 -p tcp --dport 443 -j ACCEPT'
        ipv6:
          pre_input:
            - '-s 2001:db8:20::/48 -p tcp --dport 22 -j ACCEPT'
```

- `iptables_hooks.ipv4` 只写入 `iptables`，`ipv6` 只写入 `ip6tables`；没有 `both`、默认 family 或自动复制。
- 每个 hook point 是字符串列表，可以写多条规则，严格保持 YAML 顺序。
- overlay 支持 `pre_input` / `post_input`、`pre_forward` / `post_forward`、`pre_output` / `post_output`。
- host 支持 `host_pre_input` / `host_post_input` 和 `host_pre_prerouting` / `host_post_prerouting`。
- `pre_input` 位于 invalid drop 和 loopback accept 之后；`pre_forward` 位于 scoped asymmetric-transit INVALID accept、通用 invalid drop 和 established/related accept 之后；`pre_output` 位于 Photon output 规则之前。所有 `post_*` 都位于 Photon 生成规则之后、terminal default verdict 之前。
- nft 表达式随 Photon 规则进入同一个 `nft -f` 事务，失败时旧 table 保持生效。
- iptables 表达式先写入 inactive generation；IPv4/IPv6 都准备完成后才切换内置链 jump，切换失败会尝试回滚已激活的新 jump。
- 表达式只能是当前 chain 的 rule body。配置会拒绝换行、分号、shell 元字符、nft object command，以及 iptables 的 `-A/-I/-D/-N/-X/-F/-P/-t` 等规则/chain/table 管理参数；命令始终以 argv 执行，不经过 shell。
- 原生 verdict（如 `ACCEPT`、`DROP`、`RETURN`）会影响后续 Photon 规则是否可达，管理员需自行负责业务语义。
- `backend: auto` 只有一套 inline 配置时会选择对应 backend；两套都存在时使用正常探测优先级。显式 backend 只有另一套配置时会报错，不会静默忽略。

---

## 4. 规则生成（Planner）

Planner 是纯逻辑函数，不执行 I/O，不依赖 root。

### 4.1 入口与输入

```go
// pkg/firewall/planner.go:50
func BuildDesiredState(spec FirewallInstanceSpec, input FirewallPolicyInput) (*FirewallDesiredState, error)
```

`FirewallPolicyInput` 包含：

| 字段 | 来源 | 作用 |
|---|---|---|
| `LocalAssigned` | `AuthorizedRouteSet` 中本 Zone 被分配的前缀 | overlay 本地前缀 |
| `MeshAuthorized` | `AuthorizedRouteSet.Announced` 中所有授权前缀 | 可信 mesh 前缀 |
| `AssignmentPrefixes` | IPAM assignment 白名单 | 已组装，但当前 planner 未使用 |
| `Forwarding` | 本 netns 的 forwarding policy | transit 决策 |
| `Revoked` | revocation state | deny-first：从 allow set 中剔除 |
| `LiveInterfaces` | 当前活跃 XFRM 接口 | 按 firewall instance 的 netns 过滤、去重；nft 精确生成接口集合，iptables 使用 `xfrm_tunnel_pattern` |
| `UpstreamInterfaces` | 同 netns routing upstream veth 接口 | routing 配置是唯一权威来源；去重后精确生成 upstream 规则 |
| `AdvertisedCurrent/Previous*Ports` | 本地 signed `ipsec/ports` record | redirect grace |

### 4.2 PrefixSets

```go
// pkg/firewall/types.go
type PrefixSets struct {
    LocalAssignedV4  []netip.Prefix
    LocalAssignedV6  []netip.Prefix
    MeshAuthorizedV4 []netip.Prefix
    MeshAuthorizedV6 []netip.Prefix
    RevokedV4        []netip.Prefix // audit-only
    RevokedV6        []netip.Prefix // audit-only
}
```

`buildPrefixSets` 会把 `Revoked` 前缀从 `LocalAssigned` 和 `MeshAuthorized` 中剔除，同时把 revoked 前缀单独保留在 `RevokedV4/V6` 中用于审计。

### 4.3 overlay netns 规则顺序

overlay 实例生成 `input`、`forward`、`output` 三条 filter chain。

#### input chain（按生成顺序）

```text
1. invalid drop (ct state)
2. loopback accept
3. pre_input hook
4. UDP 6696 (Babel) accept
5. ICMP / ICMPv6 accept
6. established/related accept (ct state)
7. local_services accept
8. mesh authorized -> local assigned accept
9. post_input hook
10. default policy (drop / accept)
```

#### forward chain

```text
1. scoped asymmetric-transit INVALID accept：仅匹配后续 transit allow 的接口、前缀和 ct state invalid
2. invalid drop (ct state)：拒绝其余 invalid，包括非 transit 流量
3. established/related accept (ct state)
4. pre_forward hook
5. XFRM->XFRM：transit=false 则 drop；transit=true 则按 forwarding policy allow
6. XFRM->upstream：允许到 local assigned 前缀
7. upstream->XFRM：允许到 mesh authorized 前缀
8. post_forward hook
9. default policy (drop / accept)
```

非对称路由下，中间节点可能看到 SYN 及后续 ACK/data，却看不到反方向的 SYN-ACK，因而把后续包标成 `INVALID`。前置例外只放行原本已由接口和授权前缀约束的 transit 流量；input chain 与其他 forward 流量仍先执行通用 `INVALID drop`。

#### output chain

```text
1. loopback accept
2. UDP 6696 (Babel) accept
3. ICMP / ICMPv6 accept
4. local assigned source accept
5. post_output hook
6. default accept（output 固定为 accept）
```

> **注意**：output chain 的默认策略当前硬编码为 `accept`，不受 `default_policy` 配置影响。

### 4.4 host netns 规则

host 实例生成以下规则：

#### Endpoint ACL（forward 链）

`EndpointACL` 通过 control API 应用，只允许匹配 Zone selector 的源访问指定目标。它支持两种 scope：

- `port`：兼容原有行为，匹配 destination、TCP/UDP protocol 和固定 port。
- `ip`：只匹配 destination IP，不限制 protocol/port；用于 GOST SOCKS5 UDP ASSOCIATE 这类动态分配 relay port 的服务。

每个 endpoint 都生成“允许+默认 drop”规则，实现 fail-closed。IP scope 的 allow/drop 不带 L4 条件，因此该地址应专用于同一安全域内的服务；不同认证或授权边界应使用不同容器 IP。

```go
// app/photon/endpoint_acl.go
if len(endpoint.Sources) > 0 {
    // accept rule
} else {
    // 不生成 accept；但始终生成 drop，保证 fail-closed
}
desired.ForwardRules = append(desired.ForwardRules, Rule{
    Action: ActionDrop, ...
})
```

#### Host ingress

`host_ports` 启用的端口生成 `HostIngressRule`：

| 端口 | 协议 | 说明 |
|---|---|---|
| 500 | UDP | IKE |
| 4500 | UDP | NAT-T |
| 51820 | UDP | WireGuard（预留） |

#### Redirect grace

当 `redirect_grace.enabled=true` 时，把当前或历史 advertised 端口重定向到当前 charon 监听端口（IKE 500 / NAT-T 4500）。同时生成 source-port rewrite 规则，使本机发出的传输流量源端口与 advertised 端口一致。

```go
// pkg/firewall/planner.go:340-361
addNatRedirects(desired, input.AdvertisedCurrentIKEPorts, ikePort, "redirect current", "ike", spec.ListenAddrs)
addNatRedirects(desired, input.AdvertisedPreviousIKEPorts, ikePort, "redirect grace", "ike", spec.ListenAddrs)
addNatRedirects(desired, input.AdvertisedCurrentNATTPorts, nattPort, "redirect current", "natt", spec.ListenAddrs)
addNatRedirects(desired, input.AdvertisedPreviousNATTPorts, nattPort, "redirect grace", "natt", spec.ListenAddrs)
addNatSourceRewrites(...)
```

这一模型的要点：

- charon 始终以稳定端口监听（IKE 500 / NAT-T 4500）；`ipsec.port_mode=range` 的 advertised entry port 只是对外公布的 wire 入口，charon 不绑定每个 generation 的端口，入口兼容完全由 NAT redirect 解决。这不是 StrongSwan per-connection listener。
- previous advertised ports 只用于入方向 grace；新出站流量的源端口始终 rewrite 到 current advertised 端口，避免延长旧 generation 的主动使用窗口。
- previous 端口记录带 grace 窗口（`ValidUntil`），过期端口不再进入 planner 输入，对应规则随下一轮 reconcile 消失。
- redirect grace 只解决 responder 入口端口兼容，source-port rewrite 只让 wire 源端口与公告一致；二者都不保证 CHILD_SA 无中断迁移，SA 生命周期仍由 StrongSwan/VICI reconcile 管理。
- 排障时注意端口视角差异：`swanctl --list-sas` / `ip xfrm state` 展示的是 charon 视角的 500/4500，underlay 接口上抓包看到的则是 rewrite 后的 advertised 端口。二者不一致是预期行为，不作为 wire-port 故障依据。

WireGuard 的 previous port redirect 也已预留字段，但依赖 Phase 7 WireGuard transport driver 提供 advertised 端口。

---

## 5. Backend 驱动

### 5.1 Driver 接口

```go
// pkg/firewall/driver.go
type FirewallDriver interface {
    Preflight(ctx context.Context, spec FirewallInstanceSpec) (FirewallPreflight, error)
    Plan(ctx context.Context, desired *FirewallDesiredState, observed FirewallObservedState) (FirewallPlan, error)
    Apply(ctx context.Context, plan FirewallPlan, desired *FirewallDesiredState) (FirewallApplyResult, error)
    ListOwned(ctx context.Context, owner Owner) (FirewallObservedState, error)
    DeleteStale(ctx context.Context, refs []FirewallObjectRef) error
}
```

overlay 实例的 driver 会把所有命令用 `ip netns exec <netns>` 包装后执行，使规则真正下发到对应命名空间；host 实例直接在 host netns 执行。

### 5.2 nftables 后端（`NFTDriver`）

- 使用 `nft` CLI（非 netlink API）。
- 所有对象放在 `inet` family 的表 `<owner_prefix>_<scope>` 中。
- overlay 创建 `input`、`forward`、`output` chain；host 额外创建 `prerouting`、`postrouting`。
- Mesh 前缀使用 `set`，命名如 `photon_h2_mesh_v4`、`photon_h2_mesh_v6`，带 `flags interval`。
- `Apply` 把 delete/recreate、set、chain 与 rule 渲染到同一个 batch 文件，通过单次 `nft -f` 事务提交；任一语句失败时内核拒绝整批变更，旧 table 继续生效。
- 支持 `nft_hooks` 原生 inline rule，并与 managed rules 一起进入同一个 batch 事务。

### 5.3 iptables 后端（`IPTablesDriver`）

- 同时操作 `iptables` 与 `ip6tables`。
- planner/ListOwned 使用 `photon_<scope>_input/forward/output` 及 host NAT chain 作为逻辑对象；内核中的实际策略使用带 desired hash 与 `a`/`b` 槽位的 generation chain。解析时只识别严格格式的 managed chain，避免误清理非 Photon 对象。
- 使用 `-m comment --comment photon-<scope>` 标记 Photon 规则。
- 每次 Apply 先在未激活槽中完整生成 INPUT/FORWARD/OUTPUT 及所需 NAT chain；全部 IPv4/IPv6 staging chain 填充成功后，才在 builtin chain 顶部插入新 jump，随后移除旧 jump 和旧 generation。准备失败不会修改当前入口，切换失败则保留旧 jump。
- NAT redirect 使用 generation prerouting chain 中的 `REDIRECT --to-ports`；source rewrite 使用 generation postrouting chain 中的 `MASQUERADE --to-ports`。
- `iptables_hooks.ipv4/ipv6` 原生 inline rule 直接写入对应 family 的 inactive generation，不创建外部 chain。
- 地址族处理：带 v4/v6 前缀或地址的规则按族只进对应 binary；族中立规则（无前缀匹配、非 ICMP 协议，如 loopback、babel、conntrack、default policy）同时下发到 `iptables` 与 `ip6tables`；ICMP 规则按族分别渲染（`-p icmp` 只进 `iptables`，`-p icmpv6` 只进 `ip6tables`）。
- 接口前缀模式在 planner 中使用 nft 风格尾随 `*`；iptables 渲染时转换为 xtables 的尾随 `+`（例如 `phx*` → `phx+`）。
- XFRM 规则使用 `xfrm_tunnel_pattern` 的前缀匹配，避免按实时接口的 `iif × oif` 组合展开；upstream veth 仍使用 routing 配置给出的精确接口名。这个后端差异有意用较宽的接口角色边界换取固定数量的 transit 规则。
- 两个及以上的 source/destination prefix 使用 generation-scoped `hash:net` ipset，并由单条规则通过 `-m set --match-set` 查询；单个 prefix 仍直接使用 `-s` / `-d`。set 名包含 instance scope 与 generation，inactive set 填充完成后才切换 built-in jump，旧 generation chain 删除后再清理无引用 set。
- iptables backend 要求 `iptables`、`ip6tables` 和 `ipset` 同时可用；set 创建、填充或引用失败会中止 staging，当前 active generation 保持不变。

### 5.4 dry-run 后端（`DryRunDriver`）

- 不修改系统，只记录 plan/apply 调用。
- 当 backend 探测不到 `nft` 或 `iptables`，或配置为 `none` 时使用。
- 用于单元测试和 smoke 场景。

### 5.5 Backend 探测

```go
// pkg/firewall/driver.go:65
func PreflightProbe(ctx context.Context) FirewallPreflight
```

探测逻辑：

1. 检查 `nft` 命令是否存在；存在便记为 `NFTNetlink=ok` 并优先选择 `nft`（字段名不代表真的探测了 netlink API）。
2. 分别检查 `iptables` 和 `ip6tables`；只有两者均存在时才选择 `iptables` backend，避免单栈半套策略。
3. 都不可用时 `Backend=none`。
4. `CAP_NET_ADMIN` 通过 `nft list tables` 做尽力探测。

> **注意**：daemon 选择 backend 时使用上述全局探测，不调用具体 driver 的 `Preflight`；`CAP_NET_ADMIN` 结果也不参与选择。当前会检查 `iptables`、`ip6tables`、`ipset` 的 host PATH，但不预先验证 netlink API、host NAT hook、目标 netns 内可执行性以及 `xt_set` 内核 match；这些能力在 staging apply 时 fail-closed 验证。详见第 8 节。无完整 backend 时，daemon 会记录 `no_backend_available` / `backend_unavailable` warning，并在实例状态中保留错误，不会伪装为 dry-run 成功。

### 5.6 Plan diff

```go
// pkg/firewall/driver.go:27
func PlanDiff(instanceID string, desired *FirewallDesiredState, observed FirewallObservedState) FirewallPlan
```

通用 diff 逻辑：

- desired 中有、observed 中无 → `create`
- desired 中有、observed 中也有 → `adopt`
- observed 中有、desired 中无 → `delete`（stale）

这个 diff 只比较对象引用（kind/family/name），不比较 rule/set 内容；当前 driver 的 `Apply` 也不会因为 `policy_hash` 未变化而跳过。因此 nft 每次 apply 都会整表替换，iptables 每次 apply 都会准备并切换另一个 `a`/`b` 槽位。

---

## 6. Reconcile 流程

### 6.1 触发时机

Firewall reconcile 在 `app/photon/firewall_reconcile.go` 中实现，触发时机见 [daemon.md](daemon.md)：

- daemon 启动时 `recoverFirewallOnStart` 设置 `firewallDirty=true` 并 flush。
- `notifyStateChanged`（网络状态、Zone record、endpoint ACL 等变化）触发 flush。
- `processEvents` 每次事件 drain 后也会 `flushFirewallReconcile`。
- `endpoint_acl_apply` / `endpoint_acl_remove` 事件单独强制 flush。
- `reload_config` 重新加载配置后触发。

### 6.2 reconcileFirewall 主流程

```text
1. 获取当前 committed snapshot 与 config
2. 调用 routing.BuildAuthorizedRouteSet 生成授权路由集
3. PreflightProbe 探测 backend
4. 对每个 enabled instance：
   a. firewallInstanceSpecFromConfig 生成 spec
   b. host 实例：resolveEndpointServices 解析 EndpointACL
   c. buildFirewallPolicyInput 组装 planner 输入
   d. firewall.BuildDesiredState 生成期望状态
   e. 选择 driver（nft / iptables / dry-run）
   f. driver.ListOwned 读取当前 owned 对象
   g. driver.Plan 计算 diff
   h. driver.Apply 应用
   i. 记录 generation、policy_hash、owned_objects 到在线 observation
5. 发布本轮 observation，供 debug/status 读取
```

### 6.3 在线观察

每个 instance 的 reconcile 结果只保留在 daemon 进程内：

```go
// pkg/firewall/types.go
type FirewallInstanceObservation struct {
	Backend      string
    Generation   uint64
    LastRunUnix  int64
    LastFailure  error
    PolicyHash   string
    OwnedObjects int
}
```

`FirewallObservation` 在进程重启后为空，由下一轮 reconcile 重建。它不参与下一轮 plan/apply；driver 仍在每轮从系统重新读取 Photon-owned 对象。`EndpointACLs` 是用户配置，仍持久化。

> **注意**：当前 `Generation` 在 `NFTDriver` / `IPTablesDriver` / `DryRunDriver` 中均返回固定值 `1`，未实现真正的 generation 递增。

### 6.4 失败语义

`reconcileFirewall` 按 instance 隔离失败，单个实例出错不影响其他实例：

- `BuildDesiredState` / `Plan` / `Apply` 任一步失败：原始 `error` 记录到该实例的 `LastFailure`，继续处理下一个实例；全部实例处理完后，首个错误写入 summary 的 `LastFailure` 并发布到在线 observation，可由 `photon debug firewall` 查看。
- nft driver 使用单次 batch 事务，任一命令失败时整批不提交，旧 ruleset 保持不变。
- iptables driver 的 staging 阶段遇错立即停止并删除未激活链，旧 generation 保持生效；所有 staging chain 完成后才进入切换阶段。iptables 与 ip6tables 以及不同 table 之间没有跨后端的统一内核事务，因此切换阶段若失败会补偿删除此前已激活的新 jump 并保留旧 generation；若补偿命令本身也失败，错误会记录到 reconcile 状态，下一轮继续收敛。
- backend 不可用（nft 缺失且 `iptables` / `ip6tables` 之一缺失）：daemon 记录 `no_backend_available` 或 `backend_unavailable` warning，并在该 instance 的 `LastFailure` 中保留失败；不会退化为 dry-run 成功。系统上已有的旧规则保持不动。
- 撤销（revocation）不走特殊通道：Zone record 变化经 `notifyStateChanged` 触发 flush，deny-first 由 planner 的 `buildPrefixSets` 在生成期望状态时保证（见 4.2）。

---

## 7. Debug 与诊断

### 7.1 photon firewall show

```bash
photon firewall
photon firewall show [--filter <text>] [--verbose]
```

这是面向 operator 的日常状态入口。默认按 instance 显示 scope、mode、实际 backend 和 active/pending/error 状态；`--filter/-f` 可按 instance ID、scope、mode 或 backend 过滤，`--verbose/-v` 增加 policy、prefix、service、generation 和 owned-object 计数。它不显示 policy hash 或 inline hook 原始表达式。

### 7.2 photon debug firewall

```bash
photon debug firewall [--netns <name> | --host] [--json]
```

默认输出每个 instance 的期望规则、owned 对象、reconcile 状态、配置 backend 和实际 resolved backend。`--netns` 可按 netns 或 instance ID 筛选，`--host` 只显示 host instance，`--json` 输出同一视图的 JSON；`--host` 与 `--netns` 互斥。配置了 inline hooks 时，还会逐条显示 backend、iptables family、hook point、原始表达式及状态：`active` 表示属于当前实际 backend，`inactive` 表示为异构主机保留但本机未使用，`pending` 表示该实例尚无 reconcile backend 结果。实现见：

- `internal/inspect/firewall.go`：构造 debug 视图
- `internal/inspect/text/firewall.go`：文本化输出
- `app/photon/debug_firewall.go`：CLI 注册

### 7.3 photon debug preflight

```bash
photon debug preflight
```

输出 backend 探测结果：`nft` 是否可用、`iptables` 是否可用、`CAP_NET_ADMIN` 状态等。

### 7.4 单元测试与 smoke

- `pkg/firewall/*_test.go`：planner 与 driver 单元测试。
- `pkg/firewall/root_smoke_test.go`：需要 root / netns 的 backend smoke 测试。
- `app/photon/firewall_test.go`：daemon 级 firewall 测试。

---

## 8. 已知限制与实现缺口

以下只列当前仍存在的限制和部分实现。原清单中的 invalid drop、`ct state established/related`、host native hooks、nft/iptables backend-native inline hooks，以及 iptables 大小写 chain/stale/jump 累积问题已经修正，不再属于当前缺口。

| 项 | 设计期望 | 当前实现 | 影响 | 下一步 |
|---|---|---|---|---|
| `mode: external` | Photon 只读取/诊断，不生成或修改规则 | 已在实例过滤、planner、plan 和 driver 层阻断变更；debug 仍显示配置与历史 reconcile 状态 | 已收口；切换到 external 不会清理此前 Photon-owned 对象 | 已完成 |
| Native inline rule 可移植性与校验 | 同一策略可跨 backend 表达，并在 apply 前完成完整语义校验 | `nft_hooks` / `iptables_hooks` 是两套原生语法；配置阶段只做边界和危险参数校验，真正的模块、match、target、表达式合法性由 nft/iptables apply 验证 | 异构节点需同时维护两套等价规则；语义错误到 reconcile 时才暴露 | 暂时不需要调整，由管理员自行控制 |
| `peer_authorized_v4/v6` set | 按 peer 分组的前缀集合 | 未实现 | 无按 peer 分组 | 暂不实现 |
| Assignment 白名单二次校验 | planner 独立校验允许进入规则的 assignment | `AssignmentPrefixes` 已组装但仍未使用；前缀规则依赖 `AuthorizedRouteSet` 派生结果 | 缺少 planner 层独立的 assignment 防御性复核 | 暂不实现 |
| Backend 探测粒度 | 检测 netlink API、`CAP_NET_ADMIN`、目标 netns、host NAT hook、ipset 及 IPv4/IPv6 CLI | 已检查 `iptables`、`ip6tables` 与 `ipset` 必须同时存在；仍主要只检查 host PATH，`CAP_NET_ADMIN` 仅以 `nft list tables` 近似且不参与 backend 选择，daemon 也未调用 driver `Preflight` | 避免单栈或缺少 set 支持的半套策略；权限、`xt_set` 或目标 netns 不可用仍可能在 staging apply 才失败 | CLI 检查已完成；内核能力与目标 netns 探测暂不实现 |
| Backend 不可用时的失败策略 | 显式 backend 不可用应 fail closed 或阻止启动 | 无可用 backend 的 instance 不会转交 DryRunDriver；会记录 `LastFailure` 并输出结构化 `no_backend_available` / `backend_unavailable` warning | daemon 继续运行，但不会把未下发规则伪装为成功 | 已完成 warning 与 fail-closed per-instance reconcile |
| netlink API | nftables 优先使用 netlink | 实际使用 `nft` CLI | 实现方式不同 | 暂不实现 |
| 无变更 reconcile | `policy_hash` 未变化时 no-op | `PlanDiff` 只比较对象名；nft 每次 apply 原子整表替换，iptables 每次 apply 重建并切换同 hash 的另一个 `a`/`b` 槽位 | 无业务变更也会产生内核写入；nft 有短暂事务切换成本，iptables builtin jump 会经历一次 generation 切换 | 问题不大 暂时保留 |
| Generation 递增 | 每次成功 apply 递增并可追踪历史 | iptables 物理 chain 已带 desired hash 和 `a`/`b` staging 槽，但 NFT/IPTables/DryRun driver 对外仍返回 `Generation: 1` | 持久化/debug 状态无法按 generation 区分历史，也不能表达实际槽位 | 问题不大 暂时保留 |
| 生命周期与跨 backend 清理 | shutdown、禁用/删除实例、scope/prefix/backend 变化时回滚旧 owned rules | daemon 不调用 `DeleteStale`；只对当前启用实例、当前 scope 和当前 backend 做 reconcile。禁用/删除实例、退出、改变 owner/scope 或切换 backend 不会遍历并清理旧 backend 对象 | 旧 nft table 或 iptables chain/jump 可能长期残留，并与新策略同时生效 | 问题不大 暂时保留 |
| 周期 reconcile timer | 设计建议有周期 timer | `defaultFirewallReconcileInterval`（30s）通过 Daemon Scheduler 调度 | 启动恢复、事件触发和周期 safety reconcile 共用同一 single-writer 入口 | 已完成 |
| 冲突检测 | 检测非 Photon 规则冲突 | `MergeConflicts` 直接返回 `nil` | 冲突检测未实现 | 问题不大 暂时保留 |
| 优先级配置 | nft base-chain priority 可按 hook 阶段配置 | 已支持 `priority.filter`、`priority.prerouting`、`priority.postrouting`；默认分别是 `filter`、`dstnat`、`srcnat`，只允许对应基准加整数偏移 | 可以在不混淆 DNAT/SNAT 阶段的前提下与管理员 chain 排序 | 已完成 |
| `AllowPeers`/`DenyPeers` | 按 peer zone 过滤 transit | 字段存在但**未实际使用** | 仅前缀过滤生效 | 问题不大 暂时保留 |
| WireGuard host 配置接线 | `host_ports.wg`、当前/历史 advertised WG port 驱动 ingress 与 grace | type/planner 中有 `WG`、`WGPort`、`AdvertisedPreviousWGPorts` 预留，但 YAML `host_ports` 只接受 `ike`/`natt`，daemon 也不填充 WG 端口输入 | 目前不能从 `config.yaml` 启用 WireGuard host firewall/grace | wg没实现前不需要进一步推进 |
| debug 命令 flag | `--netns` / `--host` / `--dry-run` / `--json` | 已支持 `--netns`（也可按 instance ID）、`--host` 与 `--json`；未实现 `--dry-run` plan | 日常定位与机器读取已收口；仍不能从 CLI 预演完整 plan | 仅 dry-run 暂不实现 |
| 命名约定 | 建议 `PHOTON-H2-INPUT` | 逻辑对象为 `photon_h2_input`，iptables 物理 chain 另带 hash/双槽 generation 后缀 | 风格差异 | 问题不大 |


### 8.1 使用建议

- 生产环境可显式配置 `backend: nft` 或 `backend: iptables` 来固定选择，但“显式”不等于 backend 可用时强制失败；仍应检查 `photon debug firewall` 的 `resolved_backend` / `last_failure` 和 daemon warning，避免实际落入 dry-run。
- `mode: external` 可用于将 instance 交给外部管理器：Photon 不会再修改它；切换前已有的 Photon-owned 规则仍需由管理员确认并清理。
- host 实例在 `ipsec.port_mode=range` 时默认启用 redirect grace；若使用固定端口，可关闭 `redirect_grace`。
- daemon 升级、停止、禁用实例或切换 backend 后，建议手动检查并清理残留的 Photon-owned table/chain（`nft list tables`、`iptables -S`、`ip6tables -S`）。

### 8.2 后续设计方向

原设计中尚未排期、仍作为方向保留的内容：

- **forwarding policy 升级为 signed record**：`ForwardingPolicy` 当前来自本地配置，后续可升级为 `routing/forwarding` signed record，使转发意图可验证、可传播，并继续由 BIRD 与 firewall 共享同一份来源。
- **gossip 中继控制信号**：源节点可通过 gossip 发布“不希望某些中继转发自己的路由”的 hint，用于规避质量差、费用高或不可信的链路。
