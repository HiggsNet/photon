# Photon Routing 与 IPAM

> **本文档状态：2026-07**
> `docs/new/` 模块化文档迁移后的 routing / IPAM 当前行为入口。
> 它替代并合并了以下旧 Phase 设计文档：
> - `docs/phase5-route-record-design.md`
> - `docs/phase6-ipam-design.md`
> - `docs/phase5-7-per-netns-bird-design.md`

Routing 把已经建立的 overlay 接口接入 BIRD/Babel，使 mesh 自动学习可达前缀。它不建立 IPsec、WireGuard 或其他 tunnel；也不把本机 BIRD 状态写进 gossip。Routing 只消费已验证的 Zone state 和本机配置，并把结果收敛为 BIRD 配置、内核路由和观测状态。

完整配置字段见 [config.md](config.md) 与根目录 `config.example.yaml`。IPsec 建链细节见 [transport-ipsec.md](transport-ipsec.md)。

---

## 目录

1. [架构概览](#1-架构概览)
2. [Record schema 与 key 规范](#2-record-schema-与-key-规范)
3. [授权模型](#3-授权模型)
4. [Route overlap 裁决](#4-route-overlap-裁决)
5. [BIRD/Babel 运行时](#5-birdbabel-运行时)
6. [veth upstream：把 mesh 接到 host](#6-veth-upstream把-mesh-接到-host)
7. [自动宣告、CLI 与诊断](#7-自动宣告cli-与诊断)
8. [实现边界](#8-实现边界)

---

## 1. 架构概览

### 1.1 控制面与运行时的边界

```text
signed Zone records                         local runtime
───────────────────                         ─────────────
pool / assignment / announcement ──verify──> AuthorizedRouteSet
                                                    │
transport interfaces ──────────────────────────────┼──> BIRD config
local routing / netns / forwarding policy ─────────┘        │
                                                             ├──> Babel neighbors
                                                             ├──> kernel routes
                                                             └──> BirdInstanceState / health
```

| 层 | 负责什么 | 不负责什么 |
|---|---|---|
| Gossip / Zone | 传播并验证签名的 authority、delegation、IPAM 和 route records | 不启动 BIRD、不修改路由表 |
| IPAM authorization | 判断谁有地址分配权、谁可以使用一段地址、哪些 announcement 有效 | 不探测节点是否真的在线 |
| Routing reconcile | 按每个 netns 生成 BIRD 配置、管理进程和 veth/upstream 路由 | 不改变 signed record 的真实性 |
| BIRD/Babel | 交换、选择并安装路由 | 不验证 Zone 签名链 |

这也符合 [daemon.md](daemon.md) 的通用原则：gossip state 与本机 runtime 是两层状态。某节点的 BIRD 崩溃只影响它自身的转发能力，不会撤销其他节点看到的 signed announcement。

### 1.2 per-netns BIRD 模型

一个 network namespace 对应一个 BIRD 实例；该 netns 内所有 overlay 接口共享 Babel 邻居、BIRD table 和 kernel table。

| 项目 | 当前行为 |
|---|---|
| 实例配置 | `routing.instances[]`，每项引用一个 `netns` |
| mesh tunnel 接口 | 默认匹配 `phx*`；使用 BIRD `type wireless` 的渐进 ETX 度量，并显式启用 RTT；同一实例可合并多个 interface pattern |
| veth upstream 接口 | 默认 `phv2host`，使用 BIRD 默认 wired 行为，不启用 ETX/RTT |

Photon 在每个托管 Babel protocol 中启用 `randomize router id`。这不会改变持久化的全局 BIRD router ID；它只在 Babel 实例启动时随机化协议内部 64-bit origin ID 的高 32 位，避免重启后从 1 开始的 sequence number 被其他节点按旧 announce 拒绝。
| RTT 选路 | 默认 `cost=64`、`min=10ms`、`max=500ms`、`decay=12`，保留 RTT 选路并抑制短时抖动 |
| Babel 周期 | Hello 默认 `4s`；周期性全量 Update 默认 `16s`，triggered update 不受该间隔限制 |
| Router-ID | 由 managed Zone、trusted root hash 与稳定 netns label 派生 |
| 路由表 | 默认写目标 netns 的 `main` table，也可指定数字 table ID |
| forwarding | `netns.*.forwarding` 同时约束 BIRD export 与 firewall 的 transit 行为 |
| BIRD 版本 | 需要 BIRD 2.14+；该基线覆盖 Ubuntu 24.04 自带的 BIRD 2.14 |

---

## 2. Record schema 与 key 规范

### 2.1 公共约定

所有 IPAM / route record 都使用同一套 CIDR 规范化：

1. 用 `netip.ParsePrefix` 解析后取 `Masked()`。
2. key 中把 `/` 替换为 `_`。

例如 `10.0.1.1/24` 规范为 `10.0.1.0/24`，key 后缀为 `10.0.1.0_24`；IPv6 `2001:db8::/32` 的 key 后缀为 `2001:db8::_32`。

record 模型不支持显式删除。撤回使用同一 key 的更高版本，并把对应 `active` 字段设为 `false`。`timestamp` 只作审计，不参与冲突裁决。

### 2.2 `ipam.pool`

- **Key**: `ipam/pools/<canonical_prefix_with_underscore>`
- **Type**: `ipam.pool`
- **Capability**: 需要 `allocate-ip` 或通用 `write`
- **Value**:

```json
{
  "version": 1,
  "prefix": "10.0.0.0/16",
  "delegated_to": "pek.catofes.",
  "active": true
}
```

`delegated_to` 表示该前缀的下一层分配权交给哪个 Zone。root 自举时可以用 `delegated_to: "."`。

### 2.3 `ipam.assignment`

- **Key**: `ipam/assignments/<canonical_prefix_with_underscore>`，shared 成员可再加 `#<member_zone>` 后缀
- **Type**: `ipam.assignment`
- **Capability**: 需要 `allocate-ip` 或通用 `write`
- **Value**:

```json
{
  "version": 1,
  "prefix": "10.42.1.0/24",
  "assigned_to": "node-a.pek.catofes.",
  "active": true,
  "shared": false,
  "tag": ""
}
```

- `assigned_to`：谁可以使用/宣告这段前缀。
- `shared`：Anycast 标志。只有 `shared: true` 的 assignment 才允许多个 Zone 持有同一前缀。
- `tag`：只能用于 shared assignment，是服务部署选择共享前缀的稳定名字。同一 tag 在同一地址族必须对应同一个 prefix。

### 2.4 `route.announcement`

- **Key**: `routes/announcements/<canonical_prefix_with_underscore>`
- **Type**: `route.announcement`
- **Capability**: 需要通用 `write`
- **Value**:

```json
{
  "version": 1,
  "prefix": "10.42.1.0/24",
  "active": true,
  "controller": ""
}
```

- `active: false` 表示撤回；撤回记录仍保留在 key 的 version chain 中用于审计。
- `controller: "auto"` 保留给 `ipam.announce` 自动管理；显式/服务创建的 record 不应使用。
- 同一 key 的 `prefix` 不允许改变。若要换前缀，必须先对旧 key 发 `active:false`，再在新 key 下发宣告。key 与前缀不一致会报 `route_announcement_key_mismatch`。

### 2.5 `routing/netns`

- **Key**: `routing/netns`
- **Type**: `routing.netns.v1`
- **Value**:

```json
{
  "version": 1,
  "netns": ["photon"]
}
```

这条记录由 daemon 自动发布，列出本节点 `routing.instances[]` 实际使用的 netns 名称。其他节点可用它把 Babel Router-ID 反推回 `(zone, netns)`，用于控制面交叉审计。不要手工写入或修改。

---

## 3. 授权模型

### 3.1 三层链

```text
pool                         assignment                         announcement
────                         ──────────                         ────────────
谁可以继续分配地址      ──> 谁可以使用一段地址          ──> 谁当前宣告它可达
```

| Record | 回答的问题 | 核心字段 |
|---|---|---|
| `ipam.pool` | 这段前缀的分配权属于谁 | `delegated_to` |
| `ipam.assignment` | 这段前缀的使用/宣告基础属于谁 | `assigned_to` |
| `route.announcement` | 我现在宣称该前缀可达 | `prefix`, `active` |

### 3.2 Pool 授权与重叠

Zone `Z` 下的一条 `ipam.pool` 有效，当且仅当满足以下之一：

1. `Z == "."` 且 `delegated_to == "."`（root 自举）。
2. 存在另一条已生效的 pool `P`，满足：
   - `P` 的 `delegated_to == Z`（分配权确实下放到了 `Z`）；
   - `P.prefix` 覆盖当前 pool 的 prefix。

Pool 之间的重叠只被允许在 delegation 链上（外层 pool 的 `delegated_to` 等于内层 pool 的 source，或经过中间 pool 桥接）。兄弟 Zone 的 pool 重叠会被拒绝，错误码 `ipam_pool_overlap`。

### 3.3 Assignment 授权与重叠

Zone `Z` 下的一条 `ipam.assignment` 有效，当且仅当存在一条已生效的 pool `P`，满足：

- `P` 的 `delegated_to == Z`；
- `P.prefix` 覆盖 assignment 的 prefix。

否则报 `ipam_assignment_pool_mismatch`。

Assignment 之间的重叠规则：

| 场景 | 是否允许 | 条件 |
|---|---|---|
| 同一 Zone | 允许 | `assigned_to` 之间存在祖先/后代关系（层级分配） |
| 不同 Zone | 允许 | 两个 Zone 在同一条 delegation 链上，且前缀是包含关系 |
| 兄弟/无关 Zone | 拒绝 | `ipam_assignment_overlap` |
| 双方 `shared: true` | 允许 | Anycast 场景，跳过普通重叠检查 |
| tag 冲突 | 拒绝 | 同一 tag 在同一地址族对应不同 prefix，报 `ipam_assignment_tag_conflict` |

### 3.4 Announcement 授权

对 announcer `Z` 的 prefix `R`，authorization 会在 `Z` 及其祖先 Zone 中寻找覆盖 `R` 的有效 assignment `A`。它必须满足：

1. `A.source` 是 `Z` 自身或 `Z` 的祖先；
2. `A.prefix` 覆盖 `R`；
3. 以下任一关系成立：
   - `A.assigned_to == Z`：分给自己，自己发布；
   - `A.assigned_to` 是 `Z` 的祖先：分给管理 Zone，其子树可发布更具体前缀；
   - `A.assigned_to` 是 `Z` 的后代，且 `A.source == Z`：父 Zone 保留聚合发布权。

### 3.5 Announcement 继承模型

**Route announcement 的授权是从 assignment 继承来的，而不是直接从 pool。** 也就是说：

- assignment 的 `assigned_to` 字段定义了“谁有权使用这段前缀”；
- announcer 必须落在 `assigned_to` 的授权范围内，才能宣告该 assignment 覆盖下的前缀（或更具体前缀）；
- 这个“授权范围”由 `assigned_to` 与 announcer 的 Zone 关系，以及 assignment 所在的 `source` Zone 共同决定。

#### 继承规则速查

| assignment source | `assigned_to` | 谁能宣告该 assignment 覆盖的前缀 | 谁能宣告更具体前缀 | 说明 |
|---|---|---|---|---|
| 父 zone | 父 zone | 父 zone 自己 | 父 zone 及其所有后代 | 父 zone 把地址块留给自己管理，子树按需要宣告 `/24`、`/64` 等 |
| 父 zone | 子 zone | 父 zone 自己（仅聚合） | 只有 `assigned_to` 子 zone 及其后代 | 父 zone 可聚合宣告 `/16`，但具体 `/24` 只能由子 zone 宣告 |
| 子 zone | 子 zone | 子 zone 自己 | 子 zone 自己 | 完全由子 zone 自行管理；父 zone 不能拿这个 assignment 再宣告 |
| 任意 zone（shared） | 多个 shared 成员 | 所有 shared 成员 zone | 所有 shared 成员 zone | Anycast 场景 |

#### 关键结论

1. **Announcement 不直接继承 pool。** 只有 assignment 才是 announcement 的授权来源。pool 只解决“谁能继续分配”，不解决“谁能宣告”。
2. **父 zone 不能“继承”子 zone 的 assignment。** 如果 assignment 写在子 zone 下（`source == child`），父 zone 不能用它来宣告子 zone 的前缀。
3. **聚合宣告需要 assignment source 在父 zone。** 父 zone 要宣告一个包含子 zone 地址的聚合前缀，必须在父 zone 自己有一条 `assigned_to` 为子 zone（或父 zone 自己）的 assignment。
4. **更具体前缀可以继承宣告权。** 只要 announcer 被授权使用某段地址，就可以在该段内宣告任意更具体前缀（受 BIRD prefix-length policy 约束）。

### 3.6 一个完整示例

```text
.
  pool 10.0.0.0/8  delegated_to=.
  pool 10.42.0.0/16 delegated_to=pek.catofes.

pek.catofes.
  assignment 10.42.0.0/16 assigned_to=pek.catofes.
  assignment 10.42.1.0/24 assigned_to=node-a.pek.catofes.

node-a.pek.catofes.
  announcement 10.42.1.0/24 active=true
```

- 根保留 `/8` 的分配权，并把 `/16` 的下一层分配权交给 `pek.catofes.`。
- `pek.catofes.` 在自己获得的 pool 内，把 `/24` 的使用权交给 `node-a`。
- `node-a` 以自己的 Zone 签名宣告 `/24` 可达；只有这时它才会进入 `AuthorizedRouteSet` 和 BIRD。

---

## 4. Route overlap 裁决

两个有效签名的 announcement 仍可能因为前缀重叠而无法同时进入路由表。`BuildAuthorizedRouteSet` 统一裁决：

| 两条 announcement 的关系 | 收敛后的结果 |
|---|---|
| 兄弟 / 无关 Zone 宣告同一或重叠前缀 | 两条都拒绝，报 `route_overlap_unauthorized` |
| 父 Zone 与子 Zone 宣告包含关系 | 保留两条；数据面由最长前缀匹配处理更具体路由 |
| 同一管理子树但两个叶节点宣告不重叠前缀 | 都保留 |
| 双方都由 shared assignment 支撑 | 允许并存，Babel 可用 ECMP 做 Anycast |

因此，管理 Zone assignment 给自己不会允许两个兄弟节点同时宣告同一 `/24`。发生冲突时 fail-closed，两个 announcement 都不可用。在网络分区尚未收敛时，每一侧只能根据自己已知的 state 决策，短暂 split-brain 无法由纯 gossip 消除；合并后会回到上述 fail-closed 结果。

---

## 5. BIRD/Babel 运行时

### 5.1 实例与 Router-ID

每个 `routing.instances[]` 项对应一个 BIRD 进程：

- `netns` 决定它在哪个 namespace 内运行；
- `provider` 当前只支持 `bird`；
- `mode` 可为 `managed`（Photon 启停配置）、`external`（只观测已有 BIRD）或 `disabled`；
- `enabled: false`（或 `disabled: true`）与 `mode: disabled` 都会在任何系统操作前跳过该实例；禁用不会自动停止或删除此前由该实例创建的 BIRD、veth、地址和路由；
- `shutdown_policy` 默认 `persist`：daemon 退出不停止 BIRD，重启后通过 pid/control socket adopt；
- `table` 指定 BIRD 主表名；
- `interface_pattern` 匹配 XFRM tunnel 接口，默认 `phx*`。

Router-ID 由 `StableRouterID(localZone, rootTrust, netnsName)` 派生：

```text
Router-ID = uint32(first-4-bytes(hash(localZone, rootTrust, netnsName)))
```

- 同一节点不同 netns 必须有不同 Router-ID；
- 不同节点因 `localZone` 不同，Router-ID 也不同；
- path netns 必须在配置中显式给出 `router_id_label`，否则没有稳定名称。

### 5.2 Reconcile 流程

`reconcileRouting()` 由 daemon 在 state/config/transport 变化和周期性 safety sweep 时调度：

1. 从 committed snapshot 建立 `AuthorizedRouteSet`。
2. 按 `ipam.announce` 选择器维护本节点自动 announcement；有变更时重读 snapshot。
3. 过滤未启用或 `mode: disabled` 的实例，再为其余 routing instance 计算 Router-ID、接口 pattern、static route 和 import/export set。
4. 可选地确保 upstream veth 与 external 路由存在。
5. 生成配置，并按 `managed` / `external` 模式管理或观测 BIRD。
6. 将 BIRD process、协议、邻居和路由观测提交回本机 state，供 health 和 observer 使用。

### 5.3 三个前缀集合

| 集合 | 来源 | BIRD 用途 |
|---|---|---|
| Import set | 全网已授权 announcement + assignment 范围 | 限制从 Babel 接收的 prefix |
| Export set，非 transit | 本 Zone 已授权 announcement | 只发布本机声明的路由 |
| Export set，transit | 全网已授权 announcement，再过 `allow_prefixes` / `deny_prefixes` | 允许中继节点继续传播的范围 |
| Local static route | `assigned_to == managed_zone` 的有效 assignment | 让 BIRD 知道本节点拥有的前缀；无 upstream 时为 blackhole |

Import filter 不验证“这个 Babel 邻居正是 announcement 的 owner”。Babel 是多跳协议：A 从 B 学到 C 的路由时，B 是直接邻居而不是原始 owner。当前防护是 signed control-plane 给出可接受范围，未来控制面交叉审计会利用 `routing/netns` + Router-ID 做来源校验。

### 5.4 前缀长度策略

即使 announcement 是 exact prefix，BIRD filter 也会接受它的一段更具体范围：

| 地址族 | 对 announcement `/n` 接受的范围 |
|---|---|
| IPv4 | `max(n, /18)` 到 `/28`；`n > /28` 时只接受 exact |
| IPv6 | `max(n, /48)` 到 `/96`；`n > /96` 时只接受 exact |

这是数据面 prefix-length policy，不表示每一个 learned 更具体路由都有一条 exact signed announcement。filter 同时会 reject default route 和 bogon。

### 5.5 安全模型与交叉审计

| 防护层 | 机制 | 多跳兼容 |
|---|---|---|
| Export filter | 诚实节点只发布本节点 `AuthorizedRouteSet` 中的前缀 | ✅ |
| 全局 import filter | 拒绝未授权前缀范围与 default route、bogon | ✅ |
| Zone 签名链 | 保证 IPAM / announcement record 真实性 | ✅ |
| 控制面交叉审计 | daemon 定期从 `birdc show route all` 读取路由，通过 Router-ID + `routing/netns` 反推 zone，验证前缀权限 | ✅ |
| BIRD per-peer / Router-ID filter | 当前 BIRD 2.x filter 语言未暴露 `babel_router_id`，实时来源验证不可行 | — |

直接 per-peer import filter 不可行的根本原因是 Babel 的距离向量传播：A 从 B 学到 C 的路由时，B 只是转发者，filter 若按 B 的权限拒绝就会破坏全网可达性。因此 Phase 5.7 之后的安全模型保持为：BIRD 负责边界过滤，Photon daemon 负责来源审计。

---

## 6. veth upstream：把 mesh 接到 host

### 6.1 何时需要 upstream

overlay 与 BIRD 通常位于独立 mesh netns，例如 `photon`。host 上的容器、服务进程或另一个 namespace 若要访问 mesh 前缀，就需要一个明确的出入口。`routing.instances[].upstream` 用一对 veth 连接两个网络边界：

```text
host / external netns                         mesh netns (photon)
─────────────────────                         ───────────────
services / containers                         BIRD + Babel + overlay tunnels
       │                                                  │
 phv2mesh  ───────────── veth pair ─────────────  phv2host
       │                                                  │
external kernel routes                           BIRD static / Babel interface
```

它不是另一条 overlay，不进入 gossip，也不改变 IPAM 授权；它只是本机或相邻 namespace 的数据面接入点。

### 6.2 配置示例

```yaml
routing:
  instances:
    - id: main
      netns: default
      provider: bird
      mode: managed
      interface_pattern: phx*
      upstream:
        mode: static
        create_veth: true
        mesh:
          interface: phv2host
          ipv4_ll: 169.254.254.1/30
          ipv6_ll: fe80::a1:1/64
        external:
          interface: phv2mesh
          # netns: ""        # 省略/空 = init host netns
          ipv4_ll: 169.254.254.2/30
          ipv6_ll: fe80::a1:2/64
```

默认值：

| 字段 | 默认值 |
|---|---|
| `mesh.interface` | `phv2host` |
| `external.interface` | `phv2mesh` |
| `mesh.ipv4_ll` / `external.ipv4_ll` | `169.254.254.1/30` / `169.254.254.2/30` |
| `mesh.ipv6_ll` / `external.ipv6_ll` | `fe80::a1:1/64` / `fe80::a1:2/64` |
| `create_veth` | `true` |
| `mode` | `static` |
| `install_source_addresses` | static 模式为 `true`；external 模式为 `false` |

`external.netns` 可引用另一个 namespace；省略/空表示 init/main host netns。`create_veth: false` 时 Photon 仍按配置使用该接口，但管理员必须保证 veth、地址、up 状态与两端 namespace 已准备好。

接口名前缀按资源角色分离：`phx*` 为 StrongSwan/XFRM，`phw*` 为 WireGuard device，`phg*` 为 WireGuard 路径上的 GRE/Babel interface，`phv*` 为 veth。这样 tunnel 的通配规则不会误匹配 upstream veth。所有名字必须满足 Linux 15 字符限制。

### 6.3 `static` 模式

默认模式。Photon 会：

1. 在 `create_veth: true` 时创建或修复 veth pair、配置两端 link-local 地址并启用接口 forwarding；
2. 让 mesh 内 BIRD 在 routing 配置给出的精确 upstream 接口（默认 `phv2host`）上运行 Babel；此接口不使用 mesh tunnel 的 `type wireless` ETX/RTT 配置；
3. 对本机 `assigned_to == managed_zone` 的前缀，在 mesh 内生成 BIRD static route，下一跳为 external 端对应地址族的 link-local，并用 `mesh.interface` 固定出口；
4. 在 external 一侧为已授权的远端 announcement 写 kernel static route，下一跳为 mesh 端 link-local 地址，并排除本机自己持有的 assignment；
5. 在 external 接口上配置本机非 shared assignment 的首个可用地址，供这些回程路由选择 source address；shared/Anycast assignment 只保留为服务路由，不配置到 veth。

`static` 的 BIRD static route 表示“本机拥有该前缀且其实际承载在 external 一侧”，不等于扩大 BIRD export 权限。一个前缀仍须有有效 announcement 才会被 export。

### 6.4 `external` 模式

`external` 模式让 Photon 保留 mesh 侧的 BIRD/Babel veth interface，但不生成本机 static route，也不在 external 一侧写 kernel route。它适合 host 或另一个 namespace 已由管理员运行 BIRD/FRR/babeld，或有自定义策略路由的场景。路由、转发和 firewall 都由管理员负责。

external 模式可显式设置 `install_source_addresses: true`，让 Photon 在自己管理的 external veth endpoint 上安装从本节点非 shared assignment 派生的源地址。shared/Anycast assignment 不会安装到 veth。地址保留 assignment 的 prefix length，因此会在 external endpoint 上生成对应的 connected route；管理员必须移除其他接口上冲突的 connected prefix。该选项不会添加远端业务静态路由，也不会接管 external 路由守护进程。

### 6.5 边界

- 业务 prefix 仍由 IPAM + announcement 决定；veth 不会让 host 自动获得未授权前缀。
- `transit: false` 只禁止 mesh overlay 间中继，不等于关闭 host ↔ mesh 的 veth 接入。
- host 侧 Docker connected route 与更宽的 host → mesh route 会按最长前缀匹配；服务子网应避开与本地 connected subnet 的意外重叠。
- `external` 模式不是“自动接入 host”的简写：它只交出接口，必须由外部路由守护进程或管理员完成数据面。

---

## 7. 自动宣告、CLI 与诊断

### 7.1 自动 announcement

```yaml
ipam:
  announce:
    - non-shared
    # - tag:edge.c
```

选择器只挑选 `assigned_to == managed_zone` 的有效 assignment：`all`、`non-shared`、`shared`、`tag:<tag>`、`assignment:<CIDR>`。

- selector 模式写入 `controller: auto`，只撤回自己创建的 announcement；手动或 service 控制的 record 不会被 selector 撤回。
- `auto_announce_assigned_ips: true` 仍兼容，但会管理本 Zone 的全部 announcement，适合旧配置，不建议新部署使用，且不能与 `ipam.announce` 同时出现。
- shared service Anycast 通常由服务生命周期决定，除非该 group 确实需要长期静态宣告，否则不应放进通用 selector。

### 7.2 常用 CLI

```bash
# IPAM 管理
photon route ipam pool create <zone> <prefix> --delegated-to <zone>
photon route ipam assign <zone> <prefix> --to <zone> [--shared --tag <tag>]
photon route ipam revoke assignment <zone> <prefix> [--to <zone>]
photon route ipam revoke pool <zone> <prefix>

# Route 管理
photon route
photon route announce <zone> <prefix>
photon route withdraw <zone> <prefix>

# 诊断
photon route ipam get <addr-or-prefix>
photon route ipam mine
photon-admin route ipam assigned
photon debug routing status
photon debug routing routes
photon debug routing routes <prefix>
photon debug routing bird status
photon debug routing bird interface
photon debug routing bird filter
photon debug routing bird route
photon debug routing ip route
photon debug routing reload
```

`photon route` 的 announcement 表会显示授权它的 assignment Tag，并按规范化 IP
prefix 排序；相同 prefix 再按 zone 排序。`photon-admin route ipam assigned` 也使用
prefix、assigned zone 的排序优先级。Observer 的 route、IPAM 和授权错误视图采用相同顺序，
并显示 route/assignment Tag。CLI 和 Observer 表格中的 zone 语义列统一右对齐，便于比较
不同层级的 Zone 名称。

`routing routes` 以 gossip 中的 route announcement 和 IPAM 授权记录为主，并在 daemon 在线时附带
BIRD RIB 交叉视图；它不是 netns 的内核路由表。`routing bird route` 只查询 BIRD 中由 Babel
学习到的路由；`routing ip route` 查询 routing instance 所在 netns 的实际内核 FIB，默认同时
显示 IPv4 和 IPv6，可用 `--netns` 和 `--family` 筛选。

所有写操作在 daemon 运行时通过 control socket 提交，由 daemon 单 writer 落盘。离线/无 daemon 时 CLI 直接写本地 DB，但不应与 daemon 并发运行。

### 7.3 排障顺序

优先按以下顺序：

1. assignment / announcement 是否在 `AuthorizedRouteSet`（`photon debug routing routes`）。
2. tunnel 或 veth 接口是否 up、地址是否正确。
3. BIRD 邻居是否建立（`show babel neighbors`）。
4. 内核路由是否安装（`show route all`、`ip route`）。

BIRD 正常不代表前缀已获授权；record 已获授权也不代表本机数据面已经起来。

---

## 8. 实现边界

| 行为 | 位置 |
|---|---|
| record schema、canonical key | `pkg/routing/records.go` |
| pool / assignment / route authorization | `pkg/routing/authorization.go` |
| record type capability 验证 | `pkg/crypto/sign.go` |
| CLI IPAM / route 写入 | `app/photon/ipam.go`、`app/photon/route.go` |
| routing reconcile、auto announcement、external routes | `app/photon/routing_reconcile.go`、`app/photon/routing_upstream_routes.go` |
| BIRD config、filter、process、veth | `pkg/routing/bird/` |
| Router-ID 派生 | `pkg/routing/bird/routerid.go` |
| BIRD 版本预检 | `pkg/routing/bird/preflight.go` |
| `routing/netns` record 发布 | `app/photon/routing_reconcile.go` |

旧的 Phase 设计文档已被本文替代；若发现实现与本文不一致，优先修实现，再更新本文。
