# `app/photon` 非测试文件与数据模型审计

> 审计时间：2026-09-12
> 审计范围：`app/photon` 目录下全部 72 个非测试 `.go` 文件，共约 1.87 万行生产代码。
> 审计基线：`windows` 分支当前工作树（HEAD `7ac417cfba0f`，包含审计时尚未提交的本地修改）。
> 本文把问题中的“DTU”按“DTO（只负责在层与层之间传数据的结构体）”理解。

## 1. 先说结论

`app/photon` 现在不是 72 个独立模块，而是同一个 `package main` 被拆成了 72 个文件。Go 编译以后不会保留这种“文件边界”，所以文件多本身既不会多占运行时内存，也不能据此判断过度设计。真正的问题是：这个 executable 层仍然同时承担 CLI、Unix control、Daemon 调度、配置解析、IPsec/routing/firewall policy、Linux 执行装配、状态投影和文本输出，职责过多。

本轮审计的总判断如下：

1. `State`、`LinuxState`、`linuxObservation` 三层都必要，不是同一份数据无意义地复制。
   - `State.Common` 保存全网可验证事实和 gossip 重启提示；
   - `LinuxState` 目前只保存无法重建的 IPsec 私钥和动态 Endpoint ACL；
   - `linuxObservation` 只保存本次进程观察到的 SA、link、BIRD 和 firewall 现状，重启后应清空重建。
2. `State.ReadLinux()` 和 `linuxObservation.*Snapshot()` 的 clone 也有必要。它们防止调用方绕过 owner 原地修改共享 map/slice，并隔离 Daemon 写入与 control/HTTP 并发读取。这里的复制是并发和所有权成本，不是装饰性 DTO。
3. IPsec 在线诊断链原有的二次换壳已收敛。当前是：

   ```text
   ipsec 原生结果
     -> internal/state 的四组 secret-free *Observation
     -> app/photon 的 ipsecObservationSummary（持锁、clone 的一致快照）
     -> internal/inspect 的同名 alias
     -> control JSON / HTTP JSON / CLI 文本
   ```

   `TransportLinkSpec` 和 `ReconcileAction` 可能携带私钥或带私钥的 spec 指针，因此第一次“脱敏投影”继续保留；inspect 不再维护第二套同字段 struct 和逐字段 builder。原先 debug rotate 独立 SA copier 漏掉的 `UniqueID`、`Initiator`、`InitiatorKnown` 也已随共享投影修复。
4. 剩余复制是按 link/SA 数量线性复制 detached observation，用于 Daemon 写与 control/HTTP 并发读取之间的隔离；相对于 VICI、BIRD、netlink、nftables 和磁盘事务通常很小。没有 benchmark 或 profile 证据前，不应为了省这点内存改成共享可变对象或无锁结构。
5. `controlRequest -> daemonEvent -> corestate.LocalIntent` 也偏长。control wire DTO 必须存在，Daemon 串行排序也必须存在；但 IPAM、route、service、record 各自的 request 再塞进一个 20 多种事件共用的“大联合体”，然后才转成 `LocalIntent`，中间层可以继续收缩。
6. 最明确的临时冗余是 legacy schema：`stateFile`、`stateMeta`、`PeerRuntimeState` 及两组 migration 文件只为旧数据库单向升级存在。它们现在有理由保留，但必须绑定明确的兼容截止版本；否则会永久成为第二套“假现行模型”。

## 2. 用人话看整个目录

Photon daemon 可以理解为一个值班调度员：

```text
config.yaml
  -> 解析成 appConfig
  -> 组装 GossipDriver、LinuxDriver、health、observer

CLI / Unix control 请求
  -> Daemon 排队，保证修改顺序
  -> Common Store 或 LinuxState 提交
  -> 触发 IPsec -> routing -> firewall 等收敛

VerifiedState + LinuxState + 操作系统现状
  -> Observe / Plan / Apply
  -> linuxObservation（仅内存）
  -> inspect canonical view
  -> CLI 文本、control JSON、Observer HTTP JSON
```

最重要的边界不是“文件放在哪”，而是谁有权修改什么：

| 数据 | 人话解释 | 是否落盘 | 正确 owner |
|---|---|---:|---|
| `VerifiedState` | 已验证、能代表全网事实的 Zone/record/authority 数据 | 是 | `pkg/core/state.Store` |
| `GossipCheckpoint` | 下次启动可以利用、丢了也能重新同步的提示 | 是 | `pkg/core/state.Store` |
| `LinuxState` | 本机无法从别处重建、又必须跨重启保留的数据 | 是 | `app/photon.State` 的 Linux 分区 |
| `linuxObservation` | 当前进程亲眼看到的 Linux/BIRD/StrongSwan/firewall 状态 | 否 | 在线 `Daemon` |
| `inspect.*View` | 给人和 API 看的解释结果 | 否 | `internal/inspect` |
| YAML/control/join DTO | 跨文件、跨进程或跨机器传输的格式 | 视边界而定 | 相应 adapter |

不要为了“少几个 struct”把上表重新并成一个大状态。那会再次造成磁盘旧快照冒充实时状态、展示字段参与控制决策、或者操作系统状态被错误持久化。

## 3. 主要 struct 和类型到底干什么

### `Daemon`

顶层生命周期和写入顺序 owner。它持有 `State`、`GossipDriver`、`LinuxDriver`、health、observer、timer、事件队列和各 reconcile 的 dirty 标记。这个对象有存在必要；问题是 `daemon.go` 还混入了完整 control method dispatch 和大量业务 handler，文件已经超过 2000 行。

### `AppContext`

一次 CLI/daemon 启动所需的应用上下文，只含解析后的配置、state 路径、clock 和是否禁用 control。它不是第二个 runtime，也不拥有 goroutine、Driver 或数据库。这个小对象合理。

### `State`

一个进程只建一个。它持有唯一 bbolt handle、公共 `Common` Store 和带锁的 `LinuxState`。`ReplaceIPsecTransportKeyIfRevision`、`ReplaceEndpointACLsIfRevision` 会检查规划时使用的 verified revision，防止旧计算结果覆盖新网络事实。它不是无意义 wrapper；它解决的是“一个 DB 句柄、两个语义不同的分区、同一 revision 防陈旧提交”。

### `LinuxState`

虽然定义在 `internal/photonlinux`，却是理解本目录的关键。它现在只有：

- `IPsecTransportKey`：本机 IPsec transport 私钥，没有其他来源，必须跨重启保持；
- `EndpointACLs`：通过 control/CLI 动态配置的本机意图，不在 gossip 和系统现状中，产品语义要求重启后仍存在。

这已经是收缩后的最小模型，不建议因为只有两个字段就删掉。字段少恰恰说明边界变干净了。

### `linuxObservation`、`ipsecObservationSummary`、`routingObservation`

它们是在线只读快照：link/SA、最近一次 IPsec 计划和动作、BIRD 实例、firewall observation、错误与时间。锁和 clone 是为了并发安全；重启后清空是为了不拿旧数据冒充 live。

其中 `ipsecObservationSummary` 使用四组 canonical `internal/state` live DTO：reconcile 边界负责“去私钥、去 Driver 细节”，inspect 直接 alias，不再做第二套同字段 struct。对应测试会把 transport 私钥和带 spec 指针的 action 放入输入，验证 observation 序列化结果不含敏感材料。

### `appConfig` 与各种 `*YAML`

`*YAML` 表示“用户写了什么”，大量 `*bool`、字符串 duration 和别名字段用来区分“没写”“写 false”“旧字段名”；`appConfig` 表示“解析、默认化、校验以后程序真正采用什么”。这次转换是配置边界，不是无意义内存搬运。

真正的问题是所有子系统配置都堆在 `config.go` 和 app package。等各子系统接口稳定后，应把 firewall/routing/IPsec/health 的 YAML 与 effective config 下沉到实际 owner；不要再造第三套总配置 DTO。

### `controlRequest`、`controlResponse`、`controlViewResponse[T]`

这是 Unix socket 的 wire schema。读请求统一返回 canonical inspect view，这个方向正确。`controlRequest` 目前是一个能装下所有 method 字段的大 struct，允许许多理论上无效的字段组合；`controlResponse` 也混合多种命令结果。短期可保留协议兼容，Windows named-pipe 接入前应加显式版本并按 method 收紧 payload，而不是继续向大 struct 加字段。

### `daemonEvent`、`daemonEventResult`

这是 Daemon 单 writer 队列里的内部联合体。事件队列本身有价值：它让控制命令、timer、VICI wakeup 和状态变化按一个明确顺序执行。联合体已膨胀到 20 多种 event 和大量互斥字段，容易构造出 `Type` 与 payload 不匹配的无效状态。

不要用几十个新 interface/command class 替换它。更直接的减法是：在 control 边界先把 IPAM/route/service/record 转成 `corestate.LocalIntent`，让一个 common-mutation 事件携带 `LocalIntent + dryRun`；平台专用事件继续保留自己的明确字段。

### join、recovery 和 mutation DTO

- `privateKeyFile`、`joinRequest`、`joinBundle` 是真正会写文件、复制给另一台机器的协议 artifact，必须有稳定结构；
- `ipamMutationRequest`、`routeMutationRequest`、`serviceMutationRequest` 是 control wire payload，也有存在理由；
- `delegationIssueResult`、`joinAcceptResult`、`recordMutationResult` 只是进程内 handler 返回值，属于小型便利结构，可在调用链收缩时顺手减少，但不是优先问题。

### 子系统配置 struct

`FirewallInstanceConfig`、`RoutingInstance`、`UpstreamConfig`、`healthConfig`、`observerConfig` 都是默认化后的运行配置，功能真实、字段也确有消费者。问题主要是 owner 位置仍在 executable package，不是类型本身不该存在。

## 4. 逐文件说明和必要性审核

下面按文件名字母顺序列出全部 72 个非测试文件。

### 1. `admission_diagnostics.go`

- 做什么：根据 `VerifiedState`、`GossipCheckpoint`、bootstrap 列表和当前时间，解释自动加入网络为什么还在 pending、已经成功还是配置有问题，并输出 CLI 文本。
- 主要构成：没有自定义 struct；核心是 `diagnoseAutoJoinAdmission` 纯投影函数。
- 审核：功能必要，且不再持久化 admission 状态是正确的。纯诊断计算应继续下沉到 `internal/inspect`，app 最终只保留取数和打印壳。

### 2. `authority.go`

- 做什么：解析 authority permission/capability，给已有 delegation 增加权限，并生成 grant bundle；同时保留 daemon control 与 `--direct` 离线路径。
- 主要构成：没有自定义 struct，主要处理 `zone.Permission`、`zone.Capability` 和 `joinBundle`。
- 审核：权限变更能力必要。解析和状态 intent 应归 core state/zone，文件中的 CLI、control fallback 和文件输出属于 app/CLI adapter；当前职责混合但不是数据模型冗余。

### 3. `cmd.go`

- 做什么：建立整个 `photon` CLI 命令树、flag 和 action，把命令接到其他文件的函数。
- 主要构成：没有自定义 struct；由大量 `cmdXxx() *cli.Command` 组成。
- 审核：composition root 必须有命令注册，但 850 行说明 handler/flag 细节仍过多。命令壳稳定后可迁入 `internal/photoncli`；不要为了减少文件数先机械搬运。

### 4. `cmd_root_init.go`

- 做什么：初始化 root authority、生成 key，并一次性建立 current Common 与 Linux state 分区。
- 主要构成：没有自定义 struct；`initializeRootState` 是核心初始化事务入口。
- 审核：必要且安全敏感。它必须保证空库初始化原子性；可以下沉 CLI 文件操作，但不能拆成两个独立 DB 写入。

### 5. `config.go`

- 做什么：读取 YAML、设置默认值、兼容旧字段、校验并生成整个 Linux app 的有效配置。
- 主要构成：`appConfig`；`configYAML`；gossip/identity/log/IPsec/IPAM/overlay 的 effective config 与 `*YAML`；`syncConfigPeer`；`netnsRefYAML`；若干 duration、key、endpoint parser。
- 审核：YAML DTO 到 effective config 的转换必要，因为 omission、默认值和字符串解析不能混成一层。过重之处在于一个文件知道所有子系统；按真实 owner 下沉配置即可，不要新建第三套“统一配置模型”。

### 6. `context.go`

- 做什么：创建 `AppContext`，集中配置、state 路径、clock 和 control 开关。
- 主要构成：`AppContext`。
- 审核：必要、足够薄，不是 Runtime 的重复实现。可保留在 app。

### 7. `control.go`

- 做什么：定义 Unix control wire 请求/响应，寻找 socket，发送请求，处理 daemon 不在线 fallback，并为各命令提供 client helper。
- 主要构成：`controlRequest`、`controlResponse`、泛型 `controlViewResponse[T]`。
- 审核：跨进程 DTO 必要，读路径直接传 canonical inspect view 也是正确的。主要冗余是 fat request/response 与大量一行 wrapper；应在协议版本化时按 method 收紧，不建议现在再套 Repository 或 client facade。

### 8. `cpu_profile.go`

- 做什么：按指定时间运行 daemon CPU profile，安全创建文件并保证 `pprof.StopCPUProfile()` 收尾。
- 主要构成：`cpuProfileHooks`，用于测试替换 start/stop。
- 审核：功能独立且边界清楚。可留作小 helper，是否另建包对复杂度影响很小。

### 9. `daemon.go`

- 做什么：启动/关闭所有组件，运行顶层 select 循环，接 control 请求，排序 mutation，安排 timer，触发 IPsec/routing/firewall/health reconcile，并处理 reload、shutdown、join、recovery 等命令。
- 主要构成：`Daemon`、`DaemonHooks`、`daemonEventType`、`daemonEvent`、`daemonRecordPut`、`daemonEventResult`。
- 审核：Daemon 作为唯一生命周期和 mutation 编排者完全必要；2173 行文件本身过载。优先把 control method dispatch/response mapping 移回 control adapter，再收缩 common mutation event；完整的启动、关闭和安全顺序仍应留在 Daemon，不能拆成互相不知道顺序的 controller。

### 10. `daemon_common_intent.go`

- 做什么：把 IPAM、route、service control 请求转换成 `corestate.LocalIntent`。
- 主要构成：没有 struct；三个很薄的 converter。
- 审核：语义转换本身必要，但单独长期存在的迁移 adapter 价值有限。更理想是 control/direct 两个入口都尽早生成同一种 intent，然后复用一个提交路径；完成后此文件可以删除或并入边界 owner。

### 11. `daemon_gossip.go`

- 做什么：从 app config/verified identity 生成 `GossipDriverConfig`，刷新地址发现，计算 peer suppression，并把 host 日志接到 app logger。
- 主要构成：没有自定义 struct。
- 审核：composition adapter 必要且已经较薄。不要再增加一套 app 级 GossipRuntime DTO；其中纯 config builder 可逐步靠近 host/config owner。

### 12. `daemon_ipsec_cleanup.go`

- 做什么：处理在线 IPsec cleanup 命令，调用同一个 `LinuxDriver` 删除受管 link/orphan，并更新在线 observation。
- 主要构成：没有自定义 struct。
- 审核：清理顺序和 owner 校验必要。app 应保留命令编排，具体 connection/XFRM 删除已经由 LinuxDriver 承担；不要再建第二套 cleanup manager。

### 13. `daemon_sync.go`

- 做什么：连接 Daemon 与 `GossipDriver`，提供 object-pull server/executor，处理 sync timer、packet 和 host event 的最终结果。
- 主要构成：没有自定义 struct；主要是 adapter 方法。
- 审核：跨组件接线必要。gossip FSM、transport 排序和 checkpoint 更新应继续由 GossipDriver 自闭环；本文件不应重新长出协议实现。

### 14. `debug_cmd.go`

- 做什么：注册 `debug` 子命令，尤其是 routing/BIRD/ping 等诊断命令和 flag。
- 主要构成：没有自定义 struct。
- 审核：CLI 注册需要，但不应承载诊断推理。最终可与其他 CLI 注册一起进入 `internal/photoncli`。

### 15. `debug_db.go`

- 做什么：离线查看 bbolt bucket、metadata、Zone、record、Merkle、旧 sync peer 和原始字节，并输出 DB 统计。
- 主要构成：没有自定义 struct，包含大量 dump/format helper。
- 审核：运维价值真实，但 544 行同时理解 current 与 legacy schema。current common dump、Linux dump、legacy dump 应按 owner 分开；旧 schema 支持结束后应删掉 `dumpSyncPeers` 等旧模型代码。

### 16. `debug_endpoints.go`

- 做什么：通过 daemon control 读取已经发布的 endpoint canonical view 并打印。
- 主要构成：没有自定义 struct。
- 审核：功能必要、实现很薄。单独文件不是运行时负担；以后随 CLI 壳一起移动即可。

### 17. `debug_firewall.go`

- 做什么：读取 firewall online observation、按 host/netns 过滤、补充配置上下文，并输出 JSON 或文本。
- 主要构成：没有自定义 struct，使用 `inspect.FirewallDebugView` 和 `firewall.FirewallObservation`。
- 审核：诊断必要。`buildFirewallDebugView` 和格式化应归 canonical inspect/presenter；app 只选择在线 source。

### 18. `debug_format.go`

- 做什么：只有一个把空字符串显示成 `-` 的 `dash` helper。
- 主要构成：没有 struct。
- 审核：功能有用，但单独文件没有清晰 owner，是最明确的可合并文件之一。可并入 `internal/inspect/text` 或现有 CLI presenter，不需要保留专门文件。

### 19. `debug_links.go`

- 做什么：要求在线 daemon，读取 links canonical view，输出简表或详细 debug，并把 overlay 映射到 BIRD 状态。
- 主要构成：没有自定义 struct；`desiredByInstanceID` 为 observer 健康上下文建立索引。
- 审核：在线限制正确，不能用磁盘 snapshot 冒充 link 实况。BIRD/desired 上下文 builder 仍是 DTO 拼装，可继续归 `internal/inspect`。

### 20. `debug_peer.go`

- 做什么：读取单个 gossip peer 的 canonical debug view 并打印。
- 主要构成：没有自定义 struct。
- 审核：必要且很薄；以后归 CLI adapter。

### 21. `debug_peers.go`

- 做什么：读取 gossip peer 列表和 peer lifecycle 视图，把 verified、checkpoint、observation 和 link 状态组合起来。
- 主要构成：没有本地 struct，返回 `inspect.PeerLifecycleDebugView` / `PeerDebugView`。
- 审核：产品诊断必要。状态推理应继续在 inspect，app 中只保留 owner 取数；当前 `buildPeerLifecycleDebugView` 仍是组合 adapter，合理但可下沉 source builder。

### 22. `debug_ping.go`

- 做什么：从在线 daemon 取健康探测目标，按用户参数选择地址，然后调用 Linux health prober 执行 ping。
- 主要构成：没有 struct；`healthTargetsFromInspect` 把 inspect DTO 反向转回 `health.ProbeTarget`。
- 审核：ping 功能必要，但这是一处明确的“展示 DTO 反向变执行 DTO”。建议 control 返回专用、可执行但不含 Driver 的 probe target wire schema，或让 canonical target 成为共享类型，删除反向 parser。

### 23. `debug_revoke_impact.go`

- 做什么：在线查询某个 Zone 被 revoke 后会影响哪些 Zone、peer、link，并打印影响报告。
- 主要构成：没有自定义 struct。
- 审核：安全运维价值高且很薄；保留功能，CLI 壳后续移动。

### 24. `debug_rotate.go`

- 做什么：手动轮换 IPsec 端口，展示 rotation/SA 状态，生成新的 `PortRecord` 并支持 online/direct 两条路径。
- 主要构成：`manualPortRotateResult`。
- 审核：能力必要，但 command、plan、control result 和 presenter 混在一起。原有独立 SA copier 已删除，在线查询与 reconcile 现在共用同一 secret-free SA 投影。

### 25. `debug_routing.go`

- 做什么：执行和显示 routing reload、Babel、BIRD、route/单 prefix 诊断，并把 link output 作为接口上下文交给 canonical inspect enrichment。
- 主要构成：没有本地 struct。
- 审核：查询能力必要。当前把 BIRD 命令选择、raw 解析和 enrichment 下沉到 `pkg/routing/bird` / `internal/inspect` 的方向正确；app 应只保留在线执行、配置文件读取和 source 装配。

### 26. `debug_routing_ip.go`

- 做什么：根据 netns 配置生成 `ip -4/-6 route` 命令，在 host/name/path namespace 中执行并格式化原始输出。
- 主要构成：`routingIPCommandRunner` 函数类型，便于测试替换命令执行。
- 审核：真实 Linux 诊断能力必要，但属于 Linux routing adapter，不应永久留在通用 executable 层。可以下沉 `internal/photonlinux/routing`，CLI 只传参数。

### 27. `debug_zone_records.go`

- 做什么：读取 Zone/record，生成 canonical inspection，支持 history/value/json 输出。
- 主要构成：没有本地 struct。
- 审核：必要。view 已用 `internal/inspect`，剩余文件主要是 CLI source/presenter adapter，可继续变薄。

### 28. `endpoint_acl.go`

- 做什么：创建、删除、列出本机 Endpoint ACL；校验 selector；把 ACL 解析成 firewall endpoint service；经 revision guard 持久化并触发 firewall reconcile。
- 主要构成：使用共享 `photonstate.EndpointACL`，本文件不另定义 struct。
- 审核：ACL intent 必须持久化，不能从 nftables 规则反推原始 selector。文件混合 CLI、domain validation、resolution 和 Daemon handler；模型/校验/resolve 应靠近 firewall owner，app 保留 control 与提交顺序。

### 29. `firewall_config.go`

- 做什么：解析 firewall YAML，生成有效 `FirewallInstanceConfig` 和 `firewall.FirewallInstanceSpec`，处理 nft/iptables hook、端口、优先级和 listen address。
- 主要构成：`firewallConfig`、`FirewallInstanceConfig`、`firewallConfigYAML`、`firewallInstanceYAML`、`localServiceYAML`、`hostPortsYAML`、`redirectGraceYAML`、`priorityYAML`、`inlineHooksYAML`、`iptablesHooksYAML`。
- 审核：这些是实际产品配置，不是凭空设计；YAML/effective/spec 三个阶段各有含义。位置偏高，应整体下沉 Linux firewall config owner，避免 `appConfig` 了解所有字段细节。

### 30. `firewall_reconcile.go`

- 做什么：从 verified routes、Endpoint ACL、IPsec link/port 和配置生成 firewall policy，调用 LinuxDriver apply，并发布 `FirewallObservation`。
- 主要构成：没有本地 struct，直接使用 `firewall` 包的 policy/spec/observation。
- 审核：reconcile 必要，且直接复用 firewall 原生 observation，DTO 层数控制得比 IPsec 好。Daemon 保留顺序；policy builder 和 Linux apply 应继续下沉。

### 31. `forwarding_config.go`

- 做什么：解析每个 netns 的 transit/allow/deny/metric 策略，并过滤 authorized prefix。
- 主要构成：`forwardingYAML`。
- 审核：安全策略真实必要。它同时服务 routing/firewall，适合由 Linux netns/forwarding owner 维护；不建议再复制一份 routing policy 和 firewall policy。

### 32. `gossip_checkpoint_migration.go`

- 做什么：把旧 `PeerRuntimeState` 中仍有恢复价值的字段单向迁移成 `GossipCheckpoint`，坏的 loss-tolerant 项丢弃并计数。
- 主要构成：`legacyGossipCheckpointReport`。
- 审核：只在支持旧 DB 期间必要，当前“只读旧格式、不反向写”设计正确。必须设置删除门槛，并和 `legacy_state.go`、`runtime_state_migration.go`、旧 dump/fixture 同批删除。

### 33. `gossip_logging.go`

- 做什么：把 gossip event 转给 app structured logger，并按配置决定是否输出 debug。
- 主要构成：没有自定义 struct。
- 审核：必要的 logging adapter，足够薄；可以留在 composition 边界。

### 34. `health_config.go`

- 做什么：解析 probe 周期、timeout、burst、并发、loss/hysteresis、remote write 和本地 spool 配置，生成 health/spool 原生 config。
- 主要构成：`healthConfig`、`healthConfigYAML`、`healthMetricsYAML`。
- 审核：配置分层合理；字段多来自真实能力。可随 Linux health composition 下沉，但没有必要把 effective config 再拆成更多 DTO。

### 35. `health_reconcile.go`

- 做什么：创建 health manager，按 link output 更新 probe target，消费异步结果、写 spool，生成 health canonical view，并提供 CLI 展示。
- 主要构成：`healthDriver`，组合 `*health.Manager`、spool 和两个生命周期标志。
- 审核：health 是可选在线子系统，wrapper 有真实生命周期职责。文件仍混合 lifecycle、observation adapter 和 CLI；应拆 owner，不应删除 manager 或把健康结果塞进持久 State。

### 36. `identity_bootstrap.go`

- 做什么：从配置加载 identity key，校验它与 verified state 一致，为空库建立 pending auto-join 状态，生成 join request，并记录 pending 日志。
- 主要构成：没有本地 struct，复用 `privateKeyFile`、`joinRequest` 和 Common/Linux state。
- 审核：安全启动链必要。`IdentityKeyPath` 留在配置而不复制进 LinuxState 是正确减法；继续保持“同公钥可移动路径、换密钥拒绝”。

### 37. `inspect_links.go`

- 做什么：把 daemon 的 IPsec link/observation、BIRD 和 health 数据拼成 `inspect.LinksDebugView`。
- 主要构成：没有本地 struct；直接把 detached canonical observation 交给 inspect，并补 BIRD/health 上下文。
- 审核：组合入口必要；原有四个 `photonstate.* -> inspect.*` 批量转换 helper 已删除，第一次安全脱敏仍留在 reconcile 边界。

### 38. `inspect_peers.go`

- 做什么：把 GossipDriver config 和 observability snapshots 组装成 `inspect.GossipPeersOptions`。
- 主要构成：没有 struct，只有一个小 builder。
- 审核：功能合理但文件很薄。可并入 daemon_gossip/inspect source adapter；是否保留独立文件不影响运行时。

### 39. `ipam.go`

- 做什么：注册 IPAM CLI，创建/撤销 pool 和 assignment，支持 online/direct mutation，生成 list/mine/get 报告并打印。
- 主要构成：`ipamMutationRequest` wire DTO。
- 审核：功能必要，但 785 行把 CLI、control DTO、intent、read model adapter 和 presenter 放在一起。核心授权/分配已在 routing/state，报告已在 inspect；app 应最终只剩参数解析、source 选择和 intent 提交。

### 40. `ipsec_publish.go`

- 做什么：生成/复用本机 transport key，构造 IPsec key/address/port/profile/overlay records，把它们变成公共 `LocalIntent` 发布计划。
- 主要构成：`localIPsecPublishPlan`、`localIPsecRecord`。
- 审核：功能和私钥先落盘逻辑都必要。两个小 plan struct 是局部组织数据，不算过度设计；但 761 行协议 policy 应逐步靠近 `pkg/transport/ipsec` 与 state publisher，app 只编排发布顺序。

### 41. `ipsec_reconcile.go`

- 做什么：从 verified records/config/旧 observation 规划 desired links，注入本机和对端 key，调用 LinuxDriver observe/apply，处理 DNS、rotation/takeover/backoff/revoke，最后发布在线 observation。
- 主要构成：`ipLookupResolver` 小接口；大量 planner/summary/helper。
- 审核：这是必要但过重的核心实现。小 resolver 接口有两个真实实现（系统 resolver 与测试替身），合理。最应清理的是 reconcile 结果到 `photonstate` 再到 inspect 的重复投影；Linux I/O 和纯 policy 应分别归 driver 与 transport planner，Daemon 保留完整顺序。

### 42. `join.go`

- 做什么：生成 join request，签发/revoke delegation，接受 bundle，校验 key/root/authority，并裁出接受方所需的最小 Network proof。
- 主要构成：`privateKeyFile`、`joinRequest`、`joinBundle`、`delegationIssueResult`、`joinAcceptResult`。
- 审核：前三个是跨机器 artifact，明确必要；两个 result 只是内部便利结构，优先级很低。文件同时含 CLI、wire codec、验证和 state mutation，可按边界拆，但不能削弱 bundle proof 验证。

### 43. `keygen.go`

- 做什么：生成 Ed25519 keypair 并以规定权限写入 key 文件。
- 主要构成：没有 struct。
- 审核：必要、很薄，适合 CLI helper；没有设计问题。

### 44. `legacy_state.go`

- 做什么：只描述已经退役的 aggregate DB schema，供单向 migration 和 legacy dump 解码。
- 主要构成：`stateFile`、`stateMeta`。
- 审核：这是有意保留的重复模型，而不是 current owner。兼容期内必要，兼容截止后必须整文件删除；任何 current 写路径重新使用它都应视为回退。

### 45. `link_outputs.go`

- 做什么：把 provider-owned `ipsec.LinkInstance` 和最近 desired 摘要投影成 health、routing、firewall、inspect 都能消费的精简 `LinkOutput`；显式去掉 owner、SA 名、rotation action 等控制细节。
- 主要构成：本文件无 struct，使用 `photonstate.LinkOutput` / `LinkReadiness`。
- 审核：这不是纯展示 DTO，已经有 health、routing、firewall 等多个真实消费者，保留一个窄 contract 有意义。它现在直接消费 canonical `DesiredLinkObservation`；不要让下游拿完整 IPsec Driver 对象。

### 46. `linux_observation.go`

- 做什么：用一个锁保存和复制当前 IPsec、routing/BIRD、firewall 在线快照。
- 主要构成：`linuxObservation`、`ipsecObservationSummary`、`routingObservation`。
- 审核：层本身必要，且绝不能落盘。clone 是并发隔离，不建议无 profile 依据改为共享可变指针；应收缩其中的 DTO 类型，并可考虑按 subsystem snapshot 分开 owner，前提是不新增 ObservationStore。

### 47. `logging.go`

- 做什么：实现 text/json、stderr/file/syslog 输出，稳定排序字段、格式化值，并限制重复日志。
- 主要构成：`logLevel`、`logMode`、`appLogger`、`repeatedLogLimiter`、`repeatedLogEntry`。
- 审核：功能必要，repeated limiter 也有实际防刷屏价值。它是 Linux app adapter，可下沉通用 logging 包，但不是主要复杂度来源。

### 48. `main.go`

- 做什么：建立 signal context，运行根命令，并把错误转成 stderr 和退出码。
- 主要构成：没有 struct。
- 审核：必须永久留在 executable，当前足够薄。

### 49. `network_state.go`

- 做什么：给 `zone.NetworkState` 安装 crypto 验证函数，并做 current state normalize。
- 主要构成：没有 struct。
- 审核：验证配置必要；如果只有 state loader/intent 使用，应最终归 `pkg/core/state`/zone 的构造边界，避免 app 中存在“记得手工 configure”的隐性前置条件。

### 50. `observer_config.go`

- 做什么：解析 observer 是否启用、监听地址、端口、UI 路径和 event buffer，检查是否只绑定 loopback。
- 主要构成：`observerConfig`、`observerConfigYAML`。
- 审核：必要且边界清楚。effective/YAML 两层合理；可随 observer composition 下沉。

### 51. `observer_server.go`

- 做什么：启动 HTTP/SSE observer，把 State、linuxObservation、health spool、BIRD 等 owner 数据组装成 status/zones/peers/links/health/routes 页面和 metrics。
- 主要构成：`observerServer`、`observerProvider`。
- 审核：server lifecycle 和 provider 必要。467 行 provider 与 control dispatch 有重复取数/组 view 逻辑；两者应调用同一 canonical source builder，而不是各自产生 HTTP DTO。不要让 observer 直接变成第二个 state owner。

### 52. `peer_lifecycle_cleanup.go`

- 做什么：从 gossip checkpoint 的最后活动时间判断 peer 是否 stale/offline/需要 cleanup，并生成 suppression 集合。
- 主要构成：没有 struct，都是纯 policy 函数。
- 审核：策略必要，但不依赖 app lifecycle，适合下沉 host/inspect policy。不要重新持久化 `PeerCleanups` tombstone；现在从 checkpoint 推导更简单。

### 53. `peer_state.go`

- 做什么：把 Network、checkpoint、IPsec links 和 observation 拼成 peer lifecycle input/status，并收集 revoked peer。
- 主要构成：没有本地 struct，使用 `inspect.PeerLifecycleInput`。
- 审核：功能必要，属于 read model/policy adapter。可以继续下沉，尤其避免 app 再维护与 inspect 重复的 peer status 结构。

### 54. `protocol_publish.go`

- 做什么：保证本机私有 transport key 先成功写进 LinuxState，再发布引用它的公共 IPsec records；并用 verified revision 拒绝陈旧计划。
- 主要构成：`protocolPublishResult`。
- 审核：这是关键一致性边界，文件虽小但必须保留语义。不能为了少一次调用把私钥和公共 record 反序写入；result struct 很小，可留。

### 55. `record.go`

- 做什么：校验通用 record 写入，支持 online/direct put/get/debug，并把 Network record 转成 canonical detail view。
- 主要构成：`recordMutationResult`。
- 审核：能力必要。generic record 是高级入口，校验不能省；CLI/control/view 混合可继续拆。result 只是内部便捷返回，不是内存问题。

### 56. `recovery.go`

- 做什么：注册 recovery CLI，export/import Zone snapshot，从指定 peer object-pull 一个 Zone 或整条 chain，以及预览/执行 revoked purge。
- 主要构成：没有本地 struct，使用 `corestate.ZoneSnapshot`、`ApplyResult` 和 `purgePlan`。
- 审核：灾难恢复功能必要且应保持显式命令。pull、state mutation 和 CLI 输出可分 owner，但不建议做自动后台 recovery 或额外持久队列。

### 57. `recovery_ipsec.go`

- 做什么：为 IPsec cleanup 提供 online control 路径和 daemon 停止时的 direct 路径；direct 模式临时创建同一种 LinuxDriver。
- 主要构成：没有 struct。
- 审核：在线/离线两条路径有真实运维用途。必须继续复用唯一 cleanup 实现；不要再复制一套 orphan 删除算法。

### 58. `revocation_cleanup.go`

- 做什么：计算 revoke 对 Zone subtree、gossip peer、IPsec link 的影响，合并 Common purge plan 与平台 link cleanup，并生成全局影响列表。
- 主要构成：`purgePlan`。
- 审核：deny-first 安全语义必要。纯 impact/view、Common purge 和平台 apply 三种职责应分开；`purgePlan` 是跨 control 的结果契约，当前合理。

### 59. `root.go`

- 做什么：在线或离线读取并打印 root public key。
- 主要构成：没有 struct。
- 审核：必要且很薄；归 CLI adapter 即可。

### 60. `route.go`

- 做什么：announce/withdraw route，支持 online/direct mutation，从 authorized route set 生成 show 报告并输出表格。
- 主要构成：`routeMutationRequest`。
- 审核：功能必要。和 IPAM 一样混合 wire、intent、read model adapter 和 presenter；可缩成 CLI + control boundary，route 授权语义继续留 routing/state。

### 61. `routing_config.go`

- 做什么：解析 netns、BIRD/Babel instance、upstream veth/静态路由、metric、socket/PID/config 路径等配置。
- 主要构成：`netnsConfig`、`netnsConfigYAML`、`netnsSpecYAML`、`routingConfig`、`RoutingInstance`、`UpstreamConfig`、`routingInstancesYAML`、`routingInstanceYAML`、`upstreamConfigYAML`、`upstreamEndpointYAML`。
- 审核：配置真实且复杂，YAML/effective 分层必要；但它明显属于 Linux routing owner。路径、RouterID、owner 等可推导值不应再进入持久 State。

### 62. `routing_reconcile.go`

- 做什么：按 netns 聚合 overlay，建立 authorized route set，生成 BIRD spec，管理 BIRD 生命周期/upstream，观察 Babel 健康，计算 auto-announce，并发布 routing observation。
- 主要构成：`netnsOverlayGroup`、`autoAnnouncePlan`。
- 审核：功能必要，但 1100 多行表明 policy、Linux process control、health adapter、debug query 和 public record intent 仍耦合。应按纯 plan、Linux apply/observe、Daemon sequencing 分层下沉；两个局部 plan struct 有真实组织作用，不是主要冗余。

### 63. `runtime_state_migration.go`

- 做什么：在一个 bbolt 写事务里检测旧 schema、投影 Common/Linux 新分区、删除旧 bucket，并拒绝新旧 schema 同时存在。
- 主要构成：`legacyStateMigrationReport`。
- 审核：兼容期必要，原子迁移和冲突拒绝都正确。停止支持旧 DB 后应整文件删除，而不是保留成“备用 loader”。

### 64. `service.go`

- 做什么：显示服务、解析 SOCKS5 endpoint flags、发布或撤销 SOCKS5 record，并支持 online/direct mutation。
- 主要构成：`serviceMutationRequest`。
- 审核：功能必要，文件规模尚小。request 是 wire DTO；转换成 `LocalIntent` 后不应再有额外 service runtime model。

### 65. `share.go`

- 做什么：Base64 JSON 编解码和权限明确的 JSON 文件读写，供 join/key/recovery artifact 使用。
- 主要构成：没有 struct。
- 审核：这是 CLI 文件格式 adapter，必要且通用。可移入 `internal/photoncli/encoding`，但当前没有过度抽象。

### 66. `state.go`

- 做什么：拥有唯一 bbolt handle、Common Store 和 LinuxState；提供 detached read 和两个按 verified revision 提交的 Linux typed mutation。
- 主要构成：`State`。
- 审核：强烈建议保留。它不是 Repository/aggregate snapshot；API 已很小。`reflect.DeepEqual` 只比较两个字段，未来可换显式 equal，但不是优先问题。

### 67. `state_bolt.go`

- 做什么：打开 DB、执行旧 schema 单向迁移、同一事务加载 Common/Linux 两个分区、恢复 `State`，并支持 direct/offline intent 与只读 snapshot。
- 主要构成：没有自定义 struct。
- 审核：composition 和崩溃一致性边界必要。离线读取返回 detached owners 是正确的；不要暴露裸 tx/bucket 给 CLI。legacy 分支删除后本文件可以明显缩短。

### 68. `status.go`

- 做什么：组合 Common、IPsec links、BIRD、health 和 daemon online 状态，生成并打印总览。
- 主要构成：没有本地 struct，使用 `inspect.StatusView` / `DaemonStatusView`。
- 审核：必要。canonical view 方向正确；source 组合可与 observer/control 共用，避免三处分别拼字段。

### 69. `sync.go`

- 做什么：实现 `sync status/serve/once` 命令的 composition，建立 gossip transport config，计算 endpoint publish intent、bootstrap 地址和同步 limits。
- 主要构成：`SyncTransportDeps`、`syncPendingZonesError`。
- 审核：单次/常驻同步入口必要。协议 FSM 已下沉 GossipDriver，这是正确边界；`SyncTransportDeps` 只在本文件使用，主要服务测试注入，后续可直接用 GossipDriver config builder 收缩，但无需急删。

### 70. `verify.go`

- 做什么：在线优先、离线 fallback 地验证指定 Zone 的信任链。
- 主要构成：没有 struct。
- 审核：安全诊断必要，文件足够薄；最终归 CLI adapter。

### 71. `version.go`

- 做什么：整理 version/commit/build time/Go version 等构建信息并输出。
- 主要构成：没有 struct。
- 审核：必要、清楚，保留即可。

### 72. `zone.go`

- 做什么：显示 Zone 列表和某 Zone 的 records，支持 filter、verbose，并调用 canonical inspect/text。
- 主要构成：没有本地 struct。
- 审核：必要。主要是 CLI adapter，后续随 CLI 下沉；不要在这里重新实现 Zone 验证或 record 状态推理。

## 5. DTO/内存转换专项审核

### 5.1 应当保留的转换

| 转换 | 为什么不是多余 |
|---|---|
| `configYAML -> appConfig` | 处理缺省值、旧字段、string duration、`*bool` presence 和强校验 |
| `control JSON -> controlRequest` | 真实跨进程边界，必须有稳定 wire schema |
| `joinRequest/joinBundle <-> JSON/Base64` | 真实跨机器 artifact |
| `LinuxState -> clone -> revision-guarded commit` | 防止绕过 owner 修改私钥/ACL，并防陈旧 completion |
| `linuxObservation -> detached snapshot` | Daemon 写与 control/HTTP 并发读之间的隔离 |
| `TransportLinkSpec/ReconcileAction -> 脱敏 observation` | 原对象可能间接持有私钥，不能长期交给展示层 |
| `LinkInstance -> LinkOutput` | 明确去掉 owner/SA/action 等控制字段，给 health/routing/firewall 三类消费者一个窄契约 |

### 5.2 可以减少的转换

1. [已完成] `DesiredLinkObservation`、`LinkSAObservation`、`LinkActionObservation`、`LinkSkipObservation` 成为唯一 secret-free live DTO；inspect 使用 alias，删除二次逐字段 builder 和 app converter。
2. [已完成] reconcile 与 debug rotate 共用 SA 投影，避免两份字段列表漂移；保留 `ipsec.SAState -> LinkSAObservation` 这一道稳定 JSON/脱离 Driver 的边界。
3. `inspect.HealthTarget -> health.ProbeTarget`：这是展示 DTO 反向变执行输入，方向不理想。应让 control 返回共享的安全 probe target，或把命令执行放到 daemon 端。
4. `controlRequest.IPAM/Route/Service -> daemonEvent 对应字段 -> LocalIntent`：可在 control/direct 边界提前变成 intent，合并成一个 common mutation event。

### 5.3 不建议做的“优化”

- 不要把 `VerifiedState`、`LinuxState` 和 `linuxObservation` 合成一个大 Runtime DTO；
- 不要让 control/observer 直接拿 Daemon 内部 map 指针，以省一次 clone；
- 不要把 `LastError`、BIRD PID、SA、LinkInstance、reconcile action 再写回 bbolt；
- 不要为了统一 Linux/Windows 提前造 `PlatformDriver`、`PlatformState` 大接口；
- 不要为减少文件数把 72 个文件机械合并成几个巨型文件；
- 不要先引入通用 Repository、Manager、EventEnvelope 或 ObservationStore 再开始迁移。

## 6. 建议的减法顺序

### 第一优先级：收缩 live DTO 链

在不改变持久 schema 的前提下，先统一 `DesiredLink/LinkSA/LinkAction/LinkSkip` 的 canonical live 类型，删除 `inspect_links.go` 中的重复 builder 和 `debug_rotate.go` 中重复 SA copier。保留一次明确的脱敏步骤，并补测试证明 observation 不含 transport private key。

这是最贴近“数据在内存里转来转去是否有意义”的改动：收益主要是减少字段漂移和代码量，性能收益只是附带结果。

### 第二优先级：缩小 Daemon 内部联合事件

保留 Daemon 单 writer 队列，但让 record/IPAM/route/service 在边界处尽早成为 `corestate.LocalIntent`，删除 `daemonRecordPut` 和三个重复 payload 分支。不要改成大量 command class 或多层 dispatcher。

### 第三优先级：让 control 与 observer 共用 source builder

`daemon.go` 的 control switch 和 `observer_server.go` 都在读取同一组 owners。把“从 owners 得到 canonical inspect view”做成直接函数调用；control/HTTP 只负责 transport 和错误映射。这样减少的是真实重复逻辑，而不是换目录。

### 第四优先级：继续下沉 Linux policy/实现

按窄切口处理：

1. routing/BIRD raw query、parser、policy；
2. firewall config/policy/apply；
3. IPsec plan/observe/apply 与 live summary；
4. health target/lifecycle adapter。

每次迁移都直接删除旧 helper/forwarder，app 只保留 composition、Unix control、CLI 注册和完整 Daemon 顺序。

### 第五优先级：给 legacy schema 定退场版本

确定“从哪个旧版本直接升级仍受支持”，到期同批删除：

- `legacy_state.go`；
- `runtime_state_migration.go`；
- `gossip_checkpoint_migration.go`；
- `internal/state/peer.go` 的 legacy peer DTO；
- `debug_db.go` 中仅服务旧 schema 的 dump；
- 对应 legacy fixtures/tests。

这会是最干净、风险也最容易界定的一次结构性减法。

## 7. 最终评价

当前设计已经纠正了最危险的过度设计：没有第二个 Runtime、没有 aggregate State snapshot、没有把 Linux 在线观察继续持久化、没有为 Windows 预造统一平台接口。`LinuxState` 只剩两个真正需要跨重启的字段，这部分不是冗余。

仍然存在的过度设计主要集中在“展示前的多层近同构 DTO”和“一个 fat control/event 联合体不断加字段”；仍然存在的结构问题则是大量 Linux policy 与 CLI/presenter 还留在 `app/photon`。建议做减法时优先删除 builder、forwarder 和中间 payload，不要仅靠搬文件或新建抽象层制造“看上去模块化”。

如果只选一个下一步，应该先收缩 IPsec live DTO 链：它范围可控、不碰数据库 schema、不改变 Daemon 安全顺序，而且最直接解决本次提出的“内存模型来回转换”问题。
