# Photon Runtime、State 与 Driver 所有权

本文冻结 Linux/Windows 重构后的运行时、内存状态和持久化边界。它描述目标架构；当前类型与目标名称的对应关系见下表，迁移期间不得为兼容旧调用再增加并列 Runtime、Store 或聚合状态根。

## 1. 顶层结构

每个平台产品只有一个顶层生命周期所有者，统一称为 `Daemon`。Linux 当前由 `app/photon.Daemon` 及其 `Run` 方法承担，没有在外面再套一个 supervisor/runtime。

```text
Daemon
├── event loop / daemon scheduler
├── GossipDriver
│   ├── gossip.Engine
│   ├── UDP/TCP transport
│   ├── object-pull
│   ├── protocol timer
│   ├── session/chunk/address-book runtime
│   └── gossip observability
├── StateStore
│   ├── VerifiedState
│   └── GossipCheckpoint
├── LinuxDriver / WindowsDriver
├── LinuxState / WindowsState
├── LinuxObservation / WindowsObservation
└── BoltStore
```

`Daemon` 是唯一产品生命周期和平台 mutation 编排者。子组件可以拥有接收 channel、bounded worker 和协议 timer，但不得再形成持有 Daemon、StateStore、平台 Driver 与 BoltStore 的第二个产品 Runtime。

Daemon 和 GossipDriver 各自拥有队列：GossipDriver 的队列只排序 packet、协议 timer、object-pull 等 gossip 事件；Daemon 的 queue/scheduler 处理 IPsec、routing、firewall、health 等平台工作。健康探测完成信号直接回到 Daemon event loop，不通过 GossipDriver 包装或转发。

Health 与 observer 都是 Daemon 管理生命周期的可选子系统，不是所有平台必须具备的公共能力。Linux 可安装 healthDriver（manager、spool、运行标志和 Linux prober），Android 可以完全不创建它；同理 HTTP observer 只在需要的平台 composition 中启动。Gossip transport/address book 只由 GossipDriver 持有，Daemon 不保存第二份 transport 指针。

`gossipStartupConfig` 不是另一个配置 owner，只是 composition root 从 AppConfig 与 verified identity 生成的短生命周期构造输入；GossipDriver 创建后持有 detached protocol config。日志、reflector 和本机 endpoint 发布策略属于 app/platform composition，不复制进该输入。

## 2. 名称与当前实现

| 目标名称 | 当前实现 | 处理方式 |
|---|---|---|
| `Daemon` | `app/photon.Daemon` | 已直接收敛为顶层 owner；`Daemon.Run` 是当前主事件循环 |
| `GossipDriver` | `pkg/core/host.GossipDriver` | 已直接改名；保留公共 gossip 闭环，逐步移出非 gossip 的 controller timer/completion |
| `StateStore` | `pkg/core/state.Store` | 保留；它是公共可信状态 owner，不是 Gossip 专属 Store |
| `LinuxDriver` | `internal/photonlinux.LinuxDriver` | 已直接改名并保持具体 Linux API；不预建统一 `PlatformDriver` 接口 |
| `LinuxState` | `internal/photonlinux.RuntimeState` | 缩减并改名；它只是持久数据，不是运行对象 |
| `WindowsDriver` | `internal/photonwindows` 后续真实平台实现 | 只按真实调用点增加 API，不要求与 Linux 方法对称 |
| `WindowsState` | Windows 平台持久分区 | 只在有真实跨重启数据时增加字段 |
| `BoltStore` | `pkg/core/state.BoltStore` | 每进程唯一 bbolt handle/事务/关闭边界 |
| 已删除 | `app/photon.SyncRuntime` | Daemon 直接持有 AppContext；GossipDriver 持有 detached 协议配置和唯一 transport/address book |
| `AppContext` | 原 `app/photon.Runtime` | 已改名；只承载 CLI/config/state-path/clock，不是产品 Runtime |
| 删除 | `app/photon.DaemonStateStore` | 迁移期 common/Linux 顺序协调器，不属于终态 |

以前文档中的 `CommonRuntime` 只是“Linux/Windows 共用的 gossip 执行闭环”的概念名，当前实现就是 `pkg/core/host.GossipDriver`。它不是额外组件，也不是顶层 Daemon。后续文档统一使用 `GossipDriver`；“common”只描述代码可跨平台复用，不再作为一个 Runtime 名称。

## 3. StateStore

`StateStore` 是公共可信状态的内存 owner，通过 commit callback 使用唯一 `BoltStore` 持久化：

```text
StateStore
├── VerifiedState
│   ├── trusted root / root pin
│   ├── managed zone / authority / delegation
│   ├── verified Network
│   ├── identity 与公共本机 intent
│   └── VerifiedRevision
└── GossipCheckpoint
    ├── retry/backoff
    ├── observed endpoint 与 grace
    ├── relay/session 恢复提示
    └── rejected object/digest
```

`VerifiedState` 是不可随意丢失的权威事实。`GossipCheckpoint` 只保存 gossip 的 loss-tolerant restart hint；损坏时可报告并丢弃，然后重新发现和同步。Gossip 只是 StateStore 的一个使用者，因此不得把整个 Store 改名为 `GossipStore`。

## 4. LinuxState / WindowsState

平台 State 与 StateStore 是并列的逻辑分区，共用同一个 BoltStore；它不是另一个带线程、DB handle 或生命周期的 Store。`Daemon` 持有当前内存值，平台 codec 只在 composition root 提供的事务中读写。

平台 State 只允许保存两类数据：

1. 无法从 VerifiedState、配置、确定性命名或操作系统 observation 重新得到，并且跨重启确有意义的数据，例如没有其他来源的本地 transport private key、显式本地 Endpoint ACL、真实随机且未发布的 generation/resource ID。
2. 非幂等多阶段操作恢复所需的最小 journal，例如 staged rotation/takeover phase、owner token、待清理资源和 deadline。

能够从配置、签名 record、确定性 ID 或系统现状推导的数据不得重复落盘。ensure/delete 应优先做成幂等；只有无法安全重建的中间态才进入 journal。

WindowsState 遵守相同原则，但不为结构对称提前复制 Linux 字段。若 Windows 第一阶段没有额外持久数据，可以为空。

## 5. Observation

当前平台事实只存在于在线 Daemon 内存，启动后由 Driver 重新 Observe：

```text
Daemon start
  -> load VerifiedState + platform State
  -> create platform Driver
  -> Observe actual OS resources
  -> derive desired state
  -> Reconcile
  -> publish in-memory Observation
```

以下数据默认不得持久化：

- StrongSwan/IKE/CHILD SA 与计数器；
- XFRM interface 的当前状态；
- 内核 address/route/rule；
- BIRD PID、control socket 可用性、protocol/route 状态；
- firewall 当前 ruleset/owned object 数量；
- health probe 结果；
- 上一次 reconcile actions、LastRun 和 LastError。

Daemon 可以直接持有一个无独立锁/线程的 `LinuxObservation` 或 `WindowsObservation`，也可以在查询时调用 Driver；不得再创建一个并列 `ObservationStore`。CLI、HTTP 和 inspect 查询平台 runtime 时必须经过在线 Daemon；离线时返回 unavailable。磁盘上的上次结果即使暂时仍存在，也只能标成 `last-known/checkpoint`，不能冒充 live observation。

内存中的错误使用 `error` 或 typed failure；展示层再映射为稳定 code/message。只有明确证明跨重启诊断有价值时，才允许增加带时间和来源的 loss-tolerant failure checkpoint，不能继续把任意 `LastError string` 混入 durable State。

## 6. 当前 LinuxState 的收缩清单

当前 `RuntimeState` 混合了 durable input、operation journal、derived state 和 observation，需要逐字段审计：

| 当前字段 | 目标处理 |
|---|---|
| `IdentityKeyPath` | 已从 current Linux state 删除；路径只由配置/应用上下文持有，启动与 reload 直接校验该文件的公钥匹配 VerifiedState 中的身份私钥；旧 schema decoder 读取后丢弃 |
| `IPsecTransportKey` | 保留；当前由本机随机生成，gossip 只发布公钥，没有第二个私钥 owner，跨重启保持 transport identity 需要它 |
| `IPsecPortRecord` | 已删除；本机 verified `ipsec/ports` record 已包含 mode、range、generation、更新时间和 previous grace，自动/手动轮换均直接以它为恢复输入，不存在独立 staged generation |
| `EndpointACLs` | 保留；它由 control API 显式创建，是非 gossip 的本机平台 intent，配置和操作系统规则都不是其完整真相源，产品语义要求跨重启继续生效 |
| `LinkInstances` | 已从 LinuxState 删除；current/previous generation 从 VerifiedState 与 StrongSwan/XFRM observation 恢复 |
| `IPsecReconcile` | 已从 LinuxState 删除；`ActualSAs`、actions、LastRun、LastError 与 derived desired 只进 Observation |
| `RoutingReconcile` | 已从 LinuxState 删除；只进 Observation |
| `FirewallReconcile` | 已从 LinuxState 删除；实际状态、诊断与可重建 policy hash/generation 只进 Observation |
| `BirdInstances` | 已从 LinuxState 删除；desired/路径/RouterID/owner 重新推导，PID/socket/status/exit/backoff 进程内 Observe |
| `PeerCleanups` | 只保留确有安全 grace/cleanup 恢复意义的字段，其余从 GossipCheckpoint/VerifiedState 推导 |
| `Admission` | 已从 LinuxState 删除；它是由 VerifiedState 与 GossipCheckpoint 即时生成的 inspect diagnosis，不是持久 state。旧 schema 字段解码时直接丢弃 |

在该审计完成前，不把现有整个 `RuntimeState` 搬进 `LinuxDriver`，也不以 current codec 已迁入 `internal/photonlinux` 为理由宣布状态边界完成。

## 7. 持久化与写入边界

```text
唯一 BoltStore
├── common/verified
├── common/gossip-checkpoint
├── linux/state
└── windows/state
```

- composition root 打开并关闭唯一 BoltStore；StateStore 和平台 state codec 不自行按路径打开数据库。
- Daemon event loop 串行发布内存 mutation；耗时 Observe/Plan/Apply 可锁外执行，completion 必须回到 owner 后再提交。
- 持久化成功后才能发布对应内存状态。
- `DaemonStateStore` 只在迁移期提供 common/Linux 顺序锁、组合读取和 commit forwarding。所有调用改用 Daemon 持有的 typed owner 后删除，不保留为终态 Repository/Store。

## 8. 迁移原则

1. 先按真实职责改调用关系，再改类型名，避免用 alias/wrapper 维持两套 API。
2. 不新增顶层 `CommonRuntime`、`ClientRuntime`、`PlatformCapabilities` 或统一 PlatformDriver 接口。
3. GossipDriver 只保留 gossip 协议闭环；controller timer、health completion 和平台 mutation 回到 Daemon。
4. Driver 执行平台 I/O，State 保存最小 durable input/journal，Observation 描述当前实际状态。
5. 测试跟随 owner：协议进 gossip/host，平台执行进 photonlinux/photonwindows，app 只保留 composition/control/daemon 顺序验收。
