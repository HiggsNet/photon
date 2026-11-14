# Photon Daemon 设计与实现

> **本文档状态：2026-11-13**
> 描述 `photon daemon` 的架构、事件循环、单 writer 模式、control socket、reconcile 调度和本机状态管理。不展开 transport、routing、firewall、health 等子模块的内部细节——那些在各自的文档中说明。

Photon daemon 是长期运行的控制循环。它把所有子系统——gossip、admin 写入、端点发布、object pull、transport reconcile、routing reconcile、firewall reconcile、health 和 observer——放在同一个本机控制边界内。

---

## 目录

1. [架构概览](#1-架构概览)
2. [Daemon 结构](#2-daemon-结构)
3. [事件循环](#3-事件循环)
   - 3.1 [Packet Demuxer](#31-packet-demuxer)
   - 3.2 [GossipDriver Scheduler](#32-gossipdriver-scheduler)
   - 3.3 [Async Object Pull](#33-async-object-pull)
4. [单 Writer 模式与状态管理](#4-单-writer-模式与状态管理)
   - 4.1 [核心原则](#41-核心原则)
   - 4.2 [当前状态 owner](#42-当前状态-owner)
   - 4.3 [写路径](#43-写路径)
   - 4.4 [Reconcile 与 Observation](#44-reconcile-与-observation)
   - 4.5 [持久化分区](#45-持久化分区)
   - 4.6 [状态变化通知](#46-状态变化通知)
   - 4.7 [状态变更边界](#47-状态变更边界)
   - 4.8 [离线写入边界](#48-离线写入边界)
   - 4.9 [状态持久化边界](#49-状态持久化边界)
5. [Control Socket](#5-control-socket)
   - 5.1 [systemd 运行约定](#51-systemd-运行约定)
   - 5.2 [同机双实例](#52-同机双实例)
   - 5.3 [状态持久化、停止与崩溃恢复](#53-状态持久化停止与崩溃恢复)
6. [Reconcile 调度](#6-reconcile-调度)
7. [子模块集成](#7-子模块集成)

---

## 1. 架构概览

Daemon 是 Photon 中唯一长期运行的系统进程。它不在每次 CLI 调用时重新加载全部状态，而是持续运行一个事件循环，按需调度各子系统的 reconcile。

```
┌──────────────────────────────────────────────────────────┐
│                    Daemon Event Loop                       │
│                                                            │
│  ┌───────────┐    ┌──────────────┐    ┌────────────────┐  │
│  │UDP Receiver│───▶│ Packet Demux│───▶│ Gossip Sync    │  │
│  │(goroutine) │    │              │    │ SyncSession FSM│  │
│  └───────────┘    └──────────────┘    └────────┬───────┘  │
│                                                 │          │
│  ┌───────────┐    ┌──────────────┐              │          │
│  │Control    │───▶│ Events chan  │──────────────┤          │
│  │Socket     │    │ (daemonEvent)│              │          │
│  └───────────┘    └──────┬───────┘              │          │
│                           │                      │          │
│  ┌───────────┐           ▼                      ▼          │
│  │Observer   │    ┌─────────────────────────────────────┐  │
│  │HTTP Server│    │          handleEvent()               │  │
│  └───────────┘    │  ┌─────────┐ ┌──────────┐ ┌──────┐  │  │
│                   │  │ IPsec   │ │ Routing  │ │FW    │  │  │
│                   │  │Reconcile│ │Reconcile │ │Reconc│  │  │
│                   │  └─────────┘ └──────────┘ └──────┘  │  │
│                   │  ┌─────────┐ ┌──────────┐ ┌──────┐  │  │
│                   │  │ Health  │ │ Endpoint │ │Object│  │  │
│                   │  │Reconcile│ │Publish   │ │Pull  │  │  │
│                   │  └─────────┘ └──────────┘ └──────┘  │  │
│                   └─────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

**关键分层原则**：
- Gossip 只传播和验证签名 Zone 状态，不执行系统配置。
- IPsec、WireGuard、BIRD、nftables/iptables 都是本机 runtime driver——它们的失败不改变 signed state 的真实性。
- Overlay/link policy 是本机策略，不默认公开到 gossip。
- Debug/Observer 展示"已验证事实 + 本机期望状态 + 实际 runtime 状态"的差异，而不是只展示某一层。

---

## 2. Daemon 结构

`Daemon` 定义在 [`app/photon/daemon.go`](../../app/photon/daemon.go) 中，是 daemon 的唯一顶层生命周期和事件循环 owner。

主要字段：

| 字段 | 类型 | 作用 |
|------|------|------|
| `Config` | `*appConfig` | 加载后的有效配置；`StatePath` 已包含环境变量覆盖 |
| `clock` | `func() time.Time` | Daemon 自己的时钟依赖，通过 `d.now` 供协议和调度使用 |
| `gossipDriver` | `*corehost.GossipDriver` | 持有 detached gossip 协议配置、transport/address book 和协议执行闭环；Daemon 不再重复保存 GossipConfig/transport |
| `State` | `*State` | 唯一进程内持久状态边界；内部管理 StateDB、Common 与 LinuxState |
| `Events` | `chan daemonEvent` | 统一事件入口（64 buffer） |
| `Interval` | `time.Duration` | 出站 sync 周期（默认 60s） |
| `ControlSocketPath` | `string` | Unix domain socket 路径 |
| `linuxDriver` | `*photonlinux.LinuxDriver` | 持有 IPsec/XFRM/BIRD/firewall/health 平台实现 |
| `health` | `*healthDriver` | 可选的健康探测 manager、spool 和运行标志 |
| `observerHub` | `*observer.Hub` | Observer SSE 事件广播 |
| `ipsecDirty` | `bool` | IPsec reconcile 待调度标记 |
| `routingDirty` | `bool` | Routing reconcile 待调度标记 |
| `firewallDirty` | `bool` | Firewall reconcile 待调度标记 |
| `objectPullExecutor` | `*host.GossipObjectPullExecutor` | Linux TCP exchange 注入点；worker 生命周期由 GossipDriver 管理 |

**DaemonEvent 类型**（[`daemon.go`](../../app/photon/daemon.go)）：

事件通过 `daemonEvent` 结构体传递，主要字段包括 `Type`（事件类型）、`Context`（上下文）和 `Reply`（结果通道）。`enqueueEvent()` 把事件放进 `Events` 通道，然后阻塞等待 `Reply` 返回结果。这样，control socket 侧的 admin 操作能拿到明确的完成或失败信号。

主要事件类型：
- `common_mutation` / `delegate_issue` / `delegate_revoke` — 状态写入；control 的 `record_put` 转成 typed intent
- `delegate_grant` / `recovery_import_zone` / `recovery_purge_revoked` — 权限变更
- `join_accept` — 节点加入；`root_init` 只保留 daemon 侧拒绝入口，用来提示停止 daemon 后执行 direct/recovery 初始化
- `sync_trigger` / `routing_reload` — 手动触发
- `ipsec_cleanup` / `ipsec_port_rotate` / `ipsec_lifecycle` — IPsec 生命周期
- `shutdown` — 优雅退出

UDP 包、协议 timer 和 object-pull 完成结果由 GossipDriver 的入口交付；平台周期任务使用 daemon 自己的 Scheduler。端点定时器直接调用刷新入口，不再包装成 `daemonEvent`。

---

## 3. 事件循环

Daemon 启动流程（[`daemonRun()`](../../app/photon/daemon.go)）：

```
daemonRun()
 ├─ loadAppConfig()       加载配置并解析 PHOTON_STATE 覆盖
 ├─ openDaemon(config)    通过 openState(config) 打开唯一 BoltStore，创建 Daemon
 └─ service.Run()         进入事件循环
```

`Run()` 方法：

1. **初始化驱动**：配置 IPsec (StrongSwan VICI + XFRM) 驱动
2. **启动子服务**：
   - `openGossipTransport()` — 开启 UDP gossip 监听
   - `startObjectPullServer()` — 启动 TCP object pull 服务
   - `startControlServer()` — 启动 Unix domain socket 控制服务器
   - `startObserverServer()` — 启动 HTTP observer 服务器
   - `startIPsecLifecycleEventWatcher()` — 监听 StrongSwan VICI 生命周期事件（后台 goroutine 订阅，单次订阅带超时、失败退避重试；VICI 卡死只产生告警日志，不阻塞 daemon 启动）
3. **启动恢复**：

```
// 1. GossipDriver 直接持有 common State owner
d.gossipDriver = corehost.NewGossipDriver(..., d.State.Common, ...)

// 2. 本机 endpoint/IPsec/routing 记录通过 typed common mutation 发布
d.prepareLocalState()
d.refreshGossipDiscovery()

// 3. 数据面从 detached common view、LinuxState 和重新 observation 恢复
d.recoverIPsecLinksOnStart(ctx)
d.routingDirty = true
d.flushRoutingReconcile(ctx)
d.firewallDirty = true
d.flushFirewallReconcile(ctx)
```

系统操作不持有状态写锁。控制和 Observer 读请求可读取已提交快照；写请求仍需等待主循环完成启动恢复。

4. **进入主循环**：

```
for {
    // 最多处理 16 个控制/生命周期事件，统一 flush 后回复
    processEvents(ctx, pendingEvent)
    // 本地签名变更按 revision 合并转发摘要
    select {
        case ctx.Done(): 退出
        case daemonEvent: 留作下一批的首事件
        case endpointResult: 按最新状态发布端点及协议记录
        case healthUpdate: 更新探测记录和 Observer
        case daemonTimer: 验证 generation，触发刷新或标记对应系统层 dirty
        case GossipDriver.Events/Completions/Continuations: 处理一批协议事件
    }
}
```

**processEvents() 阶段**：

每批最多处理 16 个已排队事件，处理完后以拒绝优先顺序执行一次 flush：
1. `flushFirewallReconcile()` — 刷新防火墙规则
2. `flushRoutingReconcile()` — 刷新路由
3. `flushIPsecReconcile()` — 刷新 IPsec 链路

签名撤销提交时清除对应的 Gossip checkpoint，共享 GossipDriver 负责清理活动会话、地址和诊断。数据面先撤销防火墙授权，再回收路由和 IPsec 链路。

IPsec 的接口、地址、可用状态或轮换阶段发生变化时，标记路由和防火墙 dirty，通过现有 Scheduler 立即唤醒下一批。后续批次仍按防火墙、路由的顺序执行；流量计数、外层端点和诊断时间变化不触发系统调整。部分应用失败也传递已经发生的有效变化。

### 3.1 Packet Demuxer

UDP reader 收到包后，由 Packet Demuxer 按 `peer_id` 路由：

- 命中活跃 `SyncSession` 的包 → `PacketEvent`，交给该 session 的 FSM。
- 未命中的包 → `UnsolicitedPacketEvent`，由事件循环里的只读 responder / hint ingress 处理：
  - `PING` / `FETCH_CATALOG_PAGE` / `FETCH_ZONE`：直接读取已提交的状态并回复。
  - 带目录摘要的 `PING`：目录根不同时触发主动同步。

Demuxer 只按 `peer_id` 路由，不解释 message type；message type 由 `SyncSession` 或 unsolicited handler 在事件循环内判断。

收到命中活跃 session 的 `PING` 时，事件循环会同时做两件事：
1. 把 summary 转成 `CatalogSummaryReceivedEvent` 交给 session FSM。
2. 直接回复 `PONG` summary（respondPing）。

### 3.2 GossipDriver Scheduler

`gossip.SyncSession` 只返回 start/cancel timer action，不创建计时资源。公共 `pkg/core/host.GossipDriver`
执行 action，其 Scheduler 用 `(namespace, owner, key, generation)` 管理 timer；gossip 当前使用：

- `round`：整轮同步超时。
- `catalog_page`：catalog page 请求超时。

Scheduler 只有一个 deadline heap 和一个 wakeup loop。Timer 到期后把带 deadline/generation 的 `TimerFired`
投递到 GossipDriver bounded queue；事件循环消费时再次验证 generation，再转换为 gossip timeout event。
timer callback 不直接修改 session/state；队列满时不会按固定超时丢弃。Session 进入 `Completed` / `Failed`
时，取消该 peer 在 gossip namespace 下的所有 timer。

Scheduler 支持 fake clock 注入，稳定覆盖同 deadline 顺序、replace/cancel、stale generation、queue backpressure
和 stop 语义。

### 3.3 Async Object Pull

TCP object pull 在独立的 worker pool 中执行，避免阻塞事件循环：

1. `SyncSession` 进入 `ObjectPulling` 后，生成 `StartObjectPull` action。
2. GossipDriver 将请求交给自己拥有的有界 worker 队列。
3. Worker 完成 TCP 连接、读取 MessagePack 响应后，把结果发回可靠完成队列。
4. 事件循环将结果转成 `ObjectPullResultEvent`，交给对应 session。

`SyncSession` 跟踪每个 zone 的 inflight pull，避免对同一个对象重复请求。

---

## 4. 单 Writer 模式与状态管理

### 4.1 核心原则

Daemon 是在线进程唯一的平台 mutation 编排者。CLI admin 操作（如 record put、delegate issue）不会绕过在线 daemon 另开 BoltDB，而是通过 control socket 把请求发给事件循环，再提交给对应 typed owner。

这样可以避免多个写者同时修改同一份本地状态。

### 4.2 当前状态 owner

Daemon 当前只组合一个具体 `State`；其内部边界为：

- `Common`（`pkg/core/state.Store`）：VerifiedState 与 loss-tolerant GossipCheckpoint；
- `LinuxState`（`internal/photonlinux.LinuxState`）：IPsec transport 私钥、显式本机 Endpoint ACL 和隧道暂停标记；
- `StateDB`（实现为唯一 `state.BoltStore`）：同一进程的 bbolt handle 和事务边界。

旧 `DaemonStateStore` 的 aggregate snapshot/forwarding API 已删除。新的 `State` 不伪装成 common Store：common 调用显式进入 `State.Common`，LinuxState 只通过 typed mutation 在 verified revision 护栏下持久化。Daemon 仍直接持有在线 `LinuxObservation` 与 `LinuxDriver`。完整边界见 [`runtime-state-ownership.md`](../runtime-state-ownership.md)。

### 4.3 写路径

本地 admin intent 和 GossipDriver 接受的远端 verified state 进入公共 Store；需要保留的本机配置通过 State 的 typed mutation 更新 LinuxState。持久变更先由唯一 BoltStore 提交，再发布内存状态。平台 Observe/Plan/Apply 在主循环、状态锁外同步执行，只更新在线 observation；系统操作结果不写成持久状态。

纯 GossipCheckpoint 更新使用独立的 `CommitCheckpoints` 回调：只复制发生变化的 peer，应用指定字段后，先提交磁盘事务，再在短读写锁内发布内存字段；不复制、编码或写入 VerifiedState，也不推进 VerifiedRevision。涉及 verified facts 和 checkpoint 的联合修改仍使用完整候选和同一个原子事务。

`ReadView()` 返回可供调用方修改的深复制快照，并不是零成本的内存指针读取。只查询 checkpoint 的协议事件使用 `PeerCheckpoints(ids)`；撤销清理使用 `RevokedPeerCheckpoints(now)`，避免复制无关 records/history。撤销查询每次按当前时间计算，不能只按 verified revision 缓存，否则未来生效的撤销会遗漏。

### 4.4 Reconcile 与 Observation

IPsec、routing、firewall 的 desired 来自 VerifiedState、配置和最小 LinuxState。系统观察和应用结果留在在线 Daemon 中：IPsec、routing、firewall 使用 LinuxObservation，health manager 持有探测结果。应用动作后不保证同轮完整重查系统，后续事件和周期检查继续确认实际状态。CLI/HTTP 查询平台运行状态必须经过在线 Daemon；离线只读取持久事实和明确标记为重启提示的 GossipCheckpoint。

### 4.5 持久化分区

状态持久化在唯一 BoltDB 文件中：common verified、common gossip-checkpoint 与 linux/state 使用不同 bucket，但共享一个 handle。当前 common schema 为 2，旧整库需先使用支持迁移的 v0.6.6 升级；旧整块 Gossip checkpoint 不再加载。Checkpoint 按 peer 保存可恢复的退避、上次成功探通地址等提示，活跃会话、观测地址有效期、最近同步结果与 relay 节流保留在内存。

### 4.6 状态变化通知

`notifyStateChanged(affected)`：

当状态变化时（sync 成功应用了 Zone snapshot、admin 写入 record 等），daemon 会：
1. 调用 `OnStateChanged` hook（测试用）
2. 通知 observer 推送 SSE 事件
3. 配置了 Linux driver 时，只合并调用者显式指定的 dirty 标记，不清除已有待办

本地变更的依赖由 `reconcile_dependencies.go` 集中声明：

| 变更 | 直接标脏 |
|---|---|
| 路由公告/撤回、IPAM pool/assignment 增删 | routing、firewall |
| Gossip endpoint、IPsec 协议记录、端口轮换、私有 transport key | IPsec |
| routing/netns 本地公告、SOCKS5 服务发现公告/撤回 | 无 Linux 系统层 |
| 远端同步、授权/撤销、身份安装、恢复、通用或未知本地 intent | 全部 |

本地协议批次取依赖并集。IPsec 输出变化再独立标脏 routing/firewall，避免把公告刷新直接当成链路变化。routing 自动公告仅标脏 routing/firewall；周期检查继续处理授权到期和系统漂移，不依赖新的签名提交。

该函数不直接执行系统调整。下一次批次统一 flush，主循环按 verified revision 合并本地摘要转发。IPsec 运行变化只通知实际依赖者，不冒充签名状态变化。

### 4.7 状态变更边界

**所有状态变更只允许在 daemon 事件循环 goroutine 中发生**。`SyncSession.OnEvent` 只读当前状态并输出动作列表，动作由事件循环统一执行。这样事件循环本身就是锁，不需要额外对 `NetworkState` 加锁。

必须在事件循环内串行执行的状态变更：

- `NetworkState` apply：`ApplySnapshot`
- peer runtime 更新：sync 状态、观测地址、backoff、last error
- typed Store mutation 和持久配置提交
- Transport 地址簿和协议运行时的更新
- IPsec / routing / firewall 的 desired-state 计算与 reconcile 触发
- 分块组装、拒绝摘要等协议缓存

可以在 worker goroutine 中执行、但结果必须以事件回注的：

- UDP 读包（单 reader，已在事件循环入口）
- TCP object pull 的网络 I/O
- reflector HTTP 查询
- health probe I/O
- VICI 生命周期事件订阅

worker 不修改共享 NetworkState 或协议 FSM。当前 IPsec 规划中的 DNS 解析仍同步执行；将来若移到 worker，必须通过完成事件回到单写者提交。

### 4.8 离线写入边界

daemon 运行时持有唯一数据库 owner，在线写入通过 control socket。当前实现没有外部文件监控、状态热重载或外部写入合并路径。直接恢复或替换数据库前必须停止使用它的 daemon；不得依赖文件时间变化使运行中的内存状态更新。

### 4.9 状态持久化边界

签名变更和本机持久配置在对应 typed mutation 中提交；协议只在 checkpoint 的实际持久字段变化时写入，独立于诊断日志和 Observer 通知。单纯刷新流量计数、同步成功时间、分块进度或 timer 不推进 VerifiedRevision。所有协议和配置写入都由主循环串行发起。

---

## 5. Control Socket

Daemon 通过 Unix domain socket 暴露控制接口。

- root 默认路径 `/run/photon/photon.sock`，非 root 默认 `<data_dir>/photon.sock`，`PHOTON_CONTROL_SOCKET` 可覆盖
- 协议是简单 JSON request/response
- 安全边界只有 Unix 文件权限（父目录 `0700`，socket `0600`），**没有应用层方法级鉴权**

CLI 通过 `sendControlRequest()` 与 daemon 通信。daemon 在线时，写操作进入事件循环由单 writer 串行执行；读操作从当前状态快照返回。

必要的系统调整仍同步执行。运行中只在 `linuxObservation` 保存一条当前操作，记录组件、阶段、开始时间和期限，结束即清空，不写数据库。CLI 状态与 Web 状态使用同一个 `RuntimeOperation` 结构，查询时计算已等待时长；Web 每 5 秒刷新可见页面的运行状态。

公网 IP 由后台采集，启动先发布配置和接口地址。每次只保留一轮采集或待处理结果，主循环消费完成结果后按最新状态签名和发布，随后更新依赖这些端点的 IPsec 地址。采集继承 daemon 的取消信号，所有 reflector 共用一次查询预算，默认 3 秒；退出时取消并等待请求结束。没有 reflector 时只同步刷新本地候选。

启动时尚未获准加入的节点，在 Gossip 自动接纳或 `join_accept` 成功后的下一批事件中，先补发本机端点和 IPsec/routing 公告，再执行系统配置，无需等待默认五分钟的端点定时器。公网 IP 采集仍在后台完成；公告失败会记录错误，后续端点定时器继续重试。

每个连接处理一个请求。客户端断开或请求到期会取消对应上下文，尚未执行的队列事件跳过提交；已经提交的修改不回滚。普通请求的等待上限是 70 秒，ping 诊断为 5 分钟。单次防火墙、路由或 IPsec 调整仍各自最多等待 20 秒，父上下文更早到期时提前结束。服务停止时取消并等待所有已接入请求收尾，再释放它们使用的状态和驱动；写响应保留 10 秒上限。

当 socket 不存在或连接被拒绝（`ECONNREFUSED`）时，只读诊断命令可回退到本地 DB 离线视图，持久状态写入命令可走 direct/recovery 路径。超时、权限错误、连接重置、协议错误等不会触发 fallback，因为这些错误可能来自仍在线但异常的 daemon。

状态写入类命令和恢复类命令支持显式 `--direct`，跳过 control socket 直接写本地 DB。使用 direct 时调用者需自行保证没有 daemon 在管理同一状态文件或 IPsec/XFRM 对象；direct 只持久化 signed record，不会触发 routing reconcile。

控制方法覆盖状态读写、delegation 管理、节点加入、恢复操作、runtime 触发（`sync_trigger`/`routing_reload`/`shutdown`）以及各类诊断接口。`config.yaml` 只在进程启动时读取，修改后需要重启 daemon。完整列表见 `app/photon/daemon_control.go` 中 `handleControlConn` 的 switch。

### 5.1 systemd 运行约定

仓库提供 [`contrib/systemd/photon.service`](../../contrib/systemd/photon.service) 示例。service 使用 `RuntimeDirectory=photon` 创建 `/run/photon`，因此不需要预先手工创建运行目录，也不需要单独的 `.socket` unit。当前 daemon 自己创建并管理 Unix socket，尚不支持 systemd socket activation。

安装后至少需要确认：

- `ExecStart` 指向实际安装的 `photon` 二进制；
- `/etc/photon/config.yaml` 和 identity/private key 仅允许运行用户读取；
- 如果启用 StrongSwan/XFRM、netns 或防火墙 apply，service 需要相应的 root/capability 权限；
- root CLI 与 daemon 使用相同的 `PHOTON_CONFIG`，从而共同定位 `/run/photon/photon.sock` 和同一份状态。

示例使用 `Restart=on-failure`、`RestartSec=2s` 和 `TimeoutStopSec=30s`：异常退出会重启；正常 shutdown 或 `SIGTERM` 不会重启；停止超过 30 秒后才强制结束。

control socket 先启动、后于 Observer 停止。control 或 Observer 启动失败会终止启动并清理已有 listener；TCP object-pull 监听失败则记录错误，继续使用 UDP 回退。control socket 创建父目录时使用 `0700`，socket 使用 `0600`，不做方法级鉴权。

Observer 请求继承 daemon 的取消上下文。关闭时先取消 SSE 事件流，再等待 HTTP 服务退出；优雅关闭超时则关闭剩余连接。Daemon 的 `Close()` 同时释放 Gossip 定时器、Linux 驱动和数据库，Linux 驱动初始化失败也会停止已创建的 Gossip 定时器。

### 5.2 同机双实例

同一主机最多运行固定的两个角色：普通节点与一个管理节点。发布和升级仍只有一份
`/usr/local/bin/photon` Go 二进制；安装器另外安装 `/usr/local/bin/photon-admin`
shell 包装器，并准备两个明确命名的 systemd unit：

默认安装只准备普通节点。仅当安装命令显式传入 `--admin` 时，才额外安装 admin
包装器、配置和 service：

```bash
curl -fsSL https://raw.githubusercontent.com/HiggsNet/photon/master/contrib/install.sh | \
  sudo sh -s -- --admin
```

后续运行 `update.sh` 时会检测已经存在的 `photon-admin` 并自动保持双实例更新，普通
节点不会因为一次常规更新而新增 admin 角色。

| 资源 | 普通节点 | 管理节点 |
|---|---|---|
| 命令 | `photon` | `photon-admin` |
| systemd unit | `photon.service` | `photon-admin.service` |
| 配置 | `/etc/photon/config.yaml` | `/etc/photon/admin/config.yaml` |
| 数据库 | `/etc/photon/photon.db` | `/etc/photon/admin/photon.db` |
| control socket | `/run/photon/photon.sock` | `/run/photon-admin/photon.sock` |

`photon-admin` 在每次执行时设置 admin 的配置、数据库和 control socket，然后 `exec`
同目录下的 `photon`。它是可供 `sudo`、systemd 和自动化脚本直接调用的包装命令，
不是依赖交互式 shell 初始化的 alias。正常命令不会误连普通节点：

```bash
photon health
photon-admin gossip delegate issue request.json
photon-admin health --verbose
```

安装器仅在 `/etc/photon/admin/config.yaml` 不存在时创建最小配置，不覆盖已有 identity、
key、数据库或配置；最小配置将 admin gossip 监听端口设为 `33435`，避开普通节点默认
的 `33434`。完成两套身份初始化并确保其他显式监听端口也不同后启动：

```bash
systemctl enable --now photon.service photon-admin.service
journalctl -u photon.service -u photon-admin.service -f
```

推荐让普通节点独占 IPsec、BIRD、firewall 和 health 数据面；admin 只承担独立的
authority/gossip 管理身份，不配置 overlays、routing instance 或 firewall instance。
这样两者不会竞争宿主 StrongSwan、XFRM、BIRD、路由表和防火墙对象。如果将来确实
需要让 admin 运行第二套完整数据面，应当另行设计 netns 和独立 charon/VICI 隔离，
不由当前固定双实例安装方案隐式支持。

### 5.3 状态持久化、停止与崩溃恢复

签名状态、最小 Gossip checkpoint 和 LinuxState 写入 BoltDB；系统 reconcile 观察、最近同步诊断、socket、连接、内存事件和进行中的 sync session 不持久化。正常关闭使用 `photon daemon --shutdown` 或 `SIGTERM`。

崩溃后，daemon 从最后一次成功提交的状态启动，重新发布本机记录并 reconcile 数据面；未完成的同步由定时任务重试。状态库无法打开时启动失败，不会用空状态覆盖原文件。

managed BIRD 的退出行为由每个 routing instance 的 `shutdown_policy` 决定：

- `persist`（默认）：保留 BIRD，重启后 adopt，减少路由中断。
- `stop`：优雅退出时停止 BIRD，适合实验环境。

强制结束或崩溃时不保证执行 `stop`；遗留对象由下次启动按 ownership 检查和收敛。

---

## 6. Reconcile 调度

Daemon 使用**三级调度策略**：事件驱动 + 周期性 + 标记脏。

### 6.1 标记脏（Dirty Flag）

每个子系统有一个 dirty 标记：
- `ipsecDirty` — IPsec 链路需要刷新
- `routingDirty` — 路由需要刷新
- `firewallDirty` — 防火墙需要刷新

标记在以下情况被设置：
1. `notifyStateChanged(affected)` — 状态变化后按显式依赖标脏
2. 周期 timer 到期
3. IPsec lifecycle 事件到达时

### 6.2 Flush 方法

每个子系统有对应的 flush 方法：

- `flushIPsecReconcile(ctx)` — 检查 `ipsecDirty`，调用 `reconcileIPsecLinks(ctx)`，之后调用 `reconcileHealth(ctx)` 刷新健康探测目标
- `flushRoutingReconcile(ctx)` — 检查 `routingDirty`，调用 `reconcileRouting(ctx)`
- `flushFirewallReconcile(ctx)` — 检查 `firewallDirty`，调用 `reconcileFirewall(ctx)`

Flush 方法返回 `bool` 表示是否确实执行了 reconcile。

周期任务在启动恢复完成后首次安排，之后只在批次 flush 后按当前结果重排。配置在单次运行中固定；IPsec 是否还需周期检查取决于刚更新的链路实例，不再由主循环每次唤醒时重复比较三份 interval 缓存。

三个系统层各有 20 秒操作预算。它们同步占用主循环，连续耗尽预算时会推迟 Gossip、timer 消费和后续写请求。控制/Observer 读请求可并发读取已提交快照和当前操作。若要异步化系统调整，需要另行设计互斥执行、过期结果处理和撤销顺序；不能仅把现有方法放进 goroutine。

### 6.3 周期性定时器

即使没有事件触发，IPsec 和 routing 也有周期性 reconcile：

- IPsec reconcile 周期：默认 60s，可通过 `overlays[*].reconcile.interval` 配置
- Routing reconcile 周期：30s（由 `defaultRoutingReconcileInterval` 定义）
- 当 link group 数为 0 且没有链路实例时，IPsec reconcile 定时器关闭（返回 0）
- 当 routing 实例数为 0 时，routing reconcile 定时器关闭

### 6.4 撤销后的拒绝优先顺序

```
flushFirewallReconcile()  // 防火墙 allow set
flushRoutingReconcile()   // 路由
flushIPsecReconcile()     // IPsec
```

Store 在提交生效的撤销时删除相关 Gossip checkpoint，共享 Gossip discovery 清理会话、端点和诊断。Linux 各子系统依据已验证的撤销更新目标状态，先收紧防火墙访问，再撤路由和 IPsec 链路。

### 6.5 同一事件队列的 sync-trigger 链

```
record_put
  → common_mutation: 提交 typed intent
  → notifyStateChanged: 设置 dirty 标记
  → processEvents drain 中: flush firewall → routing → ipsec

sync timer
  → handleSyncTimerEvent: 为符合退避规则的 peer 启动 SyncSession
  → GossipDriver 验证并提交远端快照，立即转发摘要
  → notifyStateChanged（如果有变化）

sync_trigger
  → 同批请求合并，在主循环内直接启动一次强制同步（绕过退避）
  → 不经过立即 timer 二次排队，不重置周期同步的时间

endpoint publish timer
  → handleEndpointTimerEvent: 发布 endpoint、IPsec transport、routing netns 记录
  → 记录无变更时直接返回，不触发 notifyStateChanged / flush
  → 有变更时 notifyStateChanged
```

---

## 7. 子模块集成

Daemon 作为编排器，各子模块通过清晰的接口与 daemon 集成：

### 7.1 Gossip Sync

- **输入**：UDP 包（从 transport.Receive() 接收）、定时器事件、object pull 结果
- **输出**：GossipDriver 直接调用公共 State 的 remote batch/checkpoint API，并通过同一 transport 发送协议响应
- **集成点**：`pkg/core/host.GossipDriver` 是当前 GossipDriver，拥有 Engine、协议 queue/scheduler、transport、object-pull、chunk/session runtime 和 gossip observability；Daemon 只消费其事件并接收需要触发平台 reconcile 的终态结果
- **状态范围**：verified signed facts 进入 VerifiedState；retry/backoff/observed endpoint 等 restart hint 进入 GossipCheckpoint；session/chunk/address book 等只在内存

目录根一致时无需拉取 Zone 快照也可完成同步；具体 PING/PONG 分流、会话生命周期和诊断由公共 GossipDriver 管理。

### 7.2 IPsec Transport

- **输入**：detached VerifiedState、最小 LinuxState、本地配置和 LinuxDriver observation
- **输出**：StrongSwan IKE child SA、XFRM interface、network namespace 内接口；只有不可重建的最小 journal 才写 LinuxState
- **集成点**：Daemon 编排 reconcile，`internal/photonlinux.LinuxDriver` 直接执行 SA/XFRM observe、apply 和 cleanup；实际 SA、动作和错误进入内存 Observation
- **状态范围**：Link instance 与 reconcile 结果只存在于 daemon 内存 `LinuxObservation`，不进入 state file 或 gossip

**XFRM 维护短路**：在 `maintainExistingXFRMInterfaces` 中，如果 observed 状态与期望状态已经匹配，则跳过 `EnsureInterface`/`AssignAddress` 等冗余命令，只保留诊断地址分配。这减少了 reconcile 周期中对已有接口的无意义重写。

已撤销 peer 不进入 desired，但重启前留下的连接和 XFRM 资源仍需拆除。Daemon 结合本机/对端身份、配置中的 overlay/namespace、端口 generation 和确定性资源名称重建仅供 teardown 的实例；连接与接口必须匹配，不能仅凭 `ipsec-` 前缀接管资源。旧端口记录仅作为清理线索，不恢复授权或发起连接，轮换中的两代资源一起进入拆除流程。

### 7.3 Routing

- **输入**：common `State.ReadView()` 中的 route announcement / authorization 记录
- **输出**：BIRD 配置文件、Babel 邻居发现、路由导入/导出 filter；在线结果发布到 `LinuxObservation`
- **集成点**：`reconcileRouting(ctx)` 在 routing_reconcile.go 中，构建 `AuthorizedRouteSet`，生成 BIRD 配置并 reconfigure
- **状态范围**：BIRD instance、status、exit 和 backoff 只存在于 daemon 内存 `LinuxObservation`，重启后重新推导/观察

### 7.4 Firewall

- **输入**：common `State.ReadView()` 中的授权路由、本地 firewall 配置
- **输出**：nftables/iptables 规则（netns ingress、host ingress、redirect grace）；在线结果写入 `LinuxObservation`
- **集成点**：`reconcileFirewall(ctx)` 通过 `firewall.BuildDesiredState()` → driver.Apply()
- **状态范围**：Firewall reconcile 结果只存在于 daemon 内存 `LinuxObservation`；`EndpointACLs` 作为用户配置持久化

### 7.5 Health

- **输入**：IPsec reconcile 结果中的期望链路和实际 SAs
- **输出**：ICMP/UDP probe、RTT/loss/jitter 指标；后续可作为 rotate cutover gate 的输入
- **集成点**：`flushIPsecReconcile()` 完成后调用 `reconcileHealth(ctx)`，刷新 health manager 的 probe target 并触发到期的 probe
- **状态范围**：health 结果不写入 gossip active state；后续如需要 signed health hint 需单独设计

探测结果属于派发时的目标实例。同一个 ProbeID 换接口、地址或 generation 后使用新统计窗口，旧结果不能更新新目标的健康状态或轮换门槛。删除目标时，正在运行的探测继续占用并发名额直至结束；同一路径的普通链路状态变化不清空历史。

### 7.6 Observer

- **输入**：common `State.ReadView()` 与 daemon 内存中的 `LinuxObservation`
- **输出**：HTTP API（/api/v1/...）、SSE 事件推送
- **集成点**：`newObserverServer()` 在启动时创建，`observerProvider` 从各自 owner 读取 common state 与在线 observation。状态变化时 daemon 通过 `d.observerHub` 广播 SSE 事件
- **状态范围**：observer 是纯只读的，不修改任何状态
