# Photon Daemon 设计与实现

> **本文档状态：2026-07**
> 描述 `photon daemon` 的架构、事件循环、单 writer 模式、control socket、reconcile 调度和本机状态管理。不展开 transport、routing、firewall、health 等子模块的内部细节——那些在各自的文档中说明。

Photon daemon 是长期运行的控制循环。它把所有子系统——gossip、admin 写入、端点发布、object pull、transport reconcile、routing reconcile、firewall reconcile、health 和 observer——放在同一个本机控制边界内。

---

## 目录

1. [架构概览](#1-架构概览)
2. [Daemon 结构](#2-daemon-结构)
3. [事件循环](#3-事件循环)
   - 3.1 [Packet Demuxer](#31-packet-demuxer)
   - 3.2 [Timer Manager](#32-timer-manager)
   - 3.3 [Async Object Pull](#33-async-object-pull)
4. [单 Writer 模式与状态管理](#4-单-writer-模式与状态管理)
   - 4.1 [核心原则](#41-核心原则)
   - 4.2 [DaemonStateStore](#42-daemonstatestore)
   - 4.3 [写路径](#43-写路径)
   - 4.4 [Reconcile 与 StateStore](#44-reconcile-与-statestore)
   - 4.5 [状态文件](#45-状态文件)
   - 4.6 [状态变化通知](#46-状态变化通知)
   - 4.7 [状态变更边界](#47-状态变更边界)
   - 4.8 [外部 state 文件监控](#48-外部-state-文件监控)
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
| `App` | `*AppContext` | config、state path、clock 等应用上下文；不是产品 Runtime |
| `gossipDriver` | `*corehost.GossipDriver` | 持有 detached gossip 协议配置、transport/address book 和协议执行闭环；Daemon 不再重复保存 GossipConfig/transport |
| `gossipTransport` | `*gossip.Transport` | 当前 gossip UDP transport |
| `StateStore` | `*DaemonStateStore` | 迁移期 common/Linux 顺序协调器，最终删除 |
| `Events` | `chan daemonEvent` | 统一事件入口（64 buffer） |
| `Interval` | `time.Duration` | 出站 sync 周期（默认 60s） |
| `ControlSocketPath` | `string` | Unix domain socket 路径 |
| `linuxDriver` | `*photonlinux.LinuxDriver` | 持有 IPsec/XFRM/BIRD/firewall/health 平台实现 |
| `health` | `*health.Manager` | 链路健康探测管理器 |
| `observerHub` | `*observer.Hub` | Observer SSE 事件广播 |
| `ipsecDirty` | `bool` | IPsec reconcile 待调度标记 |
| `routingDirty` | `bool` | Routing reconcile 待调度标记 |
| `firewallDirty` | `bool` | Firewall reconcile 待调度标记 |
| `gossipDriver` | `*host.GossipDriver` | 当前 GossipDriver：协议 queue/scheduler/Engine/transport/object-pull owner |
| `objectPullExecutor` | `*host.GossipObjectPullExecutor` | Linux TCP exchange 注入点；worker 生命周期由 GossipDriver 管理 |

**DaemonEvent 类型**（[`daemon.go:70-95`](../../app/photon/daemon.go#L70-L95)）：

事件通过 `daemonEvent` 结构体传递，主要字段包括 `Type`（事件类型）、`Context`（上下文）和 `Reply`（结果通道）。`enqueueEvent()` 把事件放进 `Events` 通道，然后阻塞等待 `Reply` 返回结果。这样，control socket 侧的 admin 操作能拿到明确的完成或失败信号。

主要事件类型：
- `record_put` / `delegate_issue` / `delegate_revoke` — 状态写入
- `delegate_grant` / `recovery_import_zone` / `recovery_purge_revoked` — 权限变更
- `join_accept` — 节点加入；`root_init` 只保留 daemon 侧拒绝入口，用来提示停止 daemon 后执行 direct/recovery 初始化
- `packet` — 收到 UDP gossip 包
- `timer_sync` / `timer_endpoint_publish` — 定时 sync 和端点发布
- `sync_trigger` / `reload_config` — 手动触发
- `ipsec_cleanup` / `ipsec_port_rotate` / `ipsec_lifecycle` — IPsec 生命周期
- `shutdown` — 优雅退出

---

## 3. 事件循环

Daemon 启动流程（[`daemonRun()`](../../app/photon/daemon.go#L1522-L1540)）：

```
daemonRun()
 ├─ NewAppContext()       加载应用配置
 ├─ rt.LoadState()        加载 BoltDB 状态文件
 ├─ openDaemon()          创建 Daemon 与唯一 BoltStore
 ├─ configureIPsecDriversFromConfig()
 └─ service.Run()         进入事件循环
```

`Run()` 方法（[`daemon.go:183-417`](../../app/photon/daemon.go#L183-L417)）：

1. **初始化驱动**：配置 IPsec (StrongSwan VICI + XFRM) 驱动
2. **启动子服务**：
   - `openTransport()` — 开启 UDP gossip 监听
   - `startObjectPullServer()` — 启动 TCP object pull 服务
   - `startControlServer()` — 启动 Unix domain socket 控制服务器
   - `startObserverServer()` — 启动 HTTP observer 服务器
   - `startIPsecLifecycleEventWatcher()` — 监听 StrongSwan VICI 生命周期事件（后台 goroutine 订阅，单次订阅带超时、失败退避重试；VICI 卡死只产生告警日志，不阻塞 daemon 启动）
3. **启动恢复**：

```
// 1. GossipDriver 直接持有 common StateStore owner
d.gossipDriver = corehost.NewGossipDriver(..., d.StateStore.common, ...)

// 2. 本机 endpoint/IPsec/routing 记录通过 typed common mutation 发布
d.prepareStartupState()
d.updateDiscoveredPeers()

// 3. 数据面从 detached common view、LinuxState 和重新 observation 恢复
d.recoverIPsecLinksOnStart(ctx)
d.recoverRoutingOnStart(ctx)
d.recoverFirewallOnStart(ctx)
```

提前释放写锁可避免恢复阶段长时间阻塞 control socket 与 Observer

4. **进入主循环**：

```
for {
    // 1. 处理所有已排队的事件（非阻塞 drain）
    processEvents(ctx)
    
    // 2. 检查磁盘状态文件是否被外部修改
    reloadStateIfChanged()
    
    // 3. 检查端点发布定时器；记录无变更时跳过下游 flush
    handleEvent(endpointTimer)
    
    // 4. 检查 sync 定时器
    handleEvent(syncTimer) + flush IPsec + flush Routing
    
    // 5. 检查 IPsec reconcile 定时器
    flushIPsecReconcile()
    
    // 6. 检查 Routing reconcile 定时器
    flushRoutingReconcile()
    
    // 7. 阻塞等待：事件 / UDP packet / sync event / object pull result / 定时器超时
    select {
        case event:  handleEvent(event)
        case packet: handlePacketEvent → SyncSession FSM
        case syncEvent: handleSyncEvent
        case pullResult: enqueueObjectPullResult
        case timer.C: 继续循环
    }
}
```

**processEvents() 阶段**（[`daemon.go:860-895`](../../app/photon/daemon.go#L860-L895)）：

非阻塞 drain 所有已排队事件，处理完后以 **Phase 6.5 拒绝优先顺序**执行 flush：
1. `flushRevocationCleanup()` — 清理已吊销 zone 的 gossip peer cache
2. `flushFirewallReconcile()` — 刷新防火墙规则
3. `flushRoutingReconcile()` — 刷新路由
4. `flushIPsecReconcile()` — 刷新 IPsec 链路
5. `flushRevocationCleanup()` — 再次清理（flush 中可能发现新的吊销路径）

这个顺序确保吊销的 prefix 和 peer entry 在任何层可能重新接受流量之前从 allow set 中移除。

### 3.1 Packet Demuxer

UDP reader 收到包后，由 Packet Demuxer 按 `peer_id` 路由：

- 命中活跃 `SyncSession` 的包 → `PacketEvent`，交给该 session 的 FSM。
- 未命中的包 → `UnsolicitedPacketEvent`，由事件循环里的只读 responder / hint ingress 处理：
  - `PING` / `FETCH_CATALOG_PAGE` / `FETCH_ZONE` / `FETCH_RECORD`：直接读取 committed snapshot 并回复。
  - `ANNOUNCE`：记录 hint，必要时创建或唤醒 active pull session。

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
2. 事件循环把请求塞进 `objectPullPool`。
3. Worker 完成 TCP 连接、读取 MessagePack 响应后，把结果发回 `objectPullResults` channel。
4. 事件循环将结果转成 `ObjectPullResultEvent`，交给对应 session。

`SyncSession` 跟踪每个 zone 的 inflight pull，避免对同一个对象重复请求。

---

## 4. 单 Writer 模式与状态管理

### 4.1 核心原则

Daemon 是在线进程唯一的平台 mutation 编排者。CLI admin 操作（如 record put、delegate issue）不会绕过在线 daemon 另开 BoltDB，而是通过 control socket 把请求发给事件循环，再提交给对应 typed owner。

这样可以避免多个写者同时修改同一份本地状态。

### 4.2 当前状态 owner

Daemon 当前组合三个真实 owner：

- `pkg/core/state.Store`：VerifiedState 与 loss-tolerant GossipCheckpoint；
- `internal/photonlinux.RuntimeState`：待收缩的 Linux 本地持久 state；
- 唯一 `state.BoltStore`：同一进程的 bbolt handle 和事务边界。

`DaemonStateStore` 只在迁移期为 common mutation 与 Linux completion 提供顺序锁、detached read 和 candidate commit，已经不拥有聚合 `stateFile` 快照。终态由 Daemon 直接持有 StateStore、LinuxState、LinuxObservation、LinuxDriver 和 BoltStore，然后删除该协调器。完整边界见 [`runtime-state-ownership.md`](../runtime-state-ownership.md)。

### 4.3 写路径

本地 admin intent 和 GossipDriver 接受的远端 verified state 进入公共 StateStore；平台 reconcile completion 只更新 LinuxState。两者都必须先由唯一 BoltStore 持久化，再发布对应内存状态。耗时 Observe/Plan/Apply 可在状态锁外执行，但 completion 要回到 Daemon owner；磁盘中的上次平台结果不能冒充当前 observation。

### 4.4 Reconcile 与 Observation

IPsec、routing、firewall 使用 `Observe -> Plan -> Apply -> Re-observe`：desired 来自 VerifiedState、配置和最小 LinuxState，实际 SA/route/BIRD/firewall/health 状态只存在于在线 Daemon 的 LinuxObservation。CLI/HTTP 查询平台运行状态必须经过在线 Daemon；离线只允许读取 verified/common 与明确标记的 GossipCheckpoint last-known 数据。

### 4.5 持久化分区

状态持久化在唯一 BoltDB 文件中：common verified、common gossip-checkpoint 与 linux/state 使用不同 bucket，但共享一个 handle。旧 `stateFile/stateMeta` 仅供旧库单向 migration 和 legacy dump；不再参与在线读写，停止支持旧 schema 时整组删除。

### 4.6 状态变化通知

`notifyStateChanged()`（[`daemon.go:1426-1462`](../../app/photon/daemon.go#L1426-L1462)）：

当状态变化时（sync 成功应用了 Zone snapshot、admin 写入 record 等），daemon 会：
1. 调用 `OnStateChanged` hook（测试用）
2. 通知 observer 推送 SSE 事件
3. 执行 `flushRevocationCleanup()`（拒绝优先）
4. 设置所有 dirty 标记并依次 flush：firewall → routing → IPsec
5. 完成后再次清理 gossip peer cache

### 4.7 状态变更边界

**所有状态变更只允许在 daemon 事件循环 goroutine 中发生**。`SyncSession.OnEvent` 只读当前状态并输出动作列表，动作由事件循环统一执行。这样事件循环本身就是锁，不需要额外对 `NetworkState` 加锁。

必须在事件循环内串行执行的状态变更：

- `NetworkState` apply：`ApplySnapshot`、`ApplyRecordSnapshot`
- peer runtime 更新：sync 状态、观测地址、backoff、last error
- `saveState()` 落盘
- `Transport` 运行时表更新：`AddKnownPeerID`、`SetPeerAddrs`、`SetObservedPeerPaths`
- IPsec / routing / firewall 的 desired-state 计算与 reconcile 触发
- `udpChunkAssemblies`、`rejectedDigests` 等运行时缓存

可以在 worker goroutine 中执行、但结果必须以事件回注的：

- UDP 读包（单 reader，已在事件循环入口）
- TCP object pull 的网络 I/O
- DNS 解析
- 较重的批量 crypto verify（结果以事件回注）

任何 worker 都不应直接持有 `stateFile`、`NetworkState` 或 `Transport` 的可变引用。

### 4.8 外部 state 文件监控

Daemon 运行期间，推荐所有写操作都通过 control socket。如果外部程序直接修改了 BoltDB 文件，daemon 通过 `fsnotify` / `inotify` 监控该路径：

- 文件内容变化（mtime / size / digest 任一变化）→ post `StateFileChangedEvent` 到事件循环。
- 事件循环收到后 `loadState()`；若 digest 变化则 `ReplaceCommitted()` 并 `notifyStateChanged()`，立即触发 outbound sync 和 relay。

`saveState()` 写盘前会对 state 文件加 `flock`（互斥锁）。外部工具若也遵守 `flock`，可避免并发写；不遵守则至少 daemon 写期间不会被覆盖。多个 writer 同时绕过 control socket 直接写 state DB 是未定义行为。

### 4.9 状态持久化边界

旧代码在收包路径里用 `defer saveState()`，落盘时机隐式。当前设计明确只在以下时机落盘：

- `SyncSession` 进入 `Completed` 或 `Failed`
- 应用 `ANNOUNCE` / object pull 结果后 digest 发生变化
- control / admin 事件处理完成后

以下情况不落盘：

- 单纯收到 `PING` / `PONG` 且状态未变
- chunk 接收但未完整重组
- timer 触发但状态未变

所有落盘都在 daemon 主 goroutine 串行执行。

---

## 5. Control Socket

Daemon 通过 Unix domain socket 暴露控制接口。

- root 默认路径 `/run/photon/photon.sock`，非 root 默认 `<data_dir>/photon.sock`，`PHOTON_CONTROL_SOCKET` 可覆盖
- 协议是简单 JSON request/response
- 安全边界只有 Unix 文件权限（父目录 `0700`，socket `0600`），**没有应用层方法级鉴权**

CLI 通过 `sendControlRequest()` 与 daemon 通信。daemon 在线时，写操作进入事件循环由单 writer 串行执行；读操作从当前状态快照返回。

当 socket 不存在或连接被拒绝（`ECONNREFUSED`）时，只读诊断命令可回退到本地 DB 离线视图，持久状态写入命令可走 direct/recovery 路径。超时、权限错误、连接重置、协议错误等不会触发 fallback，因为这些错误可能来自仍在线但异常的 daemon。

状态写入类命令和恢复类命令支持显式 `--direct`，跳过 control socket 直接写本地 DB。使用 direct 时调用者需自行保证没有 daemon 在管理同一状态文件或 IPsec/XFRM 对象；direct 只持久化 signed record，不会触发 routing reconcile。

控制方法覆盖状态读写、delegation 管理、节点加入、恢复操作、runtime 触发（`sync_trigger`/`reload`/`routing_reload`/`shutdown`）以及各类诊断接口。完整列表见 `app/photon/daemon.go` 中 `handleControlConn` 的 switch。

### 5.1 systemd 运行约定

仓库提供 [`contrib/systemd/photon.service`](../../contrib/systemd/photon.service) 示例。service 使用 `RuntimeDirectory=photon` 创建 `/run/photon`，因此不需要预先手工创建运行目录，也不需要单独的 `.socket` unit。当前 daemon 自己创建并管理 Unix socket，尚不支持 systemd socket activation。

安装后至少需要确认：

- `ExecStart` 指向实际安装的 `photon` 二进制；
- `/etc/photon/config.yaml` 和 identity/private key 仅允许运行用户读取；
- 如果启用 StrongSwan/XFRM、netns 或防火墙 apply，service 需要相应的 root/capability 权限；
- root CLI 与 daemon 使用相同的 `PHOTON_CONFIG`，从而共同定位 `/run/photon/photon.sock` 和同一份状态。

示例使用 `Restart=on-failure`、`RestartSec=2s` 和 `TimeoutStopSec=30s`：异常退出会重启；正常 shutdown 或 `SIGTERM` 不会重启；停止超过 30 秒后才强制结束。

control socket 先启动、后于 Observer 停止。任一服务启动失败都会终止启动并清理已有 listener。control socket 使用父目录 `0700`、socket `0600`，只允许 root 管理，不做方法级鉴权。

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

签名状态、peer sync 状态和 reconcile 快照写入 BoltDB；socket、连接、内存事件和进行中的 sync session 不持久化。正常关闭使用 `photon daemon --shutdown` 或 `SIGTERM`。

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
1. `notifyStateChanged()` — 任何状态变化后
2. `processEvents()` — 处理完事件队列后
3. IPsec lifecycle 事件到达时

### 6.2 Flush 方法

每个子系统有对应的 flush 方法：

- `flushIPsecReconcile(ctx)` — 检查 `ipsecDirty`，调用 `reconcileIPsecLinks(ctx)`，之后调用 `reconcileHealth(ctx)` 刷新健康探测目标
- `flushRoutingReconcile(ctx)` — 检查 `routingDirty`，调用 `reconcileRouting(ctx)`
- `flushFirewallReconcile(ctx)` — 检查 `firewallDirty`，调用 `reconcileFirewall(ctx)`

Flush 方法返回 `bool` 表示是否确实执行了 reconcile。

### 6.3 周期性定时器

即使没有事件触发，IPsec 和 routing 也有周期性 reconcile：

- IPsec reconcile 周期：默认 60s，可通过 `overlays[*].reconcile.interval` 配置
- Routing reconcile 周期：30s（由 `defaultRoutingReconcileInterval` 定义）
- 当 link group 数为 0 且没有链路实例时，IPsec reconcile 定时器关闭（返回 0）
- 当 routing 实例数为 0 时，routing reconcile 定时器关闭

### 6.4 Phase 6.5：拒绝优先顺序

```
flushRevocationCleanup()  // 1. 清理 gossip peer cache
flushFirewallReconcile()   // 2. 防火墙（allow set）
flushRoutingReconcile()    // 3. 路由
flushIPsecReconcile()      // 4. IPsec
flushRevocationCleanup()   // 5. 再次清理
```

吊销优先于任何允许操作。被吊销 zone 的 peer 必须先从 endpoint cache、observed path、object-pull 候选中被清除，这样后续的防火墙 / routing / IPsec reconcile 才不会继续考虑它。

### 6.5 同一事件队列的 sync-trigger 链

```
record_put
  → handleRecordPutEvent: 写入签名 record
  → notifyStateChanged: 设置 dirty 标记 + flush 子系统
  → processEvents drain 中: flush revocation → firewall → routing → ipsec

sync timer
  → handleSyncTimerEvent: 加载新状态 + 为每个出站 peer 启动 SyncSession
  → SyncSession FSM 完成 → completeSyncSession
    → notifyStateChanged（如果有变化）
    → relaySyncToPeers: 通知其他 peer

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
- **输出**：GossipDriver 直接调用公共 StateStore 的 remote batch/checkpoint API，并通过同一 transport 发送协议响应
- **集成点**：`pkg/core/host.GossipDriver` 是当前 GossipDriver，拥有 Engine、协议 queue/scheduler、transport、object-pull、chunk/session runtime 和 gossip observability；Daemon 只消费其事件并接收需要触发平台 reconcile 的终态结果
- **状态范围**：verified signed facts 进入 VerifiedState；retry/backoff/observed endpoint 等 restart hint 进入 GossipCheckpoint；session/chunk/address book 等只在内存

**稳态 unsolicited ping 短路**：收到对端主动发来的 `MessagePing` 时，如果 ping 携带的 catalog root 与本端一致，`maybeShortcutSyncFromPingSummary` 直接记录 peer sync 状态并返回，不再创建 SyncSession。只有 root 不一致或 summary 生成失败时，才回退到完整 sync round。respondPing 仍正常回复 PONG，让对端拿到本端 summary。

### 7.2 IPsec Transport

- **输入**：detached VerifiedState、最小 LinuxState、本地配置和 LinuxDriver observation
- **输出**：StrongSwan IKE child SA、XFRM interface、network namespace 内接口；只有不可重建的最小 journal 才写 LinuxState
- **集成点**：Daemon 编排 reconcile，`internal/photonlinux.LinuxDriver` 直接执行 SA/XFRM observe、apply 和 cleanup；实际 SA、动作和错误进入内存 Observation
- **状态范围**：Link instance 与 reconcile 结果只存在于 daemon 内存 `LinuxObservation`，不进入 state file 或 gossip

**XFRM 维护短路**：在 `maintainExistingXFRMInterfaces` 中，如果 observed 状态与期望状态已经匹配，则跳过 `EnsureInterface`/`AssignAddress` 等冗余命令，只保留诊断地址分配。这减少了 reconcile 周期中对已有接口的无意义重写。

### 7.3 Routing

- **输入**：common `StateStore.ReadView()` 中的 route announcement / authorization 记录
- **输出**：BIRD 配置文件、Babel 邻居发现、路由导入/导出 filter；在线结果发布到 `LinuxObservation`
- **集成点**：`reconcileRouting(ctx)` 在 routing_reconcile.go 中，构建 `AuthorizedRouteSet`，生成 BIRD 配置并 reconfigure
- **状态范围**：BIRD instance、status、exit 和 backoff 只存在于 daemon 内存 `LinuxObservation`，重启后重新推导/观察

### 7.4 Firewall

- **输入**：common `StateStore.ReadView()` 中的授权路由、本地 firewall 配置
- **输出**：nftables/iptables 规则（netns ingress、host ingress、redirect grace）；在线结果写入 `LinuxObservation`
- **集成点**：`reconcileFirewall(ctx)` 通过 `firewall.BuildDesiredState()` → driver.Apply()
- **状态范围**：Firewall reconcile 结果只存在于 daemon 内存 `LinuxObservation`；`EndpointACLs` 作为用户配置持久化

### 7.5 Health

- **输入**：IPsec reconcile 结果中的期望链路和实际 SAs
- **输出**：ICMP/UDP probe、RTT/loss/jitter 指标；后续可作为 rotate cutover gate 的输入
- **集成点**：`flushIPsecReconcile()` 完成后调用 `reconcileHealth(ctx)`，刷新 health manager 的 probe target 并触发到期的 probe
- **状态范围**：health 结果不写入 gossip active state；后续如需要 signed health hint 需单独设计

### 7.6 Observer

- **输入**：common `StateStore.ReadView()` 与 daemon 内存中的 `LinuxObservation`
- **输出**：HTTP API（/api/v1/...）、SSE 事件推送
- **集成点**：`newObserverServer()` 在启动时创建，`observerProvider` 从各自 owner 读取 common state 与在线 observation。状态变化时 daemon 通过 `d.observerHub` 广播 SSE 事件
- **状态范围**：observer 是纯只读的，不修改任何状态
