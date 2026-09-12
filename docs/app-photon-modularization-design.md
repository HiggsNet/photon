# app/photon 模块化设计

> Phase 10 的最新逐文件盘点和 platform runtime 持久化边界见
> [`app-photon-runtime-migration-report.md`](app-photon-runtime-migration-report.md)。本文前半部分保留
> Phase 6.7.7 的历史落地记录；后续迁移以新报告和 Photon Windows 设计中的 GossipDriver 边界为准。

> **文档状态**：Phase 6.7.7 第一阶段已落地；本文继续作为后续模块化约束和演进记录。
> **目标**：将 `app/photon` 从单一巨大 `main` 包逐步拆成清晰的应用模块。`app/photon` 最终只保留 executable wiring、CLI 命令注册、配置装配和少量 daemon live adapter；health、routing、revocation、peer lifecycle、observer、debug/inspect、firewall、IPsec reconcile、sync runtime 等可复用或相对独立的应用逻辑应下沉到 internal/package 模块中。

---

## 1. 背景

`app/photon` 目前已经承担了太多角色：

- CLI 命令入口：`cmd.go`、`record.go`、`route.go`、`ipam.go`、`recovery.go` 等。
- daemon 生命周期和事件循环：`daemon.go`、`daemon_sync.go`。
- sync/gossip runtime：`sync.go`、`sync_session.go`、`packet_demux.go`、`objectpull.go`。
- data-plane reconcile：`ipsec_reconcile.go`、`routing_reconcile.go`、`firewall_reconcile.go`、`health_reconcile.go`。
- 状态与配置：`state.go`、`config.go`、`*_config.go`。
- 诊断和 observer：`diagnostics.go`、`debug_*.go`、`observer_server.go`。
- 安全和生命周期辅助：`peer_state.go`、`revocation_cleanup.go`、`admission_diagnostics.go`。

这些文件都在 `package main` 中，导致几个问题：

1. 子系统可以直接读写 `stateFile`、`appConfig`、`DaemonService` 和其他私有类型，边界不明显。
2. debug/observer/control/CLI 经常重复解释同一份状态。
3. health、routing、firewall、IPsec、revocation、peer lifecycle 的 reconcile 逻辑互相调用或共享私有状态，难以独立测试。
4. 新功能倾向继续加到 `app/photon` 文件里，而不是形成稳定模块。

模块化目标不是一次性把所有类型导出，也不是机械移动文件，而是逐步把“领域纯逻辑、应用服务、读侧诊断、presenter、source adapter”拆开，让 `app/photon` 成为 thin executable layer。

## 1.1 Phase 6.7.7 落地状态

6.7.7 已完成 Observer/debug/inspect 读侧优先重构，可以作为第一阶段关账：

- `internal/observer` 已承接 HTTP routing、SSE、static web、API envelope 和通用 handler 测试；`app/photon/observer_server.go` 保留 daemon provider、health spool/runtime 投影和启动接线。
- `internal/inspect` 已承接 links、zones/records、peers/endpoints、peer lifecycle、routes/BIRD、health、revocation、firewall、admission、rotate、ping、sync status 等只读 view/reason/builder。
- `internal/inspect/http` 已承接 observer 专用 DTO/builder，避免 HTTP schema 直接绑 app 私有 state 或原始 runtime struct。
- `internal/inspect/text` 已承接 CLI debug/sync/status 文本 presenter 和 focused output 测试；`app/photon/debug_*.go` 主要保留参数解析、control socket/live/offline source 选择和 presenter 调用。
- `internal/state` 已承接 peer runtime、link runtime、BIRD/firewall reconcile 等跨 app/inspect 共享的只读 snapshot 类型；app 层通过 alias 表达 state ownership。
- 明确不新增 `internal/debug` 包：debug 是 CLI 命令面，可复用读模型属于 `internal/inspect`，文本输出属于 `internal/inspect/text`。

仍然延后的边界：

- `internal/inspect/source` 暂不急建；control socket、offline DB、live daemon source 仍与 `Runtime`、`DaemonService` 和私有 state adapter 贴得较近，后续等 metrics store / source collector 接口稳定后再抽。
- admission 诊断中涉及 `stateFile`、`autoJoinPending`、join request 编码和 admission state 更新的 adapter 仍留在 app 层；若继续下沉，必须先定义纯 `AdmissionDiagnosisInput`，不能让 inspect 依赖 app 私有协议。
- `sync.go`、`daemon.go`、`ipsec_reconcile.go`、`routing_reconcile.go`、`config.go` 仍是后续模块化主战场，但不属于 6.7.7 阻塞项。
- `DatagramStats`、`ObjectPullStats` 等纯观测计数仍随 `PeerRuntimeState` 持久化，后续应随 metrics/readmodel store 拆出，避免诊断计数推动主 committed state revision。

---

## 2. 分层目标

当前已落地结构更接近“横向抽读侧，写侧暂留 app”：

```text
app/photon
  - main / cmd registration
  - config loading + runtime assembly
  - daemon lifecycle / workspace commit / reconcile / sync runtime
  - command-service wiring and control socket handlers
  - live adapters: inspect_links.go, inspect_peers.go, observer_server.go, debug_*.go
        |
        v
internal/inspect (+ internal/inspect/http, internal/inspect/text)
  - shared read-model / view builders / reason code
  - HTTP JSON presenter / DTO builders
  - CLI text presenter
        |
        v
internal/state
  - runtime state DTOs shared by app and inspect
  - no persistence, no locking, no workspace/commit semantics
        |
        v
pkg/*
  - stable domain libraries
  - wire/protocol/model/planner/driver logic
```

这不是最终形态的全部，但它是当前应遵守的事实边界：读侧已经横切到 `internal/inspect`，写侧、reconcile、daemon lifecycle、config assembly 和 state commit 仍在 `app/photon`。

分层规则：

1. `pkg/*` 继续放稳定领域模型和底层能力，例如 zone、gossip、routing authorization、firewall planner、health manager、transport/ipsec provider。
2. `internal/*` 放 Photon 应用层模块：它可以组合 `pkg/*`，但不应该依赖 CLI 框架、stdout、环境变量散读或 `main` 包未导出类型。
3. `app/photon` 保留 executable glue：命令注册、配置入口、daemon assembly、需要访问未导出状态的临时 adapter。
4. `internal/state` 只放确有跨包共享需求的数据 DTO；IPsec、BIRD 和 firewall 在线 observation 已回归各自领域/daemon 边界，不再为共享方便复制一层 `state` 类型。
5. 所有写路径仍通过 typed owner：common mutation 进入 `core/state.Store`，LinuxState completion 回到 Daemon 并经唯一 BoltStore 持久化；readmodel/inspect 不执行写操作，也不读取未发布 candidate。
6. 每次迁移都要先定义输入/输出结构，避免把 `stateFile` 原样搬进 internal 后形成新的大泥团。

---

## 3. 当前模块状态与后续规划

当前不要按旧设想一次性创建很多垂直 `internal/*app` 包。已落地的主线是：读侧统一收敛到 `internal/inspect`，运行时快照 DTO 放到 `internal/state`，写侧和 lifecycle/reconcile 暂留 `app/photon`。

| 职责 | 当前实际位置 | 后续规划 / 注意事项 |
|------|--------------|---------------------|
| Observer HTTP | `internal/observer` | 已承接 HTTP routing、SSE、static、API envelope 和通用 handler 测试；`app/photon` 保留 daemon provider、health spool/runtime adapter 和启动接线。 |
| Inspect / diagnostics | `internal/inspect` | 已成为核心共享读模型层，横切 observer、CLI debug、control status；新增诊断输出应优先补 inspect view。 |
| HTTP JSON presenter | `internal/inspect/http` | 已承接 observer DTO/builder；HTTP schema 不应直接绑定 app 私有 state 或原始 runtime struct。 |
| CLI text presenter | `internal/inspect/text` | 已承接 debug/sync/status 文本输出；text 包只做 writer/formatter，不定义跨包业务 view。 |
| Runtime state DTO | `internal/state` | 只放 `PeerRuntimeState`、link runtime、BIRD/firewall reconcile 等共享 DTO；不是 `stateFile`、锁、bbolt、workspace 或 commit 层。 |
| Debug ping executor | `internal/ping` | 已作为小型执行模块独立；app 层保留 CLI wiring 和 state/config -> target adapter。 |
| Peer lifecycle | `internal/inspect/peer_lifecycle.go` + `app/photon/peer_state.go` | 状态推导/view 已在 inspect；cleanup 决策、flush 顺序和 state adapter 仍在 app。暂未创建 `internal/peerstate` / `internal/lifecycle`。 |
| Revocation impact / cleanup | `internal/inspect/revocation.go` + `app/photon/revocation_cleanup.go` | revocation view/status 已在 inspect；实际 cleanup、layer flush 和 daemon 顺序仍在 app。暂未创建 `internal/revocation`。 |
| Admission diagnostics | `internal/inspect/admission.go` + `app/photon/admission_diagnostics.go` | reason/view/text 已下沉；auto-join state/key/delegation 检查、join request 编码和 admission state 更新仍在 app。暂未创建 `internal/admission`。 |
| Health app layer | `internal/inspect/health_debug.go`, `internal/inspect/http/health.go` + `app/photon/health_reconcile.go` | view/presenter/context 已下沉；probe manager、spool append/query adapter 和 reconcile lifecycle 仍在 app。暂未创建 `internal/healthapp`。 |
| Routing/BIRD app layer | `internal/inspect/routing.go`, `internal/inspect/http/routes.go` + `app/photon/routing_reconcile.go` | route/BIRD readmodel 和 presenter 已下沉；BIRD process/client lifecycle、config render/apply 和 reconcile timer 仍在 app。暂未创建 `internal/routingapp`。 |
| Firewall app layer | `internal/inspect/firewall.go` + `app/photon/firewall_reconcile.go` | debug view/presenter 和 reconcile snapshot DTO 已下沉； privileged apply、driver construction 和 policy input adapter 仍在 app。暂未创建 `internal/firewallapp`。 |
| IPsec app layer | `internal/inspect/links.go`, `internal/inspect/rotate.go` + `app/photon/ipsec_*.go` | links/rotate readmodel 已下沉； publish/reconcile/cleanup/provider lifecycle 基本仍在 app。暂未创建 `internal/ipsecapp`。 |
| Sync runtime | `app/photon/sync.go`, `sync_session.go`, `daemon_sync.go` | 只有 sync status view/text 和 peer debug runtime view 已下沉；FSM、packet demux、object pull、timer、state apply adapter 仍在 app。暂未创建 `internal/syncapp`。 |
| Control API | `app/photon/control.go` | control socket 和 DTO/client helper 仍在 app；Phase 7.10 可逐步抽 `internal/controlapi`，但 daemon handler registration 留 app。 |
| Config parsing | `app/photon/config.go`, `*_config.go` | 仍在 app；只有等 subsystem 接口稳定后再考虑 focused parser 包。暂未创建 `internal/config`。 |
| App state / commit | `app/photon/state.go`, `state_bolt.go`, `legacy_state.go` | 一个具体 State 管理唯一 StateDB、Common 与 LinuxState；Daemon 不直接持有锁或数据库，旧 schema 单独留在 legacy 文件中，不要把 `internal/state` 误认为完整 app state 层。 |

后续新包名应由实际迁移切口驱动，而不是按旧设计表格预先占坑。优先继续保持：纯 readmodel/view 进 `internal/inspect`，共享 runtime DTO 进 `internal/state`，写侧 adapter 和 daemon commit 留 `app/photon`。

---

## 4. 迁移原则

### 4.1 不直接搬 `stateFile`

`stateFile` 仍是当前耦合中心，但 daemon 读侧事实源已经变成 committed snapshot。迁移时优先定义小 input：

```go
type PeerLifecycleInput struct {
    Now         time.Time
    ManagedZone zone.ZonePath
    Peers       []PeerInput
    Links       []LinkInput
    Revoked     map[zone.ZonePath]bool
}
```

internal 模块吃 input，输出 view/decision。`app/photon` adapter 负责从 common `State.ReadView()`、离线 DB snapshot 或 control socket response 拷贝 committed state；health、BIRD、actual SA 等 live 诊断作为单独 source 汇入 input。adapter 不应把未提交 workspace 或 `stateFile` 锁本身传入 internal。

### 4.2 写侧和读侧分开

- 写侧：daemon event loop、control command service、reconcile apply；对 state 的修改先落在 workspace，只有 commit 成功后才成为读侧事实。
- 读侧：inspect/readmodel、debug/observer/control status；默认读取 committed snapshot，再合并只读 runtime diagnostics。

readmodel 可以输出 `SuggestedAction` / `CommandHint`，但不能直接调用 apply、record put、delegate、reload、cleanup 或 reconcile，也不能通过频繁诊断计数推进 committed state revision。

### 4.3 Presenter 不做推理

CLI text、HTTP JSON、control response 都不应该各自判断 `revoked/stale/offline/up/degraded`。这些状态解释应来自共享 view。

### 4.4 先抽纯逻辑，再抽 adapter

如果某段代码大量依赖 `DaemonService` 或未导出状态，先把纯函数和输出结构抽走，live adapter 暂留 `app/photon`。这样迁移可控，测试也能先落地。

---

## 5. 迁移进度与后续顺序

### 5.1 Inspect/debug/observer 读侧（已基本完成）

优先级高，因为它横跨 observer、debug、control status，同时风险较低：

1. 建立 `internal/inspect`、`internal/inspect/http`、`internal/inspect/text` 骨架；`internal/inspect/source` 延后到 source/fallback 瘦身阶段。
2. 先抽 links：`debug links` 与 `/api/v1/links` 重合最高；links input 优先使用最近一次 committed reconcile snapshot，只有离线/显式 dry-run 才重新 plan desired。
3. 再抽 peer/endpoints：`debug peer`、`sync status --verbose`、`debug peers`、`/api/v1/peers` 共用 endpoint merge 和 lifecycle reason。
4. 再抽 zone/records/admission/revocation。
5. 最后抽 routes/BIRD/firewall/health 的 view 和 presenter。

**当前状态：已完成第一阶段。** 后续新增 observer/debug/control status 输出时，默认先补 `internal/inspect` view，再补 `internal/inspect/text` 或 `internal/inspect/http` presenter；不要在 `app/photon` 重新手写状态推理或 DTO 组装。

### 5.2 Peer lifecycle + revocation（部分完成）

`peer_state.go` 和 `revocation_cleanup.go` 已经像独立模块，但仍依赖 `stateFile`。Peer lifecycle readmodel 和 debug presenter 已先行下沉到 `internal/inspect`；后续如果继续拆，应聚焦写侧 cleanup decision 和 daemon flush ordering：

1. 把 `derivePeerStatus`、cleanup decision、revoked subtree impact 改成 input -> decision。
2. `app/photon` 保留 `stateFile` adapter 和 daemon flush ordering。
3. debug/observer/control 都消费同一 decision/view。

当前状态：

- 已完成：peer lifecycle 状态推导、debug view/text、revocation impact/debug view/status 的读侧下沉。
- 未完成：revocation cleanup 执行、cleanup decision 与 daemon flush ordering 仍在 app。

### 5.3 Health / routing / firewall app 层（部分完成）

这些子系统都有 config、reconcile、debug、observer/control 状态：

1. 先迁移 view/presenter 和 config-to-spec helper。
2. 再迁移不触碰 daemon lifecycle 的 planner input builder。
3. privileged apply、probe manager、BIRD process lifecycle 暂留 app adapter，待接口稳定后再下沉。

当前状态：

- 已完成：health/routing/firewall/BIRD 的 view、HTTP DTO、文本 presenter、部分 reconcile snapshot DTO。
- 未完成：health probe manager/spool lifecycle、BIRD process lifecycle、routing/firewall privileged apply、driver construction 和 reconcile timer 仍在 app。

### 5.4 Sync runtime（未开始写侧迁移）

`sync.go` 仍是最大文件，且耦合传输、状态、CLI 输出、object pull、peer discovery。建议较晚处理：

1. 先保留 event loop wiring 在 `app/photon`。
2. 抽 `SyncSession`、timer、packet demux、peer address ranking、object pull client/pool 到 `internal/syncapp`。
3. `sync status` view/text 已下沉；继续拆时只迁移纯 runtime/FSM，不把 daemon commit adapter 搬进 internal。
4. 再拆旧 `sync.go` 的 transport open、packet handling、state apply adapter。

当前状态：

- 已完成：`sync status` view/text、peer runtime debug view、部分 shared `PeerRuntimeState` DTO。
- 未完成：`sync.go`、`sync_session.go`、`daemon_sync.go`、packet demux、object pull、timer、transport open 和 state apply adapter 仍在 app。

### 5.5 State/config/control（未开始主体迁移）

这是最后处理的核心边界：

1. 先把 control DTO/client helper 下沉到 `internal/controlapi`。
2. 把 per-subsystem config parser 移到对应 internal module，顶层 `appConfig` 只做组合。
3. 评估是否将 `stateFile` 类型移到专门 app state 包。当前 `internal/state` 不是这个包；它只承接运行时 DTO。这一步影响面最大，必须等上面模块已经通过 input/view 降耦合后再做。

当前状态：

- 已完成：旧 `DaemonStateStore` aggregate API 已删除；新的具体 State 只管理唯一 StateDB 和 typed partitions，Common 与 LinuxState 使用独立 detached read 和各自 revision/transaction commit。
- 未完成：`stateFile`、bbolt 持久化、clone、workspace/commit、control socket DTO/client helper、config parsing/assembly 仍在 app。

### 5.6 剩余 app/photon 大文件清单

下一阶段如果继续模块化，应优先从这些文件中选择一个窄切口，而不是同时创建多个空包：

- Sync/runtime：`sync.go`、`sync_session.go`、`daemon_sync.go`、`packet_demux.go`、`objectpull.go`、`timer_manager.go`
- IPsec：`ipsec_reconcile.go`、`ipsec_publish.go`、`ipsec_cleanup.go`
- Routing/BIRD：`routing_reconcile.go`、`routing_reconcile_helpers.go`
- Firewall：`firewall_reconcile.go`
- Health：`health_reconcile.go`、`health_spool.go`
- Lifecycle/security：`peer_state.go`、`revocation_cleanup.go`、`admission_diagnostics.go`
- Control/config/state：`control.go`、`config.go`、`context.go`、`state.go`、`state_bolt.go`、`legacy_state.go`

建议顺序仍然是：先抽纯 input/view/decision，再抽不触碰 daemon lifecycle 的 planner/helper，最后才移动持久化、commit、driver lifecycle 或 privileged apply。

---

## 6. 验证策略

每个迁移批次至少保留：

- 原有 focused smoke，例如 `make observer-smoke`、routing/firewall/health 相关 smoke。
- 相关 package 单测：新 internal module 的 pure tests 应多于 app wiring tests。
- CLI golden/output 测试迁到 presenter 层，app 层只保留参数解析和 fallback/source 选择。
- `go test ./app/photon` 用于验证 executable wiring 未断。
- 对涉及 shared behavior 的迁移，补一组 HTTP/CLI 双入口使用同一 view 的测试。

---

## 7. 非目标

- 不一次性把 `app/photon` 改成很多微包。
- 不为了移动文件而导出所有内部状态。
- 不把写命令放进 readmodel。
- 不把 `pkg/*` 变成应用运行时包；`pkg/*` 仍保持稳定领域/协议/driver 边界。
