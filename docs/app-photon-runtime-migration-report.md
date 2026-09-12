# `app/photon` Runtime 迁移盘点

> 初始盘点基线：`3aa43fb`（2026-08-27）；进度复核：2026-08-28 E2g
> 范围：`app/photon` 下 76 个非测试 Go 文件  
> 目标：说明每个文件当前职责、最终归属，以及 State、GossipDriver、LinuxState、LinuxDriver、Observation 和 presentation 之间的边界。冻结术语见 [`runtime-state-ownership.md`](runtime-state-ownership.md)。

## 1. 最终分层

| 层 | 所有权 |
|---|---|
| `app/photon` | Linux Daemon、唯一顶层事件循环、executable 入口、CLI 注册和依赖装配 |
| `pkg/core/host` | 公共 GossipDriver：协议事件队列、gossip scheduler/action、transport、object-pull 和协议 worker completion |
| `pkg/core/gossip` | wire codec、同步 FSM/session、chunk、object-pull 协议和 endpoint discovery |
| `pkg/core/state` | verified state、`GossipCheckpoint`、typed intent、签名验证和公共事务 |
| `pkg/core/zone` | authority、delegation、revocation、record 和 Network 等最低层模型 |
| `internal/photonlinux` | LinuxDriver、LinuxState codec，以及 Linux IPsec、routing、firewall、health 的具体实现 |
| `internal/observability` | 可丢失的实时统计和诊断 |
| `internal/inspect` | 只读 view；不拥有 mutable store |
| `internal/controlapi` | 平台无关 Command/Response DTO；Unix socket/named pipe 是平台 adapter |
| `internal/photoncli` | CLI 参数、文件导入导出、输出和显式离线调用 |
| `internal/photonlinux/migration` | 旧 Linux 数据库单向升级；不提供反向映射或兼容写入 |

固定依赖方向：

```text
app -> host -> gossip -> state -> zone
app -> Linux controllers
observer/CLI -> inspect/read model
```

迁移不能把当前大文件原样搬到另一个目录。`daemon.go`、`state.go`、`sync.go`、`ipam.go` 等文件同时包含多层职责，必须先按输入、输出和 owner 拆开。

## 2. Platform runtime 是否需要持久化

### 2.1 结论

Platform controller 必须满足幂等、可重试和最终收敛的 reconcile 合约。持久化不是默认要求：只要一个值能够从配置、verified record 和当前系统 Observe 唯一重建，就不应再在 platform runtime 中保存第二份。

当前字段应按以下规则重新分类：

| 内容 | 是否需要 platform 持久化 | 原因 |
|---|---|---|
| BIRD PID file/control socket/config path | 不需要 | 从 routing 配置和稳定目录规则直接推导 |
| BIRD config hash | 不需要 | 从本轮生成的配置重新计算，并与磁盘文件/运行实例比较 |
| StrongSwan connection/child name | 不需要 | 从 transport/link ID 和 generation 稳定推导 |
| resource owner/token | 不需要 | 从 manager、group、link、transport 等稳定输入推导 |
| XFRM if_id/interface name | 不需要 | 已有稳定 hash/命名函数；也可通过 XFRM Observe 验证 |
| reqid、实际 SA、实际进程状态 | 不需要 | 属于外部 observed state，每次启动重新查询 |
| port generation | 不需要 | 当前 verified port record 已包含 generation、range、更新时间和 previous grace；自动/手动轮换直接从它恢复，发布失败也不会产生必须单独保存的 staged generation |
| 配置文件中的 Endpoint ACL | 不需要 | 配置文件是 desired source of truth |
| CLI 动态创建且要求跨重启保留的 Endpoint ACL | 需要 | 当前产品选择“持久本机配置”语义；它不在配置和 gossip 中，系统规则也不能无损还原 selector intent |
| 随机生成的 IPsec transport private key | 需要 | 当前产品选择跨重启保持 transport identity；gossip 只有公钥且没有独立 key-file owner，不能反推出私钥 |
| LastError、LastRun、action/skip、backoff | 不需要保证 | 属于 diagnostics/observability；可丢失，不参与 reconcile 正确性 |

因此目标不应是建立一个内容越来越多的 `PlatformCheckpoint`，而应尽量删除 platform runtime 字段。只有无法推导、无法 Observe、且产品明确要求跨重启连续的本机值才持久化。

当前审计已删除重复的 `IPsecPortRecord` runtime 缓存，并明确保留 transport private key 与动态 Endpoint ACL。若未来把 transport key 迁入独立 key-file owner，且产品另行改为 ACL 重启丢失或配置托管语义，`photon:linux-runtime` 才可能继续缩到没有 correctness-critical payload；这不影响公共 `VerifiedRevision`。

### 2.2 幂等是 controller 的硬性要求

每个 controller 应优先暴露收敛操作：

```text
Observe(current external state)
Plan(verified view, local desired state, observed state)
Ensure/Delete(stable resource identity)
Observe again
Commit completion(source verified revision)
```

`Ensure` 重复执行必须安全；`Delete` 对不存在资源也应成功；resource name、owner tag、if_id、netns 和 connection name 必须稳定推导。`reqid` 等由外部系统分配的值应通过 Observe 获取。外部系统和 bbolt 无法组成原子事务，因此数据库中的“已完成”标记不能代替重新 Observe。

### 2.3 BIRD PID 的具体处理

不应把数值 PID 当作持久真相，因为 PID 会复用；PID file 路径本身也不需要写进 runtime state，因为它已经由 routing 配置和稳定目录规则确定。control socket、config path、owner token 和 router ID 同理都可重算。

重启后 controller 应根据当前配置计算精确 PID file/control socket 路径，读取并校验进程、owner、netns 和 control socket；校验失败就清理该明确路径下的陈旧资源并重新 start。这里应按稳定 owner 和精确路径查找，而不是无边界扫描目录后接管名字相似的进程。

当前 `BirdInstanceState` 中的 `PIDFile`、`ControlSocket`、`Owner` 和 `LastConfigHash` 可以作为迁移期诊断缓存，但不应成为最终持久化依赖。

### 2.4 崩溃顺序

对于会公开到 gossip 的本机运行事实，使用以下顺序：

1. 从配置、verified record 和 Observe 重建 desired state；
2. 如存在明确要求跨重启连续、且无法推导的本机值，先持久化该最小值；
3. 幂等应用外部资源；
4. 重新 Observe 确认；
5. 发布或更新公共 record；
6. diagnostics 只写 observability，不能决定下次是否跳过 Observe。

IPsec transport key 有两种都正确的产品策略：持久化私钥以维持 transport identity；或者只保存在内存中，每次启动生成新 key 并立即替换公开 record。后一种会带来重启后的 SA 重建和传播窗口，但不要求 platform 持久化。port generation 则可直接从 verified port record 恢复。BIRD/路由规则始终以 Observe 为准。

### 2.5 建议拆分当前 Linux runtime payload

当前单一 JSON payload 可以继续作为迁移期实现，但目标应先删除所有可推导和可 Observe 字段，而不是马上把它们拆成更多持久 bucket。清理后如果仍存在跨重启连续值，只保留：

```text
local-desired        不在配置文件中、但产品要求跨重启保留的本机配置
continuity           无法推导、但产品要求保持的随机生成值
operations           极少数确实无法改造成幂等/可观察操作的 journal
```

`recovery` 和 `diagnostics` 默认不持久化；需要重启后展示时可以进入独立、可整体丢弃的 observability spool。若 transport key 选择重启轮换、动态 ACL 选择重启丢失，并且不存在不可安全重放操作，Linux runtime bucket 最终可以删除。

## 3. 逐文件迁移清单

### 3.1 Admission、authority、daemon

| 文件 | 当前作用 | 最终位置 / 层 |
|---|---|---|
| `admission_diagnostics.go` | auto-join 诊断 | 保持纯投影：从 VerifiedState 与 GossipCheckpoint 即时生成 `internal/inspect` DTO；不再持久化 admission snapshot，CLI wrapper 后续进 `internal/photoncli` |
| `authority.go` | 权限解析、delegate grant、旧 direct 修改 | CLI 进 `internal/photoncli`；权限合并/epoch/父子 authority 更新成为 `pkg/core/state` intent；旧 direct writer 删除 |
| `state_bolt.go` | 组合 Common 与 LinuxState 的启动加载 | 启动已优先读取新 schema，仅未初始化时进入旧 bootstrap/migration；唯一 StateDB 随后交给具体 State 管理 |
| `cmd.go` | Linux CLI 命令树 | 留 `app/photon` 但缩成注册；handler 进 `internal/photoncli` |
| `config.go` | 混合解析 gossip、identity 和全部 Linux subsystem | 顶层 YAML 进 `internal/photonlinux/config`；公共参数转换为 host/gossip config；各 Linux 配置归各 controller |
| `control.go` | 私有 DTO、Unix socket client、命令 wrapper 和部分 view | DTO 进 `internal/controlapi`；Unix transport 进 `internal/photonlinux/control`；CLI/view 分别进 photoncli/inspect |
| `cpu_profile.go` | daemon CPU profile 生命周期 | `internal/runtimeprofile` 或薄 app helper；不属于状态层 |
| `daemon.go` | event loop、控制服务、admin mutation、publisher、controller 生命周期 | sync/endpoint/IPsec/routing/firewall/health 周期 deadline 由 Daemon 自己的 Scheduler/queue 管理；GossipDriver 只投递协议事件，Unix control 和 Linux controller 继续下沉，最终只留 composition root |
| `daemon_common_intent.go` | control DTO 到公共 intent 的转换 | typed control command 落地后删除，不保留永久 adapter |
| `daemon_gossip.go` | Daemon 到 GossipDriver 的配置适配、lifecycle suppression 与 discovery 刷新触发 | 规划、checkpoint patch、persist-before-publish 和地址簿更新已进 GossipDriver；地址簿是可重建的公共 transport runtime state。 |
| `daemon_object_chunk.go` | 已删除 | chunk assembly、repair deadline、snapshot decode/root check、reject checkpoint 和 completion 回投已归 GossipDriver；剩余 sent-chunk/NACK repair 随 F0e3b 从 `sync.go` 收口 |
| `daemon_runtime_commit.go` | 已删除 | 原函数只做 nil guard 和单次转发；调用方现直接进入 typed Linux runtime commit，后续整体迁入 platform owner |
| `daemon_state_store.go` | 已删除 | 旧 aggregate/forwarding Store 不再存在；`state.go` 用一个具体 State 管理唯一 StateDB 与 typed partitions，protocol publish 只负责编排私钥先于公共 record 持久化 |
| `daemon_sync.go` | GossipDriver 终态结果到 Linux reconcile 的接线 | gossip packet/session FSM、发送、observed checkpoint、relay、日志和 observability 已在 GossipDriver 闭环；daemon 不再提供 gossip I/O/controller adapter |

### 3.2 DB、debug 和 diagnostics

| 文件 | 当前作用 | 最终位置 / 层 |
|---|---|---|
| `debug_db.go` | 离线 dump 公共、旧和 Linux state bucket | 公共 dump 进 `internal/stateinspect`；Linux dump 进 `internal/photonlinux/inspect`；CLI 进 photoncli |
| `debug_cmd.go` | debug 命令注册 | app 或 `internal/photoncli`，只注册命令 |
| `debug_endpoints.go` | signed endpoint 展示 | 采集只在协议发布路径执行；inspect 直接从 verified `sync/endpoint/*` record 投影实际发布结果，查询和离线读取均不重新探测；CLI wrapper 后续进 photoncli |
| `debug_firewall.go` | firewall 实时诊断 | observe 进 Linux firewall；view 进 inspect；CLI 进 photoncli |
| `debug_format.go` | 时间/空值格式化 | 合并到 `internal/inspect/text` |
| `debug_links.go` | IPsec/BIRD link 展示 | Linux live query 进 controller；view 进 inspect；CLI 进 photoncli |
| `debug_peer.go` | 合并 verified/checkpoint/observability 的单 peer 诊断 | `internal/inspect`，从稳定 ReadModel 取数 |
| `debug_peers.go` | peer lifecycle 列表 | `internal/inspect` + photoncli |
| `debug_ping.go` | peer ping CLI | 执行继续由 `internal/ping`；本文件缩成 photoncli adapter |
| `debug_revoke_impact.go` | revocation 影响展示 | 公共 purge plan 来自 state，平台影响由 controller 补充，view 进 inspect |
| `debug_rotate.go` | IPsec port rotate 和诊断 | plan 进 IPsec publisher/controller；runtime mutation 进 Linux IPsec；展示进 inspect |
| `debug_routing.go` | BIRD/Babel/routes 查询和解析 | Linux BIRD adapter 进 routing controller；view/text 进 inspect |
| `debug_routing_ip.go` | netns 中执行 Linux `ip route` | `internal/photonlinux/routing` diagnostics |
| `debug_zone_records.go` | zone/record 展示 | Store read API + `internal/inspect`/text |
| `diagnostics.go` | gossip event 到日志 | 稳定事件名留 gossip；logger adapter 进 host/internal logging |

### 3.3 Firewall、health、identity、IPAM、IPsec、join

| 文件 | 当前作用 | 最终位置 / 层 |
|---|---|---|
| `endpoint_acl.go` | ACL CLI、验证、resolve 和 firewall runtime mutation | Linux firewall model/controller；CLI/control 留 adapter；属于 platform desired runtime |
| `firewall_config.go` | nftables/iptables/netns/hook 配置 | `internal/photonlinux/firewall/config` |
| `firewall_reconcile.go` | firewall plan/apply/completion | `internal/photonlinux/firewall` PlatformController |
| `forwarding_config.go` | Linux forwarding policy | Linux firewall/routing config |
| `gossip_checkpoint_migration.go` | 旧 SyncPeers 到 GossipCheckpoint | `internal/photonlinux/migration`；仅由旧数据库单向迁移调用，不属于在线兼容层；只有明确停止支持旧 schema 时才删除 |
| `health_config.go` | probe/hysteresis/metrics 配置 | 通用类型留 `pkg/health`；Linux YAML 进 Linux health config |
| `health_reconcile.go` | health manager 装配、快照发布和 CLI 展示壳 | manager/状态机留 `pkg/health`；raw ICMP、setns、exec fallback 在 `internal/photonlinux/healthprobe`；tick/completion 已进入 Daemon scheduler/event loop；`LinkOutput -> ProbeTarget` 规则已进 `internal/photonlinux/linkstate` |
| `health_spool.go` | JSONL health 历史和查询 | 已整体迁入 `internal/observability/healthspool` 并删除 app 文件；不属于 state/checkpoint |
| `identity_bootstrap.go` | identity key/config、pending auto-join bootstrap 和 refresh | 空库直接初始化 current common/Linux partitions：common 保存 trusted root、identity key 与 authority-less managed-zone placeholder，runtime 保存 canonical key path；不再写临时 legacy schema，正式 root pin/private-key/managed-zone entry 校验不放宽 |
| `init.go` | root 初始化 | 已直接原子初始化 common/Linux buckets，不再写 legacy aggregate schema；文件/CLI 壳后续进 photoncli |
| `inspect_links.go` | Linux link 到 inspect input | Linux controller 输出稳定 DTO，view 进 inspect |
| `inspect_peers.go` | verified/checkpoint/bootstrap/observability endpoint view | `internal/inspect`，不再依赖 stateFile |
| `ipam.go` | IPAM CLI、旧 mutation 和报告 | mutation 只调 state intent；报告进 inspect；CLI 进 photoncli；旧 apply 函数删除 |
| `ipsec_cleanup.go` | StrongSwan/XFRM cleanup 的 CLI 与装配 | owner 校验、link teardown、缺失资源幂等和 orphan cleanup 已作为唯一 `photonlinux.LinuxDriver` 的真实方法迁入 `internal/photonlinux/ipsec_cleanup.go`；online cleanup、IPsec reconcile、lifecycle watcher 与 purge 复用该实例，只有 direct 命令临时创建；driver 在配置构造时明确选择，不在运行中隐式补 DryRun；direct cleanup 已写 Linux runtime owner、不再写旧 stateFile；剩余 control/CLI 进 photoncli |
| `ipsec_publish.go` | transport key/address/port/overlay record 和私有 runtime | record 构造进 transport/state publisher；只有无第二来源的 transport private key 进入 platform runtime，port generation 从 verified record 恢复；排序由 host 保证 |
| `ipsec_reconcile.go` | StrongSwan/XFRM/SA/rotation reconcile | app 仅保留协议规划、rotation 编排与结果提交；SA live observation、action apply、lifecycle subscription，以及 XFRM batch observe、missing-link filter、diagnostic address、drift repair 都直接实现为唯一 `photonlinux.LinuxDriver` 的方法，并按 `linux_driver.go`、`xfrm.go`、`ipsec_cleanup.go` 分文件组织；没有再套平台聚合层或逐方法代理，迁移期 `XFRMDriver()` 访问口已删除 |
| `join.go` | join DTO、issue/revoke/accept、key/bundle、旧 direct writer | DTO/验证进 state admission；文件 CLI 进 photoncli；全部 mutation 复用 Store；旧 writer 删除 |

### 3.4 Key、link、logging、object-pull、observer、peer

| 文件 | 当前作用 | 最终位置 / 层 |
|---|---|---|
| `keygen.go` | Ed25519 key 文件生成 | `internal/photoncli/keygen`，底层复用 crypto |
| `link_outputs.go` | Linux link runtime 到 health/routing output | `internal/photonlinux/linkstate` 或 IPsec controller 输出 DTO |
| `linux_state_view.go` | 已删除 | gossip checkpoint 的生产调用方已直接读取公共 typed owner；Linux runtime clone 并入 `state_clone.go`，旧 peer read model 只留在 legacy migration 测试 fixture |
| `logging.go` | app logger 实现 | host 定义 Logger interface；Linux 实现进 internal logging |
| `main.go` | executable 入口 | 永久留 `app/photon`，只负责装配/退出码 |
| `observer_config.go` | Observer 配置 | 模型进 observer；Linux YAML 进 Linux config |
| `observer_server.go` | HTTP/OpenMetrics/SSE provider wiring | server/read model 进 observer；Linux app 只注入 provider |
| `peer_lifecycle_cleanup.go` | peer 过期、checkpoint/observability/platform cleanup | policy/调度进 host；checkpoint 由 state 删除；平台资源通过 action 清理 |
| `peer_state.go` | peer lifecycle 状态推导 | view 进 inspect；参与调度的纯 policy 进 host |

### 3.5 Record、recovery、routing、state、sync 和基础 CLI

| 文件 | 当前作用 | 最终位置 / 层 |
|---|---|---|
| `record.go` | record CLI 和查询 | mutation 只调 state intent；旧 aggregate 本地签名 helper 已移到 test-only fixture；查询进 inspect，CLI 进 photoncli |
| `recovery.go` | export/import/pull/purge 和 Linux cleanup | export/import/pull/purge 已通过唯一 BoltStore、common Store typed API 与 Linux runtime candidate 完成，不再读写旧 Network；继续把平台 cleanup 交 controller，CLI 进 photoncli |
| `revocation_cleanup.go` | impact、typed peer cleanup policy、purge plan | 未接线的旧 aggregate peer-cache mutator 已删除；verified/checkpoint purge 留 state，平台 cleanup 变成 host action，view 进 inspect |
| `root.go` | root public key CLI | Store read API + photoncli |
| `route.go` | route CLI、旧 direct mutation、报告 | mutation进 state intent；授权计算留 routing；报告进 inspect；CLI 进 photoncli |
| `routing_config.go` | netns/BIRD/Babel/upstream config | `internal/photonlinux/routing/config` |
| `routing_reconcile.go` | BIRD/netns/veth/upstream、health、auto announce | Linux reconcile 进 routing controller；授权留 pkg/routing；公共 announce 用 state intent |
| `routing_upstream_routes.go` | Linux `ip` 安装 upstream 地址/路由 | `internal/photonlinux/routing` driver |
| `runtime_state_migration.go` | 旧 `stateFile/stateMeta` 单向 decoder | current LinuxState/type/clone/codec/commit 已归 `internal/photonlinux`；本文件只保留旧 schema 拆分与原子迁移，停止支持旧库时删除 |
| `service.go` | SOCKS5 CLI、旧 direct record mutation | intent 留 state/service；CLI 进 photoncli；展示进 inspect；旧 apply 删除 |
| `share.go` | base64 JSON 和文件 I/O | `internal/photoncli/encoding`；不是 state codec |
| `state.go` / `state_bolt.go` | 当前 State owner 与启动持久化边界 | State 持有唯一 DB、Common 与 LinuxState；启动恢复直接构造完整 State，不向调用方暴露裸分区再二次组装 |
| `context.go` / `legacy_state.go` | 当前应用上下文与旧 schema DTO | `AppContext` 只承载 config/state-path/clock/control 选择；`stateFile/stateMeta` 只供单向旧库迁移和 legacy db dump |
| `state_clone.go` | 已删除 | 各 Linux DTO clone 统一归 `internal/state`，供 app planner 与 `photonlinux.LinuxState` 共用；不在迁移后保留两套深拷贝实现 |
| `state_gc.go` | 已删除 | 原功能只删持久化 BIRD 诊断表，不管理进程或内核资源；`BirdInstances` 转为在线 observation 后不再有 GC 目标 |
| `status.go` | status CLI | inspect read model + photoncli |
| `sync.go` | Linux UDP open、endpoint publish、transport config 和 CLI | `SyncRuntime`、Daemon 重复 GossipConfig/transport/deps 与 `gossipStartupConfig` 中间 DTO 已删除；composition root 从 AppConfig/verified identity 直接生成 detached GossipDriver/transport config，endpoint/log 直接读取 AppConfig；剩余 Linux UDP open 后续进入 LinuxDriver，CLI 进 photoncli |
| `verify.go` | chain 验证 CLI | 验证留 crypto/state；CLI 进 photoncli |
| `version.go` | build info | `internal/buildinfo` 供 Linux/Windows 复用 |
| `zone.go` | zone/record 列表 CLI | Store read API + inspect/text + photoncli |

## 4. 推荐迁移顺序

1. **删除剩余旧 direct writer**：record、IPAM、route、service 和 delegation issue/grant/revoke 的 `--direct`
   已统一为打开唯一 BoltStore/common Store 后调用同一个 typed intent；旧手工签名、授权校验和聚合 state mutation
   已删除。fresh join accept 现在会在同一 Bolt 事务中直接建立 common 与 Linux runtime bucket；原 `state_gc --direct` 随唯一的持久化 BIRD 诊断表一起删除。
2. **迁移公共 GossipDriver**：依次拆 `daemon_sync.go`、`daemon_object_chunk.go`、`daemon_gossip.go`、`objectpull.go`、`sync.go` 和 `daemon.go` 的 event loop。
3. **收拢 Linux runtime**：先把 IPsec、routing、firewall 的真实平台动作和共享 netns 执行上下文迁入同一个 Linux composition root；内部仍可按领域分模块。等 Windows/Android 出现真实同构调用点后，再从 consumer 侧提取最小平台接口，不预建成套 controllers。
4. **删除聚合 stateFile**：在线与普通测试迁移已完成；production `stateFile` 只剩旧 schema 单向 migration decoder，legacy test helper 只负责写入退役 schema。旧 `DaemonStateStore` aggregate API 已删除；新的具体 State 管理唯一 StateDB、Common 与 LinuxState typed partition。
5. **收口 CLI/展示**：`debug_*.go`、`status.go`、`zone.go`、`debug_db.go` 最终只做参数解析、control/read model 调用和 presenter 输出。

迁移过程中不再为单个调用点增加新的 stateFile wrapper。需要过渡时只允许 detached typed DTO，并在同一任务中写明删除条件。

## 5. E2f/E2g 收口复核

E2f 盘点时 `app/photon` 有 74 个非测试 Go 文件；当前为 69 个。历史上已删除或迁出的
`daemon_state_projection.go`、`objectpull.go`、`routing_upstream_routes.go` 和 `health_spool.go` 不再作为当前文件列出。
production staticcheck 已清零。

这次复核确认可以继续保留的只有三类代码：可执行程序装配和 Linux control transport、尚待下沉的 Linux
controller/driver 实现、以及旧数据库单向迁移。后两类“仍有生产调用”不代表最终永久留在 app：例如
`firewall_reconcile.go` 的策略输入和调度归 Daemon，nftables/iptables/netns 观测与 apply 已进入
`photonlinux`；BIRD process/client、upstream veth/route 以及 Linux health probe 执行也已下沉。
`gossip_checkpoint_migration.go` 和 `runtime_state_migration.go` 则只在启动事务读取旧 schema。
未再发现仅为测试或旧在线双路径保留的 production wrapper。

### 5.1 E2g 后还留在 app 的原因

本轮将原 `pkg/health` 中混入的 Linux raw socket、`setns` worker、`ip netns exec ping` fallback
及其实现级测试整体迁入 `internal/photonlinux/healthprobe`。唯一 `photonlinux.LinuxDriver` 在初始化时选择
真实或注入 prober，在关闭/替换 runtime 时一并关闭 raw socket worker。daemon 不再构造、记录或关闭
Linux prober，只把平台实现交给公共 `health.Manager`。没有保留旧入口；语义不可靠且从未真正接线的
“UDP write 成功即健康” prober 同时删除。

`health_reconcile.go` 的 runtime 边界现已收口：

1. Linux link output 到 `ProbeTarget` 的组合已进入 `internal/photonlinux/linkstate`；
2. `health.Manager` 的一秒异步 tick 与 completion 唤醒已进入 Daemon scheduler/event loop；
3. spool 已进入 `internal/observability/healthspool`，Observer/control 使用 canonical inspect DTO。

app 中剩余的是配置装配、把 committed Linux link output 交给 manager，以及 CLI/text 入口，不再拥有平台 probe、
独立 ticker、独立 completion queue 或 health 历史存储。

### 5.2 测试是否可以迁走

测试跟随被测 owner，而不是为了减少 `app/photon` 文件数整批搬迁：

- raw ICMP、setns、exec ping 的 700 多行实现级测试已随代码迁入 `internal/photonlinux/healthprobe`；
- health spool 的文件、裁剪、packet count 与 rotate series 测试已迁入 `internal/observability/healthspool`；
- firewall/BIRD/upstream 等平台实现测试应继续随实现留在 `internal/photonlinux`；
- `app/photon` 的 CLI flag、Unix control、composition、完整 daemon 顺序和 root smoke 测试仍属于 executable 集成边界，不能迁成底层包单测；
- 普通测试已经使用 typed owners；只有旧 schema migration/codec 测试可以继续构造 `stateFile`，不得把该 fixture 用回在线行为测试。

GossipDriver 公共 gossip 闭环、aggregate 清理和 current Linux codec 迁移已完成。旧 schema decoder 仍留在 app migration
边界，不能随 current codec 一起误搬成在线兼容层。这里的 codec owner 完成不等于 live state 边界完成：当前
`photonlinux.LinuxState` 已删除 routing/firewall reconcile summary、BIRD instance 数据与 `PeerCleanups`，现在只保留无法从其他 owner 恢复的 IPsec transport 私钥和显式本机 Endpoint ACL。
`IdentityKeyPath` 已从 current LinuxState、clone 和 codec 中删除，启动不再为配置路径补写一次 Linux state；配置路径移动时只要密钥身份不变即可，启动与 reload 都以配置 key 的公钥匹配 VerifiedState 为准。旧 `stateFile/stateMeta` 仍解码该字段以读取旧库，但迁移投影明确丢弃，不形成 current schema 的第二真相源。
持久化 `Admission` 也已删除：pending/adopted、reason/detail 与 join request 直接从 VerifiedState 推导，最近 bootstrap sync 从 GossipCheckpoint 中对应 peer 的 `LastSyncUnix` 推导。原有 pending 时间、adopted 时间和 error 字段没有生产写入者，不为它们新增公共 owner、bucket 或 schema migration；旧 JSON 字段由 current/legacy decoder 忽略。
持久化 `RoutingReconcile` 与 `BirdInstances` 均已删除：LastRun/LastError、BIRD status/exit/backoff 只进入 daemon 内的 `LinuxObservation`，进程重启后由下一次 reconcile 重建；路径、RouterID、owner 和 config hash 从配置与 VerifiedState 重新推导。旧 aggregate/current JSON 字段直接丢弃。
持久化 `FirewallReconcile` 同样已删除：backend、generation、policy hash、owned object count 与 LastRun/LastError 只用于展示，统一进入 `LinuxObservation`；实际 reconcile 每次仍从系统 owned objects 重新观察，不消费旧 summary。`EndpointACLs` 是用户配置，继续由 Linux state 持久化。

目标所有权与命名统一见 [`runtime-state-ownership.md`](runtime-state-ownership.md)：当前 `Daemon` 是唯一顶层
`Daemon`，`host.GossipDriver` 是公共 `GossipDriver`，`photonlinux.LinuxDriver` 是具体 Linux 平台实现，`state.Store` 是公共
`Common`。Daemon 的普通 common mutation 显式进入 `State.Common`，误称同 revision 的 common/Linux aggregate read 已拆成各 partition 的独立 snapshot。旧 `DaemonStateStore` 已删除；新的具体 State 内部持有唯一 StateDB、Common、LinuxState 和对应锁，并在 platform completion 上用 verified revision 和 Bolt 事务拒绝 stale candidate。Daemon 不再平铺这些字段。原协调器的跨 owner `writeMu` 实际无法覆盖 GossipDriver 对 Common 的写入，因此没有保留或搬进 LinuxDriver。单调用方的 Bird GC、revoked purge 和 peer cleanup commit 壳也已删除。

下一轮先把平台数据分成 `LinuxState` 与纯内存 `LinuxObservation`：只保存无法重建的本地 intent/secret 和非幂等
多阶段操作的最小 journal；SA、route、BIRD/firewall 当前状态、reconcile action、LastRun/LastError 启动后重新 Observe，
不得继续从 bbolt snapshot 冒充在线状态。

### 5.3 推荐顺序的当前进度

1. direct writer：已完成；record/IPAM/route/service/delegation 与 fresh join bootstrap 均写入各自 owner，不再通过聚合 `stateFile` 落盘；无持久化目标的 Linux state GC 已删除。
2. 公共 GossipDriver：只保留协议 receive/timer、object-pull、discovery 和 gossip observability；IPsec/routing/firewall/health
   周期调度已回到 Daemon 自己的 scheduler/queue，health completion 也由 Daemon event loop 直接消费。GossipDriver 已直接持有
   common Store 和同一个 gossip Transport，不再经 `DaemonStateStore` 或 daemon I/O adapter 转发。
3. Linux driver：IPsec/XFRM、firewall、upstream routing、BIRD 和 health probe 实际执行均已下沉；执行侧主体完成。
   current `LinuxState`、detached clone、bbolt codec 和 revision-guarded commit 已归 `internal/photonlinux`；app 旧库迁移只负责
   `stateFile/stateMeta` 解码及一次性字段投影。平台包不自行打开数据库，仍使用 composition root 传入的唯一 BoltStore/transaction。
   `IdentityKeyPath` 已从 current schema 删除并回归配置 owner；`Admission`、`RoutingReconcile`、`FirewallReconcile`、`BirdInstances` 与 `PeerCleanups` 已作为纯派生/在线诊断从 current schema 删除，旧迁移投影直接丢弃。当前 LinuxState 只剩 IPsec transport 私钥与显式本机 Endpoint ACL；不再保留 RuntimeState alias 或同构 DTO。
   IPsec crash/restart 已补真实双代观察恢复：当 verified current/previous 对应的 connection/SA/XFRM 同时存活时，启动重建 previous active + current staged，重新开始有界 retention；若 current 只有 loaded connection 则重新开始 prepare deadline。这样旧代仍由 rotation owner 明确收口，不因直接 adopt current 而变成失联资源。current-only、previous-only、loaded-no-SA 与空 runtime create 保持独立回归覆盖；current 已建立但 previous cleanup 未完成时会重新进入正常 `commit_rotate` teardown。secondary takeover 只从 SA initiator 事实恢复，并从启动时建立 fresh lease，不恢复旧 backoff/deadline。撤销或配置删除后，空 Observation 不足以证明完整资源 owner，启动不会按名称猜测并自动删除；显式 orphan cleanup 只终止/卸载未引用的 Photon connection，保留外部 connection，且不删除缺少完整 ownership proof 的 XFRM interface。
   IPsec、routing 与 firewall 的顶层 reconcile 错误不再在 Observation 内提前压成 `LastError string`，而是直接保存 process-local `error`；canonical inspect/control/HTTP 边界只投影一个 `FailureView{code,message}`，删除并行的顶层 error/code 字段。稳定 code 为 `ipsec_reconcile_failed`、`routing_reconcile_failed`、`firewall_reconcile_failed`；failure 仍随进程丢失，不进入 LinuxState。
   实例级 IPsec link/takeover、BIRD 与 firewall observation 也已改为 process-local `error`，展示时分别映射 `ipsec_link_failed`、`ipsec_takeover_failed`、`bird_instance_failed`、`firewall_instance_failed`。状态机仍只依赖 failure count、backoff、deadline、phase 等结构化字段；provider-neutral `LinkOutput` 中无人消费的 `LastError` 已删除。BIRD 即时查询失败单独映射为 `bird_query_failed`，不回写 instance observation。
   health probe result/manager/snapshot 与 gossip object-pull diagnostics 同样只在进程内保留 `error`，到 health/ping/peer/sync inspect 边界分别映射 `health_probe_failed`、`gossip_object_pull_failed`。持久化 GossipCheckpoint 继续使用已有 `PeerFailure{code,message,at_unix}`，展示直接投影，不再转换成 legacy peer `LastError`；contact quality 从未有生产错误文本来源，对应两个字符串字段和 rank reason 拼接已删除，只保留 successes/failures/backoff。legacy peer `LastError` 仅供旧 schema 单向迁移和 dump。
   最后一轮删除了重复承载返回错误的 `FirewallApplyResult.Errors`，BIRD process exit 保留原始 `error`；service record、BIRD dump/filter 与 revocation cleanup 展示复用 `FailureView`。仍为 string 的 error 只存在于 gossip wire/log event、control response 和 Observer HTTP response 等明确序列化边界。
   `stateFile/stateMeta` 的生产引用已只剩启动时的单向旧 schema migration 和显式 legacy DB dump；current peer inspect 也不再把 `PeerCheckpoint` 反向转换成 legacy `PeerRuntimeState`，debug/HTTP view 直接读取 checkpoint。
4. 聚合 `stateFile`：在线和普通测试迁移已经完成；fresh join 已退出聚合写入；在线 IPsec cleanup、revoked purge、Endpoint ACL、
   reconcile completion 以及 Firewall/IPsec 主 planner 已直接读取 common/Linux 两个 owner，不再构造完整 Snapshot。
   本机 endpoint/IPsec/routing protocol publish 也已直接使用两个 owner，routing 主 reconcile planner 同样完成切换。
   在线 control/debug、配置 reload、手动端口轮换和 hook/composition 也已切走，production `currentState()` 已删除。
   CLI 查询已按来源收口：verified/common 允许离线读取；gossip checkpoint 离线时明确标为 last-known；links/firewall/BIRD/health/ping/
   peer lifecycle 等 platform runtime 查询要求在线 daemon，不再从 bbolt reconcile snapshot 冒充 live，也不由 CLI 直接调用 platform driver。
   read model 随后开始收敛为 typed canonical view envelope：zone/service/route/IPAM/endpoint、records/sync/peer/zone debug、
   status/peer lifecycle/gossip peers/health 均由 daemon 或离线 owner 调用同一查询函数生成最终 inspect DTO，CLI 只负责呈现；
   links/firewall/Babel/health/ping 也已改为 daemon 直接返回 canonical inspect DTO，旧 resource response 和 links live-replan 换壳已删除；
   `record_get`、admission diagnosis 和 Endpoint ACL list 也已退出巨型 `controlResponse`，直接通过 typed view envelope 传输；
   旧 `status` 混合回包也已拆除，Observer/control 共用同一 operational status 投影，root public key 改为独立 typed view；
   `verify_chain` 同样返回 typed bool view，只读 control 已不再借用 mutation response；
   E2k 最终边界测试确认在线 daemon 独占 Bolt handle 时 CLI 只经 control 读取，关闭 daemon 后 offline owner 生成相同 canonical Zone DTO，
   且 control、CLI presenter、Observer HTTP 对同一 owner fixture 的 Zone path/count/revoked 语义一致。
   routes canonical DTO 已从 HTTP 包迁到 `internal/inspect`，HTTP 只保留稳定 schema alias；zones/peers/status 的排序、来源判定和
   聚合投影也已归入 `internal/inspect`。links 的 REST 契约需要同时保留扁平兼容字段与 `raw` canonical view，因此只保留薄 HTTP adapter，
   不在 HTTP 层重新推导 desired/runtime 状态。
   `debug rotate --direct` 已改用正式 typed intent/runtime commit。production 已无 aggregate `Snapshot()`、clone、loader 或 writer；
   `stateFile/stateMeta` 只承担旧 schema 单向读取和 legacy db dump，明确随旧数据库支持周期删除。Daemon 不再缓存第二份
   common revision 或不完整的 `SnapshotTime`，status revision 直接来自 common Store。
5. CLI/展示：尚未系统迁移；只在 owner 拆分时同步迁走实现级代码和测试，不先做目录搬家。
