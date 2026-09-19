# `app/photon` Runtime 迁移盘点

> 初始盘点基线：`3aa43fb`（2026-08-27）；当前复核基线：`3603972c9806`（2026-09-16）
> 当前范围：`app/photon` 下 72 个非测试 Go 文件、18451 行生产代码
> 目标：说明每个文件当前职责、最终归属，以及 State、GossipDriver、LinuxState、LinuxDriver、Observation 和 presentation 之间的边界。冻结术语见 [`runtime-state-ownership.md`](runtime-state-ownership.md)。

## 1. 最终分层

| 层 | 所有权 |
|---|---|
| `app/photon` | Linux Daemon、唯一顶层事件循环、executable 入口、Unix control 协议/client/server、CLI 注册和依赖装配 |
| `pkg/core/host` | 公共 GossipDriver：协议事件队列、gossip scheduler/action、transport、object-pull 和协议 worker completion |
| `pkg/core/gossip` | wire codec、同步 FSM/session、chunk、object-pull 协议和 endpoint discovery |
| `pkg/core/state` | verified state、`GossipCheckpoint`、typed intent、签名验证和公共事务 |
| `pkg/core/zone` | authority、delegation、revocation、record 和 Network 等最低层模型 |
| `internal/photonlinux` | LinuxDriver、LinuxState codec，以及 Linux IPsec、routing、firewall、health 的具体实现 |
| `internal/observability` | 可丢失的实时统计和诊断 |
| `internal/inspect` | 只读 view；不拥有 mutable store |
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

持久化 `BirdInstanceState` 已删除。PID/control socket/config path/owner 由配置和稳定命名重算，运行、退出、
backoff 与查询失败只进入 process-local Observation；启动不会用旧缓存跳过 Observe。

### 2.4 崩溃顺序

对于会公开到 gossip 的本机运行事实，使用以下顺序：

1. 从配置、verified record 和 Observe 重建 desired state；
2. 如存在明确要求跨重启连续、且无法推导的本机值，先持久化该最小值；
3. 幂等应用外部资源；
4. 重新 Observe 确认；
5. 发布或更新公共 record；
6. diagnostics 只写 observability，不能决定下次是否跳过 Observe。

IPsec transport key 有两种都正确的产品策略：持久化私钥以维持 transport identity；或者只保存在内存中，每次启动生成新 key 并立即替换公开 record。后一种会带来重启后的 SA 重建和传播窗口，但不要求 platform 持久化。port generation 则可直接从 verified port record 恢复。BIRD/路由规则始终以 Observe 为准。

### 2.5 当前 LinuxState payload

字段清理已经完成，没有为可推导/可 Observe 数据新增更多 bucket。当前 `LinuxState` JSON 只保留两类跨重启连续值：

```text
local-desired        不在配置文件中、但产品要求跨重启保留的本机配置
continuity           无法推导、但产品要求保持的随机生成值
operations           当前为空；rotation/takeover 从真实系统 Observation 恢复
```

`local-desired` 当前是动态 Endpoint ACL，`continuity` 当前是 IPsec transport private key。`recovery` 和
`diagnostics` 不持久化；若未来产品明确改为 transport key 重启轮换且动态 ACL 由配置托管，Linux runtime bucket
才可能继续缩减。这不是当前迁移余项。

## 3. 逐文件迁移清单

### 3.1 Admission、authority、daemon

| 文件 | 当前作用 | 最终位置 / 层 |
|---|---|---|
| `admission_diagnostics.go` | auto-join 诊断 | 保持纯投影：从 VerifiedState 与 GossipCheckpoint 即时生成 `internal/inspect` DTO；不再持久化 admission snapshot，CLI wrapper 后续进 `internal/photoncli` |
| `authority.go` | 权限解析、delegate grant、旧 direct 修改 | CLI 进 `internal/photoncli`；权限合并/epoch/父子 authority 更新成为 `pkg/core/state` intent；旧 direct writer 删除 |
| `state_bolt.go` | 组合 Common 与 LinuxState 的启动加载 | 启动已优先读取新 schema，仅未初始化时进入旧 bootstrap/migration；唯一 StateDB 随后交给具体 State 管理 |
| `cmd.go` | Linux CLI 命令树 | 留 `app/photon` 但缩成注册；handler 进 `internal/photoncli` |
| `cmd_root_init.go` | root authority/key 初始化与 current partitions 原子建立 | CLI 文件操作后续随壳进入 photoncli；Common/Linux 两个分区必须继续在同一初始化事务内建立 |
| `config.go` | 混合解析 gossip、identity 和全部 Linux subsystem | 顶层文件读取/组合留 app；firewall/routing/IPsec/health 等 focused YAML/effective config 随真实 owner 下沉，不新增第三套总配置 DTO |
| `control.go` | 私有 DTO、Unix socket client、命令 wrapper 和部分 view | 保留 executable control 边界；只有出现第二个真实 client 时才整体抽 typed protocol/client，不再单独下沉 transport helper；CLI/view 分别进 photoncli/inspect |
| `cpu_profile.go` | daemon CPU profile 生命周期 | `internal/runtimeprofile` 或薄 app helper；不属于状态层 |
| `daemon.go` | event loop、控制服务、admin mutation、publisher、controller 生命周期 | sync/endpoint/IPsec/routing/firewall/health 周期 deadline 由 Daemon 自己的 Scheduler/queue 管理；record/IPAM/route/service 已共用一个携带 `LocalIntent` 的 mutation event；control server 留在 executable 集成边界，Linux controller 继续下沉 |
| `daemon_common_intent.go` | control/direct DTO 到公共 intent 的共享转换 | 每个 converter 有 online 与 direct 两个真实消费者；wire DTO 下沉时随 control 边界移动，不新增 adapter |
| `daemon_gossip.go` | Daemon 到 GossipDriver 的配置适配、lifecycle suppression 与 discovery 刷新触发 | 规划、checkpoint patch、persist-before-publish 和地址簿更新已进 GossipDriver；地址簿是可重建的公共 transport runtime state。 |
| `daemon_ipsec_cleanup.go` | 在线 cleanup 事件、Observation 与通知编排 | 留在 Daemon owner；StrongSwan/XFRM teardown、owner 校验和幂等执行已归唯一 LinuxDriver |
| `daemon_object_chunk.go` | 已删除 | chunk assembly、repair deadline、snapshot decode/root check、reject checkpoint 和 completion 回投已归 GossipDriver；剩余 sent-chunk/NACK repair 随 F0e3b 从 `sync.go` 收口 |
| `daemon_runtime_commit.go` | 已删除 | 原函数只做 nil guard 和单次转发；调用方现直接进入 typed Linux runtime commit，后续整体迁入 platform owner |
| `daemon_state_store.go` | 已删除 | 旧 aggregate/forwarding Store 不再存在；`state.go` 用一个具体 State 管理唯一 StateDB 与 typed partitions，protocol publish 只负责编排私钥先于公共 record 持久化 |
| `daemon_sync.go` | GossipDriver 终态结果、object-pull listener 与 Daemon wakeup 接线 | gossip packet/session FSM、发送、checkpoint、relay 和 observability 已在 GossipDriver 闭环；已删除只被测试调用的 `EnableEventLoopSync` / `processPacketEvent`，测试改走现有 scheduler / Daemon event 入口，不恢复协议 controller adapter |

### 3.2 DB、debug 和 diagnostics

| 文件 | 当前作用 | 最终位置 / 层 |
|---|---|---|
| `debug_db.go` | 离线递归 dump 原始 bucket；zone 筛选只读取当前 VerifiedState | 公共 dump 进 `internal/stateinspect`；Linux dump 进 `internal/photonlinux/inspect`；CLI 进 photoncli |
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
| `debug_routing_ip.go` | daemon control 查询与 canonical 文本渲染 | 已完成：netns 解析及 Linux `ip route` 执行归 `internal/photonlinux/routing`，CLI 不再直连平台 |
| `debug_zone_records.go` | zone/record 展示 | Store read API + `internal/inspect`/text |
| `diagnostics.go` | 已删除 | gossip 事件日志 adapter 已收敛到 `gossip_logging.go` |
| `gossip_logging.go` | gossip/host 稳定事件到 app logger 的映射 | 保留薄 composition adapter；不得重新承载协议状态机或 checkpoint mutation |

### 3.3 Firewall、health、identity、IPAM、IPsec、join

| 文件 | 当前作用 | 最终位置 / 层 |
|---|---|---|
| `endpoint_acl.go` | ACL CLI、验证、resolve 和 firewall runtime mutation | Linux firewall model/controller；CLI/control 留 adapter；属于 platform desired runtime |
| `firewall_config.go` | 已迁至 `internal/photonlinux/firewall_config.go` | Linux owner 持有 YAML/effective config、managed 实例筛选与 spec 构造；app 直接传 namespace specs 和 IPsec port mode，旧类型/helper 已删除 |
| `firewall_reconcile.go` | firewall plan/apply/observation 顺序 | YAML/effective config 与 policy input builder 已下沉 Linux owner；Daemon 读取 owner、构建 LinkOutput、检查 revision 并逐实例调用 Driver/发布 Observation，私有 LinuxState 不再进入纯策略 builder |
| `forwarding_config.go` | 已删除 | namespace forwarding 解析和 lookup 已归 Linux routing config；前缀过滤归现有 pkg/firewall，app 不保留 helper/alias |
| `gossip_checkpoint_migration.go` | 旧 SyncPeers 到 GossipCheckpoint | `internal/photonlinux/migration`；仅由旧数据库单向迁移调用，不属于在线兼容层；只有明确停止支持旧 schema 时才删除 |
| `health_config.go` | probe/hysteresis/metrics 配置 | 通用类型留 `pkg/health`；Linux YAML 进 Linux health config |
| `health_reconcile.go` | health manager 装配、target 组合、快照发布和 CLI 展示壳 | manager/状态机留 `pkg/health`；`LinkOutput -> ProbeTarget` 与 probe ID/rotate role 是 health 专属组合规则；raw ICMP、setns、exec fallback 在 `internal/photonlinux/healthprobe`；tick/completion 已进入 Daemon scheduler/event loop |
| `health_spool.go` | JSONL health 历史和查询 | 已整体迁入 `internal/observability/healthspool` 并删除 app 文件；不属于 state/checkpoint |
| `identity_bootstrap.go` | identity key/config、pending auto-join bootstrap 和 refresh | 空库直接初始化 current Common/Linux partitions；identity path 只属于配置，启动校验 key 与 VerifiedState 身份一致，不再写入 LinuxState 或 legacy aggregate schema |
| `init.go` | 已删除/改名 | root 初始化当前由 `cmd_root_init.go` 承担；已直接原子初始化 Common/Linux buckets，不再写 legacy aggregate schema |
| `inspect_links.go` | Linux link 到 inspect input | Linux controller 输出稳定 DTO，view 进 inspect |
| `inspect_peers.go` | verified/checkpoint/bootstrap/observability endpoint view | `internal/inspect`，不再依赖 stateFile |
| `ipam.go` | IPAM CLI、旧 mutation 和报告 | mutation 只调 state intent；报告进 inspect；CLI 进 photoncli；旧 apply 函数删除 |
| `ipsec_cleanup.go` | 已删除/拆分 | online 编排在 `daemon_ipsec_cleanup.go`，CLI/control/direct recovery 在 `recovery_ipsec.go`；具体 teardown 只有 `internal/photonlinux/ipsec_cleanup.go` 一套实现 |
| `ipsec_publish.go` | transport key/address/port/overlay record 和私有 runtime | record 构造进 transport/state publisher；只有无第二来源的 transport private key 进入 platform runtime，port generation 从 verified record 恢复；排序由 host 保证 |
| `ipsec_reconcile.go` | StrongSwan/XFRM/SA/rotation reconcile | app 仅保留协议规划、rotation 编排与结果提交；SA live observation、action apply、lifecycle subscription，以及 XFRM batch observe、missing-link filter、diagnostic address、drift repair 都直接实现为唯一 `photonlinux.LinuxDriver` 的方法，并按 `linux_driver.go`、`xfrm.go`、`ipsec_cleanup.go` 分文件组织；没有再套平台聚合层或逐方法代理，迁移期 `XFRMDriver()` 访问口已删除 |
| `join.go` | join DTO、issue/revoke/accept、key/bundle、旧 direct writer | DTO/验证进 state admission；文件 CLI 进 photoncli；全部 mutation 复用 Store；旧 writer 删除 |

### 3.4 Key、link、logging、object-pull、observer、peer

| 文件 | 当前作用 | 最终位置 / 层 |
|---|---|---|
| `keygen.go` | Ed25519 key 文件生成 | `internal/photoncli/keygen`，底层复用 crypto |
| `link_outputs.go` | Linux link runtime 到 health/routing output | IPsec controller 直接输出 provider-neutral DTO |
| `linux_observation.go` | IPsec、routing/BIRD 与 firewall 在线快照、锁和 detached clone | 留作 Daemon-owned process-local Observation；不得落盘或为省 clone 暴露共享可变对象 |
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
| `recovery_ipsec.go` | IPsec cleanup 的 online control 与 daemon-offline direct 入口 | 两条运维路径复用唯一 LinuxDriver cleanup；direct 路径只临时装配真实 VICI/XFRM driver，不复制删除算法 |
| `revocation_cleanup.go` | impact、typed peer cleanup policy、purge plan | 未接线的旧 aggregate peer-cache mutator 已删除；verified/checkpoint purge 留 state，平台 cleanup 变成 host action，view 进 inspect |
| `root.go` | root public key CLI | Store read API + photoncli |
| `route.go` | route CLI、旧 direct mutation、报告 | mutation进 state intent；授权计算留 routing；报告进 inspect；CLI 进 photoncli |
| `network_state.go` | 为 NetworkState 安装验证函数并规范化 current state | 最终靠近 `pkg/core/state`/zone 构造边界；避免 app 调用方依赖“记得先 configure”的隐性前置条件 |
| `protocol_publish.go` | 私有 transport key 先落盘、公共 protocol record 后发布 | 保留关键顺序与 verified revision guard；纯 record 构造继续靠近 transport/state publisher owner |
| `routing_config.go`（已删除） | BIRD/Babel/upstream YAML 解析与默认值 | 全部配置类型、解析和校验已归 internal/photonlinux/routing_config.go；三个 app namespace helper 已删除或归入 Linux 配置；spec/export/announce 继续下沉 |
| `routing_reconcile.go` | BIRD/netns/veth/upstream、health、auto announce | 配置与纯 spec/export/announce、轮换 metric 策略已归 routing/Linux owner；Daemon 保留多实例/health/intent/shutdown 顺序，Linux 执行复用现有 LinuxDriver |
| `routing_upstream_routes.go` | Linux `ip` 安装 upstream 地址/路由 | `internal/photonlinux/routing` driver |
| `runtime_state_migration.go` | 旧 `stateFile/stateMeta` 单向 decoder | current LinuxState/type/clone/codec/commit 已归 `internal/photonlinux`；本文件只保留旧 schema 拆分与原子迁移，停止支持旧库时删除 |
| `service.go` | SOCKS5 CLI、旧 direct record mutation | intent 留 state/service；CLI 进 photoncli；展示进 inspect；旧 apply 删除 |
| `share.go` | base64 JSON 和文件 I/O | `internal/photoncli/encoding`；不是 state codec |
| `state.go` / `state_bolt.go` | 当前 State owner 与启动持久化边界 | State 持有唯一 DB、Common 与 LinuxState；启动恢复直接构造完整 State，不向调用方暴露裸分区再二次组装 |
| `context.go` / `legacy_state.go` | 当前应用上下文与旧 schema DTO | `AppContext` 只承载 config/state-path/clock/control 选择；`stateFile/stateMeta` 只供单向旧库迁移 |
| `state_clone.go` | 已删除 | 各 Linux DTO clone 统一归 `internal/state`，供 app planner 与 `photonlinux.LinuxState` 共用；不在迁移后保留两套深拷贝实现 |
| `state_gc.go` | 已删除 | 原功能只删持久化 BIRD 诊断表，不管理进程或内核资源；`BirdInstances` 转为在线 observation 后不再有 GC 目标 |
| `status.go` | status CLI | inspect read model + photoncli |
| `sync.go` | Linux UDP open、endpoint publish、transport config 和 CLI | `SyncRuntime`、Daemon 重复 GossipConfig/transport/deps 与 `gossipStartupConfig` 中间 DTO 已删除；composition root 从 AppConfig/verified identity 直接生成 detached GossipDriver/transport config，endpoint/log 直接读取 AppConfig；测试专用 SyncTransportDeps/default builder 与全局 endpoint collector 替换点已删除；剩余 Linux UDP open 后续进入 LinuxDriver，CLI 进 photoncli |
| `verify.go` | chain 验证 CLI | 验证留 crypto/state；CLI 进 photoncli |
| `version.go` | build info | `internal/buildinfo` 供 Linux/Windows 复用 |
| `zone.go` | zone/record 列表 CLI | Store read API + inspect/text + photoncli |

## 4. 历史推荐迁移顺序与当前状态

1. **删除剩余旧 direct writer**：record、IPAM、route、service 和 delegation issue/grant/revoke 的 `--direct`
   已统一为打开唯一 BoltStore/common Store 后调用同一个 typed intent；旧手工签名、授权校验和聚合 state mutation
   已删除。fresh join accept 现在会在同一 Bolt 事务中直接建立 common 与 Linux runtime bucket；原 `state_gc --direct` 随唯一的持久化 BIRD 诊断表一起删除。
2. **迁移公共 GossipDriver**：协议 FSM、object-pull、checkpoint 与 transport ordering 已完成下沉；app 只剩 composition、产品 lifecycle policy 和 Daemon wakeup 接线。当前余项是删除 test-only helper/transport test seam，不再迁一次协议 owner。
3. **收拢 Linux runtime**：IPsec、routing、firewall、health 的真实平台动作和共享 netns 执行已经进入唯一 LinuxDriver。当前只继续下沉 focused config 与纯 policy；等 Windows/Android 出现真实同构调用点后，再从 consumer 侧提取最小接口，不预建成套 controllers。
4. **删除聚合 stateFile**：在线与普通测试迁移已完成；production `stateFile` 只剩旧 schema 单向 migration decoder，legacy test helper 只负责写入退役 schema。旧 `DaemonStateStore` aggregate API 已删除；新的具体 State 管理唯一 StateDB、Common 与 LinuxState typed partition。
5. **收口 CLI/展示**：`debug_*.go`、`status.go`、`zone.go`、`debug_db.go` 最终只做参数解析、control/read model 调用和 presenter 输出。

迁移过程中不再为单个调用点增加新的 stateFile wrapper。需要过渡时只允许 detached typed DTO，并在同一任务中写明删除条件。

## 5. E2f/E2g 与 2026-09-16 收口复核

E2f 盘点时 `app/photon` 有 74 个非测试 Go 文件；2026-09-16 当前为 72 个、18451 行。文件数相对中间快照
出现回升，是因为 root init、IPsec cleanup/recovery、protocol publish 等真实职责被拆成独立文件；文件数本身
不是迁移完成度指标。历史上已删除或迁出的 `daemon_state_projection.go`、`objectpull.go`、
`routing_upstream_routes.go` 和 `health_spool.go` 不再作为当前文件列出。

当前可以继续保留的代码分为三类：可执行程序装配/Unix control/完整 Daemon 顺序、尚待下沉的子系统配置与
纯策略、以及旧数据库单向迁移。Linux 实际执行侧已大体闭环：nftables/iptables/netns 观测与 apply、BIRD
process/client、upstream veth/route、kernel route 查询和 Linux health probe 均已进入 `internal/photonlinux`。
后续重点不是把 `reconcile*` 整体搬进新 controller，而是移动不依赖 Daemon 生命周期的 YAML/effective config、
spec/policy builder 和安全 projection，同时让 app 继续负责 owner 读取、revision guard、Driver 调用、Observation
发布和 shutdown 顺序。

旧数据库只剩 `gossip_checkpoint_migration.go`、`runtime_state_migration.go`、`legacy_state.go`、legacy peer DTO。`debug_db.go` 的 legacy 专用 dump 已删除，通用原始 bucket 读取不解码旧模型。它们不属于 current 在线模型，但尚未绑定直接升级截止版本，不能无限期作为
“备用 loader”保留。

本轮已删除没有生产调用方的 `Daemon.EnableEventLoopSync` 与 `Daemon.processPacketEvent`，测试直接复用
GossipDriver.ResetScheduler 和正式 Daemon.handleGossipDriverEvent。另删除 `SyncTransportDeps`、默认 deps builder
与全局 `collectSyncLocalEndpoints` 替换点：transport config 直接从 GossipDriver config 组装，endpoint 测试使用
显式 advertise 配置调用真实 collector。不新增 interface、manager、wrapper 或 runtime；生产代码新增 7 行、删除 53 行，净减 46 行。

### 5.1 E2g 后还留在 app 的原因

本轮将原 `pkg/health` 中混入的 Linux raw socket、`setns` worker、`ip netns exec ping` fallback
及其实现级测试整体迁入 `internal/photonlinux/healthprobe`。唯一 `photonlinux.LinuxDriver` 在初始化时选择
真实或注入 prober，在关闭/替换 runtime 时一并关闭 raw socket worker。daemon 不再构造、记录或关闭
Linux prober，只把平台实现交给公共 `health.Manager`。没有保留旧入口；语义不可靠且从未真正接线的
“UDP write 成功即健康” prober 同时删除。

`health_reconcile.go` 的 runtime 边界现已收口：

1. `LinkOutput` 到 `ProbeTarget` 的组合与 probe ID/rotate role 规则已并入 `health_reconcile.go`，不再伪装成 Linux link state；
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

GossipDriver 公共 gossip 闭环、aggregate 清理、current Linux codec 与 live state 边界迁移均已完成。旧 schema decoder
仍留在 app migration 边界，不能随 current codec 一起误搬成在线兼容层。当前
`photonlinux.LinuxState` 已删除 routing/firewall reconcile summary、BIRD instance 数据与 `PeerCleanups`，现在只保留无法从其他 owner 恢复的 IPsec transport 私钥和显式本机 Endpoint ACL。升级旧库时，启动事务会把有效的离线 `PeerCleanups` marker 单向投影为 GossipCheckpoint 的最后观察时间，并在已有更新成功同步时丢弃过期 marker；随后重写 Linux payload 删除旧字段。current schema 不再读写第二份 cleanup tombstone。
`IdentityKeyPath` 已从 current LinuxState、clone 和 codec 中删除，启动不再为配置路径补写一次 Linux state；配置路径移动时只要密钥身份不变即可，启动以配置 key 的公钥匹配 VerifiedState 为准。旧 `stateFile/stateMeta` 仍解码该字段以读取旧库，但迁移投影明确丢弃，不形成 current schema 的第二真相源。
持久化 `Admission` 也已删除：pending/adopted、reason/detail 与 join request 直接从 VerifiedState 推导，最近 bootstrap sync 从 GossipCheckpoint 中对应 peer 的 `LastSyncUnix` 推导。原有 pending 时间、adopted 时间和 error 字段没有生产写入者，不为它们新增公共 owner、bucket 或 schema migration；旧 JSON 字段由 current/legacy decoder 忽略。
持久化 `RoutingReconcile` 与 `BirdInstances` 均已删除：LastRun/LastError、BIRD status/exit/backoff 只进入 daemon 内的 `LinuxObservation`，进程重启后由下一次 reconcile 重建；路径、RouterID、owner 和 config hash 从配置与 VerifiedState 重新推导。旧 aggregate/current JSON 字段直接丢弃。
持久化 `FirewallReconcile` 同样已删除：backend、generation、policy hash、owned object count 与 LastRun/LastError 只用于展示，统一进入 `LinuxObservation`；实际 reconcile 每次仍从系统 owned objects 重新观察，不消费旧 summary。`EndpointACLs` 是用户配置，继续由 Linux state 持久化。

目标所有权与命名统一见 [`runtime-state-ownership.md`](runtime-state-ownership.md)：当前 `Daemon` 是唯一顶层
`Daemon`，`host.GossipDriver` 是公共 `GossipDriver`，`photonlinux.LinuxDriver` 是具体 Linux 平台实现，`state.Store` 是公共
`Common`。Daemon 的普通 common mutation 显式进入 `State.Common`，误称同 revision 的 common/Linux aggregate read 已拆成各 partition 的独立 snapshot。旧 `DaemonStateStore` 已删除；新的具体 State 内部持有唯一 StateDB、Common、LinuxState 和对应锁，并在 platform completion 上用 verified revision 和 Bolt 事务拒绝 stale candidate。Daemon 不再平铺这些字段。原协调器的跨 owner `writeMu` 实际无法覆盖 GossipDriver 对 Common 的写入，因此没有保留或搬进 LinuxDriver。单调用方的 Bird GC、revoked purge 和 peer cleanup commit 壳也已删除。

平台数据拆分已经完成：`LinuxState` 只保存 IPsec transport 私钥和显式本机 Endpoint ACL；SA、route、
BIRD/firewall 当前状态、reconcile action 与 failure 均属于纯内存 `LinuxObservation`，启动后重新 Observe。
下一轮不再重复这一迁移，而是按 firewall、routing/BIRD、IPsec 顺序下沉剩余配置与纯策略，并先删除已确认的
test-only production helper。

### 5.3 推荐顺序的当前进度

1. direct writer：已完成；record/IPAM/route/service/delegation 与 fresh join bootstrap 均写入各自 owner，不再通过聚合 `stateFile` 落盘；无持久化目标的 Linux state GC 已删除。
2. 公共 GossipDriver：只保留协议 receive/timer、object-pull、discovery 和 gossip observability；IPsec/routing/firewall/health
   周期调度已回到 Daemon 自己的 scheduler/queue，health completion 也由 Daemon event loop 直接消费。GossipDriver 已直接持有
   common Store 和同一个 gossip Transport，不再经 `DaemonStateStore` 或 daemon I/O adapter 转发。
3. Linux driver：IPsec/XFRM、firewall、upstream routing、BIRD 和 health probe 实际执行均已下沉；执行侧主体完成。
   current `LinuxState`、detached clone、bbolt codec 和 revision-guarded commit 已归 `internal/photonlinux`；app 旧库迁移只负责
   `stateFile/stateMeta` 解码及一次性字段投影。平台包不自行打开数据库，仍使用 composition root 传入的唯一 BoltStore/transaction。
   `IdentityKeyPath` 已从 current schema 删除并回归配置 owner；`Admission`、`RoutingReconcile`、`FirewallReconcile` 与 `BirdInstances` 已作为纯派生/在线诊断从 current schema 删除，旧迁移投影直接丢弃。`PeerCleanups` 同样不再进入 current schema，但旧库中有效的离线 marker 会先迁入 GossipCheckpoint，保留链路抑制语义，再从 Linux payload 删除；已有更新成功同步时不会被旧 marker 覆盖。当前 LinuxState 只剩 IPsec transport 私钥与显式本机 Endpoint ACL；不再保留 RuntimeState alias 或同构 DTO。
   IPsec crash/restart 已补真实双代观察恢复：当 verified current/previous 对应的 connection/SA/XFRM 同时存活时，启动重建 previous active + current staged，重新开始有界 retention；若 current 只有 loaded connection 则重新开始 prepare deadline。这样旧代仍由 rotation owner 明确收口，不因直接 adopt current 而变成失联资源。current-only、previous-only、loaded-no-SA 与空 runtime create 保持独立回归覆盖；current 已建立但 previous cleanup 未完成时会重新进入正常 `commit_rotate` teardown。secondary takeover 只从 SA initiator 事实恢复，并从启动时建立 fresh lease，不恢复旧 backoff/deadline。撤销或配置删除后，空 Observation 不足以证明完整资源 owner，启动不会按名称猜测并自动删除；显式 orphan cleanup 只终止/卸载未引用的 Photon connection，保留外部 connection，且不删除缺少完整 ownership proof 的 XFRM interface。
   IPsec、routing 与 firewall 的顶层 reconcile 错误不再在 Observation 内提前压成 `LastError string`，而是直接保存 process-local `error`；canonical inspect/control/HTTP 边界只投影一个 `FailureView{code,message}`，删除并行的顶层 error/code 字段。稳定 code 为 `ipsec_reconcile_failed`、`routing_reconcile_failed`、`firewall_reconcile_failed`；failure 仍随进程丢失，不进入 LinuxState。
   实例级 IPsec link/takeover、BIRD 与 firewall observation 也已改为 process-local `error`，展示时分别映射 `ipsec_link_failed`、`ipsec_takeover_failed`、`bird_instance_failed`、`firewall_instance_failed`。状态机仍只依赖 failure count、backoff、deadline、phase 等结构化字段；provider-neutral `LinkOutput` 中无人消费的 `LastError` 已删除。BIRD 即时查询失败单独映射为 `bird_query_failed`，不回写 instance observation。
   health probe result/manager/snapshot 与 gossip object-pull diagnostics 同样只在进程内保留 `error`，到 health/ping/peer/sync inspect 边界分别映射 `health_probe_failed`、`gossip_object_pull_failed`。持久化 GossipCheckpoint 继续使用已有 `PeerFailure{code,message,at_unix}`，展示直接投影，不再转换成 legacy peer `LastError`；contact quality 从未有生产错误文本来源，对应两个字符串字段和 rank reason 拼接已删除，只保留 successes/failures/backoff。legacy peer `LastError` 仅供旧 schema 单向迁移。
   最后一轮删除了重复承载返回错误的 `FirewallApplyResult.Errors`，BIRD process exit 保留原始 `error`；service record、BIRD dump/filter 与 revocation cleanup 展示复用 `FailureView`。仍为 string 的 error 只存在于 gossip wire/log event、control response 和 Observer HTTP response 等明确序列化边界。
   `stateFile/stateMeta` 的生产引用已只剩启动时的单向旧 schema migration ；current peer inspect 也不再把 `PeerCheckpoint` 反向转换成 legacy `PeerRuntimeState`，debug/HTTP view 直接读取 checkpoint。
4. 聚合 `stateFile`：在线和普通测试迁移已经完成；fresh join 已退出聚合写入；在线 IPsec cleanup、revoked purge、Endpoint ACL、
   reconcile completion 以及 Firewall/IPsec 主 planner 已直接读取 common/Linux 两个 owner，不再构造完整 Snapshot。
   本机 endpoint/IPsec/routing protocol publish 也已直接使用两个 owner，routing 主 reconcile planner 同样完成切换。
   在线 control/debug、手动端口轮换和 hook/composition 也已切走，production `currentState()` 已删除。随后删除了不完整的配置热重载链：`config.yaml` 只在进程启动时读取，配置变更通过完整 restart 应用，不再局部替换 LinuxDriver/gossip config 而遗留旧 watcher、health worker、Observer 或 transport。
   CLI 查询已按来源收口：verified/common 允许离线读取；status/peer/peers/sync/admission 使用 gossip checkpoint 的离线路径统一明确标为 checkpoint/last-known；links/firewall/BIRD/health/ping/
   peer lifecycle 等 platform runtime 查询要求在线 daemon，不再从 bbolt reconcile snapshot 冒充 live，也不由 CLI 直接调用 platform driver。
   read model 随后开始收敛为 typed canonical view envelope：zone/service/route/IPAM/endpoint、records/sync/peer/zone debug、
   status/peer lifecycle/gossip peers/health 均由 daemon 或离线 owner 调用同一查询函数生成最终 inspect DTO，CLI 只负责呈现；
   links/firewall/Babel/health/ping 也已改为 daemon 直接返回 canonical inspect DTO，旧 resource response 和 links live-replan 换壳已删除；
   `record_get`、admission diagnosis 和 Endpoint ACL list 也已退出巨型 `controlResponse`，直接通过 typed view envelope 传输；
   旧 `status` 混合回包也已拆除，Observer/control 共用同一 operational status 投影，root public key 改为独立 typed view；
   `verify_chain` 同样返回 typed bool view，只读 control 已不再借用 mutation response；
   E2k 最终边界测试确认在线 daemon 独占 Bolt handle 时 CLI 只经 control 读取，关闭 daemon 后 offline owner 生成相同 canonical Zone DTO，
   且 control、CLI presenter、Observer HTTP 对同一 owner fixture 的 Zone path/count/revoked 语义一致。
   routes canonical DTO 已从 HTTP 包迁到 `internal/inspect`，Observer 直接返回该模型；zones/peers/status 的排序、来源判定和
   聚合投影也已归入 `internal/inspect`。links 只保留前端实际消费的扁平 REST schema，不再附带 `raw` canonical view，也不在 HTTP 层重新推导 desired/runtime 状态。BIRD raw debug 的命令选择已归 `pkg/routing/bird`，neighbors/routes/entries、
   filter definition 解析、LinkOutput 接口上下文和 canonical dump enrichment 也已从 executable wrapper 移入 `internal/inspect`；app 只保留在线执行、配置文件读取及传入 provider-neutral link outputs。
   `debug routes` 与单前缀 `debug route` 也已合并重复的 control/offline fallback：两者共用同一个 canonical routes loader，在线读取 daemon control，离线只从 common owner 构建授权路由视图。
   IPsec desired/SA/action/skip 在 reconcile 边界投影为不含私钥和 spec 指针的 canonical `internal/state` observation；`internal/inspect` 直接 alias 这四组 live DTO，已删除第二套同字段 struct、逐字段 builder、app 批量 converter 和 debug rotate 的重复 SA copier。Observation clone 仍保留并发隔离，`LinkOutput` 仍作为 routing/firewall/health 的窄消费契约。
   health canonical view 与 daemon 内的 `debug ping` 执行链直接共用现有的安全 `health.ProbeTarget`，不再先转成字符串型 `inspect.HealthTarget` 再解析回执行类型。随后中间 `ping_targets` control 也已删除：daemon 使用自己持有的 Linux health prober 完成目标选择与探测，直接返回带稳定 snake_case JSON schema 的 canonical `inspect.PingDebugView`；CLI 只传选项并渲染结果，不再创建平台 prober。长探测使用 context-aware control transport，不受普通只读请求 10 秒 deadline 限制，并仍可由 CLI context 取消。
   record/IPAM/route/service 的在线请求也已在 control 边界直接转成与 `--direct` 相同的 `corestate.LocalIntent`；Daemon 单 writer 队列只携带一个 `common_mutation + LocalIntent + dryRun`，原四种事件 payload、`daemonRecordPut` 和 app 侧重复的 reserved-record 校验表已删除，IPAM/route 成功提交后的同步路由刷新改由 intent 类型判定。
   Observer routes/peers/status/zones/BIRD/links/health 均直接使用 canonical `internal/inspect` DTO；`LinkInspection` 自身采用现有扁平 REST schema 和稳定 JSON tags，不再复制 `LinksResponse/LinkJSON`。Health 的 target/sample/instance/desired 合并移入 `internal/inspect.BuildHealthView`，control、文本与 Observer 共用最终 `HealthView`；canonical JSON schema tests 也已迁回真实 owner，`internal/inspect/http` 已整组删除。
   Health view 只接收已脱敏的 canonical `inspect.LinkInstance/DesiredLink`，输出页面与 CLI 所需的 link/probe context，避免携带 owner token、内部错误和状态机对象。Links canonical inspect 同样只保留安全的 owner manager；owner token 在进入查询模型前已经删除。
   Health datasource/series 的固定 HTTP 字段也已改用现有具体类型；BIRD endpoint 直接返回带稳定 JSON tags 的 canonical `BabelDebugView`，runtime resource owner/token 明确不进入响应，页面消费 instance/reconcile `FailureView`。
   Health join 在 canonical builder 内直接建立短生命周期的 target/instance/desired 索引；原 Observer 单调用转发 helper 和 HTTP 二次 builder 均已删除。
   Observer 页面残留的 `last_error` 读取与 Health 裸 sample/嵌套 sample fallback 也已删除；status、peer、health、takeover 与 routing 错误统一消费 canonical `last_failure {code,message}`，Health 统一读取 `HealthLinkView.health`，不再依赖兼容字段。
   Health runtime context 也已直接复用 secret-free `inspect.LinkInstance`，不再维护 `HealthInstanceContextInput` 与另一份六字段逐项投影。
   `debug rotate --direct` 已改用正式 typed intent/runtime commit。production 已无 aggregate `Snapshot()`、clone、loader 或 writer；
   `stateFile/stateMeta` 只承担旧 schema 单向读取，明确随旧数据库支持周期删除。Daemon 不再缓存第二份
   common revision 或不完整的 `SnapshotTime`，status revision 直接来自 common Store。
5. CLI/展示：尚未系统迁移；只在 owner 拆分时同步迁走实现级代码和测试，不先做目录搬家。

### 5.4 2026-09-16 审计后的可执行余项

核心 Runtime/State/Observation 和 canonical inspect 迁移已经闭环，后续只保留以下明确切片：

1. 已完成：删除 `EnableEventLoopSync`、`processPacketEvent`、`SyncTransportDeps` 与 endpoint collector 全局测试接缝；
2. 已完成：firewall YAML/effective config、managed 实例筛选、spec 构造、forwarding policy 和 policy input builder 已下沉；app 保留 reconcile 顺序；
3. 已完成：routing/BIRD 的 netns/BIRD/upstream 配置与纯 spec/export/announce、轮换 metric 策略已归 routing/Linux owner，复用既有 LinuxDriver 执行；
4. IPsec：下沉 protocol record 纯构造、reconcile 纯 helper 与安全 live projection，保留私钥先落盘和 rotation/apply
   的 Daemon 顺序；
5. 冻结 legacy schema 的直接升级截止版本，到期同批删除 decoder、DTO 与 fixtures；
6. CLI 壳只随真实 owner 迁移进入 `internal/photoncli`，不单独做目录搬家。

本次复核在 HEAD `3603972c9806` 上执行 fresh `make check`：fmt、vet、全量 Go 测试、Linux build 和 Windows amd64
cross build 均通过；`git diff --check` 通过，复核开始时工作树干净。没有为本次只读审计额外运行 race 或特权 smoke。

A5 测试接缝清理验证（2026-09-16）：fresh `make check` 通过 fmt、vet、全量 Go 测试、Linux build
和 Windows amd64 cross build；`git diff --check` 通过。首次沙箱执行因本地 UDP socket 权限失败，
完整检查在允许本地 socket 的环境执行。endpoint no-op fixture 显式关闭 IPsec gossip 地址引用，
避免真实接口采集引起下一轮 IPsec 地址补发；仍覆盖重复发布不写盘、不触发同步。
未运行特权数据面 smoke；本切片不改变生产协议、平台 apply 或关闭顺序。

A5 firewall 配置切片（2026-09-16）：生产代码新增 452 行、删除 454 行，净减 2 行（含移动文件）。
调用链为 app YAML 装配 → photonlinux.ParseFirewallConfig → FirewallConfig.ManagedInstances / FirewallInstanceConfig.Spec；
reconcile、Endpoint ACL enforcement 和 debug 均直接消费同一配置，不保留 app alias 或 forwarding wrapper。
解析只接收现有 namespace spec map 和 port mode，不再传完整 app netns/IPsec 配置或未使用的 dataDir；
稳定 charon 端口和 ListenAddrs 由 spec builder 直接提供。app 原有 enabled/disabled helper 保留在 config.go；
firewall 的 present-default-true 校验就地放在 firewall_config.go，不为简单布尔规则新增共享包。
prefix parser 留归其唯一 forwarding 消费者。
实例筛选/spec 单测已迁入 Linux owner；app 保留 YAML 集成、reconcile、ACL 与 revocation 测试。
定向配置测试与 fresh make check（fmt、vet、全量 Go 测试、Linux build、Windows amd64 cross build）通过，
git diff --check 通过。未运行特权数据面 smoke。forwarding policy 和 policy input builder 尚未迁完，TODO 保持未勾选。

配置包收口复核：已删除临时 configutil 包，撤回 routing/health/Observer 的关联改动；
app/photon 与 internal/photonlinux 的配置及 firewall instance 定向测试重新执行通过，git diff --check 通过。

A5 firewall 纯策略切片（2026-09-16）：生产代码新增 487 行、删除 499 行，净减 12 行（含移动文件）。
namespace YAML/parser、forwarding policy 的别名解析和 routing/upstream 有效类型归 internal/photonlinux/routing_config.go；
app 的旧 netns/实例类型和 forwarding_config.go 删除。没有新增包、接口、队列或兼容 alias。
Daemon → photonlinux.BuildFirewallPolicyInput 只传 verified view、授权路由集、已有 LinkOutput、namespace 配置和 routing 实例；
原 LinuxState、IPsec LinkInstance map 与 reconcile 工作对象不进入纯策略。host redirect grace 与 namespace 接口筛选随 builder 迁移。
共享分配前缀查询归 pkg/routing，BIRD 的 forwarding 前缀过滤归现有 pkg/firewall；删除单消费者 assignmentPrefixes helper、
无消费的 revokedSet、重复切片拷贝及等价错误分支。Daemon 的 owner 读取、revision 校验、Driver apply、Observation 发布与关闭顺序保留。
端口宽限期、共享前缀、namespace 隔离单测随 owner 迁移；app 保留 YAML 集成、reconcile/ACL/revocation 测试。
定向测试与 fresh make check（fmt、vet、全量 Go 测试、Linux build、Windows amd64 cross build）通过，git diff --check 通过。
未执行特权数据面 smoke。routing/BIRD YAML/spec/export/announce 和 IPsec 其余纯构造仍是 TODO 未完成项。

前缀查询后续收口：三个 helper 合并为 LocalAssignedPrefixes(ars, managedZone, includeShared)，
上游源地址调用传 false，其余消费者传 true，删除回调和两个旧入口。forwarding_config_test.go 已删除，
其中三个 app YAML 集成测试并入 config_netns_test.go；测试仍覆盖 namespace policy 装配、别名及错误配置层级。
本次定向前缀、上游源地址、firewall policy 与 namespace/forwarding 配置测试通过，git diff --check 通过。
提交前复核：函数合并与测试文件整理后的最终工作树再次通过 make check（fmt、vet、全量 Go 测试、Linux/Windows 构建）及 git diff --check。

A5 routing 配置切片（2026-09-16）：BIRD/upstream YAML、RoutingConfig、解析、默认值与校验归现有 internal/photonlinux，删除 app/photon/routing_config.go。
app config.go 直接调用 ParseRoutingConfig，不保留转发 wrapper 或 alias。enabled/disabled 沿用 Linux 层原有私有 helper，扩为同包配置共用，没有新增包。
删除重复 namespace target helper、两个默认字符串 wrapper 和无用 strings 占位；shutdown 直接判断 stop，空值仍保持 persist 行为。
upstream 解析及长 Unix socket 路径单测迁入 Linux owner；app 保留严格 YAML 装配、默认 namespace 与 reconcile 集成测试。
尚未下沉的 overlay namespace、router ID 与 namespace 列举暂归其 app reconcile 消费处，后续与 BIRD spec/export/announce 纯策略一起处理；Daemon 执行顺序不变。
本切片生产代码新增 451 行、删除 476 行，净减 25 行。make check（fmt、vet、全量 Go 测试、Linux build、Windows amd64 cross build）通过，git diff --check 通过；未执行特权数据面 smoke。

namespace 收口复核（2026-09-17）：删除 resolveOverlayNetNSName、routingNetnsNames、netnsRouterIDLabel。
overlay 直接消费配置解析完成的 NetNSSpec，通过 Linux NetNSTarget 与 routing/firewall/driver 共用 host/name/path 到运行时 key 的转换；删除 Normalized 后不可达的默认回退及参数。
RoutingConfig.NetNSNames 收集、排序、去重有效实例 namespace；Router ID 使用显式标签或已解析的实例 NetNS，不再次查询可能发生别名碰撞的配置 map。
本轮完整未提交生产差异新增 435 行、删除 499 行，净减 64 行；routing_reconcile.go 相比提交前净减 1 行。新增 host、named alias、path 配置与 overlay target 一致性测试，覆盖 path 必须提供稳定标签。
收口后的 make check（fmt、vet、全量 Go 测试、Linux/Windows 构建）与 git diff --check 通过；未运行特权数据面 smoke。

Firewall Spec 收口（2026-09-17）：YAML 解析直接返回 pkg/firewall.FirewallInstanceSpec，并填入稳定 charon 500/4500 端口。删除重复 FirewallInstanceConfig 及逐字段 Spec() 转换；managed 筛选、debug、Daemon 与测试直接消费同一类型。reconcile 按值遍历 spec，仅在局部副本赋入动态 EndpointServices，不写回配置。原转换测试改为解析测试，覆盖端口、服务和监听地址。
Spec 收口后的 make check（fmt、vet、全量 Go 测试及 Linux/Windows 构建）与 git diff --check 通过；未执行特权数据面 smoke。

Routing Spec 组合收口（2026-09-17）：RoutingInstance 仅保留实例管理字段和 BirdInstanceSpec/UpstreamConfig；UpstreamConfig 仅保留开关与策略，并持有 VethSpec。删除 BIRD 路径、metric、Babel、ECMP 和 veth 接口/地址的重复字段，解析直接填写现有执行类型。
reconcile 与 shutdown 按值使用基础 BIRD spec，补入 RouterID、Owner、静态路由与接口策略；veth 直接使用配置中的 spec。删除旧逐字段搬运和无效 dataDir 推导及传参。
BIRD namespace spec 在解析时保留，修复命名别名且无 overlay 时重新按目标查配置 map 会丢失 namespace 的问题；测试覆盖真实 namespace、veth namespace 一致，以及动态 RouterID/Upstream 不写回配置。BIRD 动态 spec/export/announce 下沉仍待后续切片。
组合收口后的 make check（fmt、vet、全量 Go 测试、Linux/Windows 构建）与 git diff --check 通过；未执行特权数据面 smoke。

Routing 配置测试归属整理（2026-09-17）：从 app/config_routing_test.go 迁走 6 组字段映射、默认值、shutdown policy、Babel 参数、禁用和开关冲突测试，改为直接解码 RoutingConfigYAML 并调用 Linux ParseRoutingConfig，原详细断言保留。app 仅保留 3 组总配置边界测试：未知旧字段拒绝、namespace/data_dir 装配、upstream 默认 namespace 衔接；删除其中与 Linux 单测重复的 veth 默认参数断言。定向测试通过。
测试整理后的 make check（fmt、vet、全量 Go 测试、Linux/Windows 构建）与 git diff --check 通过；未执行特权数据面 smoke。

Firewall/namespace 测试归属整理（2026-09-17）：11 组 firewall 字段、hooks、priority、host、监听地址和 mode/backend/冲突校验直接调用 Linux ParseFirewallConfig；overlay 测试拆分，app 只检查 namespace forwarding 的装配。5 组 namespace 默认值、具名项、forwarding 别名和非法 host 配置测试归 ParseNetNSConfig。app 保留 IPsec port mode 联动、默认 namespace、未知引用和严格 YAML 拒绝，forwarding/default_netns/mode/backend/host 拒绝断言核对具体错误。原有效断言保留，未新增生产代码。定向测试通过。
本次测试归属整理后的 make check（fmt、vet、全量 Go 测试、Linux/Windows 构建）与 git diff --check 通过；未执行特权数据面 smoke。

A5 路由前缀策略下沉（2026-09-17）：AuthorizedPrefixes 与 AutoAnnounceAssignedPrefixes 归 pkg/routing/prefixes.go，后者只接收全量开关和 selectors，不依赖 app ipamConfig。BIRD export 及 upstream route/source prefix 选择归 internal/photonlinux/routing_prefixes.go；export 直接接收已有 ForwardingPolicy，零值维持非 transit 语义。删除 app 原 helper 与单调用开关 wrapper。
共享分配源地址单测跟随 owner 迁移；新增 selector/旧 assignment 布局回退、transit allow/deny、上游排除本地子网并保留聚合和去重远端路由的策略单测。原发布、撤回、显式宣告保留、IPsec 和 BIRD reconcile 集成测试继续覆盖 app 调用链。未新增包或接口。动态 BIRD spec、轮换接口策略与自动宣告计划仍待下沉；本切片不改变提交和 Driver 执行顺序。
本切片 make check（fmt、vet、全量 Go 测试、Linux/Windows 构建）与 git diff --check 通过；未执行特权数据面 smoke。
前缀 helper 收口：删除 routing_prefixes.go 中 firstUsablePrefixAddress、prefixWithinAny、prefixWithin、netipPrefixLess 四个 helper；源地址选择及包含判断就地表达，排序复用同包 routing.go 的 prefixLess。保留地址族、前缀长度、地址边界与去重语义，未新增通用工具包。相关上游前缀与导出策略定向测试通过。
helper 收口后的 make check（fmt、vet、全量 Go 测试、Linux/Windows 构建）及 git diff --check 通过。

A5 自动宣告计划下沉（2026-09-17）：比较当前宣告与已选 assignment 的纯逻辑归现有 pkg/routing/prefixes.go 的 AutoAnnounceChanges，显式接收全量开关和 selectors，返回 announce/withdraw 两组前缀。删除 app autoAnnounceAssignedIPsPlan、autoAnnouncePlan、changed 方法、永远为空的 error 返回链和重复 managed zone 判断；未新增包、接口或转发入口。
调用链为 Daemon 读取 Common view -> routing.AutoAnnounceChanges -> Common.ApplyLocalIntents -> 日志与通知；签名、原子提交和产品生命周期继续归既有 owner。selector 模式只撤回 auto-owned 宣告，旧全量模式继续管理所有本机宣告；规划不修改 NetworkState。
生产代码新增 67 行、删除 80 行，净减 13 行；app routing_reconcile.go 净减 73 行。纯策略回归测试归 pkg/routing，既有 app 发布/撤回/重复发布与 selector 集成测试保留。make check（fmt、vet、全量 Go 测试、Linux 构建及 Windows amd64 cross build）与 git diff --check 通过；未执行特权数据面 smoke。BIRD 动态 spec 与轮换接口策略仍待后续切片。

A5 BIRD 动态 spec 下沉（2026-09-17）：BuildBirdInstanceSpec 归现有 internal/photonlinux/routing_spec.go，组合 RoutingInstance、router ID、link groups 与 AuthorizedRouteSet。按 namespace 直接选择 overlays，保留首个匹配 group 的 namespace spec；无 overlay 时保留解析后的 namespace。删除 app netnsOverlayGroup、groupOverlaysByNetns、buildBirdInstanceSpecForNetns、upstreamPeerNextHop、upstreamStaticRoutesEnabled 及 reconcile 的中转 map 参数。
Daemon 继续读取 owner、推导 Router ID、生成轮换接口策略，并按原顺序执行 veth/upstream/BIRD 与发布 Observation。上游 static/external/disabled、IPv4/IPv6 next hop 和 shared assignment 路由语义不变。namespace 无 overlay 与 external upstream 的纯构造测试迁回 Linux owner，新增多 overlay/跨 namespace、双栈静态下一跳和配置不被写回的覆盖；app 保留真实 reconcile/生成配置/平台调用集成测试。
本切片生产代码净减 27 行；连同上一轮自动宣告未提交改动，生产代码新增 136 行、删除 176 行，累计净减 40 行。make check（fmt、vet、全量 Go 测试、Linux build、Windows amd64 cross build）与 git diff --check 通过；未执行特权数据面 smoke。轮换接口策略仍待下沉，未新增 package、controller 或转发入口。

A5 BIRD 轮换策略下沉（2026-09-17）：BirdRotateInterfacePolicies 归现有 internal/photonlinux/routing_spec.go，直接接收 IPsec LinkInstance、现有 LinkOutput 与 BirdInstanceSpec，不依赖 app observation summary 或 AppConfig。LinkOutputBelongsToBirdInstance 由轮换策略和 app 健康观察两个真实消费者共用；删除 app 同名旧函数、birdRotateInterfacePolicies 与单用途 linkInstanceByLinkID，不新增状态、DTO 或 owner。接口策略直接排序最终结果，删除中间接口名称切片。
纯 metric 单测随实现迁回 Linux owner；补充 namespace/overlay 排除、缺失实例与非轮换实例、LinkID/ID 回退、共享接口取最大 metric 和输入顺序不影响输出的回归测试。app 继续以集成测试覆盖 BIRD 观察到 health cutover gate 的调用链。该切片生产代码净行数持平；累计未提交生产代码新增 200 行、删除 240 行，净减 40 行。make check（含全量测试、Linux 与 Windows amd64 构建）和 git diff --check 通过，未执行特权数据面 smoke。A5 routing/BIRD 配置与纯策略项已完成，后续转向 IPsec 窄边界迁移。

### routing_reconcile.go 函数复核（2026-09-17）

本轮沿用工作区已有的 spec/export/announce 策略下沉，逐个核对余下函数及调用方：

| 函数 | 结论与依据 |
| --- | --- |
| reconcileRouting | 保留 Daemon；读取一致快照、auto-announce 后刷新版本、调度实例并发布结果。 |
| publishRoutingObservation | 保留；版本过期时拒绝发布并重新标脏，是必要的状态边界。 |
| reconcileRoutingForInstance | 保留编排；spec 来自 photonlinux，文本来自 bird.Generate，Driver 执行 I/O；应用层负责执行顺序、失败状态、hash、强制重载与 health 通知。没有为 Generate 再加转发包装。 |
| observeBirdForHealth | 保留；Daemon 持有 health 生命周期并限定观测超时。 |
| recordBirdHealthObservationUnavailableForLinks | 删除纯转发包装；调用方直接发布空观测，保留使 cutover 失效的行为。 |
| recordBirdHealthObservationForLinks | 保留；读取 app LinkOutput、选择 staged 链路并写入 Daemon health。 |
| birdObservationForInterface | 下沉 photonlinux.BirdObservationForInterface；是 BIRD 到 health 的无状态适配，不应让通用 BIRD 包反向依赖健康策略。纯单测一起迁移。 |
| birdRouteIsBabel | 删除单用途函数，判定内联到上述转换。 |
| stopManagedBirdInstances | 保留；关闭策略与强制停止由 Daemon 生命周期决定。 |
| birdDumpForControl | 保留；control 请求聚合 Driver 原始输出与 inspect DTO，属于应用层诊断入口。 |
| routingInstancesEnabled | 保留；reconcile 与 daemon 周期调度两个调用方共用过滤结果。 |
| routingInstanceEnabled | 保留；批量过滤与单实例入口共用禁用判定，避免直接入口漏掉安全检查。 |
| birdOwnerForInstance | 下沉为 RoutingInstance.BirdOwner；启动/停止共用同一资源身份构造，删除可与实例 namespace 不一致的额外参数。 |
| routingCrashBackoff | 保留；属于 Daemon 重试时序，不是 BIRD 配置语法。 |
| formatBirdProcessExit | 保留；为 app 运行观测生成失败描述，无需新增导出接口。 |
| rootTrustHash | 保留；提取 Photon Network 根身份并用于稳定 router ID，通用 BIRD 包只接收身份字节。 |
| isDryRunMissingBirdError / isDryRunConnectError | 暂保留行为；命名有误导，实际仅按错误文本分类，没有检查 dry-run 开关。是否收紧错误传播应另做行为变更及回归，不混入本轮移动。 |
| autoAnnounceAssignedIPsResult | 保留；纯决策已归 routing.AutoAnnounceChanges，这里负责事务、日志和变更通知。 |
| routingNetnsProtocolIntent | 保留；发布 namespace 信息，供未来 Router-ID 来源审计使用。当前没有业务读取方，但属于明确保留的协议设计。本地 Router-ID 从 Zone、trusted root 和 namespace/显式标签直接派生，不读取该记录；来源约束尚未实现。 |
| bytesEqual | 删除，使用标准库 bytes.Equal。 |

测试文件改为 routing_reconcile_apply_test.go：保留授权前缀进入实际生成文件、启动/重载、版本拒绝、external/disabled 和调度行为；删除与 bird/generator_test.go 重复的接口模板、RTT/interval 文本断言及重复 namespace 赋值。生成器语法单测继续由 BIRD 包负责，app cutover 集成测试继续覆盖观测失效阻止切换。

本轮验证：首次全量测试受沙箱 Unix/UDP socket 权限限制；在允许本地 socket 的环境重跑 make check 全部通过（fmt、vet、全量测试、Linux 构建、Windows amd64 交叉构建），git diff --check 通过。未执行特权数据面 smoke，未提交或发布。

### IPsec 自动端口发布策略下沉（2026-09-19）

调用链为 Daemon.publishLocalProtocols → ipsecProtocolPlan → localIPsecRecords → ipsec.PlanPortPublication → 按需 PlanPortRecord。app 继续读取当前 verified 的端口记录，协议层接收 mode/range、轮换间隔、宽限时间、旧记录与显式时钟，决定复用还是生成下一代。复用不刷新 UpdatedAt，固定模式不自动轮换；range 模式严格超过间隔才轮换，长时间停机也只前进一代。手工轮换继续通过原 PlanPortRecord 指定代数。

删除 app 的 localIPsecPortRecord、nextPortGeneration、portRecordMatchesConfig、ipsecPortRangesEqual；没有新增配置 DTO、facade 或状态 owner。已有私钥落盘、revision guard、公共 record 发布和 data-plane apply 顺序不变。生产代码新增 32 行、删除 73 行，净减 41 行。

协议层新增边界测试覆盖轮换前/恰好到期/到期后、禁用轮换、长时间间隔、缺失时间戳、range 变化、切换固定模式、无效 range、旧记录不被修改及 previous grace；app 保留发布与持久化集成测试。IPsec 地址、transport key、overlay 构造和其余 reconcile helper 仍待后续独立切片。

验证：定向端口策略与 app 发布/手工轮换测试通过；make check（fmt、vet、全量测试、Linux 构建、Windows amd64 交叉构建）和 git diff --check 通过。未运行特权数据面 smoke；本切片尚未提交、推送或部署。

### IPsec profile、overlay 和公钥投影下沉（2026-09-19）

本轮继续完成三个独立纯构造边界：

- pkg/transport/ipsec.BuildProfileRecord 组合本地 Zone、transport fingerprint、role、groups 和 AddressRecord。PublicationFamilies 保留声明侧顺序、去重和 IPv4 fallback，显式与 planner 的 peer contact-family 选择区分；后者对 singular/plural 优先级、空集合和 IPv4-mapped IPv6 有不同语义，不强行合并。NAT public hint 不被当作入站可达证明。
- BuildOverlayIntentRecords 接收 groups、声明 families、本 Zone 原有记录 map 和时钟；保留无效 group 跳过、exhaustive/family-redundant path keys，以及内容相同保留 UpdatedAt。app 保留 verified snapshot 读取和协议 intent 提交；删除 localIPsecOverlayIntentRecords、existingOverlayIntentRecord、overlayIntentContentEqual、localOverlayIntentPathKeys，两个单用途纯 helper 直接并入 builder。
- internal/photonlinux.PublicTransportKeyRecord 负责持久化 key 的公开投影及旧记录缺省值，不读取/修改 PrivateKey。删除 app buildTransportKeyRecord、ipsecPublicKeyString 和 sameIPsecPublishRuntime 转发包装。ensureIPsecTransportKey、事务 revision guard 和私钥先持久化仍归原应用/State 路径。

纯测试覆盖 dual-family DNS、去重和 fallback、path mode 去重、保守 NAT、overlay timestamp 稳定/变化、错误旧记录恢复、输入不可变，以及公钥投影缺省元数据和私钥隔离。app 保留签名、持久化、DNS families、endpoint lease 刷新和 overlay 重复发布等集成测试。IPsec 大项仍未完成：地址宣告/gossip endpoint 适配和其余 reconcile/live projection 留待后续。

本轮定向测试及 make check（fmt、vet、全量 Go 测试、Linux 构建、Windows amd64 交叉构建）全部通过，git diff --check 通过。连同上一轮端口策略，当前未提交生产代码新增 204 行、删除 275 行，净减 71 行；其中本轮净减 30 行。未执行特权数据面 smoke，未提交、推送或部署。

### IPsec 地址宣告下沉（2026-09-19）

localIPsecAddressRecord 现在只读取配置、从本 Zone verified record 解码可选 gossip.EndpointRecord，再调用 internal/photonlinux.BuildIPsecAddressRecord。Linux 平台适配层组合 IPsec 专用手工地址、兼容 advertise 地址、手工 DNS、gossip endpoint 与 listen fallback；未新增配置 DTO 或状态 owner，也未把 gossip 适配塞进通用 IPsec 协议包。

保留来源顺序、priority、ID、地址去重和 scope/source 映射；gossip endpoint 超过 TTL+grace 才丢弃，缺省 TTL 回退不变；LastObserved 不进入 IPsec 声明，所以续租不触发重复发布。splitAdvertiseAddress 的端口返回值原本无人使用，改为仅解析 host 的内部函数。app 删除 ipsecFamily/ipsecReachability 等纯地址 helper，现有发布、DNS 和 endpoint 集成测试继续覆盖真实配置读取。

新增纯测试覆盖手工地址优先及跨来源去重、DNS 去重、精确过期边界、默认 TTL、过期/无效地址排除、scope/source 分类、续租内容稳定、输入不变，以及 IPv4/IPv6/wildcard/hostname listen fallback。既有地址 ID 生成规则保持不变，本轮不混入语义调整。IPsec 大项仍留 reconcile helper 和安全 live projection 待审核。

验证：地址纯测试、app IPsec 发布/地址集成测试、make check（fmt、vet、全量测试、Linux 与 Windows amd64 构建）及 git diff --check 全部通过。累计未提交生产代码净减仍为 71 行，本切片生产代码总行数持平。未运行特权数据面 smoke，未提交、推送或部署。

### IPsec 安全观测与旧逻辑删减（2026-09-19）

发布策略已提交为 434ef9c。后续将 desired/action/SA 的字段白名单投影归 internal/photonlinux，app 仍拥有 summary、版本校验及发布；在线 SA 诊断复用同一投影。删除单用途 endpoint/撤销查询 helper，group 的 spec/backoff/retention 改为一次遍历，action 共用一次原始 group 查询，rollback/cleanup 合并 staged 清理并保留各自失败和时间戳语义。当前生产代码新增 116 行、删除 145 行，净减 29 行。测试保留 app 私钥隔离集成检查，并补充投影脱离输入引用、spec 身份优先、空地址和计数刷新验证。

验证：make check 与 git diff --check 通过。新增测试按现有 FormatScopedTunnelAddress 的缺失地址占位符 `-` 校正预期，生产格式未改变。未运行特权数据面 smoke，本轮续作未提交。

测试去重：删除 app 的独立 DNS 声明、endpoint 续租稳定、manual/endpoint 去重三个重叠用例；DNS 保留 profile/overlay 联动验证，续租与去重保留 Linux builder 测试，手工配置传递保留 app 检查并覆盖 advertise 重复地址。新增纯测试删去与发布集成测试重叠的 unchanged overlay 时间戳、profile 简单字段及端口初始默认值断言；保留 family 改变、错误旧记录、NAT 保守判断和轮换边界。此次测试净减 118 行，make check 与 git diff --check 通过，尚未提交。

### 本机 DNS 重连策略（2026-09-19）

LocalAnnounceDNSForceUpdates 归 pkg/transport/ipsec，直接接收域名、空闲阈值和现有 desired/instance/SA/resolver。删除 app 重复 resolver interface，单用途 SA 查找和空闲判断并入策略；保留 family/scope、入站计数、initiator 和解析错误保护。Daemon 仍负责 resolver 生命周期和错误日志。原两个测试迁到协议包并复用已有 fake，只新增部分 DNS 解析失败不重连的断言，未复制两套测试。

本切片生产代码净减 4 行、测试净减 2 行。make check（含全量测试和 Linux/Windows 构建）及 git diff --check 通过；未运行特权数据面 smoke，续作尚未提交。

### IPsec action 结果状态更新（2026-09-19）

上一批观测/DNS/测试去重已提交为 115d0d5。继续把 app 的 markIPsecActionFailed/markIPsecActionSucceeded 合并进现有 IPsec 状态机的 RecordActionResult，共用实例查找；ReconcileAction.InstanceID 同时用于结果处理和 app 日志。Driver 执行、diagnostic address 失败处理、revision guard 与观测发布仍留 Daemon。保留 rollback 的既有失败退避、standby down、takeover cooldown 和成功 teardown 删除语义。原两个纯状态测试迁入协议包，仅补失败 teardown 的保留/重试检查，app 集成测试不复制。

验证：make check 与 git diff --check 通过，未运行特权数据面 smoke。生产代码净减 1 行；测试迁移后因新增 teardown 检查及独立文件头净增 24 行。本轮续作未提交、推送或部署。

### IPsec contact 质量适配（2026-09-19）

统一协议 contact 解析与 gossip 质量匹配中的 observed/advertised 端口选择为 PortBinding.DialPort；删除 app contactDialPort 和 ipsecQualityAddrPortMatches。BuildIPsecContactQuality 归现有 Linux 地址适配文件，接收已读取的 gossip AddrQuality、地址和有效端口代数；Daemon 保留 transport/state 读取、peer 过滤和有效 record 提取。原端口布尔匹配测试替换为实际 quality map 检查，覆盖 observed 优先、advertised 回退、旧声明端口拒绝、零端口和跨地址排除，同时验证成功/失败/退避数据传递和 generation 隔离。

本切片生产代码净减 4 行，测试替换后净增 6 行；make check 和 git diff --check 通过。未运行特权数据面 smoke；连同 action 结果迁移仍未提交。

### IPsec reconcile 执行流减法（2026-09-19）

成组完成五项：publishIPsecObservation 改为无返回值，删除四处恒不可达的保存失败包装；action apply 与诊断地址失败共用一次 RecordActionResult/观测发布/错误返回；recordIPsecReconcileError 直接使用 ipsecSnapshot 已复制的 summary；单用途 missing-XFRM 状态循环回到调用处；密钥填充下沉 Linux 适配层并删除 peer 公钥解码后的二次复制。本地私钥逐 spec 复制保留，app 仍控制 persisted key 读取、Driver I/O、revision guard 和结果发布顺序。

现有 SA 计数刷新、过期版本拒绝和 daemon 回归继续验证执行流；新增一项密钥隔离测试检查 planner 输入、持久化私钥及不同 spec 不共享注入的私钥缓冲区，并检查 peer 缺失/非法记录。未新增状态 owner、配置 DTO 或转发层。

验证：现有 IPsec 应用测试、密钥隔离测试及 make check 全部通过，git diff --check 通过。本切片生产代码净减 21 行；连同 action/quality 未提交改动累计生产代码净减 26 行。测试复用原有观测/版本回归，删除无意义 error 断言，仅新增密钥隔离检查。未运行特权数据面 smoke，未提交、推送或部署。

### IPsec 发布规划去冗余（2026-09-19）

规划阶段的 publish_saved/publish_unchanged 改为 publish_planned，输出 record_updates 数量，不再把尚未提交的计划说成已保存。删除只为选择日志分支而存在的完整 transport key 比较；端口决策日志并入已有 record 遍历，删除第二次遍历及没有实际调用来源的值类型分支。zonePublicKey 并回密钥生成处，仍把身份公钥作为 forbidden key，私钥落盘和协议提交链不变。复用现有发布、密钥与持久化回归，无新增测试。

验证：定向回归、make check 和 git diff --check 通过；本切片生产代码净减 25 行，测试无增量。未运行特权数据面 smoke，未提交或发布。

### 轮换状态清理去重（2026-09-19）

五处 staged 字段清理统一为包内 LinkInstance.clearStaged，调用方明确选择 idle/rollback/dual-running，原有失败退避、transition time 和旧 SA 清理动作不变。两段相同 route_cutover_pending 分支合并条件。复用现有轮换场景测试，仅增强原回滚用例对 staged 资源、deadline 和重试字段的检查，不新增测试用例。

验证：轮换定向测试、make check、git diff --check 通过。本切片生产代码净减 42 行；未运行特权数据面 smoke，尚未提交。

### IPsec 隧道地址配置与轮换窗口校验（2026-09-19）

overlay 的 tunnel_address YAML 类型、模式/地址族/地址池解析，以及端口宽限期覆盖 overlay 轮换保留期的校验迁入 internal/photonlinux/ipsec_config.go。app 直接调用新 owner，删除旧解析器和轮换校验 helper；LinkGroupSpec.Normalized 已补齐一小时保留期，因此删除 app 的重复默认值与不可达兜底。配置字段、错误文本和兼容行为保持原样。

参数单测随解析器迁移，app 保留 YAML 接线、旧地址池兼容、新旧格式互斥及跨配置窗口检查。补充 family 推导、缺失 pool、默认轮换保留期和窗口相等边界；本切片测试净减 23 行。todo 下一步改为尚未完成的 IPsec 顶层配置与 overlay 组合解析，避免重复安排已完成的 test-only helper 清理。

验证：定向配置测试、make check（含 Linux/Windows 构建）、git diff --check 通过。未运行特权数据面 smoke；本轮与前几轮改动仍在工作区，未提交、推送或部署。
