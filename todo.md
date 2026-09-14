# Photon Todo

设计文档见 [docs/design.md](docs/design.md)。本文件只保留可执行任务。

## 当前执行：xfrm policy 收口到 XFRMDriver

目标：policy 不再把 `lo` 泄漏进 spec/instance；附着点（地址、路由、inspect）收进 XFRMDriver。Create/Adopt/Repair/Staged 走同一条 Ensure。daemon 不再读 `xfrm_backend`。决策见 `docs/wsl2-action-plan-tmp.md`。

- [x] planner/rotate 保持 InterfaceName=`phx*`；owner 能校验
- [x] policy Ensure 装 underlay 路由并返回错误；Assign 落 lo 不剪枝；Delete 不删 lo
- [x] Inspect/匹配看 lo（SharedAttachment），不要求 MULTICAST；删除 daemon `policyXFRMBackend()`
- [x] Adopt 走 Ensure；删除 `XFRMPeerRouteInstaller`（Staged 已走 EnsureInterface）
- [x] 更新 `docs/wsl2-xfrm-backend.md`；duplicate_gc 去掉 VTI 注释
- [x] `go test ./pkg/transport/ipsec` 绿灯；`app/photon` Linux 编译通过（本机 Windows 无法跑 daemon 测试）
- [x] 第 3 步：firewall 叙事解绑（planner 注释 + `docs/new/firewall.md` §4.3；规则未改）

## 已完成里程碑归档

完整历史清单已拆到 [docs/roadmap-archive.md](docs/roadmap-archive.md)，主 TODO 只保留当前执行队列和后续计划。

- [x] Phase 0-2：可信状态机、join/delegation、gossip 同步、discovery、bounded history 和操作文档。
- [x] Phase 3-3.6：daemon/single-writer 基座、NAT/observed path、MTU-safe gossip 和 object-pull/chunk fallback。
- [x] Phase 4：StrongSwan/XFRM 主线、daemon admin 写入、auto-join、planner/reconcile、host-born XFRM、低频 rotate、bidirectional takeover。
- [x] Phase 5：BIRD Babel、route authorization、per-netns BIRD 配置模型、routing debug 和 dry-run smoke 基座。
- [x] Phase 6.0-6.7.6：事件驱动控制面、IPAM、准入诊断、防火墙、动态 peer、撤销清理、链路健康和 Observer MVP 主线。
- [x] Phase 6.7.7：`app/photon` 模块化重构第一阶段（Observer/debug/inspect 先行）。`internal/observer`、`internal/inspect`、`internal/inspect/http`、`internal/inspect/text` 和 `internal/state` 已承接读侧 view、HTTP DTO、CLI presenter、通用 observer handler 和共享 snapshot 类型；`app/photon` 保留 executable wiring、daemon provider、control/live/offline source adapter。详细归档见 [docs/roadmap-archive.md](docs/roadmap-archive.md)，后续约束见 [docs/app-photon-modularization-design.md](docs/app-photon-modularization-design.md)。
- [x] Phase 7.1 异构 TransportLink 并行共存（模型、实验与公共边界已冻结）。
- [x] Phase 7.3 Gossip UDP object chunk repair。
- [x] Phase 7.10 Daemon / 本地控制接口生产化。
- [x] Phase 7.13-7.15 稳态冗余优化（XFRM maintenance、endpoint timer、unsolicited ping）。
- [x] Phase 7.16 Firewall backend-native inline hooks 及后续收口（external mode、ip6tables 双栈探测、`photon debug firewall` flag、nft priority 配置）。详细实现归档见 [docs/roadmap-archive.md](docs/roadmap-archive.md)。

## Phase 9: Observer Web UI 重构（已完成）

**目标：** 解决现有 observer 网页视觉陈旧、信息架构混乱的问题。设计定稿见 [docs/new/observer-ui-redesign.md](docs/new/observer-ui-redesign.md)；observer 只读定位、REST API 形状与安全模型不变。

**约束：** 零构建（原生 ES Modules + 多 CSS 文件，无 Node 工具链）、零运行时依赖、纯 embed；注意 `//go:embed web/*` pattern 需随新增子目录扩大。

- [x] **9.1 设计基座**
  - `web/style/tokens.css`：中性灰底 + 单一 accent + 语义状态色（ok/warn/err/unknown）、字号/间距阶梯、radius token。
  - 布局壳重写：侧栏分组导航（总览 / 网络 / 监控）、底部连接状态三态指示、统一页头（标题 + 说明 + 页面级操作区）。
  - 基础组件收敛到 `style/base.css`：card、stat-card、badge、dot、table、kv、details、empty/loading/error 三态。

- [x] **9.2 前端模块化与重绘策略**
  - `app.js`（1153 行单文件）拆分为 `web/src/` 原生 ES modules：`api.js` / `store.js` / `events.js` / `router.js` / `format.js` / `components/*` / `pages/*`，单文件 < ~200 行。
  - store 按 endpoint 缓存 + 事件类型到 endpoint 的失效映射，SSE 事件只重取受影响键，不再整页刷新。
  - 重绘保留 scrollTop / 输入 / `<details open>` 状态，删除 `foldState` 全局补丁。
  - Health 页 sparkline 懒加载，消除每次刷新每条 link 一个 series 请求的 N× 放大。

- [x] **9.3 页面信息架构重构**
  - Overview 仪表盘化：全局状态横幅 + 问题清单（带深链）优先，统计卡与 reconcile 摘要其次。
  - Overlay（控制面：planner/SA/reconcile/rotation）与 Health（数据面：探针/RTT/loss/曲线）职责分离，导航文案明确。
  - Zones 双栏布局；authority/proof/revocations/history/Raw JSON 全部收入 Inspect 折叠区；hash 截断 + 点击复制。
  - Routes 错误置顶 + zone 过滤；BIRD 错误醒目展示；Gossip diagnostics 格式化 kv。
  - 全局：相对时间、列表页文本过滤、选中态写入 hash 可深链。

- [x] **9.4 事件链路补完（可选，动后端）**
  - `daemon.go` 广播点携带轻量 payload（`link_id` / `peer_id`），前端条目级失效。
  - 落地 `event_buffer_seconds` 环形缓冲 + Events 时间线页（独立可裁）。

- [x] **9.5 测试与文档收口**
  - `webapp_test.go` token 断言改写为模块化后的关键导出；`static_test.go` 覆盖新增子目录；`internal/observer` 与 `app/photon` observer 族测试全绿。
  - `app/photon/observer_api_*_test.go` 不应需要修改（REST 响应不变，9.4 除外），若需修改则说明越界。
  - `docs/new/observer.md` 第 6/9 节同步为重构后行为。

## Phase 7: 生产化收口与高级能力候选

**目标：** 先把 daemon/control/运维面补到可长期运行，再按真实需求推进异构 TransportLink 并行、可靠性补强和可选传输能力。Phase 7 不要求按编号顺序执行。

**当前建议顺序：**
1. 先完成 7.11.8/7.11.9 的稳态磁盘写入与 reconcile CPU 收口，并在真实 17-peer / 23-link 节点上复测。
2. 随后选择 7.7/7.8 discovery/relay 或 7.11 metrics/readmodel 的下一窄切口。
3. 7.2 高频 port hopping、7.4 WireGuard、7.5 GRE/VXLAN、7.6 SRv6 保持可选，等需求和实验环境明确后再开。

- [ ] **7.7 可选 Global Discovery Server**
  - 作为独立公网 rendezvous 服务，只用于无稳定 bootstrap、IP 频繁变化、复杂 NAT 等场景；默认 discovery 仍以 signed endpoint record + gossip 为主。
  - 服务端不成为信任根，不持有 root/admin/zone 私钥；客户端仍以 signed endpoint record 和 Zone trust chain 为准。
  - 支持最小 HTTP/JSON API：`POST /v1/announce` 上报本机 signed endpoint，`GET /v1/peers/{peer_id}` 查询候选 endpoints、observed addr、ttl 和 source。
  - 服务端负责 ttl cache、observed remote addr、限流、防重放和基础滥用防护；不替客户端做最终信任裁决。

- [ ] **7.8 可选 Relay Bootstrap Server**
  - 作为独立公网 bootstrap/relay 程序运行，负责收集节点发布的已签名 Zone/Record/endpoint 数据，维护本地数据库，并向其他节点传播。
  - relay server 不需要自己的 Zone，不持有 root/admin/zone 私钥，不签发 delegation/record，不成为信任根。
  - 支持 gossip bootstrap 行为：响应 `PING`/`PONG`/`FETCH_ZONE`/`FETCH_RECORD`/`ANNOUNCE`，并可 fanout/relay verified data。
  - 支持查询接口：节点按 peer id、zone、digest 查询 relay 已知 endpoints、zone snapshots、record snapshots。
  - 增加 backpressure、去重、allowlist 策略和 relay-only smoke。

- [ ] **7.11 运维与可观测性**
  - Prometheus/OpenMetrics 导出：节点数、链路状态、gossip 流量、zone 数量、chunk repair、object pull、health probe。
  - 先按 7.11.0 将 peer 纯诊断数据从 committed state 拆到独立 observability store；不能用 peer ID、endpoint 或原始错误串作为 metrics label。
  - 梳理 `photon status`、`photon zones`、`photon peers`、`photon sync` 等面向日常运维的简洁 CLI。
  - Observer 后续增强另见 Phase 7 之后远期后续。
  - Health probe 性能：已实现按 netns 常驻的 raw-ICMP worker，worker 固定 OS thread 后 `setns` 并按源/接口复用 ICMP socket；raw socket / `setns` 的 setup 失败自动回退 exec prober，消除正常路径的 `ip netns exec ping` fork/exec/mount 开销。待完成 root smoke：IPv4、IPv6 link-local scope、netns 删除/重建、`CAP_NET_RAW` / `CAP_SYS_ADMIN` / `NoNewPrivileges` 缺失时的降级；验收后再确认默认路径的长期运行行为。
  - [x] **Health burst 按包统计与链路状态精度**：`ProbeResult`、rolling window、状态机、CLI/Observer、spool 与 OpenMetrics 已改为累计真实 sent/received/lost；RTT 明确定义为每个 burst 最后一个成功回复的 RTT，部分回复保留 RTT，jitter 按时间序相邻 replied burst 计算。`loss_window`、连续失败、冷启动 down 门槛与恢复迟滞仍按 burst 计数，仅 loss threshold 改用包级比例，以保持生产告警灵敏度。单测覆盖 `3/3`、`2/3`、`1/3`、`0/3`、跨 burst window、raw/exec 一致性、执行错误；root smoke 在真实 netns 以确定性 10%/30%/70% 丢包验证包计数及 healthy/degraded/down 状态，并保留 100% loss/cutover/recovery 验收。Observer 在 metrics 启用时新增 `/metrics`。
  - **Daemon state-store 性能（perf 2026-07-24，2026-07-31 复核）**
    - daemon 生产写路径由主事件循环串行执行；packet receiver、object-pull、health 和 control 后台 goroutine 只投递事件或更新独立 observability，正常运行时不会并发执行两个 routing reconcile，也不会在 reconcile 中途插入另一个 committed writer。`DaemonStateStore` 的锁仍用于并发读和边界防护，全局 `revision` 用于排序及检测意外绕过 single-writer 的写入，而不是把多 writer 当作正常工作模式。
    - 当前 committed root 及其可达子结构必须永久不可变；写操作只修改 detached workspace 或 typed COW 拥有的字段，发布时在锁内替换一次 root。`Snapshot()` 在取得 root/revision 后释放锁再复制是安全的，前提正是旧 root 不再原地修改。
    - 当前主要成本不在 commit 语义，而在 `BeginUpdate`、`Commit` 和只读 snapshot 反复通过 JSON round-trip 复制完整 state，体积最大的 `Network` 因此反复分配、base64 编解码并增加 GC/缺页压力。
    - 实机 `photon db stats` 显示逻辑有效数据约 1,094,124 bytes：`_meta` 约 34,099 bytes（3.1%），所有 `zone:*` bucket 约 1,060,025 bytes（96.9%）。磁盘文件约 4 MB 是 bbolt 页、空闲页和索引等分配后的文件大小；此前提及的 48 MB 是 health spool，不是 Network/state DB。
    - [x] 将每个 `zone/key` 的 `RecordHistory` 上限从 128 收紧为最近 16 条；新写入持续按 16 条截断，加载旧数据库时也裁掉更早历史，下一次成功保存会重写逻辑值。bbolt 文件不会因此自动缩小，物理回收若有需要应另做离线 compact，不纳入当前 CPU 修复。
    - 保留通用 `StateStore.Update` 当前的完整隔离语义：不得直接转移 workspace 所有权，也不得单独删除 commit 的第二次 clone。`Workspace()` 仍会把裸指针交给调用者，且 callback 可以 retain 指针；在 typed mutation 收口前，第二次 clone 是 committed 私有性的保证。
    - 不把完整 clone 移入 store 锁内；仅把 clone 延后到第一次 revision 检查之后只能优化 stale transaction，当前 perf 未证明 stale 是热点，不作为独立优化。
    - 不引入 component/per-chunk revision。typed COW 继续使用单一全局 revision；按 single-writer 设计，stale 属于异常防护，必须丢弃结果并重新排队，不能通过字段级 merge 把基于旧输入计算的结果合入新 root。若未来明确把 routing/IPsec reconcile 改为后台并行计算，再单独设计 read-set/component revision。
    - 决定先实现完整手写深拷贝，作为保持现有事务边界不变的低风险降本层。2026-07-31 使用 1000 records、每条 128-byte value 的同一 Network fixture 复核：JSON clone 为 4.61-4.90 ms、1.47-1.56 MB、约 10,055 allocs；现有类型化手写 Network clone 为 0.212-0.226 ms、471 KB、4,013 allocs，约快 21-23 倍。该结果只代表 record-heavy Network，不把它直接外推为整机固定收益；手写 clone 之后仍需以同负载 perf 决定后续 COW 优先级。
    - `ZoneState.MerkleRoot` 当前没有完整的计算/失效维护，不能直接作为 digest cache。只有未来 perf 再次证明 zone digest 是热点，并覆盖 record/history、delegation、revocation、snapshot apply、recovery/import/purge、join/adoption 等所有 Network mutation 后，才考虑启用。
    - 不新增高基数内部 metrics；阶段验收继续由开发者手工运行 perf/strace，对比 idle CPU、clone/alloc、`LoadNetwork` 和 fork/exec。

  - [x] **7.11.0 先拆 committed control state 与纯 observability**
    - 这一步是 state-store 性能优化的前置阶段。Phase 6.7.7 已把 inspect/readmodel/presenter 从 `app/photon` 拆出，但数据所有权仍集中在 `stateFile`：代码模块化不等于存储模型已经模块化。先消除不该发生的 commit，再优化剩余 commit 的复制方式。
    - 先按语义把数据分为三层：必须强一致和持久化的权威状态；会影响调度、路径选择和重启收敛的控制器运行状态；只供 observer/debug/status 使用、允许丢失或短暂不一致的 observability。readmodel 在读取时合并 committed control snapshot、observability snapshot 和 health/BIRD actual snapshot，现有 CLI/HTTP DTO 尽量保持不变。
    - 第一窄切口只迁移已经确认纯诊断的 `DatagramStats` 和 `ObjectPullStats`，包括其中的 catalog/page/reject、too-large、repair/fallback 计数与最近一次详情。随后逐字段审计并考虑迁移 hint accepted/suppressed、read-only responder、active-pull 展示状态、relay suppression reason 和其他最近一次 action/error detail；不能因为字段显示在 debug 页面就认定它是纯诊断。
    - `BackoffUntilUnix`、`FailureCount`、`LastRelayUnix`、`DiscoveredAddr`、observed path/TTL/grace、`LastSyncUnix`、`RejectedDigests` 等仍影响同步、限流或实际路径，先留在 control state。`LastError` 当前也参与 observed/discovered path 判断，迁移前应先拆成稳定的控制错误码/状态和仅展示的错误文本。
    - 引入有界的 `PeerObservabilityStore`，优先放在窄职责的 `internal/observability`，由 `app/photon` 负责 wiring，由 `internal/inspect` 继续负责纯 view 构建；不要把 mutable store 放进 `internal/inspect`。store 自带独立锁或分片、按 peer snapshot 和删除/过期能力，不持有 `stateFile` 或 committed 子结构指针。
    - 第一版 diagnostics 不随主 state 持久化，daemon restart 后计数归零；旧 state 中遗留字段可兼容读取但不再回写。live observer/debug 合并新 store，offline DB 诊断允许显示 unavailable/reset。若以后确有历史需求，再低频批量写独立 spool/metrics store，不能重新推动主 revision。
    - 将 `recordDatagram*`、`recordCatalog*`、`recordObjectPull*` 等调用改写为 observability store 更新后，不得调用 `StateStore.Update`、install、publish 或 `SaveState`。补充并发 snapshot、peer 清理、restart reset、旧 state 兼容以及 CLI/HTTP schema 测试，再跑相同负载 perf 判断剩余 `recordSyncPeerState` 热点。

  - [x] **7.11.1 合并同一事件内的重复 peer mutation**
    - 在纯 diagnostics 迁出后，合并同一个 sync/packet 事件内剩余的 `sync_hint`、`peer_sync`、observed path、backoff/rejected digest 等控制状态写入，尽量一次提交；observability 更新独立聚合，不再参与 committed transaction。
    - 不改变状态机、control/observer DTO、落盘格式和 wire 格式；先做调用点收敛，不修改通用 `StateStore.Update`。
    - sync event 现在用事件内 mutation batch 按原顺序聚合 active-pull、backoff 和 completion，并在 `SaveState` 前 flush；hint shortcut 与 hinted-session 初始化也各自合并为一次提交。fetch responder packet 将 observed-path 与 read-only responder 合并，除仍会直接 apply Network 的 object-chunk 外，不再在 packet 末尾重复 publish 已安装的 committed snapshot。

  - [x] **7.11.2 实现 `UpdateSyncPeer` 局部 COW**
    - 保留全局 revision/CAS；新版本只构造新的 state root，复制 `SyncPeers` map，并深拷贝目标 peer 中会修改的 map、slice、pointer；`Network` 和其他未修改块只读共享。
    - mutation API 不向调用者暴露完整可变 `*stateFile`，也不得允许 callback retain 最终 committed root。`stateFile` 含 mutex，不能用普通结构体赋值直接复制锁；应显式构造不复制 mutex 的 root，或先拆出不含锁的 immutable root。
    - stale 时只允许有界重试。mutation 必须纯粹且可重放：不得在 callback 内执行 transport、网络、磁盘、`SaveState`、事件广播或外部计数；时间/随机输入在重试外捕获；依赖 Network 的判断每次基于最新 committed revision 重新计算。
    - 第一阶段继续保留 `Snapshot()` 和 `installCommittedSnapshot` 的完整 clone，让 `d.Sync.State` 仍是与 committed 隔离的可变副本；先消除 `recordSyncPeerState` 中 `BeginUpdate` + `Commit` 的全量 JSON clone，不同时改 live-state 一致性模型。
    - 只迁移剩余高频且确实影响控制行为的 `SyncPeers` 写路径，例如 backoff、observed/discovered path、relay throttle 和 rejected digest；peer repair、chunk fallback/NACK 等纯诊断应已在 7.11.0 迁出。`updateDiscoveredPeers` 必须拆成“从 immutable view 计算变化 → 提交 peer mutation → commit 成功后更新 transport”，避免 CAS retry 重复 transport 副作用。
    - `UpdateSyncPeer` 使用最多 4 次全局 revision/CAS 重试，只复制 state root、`SyncPeers` map 和目标 peer，并在 commit 前仅二次复制目标 peer 来隔离 retained callback；sync event/hint/backoff/relay/read-only responder/observed-path 已切换到局部 COW，`Snapshot()`/install 仍按计划保留完整 clone。
    - `updateDiscoveredPeers` 已拆成 replayable batch plan：基于每次最新 immutable view 一次计算 peer state replacements 与 transport plan，通过局部 COW 一次提交所有变化，commit 成功后才更新 known peer、discovered/observed transport cache；stale/no-op 都会复核 revision，无状态变化不升 revision但仍可修复 transport cache。daemon 调用点均切到新路径，独立非-daemon helper 保留原兼容行为。
    - 当前 1 MiB Network benchmark 的短基准为：通用 full update 约 15.99 ms / 6.53 MB / 137 alloc，local COW 约 633 ns / 1.26 KB / 6 alloc；该结果只确认复制路径量级，阶段后的实机 idle/perf 仍按上面的手工验收约定执行。

  - [x] **7.11.3 阻断 daemon 自写导致的 state reload**
    - 现有 `reloadStateIfChanged` 已用同一文件、mtime、size 的文件标记跳过无变化的 `BoltStore.LoadNetwork`；文件原子替换、读期间变化或 `stat` 失败时继续保守重读。
    - daemon 自己成功完成 Bolt save/commit/close 后，再读取并记录稳定的文件标记；reload 仅在标记明确等于当前进程刚完成的自写结果时跳过。保存期间文件再次变化、`stat` 失败或标记不确定时清空缓存并在下一轮正常 reload，不能屏蔽外部管理命令或其他进程写入。
    - 该项与 state COW 独立，可并行实现；perf 中剩余 `LoadNetwork` 约 1.49% 不保证全部来自自触发，改后需通过调用次数和新 perf 区分合法 reload。
    - 已完成：daemon 所有 SyncRuntime/StateStore 持久化路径统一在 Bolt transactions 与 `Close` 成功后记录文件 identity/size/mtime；close 前后标记不稳定、`stat` 失败或保存失败时保持空缓存。命中当前进程的稳定自写标记时只报告“无外部变化”，不返回任何内存 state；测试覆盖自写零 loader、外部写入仍 reload、读取期间文件变化不缓存以及保存失败清标记。

  - [x] **7.11.4 清零对 `d.Sync.State` 的直接写入**
    - 完整盘点 direct writer，至少覆盖 object chunk snapshot apply、rejected digest、discovery、admission，以及启动阶段 endpoint/IPsec/routing record publish；chunk fallback、NACK/peer repair 等纯诊断在 7.11.0 后不应再写 `d.Sync.State`。
    - 高频 `SyncPeers` writer 使用 `UpdateSyncPeer`；低频 admission、endpoint、IPsec、routing writer可先迁到现有通用 `StateStore.Update`，优先统一写入权威，不要求为每个字段预先建立专用 chunk API。
    - object chunk 对 `Network` 的修改是移除 live/store 双状态前的关键阻塞项：先提供保证 committed 隔离的 Network mutation；若完整 Network clone 仍成为热点，再进入 per-zone COW。
    - `recordBirdHealthObservationForState` 只从 state 读取并更新 health manager，不是 state writer；迁移时改用 immutable read/view，不为它新增 `BirdInstances` mutation。
    - 同时审计所有可能 retain/mutate committed 子结构的入口，不限于 `ReadCommitted`：包括返回 `*stateFile`/`*NetworkState` 的 API、validation 配置、map/slice/pointer 内部修改和 `d.Sync.State` 的全部调用点。结构共享后，任何旧 revision 被修改都会污染共享它的新 revision。
    - daemon UDP object chunk 已把 assembly/repair 与 committed mutation 分开：完整 zone snapshot 通过通用 StateStore workspace apply，损坏 chunk 的 rejected digest 通过 peer 局部 COW 提交；成功路径只升一个 apply revision，不再在 packet 尾部反向 publish。`sync serve` / `sync once` 也通过 DaemonStateStore 运行事件循环。
    - daemon 启动 admission diagnosis、endpoint、IPsec 和 routing record publish 已合并为一个隔离 workspace、一次 commit 和一次 save；无变化的第二次 prepare 不升 revision。外部 state reload 直接替换 committed authority。
    - reader/retain 审计已处理 transport observed grace slice 的原地 compact、verified-zone validation hook 对 Network root 的写入、health/BIRD 的状态读取，以及 `OnStateChanged` hook retain：transport/health 改读不可变 view，hook 接收 detached snapshot。`SyncRuntime.State` 字段已删除，编译器会阻止重新引入旧的双状态调用方式。

  - [x] **7.11.5 移除 live/store 双状态桥接**
    - 仅在 direct writer 清零、所有 reader 均遵守不可 retain/mutate 约定后，才把 runtime 读侧切换为 immutable committed view 或更小的 store projection；不要仅把一个仍可写的 `d.Sync.State` 指针指向 committed。
    - 随后删除 `installCommittedSnapshot` 的完整 clone 和 packet 后的 `publishCommittedStateSnapshot`；短、确定纯读的操作使用 committed view 或 `ZoneDigests()`、peer summary 等返回小结果的 projection，不为读操作复制完整 Network。
    - routing reconcile 的第二次 snapshot 保留其一致性语义：auto-announce 可能修改/撤回 record，BIRD 配置必须读取提交后的新状态。只有等价的数据依赖得到证明后才允许收敛，不能仅以减少 clone 为由删除。
    - 已删除 daemon 的 install/publish 桥接；peer、packet、object chunk、discovery、reconcile 和 control 写侧只提交 StateStore，持久化直接保存 committed snapshot。`SyncRuntime.State` 字段及无 StateStore fallback 已删除；transport 初始化和 legacy/standalone helper 必须显式接收 state，不能暗中持有第二份状态。
    - PING、catalog summary/page、hint session、timer、普通 `FETCH_ZONE`、relay、object-pull 与 observed-path seed 已改为 committed view 内生成 detached projection；回调外发送消息、更新 transport 或记录日志。完整 chunk fallback 与 reconcile 继续使用隔离 snapshot，避免在 committed 读锁中执行外部副作用。
    - routing reconcile 的 auto-announce 后第二次 snapshot 保留；空 firewall/routing flush、peer 局部写和 daemon 自写 reload 回归测试检查 revision 不被隐式 republish、committed state 不被旧快照替换。1 MiB Network 的服务级 `recordSyncPeerState` 隔离基准约 0.92–1.00 µs / 2.10 KB / 10 alloc，对照通用 full update 约 15.5–15.8 ms / 6.44–7.08 MB / 136–139 alloc。

  - [ ] **7.11.6 StateStore 正确性、手写 clone 与分层 COW**

    **目标与边界**
    - 在不改变 daemon single-writer、磁盘格式、wire 格式、sync 部分成功语义和现有 control/observer DTO 的前提下，先修复 snapshot apply 的失败原子性，再降低完整 clone 单价，最后逐步消除不必要的完整 clone。
    - 保留一个全局 `revision`。本阶段不增加 Network/Link/IPsec/Routing/Peer component revision，不支持两个 routing reconcile 并行合并，也不把 StateStore 扩展为通用多 writer MVCC。
    - committed root 及所有共享子结构一经发布不得原地修改；任何会写 map、slice、pointer 或 validation hook 的代码必须先取得该对象的独占副本。只读共享可以跨 revision 保留，Go GC 负责旧 root 生命周期。
    - 通用 `StateStore.Update` 在 typed mutation 完成前继续保留 detached workspace 和 commit 前第二次 clone，防止 callback retain `Workspace()` 后污染 committed。每个 typed COW API 只拥有明确字段，不向 callback 暴露完整可写 `*stateFile`。
    - 每个子阶段独立落地、独立 benchmark/测试；前一阶段的正确性和 perf 数据验收后再进入下一阶段。不得为了达到最终 COW 形态而在一个改动中同时重写 sync、routing、IPsec、firewall 和 persistence。

    - [x] **7.11.6.1 修复 `ApplySnapshot` 失败原子性**
      - 当前 `gossip.ApplySnapshot` 使用完整 candidate 验证 trust chain，但验证后转而修改传入 `NetworkState`；delegation/revocation 已写入或部分 record 已 `PutAt` 后发生错误时，调用者可能提交部分 snapshot。
      - 将 authority、parent proof、delegation、revocation、record/history 的全部变更先应用到 detached candidate；只有所有验证和 record apply 完成后才一次性安装结果。任何错误返回时，传入 Network 的字段、map、slice、record/history、root 和 validation hook 均保持不变。
      - 保持现有 stale record、record conflict、apply count、delegation count、auto-join 和 rejected digest 对外语义。snapshot apply 失败只记录 rejected digest；失败 snapshot 不得借由外层 `StateStore.Update` 提交 Network 的部分变化。
      - 测试至少覆盖：trust chain 失败、delegation/revocation 校验失败、前一条 record 成功而后一条失败、stale/conflict 被跳过、成功 apply；失败用序列化状态或逐字段断言验证前后 Network 等价，并运行 `pkg/core/gossip` race 测试。
      - 已完成：snapshot 的 trust、delegation、revocation 和有序 record 合并全部在完整 detached candidate 上执行，成功后才一次替换传入 Network；candidate clone 保留 nil/empty 形态、root、validation hook 和 nil zone entry。回归测试覆盖全部失败点、stale/conflict 跳过、成功 history 更新及 retained target/snapshot 隔离；`go test -race ./pkg/core/gossip ./pkg/core/zone`、全量测试、`make check`、chain relay/object pull/routing dry-run smoke 均通过。

    - [x] **7.11.6.2 删除 routing stale 字段级 merge**
      - 保留 `routingSnapshot()`：只深拷贝 routing-owned 的 `BirdInstances`、`RoutingReconcile`，`Network`、link/IPsec 和其他 committed 子结构继续只读共享。
      - `commitRoutingIfRevision` 正常成功时按现有方式替换 routing-owned 字段；全局 revision stale 时不再调用 `commitRoutingBirdInstancesByNetNS`，不比较 owner token，也不按 netns merge。直接保留最新 committed、设置 `routingDirty` 并等待下一次完整 reconcile。
      - auto-announce 在同一 reconcile 内主动更新 Network 后必须继续重新取得 routing snapshot/revision，并基于提交后的 Network 重建 authorized route set；不得因为 single-writer 假设删除这次 refresh。
      - 删除只服务于 stale merge 的 helper/测试，增加防护测试：reconcile 被测试桩阻塞时人工推进 revision，旧 routing 结果不得覆盖新 state，服务必须重新标 dirty。生产路径出现 stale 应记录足够诊断信息，因为它意味着 single-writer 假设被绕过。
      - 已完成：删除按 netns 重取 snapshot/比较 base/合并的 stale fallback；CAS stale 现在记录 source/current revision 与 changed netns，保留最新 committed 并发布 routing dirty。阻塞式 BIRD 测试覆盖 reconcile 中途推进全局 revision，确认旧 `BirdInstances`/`RoutingReconcile` 被整体丢弃且不会额外升 revision；auto-announce 后 refresh 保留。相关 app race、全量 `make check` 与 routing dry-run smoke 通过。

    - [x] **7.11.6.3 以完整手写 clone 替换 JSON round-trip**
      - `cloneStateFile` 保持现有输入输出、nil 处理、detached 语义和 validation 配置语义，但不再调用 `json.Marshal`/`json.Unmarshal`。不得在本步骤删除 `BeginUpdate` 或 commit 的任一次 clone。
      - clone 代码按类型所有权集中：`NetworkState`/`ZoneState`/authority/delegation/revocation/record/history 由 zone/core 层提供完整 clone；daemon-local state 为私钥 byte slice、SyncPeers、IPsec key/port、LinkInstances、IPsecReconcile slices、RoutingReconcile、FirewallReconcile、EndpointACL selectors、Bird overlays 和 Admission 分别提供显式 clone helper。
      - 明确保留 nil 与 empty map/slice 的区别；复制所有 `[]byte`、map、slice、pointer 和嵌套 pointer；函数 hook 不得通过 JSON 偶然丢失，app clone 完成后仍保证 `RecordVerifier`/`RecordHasher` 配置正确；不得复制 `stateFile.mu`。
      - 扩充 clone 完整性测试：修改 clone 的每个可变叶子均不得影响原值，反向修改原值也不得影响 clone；增加字段清单/schema guard，使 `stateFile` 或核心状态类型新增字段时测试强制提醒更新 clone。
      - 保留 record-heavy fixture benchmark，并增加包含 SyncPeers/IPsec/routing/firewall 的完整 `stateFile` benchmark；记录 JSON 基线与手写 clone 的 ns/op、B/op、allocs/op，随后重跑 2026-07-31 同负载 perf。
      - 已完成：`cloneStateFile` 和 core Network 已改为完整手写 clone，完整性、双向隔离、nil/empty、nil entry、validation hook 与 schema guard 测试通过。1000 records + 完整 peer/IPsec/routing/firewall fixture（最终 3 次）中，JSON 基线为 4.52-4.59 ms / 1.23-1.32 MB / 8,969-8,971 allocs，手写 clone 为 0.230-0.239 ms / 479 KB / 4,057 allocs，约快 19-20 倍。另以独立 data/control/UDP/observer 的 1000-record 常驻 daemon 执行并发 observer status 实测：`strace -f -c` 覆盖 630,976 个 HTTP 200 响应；无超时截断的 5 秒文件 trace 完成 216,853 个 HTTP 200（43,356 req/s，p50 0.154 ms、p99 0.908 ms），并确认状态 DB 仅在启动阶段打开，并发读取阶段没有状态文件 open/fsync/fdatasync。宿主机 `perf_event_paranoid=4` 且容器无 `CAP_PERFMON`，root `perf record` 亦被内核拒绝，已保留明确诊断而不修改宿主 sysctl。

    - [x] **7.11.6.4 用 detached 只读投影替换高频完整 Snapshot**
      - 盘点 `snapshotState()`/`Snapshot()` 调用，按调用频率和返回数据量排序；优先替换只需要 ManagedZone、zone digests、catalog page、peer endpoint、route/link summary 的路径。
      - projection 必须在锁内完成必要读取并返回独立标量、slice/map 或 DTO；不得让 `*stateFile`、`*NetworkState`、zone map、record pointer 从通用只读 API 逸出。`configureValidation` 只能作用于 detached Network root，不能在 read path 修改共享 committed。
      - persistence 单独提供受限的 committed immutable view/lease：取得某一 revision 的 root 后可在锁外编码，因为旧 root 永不修改；接口只供保存适配器使用，不升级为通用裸指针 API。保存完成时记录的文件 marker 必须对应实际编码的 revision。
      - 每替换一个 projection 都补充 detached/retain 测试，并确认调用方的日志、transport、磁盘和 hook 副作用发生在 store 锁外。
      - 已完成：删除生产通用 `ReadCommitted(func(*stateFile))` 与 `snapshotState()`，按 status/record/ACL/BIRD/routes/link/peer/health/revocation、sync timer/catalog/digest/fetch/object-pull/relay/discovery、GC/purge/auto-announce 等调用形状提供锁内构造的 detached DTO/scalar projection；传输、日志、BIRD 查询、observer 编码与磁盘保存均在解锁后执行。持久化仅保留私有 `committedStateLease{state, revision}`，直接编码不可变 committed root，并在成功关闭 DB 后记录与实际 root 对应的 revision marker；retain/嵌套可变叶子和 schema guard 回归通过。生产完整 Snapshot 仅保留 daemon 启动 transport 初始化、独立启动兼容读取和任意 `OnStateChanged` hook 的显式 detached clone。1000-record benchmark（最终 3 次）中完整 Snapshot 为 239-248 us / 473 KB / 4,026 allocs，status projection 为 29.1-29.4 ns / 0 B / 0 allocs，persistence lease 为 4.61-4.71 ns / 0 B / 0 allocs；app/gossip/zone race、全量 `make check`、chain relay、object pull 和 routing dry-run smoke 均通过。

    - [x] **7.11.6.5 收敛 typed COW mutation，仍使用全局 revision**
      - typed API 的目的只是表达字段所有权并减少复制，不提供并行 writer merge：Peer 路径复用现有 `UpdateSyncPeer`；Routing 只拥有 `BirdInstances`/`RoutingReconcile`；IPsec 只拥有 transport key/port、LinkInstances 和 IPsecReconcile；Firewall 只拥有 EndpointACLs/FirewallReconcile；Network mutation 使用独立入口。
      - 开始事务时只复制该事务会修改的字段；提交时在锁内确认全局 revision 未变化，从当前 committed root 显式构造新 root并替换 detached owned fields。stale 时丢弃结果、标记相应 dirty/重新排队，禁止字段级 merge。
      - mutation callback 必须无 transport、文件、网络、日志计数和其他外部副作用；需要执行的外部动作在 commit 成功后进行。routing/IPsec reconcile 中本来就先执行的幂等系统操作维持现有模型，但若最终 commit 意外 stale，必须 dirty 重跑，不能伪造已提交状态。
      - 为每类 typed mutation 增加 ownership 测试：未拥有的子结构应保持共享且不可修改，拥有的所有可变叶子必须 detached；保留 race、retained callback 和 stale 防护测试。
      - 已完成：Routing 延用 `routingSnapshot`/CAS；IPsec 新增完整 key/port/link/reconcile owned snapshot/commit；Firewall 新增 ACL/reconcile owned snapshot/commit；Network 新增独立 snapshot/commit 并迁移 daemon `record_put`。已删除 IPsec stale instance/owner-token merge、stale diagnostic 回写和 Firewall 在新 revision 上重提旧 summary；所有 stale 结果现在整体丢弃、记录 source/current revision 并 dirty 重跑。ownership、retained input、stale 与 race 测试、全量 `make check`、chain relay、routing/IPsec/firewall dry-run smoke 均通过；使用 Nix StrongSwan PATH 的完整 `make root-smoke` 也通过，覆盖 StrongSwan/XFRM lifecycle/IKE/takeover/rotate、BIRD/Babel exchange/filter/failover/adopt、nft firewall、health fault injection 和 revocation deny-first。

    - [x] **7.11.6.6 收敛 daemon authoritative mutation 与 fail-closed control 写入**
      - 事故背景：root 身份运行测试时，CLI 使用测试临时 DB 中的 synthetic root pool 完成 IPAM dry-run，却把 mutation 通过生产 `/run/photon/photon.sock` 作为通用 `record_put` 交给 daemon；daemon 未按自己的当前 Network 重新执行 pool ownership/assignment covering 校验，最终在生产 `catofes.` 写入测试 pool/assignments。测试/smoke 已先增加私有 `TMPDIR`、按 `data_dir` 派生 control socket、清空 `PHOTON_STATE` 覆盖和 root 回归测试作为止血，但这不能替代 authoritative mutation 修复。
      - 所有在线 mutation 必须只向 daemon 发送 typed intent；client 只负责 CLI 参数解析、类型编码和展示响应，不加载本地 StateStore、不执行任何依赖 Network/revision 的预校验，也不在 client/daemon 之间维护两套 semantic validation。daemon 在 single-writer 事件循环中基于当前 committed StateStore revision 完成输入规范化、权限、当前对象状态、跨 record 约束和撤销条件校验，再构造/签名 record、typed COW commit、持久化并触发对应 reconcile；预览如有需要也必须作为 daemon typed dry-run 请求执行。
      - 将每类操作收敛成接收 `(committed state, typed intent)`、返回 `(candidate/typed patch, effects, error)` 的纯领域 mutation，验证与构造不可拆开且成功前无外部副作用。在线 handler 在 daemon single-writer 内调用它；显式 `--direct` 的 recovery/offline 路径在取得独占状态后复用同一领域 mutation，再完成持久化，不能另留一套 client/direct 验证实现。
      - 新增 typed control methods 覆盖 `ipam_pool_create/revoke`、`ipam_assignment_create/revoke`、`route_announce/withdraw`、`service_publish/withdraw`；IPAM 必须在 daemon 当前 Network 上校验 `allocate-ip`、pool ownership/covering、overlap/shared/tag，route 必须校验 assignment 与当前 active record，service 必须校验 managed zone、endpoint schema 和当前 authorized assignment。
      - 通用 `record_put` 只保留非保留命名空间的普通应用/policy record；拒绝 `ipam/`、`routes/`、`services/`、`routing/`、`ipsec/`、endpoint/sync 等 daemon-owned key/type，防止调用者绕过 typed API 写入结构合法但语义无效、或覆盖 daemon 生命周期 record。保留命名空间和 key/type 配对必须集中定义并有表驱动测试。
      - mutation control socket 不可用时一律 fail closed；只有用户显式传入 `--direct` 的 recovery/offline 命令才可写本地 DB。逐项删除 record、IPAM、route、service、delegation issue/grant/revoke、join accept、recovery import/purge、state GC、IPsec cleanup 的隐式 direct fallback；只读 status/debug/list 仍可安全回退离线视图。Endpoint ACL 与 rotate-port 已有的 require-daemon 行为保持不变。
      - 审计现有 typed handlers：delegation、recovery、Endpoint ACL、GC、rotate/cleanup 继续由 daemon 当前状态重验；将 `join_accept` 从内部直接 `SaveState` 后 reload 收敛到 typed StateStore COW；Endpoint ACL 的 assignment 校验和 commit 应绑定同一 source revision，意外 stale 时丢弃并重试/报错，不跨 revision 接受旧判断。
      - 回归测试必须故意让 CLI 本地 DB 与 daemon committed state 不一致：本地有 pool/assignment 而 daemon 没有、本地旧 active record 而 daemon 已撤销/替换、本地 service endpoint 合法而 daemon assignment 已变化；在线 client 不应读取该本地 DB，daemon 应按自己的 revision 接受或拒绝，拒绝时 revision、record/history、磁盘和 reconcile 均不变。另覆盖 daemon typed dry-run 与真实 mutation 使用同一验证结果、online/direct 复用同一领域 mutation、raw `record_put` 保留命名空间拒绝、socket 缺失 mutation 不落盘、显式 `--direct` 才允许离线恢复，以及旧 client/new daemon 的 fail-closed 兼容行为。
      - 已完成：IPAM pool/assignment、route announce/withdraw 和 SOCKS5 service publish/withdraw 全部改为 typed intent；client 在线路径不再加载本地 StateStore，daemon 在 committed revision 的 detached Network workspace 上完成规范化、权限、pool/assignment/active-record/service endpoint 校验、签名和一次提交，direct 路径复用相同领域 mutation。通用 `record_put` 在 control 和 event 两层集中拒绝 IPAM/routes/services/routing/IPsec/sync endpoint 的保留 key/type；旧 client 的 raw 保留命名空间写会 fail closed。除 daemon 启动前的 `root init` bootstrap 外，所有管理 mutation 在 socket 缺失时返回错误，离线恢复/写入必须显式 `--direct`，Makefile smoke fixture 也已逐项显式声明；原 fallback smoke 改为验证先拒绝且不落盘、再显式 direct。daemon `runStateStoreWrite`、join accept、Endpoint ACL 和 IPsec cleanup 均改以 committed StateStore 为 authority，其中 join accept 不再内部 SaveState/reload，Endpoint ACL 校验与 firewall-owned CAS 绑定同一 revision。回归覆盖磁盘与 committed pool 状态双向不一致、拒绝不升 revision/不落盘、typed dry-run、direct/daemon 同源错误、typed control event、raw 保留命名空间拒绝和 socket 缺失不落盘；app/gossip race、全量 `make check`、admin daemon、phase3 fail-closed、chain relay、delegation revoke、routing/IPsec/firewall dry-run smoke 均通过。

    - [x] **7.11.6.7 实现 Network target-zone COW**
      - 在 7.11.6.1 的失败原子性稳定后，将 Network 写入从完整 Network clone 收敛为：浅复制 `NetworkState` root、复制 `Zones` map、完整复制目标 `ZoneState` 及实际会修改的 records/history/delegation/revocation；其他 zone 跨 revision 只读共享。
      - `ApplySnapshot`/Network mutation 应返回 detached 新 Network 或 typed patch，不直接修改传入 Network。validation 可在新 root 上读取共享祖先 zone，但只能修改 detached 目标 zone；成功后一次性挂到新 state root，失败直接丢弃 candidate。
      - 第一版不启用 `MerkleRoot`/digest cache；当前 root 缓存没有覆盖所有 mutation 的完整失效协议，不能与 target-zone COW 同时引入。
      - 测试覆盖：未修改 zone 确实共享、目标 zone 完全 detached、祖先 delegation/revocation 读取正确、目标 records/history 更新不泄漏、失败不变、连续更新同一 zone、不同 zone 顺序更新和 race。benchmark 分别使用单大 zone、多小 zone 和 history-heavy fixture。
      - 已完成：新增 `CloneNetworkStateForZone`，仅浅复制 Network root、复制 `Zones` map 并完整 detach 目标 `ZoneState`；`ApplySnapshot` 改为返回 detached candidate，不再修改输入，祖先 zone 保持只读共享。daemon 普通 record、IPAM、route、service typed mutation 也改用 target-zone workspace 和 ownership-transfer CAS commit，candidate validation 不再完整 clone Network；未引入 `MerkleRoot`/digest cache。回归覆盖结构共享、目标深层隔离、失败原子性、祖先 proof/revocation、同 zone 连续更新、不同 zone 正反顺序和 race；benchmark 覆盖单大 zone、多小 zone与 history-heavy fixture。

    - [x] **7.11.6.8 最后评估批量 `ApplySnapshot`**
      - 只有单 action 原子性、target-zone COW 和 typed Network commit 均验收后才开始；若新 perf 已不再显示 snapshot commit/persist 为热点，本项可以继续保留而不实现。
      - 必须保留当前“合法 action 成功、非法 action 被拒绝、后续 action 继续”的部分成功语义。每个 action 使用独立 savepoint：从批次工作 Network 创建 candidate，成功才推进批次工作副本，失败丢弃该 candidate 并记录 rejected digest。
      - 批次结束后最多一次 committed root 发布和一次持久化；日志、事件通知、transport send 等副作用只能基于成功提交的结果执行。虽然 single-writer 下正常不会 stale，意外 stale 时仍应丢弃整个批次结果并重新排队，不能直接重放带副作用的 callback。
      - 明确并测试可见性变化：读者从“可能看到逐 action 的中间 revision”变为“只看到最终批次 revision”。若该变化不可接受，则保持逐 action commit，只复用 target-zone COW，不实施批量发布。
      - 已完成：同一 sync event 的 snapshot actions 先收集为批次，每个 action 从当前批次工作 Network 创建独立 target-zone candidate；合法 action 推进 savepoint，非法 action 只记录 rejected digest，后续 action 继续。批次最终通过一次 CAS 发布一个 committed revision，成功后只持久化一次；stale 会丢弃并从新 committed root 重新计算整批，日志和 transport 等外部副作用均移到成功发布后。可见性明确为读者只观察到最终批次 revision；回归覆盖“成功—拒绝—后续成功”的部分成功、rejected digest、未修改 zone 共享、两个成功 target detach、单 revision 发布和持久化 reload。

    **阶段验收**
    - 必跑 `go test ./pkg/core/gossip ./pkg/core/zone ./app/photon`、相关 `-race` 测试、`make check` 以及 snapshot/routing/sync smoke；涉及真实 BIRD/IPsec 行为的步骤继续跑对应 root smoke。
    - 每一性能步骤使用相同 fixture 和相同实机负载记录 wall/CPU、clone 栈、alloc/GC、minor/major fault、bbolt 与 fork/exec；收益统计不得把 inclusive clone、GC 和缺页百分比直接相加。
    - 完成标志：snapshot apply 失败无任何 Network 变化；routing 不再进行 stale merge；JSON clone 不再出现在 daemon state clone 热路径；高频纯读不复制完整 Network；typed writer 只复制 owned fields；target-zone 写入成本随目标 zone 而非整个 Network 增长。

  - [ ] **7.11.7 `app/photon` 与 state ownership 后续模块化（性能收口后）**
    - `app/photon` 当前仍同时承载 daemon wiring、sync runtime、state adapter 和多个 reconcile 写侧，后续确有继续拆分价值；但本轮不机械搬迁整个 `stateFile`，也不在同一改动中同时重构 sync/IPsec/routing/firewall。
    - 先通过 7.11.0 验证一个完整的窄切口：独立数据所有者/store、app wiring、inspect view 合并、兼容测试。该边界稳定后，再按“权威 state / controller runtime state / observability”逐块迁移，而不是创建一批没有稳定 API 的空 package。
    - 后续候选包括：持久化 control-state store、peer sync controller state、reconcile observation store，以及 health/BIRD/actual source adapter。`Network`、密钥、owner token、rotate/adoption 等生命周期状态的归属必须由重启恢复语义决定，不能仅按文件大小或字段名字移动。
    - 每次只迁一个字段族并保持磁盘格式、wire 格式和 control/observer schema 的兼容；模块化不阻塞当前性能修复，是否继续拆由 7.11.0-7.11.5 完成后的新 perf 和调用关系决定。

  - [ ] **7.11.8 收敛稳态 bbolt 写放大（实机问题，2026-08-22）**

    **实现进度（2026-08-22）**
    - [x] P0-A 第一窄切口：`SaveStateAction` 已携带显式 persistence scope；pong、matching/empty catalog、timeout/backoff 等 peer-only 路径改为 metadata-only，同批 snapshot 实际改变 Network 时由执行器自动升级为完整保存。未声明 scope 的未来调用默认 fail-safe 为完整保存。
    - [x] P0-B：IPsec/Firewall 已增加 substantive equality；时间戳、IPsec SA age/traffic counter 与 SA 返回顺序等纯采样变化不推进 revision，link lifecycle/owner/backoff、稳定 SA 状态、desired/action/skip、Firewall policy/backend/generation/error 等变化仍提交。重复相同 IPsec error 已去重，首次/变化/恢复仍保存；两类 reconcile 的实质 metadata 变化均改为 metadata-only。
    - [x] P1 存储窄切口：完整 state 的 `_meta` 与 Network 已合并为单一 bbolt transaction；JSON value 先稳定序列化并与现值比较，相同值不 `Put`，整笔无变化时 rollback 为 no-op。新增/删除 zone、失败回滚和 metadata-only 兼容路径保留。
    - [x] P2 checkpoint 第一窄切口：只延迟 sync FSM 明确标记为 peer metadata-only 的 `SyncPeers` 更新；第一次 dirty 后在 `min(sync interval, 1m)` 到期，后续 peer completion 不滑动 deadline。正常 shutdown 强制 flush，失败保持 dirty 并按 1s 起步指数退避；任何成功且 revision 足够新的即时 full/meta 保存会原子吸收待写 checkpoint。Network/admin/security mutation 仍同步持久化。
    - [x] 延迟期间的外部 Network reload 已按字段所有权 rebase：磁盘侧 Network 保留，内存侧 pending `SyncPeers` 覆盖到新 committed state，再推进 checkpoint revision；不会用磁盘旧 metadata 覆盖本地 peer runtime，也不会用本地旧 Network 覆盖外部权威变更。`kill -9` 最坏只丢最后一个 sync interval 内的 peer runtime；其影响是重启后一次额外重试或 recent endpoint grace 缩短，不影响 zone、ACL、密钥或 link ownership。
    - [ ] 常驻 DB handle 与 typed changed-zone set 尚未实施。当前写量已收口，常驻 handle 仍涉及在线 CLI/file-lock/external reload 协调，不和本轮低风险 checkpoint 合并。
    - [x] 验证进度：新增 transaction ID、原子失败、reconcile equality/error 去重、checkpoint 合并/固定 deadline/失败重试/shutdown/reload rebase/即时保存吸收测试；`make check`、完整 `make smoke-all`、Nix StrongSwan PATH 下的 `make root-smoke` 以及 `go test -race ./app/photon ./pkg/core/gossip ./pkg/core/zone ./pkg/routing/bird` 均通过。`less` 新候选版无调试器 65 秒 `write_bytes=258,048` bytes、`syscw=282`、CPU 1.076 秒（约单核 1.66%）；相对原始 39,849,984 bytes 写入下降 99.35%，相对上一正式版 1,548,288 bytes 再下降 83.3%。该窗口无真实 `zone_applied`，代表稳态 checkpoint 收益。

    **现场基线与根因**
    - `less`（17 peers、约 23 条 XFRM link）运行 19 小时后，`photon` 主进程 `/proc/<pid>/io` 的 `write_bytes` 约 47.8 GB；BIRD 只写 4 KB，journal 总占用约 495 MB，写盘主体可确定为 Photon 自身。`systemctl status` 的约 88.1 GB 同时累计了 device-mapper `254:0` 和底层块设备 `8:0` 的同一批 I/O，不能当作真实物理写入量，但去重后的约 47.8 GB 仍异常。
    - 无 strace 的 65 秒稳态采样写入 39,849,984 bytes、发生 3,459 次 write syscall，按当前负载约为 53 GB/天；4 MB 的 `/etc/photon/photon.db` 没有持续同比增长，问题是反复覆盖 bbolt 页并同步落盘。
    - 75 秒 syscall 采样捕获 1,320 次 `pwrite64` 和 88 次 `fdatasync`。一轮 60 秒同步中，17 个 peer 的 `LAST_SYNC` 几乎集中在同一秒；`SyncSession` 在 pong/catalog 无差异时仍生成 `SaveStateAction`，每个 peer 随后分别调用完整 `saveCommittedState()`。
    - `saveStateAtWithFileInfo` 每次先用一个 bbolt transaction 写 `_meta`，再用第二个 transaction 调用 `SaveNetwork`；一次完整 save 至少包含两次 commit/fsync，而且崩溃可能停在“新 meta + 旧 Network”的中间状态。`SaveNetwork` 又会遍历所有 zone 并重新 Put authority/proof/delegation/revocation/records/history/root；bbolt 不会因为调用方 Put 的字节相同就自动替 Photon 省掉所有 dirty page 写入。
    - 每次保存还会重新 `bolt.Open -> mmap/freelist -> transaction -> Close/munmap`。这是额外 CPU/锁开销，但在当前架构中也让外部 CLI 有机会取得 bbolt 文件锁；它不是可以脱离多进程协调语义“顺手复用句柄”的独立低风险改动。
    - IPsec 成功 summary 每轮都会更新 `LastRunUnix`/`SourceRevision` 并完整保存；`recordIPsecReconcileError` 的持续同错误路径也会每轮完整保存。Firewall 每次实际 flush 都会更新 summary/每实例 `LastRunUnix`，没有 substantive equality 检查并直接完整保存。需要注意：当前 no-diff sync timer 不直接周期 flush Firewall，Firewall 主要由启动和真实 state-change 通知触发；但它一旦运行就必定 commit/save，仍是明确的次级写放大源。

    **优化顺序与兼容边界**

    **P0-A：先停止无差异同步重写 Network**
    - 引入明确的持久化意图/dirty family，至少区分 `Network` 权威数据和 daemon-local metadata。所有调用点必须显式声明写入范围；发生 zone/delegation/revocation/record/history 变化时仍同步执行完整持久化并在成功后才对管理请求确认，不能降低权威 mutation 的 durability。
    - 第一窄切口只把 pong/catalog 无差异完成、round timeout/backoff 等只修改 `SyncPeers` 的路径改为 `saveCommittedMeta()`；snapshot/object chunk/typed Network mutation 仍走完整保存。保持现有 `_meta` JSON 和 zone bucket 格式，不做数据库迁移，旧二进制与离线 debug/db 命令应继续可读。
    - 不把 `LastSyncUnix`、backoff、failure 或 discovered/observed endpoint 笼统归类为纯 observability：`LastSyncUnix` 参与 recent discovered address 的 grace 判断，backoff/failure 参与下一轮调度，observed/discovered 状态影响连通路径。第一步仍保持这些字段每次同步完成后立即 metadata-only 落盘，只消除 Network rewrite，以最小化语义变化。
    - `SaveStateAction` 应携带或由 action result 推导 `networkChanged/metaChanged`，不能只靠 reason 字符串判断。成功 snapshot 与 peer completion 同属一个 action batch 时只做一次完整保存；失败/rejected digest 若只改 peer metadata，则只做 metadata 保存。

    **P0-B：IPsec/Firewall substantive equality 与错误去重**
    - 仿照 `routingReconcileResultEqual` 为 IPsec 和 Firewall 定义字段所有权清晰的 substantive comparator。比较时忽略经审计确认纯运行观测的 `LastRunUnix`；IPsec 的 `SourceRevision`、`Committed`、`Stale` 是否影响 restart/debug 必须逐字段证明后才能排除，不能简单把整个 summary 清零比较。
    - IPsec 必须同时比较 transport key/port、LinkInstances、desired/actual SA、actions/skips、rotate/takeover/draining、owner token 和稳定错误状态；Firewall 必须比较 EndpointACL、backend、policy hash、generation、owned object 数与稳定错误状态。实质结果相同则不升 committed revision、不持久化、不触发下游通知。
    - 有实质变化但 Network 未变时统一走 `saveCommittedMeta()`。`recordIPsecReconcileError` 对连续相同错误做去重：首次出现、错误类别/内容变化和恢复清零需要提交；相同错误仅刷新纯 live observation，不得每分钟 full save。错误去重不能压掉 failure count、backoff、stale/dirty 或 owner lifecycle 的真实变化。
    - Firewall 的优化不能改变 deny-first 顺序。ACL、revocation、authorized route 或 backend-owned object 变化仍必须在 control 请求返回前 apply 并持久化；这里只跳过“输入、observed、plan、result 均等价”的重复 summary。

    **P1：存储层原子事务与相同值兜底**
    - 将完整 state save 的 `_meta` 与 Network 写入合并到同一个 bbolt `Update`，把一次完整保存从两个事务降为一个，并消除 crash 时 meta/network 跨事务不一致窗口。先把现有 store helper 重构为接收同一 `*bolt.Tx` 的内部函数；metadata-only 路径仍保持单独一个 transaction。
    - 为 JSON value 写入提供 `putJSONIfChanged`：先稳定序列化，再与当前 bucket value 做 `bytes.Equal`，相同则不调用 `Put`；追踪本事务是否发生 Put/Delete，没有任何逻辑变化时通过受控 no-op/rollback 路径退出并用 syscall 测试确认不产生 fsync。必须保持 nil/empty、bucket create/delete 和 stale zone 删除语义。
    - 不用当前 `ZoneState.MerkleRoot` 判断 zone 是否变化：现有 TODO 已记录其计算/失效维护不完整。若相同值 guard 后仍需 zone delta，优先从 typed Network mutation 显式传递 changed/deleted zone set，并在保存失败时把 dirty set 与后续 mutation 做并集；不能用可能过期的 root 跳过权威写入。
    - 第一阶段继续保持每次保存独立打开/关闭 bbolt。常驻 DB handle 只能在 daemon 成为唯一在线 writer、所有管理写走 control socket、direct 模式要求 daemon 停止，并明确外部变更/reload/file-lock 行为之后单独评估；写量收口后先复测 Open/Close 是否仍是可见热点。

    **P2：有界 metadata checkpoint（仅在 P0/P1 验收后）**
    - 先逐字段形成 restart 语义表：权威/安全字段必须同步落盘；backoff/failure 丢失会导致重启后额外重试；`LastSyncUnix` 丢失可能让 recent discovered endpoint 失效；纯展示时间/计数可以丢失。只有明确最坏影响和恢复路径后，才允许把相应字段从 per-peer fsync 改为 checkpoint。
    - 启用延迟 checkpoint 前必须修正 `handleSyncTimerEvent` 的无条件 `LoadState -> ReplaceCommitted`：当前立即保存语义下它不会覆盖未落盘内存 mutation，但延迟后会直接丢失 metadata dirty。sync timer 应只在文件 marker 证明存在真实外部修改时 reload；若本地仍 dirty，必须先按 typed ownership 定义 flush/rebase/conflict 顺序，不能把磁盘旧 metadata 或本地旧 Network 任一方盲目覆盖到另一方。
    - `daemon.go` 的 sync timer 只负责启动一批异步 session，不代表该轮 peer 已全部完成，不能在那里直接“每轮保存一次”。最终采用 metadata dirty revision + 固定最大 deadline：第一次 dirty 从当前时刻计算 `min(sync interval, 1m)`，后续交错完成不滑动 deadline；相比依赖“本轮全部 terminal”，它也覆盖跨轮 timeout/持续流量，且不会被活跃 peer 无限推迟。管理/权威 mutation 成功时按 revision 吸收，shutdown 强制 flush。
    - 初始最大丢失窗口不超过一个 sync interval；如需扩到 5–10 分钟，必须先证明 endpoint grace、peer lifecycle/cleanup、backoff storm 和 bootstrap-only 节点重启行为可接受。SIGTERM/正常 shutdown 必须有界 flush；save 失败保持 dirty、指数退避重试，后续成功保存覆盖失败期间全部 metadata 变化。`kill -9` 明确允许只丢失最后一次成功 checkpoint 之后的非权威 metadata。
    - Network/admin/security mutation 不进入延迟队列。执行同步权威保存时可以顺带吸收当前 metadata dirty，但只有该事务成功后才能清 dirty；失败不得因稍后的 metadata-only save 而把未持久化 Network revision 标记为已保存。

    **共同限制与观测**
    - 不以 bbolt `NoSync`/`NoFreelistSync`、tmpfs 或关闭持久化作为修复；这些措施会改变断电/崩溃恢复保证。单纯增大 daemon interval 只允许作为临时运维缓解，不能作为验收结果。
    - 增加低基数持久化观测：按 `network/meta` 与固定 reason family 统计 requested、executed、no-op、coalesced、failed、duration；不得使用 peer ID、zone 或原始错误作为 metrics label。测试可注入 saver，精确断言每个事件的完整保存/metadata 保存次数。

    **回归与验收**
    - 单测覆盖：无差异 pong、matching/empty catalog、round timeout/backoff、含 snapshot 的部分成功批次、object chunk、endpoint publish、IPsec rotate/takeover、重复/变化/恢复的 reconcile error、Firewall ACL、routing auto-announce，以及连续 save failure 后恢复。逐项断言内存 revision、磁盘 reload 结果、dirty/retry 和通知顺序不变。
    - 增加 bbolt transaction/bucket 级回归：完整 save 只 commit 一次且 meta/network 要么同时可见要么都不可见；metadata-only save 不改写任何 `zone:*` value；相同值 guard 不 Put；Network save 仍完整保存新增/删除 zone、record/history 和 revocation。保存失败不能更新 reload marker，也不能向调用方报告成功。
    - checkpoint 测试使用可控 clock/saver 覆盖 peer 合并、交错完成不滑动 deadline、保存期间 revision 覆盖、失败保持 dirty/退避、shutdown 强制 flush、即时 full save 吸收，以及外部 Network reload 与 pending `SyncPeers` rebase。后续若把窗口扩到 5–10 分钟，再补 active session、discovered grace、backoff storm、peer lifecycle 与 `kill -9` 恢复的长窗口测试。
    - 保留外部 state 写入检测、daemon 自写 marker、显式 direct 模式和多进程 bbolt file lock 的既有测试；任何常驻句柄实验必须额外证明在线 CLI 不死锁、不永久阻塞且外部写入不会被 reload marker 屏蔽。
    - 必跑 `go test -race ./app/photon ./pkg/core/gossip ./pkg/core/zone`、`make check`、chain relay、object pull、delegation revoke、IPsec/firewall/routing smoke。分阶段实机验收：P0-A 后无差异 sync 不再调用 `SaveNetwork`，物理写入至少下降 80%；P0-B/P2 后 75 秒稳态 `fdatasync` 从 88 降到个位数、65 秒 `write_bytes` 以约 1 MiB 为目标且不得超过 2 MiB。peer 状态、重启恢复和同步收敛时间不得退化。

  - [ ] **7.11.9 消除 IPsec/XFRM 稳态 reconcile 子进程风暴（实机问题，2026-08-22）**

    **实现进度（2026-08-22）**
    - [x] P0 命令后端第一窄切口：`SystemXFRMDriver` 新增按 netns 批量观测；同一 namespace 使用一次 `ip -j -d link show`、一次 `ip -j addr show` 和一次批量 forwarding sysctl 读取形成 immutable snapshot，pre-filter 与 maintenance 复用同一份结果。批量 JSON/字段读取失败会记录 fallback 并回到原逐接口 inspection，不把 unknown 当 healthy。
    - [x] P0 drift-only apply：批量 snapshot 同时覆盖 UP/MULTICAST、IPv6 addrgen、namespace/interface forwarding、主地址和 diagnostic `/128`；健康接口零 mutation，单项漂移只修对应 flag/sysctl/address。namespace forwarding 每 namespace 至多修一次，既有 create/move/action 顺序未改变。
    - [x] P0 PATH 探测：driver 构造时解析 `ip`/`sysctl`/`true` 绝对路径，并把绝对内层命令交给 `ip netns exec`，减少每轮 execvp PATH 失败探测；保留零值 driver 的旧命令名以兼容 fake runner。
    - [x] P1 第一窄切口：sync timer 只启动异步 session，不再无条件 dirty/立即 flush IPsec 与 Routing。真实 snapshot apply 仍由 `notifyStateChanged` deny-first 唤醒三层，VICI/control/health 等原事件路径不变，独立 IPsec/Routing periodic timer 继续兜底。
    - [x] P2 routing/veth 后续窄切口：真实 profile 确认健康 `EnsureVethPair` 每轮仍无条件执行 addrgen/link-up/四个 forwarding sysctl，并按地址族重复查询。现改为每端一次 `ip -j addr show` + 一次多 key `sysctl -n`，内存比较 UP/addrgen/IPv4+IPv6 forwarding/地址，只修单项 drift；接口缺失、JSON 或 sysctl 不兼容时完整回退旧创建/修复流程。
    - [x] P3 有界函数级诊断入口：`photon daemon` 新增显式 opt-in 的 `--cpu-profile <absolute-path>` 与 `--cpu-profile-duration <duration>`；默认关闭，最长 30 分钟，只允许新建本地绝对路径、文件权限 `0600`、拒绝覆盖既有文件，也不开放 HTTP/远程 profile 端口。profile 到期只停止采样、不停止 daemon；daemon 提前退出时同步封口。进程入口现用 `signal.NotifyContext` 接管 SIGINT/SIGTERM，使正常 systemd stop 能真正经过 daemon shutdown defer 并强制 flush 待写 metadata checkpoint。
    - [x] P3 profile 第一处热点：`less` 5 分钟函数级采样共 8.95 秒 Photon CPU（约单核 2.98%，窗口内 35+ 次真实 `zone_applied`）；`flushRevocationCleanup` 累计 3.37 秒，其中 `DaemonStateStore.Update -> cloneStateFile/CloneNetworkState` 占约 3.3 秒。根因是数据库中存在长期有效 revocation 时，每个 packet/sync event 都进入全量 COW，即使对应 peer cache 已在第一次清理后达到目标状态。现增加与 `CleanupRevokedPeerCache` 字段一一对应的显式 typed predicate；仍先执行 deny-first flush hook并清理独立 `PeerObservability`，但只有 committed peer 字段确有 drift 才创建/提交 workspace。健康 revocation 快路径 benchmark 约 0.55 微秒、376 B、7 alloc/op，不使用 reflection。
    - [x] P3 digest 收口：撤销空转修复后的 5 分钟 profile 仅采到 1.48 秒 Photon CPU（约单核 0.49%，窗口内 6 次真实 `zone_applied`），全量 clone 热点消失；剩余 `ZoneDigests/ZoneRoot/RecordHash` 累计约 0.38/0.30 秒。event loop 现由 sync action 的 typed `networkChanged` 返回值决定是否刷新 reload 基线，timer、普通 packet 和 metadata-only completion 不再反复遍历 Network；summary+digests 组合投影及无会话 ping 的 pong/shortcut 在同一调用链内只计算一次 digest。没有加入跨事件缓存，避免改变按 `RevokedAt` 生效的时间语义或引入失效协议。最终 3 分钟 profile 遇到 10 次真实 `zone_applied`，Photon 样本 0.96 秒（约单核 0.53%）；Photon+BIRD cgroup 含启动为 2.03 秒/197 秒（约 1.03%），随后无 `zone_applied` 的 35 秒稳态为 0.212 秒（约 0.61%）、Photon `write_bytes` 90,112 bytes。25 条 XFRM link、BIRD 与同步均正常。
    - [x] 验证进度：新增批量解析、健康零 mutation、单项漂移、同轮 snapshot 复用和批量失败回退测试；目标节点已确认 XFRM 与 veth 所需 JSON/多 key sysctl 格式兼容。`make check`、完整 `make smoke-all`、Nix StrongSwan PATH 下的 `make root-smoke` 和相关 race 均通过，覆盖 restart/adopt、IKE/takeover/rotate、BIRD/Babel/veth upstream、nft、health fault 和 revocation deny-first。`less` 40 秒时间戳 profile 捕获一轮 XFRM + 两轮 routing，共 21 个成功 `execve`：XFRM 健康轮 7 个批量 observe，每个 routing veth 健康轮由约 17 个命令降为 6 个 observe，另保留 1 个 upstream source `addr replace`。65 秒逐进程 CPU 为 Photon 0.95 秒、BIRD 0.09 秒、cgroup 1.053 秒（约单核 1.62%）；目标机无 perf/bpftrace，35 秒 syscall profile 已确认仅 7 次 exec，函数级 pprof 结果与后续收口见 P3。upstream replace 若改成独立 `ip show` 只会一换一、不减少 fork，暂不扩大 manager 接口；后续若继续优化应共享 veth observed snapshot。

    **现场基线与根因**
    - cgroup 生命周期 CPU 约为单核 6%；无调试器的 65 秒窗口消耗 3.00 秒 CPU（约单核 4.6%），主要呈每分钟 reconcile 突发，而不是 BIRD 常驻计算。
    - 20 秒 process trace 捕获 552 次 `execve` 尝试，其中 229 次执行 iproute2 `ip`；其余包含 `true`、`sysctl` 及 `execvp` 沿 PATH 的失败探测。典型序列为每条 link 重复执行 `ip netns exec photon ip link show`、IPv4/IPv6 addr show/replace、namespace `true` 和 forwarding sysctl。
    - daemon 每轮 sync 启动后都无条件把 IPsec/Routing 标记为 dirty 并立即 flush；同时 IPsec 默认 1 分钟、Routing 默认 30 秒仍有 periodic safety reconcile。即时 flush 会重置下一次 deadline，因此不是简单把两个计时器次数相加，但它把“本轮只是发送 ping、尚无新输入”也当成 reconcile 输入，造成不必要的突发。
    - `SystemXFRMDriver.EnsureInterface` 对已存在接口仍逐条确保 namespace、addrgen、multicast、link up 和 forwarding，`InspectLink` 也按 link 独立查询。接口数增长时 fork/exec、`ip netns exec` namespace 切换和文本解析成本近似按 link 数线性放大。

    **优化顺序与兼容边界**

    **P0：先把单轮 XFRM reconcile 变成 no-op cheap path**
    - 先给 command runner 增加仅测试/诊断使用的固定 operation family 计数，建立一轮 reconcile 的 observe/mutate 命令清单；不能为了降低计数而取消周期性 drift 检查。缓存只能作为加速提示，内核实际状态仍是 reconcile authority。
    - 将 reconcile 明确拆成 `Observe -> Plan -> Apply -> Re-observe/Commit`：先按 netns 批量取得 link/address/namespace/forwarding 状态，构造不可变 observed snapshot，再只对缺失或不一致项执行 add/move/addr replace/flag/sysctl。健康接口的第二轮 no-op reconcile 不得执行 mutation 命令。
    - 第一阶段可继续使用现有命令 backend，但每个 netns 的 namespace existence 与 forwarding 只检查/设置一次，link/address 尽量用 `ip -j` 批量读取；解析失败或字段未知时 fail closed 到现有逐项检查，不得把 unknown 当作 already-correct。
    - 消除嵌套命令的 PATH 扫描：启动时解析受支持的 `ip`/`sysctl` 绝对路径并传给 netns wrapper，同时保留 NixOS 与普通发行版 PATH/安装探测测试。该项只减少 exec 探测，不能替代 observe/plan 去重。
    - 命令版 no-op 路径稳定后，再评估 rtnetlink + 每 netns 常驻 `setns` worker。若采用，worker 必须 `runtime.LockOSThread`、进入和恢复 namespace、支持 namespace 删除/重建、context cancel 与有界退出；不得让 Go runtime 的其他 goroutine 意外留在目标 netns。
    - 不在本阶段并行执行同一 netns 的 mutation，也不打乱 create/move/configure/up/route/BIRD 的既有顺序。StrongSwan SA、XFRM if_id、owner token、staged/draining/takeover、地址替换、IPv6 link-local 和 BIRD interface 可见性的现有语义必须保持。
    - 不以单纯增大 reconcile interval 作为修复；那会线性增加接口/namespace 漂移后的修复延迟。只有在 no-op 成本收口后，才根据明确的恢复 SLO 调整 periodic safety interval。

    **P1：按真实输入标 dirty，消除 sync timer 假唤醒**
    - 删除 `daemon.go` 中 sync timer 后的无条件 `ipsecDirty/routingDirty` 之前，先定义 typed dirty reasons/input generations，不能只比较 zone digest。Routing 的输入至少包括授权 route/announcement、link output、配置、BIRD lifecycle/force reload；IPsec 的输入还包括 transport contact-point quality、DNS/port generation、VICI lifecycle、rotate/takeover/draining/backoff deadline 和配置。
    - sync timer 仅启动 session，不应立刻触发 reconcile。成功 snapshot/record mutation、peer endpoint/path quality 的实质变化、link lifecycle event、配置 reload 或时间 deadline 到达时，分别标记对应 layer dirty；同一 event drain 内多个原因合并为一次 reconcile。纯 `LastAttemptUnix`/相同 catalog completion 不应唤醒数据面。
    - 保留现有 periodic safety reconcile，用于修复进程外 drift、namespace/interface 被管理员删除、BIRD/StrongSwan 状态变化但事件丢失等情况。event-driven dirty 负责低延迟，periodic timer 负责最终自愈；两者命中同一时刻必须合并，不能连续跑两遍。
    - deny-first/security 事件不得等待普通 debounce：revocation、ACL 收紧和授权 route 撤销仍按 Firewall -> Routing -> IPsec 的现有顺序立即 flush。新增/放宽策略可以合并，但必须保持 control 请求目前要求的同步 apply/错误返回语义。
    - 为每类 dirty reason 增加表驱动测试，证明“输入变化一定唤醒、纯观测变化不唤醒、丢失事件仍由 periodic 修复”。不得用 committed 全局 revision 是否变化作为唯一条件，因为 peer metadata revision 可能变化而数据面输入不变，transport runtime 也可能变化而 Network digest 不变。

    **回归与验收**
    - fake runner 测试精确覆盖首次创建、第二轮完全 no-op、单接口 down、multicast/addrgen 漂移、IPv4/IPv6 地址缺失或多余、forwarding 被关闭、接口被移回 host、namespace 删除重建，以及 observe/parse/apply 中途失败。no-op 必须零 mutation，任一漂移必须在下一轮修复。
    - root smoke 覆盖 daemon restart/adopt、23-link 规模、StrongSwan SA 与 XFRM link 映射、rotate/takeover/draining、BIRD 邻居/路由不中断、namespace 删除重建及 revocation deny-first；优化前后比较最终 `ip -j link/addr`、sysctl、SAs、routes 和 persisted owner state，而不只比较命令数。
    - 保留每个外部命令的 context timeout、错误输出截断、partial apply 后 dirty 重跑和 shutdown cancel 行为。批量 observe 失败时不得提交虚假的 healthy 状态，也不得清除原有可恢复的 LinkInstances。
    - 调度测试额外覆盖：no-diff sync 不触发数据面、snapshot/endpoint/quality/VICI/config/deadline 分别触发正确 layer、同 tick timer+event 只 reconcile 一次、事件漏失后 periodic 自愈，以及 revocation/ACL deny-first 不被 debounce。
    - 必跑 IPsec/XFRM 单测与 race、完整 `make root-smoke`、BIRD/Babel、health fault、firewall 和 revocation smoke。真实节点以相同 20/65 秒窗口复测；目标是健康稳态每轮外部命令数量从 O(links) mutation 降为 O(netns) observe、20 秒 `execve` 从 552 降到 50 以下（成功执行数量至少下降 90%），cgroup 单核占用从约 5–6% 降到 1% 左右且至少下降 60%，同时漂移修复时间和数据面连通性不退化。

- [ ] **7.9 可选 Admission 管理面**
  - 在 auto-join 主链路和本地控制接口稳定后，再考虑父 Zone 管理节点的 join request inbox、审核队列、批量 approve/reject 和受限网络化提交。
  - 第一版 admission 仍不引入新的公网 request 协议，也不让 leaf 自动把 join request 写入 gossip active state。
  - 候选命令：`photon join pending`、`photon join approve <request-id>`、`photon join reject <request-id>`。
  - admission policy 仅覆盖父 Zone 有权签发/写入的对象，不配置本机 MeshPolicy / link group / connect-deny override。

- [ ] **7.4 WireGuard 传输底座与上层 per-peer 接口（可选实验）**
  - 通过 `wgctrl-go` 操作内核 WG 接口，复用 Zone K-V 中的 `wireguard/*` record。
  - WG 与 IPsec/XFRM 可以作为同一 peer 的并行 active TransportLink；是否表现为等价路径、较高 cost 的 fallback 或按目的前缀分流，由本地 policy/Babel 决定，不固化在 provider 类型中。
  - 不把共享裸 WG mesh interface 直接交给 Babel：WG 需要依靠 AllowedIPs 选择加密 peer，若把业务前缀写入 AllowedIPs，会与 Babel 的动态多跳下一跳选择重复并冲突。
  - WG AllowedIPs 只放每个直连 peer 的 transit `/32` 或 `/128`；业务前缀仍交给 Babel/route authorization。WG 上层通过 GRE 或其他封装提供独立 per-peer 接口，使 Babel 选择接口/下一跳后，WG 只负责把外层包投递给对应 peer。
  - WG、上层封装与 Babel 接口原则上归属同一个目标 netns；若 WG 留在 host netns，必须显式设计跨 netns underlay、路由、转发、防火墙和 teardown，不作为默认拓扑。
  - 若进入正式实现，先一次性落地 provider-aware Link ID helper，并覆盖 StrongSwan legacy ID adopt/restart 迁移；随后实现 WG records/overlay intent、本地 policy、shared device/peer desired state、独立持久化 state、owner/live marker、inspect/reconcile/apply/teardown、private key 持久化、staged device rotate、listener/firewall grace 与零引用 cleanup。不得迁移或包装 StrongSwan 内部 lifecycle。

- [ ] **7.5 GRE / VXLAN 上层封装选择（远期可选）**
  - 先用真实 netns + WG + BIRD smoke 比较 GRE 与 VXLAN；仅需 point-to-point 三层 Babel 接口时优先评估 GRE，明确需要二层承载时再选 GRETAP/VXLAN。
  - VXLAN 方案必须明确 VNI、VTEP、静态/动态 FDB、广播/多播复制和额外 MTU 开销；共享 VNI 不能假设 WG 自动向所有 peer 复制广播/多播。
  - GRE/VXLAN endpoint 使用 WG transit address，业务前缀不进入 WG AllowedIPs；封装设备在目标 netns 内创建并通过 WG underlay 可达。
  - 选定上层封装后再实现 per-peer interface lifecycle 与 `LinkOutput` 投影，并收口 BIRD per-interface policy、LinkGroup base cost、按 peer/group/provider 展示、双 provider dry-run，以及 IPsec/XFRM + WG + GRE/VXLAN 联合 root/container smoke。

- [ ] **7.6 SRv6 支持（实验性）**
  - 通过 netlink 配置 SRv6 SID、End.DT4/End.DX6 行为。
  - 与 BIRD/FRR 的 SRv6 扩展联动，如后续引入 BGP。

- [ ] **7.12 可选策略路由与系统路由审计（远期）**
  - 当前主线保持一个 netns 一个 BIRD 实例，BIRD 直接写该 netns 的 main table；默认不启用额外 `ip rule` / per-overlay table 隔离。
  - 如后续需要 external BIRD、管理员自定义策略路由、或非默认共享 netns 拓扑，再补 `ip rule` / fwmark / iif-oif 策略路由和 `/run/photon/rt_tables.d` 诊断输出。
  - route-table auditor 仅作为可选兜底，用于交叉检查 Photon authorized route set、BIRD learned/installed routes 与内核 route table 是否一致。

## Phase 7 之后的远期后续

- [ ] 跨数据面 rotate smoke：结合端口/IPsec rotate 与真实 BIRD route/metric 观测验证数据面切换窗口；不阻塞 Phase 5/6 收尾。
- [ ] state 文件外部协调补强：在现有 bbolt 文件锁基础上增加显式 `flock` / fsnotify watcher，避免多进程或外部修改时状态漂移。
- [ ] Observer 增强：拓扑图、zone tree、VictoriaMetrics/Prometheus-compatible datasource/push 集成、BIRD protocols/routes/neighbors 深度解析。

## Phase 8: 应用层服务与代理（已验收）

**目标：** 在 Photon L3 mesh 上提供可发现、可授权的内网 SOCKS5 服务，同时支持本地唯一 endpoint 和 shared Anycast endpoint；应用层源路由 relay 保持独立演进。

**设计边界：**
- Photon 只负责服务地址归属、签名 record 发布/撤销和动态防火墙授权；独立 `photon-services` 读取 `/etc/photon/service.yaml` 并生成 Docker Compose/代理配置。两者都不通过 Docker API 管理容器生命周期，Compose 由管理员检查后手工启停。
- 本地网络通过 `auto` 选择当前节点唯一的非 shared assignment；Anycast 网络通过 shared assignment 的稳定 tag（如 `socks5.cn`）选择，`region` 仍只是公开 endpoint 的服务选择属性。
- Docker bridge 位于 host netns，容器地址属于 Photon 管理的服务前缀；host 侧通过指向 Photon netns 的聚合路由和 Docker connected route 最长前缀匹配，overlay 侧复用显式 `routing.instances[].upstream` 返回 host。
- SOCKS5 第一版可使用 `NO AUTH`，由 Photon overlay 身份/前缀和本机 firewall 提供 zone/node 级授权；这不承诺同一节点内的用户级身份区分。

- [x] **8.4 本地与 Anycast 数据面验证**
  - 已实现 `services-smoke`：真实 Docker bridge 上运行 SOCKS5 和目标 TCP 容器；client netns 经 BIRD/Babel、host route 和 static upstream 回程完成代理请求。
  - root smoke 断言 Docker connected route 优先于更宽的 host -> overlay 聚合路由；另一 Photon 前缀仍命中该聚合路由。
  - non-owner service publish、shared tag 冲突、空 ACL selector fail-closed、未监听 endpoint 不发布分别由 `pkg/service`、routing、firewall 与 `photon-services` 单元测试覆盖；shared prefix 成员故障收敛复用 BIRD Anycast root smoke。
  - 已于 2026-07-21 在允许 netns、具备目标 host firewall 配置的 root 环境执行 `sudo make services-smoke` 并通过。

- **8.5 不纳入 Phase 8**：客户端 service selection/health policy 不是 SOCKS5 发布数据面；Anycast 的 L3 选路和故障收敛交给 BIRD/Babel。出现明确客户端需求后再独立设计。

- **8.7 不纳入 Phase 8**：应用层源路由 relay 是独立协议/项目，不与 SOCKS5 发布、IPAM 或 BIRD 数据面耦合。

## 下一步

1. 先完成 7.11.8：将无差异 peer/control-state 写入从完整 Network save 分离，并以 `less` 相同负载复测 bbolt 页写与 fsync；不得降低权威 mutation 的同步持久化保证。
2. 再完成 7.11.9：把 XFRM reconcile 收敛为批量 observe、按 drift apply，并用完整 root smoke 验证 restart/rotate/takeover/BIRD/撤销行为。
3. 7.11.6 StateStore 正确性、手写 clone、分层/target-zone COW 与批量 snapshot apply 已完成；继续保持现有全局 revision 和不可变 committed root，不引入 `MerkleRoot`/digest cache，除非新 profile 再次证明 digest 计算为热点。
4. 上述稳态问题收口后，再按需求选择 7.7/7.8 discovery/relay 或 7.11 metrics/readmodel；WG 与 GRE/VXLAN 继续作为可选 7.4/7.5。
5. 后续模块化不再单独扩大范围；新增 debug/observer/control 输出默认走 `internal/inspect` view + `inspect/text` 或 `inspect/http` presenter，写侧/daemon adapter 继续留在 app 层直到接口稳定；公共 control DTO/typed client 等出现实际复用需求再迁移。
6. Phase 8、Phase 9 已完成验收；客户端服务选择和应用层 relay 按需作为独立项目评估。
