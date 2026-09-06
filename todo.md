# Photon Todo

本文件只保留当前可执行任务和仍未完成的产品计划。已完成阶段与历史实施细节见：

- [docs/roadmap-archive.md](docs/roadmap-archive.md)：Phase 0-9 与近期重构归档；
- [docs/app-photon-runtime-migration-report.md](docs/app-photon-runtime-migration-report.md)：`app/photon` 逐文件迁移状态；
- [docs/runtime-state-ownership.md](docs/runtime-state-ownership.md)：Runtime、Driver、State、Observation 和 BoltStore 的冻结边界；
- [docs/photon-windows/design.md](docs/photon-windows/design.md)：Photon Windows 产品和安全设计。

精确的已完成步骤由 Git 历史保存，不再把逐提交日志复制进 TODO。

## 当前架构边界

目标结构：

```text
Daemon
├── event loop / daemon scheduler
├── GossipDriver
├── StateStore               current: pkg/core/state.Store
│   ├── VerifiedState
│   └── GossipCheckpoint
├── LinuxDriver/WindowsDriver
├── LinuxState/WindowsState
├── LinuxObservation/WindowsObservation
└── BoltStore                one process, one bbolt handle
```

固定约束：

- `Daemon` 是唯一产品生命周期和平台 mutation 编排者；Linux 当前由 `Daemon.Run` 承担。
- 以前的 `CommonRuntime` 就是当前 GossipDriver 的概念名，不是额外层；后续统一称 `GossipDriver`。
- `StateStore` 不是 GossipStore：VerifiedState 是公共权威事实，GossipCheckpoint 才是 gossip 可丢失恢复提示。
- LinuxDriver/WindowsDriver 是具体平台实现，不预建统一 `PlatformDriver`、`PlatformCapabilities` 或成套 controller interface。
- LinuxState/WindowsState 只保存无法重建的本地 intent/secret 和非幂等操作最小 journal；当前实际系统状态进入纯内存 Observation。
- composition root 创建唯一 BoltStore；Store、Driver 和平台 codec 不自行按路径打开数据库。
- 不新增 `ClientRuntime`、Repository、aggregate snapshot 或只为迁移存在的转发 wrapper。

## A. 当前主线：收口 Linux Daemon/State 边界

### A1. 纠正 Runtime 命名和职责

- [x] 将目标所有权、`CommonRuntime` 历史含义、State/Observation 持久化规则写入设计文档。
- [x] 将 `DaemonService` 直接改名并收敛为唯一顶层 `Daemon`，没有在外面增加 supervisor 或兼容 alias。
- [x] 删除 `SyncRuntime`：Daemon 直接持有 AppContext，clock/logger 使用真实 owner；gossip transport/config 随后继续归回 GossipDriver。
- [x] 将 `app/photon.Runtime` 改名为 `AppContext`，明确它只承载 CLI/config/state-path/clock，不再冒充产品 Runtime。
- [x] 将 `pkg/core/host.Runtime` 直接改名为 `GossipDriver`，同步构造器、配置、错误、调用方和文档术语，不保留兼容 alias。
- [x] 将 `internal/photonlinux.Runtime` 直接改名为 `LinuxDriver`，同步构造器、options、Daemon owner 和测试，不增加跨平台公共接口或兼容 alias。

### A2. 收紧 GossipDriver

- [ ] GossipDriver 只拥有 gossip Engine、UDP/TCP transport、object-pull、session/chunk/address book、协议 timer 和 gossip observability。
- [x] 删除 Daemon 保存的第二份 gossip transport 和测试专用 transport deps；transport/address book 只由当前 GossipDriver 持有。
- [x] 删除 `Daemon.GossipConfig`；协议 limits/discovery/peer identity 由 GossipDriver 持有可替换的 detached config，app 侧 endpoint/log/展示配置从 AppContext 按需派生，不增加 app 级 wrapper。
- [x] `syncConfigFile` 已缩减并改名为 `gossipStartupConfig`，只作为 composition root 创建 GossipDriver/transport 的短生命周期输入；日志和本机 endpoint 发布策略直接读取 AppConfig。
- [x] IPsec/routing/firewall/health timer 已迁入 Daemon 自己的 scheduler/queue；健康完成直接由 Daemon event loop 消费，不再包装成 GossipDriver completion。
- [ ] 审计剩余平台异步 completion；全部迁回 Daemon，安全 deny-first 仍立即处理。
- [ ] 保持一个 gossip ingress/event queue 和一个 Engine action ordering 实现；Linux/Windows 不复制协议 executor。
- [ ] 明确 shutdown/backpressure：GossipDriver 停止后不再投递，Daemon drain 已完成的平台 completion 后再关闭 BoltStore。

### A3. 将 RuntimeState 拆成 State 与 Observation

- [ ] 把 `internal/photonlinux.RuntimeState` 改名/收缩为 `LinuxState`，逐字段给出“保留、推导、迁移、删除”的测试证据。
- [ ] `IdentityKeyPath` 回到配置/应用上下文；`Admission` 迁到跨平台 bootstrap/join owner。
- [ ] 审计 `IPsecTransportKey`、`IPsecPortRecord` 和 Endpoint ACL：只保留没有其他真相源且跨重启必须保留的数据。
- [ ] 拆分 `LinkInstances`：rotation/takeover/ownership 的最小恢复 journal 可持久化；ActualState、计数、LastError 和实时 SA 信息进入 Observation。
- [ ] 删除 `IPsecReconcile` 中持久化的 ActualSAs、actions、LastRun/LastError 和可重新推导的 desired snapshot。
- [ ] 将 `RoutingReconcile`、`FirewallReconcile`、BIRD status/PID/socket 可用性改为启动后重新 Observe；确定性路径、resource ID 和 policy hash 不重复落盘。
- [ ] 审计 `PeerCleanups`：只保留真正影响安全 grace/cleanup 恢复的字段，其余由 VerifiedState/GossipCheckpoint 推导。
- [ ] 新增或收敛无独立线程/DB 的 `LinuxObservation` read model；Daemon 在线时更新，重启时清空并重建。
- [ ] platform inspect/control/HTTP 只读在线 Observation；Daemon 离线时返回 unavailable，不用 bbolt 上次 reconcile snapshot 冒充 live。
- [ ] 内存错误使用 `error`/typed failure，展示时映射稳定 code/message；没有证明价值时不持久化 LastError。

### A4. 删除 DaemonStateStore

- [x] common Store 已由 GossipDriver 直接使用；生产 aggregate Snapshot、重复 revision metadata 和单调用方 Bird GC/purge/peer-cleanup commit wrapper 已删除。
- [ ] Daemon 直接持有 StateStore、LinuxState、LinuxObservation、LinuxDriver 和 BoltStore 的引用/生命周期。
- [ ] 把剩余 routing/IPsec/firewall typed candidate commit 移到 Daemon 的平台 state mutation 边界；保留真正的多字段原子替换，不保留 forwarding Store。
- [ ] 将 common mutation、platform completion 和 security barrier 都串回 Daemon owner，删除 `DaemonStateStore.writeMu`、coherent aggregate read 和 commit callback 包装。
- [ ] 删除 `daemon_state_store.go`、app 内 Linux state alias，以及仅测试迁移 coordinator 的 fixture。
- [ ] 旧 `stateFile/stateMeta` 只留启动单向 migration decoder 和 legacy DB dump；停止支持该 schema 时整组删除，不形成在线兼容层。

### A5. app/photon 与查询边界继续清理

- [ ] 按迁移报告继续下沉 firewall/routing/IPsec policy 与 Linux 实现；app 只保留 composition、Unix control、CLI 注册和完整 Daemon 顺序。
- [ ] 继续删除只有一个调用方的 wrapper、重复 clone/DTO builder 和 legacy 测试准备；测试跟随实际 owner 迁移。
- [ ] CLI/control/HTTP 共用 canonical inspect DTO；CLI 不再从 HTTP DTO 反向转换，也不直接调用平台 Driver。
- [ ] verified/common 允许离线读；GossipCheckpoint 离线必须标记 `last-known`；platform Observation 只允许在线读。
- [ ] CLI 壳稳定后再迁入 `internal/photoncli`，不为了减少 `app/photon` 文件数先搬目录。
- [ ] 每一批迁移更新 runtime migration report，并执行相关单测、race（适用时）、Windows cross build、`make check` 和 `git diff --check`。

### A6. 显式配置重载

- [ ] 不监听或轮询 `config.yaml`；实现 `photon daemon reload`，经 control API 串行 parse/validate/replace。
- [ ] Linux systemd 可选提供 `ExecReload`；Windows 使用 named-pipe control，不依赖 Unix signal。
- [ ] reload 失败保持旧 config/Driver/State；成功时按依赖顺序替换资源并关闭旧 Driver。

## B. Photon Windows 当前主线

已完成的 F0a-F0e 公共状态/gossip 前置重构、Windows 配置 schema、交叉编译和 memory convergence 已归档。Windows 不复制 Linux `DaemonStateStore`、gossip executor 或平台 controller。

### B1. 冻结 v1 契约

- [ ] 支持矩阵先固定 Windows 11 amd64；Windows 10、arm64 在首个 vertical slice 后按真实 CI/设备验证扩展。
- [ ] 固定首版算法集与 StrongSwan profile：Ed25519 raw public-key auth、X25519、AES-GCM-16，明确禁止项和协商失败行为。
- [ ] v1 保持 outbound-only leaf、一个 active gateway、split tunnel；不做 transit、IKE responder、full tunnel、DNS/NRPT、GUI 或自动更新。
- [ ] 冻结 route-origin 验证：Babel route 安装前必须匹配 Photon verified authorization，撤销/授权收紧 fail closed。
- [ ] 定义 revocation、network change、service stop 和 crash recovery SLO。

### B2. Windows composition 与公共 gossip

- [ ] Windows service composition 创建一个 Daemon、一个 GossipDriver、一个 StateStore、一个 WindowsDriver、一个 WindowsState 和一个 BoltStore。
- [ ] 接入真实 Windows UDP adapter：bind/read/write/rebind/close 有界且可取消；GossipDriver 继续唯一拥有 receive/object-pull/protocol event ordering。
- [ ] 从 verified records 生成 gateway candidates，校验 identity/key、address/port、overlay、route authorization 和撤销状态。
- [ ] 私钥沿用管理员负责的本地安全模型，可直接存同一 bbolt；不增加本地加密/解密层。
- [ ] WindowsState 只按真实需求保存不可重建 secret/intent/journal；不为与 Linux 字段对称提前建 schema。
- [ ] 完成真实 UDP 双节点 gossip、关闭重开和 state recovery 验收后，才进入用户态 packet pipeline。

### B3. IKEv2 与 ESP

- [ ] 先完成 `ranet-lite` port map、license/provenance 和采用/重写决策；任何实质派生保留 MIT notice。
- [ ] 分离 IKE codec/parser 与 initiator session state machine，实现 `IKE_SA_INIT -> IKE_AUTH -> CHILD_SA`。
- [ ] 与 Photon StrongSwan 验证 ID encoding、raw Ed25519、NAT-T、proposal、retransmit、fragmentation 和错误通知。
- [ ] 实现 CHILD/IKE rekey、overlap、simultaneous rekey、DPD/liveness 与网络变化重连。
- [ ] 实现 tunnel-mode IPv4/IPv6 ESP、SPI demux、sequence、anti-replay、AEAD/padding/length 验证和 bounded crypto workers。
- [ ] 一个共享 UDP socket 承载 IKE/ESP/gossip 所需流量；明确分流、队列、MTU 和 Windows batch-send 退化路径。

### B4. Babel/SADR 与 Wintun

- [ ] 实现 leaf-only Babel codec/neighbor/route selection；不转发 learned route，只 originate 本节点获授权 prefix。
- [ ] Router ID 从稳定身份材料推导；若完全可推导则不持久化。
- [ ] 实现 SADR lookup、ECMP/metric 切换和 route authorization gate，撤销后立即停止安装/使用非法 route。
- [ ] Wintun 使用固定官方 API/binding，明确 DLL 来源、ring ownership、packet buffer 归还、取消与 shutdown。
- [ ] WindowsDriver 通过 IP Helper 管理 address/route/interface metric，使用 `Observe -> Plan -> Apply -> Re-observe`，不 shell out。
- [ ] 完成 `Wintun -> SADR -> ESP -> shared UDP` 及反向 pipeline 的 memory 与真实 interop 测试。

### B5. Windows service、IPC 与 observation

- [ ] 使用 `x/sys/windows/svc` 接入 SCM，并提供复用同一 composition 的 `run --console`。
- [ ] 网络变化通过 Windows notification 进入 Daemon；重建 UDP/IKE/route 时保持 owner/cleanup 顺序。
- [ ] 使用 versioned named-pipe IPC，ACL 默认管理员；首版支持 status、peers、routes、diagnostics、reload、stop。
- [ ] WindowsObservation 展示 Wintun、UDP、IKE/CHILD_SA、Babel 和 route 的实时状态；离线只读 verified/config，不冒充 runtime。
- [ ] Event Log/文件日志使用稳定 event id、severity 和敏感字段脱敏；metrics 保持有界低基数。

### B6. 验收、安全与发布门槛

- [ ] 建立 Windows VM + Linux Photon gateway 的可重复 test rig。
- [ ] 里程碑 1：service、Wintun、split route、真实 gossip 与关闭重开。
- [ ] 里程碑 2：StrongSwan IKE_AUTH/CHILD_SA 与双向 ESP IPv4/IPv6。
- [ ] 里程碑 3：Babel 邻居、授权 route、SADR 与 gateway 切换。
- [ ] 里程碑 4：rekey、loss/dup/reorder、sleep/resume、network change、revocation 与 crash recovery。
- [ ] teardown 必须只删除本产品 owned resource；覆盖 normal stop、partial startup、crash restart、uninstall 和 stale resource adopt。
- [ ] codec/parser/state machine 持续 fuzz；portable 测试覆盖 Linux/Windows，管理员/driver 集成测试明确分层。
- [ ] 发布前完成吞吐/CPU/内存基线、72h soak、Authenticode、checksum、SBOM 和安装/升级/卸载测试。

## C. 非当前主线

这些任务不阻塞 Runtime/State 收口和 Photon Windows vertical slice：

- [ ] Photon Android：Windows 核心稳定后另建项目，由 Kotlin `VpnService` 管理 TUN/protected socket/生命周期；不提前创建工程或公共抽象。
- [ ] 可选 Global Discovery Server 与 Relay Bootstrap Server；需先冻结 abuse/auth/rate-limit 模型。
- [ ] 可选 Admission 管理面：父 Zone inbox、approve/reject 和审计；不引入公网自动提交旁路。
- [ ] WireGuard + GRE/VXLAN 并行 TransportLink 实验；先做真实 netns/BIRD smoke，再决定封装和 provider-aware ownership。
- [ ] SRv6 与额外 policy-routing/system-route audit，按真实部署需求启动。
- [ ] 跨数据面 rotate smoke、Observer 拓扑/zone tree/metrics datasource 增强。
- [ ] 多进程/外部数据库修改协调：先证明 bbolt 文件锁之外确有需求，再评估显式 flock/fsnotify；不得引入第二 writer。

## 下一步执行顺序

1. 完成 A1-A3：统一命名，移出非 gossip 调度，给当前 RuntimeState 每个字段分类。
2. 完成 A4：Daemon 直接持有两个 state owner 和唯一 BoltStore，删除 DaemonStateStore。
3. 完成 A5-A6：继续清理 app/test/CLI，并补显式 reload。
4. 实现 B2 的 Windows composition 与真实 UDP gossip vertical slice。
5. 依次推进 IKE/ESP、Babel/SADR、Wintun、SCM/named-pipe 和完整验收。
