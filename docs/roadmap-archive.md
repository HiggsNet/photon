# Photon Roadmap Archive

本文件从 `todo.md` 拆出，用来保存阶段历史清单、已完成细节和旧阶段遗留的后续设计决策。主 `todo.md` 只保留当前可执行任务、未来计划和指向本归档的摘要链接。

## 2026-09 Runtime/State 重构阶段归档

- Observer Web UI Phase 9 已完成：原生 ES module 拆分、统一视觉/页面信息架构、按 endpoint 缓存与 SSE 精确失效、Events 时间线和后端测试均已落地。详细设计见 `docs/new/observer-ui-redesign.md` 与 `docs/new/observer.md`。
- Windows 前置 F0a-F0e 已完成：撤销重复的 `photonclient.Runtime`，公共 gossip FSM、receive、timer、object-pull、chunk、discovery、checkpoint、transport 与 observability 已收口到 `pkg/core/{gossip,host,state}`；Linux/Windows memory convergence 直接使用同一 GossipDriver/Store/Transport。
- Linux verified/runtime aggregate 已拆开：公共 `state.Store/BoltStore` 拥有 verified/checkpoint，current Linux state type/clone/codec/commit 已进入 `internal/photonlinux`；`stateFile/stateMeta` 只留旧库单向迁移和 legacy dump。
- Linux 实际执行已逐步下沉：IPsec/XFRM、firewall、BIRD/upstream、health probe 和 cleanup 使用唯一 `internal/photonlinux.LinuxDriver` 实例；旧 app driver 字段、重复 adapter、单调用方 commit wrapper 和大量 legacy 测试 fixture 已删除。
- canonical inspect DTO 已成为 control/CLI/HTTP 的公共展示边界；platform runtime 查询要求在线 Daemon，离线只允许 verified/common 与明确标记的 gossip last-known checkpoint。
- 本阶段曾把 `CommonRuntime`、`GossipDriver`、Linux Runtime 和 Daemon coordinator 混称为 Runtime。2026-09 的所有权复核已纠正：目标术语和剩余删除条件见 `docs/runtime-state-ownership.md`，当前执行队列见 `todo.md`。

精确提交级实施记录继续由 Git 历史和 `docs/app-photon-runtime-migration-report.md` 保存，不再把逐文件完成日志复制回主 TODO。

## Phase 0: 单机可信状态机（预计 1-2 周）

**目标：** 在单机完成可验证的配置状态机，不依赖网络。

- [x] **0.1 项目结构**
  - 入口目录：沿用当前 `app/photon/`；后续如需要标准 Go 布局，再迁移到 `cmd/photon/`
  - [x] 已创建：`pkg/core/zone/`, `pkg/crypto/`
  - [x] 待创建：`pkg/core/{identity,merkle,gossip}`, `pkg/transport/wireguard/`, `pkg/routing/bird/`
  - Go 版本已按当前依赖更新为 `go 1.25.0`
  - [x] 引入 Phase 0 依赖：`go.etcd.io/bbolt`, `golang.org/x/crypto`
  - `golang.zx2c4.com/wireguard/wgctrl`, `github.com/vishvananda/netlink` 延后到 WireGuard/路由阶段引入，避免 Phase 0 携带未使用依赖

- [x] **0.2 身份与密钥系统**
  - [x] ED25519 主密钥生成与本地存储
  - [x] 提供 passphrase + bcrypt 加密私钥工具；Phase 0 CLI 默认不强制使用，bbolt 状态库保持本地明文调试语义
  - [x] NodeID = blake2b(pubkey)

- [x] **0.3 Zone / Authority / Delegation / Record 基础模型**
  - [x] 定义设计文档中的核心数据结构
  - [x] 实现 `Get(fqkey)`：解析 Zone + Key → 本 Zone 查找 → 向上 fallback 直到根
  - [x] 实现基础 `Put(record)` 写入 active state
  - [x] 在 `Put(record)` 中接入本地 authority 验证、版本比较和冲突处理

- [x] **0.4 签名与验证**
  - [x] 实现 Record / Delegation 的 Sign 和 Verify
  - [x] 实现 ZoneAuthority canonical hash
  - [x] 实现 VerifyChain
  - [x] 定义并使用 domain separator
  - [x] Phase 0 只接受 `threshold=1`，遇到 `threshold>1` 返回 `unsupported threshold`
  - [x] 预留 `Delegation.Scope`；Phase 0 只接受 `direct-child`，遇到 `subtree` 返回 `unsupported delegation scope`

- [x] **0.5 bbolt 持久化**
  - [x] 按 Zone 分 bucket 存储
  - [x] 加载/恢复/版本链审计
  - [x] 保留 bounded `RecordHistory` 用于版本审计；普通同步不再维护 pending 补前驱状态

- [x] **0.6 CLI 调试**
  - [x] `photon init`
  - [x] `photon gossip zone show <zone>`
  - [x] `photon gossip record put <zone> <key> <value>`
  - [x] `photon verify <zone>`
  - [x] `photon db dump [zone]`：以只读模式打开 bbolt，按 bucket 打印 key-value（JSON 美化）
  - [x] `photon db stats`：统计各 bucket 的 key 数和数据大小

## Phase 1: 两节点 Zone 同步（预计 1-2 周）

**目标：** 跑通安全边界明确的同步流程。

- [x] **1.1 Gossip 传输层**
  - [x] UDP socket 监听（固定端口，如 33434）
  - [x] Protobuf 消息定义：`Ping`, `Pong`, `FetchZone`, `FetchRecord`, `Announce`
    - 已补 `gossip.proto`；Go 代码先使用稳定 message/codec，后续接入 pb 生成代码
  - [x] Anti-replay：64-bit nonce + 时间戳窗口（±5分钟）
  - [x] 限流与配额：每 peer 限制速率/字节/对象数

- [x] **1.2 节点发现**
  - [x] 通过配置文件中的 bootstrap 列表启动
  - [x] 仅接受已知 peer 的连接

- [x] **1.3 Whole-Zone 同步**
  - [x] Phase 1A 先不做 Merkle diff，hash 不同直接拉完整 Zone
  - [x] 数据进入候选状态（quarantine 语义），验签通过后才提升到 active store
  - [x] 逐条验证签名链（VerifyDelegation → VerifyRecord → VerifyChain）
  - [x] 高版本 Record 验签通过后可作为 latest active state；历史补齐不阻塞普通同步
  - [x] 验证通过后提升到 `active store`

- [x] **1.4 闭环验证**
  - [x] 节点 A 修改本地 Zone Record
  - [x] Gossip 到节点 B（`photon sync serve` + `photon sync once <peer>`）
  - [x] B 验证通过后 active store 可见
  - [x] CLI: `photon sync status`

## Phase 1.5: 配置与节点准入工具（已完成）

**目标：** 把 Phase 1 的手工状态准备收敛成固定配置文件和可重复的 join/delegation 流程。

- [x] **1.5.1 固定配置文件**
  - [x] 默认读取 `config.yaml`，可用 `PHOTON_CONFIG=/path/to/config.yaml` 覆盖
  - [x] 配置数据库目录：`data_dir` / `database_dir`，默认状态库为 `<data_dir>/photon.db`
  - [x] 配置监听地址：`listen_addr`，或用 `listen_port` 生成 `:<port>`
  - [x] 配置 bootstrap allowlist：`bootstrap: [{id, addr}]`
  - [x] 配置根信任公钥：`trusted_root_public_key`（默认 base64，兼容 hex 的 ED25519 public key）
  - [x] 使用 `gopkg.in/yaml.v3` struct decode 解析配置文件：启用 `KnownFields`，保留旧字段别名，并支持标准 YAML list 与旧逗号分隔列表兼容
  - [x] 提供 `config.example.yaml`

- [x] **1.5.2 根 Zone 与准入 CLI**
  - [x] `photon gossip root init`：只创建根域 `.` 的 root authority
  - [x] `photon gossip root pubkey`：输出根公钥，供其他节点配置 `trusted_root_public_key`
  - [x] root/admin 状态库与业务节点状态库分离；`node-admin` 只持有 `.` 的 root 私钥
  - [x] 一级管理 Zone（如 `catofes.`）也通过 join request / root delegation 独立加入，并由自己的管理私钥继续委派子 Zone
  - [x] `photon gossip keygen <key.json>`：生成新节点 ED25519 keypair
  - [x] `photon gossip join request <zone> <key.json> [request.b64]`：新节点生成可直接复制的 base64 加入申请
  - [x] `photon gossip delegate issue <request-b64|request-file> [bundle.b64]`：父 Zone 持有者签发可直接复制的 base64 delegation bundle
  - [x] `photon gossip join accept <bundle-b64|bundle-file> <key.json>`：新节点导入信任链和本 Zone authority
  - [x] 新节点不会接触 root/admin 私钥，只持有自己的 Zone 私钥

- [x] **1.5.3 验证目标**
  - [x] `make check`：格式化、vet、单元测试、构建
  - [x] `make join-smoke`：本地验证 root/delegation/join/record/verify 流程
  - [x] `make phase1-smoke`：本地两 peer UDP gossip smoke；需要运行环境允许 UDP socket

## Phase 2: 双节点/多节点配置同步收敛（预计 1-2 周）

**目标：** 在不引入 WireGuard 的前提下，把配置状态同步做扎实：两节点可重复验证，三节点可传播，节点重启后可恢复，latest record / bounded history / conflict 状态可观测。

- [x] **2.1 双节点端到端同步验证**
  - [x] `node-admin` 创建 root `.`，不持有 `catofes.` 私钥
  - [x] `zone-catofes-admin` 通过 root delegation 加入并管理 `catofes.`
  - [x] `node-a`、`node-b` 都通过 `catofes.` delegation bundle 加入
  - [x] `node-a` / `node-b` 分别写入本 Zone record
  - [x] A/B 通过 gossip 双向同步
  - [x] 两端 `sync status`、`zone show`、`verify` 结果一致
  - [x] 将流程固化为不依赖手工复制 DB 的 `make phase2-smoke`

- [x] **2.2 多节点传播**
  - [x] 支持 B-A-C bootstrap 拓扑下的 transitive zone propagation
  - [x] 新 Zone/Record 从 B 写入，经 A 传播到 C
  - [x] 节点离线后重启，能通过摘要比较补齐缺失 Zone
  - [x] 增加 `make multi-node-smoke`，覆盖 3 节点本机流程

- [x] **2.3 同步状态可观测性**
  - [x] `photon sync status` 输出每个 peer 的最近同步时间、已知 Zone 数和本地 root hash
  - [x] 显示 local root hash / per-zone root hash / last error
  - [x] 扩展 `sync status` 用于排查 bootstrap 与 allowlist

- [x] **2.4 Debug / Diagnostics 增强**
  - [x] 为 `sync serve` / `sync once` 增加结构化 debug log；`sync run` 接入留到 2.5 创建该命令时完成
  - [x] 输出消息方向、peer id、message type、zone 数、record 数、字节数、耗时
  - [x] 记录 reject 原因：unknown peer、addr mismatch、message too large、replay、quota、verify failed、unsupported wire version
  - [x] `sync status --verbose` 显示 bootstrap peers、discovered peers、allowlist 来源、resolved addr、last_success、last_error
  - [x] 增加 `photon debug peer <peer-id>`：查看某个 peer 的最近同步、错误、backoff、known endpoint、发现来源
  - [x] 增加 `photon debug zone <zone>`：查看 zone root、record/history 数量、delegation、parent proof、验证结果
  - [x] 支持 `PHOTON_LOG_LEVEL=debug` 或配置项开启详细日志，默认保持简洁输出

- [x] **2.5 自动重连与周期同步**
  - [x] 增加长期运行模式：`photon sync run`
  - [x] `sync run` 同时执行 UDP serve 与周期性 outbound sync
  - [x] 对 bootstrap peers 定时执行摘要比较和缺失 Zone/Record 补齐
  - [x] peer 失败后记录 `last_error`，并使用 backoff 避免紧密重试
  - [x] 网络恢复后自动重试并收敛，不需要手动 `sync once`
  - [x] `sync status` 显示 peer online/stale/backoff/next_retry
  - [x] 增加 smoke：断开/停止 peer 后恢复，验证自动补齐

- [x] **2.6 链式拓扑主动传播 / relay fanout**
  - [x] 明确当前语义：在 A-B-C-D 链式 bootstrap 中，A 更新 record 后会优先同步/announce 给直接 peer B；C/D 默认依赖各自周期性摘要比较或 B 后续 outbound sync 才能得到更新
  - [x] 决定 Phase 2 目标语义：B/C 在成功 apply A 的新 Zone/Record 后，立即向除来源 peer 外的已知 peers 触发 lightweight sync round
  - [x] 增加基础变更来源 tracking：只在 zone digest 发生变化时 relay，并跳过来源 peer，避免 A-B-A、B-C-B 直接回环
  - [x] 为 relay 增加节流和批处理，避免一个 record 更新在稠密拓扑中产生广播风暴
  - [x] `sync run` 在本地 record put 或远端 apply 成功后，支持唤醒 outbound sync，而不是完全等待下一次 interval
  - [x] 增加 smoke：A-B-C-D 链式拓扑中 A 写入 record，验证 D 在无需等待完整轮询周期的情况下收敛
  - [x] `sync status --verbose` 显示已落盘的 peer 最近一次更新来源与 relay 抑制原因，方便离线排查“为什么只到 B 没到 C/D”

- [x] **2.7 Peer discovery / 动态 allowlist**
  - [x] 明确默认身份模型：普通节点的 `peer_id` 默认等于本节点授权 Zone（如 `node-a.catofes.`），bootstrap/discovery 均以 Zone FQDN 作为 peer id
  - [x] 明确 endpoint 模型：一个 `peer_id` 可对应多个 endpoint；多网卡、双栈、迁移地址不应引入多个 peer id
  - [x] 定义高级例外：只有同一授权 Zone 下存在多个独立 gossip 实例/角色时，才引入 peer alias 或 instance id，并必须由该 Zone 显式授权
  - [x] 定义绑定约束：endpoint record 必须由对应授权 Zone 签名，声明的 `peer_id` 默认应等于该 Zone，声明的 endpoints 才能进入 discovered peer table
  - [x] 定义同步 endpoint record 格式，如 `sync/endpoints/udp` 或 `sync/peers/default`，支持一个 peer 下多个 endpoint
  - [x] 明确主路径：节点自动或手工获得自己的公网 endpoint 后，写入本 Zone 下的 signed endpoint record，再通过现有 bootstrap gossip 传播给其他节点
  - [x] 明确本机 endpoint 采集来源：手工配置的 `listen_addr` / `advertise_addr`、本机网卡地址扫描、public IP reflector 返回的公网地址；公网部署不考虑局域网 multicast/broadcast discovery
  - [x] 增加本机网卡地址扫描器：枚举可用 interface addresses，过滤 loopback、down interface、link-local、docker/容器/临时地址等不可发布地址，按 IPv4/IPv6、private/public、interface priority 生成候选 endpoint
  - [x] 增加显式 `advertise_addr` / `advertise_addrs` 配置，用于覆盖自动探测结果；自动发现只能补充，不应覆盖管理员显式声明
  - [x] 增加 public IP reflector 支持框架：可配置多个 reflector 服务，失败时返回错误信号并继续使用其他本地 endpoint 候选
  - [x] 实现 public IP reflector HTTP client：按配置顺序/超时查询多个服务，支持纯文本 IP 与常见 JSON 响应，校验 IPv4/IPv6 后生成 `SourceReflector` endpoint 候选
  - [x] 明确 reflector 结果只是本节点自发现输入：节点必须用自己的 Zone 私钥签名后写入 endpoint record，其他节点只信任 verified active state 中的 signed endpoint，不直接信任第三方 reflector
  - [x] 增加 reflector endpoint 定时刷新：配置 `reflector_interval` / `endpoint_ttl`，周期发布 endpoint record；IP 或端口变化时生成新的 signed endpoint record 版本并触发 outbound sync
  - [x] 处理 endpoint 变更窗口：新 endpoint 发布后保留旧 endpoint grace period，远端根据 ttl/last_observed/连接成功情况逐步淘汰旧地址，避免公网 IP 切换时短暂失联
  - [x] 定义 endpoint 可信度与来源优先级：static advertise addr > signed active-state endpoint record > reflector-derived signed endpoint > interface scan；连接成功后提升可用性分数，失败/backoff 后降级
  - [x] endpoint record 中保留来源、scope、ttl、priority、last_observed 等元数据，避免把临时公网/NAT 反射地址永久固化为稳定配置
  - [x] 新节点加入时写入自己的 gossip endpoint record；如果启用自动探测，则先写入可验证的稳定候选，临时 observed endpoint 走 discovered peer table 而不是长期 record
  - [x] 从 verified active state 解析已授权 peer 的 endpoints
  - [x] 将 discovered peers 合并到运行时 known peer table，bootstrap 作为种子节点保留
  - [x] 接收包时仍按 peer id + endpoint allowlist 校验，避免 unknown peer 直接注入状态
  - [x] endpoint 变更后更新 known peer table，过期/撤销后标记 stale 或移除
  - [x] 增加 CLI 诊断：`photon debug endpoints` 显示本机候选 endpoints、discovered peers；`sync status --verbose` 显示 discovered peers；`debug peer` 显示 discovered_addr
  - [x] 增加 smoke：`make discovery-smoke` 验证新 peer 发布 signed endpoint record 并经 gossip 传播后其他节点可动态发现
  - [x] 增加 smoke：公网 endpoint 由 reflector 自动发现并签名发布；IP 变化后自动发布新版本，其他节点验证 record 后更新 known peer table，并在失败时回退 bootstrap/static endpoint

- [x] **2.8 Latest signed record / bounded history**
  - [x] 明确普通同步语义：更高版本且签名有效的 record 可直接成为 active，不要求从 `@1` 顺序重放
  - [x] `PrevHash` 降级为审计/调试约束：只有本地正好持有直接前驱时才检查，不阻塞跳版本 fast-forward
  - [x] Whole-zone snapshot 只同步 active records，不再把远端完整 `RecordHistory` 作为冷启动依赖
  - [x] 每个 `zone/key` 的历史版本设置有界保留；最初上限为 128，2026-07-24 根据实际 state DB 体积进一步收紧为最近 16 条。
  - [x] 从普通同步主路径移除 pending 补前驱机制；最终一致性依赖 digest + snapshot + 更高版本 signed record
  - [x] 保留 `FETCH_RECORD` wire message 作为兼容和手工按需取单条历史 record 的能力

- [x] **2.9 测试补强**
  - [x] 为 `sync status --verbose`、`debug peer`、`debug zone` 增加 CLI golden/output 测试
  - [x] 增加 gossip 故障注入测试：unknown peer、message too large、replay、quota、unsupported wire version；addr mismatch 保留 reject reason 映射（接收路径已不做地址绑定）
  - [x] 增加 verify failure 测试：错误 root key、篡改 delegation、篡改 record signature、过期 authority key
  - [x] 增加 latest-record 边界测试：跳版本 fast-forward、同版本冲突、直接前驱 PrevHash mismatch、历史窗口裁剪、重启恢复
  - [x] 增加 snapshot limit 测试：zone count、record count、message bytes 达到边界时的 accept/reject 行为
  - [x] 增加 sync run 自动重连集成测试：`phase2-run-smoke` 覆盖 peer 停止/恢复/最终收敛；单测覆盖 backoff 后成功恢复
  - [x] 增加 relay fanout 集成测试：`chain-relay-smoke` 覆盖链式拓扑最终收敛；单测覆盖去重/节流决策
  - [x] 增加 peer discovery 集成测试：`discovery-smoke` 覆盖 endpoint record 发布；单测覆盖更新、撤销后 known peer table 收敛
  - [x] 将需要 UDP 的测试与纯逻辑测试分层，确保受限环境仍能跑完非网络测试
  - [x] 为 smoke 目标输出失败时的关键日志，减少 CI/本机排障成本

- [x] **2.10 同步协议收敛**
  - [x] 明确 JSON wire format 的兼容边界和版本字段
  - [x] 为 message size、zone count、record count 增加可配置限制
  - [x] 梳理是否需要在 Phase 2 末尾切 protobuf；默认仍不引入 `protoc`

- [x] **2.11 文档与操作手册**
  - [x] README 增加双节点完整同步脚本
  - [x] README 增加三节点传播示例
  - [x] README 记录链式拓扑传播语义：周期收敛 vs 主动 relay fanout 的差异
  - [x] 记录常见错误：root public key 不匹配、unknown peer、UDP socket 不允许、record conflict

- [x] **2.12 应用运行时与依赖边界整理**
  - [x] 盘点并收敛 CLI 层隐式依赖：config/state/store、sync transport、known peer table、logger、clock、stdout/stderr、validation hooks
  - [x] 引入轻量 `Runtime` / `App` struct，负责一次性加载 `appConfig`、解析 state path、打开/保存 `stateFile`，并缓存由 config 派生出的 sync config
  - [x] 将 `loadState()` / `saveState()` 拆出显式依赖版本，如 `loadStateAt(path, trustRoot)`、`saveStateAt(path, state)`；保留薄 wrapper 兼容简单 CLI 命令；`saveState` 目前每次调用都经由 `configuredStatePath()` 触发 `loadAppConfig()`，每次包处理落盘均读配置文件，需一并修正
  - [x] 避免热路径重复读配置：`handleSyncPacket`、`relaySync` 直接调用 `loadSyncConfig`；`syncRoundWithTransport` 通过内部调用 `handleSyncPacket` 间接触发，修复 `handleSyncPacket` 即可，无需额外给 `syncRoundWithTransport` 传 config 参数；`syncRun` 主循环中 `reloadStateIfChanged` 约每 250ms 调用一次 `loadState()` → 双重 `loadAppConfig()`，同样需要收敛到运行时持有的 config
  - [x] 引入 `SyncRuntime` / `SyncService`，聚合 `state`、`syncConfig`、`transport`、`limits`、`logger`、`clock`，把 packet handling、round、relay fanout 收为方法；注意应先让函数返回结构化结果（见「CLI 输出隔离」条目），再以方法形式注入 runtime，避免直接平移导致多职责一起塞入大对象，与下方「边界克制」原则矛盾
  - [x] 将 `openSyncTransport` 的 replay window、peer quotas、known peers、debug logger 从局部构造改为运行时可配置依赖，为动态 discovery 和测试注入留接口
  - [x] 补 relay fanout 风险控制：验证失败的 `ANNOUNCE` 当前不会触发 relay，但同一坏 digest 可能被周期性 fetch/reject 形成局部噪音；增加 `(peer_id, zone, root_hash, reject_reason)` rejected digest cache / verify-failed circuit breaker / 更长永久失败 backoff，确保 root mismatch、bad signature、过期 delegation、缺 parent proof 等不会被重复拉取放大
    - 已实现 per-peer rejected digest cache：`syncPeerState.RejectedDigests[zone]` 持久化记录 root hash、reject reason、TTL；后续 `Ping`/`Pong`/`Announce` 摘要比较在 TTL 内跳过同一坏 root，root hash 变化或 TTL 过期后恢复尝试
  - [x] 为 relay 风险增加测试：验证失败不触发 relay；同一坏 digest 在 TTL 内不重复 fetch；远端 root hash 变化后允许重新尝试；多跳链式拓扑中单点拒绝不会造成全网 relay 风暴
    - 已补单测覆盖 bad announce 记录 rejected digest、TTL 内跳过 fetch、root hash 变化/TTL 到期后重试、source/backoff relay 抑制；`chain-relay-smoke` 继续覆盖链式 relay 收敛
  - [x] 把 `configureValidation(state.Network)` 这类散落调用收敛到 state/network 加载边界，或明确为 `Runtime.ConfigureNetworkValidation()`，避免忘记调用导致行为差异
  - [x] 将 `time.Now()` 的同步/backoff/record timestamp 使用收敛到运行时 clock；生产默认真实时间，测试可注入固定时间
    - `SyncRuntime.now()` 覆盖 sync/backoff/endpoint/record timestamp 主路径；`record put`、endpoint record 发布、join/delegation verify、debug status 使用 `Runtime.Now()`，接收 deadline 保持 wall clock I/O 语义
  - [x] 将 CLI 输出从业务函数中逐步隔离：命令层负责 `fmt.Printf`，核心函数返回结构化结果；优先处理 sync status/debug/db dump 等未来要做 golden test 的命令
    - `sync status` 已拆出 `writeSyncStatus(io.Writer, ...)`，diagnostics 路径改为先经 Runtime 加载依赖；现有 golden/output 测试继续覆盖 `sync status --verbose`、`debug peer`、`debug zone`
  - [x] 梳理文件 I/O 边界：key/join bundle/config/state 读写保留在 app 层，`pkg/core/*` 继续保持纯模型和协议逻辑
  - [x] 保持重构边界克制：不要把签名验证、snapshot、record put 等 core 逻辑塞进大对象；struct 只负责生命周期、依赖注入和运行态协调
  - [x] 增加针对 runtime 的单元测试：config 只加载一次、state path/env 覆盖优先级、trusted root 校验、sync limits 派生、debug log env/config 优先级
  - [x] 重构后跑通 `make check`、`make phase2-smoke`、`make multi-node-smoke`、`make chain-relay-smoke`

- [x] **2.13 Delegation 撤销 / Zone 删除语义**
  - [x] 明确删除模型：父 Zone 中的 delegation 是子 Zone 授权的唯一权威来源；删除子 Zone 必须由父 Zone 写入 signed revocation/tombstone，而不是仅从本地 map 中移除
  - [x] 定义 revocation/tombstone 数据结构：包含 child zone、parent zone、revoked authority epoch/hash、reason、revoked_at、ttl/grace、signer，并由父 Zone authority 签名
  - [x] 定义父 Zone snapshot 的优先级：同一 child 的有效 delegation 与 revocation 冲突时，以父 Zone 中版本/epoch 更新且签名有效的状态为准；子 Zone 的 `ParentProof` 只是缓存，不可覆盖父 Zone 撤销
  - [x] 撤销后，本地 active state 将该 Zone 及其子树标记为 revoked/quarantined：停止接受该 Zone 新 record、停止 relay 其新 announce、停止将其 endpoints 加入 known peer table
  - [x] 保留已撤销 Zone 的历史数据用于审计和冲突排查，但默认查询、配置生成、peer discovery、route authorization 不再使用其 active records
  - [x] 清理撤销子树相关 sync peer 状态、discovered endpoints、relay fanout 队列，避免已撤销节点继续通过 relay 恢复活跃状态
  - [x] 增加 CLI：`photon gossip delegate revoke <zone>` 由父 Zone 管理者签发撤销；`photon debug zone <zone>` 显示 revoked 状态、撤销来源、撤销时间和影响子树
  - [x] 增加 gossip 同步语义：revocation/tombstone 必须进入 zone digest/snapshot，传播优先级高于普通 record，节点收到后立即触发 outbound sync/relay fanout
  - [x] 增加测试：撤销普通节点 Zone 后，其他节点拒绝其新 record 和 endpoint；撤销中间管理 Zone 后，其整个子树失效；重启后 revoked 状态仍持久化
    - 已补核心单测：父 Zone tombstone 传播后 VerifyChain/RecordSnapshot 拒绝 revoked child；revoked zone endpoint 不再进入 discovery；父 Zone revocation 覆盖整棵子树；bbolt 重启后 revocation 持久化。
  - [x] 增加 smoke：A/B/C 已建立同步后，管理员撤销 node-b delegation，A/C 收敛后不再信任 B 的 record、endpoint、route announcement
    - 已新增 `make delegation-revoke-smoke`，覆盖 node-b record/endpoint 先传播，随后 catofes 管理员签发 revocation，A/C 收敛后 `verify node-b.catofes.` 失败、`debug zone` 显示 revoked、endpoint discovery 移除 node-b。

- [x] **2.14 Bootstrap 准入死锁 / 新节点首次接入问题**
  - [x] 问题：Transport.validatePeer() 仅接受有 endpoint record 的 peer，新节点 B 首次向 A 发 Ping 时被拒（ErrUnknownPeer），B 的 endpoint 永远无法传播给 A，形成死锁
  - [x] 根因：传输层 `knownPeers` 混淆了「准入控制（身份）」与「地址发现（可达性）」两个角色
  - [x] 修复：拆分准入与地址概念
    - [x] `Transport.AddKnownPeerID(peerID)`：只写入 `knownPeers` 入站白名单，不写 `outboundAddrs`
    - [x] `addVerifiedZonePeers()`：扫描 active state 中所有 `VerifyChain` 通过的 zone，调用 `AddKnownPeerID` 加入白名单
    - [x] `openSyncTransport` / `updateDiscoveredPeers`：初始化时先执行 `addVerifiedZonePeers`，有 endpoint record 的再追加 `SetPeerAddrs`
    - [x] `Transport.lastSeenAddrs`：Send() 无静态 outbound 地址时，回退到最近 inbound 包的 UDP 源地址，使 A 能在无 B 的 endpoint record 时仍回复首条 Pong
  - [x] 安全边界：入站白名单放宽到「有合法 delegation chain」的 zone，但消息内容仍经过完整 `VerifyChain` / `VerifyRecord` 验证，信任根不变
  - [x] 增加 `pkg/core/gossip/transport_test.go`：AddKnownPeerID / lastSeenAddrs 单元测试
  - [x] 增加 `app/photon/sync_test.go`：openSyncTransport / updateDiscoveredPeers 单元测试（构造 root→catofes→node-b delegation chain）
  - [x] 增加 `make bootstrap-join-smoke`：验证全新节点 B 只配置 bootstrap A、A 有 B 的 zone 但无 endpoint record 时，双向 gossip 同步成功建立

## Phase 3: 最小节点 daemon / 单 writer 边界（预计 1-2 周）

**目标：** 在进入 WireGuard 前，先把长期运行同步、CLI 写入、后续 apply 触发统一收到本机 daemon 的串行写入路径里，避免多个进程同时修改 state DB。

- [x] **3.1 Daemon 服务骨架**
  - [x] 明确 Phase 2 → Phase 3 边界：同步已经具备最终一致性；Phase 3 的首要风险是长期进程、CLI 写入和 WG apply 同时改 state，因此先做 daemon 单 writer，再做 WG
  - [x] 抽出 `SyncService` / `DaemonService`：复用 `sync run` 的 UDP serve、周期 outbound sync、endpoint publish、relay fanout、backoff/rejected digest 逻辑，避免维护两套同步主循环
  - [x] 增加 `photon daemon` 常驻模式：加载一次 config/state，启动 UDP transport，进入统一事件循环，并为后续 WG/Babel/firewall apply 预留 state-change hook
  - [x] 明确 daemon 是本节点 state DB 的唯一长期 writer：`record put`、endpoint publish、sync apply、sync trigger、未来 WG apply 相关状态都通过 daemon 串行执行

- [x] **3.2 本地事件队列与控制接口**
  - [x] 定义最小内存事件队列：local record put、remote announce applied、timer tick、manual sync trigger、shutdown/reload；同一队列串行落盘和触发后续动作
    - 已接入 local `record_put`、manual `sync_trigger`、`shutdown`；UDP packet / remote announce applied、endpoint publish timer、outbound sync timer 也已统一为 daemon event handler 分支
  - [x] 提供最小 Unix domain socket control API：`status`、`record_put`、`sync_trigger`、`reload`、`shutdown`；只做本机接口，不做远程管理
  - [x] 约定 socket 路径和权限：默认 `/run/photon/photon.sock` 或 `<data_dir>/photon.sock` fallback；默认只允许本机同用户/管理员访问

- [x] **3.3 CLI client 化与兼容模式**
  - [x] CLI 在检测到 daemon control socket 存在时优先作为 client 提交写命令；daemon 不存在时保留当前直接写 DB 的开发/恢复模式，并输出明确提示
  - [x] `record put` client 化：daemon 存在时提交 `record_put`，由 daemon 签名、写 DB、触发 outbound sync；daemon 不存在时沿用现有直接写入路径
  - [x] `sync status --verbose` / `debug peer` 优先读取 daemon live 状态；daemon 不存在时 fallback 到 bbolt 快照，保证离线排障仍可用
  - [x] 将 `sync run` 标记为开发/兼容入口，内部尽量委托 daemon service 实现，避免 Phase 3 后出现两套长期运行路径

- [x] **3.4 Daemon 测试闭环**
  - [x] 增加 daemon 单元测试：事件队列串行处理、config 只加载一次、state reload 不覆盖更新、control API request/response 兼容错误路径
    - 已覆盖事件串行、state reload 防旧快照覆盖、control API 错误响应；config 只加载一次沿用 `Runtime` 测试覆盖
  - [x] 增加并发安全测试：daemon 运行期间多个 CLI 写命令串行处理，不出现旧 state snapshot 覆盖新写入
  - [x] 增加 smoke：daemon 运行时 CLI `record put` 通过 control socket 提交，daemon 写 DB、触发 gossip sync，远端收敛
    - 已增加 `make phase3-daemon-smoke`；local `record_put` / manual sync trigger 唤醒的 outbound round 会绕过旧 backoff 一次，确保 CLI 写入后立即尝试传播
  - [x] 增加 smoke：daemon 停止后 CLI 直接写 DB 的开发模式仍可用，并能被下一次 daemon 启动正确加载
    - 已增加 `make phase3-daemon-fallback-smoke`

## Phase 3.5: NAT 后节点 / verified inbound UDP path（紧急，Phase 4 前必须完成）

**目标：** 在进入 WireGuard 前，先保证 gossip 能处理“节点在 NAT 后、只能主动发起 UDP”的公网拓扑。已通过 trust chain 验证的 peer 如果从某个 UDP 源地址发来有效消息，本节点应把这条 observed path 当作短期可信通信路径维护，用于回复、后续同步和 keepalive；但不能把临时 NAT 映射永久写成 signed endpoint。

- [x] **3.5.1 入站路径信任语义**
  - [x] 明确 `signed endpoint record` 与 `observed UDP path` 的区别：前者是长期、可传播、由 Zone 签名的可达性声明；后者是本 daemon 运行态观察到的短期 NAT 映射，只能本地使用
  - [x] 只有当 `peer_id` 已在 bootstrap 或 verified active state 中通过 delegation chain 准入，且消息本身通过 replay/quota/wire 校验和 zone/record 验证后，才把 packet source addr 记录为 verified observed path
  - [x] 对未准入 peer、验证失败消息、已撤销 Zone、过期 delegation、bad root digest 的来源地址，不建立 observed path，并记录 reject reason

- [x] **3.5.2 运行态 observed path 维护**
  - [x] 将 `Transport.lastSeenAddrs` 从“无 outbound 地址时的临时 fallback”提升为带状态的 path table：peer_id、remote UDP addr、first_seen、last_seen、last_success、ttl、失败次数、来源消息类型、验证状态
  - [x] daemon 周期性对 observed path 做轻量 keepalive / PING，维持 NAT 映射；成功时提升优先级，失败/backoff 后降级或过期移除
  - [x] `Send(peerID)` 地址选择顺序改为：static/bootstrap 或 signed direct endpoint 优先；当 direct endpoint 失败或 peer 标记为 NAT/outbound-only 时，优先使用仍有效的 verified observed path
  - [x] 收到同一 peer 的新源地址时允许迁移 path，但保留旧 path grace period，避免 NAT 重绑定或公网 IP 切换期间立即失联

- [x] **3.5.3 协议与诊断**
  - [x] 在 peer debug/status 中显示 `observed_addr`、path 状态、TTL、last_seen、last_success、失败原因、是否用于当前 outbound
  - [x] endpoint metadata 增加或明确 `scope/reachability`：`direct`、`reflector_candidate`、`observed_udp`、`outbound_only`；`observed_udp` 默认不写入 signed endpoint record，只在本地 runtime/peer state 中保存
  - [x] README 明确 NAT 语义：NAT 后节点可通过主动 outbound gossip 与公网 bootstrap/peer 收敛；任意节点主动拨入 NAT 后节点仍需要端口映射、IPv6、hole punching 或后续 relay 能力

- [x] **3.5.4 测试闭环**
  - [x] 单测覆盖：验证成功后记录 observed path；验证失败/撤销后不记录；path TTL 过期；新源地址迁移；地址选择优先级与 backoff 降级
  - [x] 集成 smoke：B 只主动向 A 发起同步，A 通过 verified observed path 回复并继续维持短期双向通信；B 不发布可直连 signed endpoint 时仍能最终收敛
  - [x] 公网手册增加 NAT 场景检查项：普通家庭宽带/CGNAT 节点只配置公网 bootstrap，验证 daemon 能显示 observed path 并完成 record 收敛

- [x] **3.5.5 Daemon observed path 自动触发测试**
  - [x] 增加 `make nat-daemon-observed-smoke`：A/B 都以 daemon 运行，B 配置 `publish_endpoints: false` 只主动连 A；A 通过 control socket `record put` 后，daemon 的本地写入触发 outbound sync，并必须通过 verified observed path 将新 record 推送给 B
  - [x] 该 smoke 明确区分 daemon 集成行为与 3.5.4 的核心 observed path 能力：测试允许 endpoint timer 存在，断言 B 没有 signed direct endpoint / `discovered_addr`（A 使用 `advertise_addr` 避免 interface scan 地址干扰），且 A 的 `observed_status` 为 active
  - [x] 覆盖异步触发边界：CLI `record put` 返回后轮询 B 收敛；失败时通过 `cat a.log b.log` 输出 daemon trigger、observed path 和 sync round 日志用于排障

## Phase 3.6: UDP MTU-safe gossip framing（紧急，Phase 4 前必须完成）

**目标：** 公网 UDP gossip 不依赖 IP fragmentation。所有常规控制面消息都应控制在保守 MTU 预算内；超过预算的数据通过可靠 object pull 拉取，不能假设 64KB UDP datagram 在公网、WSL、NAT、隧道或云网络中可靠到达。UDP chunk fallback 只作为后续可选能力，不进入第一版主路径。

- [x] **3.6.1 MTU 预算与配置语义**
  - [x] 将 `max_message_bytes` 从“允许的最大 UDP payload”重新定义为安全 datagram 上限，默认调整到保守值（建议 1200 bytes，兼容 IPv6、NAT、隧道和常见公网路径）
    - 已将 gossip 默认 datagram 预算调整为 1200 bytes；旧 `max_message_bytes` 仍兼容读取，但新配置示例使用 `max_datagram_bytes: 1200`
  - [x] 增加或明确 `max_datagram_bytes` / `target_datagram_bytes` 配置；两端协商或取本地保守值，禁止发送超过预算的 UDP packet
    - `max_datagram_bytes` / `target_datagram_bytes` 优先于旧字段；发送端通过 MessagePack wire size preflight 和 `Transport.Send` 双重限制，超预算对象转 object pull / digest-only announce
  - [x] debug/status 输出当前 datagram 预算、最近丢弃/拒绝的大包、拆包统计，避免只看到 `quota` / timeout 难以定位
    - `sync status --verbose` 已输出 `max_datagram_bytes` / `wire_codec`，并按 peer 显示持久化的 oversized UDP drop、digest-only announce 和 UDP chunk fallback 计数；`debug peer` 显示最近 oversized 对象、zone/key、bytes/limit。第一版主路径无 UDP chunk，因此 fallback 计数保持为显式 0。
  - [x] README 和公网手册明确：Photon gossip 不依赖 IP fragmentation；调大上限只是实验/内网诊断选项，不是公网推荐配置

- [x] **3.6.2 MessagePack wire codec / 压缩协议**
  - [x] 设计并切换 gossip wire codec：从当前 JSON payload 迁移到 MessagePack，避免一开始引入 protobuf/protoc codegen；protobuf 保留为未来极限优化或强 schema 需求的 optional later 路线
  - [x] Go struct 使用短 tag（如 `msgpack:"t"` / `msgpack:"z"` / `msgpack:"r"`）压缩字段名，让 MessagePack 体积接近 protobuf，同时保持开发和调试轻量
  - [x] 二进制格式必须直接承载 `bytes` 字段（pubkey、signature、hash、record value），避免 JSON base64 与字段名开销放大数据包
  - [x] 定义 wire version / codec negotiation：保留 magic/version，支持短期 JSON v1 兼容或明确升级窗口；未知 codec 返回 `unsupported_wire_version` / `unsupported_codec`
    - 默认发送 `photon.gossip.m1` MessagePack；接收端短期兼容旧 JSON magic；未知 codec / version 已有单测覆盖
  - [x] 为常见消息建立 size benchmark：Ping/Pong、metadata snapshot、single record、endpoint record、delegation/revocation；以 1200-byte datagram 预算评估剩余 headroom
    - 已补 `TestCommonMessageSizesWithinDatagramBudget`，覆盖 Ping/Pong、metadata snapshot、single record、endpoint record、delegation snapshot、revocation snapshot 的默认 MessagePack wire size，并按 1200-byte budget 断言。
  - [x] 评估是否需要通用压缩（如 zstd）但默认不对 UDP 小包启用；压缩只允许用于大 object pull，且必须有阈值、最大解压大小和 CPU/内存上限，避免解压炸弹和小包负收益
    - 当前 UDP 控制面不启用通用压缩；TCP object pull 仍为 length-prefixed MessagePack。后续若引入 zstd，仅用于大 object pull 响应，并必须带压缩阈值、最大解压大小和 CPU/内存上限。
  - [x] 更新 README / docs/protocol.md（后并入 `docs/new/` 系列文档；`docs/protocol.md` 已删除）：当前 JSON framing 只作为旧协议说明，新公网推荐路径是 MessagePack + MTU-safe framing；`gossip.proto` 保留为协议形状参考而非当前构建依赖

- [x] **3.6.3 Snapshot / record 分帧**
  - [x] 固化当前临时修复方向：Zone metadata snapshot 与 record payload 分开发送，单条 record 走独立 `RecordSnapshot` 或等价小消息
  - [x] UDP gossip 主路径只传 digest、fetch request、ack/nack、小 metadata 和小 record；单条 record value 超过 datagram 预算时不直接塞进 UDP announce
    - 超预算对象不走 UDP announce payload，由 object pull / chunk fallback 补齐
  - [x] 对多 record / 多 zone 同步增加发送批次规划：按预算打包，优先发送 digest、parent proof、delegation/revocation，再发送 active records
    - 已增加预算内 announce planner；后续读写分离后收敛为只发送 digest hint，完整对象由 object pull / chunk fallback 获取
  - [x] 接收端只在完整对象通过大小/数量限制后进入验证；超预算对象必须走 object pull，不能通过大 UDP datagram 隐式传输

- [x] **3.6.4 Reliable object pull**
  - [x] 设计 object transfer 层：UDP gossip 发现 digest/object 缺失后，通过短连接 TCP pull 拉取完整 snapshot 或大 record；后续可升级 QUIC，但第一版先保持 TCP request/response 简单模型
  - [x] object pull 必须沿用同一 trust boundary：对象内容仍按 root/delegation/record signature 验证；TCP/QUIC 只是传输优化，不是信任捷径
  - [x] TCP pull 不做完整 gossip、不维护长连接、不引入连接池；只支持按 object id / zone digest 拉取对象，设置短超时、并发上限和响应大小上限
    - TCP pull 保持短连接 request/response，支持 zone snapshot / record request；客户端有短超时、本地并发上限（4）和 8 MiB 响应大小上限
  - [x] endpoint/可达性选择：有 signed direct endpoint 或主动连接公网 bootstrap 时使用 TCP pull；对只有 verified observed UDP path 且 TCP 不可达的 peer，第一版允许标记 `large_object_unreachable` 并等待后续可选 fallback
    - TCP 地址继续从 bootstrap 或 signed endpoint 推导，并使用同一个数字端口；没有 TCP 地址时写入 object pull stats，并标记 `large_object_unreachable`
  - [x] debug/status 显示 object pull 最近错误、对象大小、来源 peer 和是否因不可达而跳过大对象
    - `sync status --verbose` 和 `debug peer` 已显示 object pull attempts/successes/failures、最近对象 zone/key/bytes/source peer、最近错误与 unreachable 标记

- [x] **3.6.5 可靠性与反放大控制**
  - [x] `sync once` 的完成条件改为基于目标 digest/对象确认或明确的 idle + no-pending-work，而不是收到任意 announce 后返回
    - 当前 sync round 会在 UDP quiet 后进入 object-pull 阶段，最终仍有 pending digest 时返回 `sync once timed out with pending zones`
  - [x] 对 object pull、record retry、relay fanout 加入 per-peer inflight 限制、超时清理和配额计费，避免大对象或坏 peer 造成内存/带宽放大
    - object pull 客户端保留全局并发上限，并新增 per-peer inflight 上限与按 peer 的 byte/object token quota；TCP dial/read/write 仍使用短 deadline。relay fanout 对单次 inbound 更新设置硬上限，超过后记录 `relay_fanout_limited`。
  - [x] 验证失败的对象按 `(peer_id, object_hash/root_hash, reason)` 进入 rejected cache；同一坏对象在 TTL 内不重复拉取
    - rejected cache 继续兼容旧 zone digest 条目，并新增 zone/record 对象维度：zone 记录 root hash，record 记录完整 object hash 与 reason；sync round/object pull apply 失败会写入 cache，同一坏 root/record 在 TTL 内跳过，hash 变化或 TTL 过期后重试。

- [x] **3.6.6 测试与 smoke**
  - [x] 增加单测：MessagePack codec 往返兼容、未知 codec/version 拒绝、消息编码必须低于 datagram 预算；超预算 record 转 object pull，不生成超预算 UDP datagram
  - [x] 增加大小基准/回归测试：JSON 与 MessagePack 对典型 gossip 消息的 encoded size 对比，确保二进制迁移实际降低包大小；protobuf 只作为可选参考基准
    - 已补典型消息矩阵，覆盖 Ping/Pong、FetchZone、FetchRecord、digest announce 和 object pull 相关对象；MessagePack size 必须小于 JSON。
  - [x] 增加 object pull 集成测试：UDP digest 发现缺失后，通过 TCP pull 拉取大 snapshot/record 并收敛；TCP 不可达时记录 `large_object_unreachable`，不假装同步成功
    - 已有 object pull 单测、sync object pull 集成测试和 `make object-pull-smoke`；新增 TCP 无服务场景，验证 sync round 返回 pending zones、未写入大 record，并累计 `large_object_unreachable`。
  - [x] 增加集成测试：模拟丢弃超过 1200 bytes 的 UDP packet，`phase1-smoke`、`phase2-smoke`、`chain-relay-smoke` 仍能收敛
    - 发送端 preflight / planner 已断言不会生成超过 1200 bytes 的 UDP announce；常规 `phase1-smoke`、`phase2-smoke`、`chain-relay-smoke` 继续覆盖默认 MTU-safe 控制面收敛。
  - [x] 增加公网/WSL 回归 smoke：覆盖 WSL loopback 或受限 MTU 环境中 1.5KB+ snapshot 不依赖 IP fragmentation 也能同步
    - `make object-pull-smoke` 覆盖 3000-byte record 在 1200-byte datagram budget 下通过 daemon + TCP object pull 收敛，不依赖 UDP/IP fragmentation。
  - [x] 保留 `message_too_large` 故障注入测试，并补充“发送端主动不生成超预算 datagram”的断言
    - `message_too_large` 故障注入仍在；新增 planner 回归测试逐个统计 announce wire size，确保 ANNOUNCE 只承载 bounded digest hint。

- [x] **3.6.7 UDP chunk fallback**
  - [x] 真实公网/NAT 测试证明需要“TCP/QUIC 不可达但 verified observed UDP path 可用的大对象同步”后启用：`fetch_zone` 请求遇到超预算 zone snapshot/record 时，发送端追加 `object_chunk` UDP fallback
  - [x] chunk 绑定 object type、zone/key/version、zone root hash、content hash、total/index；接收端使用短期内存重组缓存，完整对象 hash 匹配后才解码
  - [x] chunk 丢失/乱序/重复/篡改不得进入 active state；完整 zone snapshot 仍经 trust chain / signature 验证后才 apply，chunk 消息继续计入 per-peer quota，并记录 `chunk_fallbacks`

- [x] **3.6.8 Catalog sync / bounded UDP control**
  - [x] 文档整理：新增 `docs/gossip-protocol.md` 作为 gossip canonical 规范（后迁移并扩展为 `docs/new/gossip.md`）；`docs/protocol.md` 改为控制面协议入口和 IPsec/overlay record 规范（后并入 `docs/new/overall.md`、`docs/new/transport-ipsec.md` 并删除）；`docs/design.md` 只保留架构边界并指向 gossip 专文。
  - [x] 定义并实现 `CatalogSummary`：`catalog_root`、`zone_count`、可选 bounded `first_page` / `next_cursor`；`PING` / `PONG` 不再承诺携带完整 `ZoneDigest[]`。
  - [x] 新增 bounded catalog page 消息：`FETCH_CATALOG_PAGE{cursor}` 与 `CATALOG_PAGE{catalog_root, entries[], next_cursor}`；`entries[]` 必须按 `max_datagram_bytes` 打包，单页超预算时 fail closed 并输出诊断。
  - [x] 同步状态机改为 summary -> catalog page diff -> object pull：catalog root 相同直接完成；root 不同则分页 diff，发现 Zone digest 不同后再 `FETCH_ZONE` / TCP object pull。
    - [x] `SyncSession` 拆分为 active pull FSM、只读 responder 和 hint ingress；`ANNOUNCE` 只作为 wakeup / digest hint。
    - [x] 新增 catalog 事件/action：`CatalogSummaryReceivedEvent`、`CatalogPageReceivedEvent`、`CatalogPageTimeoutEvent`、`SendFetchCatalogPageAction`、`SendCatalogPageAction`；`ObjectPulling` / `ChunkFallback` 继续作为完整对象传输阶段。
    - [x] `PacketQuietTimeout` 只用于 UDP hint/page quiet 和 fallback 收尾，不能再作为“发现 digest mismatch 后才启动 object pull”的主路径；page diff 得出的不同 Zone 应立即进入 object pull。
  - [x] 所有 list 型 UDP 字段统一预算化：Ping/Pong summary、catalog page、announce digest 均不得生成超过 `max_datagram_bytes` 的 datagram。
  - [x] 测试：构造大量 Zone 导致旧 full-digest `PING` 超过 1200 bytes 的场景，验证 catalog page sync 能收敛；覆盖 cursor 稳定性、空 page、单个过长 ZonePath、page root 不一致、恶意/乱序 page。
  - [x] 文档/诊断：`sync status --verbose` / `debug peer` 显示 catalog root、zone count、最近 catalog page cursor、page oversized / rejected reason。

## Phase 4: StrongSwan / XFRM interface 建链（预计 2-3 周）

**目标：** 两个节点能根据同步后的 Zone 配置自动建立 IKEv2/IPsec SA，并通过 XFRM interface 暴露为普通三层链路。WireGuard 后移为可选轻量传输驱动，不作为动态路由主线。

- [x] **4.x IPsec 链路身份重新分层**
  - [x] 引入无方向 `LinkID` / `PairID` 作为两节点同一逻辑 link 的唯一基础身份：`hash(sorted(local_zone, peer_zone), overlay_id, path_key)`；`path_key` 第一版为 `default` 或 `family:ipv4` / `family:ipv6`。
  - [x] `LinkInstance`、routing/debug/health read model 以稳定 `LinkID` 为主键；runtime connection、generation、interface 作为观测 label，避免 rotate 后历史断裂。
  - [x] 将 `TransportID` 降级为 runtime resource id：`RuntimeConnectionID = "ipsec-" + short(hash(LinkID, generation, provider, "runtime"))`，staged generation 使用 `-r<generation>` 短名；`ChildSAName = RuntimeConnectionID + "-child"`。
  - [x] XFRM 与 interface 从 runtime 派生：`XFRMIfID = uint32(hash(LinkID, generation, provider, "xfrm-if-id"))`，0 改为 1；`InterfaceName = phx<8hex>`，保持 Linux 15 字符限制。
  - [x] owner token 从 `hash(LinkID, RuntimeConnectionID, "owner-token")` 派生，用于 create/adopt/cleanup/revocation 的 owner guard；兼容旧 `TransportID` owner token 的迁移/清理。
  - [x] `derived-link-local` / `derived-pool` 地址改为从 `LinkID + address_epoch + mode + pool? + lower/higher` 派生；`address_epoch=0` 为稳定地址，staged old/new 同 family 双 running 时用 generation 作为 epoch，尤其避免 `derived-pool` 地址复用。
  - [x] `derived-pool` 派生把 pool 纳入 hash：IPv4 跳过 network/broadcast/不可用 host，IPv6 跳过 pool base/不可用地址，通过 retry 处理候选不可用。
  - [x] 新增 overlay/link intent 记录层：`ipsec/overlays/<overlay_id>` / `ipsec.overlay_intent.v1` 表达本节点愿意把节点级 `ipsec/profile`、`ipsec/addresses`、`ipsec/ports`、`ipsec/transport-key` 能力用于哪个 `overlay_id/path_key`；daemon 为每个本地 StrongSwan overlay 发布 signed intent，`family-redundant` 发布 `family:ipv4` / `family:ipv6`，`exhaustive` 发布 `default`。
  - [x] planner 只有在远端 capability 完整可信、本地 `connect` 选择 peer、远端 overlay intent 与本地 `overlay_id/path_key` 和 tunnel address mode/family/pool 兼容时才输出 desired link；缺 intent 输出 `missing_overlay_intent`，provider/path_key/tunnel address 不兼容输出 `overlay_intent_mismatch`。
  - [x] `sequential-pool` 标为 legacy：保留兼容和迁移测试，但新设计、示例和文档默认使用 `derived-link-local` 或 `derived-pool`。
  - [x] 补迁移策略：从旧 `TransportID`/directional address 状态恢复时能 adopt/cleanup 旧资源，重新写入 `LinkID`、runtime id、owner token、tunnel address；debug links 显示 `link_id`、`path_key`、`runtime_id`。
  - [x] 测试闭环：核心 planner/instance、daemon dry-run bringup/SA observation、debug read model、overlay intent record、不同 overlay skip、tunnel address intent mismatch、双端同 overlay `LinkID` 一致、family-redundant 不同 path_key/LinkID、单 family intent 过滤、runtime generation 派生、derived-pool staged address epoch 不复用、staged/current runtime restart 恢复均已有覆盖。

- [x] **4.0 Admin 写操作 daemon 化 / 控制 API 补齐**
  - [x] 将 `delegate issue` client 化：daemon 存在时通过 control socket 提交 join request，由 daemon 持有父 Zone 私钥、签发 delegation、写 DB、返回结构化 bundle；CLI 负责人类可读输出和 bundle 文件写入；daemon 不存在时保留 direct/recovery 模式并输出明确提示
  - [x] 将 `delegate revoke` client 化：由 daemon 串行写入 signed revocation/tombstone、清理 peer state、触发 outbound sync 和后续 apply hook
  - [x] 将 `join accept` 纳入本地 daemon/recovery 边界：普通节点 daemon 未运行时允许初始化；daemon 已运行时通过 control API 导入 bundle，避免旧 snapshot 覆盖运行态更新
  - [x] 梳理 `root init` / `root pubkey` / root delegation 的运行形态：`root init` 是 daemon 启动前的离线初始化；已有 daemon 加载 state 时拒绝 root 重置；root delegation 通过 `delegate_issue` 进入 root admin daemon 单 writer 边界
  - [x] 扩展 control API：`delegate_issue`、`delegate_revoke`、`join_accept`、`root_init` guard；返回结构化 JSON，CLI 负责人类可读输出和 bundle 文件写入
  - [x] 加入授权分级第一版：只做本机 Unix socket，socket 文件权限 `0600`；远程 token/mTLS 留给后续远程管理阶段
  - [x] 增加测试：daemon admin 事件覆盖 `delegate issue` / `join accept` / `delegate revoke` 串行落盘；root init control guard 覆盖已运行 daemon 不可重置；`admin-daemon-smoke` 覆盖 root/catofes daemon 签发 bundle 和撤销

- [x] **4.0.1 Auto-join / 配置化身份初始化**
  - [x] 增加配置项：`managed_zone` 声明本节点 Zone，`identity.key_path` 指向本节点 ED25519 私钥文件；配置文件只引用 key 文件路径，不直接内嵌私钥
  - [x] daemon/CLI 启动加载 state 时支持配置化 identity overlay：先校验 key 文件自洽，再校验 key public 与 DB 中 `ZonePrivateKey`、`ManagedZone` authority 一致；不一致时 fail closed
  - [x] 明确身份不可变：DB 一旦已有 `ManagedZone` / signing key，启动或 reload 发现 `managed_zone`、`identity.key_path` 或 key public 与 DB 不一致，直接拒绝并提示使用新的 `data_dir` / `state_path` 重新创建节点
  - [x] reload 只允许验证身份配置仍与当前 DB/运行态一致，不支持热切换身份；身份变更等价于新节点，不做 DB 迁移、覆盖或半更新
  - [x] 空 DB / 未初始化 DB 首次启动时，如果配置同时提供 `managed_zone`、`trusted_root_public_key`、`identity.key_path` 和 bootstrap peer，则自动创建最小 bootstrap state，不再要求人工 `join accept <bundle.b64> <key.json>`
  - [x] auto-join 节点启动后从 bootstrap peer 普通同步 root 到本 Zone 的 authority/delegation chain；只有验证 `trusted_root_public_key`、delegation chain 和本地 key public 均匹配后，才进入正常 record signing、endpoint publish、IPsec publish/reconcile
  - [x] auto-join pending 时 daemon 日志直接打印可提交给父 Zone 管理节点的 base64 `join_request`，并提示可用 `photon gossip join request --from-config [request.b64]` 输出或保存同等内容；daemon 不引入 `join_request_path`，也不自动提交授权请求
  - [x] 保留 `join request` / `delegate issue` 作为父节点授权入口；父节点签发 delegation 后写入自身 active state，从节点重连后通过同步获得授权信息，bundle 文件导入只作为 recovery/debug 兼容路径
  - [x] 增加测试：空 DB auto-join happy path、key/public mismatch 拒绝启动、`managed_zone` mismatch 拒绝启动、reload 身份变化拒绝、已初始化 DB 与配置一致时可正常启动/reload

- [x] **4.1 StrongSwan / XFRM 控制模块**
  - [x] 定义 overlay/provider 分层：`MeshPolicy` 只描述“选择哪些 peer 形成哪类 overlay”；`OverlayProvider` 负责把 desired link 渲染为 StrongSwan/WireGuard/VXLAN 等具体系统配置；Phase 4 只实现 `provider=strongswan`，但内部模型不得把 mesh 选择逻辑写死到 IPsec driver
  - [x] 定义最小 `TransportLinkSpec`：local zone、peer zone、overlay id、provider、transport id、IKE identity、认证材料引用、`ContactPoint` candidates、XFRM `if_id`、interface name、本地/远端 tunnel address、目标 network namespace
  - [x] 定义 `LinkGroupSpec` / overlay group 模型：group id/name、provider、目标 netns、默认 path mode、地址来源优先级、最大 peer/link 数、tunnel address pool、reconcile/backoff 策略；daemon 以 link group 为 desired-state 边界生成多条 `TransportLinkSpec`，避免把每条 peer link 都变成手工配置
  - [x] 认证材料不复用 Zone signing key；生成独立 IKE key/cert 或 raw public key，优先 Ed25519，兼容性不足时退到 ECDSA P-256，避免 RSA 长 key/大 record 体积
  - [x] 通过 signed transport record 将 IKE public key / fingerprint 绑定到 Zone trust chain：Zone key 证明 transport key 属于该 Zone，IKE 握手只使用 transport key
  - [x] 定义 IPsec public profile record：节点公开 `ipsec/profile`，包含 `enabled`、IKE public key/fingerprint、公开 role intent（`out` / `in` / `both`）、支持的 address family、path mode 能力、NAT/reachability hint；该 record 只表达“可被尝试连接的能力/意图”，不公开完整本地 mesh 规则或拓扑
  - [x] 定义 IPsec address advertisement record：节点公开 `ipsec/addresses`，地址与端口分开建模；地址来源支持 `manual-address`、`manual-dns`、`discovery`、`reflector`、`local`，并保留 family、scope/reachability、source、priority、TTL、DNS refresh interval、last_observed 等元数据
  - [x] 定义 IPsec port advertisement record：节点公开 `ipsec/ports`，端口不嵌入 address；支持固定端口、端口范围、当前端口、上一组端口 grace period、local/listen port、advertised port、observed external port，并为后续 rotate/hopping 预留 generation/valid_until 字段
  - [x] 定义 `AddressCandidate` / `PortAdvertisement` / `ContactPoint` 三层模型：resolver 先得到当前可用地址，再读取当前端口公告，最后组合出 StrongSwan 可拨号目标；避免把 `ip:port` 固化为单一 endpoint
  - [x] 支持 DNS 作为一等地址来源：保存原始域名，按配置周期 refresh A/AAAA 记录；DNS 解析结果只是运行时 address candidates，DNS 不天然高于 discovery/reflector，优先级由本地配置决定
  - [x] 支持 discovery server / reflector 作为可选地址来源：discovery 可返回候选地址/域名/端口公告；reflector 主要提供 observed address/port；两者都不能成为信任根，远端仍必须验证 Zone 签名记录和本地 mesh policy
    - `AddressAdvertisement{Source: discovery}` 可携带 IP 或 host；`ResolveAddressCandidates` 在运行时 resolver 存在时展开 discovery host，reflector/local/manual IP 继续按 signed record 与 TTL 进入候选。
  - [x] 支持本地地址来源 `local`：用于 LAN、实验和显式启用场景；公网默认配置应允许禁用 private/link-local/interface-scan 结果，避免误把内网地址用于公网 IPsec
    - `AddressCandidateOptions.AllowPrivateLocal` 默认 false，local 私网、loopback、link-local、ULA 候选会被过滤；LAN/实验场景可显式放开。
  - [x] 支持 address source priority 配置：默认可为 `manual-address/manual-dns > discovery > reflector > local`，但必须允许管理员改顺序或按 rule 限制来源；不要把动态 DNS 视为天然最高优先级
    - `AddressCandidateOptions.SourceOrder` / `AllowedSources` 控制排序与过滤；排序先按 source order，再按单条 priority/current generation，避免动态 DNS 被硬编码成最高优先级。
  - [x] 设计端口选择/轮换边界：端口由本节点在配置的固定值或范围内选择并公告；轮换时同时发布 current 与 previous grace；peer 连接时用当前地址候选与端口公告组合；当前实现只完成公告/planner/dry-run 层，不代表 StrongSwan 已同时监听新旧端口；平滑 rotate 的低频生产路径提前到 Phase 4.4 规划，高频 port hopping / 对抗性跳变留到 Phase 7
  - [x] 通过 VICI 控制 StrongSwan，优先使用 `github.com/strongswan/govici/vici`；`swanctl` 只作为人工 debug/dry-run 对照，不作为核心控制面输出解析依赖
    - 已新增 `StrongSwanDriver` / `VICIClient` 边界：driver 只发 `load-conn`、`terminate`、`unload-conn`、`list-sas` VICI command，不解析 `swanctl` 输出；`VICIClient` 的 command/message 形状与 govici 的 `Session.Call` / streaming command 模型对齐，真实环境接入 govici session 时不改变 `IPsecDriver` 边界。
  - [x] 定义 `IPsecDriver` / `XFRMDriver` 薄接口：`LoadConnection`、`UnloadConnection`、`TerminateSA`、`ListSAs`、`EnsureInterface`、`DeleteInterface`、`AssignAddress`
  - [x] 增加 fake/dry-run driver：非 root、无 strongSwan、无 XFRM 权限环境仍可测试 desired config 推导、apply 顺序和错误路径
    - `ApplyTransportLink` 生成可审计 `ApplyPlan`，并按 ensure namespace -> load connection -> ensure XFRM interface -> assign tunnel address 的顺序调用 dry-run driver。
  - [x] 做运行依赖检测：VICI socket / `charon` 可用性、strongSwan XFRM 支持、Linux kernel/iproute2 XFRM interface 支持、`CAP_NET_ADMIN`/root 权限、UDP 500/4500 或自定义端口可用性
  - [x] 稳定派生 XFRM `if_id` 与 interface name：基于 local zone + peer zone + transport id hash，`if_id` 使用 32-bit 值，接口名满足 Linux 15 字符限制并处理冲突
  - [x] 第一版默认一条 peer link 一个 XFRM interface；后续再评估 shared XFRM interface 或 in/out 分离 interface
  - [x] 定义 netns 配置来源：`config.yaml` 暴露 `netns.default` / `netns.names`，link group 通过 `overlays[].netns` 引用声明的 netns；单条 `TransportLinkSpec` 可继承或覆盖；默认 netns 为 `name:photon` 且允许创建，避免 XFRM/Babel overlay data-plane 默认落在 host ns；`overlay.default_netns` / `ipsec.default_netns` 仅保留为旧配置兼容别名
  - [x] 定义 namespace ensure 边界：`XFRMDriver.EnsureNamespace` 在 interface 创建前确保目标 ns；dry-run 记录将创建的 ns；真实 provider 后续只自动创建 Photon 配置声明且带归属边界的 named ns，`host` 和 path ns 不隐式创建
  - [x] 实现真实 XFRM/netns provider：创建缺失的 named netns（默认 `photon`）、在目标 named netns 内创建 XFRM interface、分配 tunnel address；失败时进入 degraded/error 并保留可审计的 apply plan
    - 已增加 `SystemXFRMDriver`：通过 `ip`/iproute2 执行 named netns ensure、XFRM interface create/up、address replace 和 delete；named netns 下直接执行 `ip netns exec <ns> ip link add ... type xfrm`，避免依赖 host-side link move；path netns 第一版只做存在性检查，需 bind 到 `/var/run/netns` 后按 named netns 管理。
  - [x] CHILD_SA 使用 route-based VPN 模型，traffic selector 可保持宽泛；Phase 4 只负责 peer-to-peer tunnel link，路由前缀授权留给 Phase 5 Babel/route filter
    - `BuildLoadConnMessage` 渲染 VICI `load-conn` message：每条 link 一个 child，`mode=tunnel`，`if_id_in/out` 使用稳定 XFRM if_id；IPv4/IPv6 tunnel address 仅决定宽泛 selector family（`0.0.0.0/0` 或 `::/0`），多前缀授权不进入 Phase 4。
  - [x] 实现撤销/删除清理：terminate IKE_SA/CHILD_SA、unload connection/secret、删除 XFRM interface、地址、临时路由和本地运行态
    - 已增加 `PlanTeardown` / `TeardownTransportLink`：按 terminate SA -> unload connection -> delete XFRM interface 的顺序执行，并由 dry-run 测试锁住撤销/删除 apply plan。

- [x] **4.2 链路实例管理**
  - [x] 定义 `LinkInstance` 运行态模型：link id、peer zone、transport kind、desired spec hash、actual state、XFRM interface、`if_id`、IKE_SA/CHILD_SA id、endpoint in use、last error、last transition
  - [x] 定义本地 `MeshPolicy` / `LinkGroupSpec` 持久化来源：优先作为本机 daemon 配置/DB policy，不通过 gossip 公开；policy 描述“哪些 group 连接哪些 peer/overlay/provider/netns”，而不是列举每个已发现节点的手工 link
    - 已在 `config.yaml` 增加本地 `netns:` / `overlays:` 配置来源，解析为 `[]ipsec.LinkGroupSpec` 并保存在 `appConfig.IPsec.LinkGroups`；link group 默认继承 `netns.default`，支持 provider、netns 引用、path mode、address source order、max peers/link、tunnel address pool、reconcile/backoff，以及本地 connect/deny rule 字符串；旧式内联 netns 和 `overlay.default_netns` / `ipsec.default_netns` 保留为兼容读取。本节点 initiator 角色由 `ipsec.role` 与远端 `role` 推导，group 中不再配置 direction。
  - [x] 设计简化 rule DSL：例如 `strongswan://*.catofes.?role=both&family=dual&source=manual-dns,discovery&mode=family-redundant`；第一版支持 zone glob/exact、role/tag、远端 role intent、address family、address source、path mode、max_peers、allow/deny 顺序
    - 已新增 `ParseMeshPolicyRule` / `ParseMeshPolicyRules`：支持 `strongswan://*.catofes.`, `strongswan://role=edge`, `strongswan://tag=lab` 三类目标，校验 `role`、`family`、`source`、`mode`、`max_peers`，并提供 zone glob/exact 匹配；`config.yaml overlays[].connect/deny` 现在会在加载时校验 rule 字符串。示例默认使用 zone glob（如 `*.lab.catofes.`），`role/tag` target selector 等待本地 peer label 来源接入后再作为常规示例。rule 中不再出现 `direction`；若旧配置包含 `direction` 或旧 `role` query，加载时报错。
  - [x] IPsec role 命名迁移：signed `ipsec/profile` schema、配置、planner/filter 和示例从 `ipsec.accept` / `accept=...` 与 `none` / `inbound` / `bidirectional` 切换为 `ipsec.role` / `role=...` 与 `out` / `in` / `both`；不保留旧配置兼容，旧 `direction` / `accept` query 直接报错。
  - [x] daemon 从 active state 的 peer profile/address/port records + 本地 MeshPolicy/LinkGroupSpec 推导 desired `TransportLinkSpec` 集合，监听 zone/delegation/revocation/ipsec profile/address/port/transport key/mesh policy/group/netns 变化
    - [x] 新增纯 planner：从 verified active state 的 `ipsec/profile`、`ipsec/addresses`、`ipsec/ports`、`ipsec/transport-key` 和本地 `LinkGroupSpec` 推导 desired `TransportLinkSpec`，并输出结构化 skip reason；daemon state-change hook 后续接入该 planner。
    - [x] planner 已实际消费 `LinkGroupSpec.ConnectRules` / `DenyRules`：zone glob/exact rule 可按远端 role intent、address family、address source、path mode、max_peers 选择 peer 并覆盖 group 默认值；deny 命中返回 `policy_denied`，connect 未命中返回 `policy_no_match`。`role/tag` target selector 已解析但暂不匹配，等待本地 peer label 来源接入。initiator role 推导不再使用 rule 的 `direction`。
    - [x] daemon state-change hook 已接入 dry-run reconcile：从 active state + 本地 `LinkGroupSpec` 生成 desired links，更新持久化 `LinkInstance`，记录 action/skip 摘要；真实 StrongSwan/XFRM driver 接入留到 4.3 系统 smoke。
    - [x] daemon `reload` control event 已重新读取 `config.yaml`，刷新本地 sync/log/IPsec overlay 配置，并触发一次 reconcile；`netns:`、`overlays:`、`connect/deny` 或 link group 删除会立即进入 create/update/teardown 判定。热 reload 明确拒绝切换 state DB/control socket 路径，避免运行中的 daemon 半路换库或迁移监听入口。
  - [x] 实现 reconcile loop：新增 link -> apply；spec 变化 -> update/reload；record 过期或 peer 不再可信 -> terminate/remove；driver 实际状态漂移 -> repair
    - [x] 新增可测试 reconcile 核心：对 desired spec、持久化 `LinkInstance`、driver SA 观测执行 create/update/adopt/repair/teardown 判定，并提供 `ApplyReconcileAction` 复用现有 StrongSwan/XFRM fake driver。
    - [x] daemon 侧新增第一版 dry-run reconcile loop：state 变化后执行 create/update/repair/teardown 的 fake apply plan，noop/adopt 不触发系统动作，并将最近 reconcile 结果落盘供 debug 使用。
    - [x] daemon 侧 teardown 成功后会从持久化 `LinkInstance` 集合移除对应实例；link group 被删除、peer record 过期或 peer 不再可信时，不会把 `removing` 状态遗留到下一轮反复 teardown。
  - [x] 设计状态机：`pending`、`configuring`、`connecting`、`up`、`degraded`、`stale`、`removing`、`down`、`error`
    - [x] daemon apply 成功后将 create/update/repair 的 `LinkInstance` 从 `configuring` 推进到 `connecting`，表示 StrongSwan/XFRM provider 配置已应用、正在等待 IKE_SA/CHILD_SA；后续 `ListSAs` 观测到匹配 SA 后才进入 `up`。
  - [x] 实现 role-only 角色规则：本节点 `role=out` 且远端 `role=in|both` 时主动拨远端；本节点 `role=in` 时只加载接收/trap 配置；双方 `role=both` 时使用稳定 tie-break（peer zone 字典序）避免重复主动拨号；首拨方长期失败后的对端接管策略拆到 Phase 4.5 设计和实现。旧的本地 `direction` 字段将彻底移除。
  - [x] 实现 path mode：`family-redundant` 每个地址族最多选择一条 ContactPoint（双栈时 IPv4 一条 + IPv6 一条）；`exhaustive` 尽量连接所有候选（调试/特殊高可用）；后续如需单条再引入 `preferred-only`，避免使用语义模糊的 `single-best`
  - [x] ContactPoint candidates 支持排序和回退：按 address source priority、address reachability、端口 generation、连接成功率、失败/backoff、IPv4/IPv6 策略综合排序；记录失败率和最近失败原因
    - [x] 已在纯 planner/model 层加入 `ContactPointQuality`：daemon 可按 peer/contact 注入 successes/failures/backoff/last_error，planner 生成的 `TransportLinkSpec` 会保留排序原因，并在 current 端口处于 backoff 时回退 previous grace 端口。
    - [x] daemon reconcile 侧已接线：`gossip.Transport.PeerAddrStates` 暴露 per-peer per-address 运行时质量，`DaemonService.buildIPsecContactPointQuality` 转换为 `LinkPlannerOptions.ContactPointQuality`，使 IPsec 地址排序复用 gossip 的成功/失败/backoff 数据。
  - [x] 明确 NAT 处理：NAT hint 只是节点自称，不作为安全事实；公网节点可接受 NAT 后节点主动拨入；主动拨入 NAT 后节点必须依赖 IPv6、端口映射、已验证 observed external port、打洞或后续 relay，不能仅凭 `behind_nat` hint 假装可达
    - `nat.hint=behind_nat` / `nat.inbound_reachable=false` 只表示远端自报“我大概率不能被公网直接拨入”，不能证明某个地址端口可用，也不能绕过 Zone trust chain、transport key、profile、revocation 和 IKEv2 认证。
    - “假装可达”指 planner 看到远端 `role=in` 或有 private/unknown 地址，就生成 outbound StrongSwan link，让公网节点反复拨 `192.168.x.x:4500`、CGNAT 反射地址或未验证端口；这种 link 应进入 skip/degraded，并在 debug 中说明缺少可拨入证据。
    - 第一版允许主动拨入 NAT 后节点的证据只包括：公开可路由 IPv6/公网地址、管理员明确配置的端口映射、reflector/discovery 产生且经本 Zone 签名发布的 observed external address/port、后续 hole punching/relay 成功路径；单独的 `behind_nat` hint 或 LAN/private 地址不算。
    - planner 应把 NAT 过滤放在 ContactPoint 选择之后、StrongSwan apply 之前：公网 inbound peer + NAT/outbound-only peer 由 NAT 节点主动拨公网 peer；公网 peer 反拨 NAT peer 时若无上述证据，返回结构化 skip/degraded reason，避免 daemon 无限重试不可达目标。
    - 已实现 planner 侧 `SkipNoInboundNATEvidence`：远端 `behind_nat` / `inbound_reachable=false` 时，只保留 public ContactPoint 或带 observed external port 的 `nat-observed` ContactPoint；只有 private/unknown 地址时不会生成 StrongSwan link。daemon debug/degraded 状态展示随后续 apply/reconcile 接线补齐。
  - [x] 处理幂等和并发：同一个 peer/group 的多次 state change 合并，apply 失败 backoff，daemon restart 后从 active state + 本地 LinkGroupSpec + 持久化 LinkInstance + StrongSwan/XFRM 实际状态恢复
    - [x] 第一版幂等骨架：同一 desired spec 再次 reconcile 时复用已落盘 `LinkInstance` 并进入 `noop`，避免 dry-run daemon 重复 create；真实 driver drift/backoff 仍待接入。
    - [x] apply 失败 backoff 已接入 `LinkInstance`：记录 failure count、backoff_until 和 last_error；backoff 未到期时 reconcile 返回 `noop/apply backoff active`，到期后 error/degraded link 重新进入 repair；daemon apply 成功会清理失败状态，失败会先落盘再返回错误。
    - [x] no-longer-desired teardown 也纳入幂等骨架：成功清理后删除本地实例，后续 state-change/restart reconcile 不会重复执行同一个 teardown action。
    - [x] daemon event drain 期间合并多次 state change：record/admin/remote apply 仍串行落盘，但同一轮事件队列只触发一次 IPsec `ListSAs` + reconcile/apply，避免同一个 peer/group 在短时间内重复加载 connection/interface。
    - [x] config reload 与 state-change 使用同一条 dirty/reconcile 路径：同一轮事件中的多次 reload/record/admin/remote apply 会合并为一次 IPsec reconcile；reload 失败不会触发 sync。
    - [x] `reconcile.interval` 已接入 daemon 主循环：存在 IPsec link group 时按最短 group interval 周期触发一次 `ListSAs` + reconcile，用于发现 strongSwan/XFRM/SA 等系统层漂移；没有 link group 但仍有残留 `LinkInstance` 时继续按默认 30s 巡检以重试 teardown；state-change/sync/reload 触发后会重置下一次周期巡检时间。
    - [x] VICI 操作增加可配置超时：普通 VICI call 默认 10s，避免调用挂起；`load-conn` 等操作在传入 context 无 deadline 时自动附加 timeout。
    - [x] `InitiateChild` 支持异步模式：默认通过独立 VICI client 在后台发起 `initiate`，不阻塞 reconcile 主路径；同一 CHILD_SA 的并发异步发起请求合并，避免重复触发。
    - [x] SA 建立引入宽限期：LinkInstance 进入 `connecting` 后，若已观测到部分 SA 状态或在 3 分钟建立宽限期内，reconcile 保持 noop 而非立即判定失败；宽限期过后仍未 established 才进入 repair/backoff。
    - [x] repair 路径主动重试 CHILD_SA 建立：`ApplyReconcileAction` 对 `ReconcileActionRepair` 在重新 `load-conn` + ensure XFRM 后显式调用 `InitiateTransportChild`，避免失败链路只反复更新 connection 而不重新发起。
  - [x] 定义 Photon 管理资源归属规则：StrongSwan connection/child、XFRM interface、地址、临时路由等必须能追溯到 `LinkGroupSpec` + `LinkInstance`；daemon 只自动修改/清理带 Photon owner 标记或命名约定且可验证归属的资源，避免误删管理员手工配置
    - [x] `LinkInstance.Owner` 记录 `manager=photon`、group、instance、transport id 和派生 owner token；reconcile 对不再 desired 的 persisted instance 先校验 owner 字段、token、`ipsec-*` transport id 与 `phx*` interface 命名，无法证明归属的资源保留为 noop，不自动 teardown。
    - [x] `ApplyReconcileAction` 对只有 `LinkInstance`、没有 desired spec 的 teardown 再执行 owner guard，防止 revocation/restart recovery 路径误删管理员手工 StrongSwan/XFRM 资源；旧状态无 token 时仍可凭 manager/group/instance/transport/name 匹配迁移。
  - [x] daemon 启动恢复时重建 link state：重新计算每个 link group 的 desired specs，读取持久化 `LinkInstance`，查询 driver 实际 connection/interface/SA；匹配则 adopt，缺失则 create，漂移则 repair，多余或已撤销则 teardown，保证重启后不会重复创建或遗留旧 link
    - [x] reconcile 核心已覆盖 adopt/create/repair/teardown 判定；daemon 持久化加载和 IPsec driver SA 查询已接入 state-change reconcile，真实 XFRM 实际状态观测仍待系统 driver 接入。
    - [x] daemon 已持久化加载/保存 `LinkInstance`，state-change reconcile 会基于已落盘实例重建 desired/current 对比；reconcile 已通过可注入 IPsec driver 查询 `ListSAs` 并可在重启后 adopt 已存在 SA，默认 daemon 仍使用 dry-run driver，真实 StrongSwan/XFRM apply 与 XFRM interface 观测留到 4.3 系统 smoke。
    - [x] daemon `Run` 启动进入主循环前会主动执行一次 IPsec reconcile：从当前 active state、本地 `LinkGroupSpec`、已持久化 `LinkInstance` 与 driver `ListSAs` 快照恢复 link state；已有 SA 会 adopt，缺失状态会进入 create/repair/noop/teardown 路径，不必等待下一次 record/reload 事件。
  - [x] 撤销优先级最高：peer Zone 或父 delegation tombstone 后，不等待普通 reconnect/backoff，立即 teardown link，并阻止 endpoint fallback、rekey 或 reconcile 重建
    - [x] reconcile 输入支持 revoked peer 集合；revocation 命中时即使 desired spec 仍存在也进入 `removing` 并产生 teardown action。
    - [x] planner 对 revoked peer 停止输出 desired spec；daemon 对已存在实例执行 owner-guarded teardown，成功后删除本地 `LinkInstance`，避免 endpoint fallback、rekey 或下一轮 reconcile 重新拉起。
  - [x] 暴露 control API/debug 输出：link 列表、desired vs actual、SA 状态、XFRM interface、`if_id`、endpoint、rekey/reconnect 原因、最近错误
    - [x] `daemon status` control response 增加 link instance 数、desired link 数和最近 reconcile error；新增 `photon debug links` 输出持久化 link、最近 action/skip、interface、`if_id`、endpoint、owner、failure count、backoff 与最近错误。
    - [x] daemon reconcile 摘要持久化最近 desired `TransportLinkSpec` 快照和 driver `ListSAs` 观测；`photon debug links` 会重新按当前 active state + `LinkGroupSpec` 规划 desired links，并与已落盘 `LinkInstance` / 最近 SA 快照并排展示 desired hash、actual hash、CHILD_SA、SA endpoint、backoff 和 apply error，便于排查“应该建什么”和“实际 StrongSwan 看到什么”的差异。
  - [x] 增加 fake driver 单元测试：create/update/delete/revoke/restart recovery；真实 StrongSwan/XFRM smoke 留到 4.3

- [x] **4.2.x role-only initiator model（消除双 initiator race）**
  - 目标：彻底移除 MeshPolicy / connect rule / link group 中的 `direction`，本节点角色仅由 `ipsec.role` 与远端 `role` 决定，避免 `direction=double` + `role=in` 导致的双端同时主动拨号。
  - 配置：
    - 新增顶层 `ipsec.role`，可选 `out` / `in` / `both`，默认 `both`。
    - 从 `MeshPolicyRule`、`LinkGroupSpec`、`TransportLinkSpec` 中删除 `Direction` 字段；connect URL 不再解析 `direction`。
    - 旧配置或 rule 中若仍出现 `direction` 或旧 `accept` query，加载时报错（建议改为 `ipsec.role` / `role=...`）。
  - 角色推导：
    - 本节点 `role=out` + 远端 `role=in|both` → `primary`（主动拨）。
    - 本节点 `role=in` → 不主动拨，initiator role 为空，生成 responder/trap 配置。
    - 双方 `role=both` → 用 peer zone 字典序 tie-break，小的一方 `primary`，大的一方 `secondary-standby`；失败后可按 4.5 接管。
    - 本节点 `role=both` + 远端 `role=out` → 加载 responder/trap，等待远端拨入。
  - StrongSwan 渲染：
    - `primary` / `secondary-takeover` 设置 `start_action=start`（或按需 initiate）。
    - 非主动 role 设置 `start_action=trap` 或仅 responder，不主动发起 CHILD_SA。
  - IPsec record 公告：
    - `app/photon/ipsec_publish.go` 把本地 `ipsec.role` 写入 `ProfileRecord.Role`，不再硬编码本机角色。
  - NAT reachability hint 保守化（同一次改造顺带修复）：
    - `localIPsecNATProfile` 不能仅凭存在 public address 就标记 `inbound_reachable=true`；只有管理员显式声明或 reflector/observed 证据才标记 reachable，默认 `unknown`。
  - 测试：
    - planner 角色矩阵单测覆盖全部 role 组合。
    - config 解析单测：合法 `ipsec.role`、非法值、旧 `direction` / `accept` query 报错。
    - StrongSwan `BuildStrongSwanConnection` 单测：主动 role 生成 `start_action=start`，非主动 role 生成 `start_action=trap`。
    - dry-run smoke：A/B 配置不同 role 时只由应主动的一侧生成 initiate action。

- [x] **4.2.y IPv4/IPv6 双链路实现（family-redundant 真正双栈）**
  - 目标：`family-redundant` 模式下，两个双栈节点之间同时存在一条 IPv4 link 和一条 IPv6 link，地址族级冗余。
  - 当前限制：
    - `BuildStrongSwanConnection` 只取首个 ContactPoint，`max_links_per_peer` 未实现，双栈节点之间只有一条 link。
  - 实现要点：
    - `SelectContactPointsWithOptions(family-redundant)` 按 family 分组，返回每个 family 最高排序 ContactPoint。
    - `PlanTransportLinks` 为每个可用 family 生成独立 `TransportLinkSpec`。
    - `TransportLinkSpec.TransportID` 引入 family/link index 派生，例如 `StableTransportID(local, peer, overlayID, family)`。
    - 每个 spec 拥有独立 XFRM `if_id` 和 interface name（如 `phx<hash_v4>` 和 `phx<hash_v6>`），15 字符限制内处理冲突。
    - `ReconcileLinkInstances` 按 `TransportID` 而不是按 peer 匹配 desired/current；每个 link 有独立 `LinkInstance`、generation、rotate phase 和 takeover 状态。
    - 防火墙规则继续按 interface pattern（`phx*`）匹配多个 XFRM interface；overlay 链的 forward/input 规则覆盖所有 link interface。
    - BIRD/Babel 在多个 `phx*` interface 上发现同一 peer 的多个邻居；ECMP 或 metric preference 由 Phase 5 路由层处理，但 IPsec reconcile 必须能独立管理每个 link。
  - 边界：
    - `max_links_per_peer` 继续保留语义，但 Phase 4 先实现 family-redundant 两条；超出 family 数量的候选仍丢弃。
    - IPv4/IPv6 共享同一组 ports record；未来可扩展为 per-family ports，但不在本次改造。
  - 测试：
    - planner 单测：双栈 peer 在 `family-redundant` 下生成 IPv4 + IPv6 两条 spec；单栈 peer 只生成一条。
    - 稳定 ID 单测：同一 peer、不同 family 的 `TransportID`/`if_id`/interface name 不同；重启后不变。
    - reconcile 单测：按 `TransportID` 独立 create/adopt/teardown，删除一条 family link 不影响另一条。
    - dry-run smoke：双栈 A/B 之间 desired links 包含 4 条（每对节点 2 条），并能独立解释每条 skip reason。

- [x] **4.3 最小闭环验证**
  - [x] 增加 `make ipsec-policy-smoke`：不要求 root/StrongSwan/XFRM，验证 URI rule/link group + 远端 role intent + address/port 分离公告能自动选择匹配 peer，不需要手写每个 link
    - 已新增 `ipsec-policy-smoke` 并纳入 `smoke-all`；覆盖 MeshPolicy URI 解析、connect/deny rule 接入 planner、role intent 过滤、source 过滤，以及从 address/port 分离公告生成匹配 `TransportLinkSpec`。
  - [x] 增加 `make ipsec-dry-run-smoke`：不要求 root/StrongSwan/XFRM，使用 fake driver 验证 A/B 同步后能从 link group + active state 推导出对称 `TransportLinkSpec`、稳定 `if_id`/interface name、Ed25519/ECDSA transport key record、AddressCandidate/PortAdvertisement/ContactPoint 组合结果和 expected VICI/XFRM apply plan
    - 当前 smoke 运行 `pkg/transport/ipsec` 的纯 Go 覆盖：active state planner、ContactPoint selection、LinkInstance reconcile create/adopt/repair/teardown/revoke、VICI/XFRM apply plan 和 transport key record；daemon 测试已补 A/B dry-run 闭环，覆盖双方从 link group + active state 规划 peer link、加载 StrongSwan connection、创建 XFRM interface、分配 tunnel address，并通过模拟 `ListSAs` 观测进入 `up`。
  - [x] dry-run 覆盖双栈多地址：两个双栈 peer 在 `family-redundant` 下最多产生 IPv4/IPv6 各一条 ContactPoint，在 `exhaustive` 下产生所有允许来源的组合，并能解释未选候选的原因
    - 已补 planner dry-run 测试：同一 peer 发布多条 IPv4/IPv6 地址时，`family-redundant` 只保留每个 family 的最高排序 ContactPoint，`exhaustive` 保留所有候选；每个 ContactPoint 携带 `RankReason` 便于 debug 展示。
  - [x] dry-run 覆盖端口轮换：peer 发布 current + previous grace 端口时优先 current，current 失败可在 grace 内回退 previous；grace 过期后不再尝试旧端口
    - 已有端口规划/ContactPoint 测试覆盖 current + previous grace、过期 previous 剔除、current 处于 backoff 时回退 previous；planner dry-run 测试继续覆盖质量输入后的 fallback 排序。
  - [x] dry-run 覆盖 DNS refresh：manual-dns record 保留域名，运行时解析 A/AAAA；DNS 变化后 planner 重新生成 ContactPoint 并触发 reconcile update
    - 已补 planner dry-run 测试：manual-dns record 保留 host，DNS resolver 返回变化后重新生成 ContactPoint 地址，同时 `TransportID` / `XFRMIfID` 保持稳定，后续 daemon reconcile 可据 spec hash/contact 变化触发 update。
  - [x] dry-run 覆盖 NAT：公网 inbound peer + NAT outbound peer 可建 outbound initiated link；两个都 `behind_nat` 且无 IPv6/port mapping/observed reachable port 时进入 degraded，并在 debug 中给出不可达原因
    - 已补 planner dry-run 测试：NAT 后本地节点可主动规划到公网 inbound peer；反向拨入 `behind_nat` 且只有 private/unknown ContactPoint 的 peer 会返回 `no_inbound_nat_evidence`，带 observed external port 的 `nat-observed` ContactPoint 则允许规划。daemon debug/degraded 展示留到 control/apply 接线。
  - [x] 增加真实环境前置检查命令：检测 Linux、root 或 `CAP_NET_ADMIN`、VICI socket/`charon`、XFRM interface 支持、`ip`/`swanctl` 可用性；缺失时给出明确 skip/error，而不是半途留下 connection/interface
    - 已增加 `make ipsec-xfrm-preflight` 与 `docs/strongswan-xfrm-test.md`，真实 `ipsec-xfrm-smoke` 仍保持显式 root/system integration 目标，默认不纳入 `smoke-all`。
  - [x] 增加 `make ipsec-xfrm-smoke`：在支持 root network namespace 的 Linux 主机上启动两个 Photon daemon、两个 isolated test namespace/配置目录，完成 root/delegation/join、gossip 同步、link group/netns 配置和 transport key record 发布
    - [x] 已增加显式 `make ipsec-xfrm-smoke` 系统集成入口，默认不纳入 `smoke-all`；运行时先执行 preflight，再用 `PHOTON_IPSEC_XFRM_SMOKE=1` 跑真实 `SystemXFRMDriver` named netns / XFRM interface / address / delete lifecycle 测试，失败时输出 netns、XFRM state/policy、link 和 `swanctl --list-sas` 诊断。
    - [x] root/system smoke 不再只停留在非 root dry-run：`make ipsec-xfrm-smoke` 必须作为显式 privileged 目标运行，测试机器可用 `sudo make ipsec-xfrm-smoke`、root VM，或具备 netns/XFRM 所需 capability 的 privileged container；默认 `make check` / `smoke-all` 仍不要求 root。
    - [x] 增加 `make ipsec-xfrm-container-smoke`：自动启动 privileged Ubuntu container、挂载当前 repo、复用已构建的本地 smoke 镜像和 Go cache volume、启动 charon 后运行 `make ipsec-xfrm-smoke`，避免每次重新 apt install / 下载 Go module；文档明确 NixOS over LXC、CI nested container 等外层受限环境即使内层 Docker 使用 `--privileged` 也可能被外层拦截，preflight 必须以真实 named netns create/delete、XFRM interface 和 VICI socket 能力检查为准。
    - [x] 增加 root-gated 双 namespace XFRM 数据面基座：创建 `ns-a/ns-b`、veth underlay、两端 XFRM interface、tunnel address、手工 XFRM state/policy，并验证 A/B tunnel IP ping；这一步先证明宿主权限、kernel XFRM interface、named netns 内 interface create、route-based dataplane 都可用。
    - [x] `SystemXFRMDriver` smoke 已改为在目标 named netns 内直接创建 XFRM interface，并同步容器脚本中的 nested netns wrapper，减少 privileged container/LXC 环境中 host-side link move 失败导致的误判；完整 daemon/VICI IKE bring-up 仍由下一条未完成项跟踪。
    - [x] 已将 XFRM interface/address apply 接到 Photon daemon reconcile：root-gated `app/photon` smoke 使用真实 `SystemXFRMDriver` 由 daemon 创建 named netns 内的 XFRM interface、分配 tunnel host prefix，并在 link group 删除后通过 daemon teardown 清理 interface；当前仍用 dry-run IPsec driver，IKE_SA/CHILD_SA 与 XFRM state 仍待 StrongSwan/VICI bring-up 接入。
    - [x] 已接入真实 govici 客户端边界：`GoviciClient` 使用 `github.com/strongswan/govici/vici` 连接 charon VICI socket，把现有 `StrongSwanDriver` 的 `load-conn` / `terminate` / `unload-conn` / streaming `list-sas` map 结构转换为 VICI message；单测覆盖 `load-conn` 嵌套 message 与 `list-sas` 事件解析，为后续系统 smoke 从 fake IPsec driver 切到真实 VICI driver 做准备。
    - [x] daemon 已支持通过 `config.yaml` 显式选择真实 StrongSwan/XFRM provider：默认 `ipsec.driver: dry-run` 保持非 root/无 charon 环境可运行；设置 `ipsec.driver: strongswan` 时启动或 `reload` 会创建真实 `GoviciClient` 和 `SystemXFRMDriver`，`ipsec.vici_socket` 可覆盖 charon VICI socket，连接失败会在启动/reload 阶段明确报错。
    - [x] daemon 已能在配置了 `overlays:` / link group 后自动发布本节点 signed `ipsec/profile`、`ipsec/addresses`、`ipsec/ports`、`ipsec/transport-key` records：transport key 独立于 Zone signing key 并持久化到本地 state meta，重复发布不会抖动 fingerprint 或 record version；地址使用本机 `advertise_addrs` / `listen_addr` 派生，端口使用当前 fixed IKE/NAT-T 边界。
    - [x] StrongSwan connection 渲染对齐 NAT-T server-port 语义：当 ContactPoint 携带自定义 NAT-T advertised/observed 端口时，`remote_port` 写入 NAT-T 端口并保持 `encap=yes`，`local_port=4500`，使初始 IKE 包走 NAT-T socket/non-ESP marker 路径；固定 500/4500 场景仍兼容。
    - [x] VICI `load-conn` 调用增加结构化 debug 日志，自动脱敏 `pubkeys`/`privkey`/`data` 等敏感字段，便于对比 provider config 与 charon log。
    - [x] 增加普通 Go 覆盖：两个 daemon 使用真实 root -> `catofes.` -> `node-a`/`node-b` 信任链，各自自动发布 signed `ipsec/*` records，经 UDP gossip 同步对端 Zone 后，从 verified active state + 本地 `LinkGroupSpec` 推导对端 `TransportLinkSpec` 并执行 dry-run apply；该测试证明完整 daemon publish/gossip/planner/reconcile 边界已闭合，但仍不触碰 root XFRM 或真实 VICI/IKE。
    - [x] 增加真实 StrongSwan/VICI driver 层 IKE bring-up 测试：`TestStrongSwanDriverIKEBringupSmoke` 在单测中启动两个隔离 charon 实例、两个 named netns、veth underlay、XFRM interface、tunnel address，通过 VICI `load-key`/`load-conn` 加载 Ed25519/ECDSA raw-public-key 认证与 connection，验证 IKE_SA/CHILD_SA 建立成功及 A/B tunnel IP 双向 `ping` 通；`TestStrongSwanDriverLoadsKeyAndConnection` 验证 VICI 公私钥加载与 `load-conn` 消息构造。该测试位于 driver 层，不经过完整 daemon/gossip，但证明 StrongSwan/XFRM/VICI 数据面闭环已打通。
    - [x] 增加真实 daemon reconcile + StrongSwan/VICI + XFRM bring-up 测试：`TestDaemonStrongSwanReconcileBringupSmoke` 在 root/container smoke 中启动两个 named netns、两个隔离 charon/VICI 实例和 veth underlay，构造已验证的 root -> `catofes.` -> `node-a`/`node-b` active state 与 signed `ipsec/*` records，让两个 daemon service 通过真实 `StrongSwanDriver` + `SystemXFRMDriver` 自动加载 private key/connection、创建 XFRM interface、分配 tunnel address、观测 VICI `list-sas` 后把 `LinkInstance` 推进到 `up`，并验证 A/B tunnel IP 双向 `ping` 通。
    - [x] 扩展真实 daemon reconcile smoke 的恢复/撤销段：同一 charon/XFRM 实例保持运行时重建 node-a daemon service，启动 reconcile 必须通过 VICI `ListSAs` 观测已有 SA、保持唯一 established SA，并继续 tunnel ping；已有 `up` 实例可保持 noop，缺失/旧状态才 adopt/repair；随后注入父 Zone 对 `node-b.catofes.` 的 revocation，daemon 必须 terminate/unload、删除 XFRM interface、清空 `LinkInstance`、输出 revoked skip reason，且 tunnel ping 失败。
    - [x] 修正 planner tunnel address 分配：同一 peer pair 独立规划时按 Zone 字典序稳定镜像 tunnel IP，避免 A/B 两端都把 pool 第一个地址当 local；新增 planner 回归测试锁住 A local/B peer 与 B local/A peer 互为镜像。
    - [x] 增加 daemon `Run` 循环级 root/container smoke：`TestDaemonRunGossipStrongSwanBringupSmoke` 启动两个 daemon service、两个 isolated named netns、两个隔离 charon/VICI 实例和 veth underlay；两端各自自动发布 signed `ipsec/profile`、`ipsec/addresses`、`ipsec/ports`、`ipsec/transport-key` records，经 UDP gossip 同步对端 Zone 后，从 verified active state 自动触发真实 `StrongSwanDriver` + `SystemXFRMDriver` reconcile，观测 VICI `list-sas` 后把 `LinkInstance` 推进到 `up`，并验证 A/B tunnel IP 双向 `ping`。该 smoke 使用真实 daemon service 主循环，但还不是外部 `build/photon daemon` OS 进程。
    - [x] 4.3 最小闭环以 Go 测试内 daemon service 为系统边界完成；外部 `build/photon daemon` 双 OS 进程、进程重启和 gossip revocation 传播保留到 Phase 7.8 daemon 生产化/hardening，不再阻塞 StrongSwan/XFRM 最小链路闭环。
    - [x] 在 root smoke 中补齐权限说明和失败分层：`CAP_NET_ADMIN` 覆盖 XFRM/link 操作，named netns 通常还需要 root 或 `CAP_SYS_ADMIN`/privileged container，VICI socket 还取决于 charon/swanctl 的本机访问权限；preflight 必须在资源创建前给出明确失败。
  - [x] smoke 断言 daemon 自动为对方加载 StrongSwan connection/secret，创建 XFRM interface，分配本地/远端 tunnel address，并在 debug 输出中显示 `LinkInstance` 从 `pending/configuring/connecting` 进入 `up`
    - [x] daemon 状态机已区分 provider apply 成功后的 `connecting` 与 driver SA 观测后的 `up`；新增 daemon A/B dry-run 测试断言 connection/interface/address apply、SA snapshot adopt、`photon debug links` 中的 `state=up`、identity、reqid 与 endpoint 字段；root-gated system smoke 已断言 daemon 使用真实 `SystemXFRMDriver` 创建/清理 XFRM interface 和 tunnel address。
    - [x] daemon-level root smoke 已把真实 `load-key`/`load-conn`/XFRM interface/address 接到 daemon reconcile，并通过 dual-charon VICI SA 观测把 `LinkInstance` 推进到 `up`；完整 CLI daemon 进程 + gossip 入口仍待后续扩展。
    - [x] daemon run smoke 已覆盖自动发布 `ipsec/*` records、UDP gossip 同步、真实 StrongSwan/VICI + XFRM apply、`LinkInstance=up` 和 tunnel ping；仍保留 CLI OS 进程化验证作为可选加严项。
  - [x] smoke 使用 VICI/`swanctl --list-sas` 双重观测 IKE_SA/CHILD_SA：断言 peer identity、CHILD_SA name、reqid/if_id、local/remote endpoint 与 `TransportLinkSpec` 一致
    - [x] VICI `list-sas` 解析与 daemon reconcile snapshot 已携带 local/remote identity、local/remote endpoint、CHILD_SA name、reqid 和 XFRM if_id；`debug links` 会展示这些字段。
    - [x] govici streaming `list-sas` 客户端适配已落地，避免用 `swanctl` 输出解析作为 daemon 核心控制面；driver 层 `TestStrongSwanDriverIKEBringupSmoke` 和 daemon-level `TestDaemonStrongSwanReconcileBringupSmoke` 都通过 VICI streaming `list-sas` 观测到 IKE_SA/CHILD_SA 并断言 identity/if_id/child 字段；`swanctl --list-sas` 保留为失败诊断/人工对照。
    - [x] root smoke 失败诊断统一输出 netns、host XFRM link/state/policy 和 `swanctl --list-sas`；daemon run smoke 在测试内额外输出 charon log、每个 namespace 的 link/address/route/XFRM state/policy，便于交叉核对 VICI snapshot 与系统实际状态。
  - [x] driver 层 smoke 验证数据面：A/B 通过 tunnel IP 互相 `ping` 成功；`TestStrongSwanDriverIKEBringupSmoke` 失败时输出 charon log、VICI SA 列表、`ip link`、`ip xfrm state/policy` 和 namespace 信息。
  - [x] smoke 验证 daemon 级数据面：双 Photon daemon 同步后 A/B 通过 tunnel IP 互相 `ping` 成功；抓取失败时输出 daemon log、VICI SA 列表、`ip link`、`ip xfrm state/policy`、`ip route` 和 namespace 信息
    - [x] root/container smoke 已覆盖 daemon reconcile 级数据面：两个 daemon service 基于已验证 active state 使用真实 VICI/XFRM 建链并完成 A/B tunnel IP 双向 `ping`；失败时输出 charon log、VICI/swanctl、netns、link、route、XFRM state/policy 诊断。完整双 `photon daemon` 进程 + gossip 同步后的同一断言仍保留为后续项。
    - [x] root/container smoke 已扩展到 daemon `Run` 循环级：双方自动发布并 gossip 同步 `ipsec/*` records 后真实建链、进入 `up` 并双向 tunnel ping；失败时保留 charon log、VICI/swanctl 和 namespace 诊断。外部 CLI `build/photon daemon` 进程级 smoke 仍可作为后续 hardening，但不再阻塞 4.3 最小闭环。
  - [x] 覆盖 daemon 级重启恢复：停止并重启任一 daemon 后，daemon 从 active state + StrongSwan/XFRM 实际状态恢复或 repair，最终仍只有一组有效 connection/interface/SA，tunnel ping 恢复
    - [x] daemon dry-run 已覆盖启动恢复：已有 SA 时 adopt 为 `up`，已有 `LinkInstance` 但 driver SA 缺失时进入 repair 并重新执行 connection/interface/address apply；driver 层真实 StrongSwan/XFRM 测试已验证首次 bring-up 后 tunnel ping；root/container daemon-level smoke 已验证重启后唯一 connection/interface/SA 和 tunnel ping。
    - [x] root/container smoke 已覆盖真实 daemon service 重启恢复：保留 charon/VICI/XFRM 运行态，重建 daemon service 后启动 reconcile 观测现有 IKE_SA/CHILD_SA，已有 `up` 状态保持 noop，缺失/旧状态走 adopt/repair；断言 established SA 仍只有一组并且 tunnel ping 恢复。外部 `build/photon daemon` OS 进程重启仍作为后续 hardening。
  - [x] 覆盖撤销闭环：父 Zone 签发 peer revocation 后，远端 daemon 收敛并立即 teardown IKE_SA/CHILD_SA、删除 XFRM interface/地址/临时路由，清空 `LinkInstance`，tunnel ping 失败且不会被 reconnect/backoff 拉起
    - [x] daemon dry-run 已覆盖 revocation 后 planner 不再输出 desired link、reconcile 执行 terminate/unload/delete interface、清空 `LinkInstance`，下一轮不会因 backoff/reconnect 重建；driver 层真实 StrongSwan/XFRM 测试已验证 teardown 后 interface/address 清理；root/container daemon-level smoke 已验证 IKE_SA/CHILD_SA 终止和 ping 失败断言。
    - [x] root/container smoke 已覆盖真实 daemon service 撤销：注入父 Zone revocation 后 planner 输出 `revoked_zone` skip，reconcile terminate/unload/delete XFRM interface，清空 `LinkInstance`，VICI 不再观测到该 SA，tunnel ping 失败。当前断言针对一端撤销收敛，完整双外部 daemon 进程 gossip revocation 传播仍作为后续 hardening。
  - [x] 明确该 smoke 不覆盖 Phase 5 多前缀路由授权；只验证 peer-to-peer tunnel address 和 route-based VPN link 可用
    - [x] `docs/strongswan-xfrm-test.md` 和 `docs/design.md` 均保持边界：Phase 4 smoke 只证明 route-based peer tunnel link、VICI/SA 观测和 tunnel IP ping，不验证 Babel、多前缀 route authorization 或 import/export policy。
  - [x] 将真实 StrongSwan/XFRM smoke 默认排除在 `make smoke-all` 之外，作为显式 root/system integration 目标；`ipsec-dry-run-smoke` 可纳入常规 `make check` 或 smoke-all

- [x] **4.3.1 派生式 tunnel/link-local 地址分配**
  - 目标：把当前 `tunnel_address_pool` 顺序分配升级为确定性地址派生，避免各节点手工配置或独立顺序规划导致 tunnel address 冲突；tunnel address 只表达每条 peer-to-peer tunnel link 的邻接地址，不作为节点身份或业务前缀，业务前缀仍由 Phase 5 Babel / route authorization 协商和过滤。
  - [x] 先定配置形状并保留兼容：
    - 新增结构化配置 `overlays[].tunnel_address`，字段包含 `mode`、`family`、`pool`；合法 mode 为 `derived-link-local`、`derived-pool`、`sequential-pool`、`disabled`。
    - `config.example.yaml` 默认改为 IPv6 `derived-link-local`，不再展示 `fd00:1234::/64` 作为默认；IPv4 默认 `disabled`。
    - 旧字段 `tunnel_address_pool` 继续接受，明确映射为 `sequential-pool` 兼容模式；二者同时出现时配置加载报错。
    - 文档说明 `sequential-pool` 只用于测试、迁移和排障。
  - [x] 扩展内部模型：
    - 在 `LinkGroupSpec` 中加入 `TunnelAddressSpec`，表达 mode、family、pool；保留 `TunnelAddressPool` 作为过渡字段。
    - `TransportLinkSpec` 继续携带本地/远端 tunnel address；`FormatScopedTunnelAddress` / `debug links` 输出 scoped link-local 地址。
    - `ApplyPlan` / `debug links` 输出 link-local 地址时显示 interface scope，例如 `fe80::...%phxxxxx`。
  - [x] 实现确定性派生函数：
    - 新增 `DeriveTunnelAddresses(local, peer, group, linkIndex)`，使用项目已有 `photoncrypto.Hash` 做稳定派生。
    - hash 输入包含 group ID、按字典序排序的 peer pair、端点 role（lower/higher）、address family、address mode、provider/link index；A/B 两端独立规划得到镜像地址。
    - IPv6 `derived-link-local` 固定使用 `fe80::/64`，派生 interface-id 并过滤不可用结果。
    - IPv6/IPv4 `derived-pool` 从配置 prefix 内派生 host bits，过滤 network/broadcast/全 0/全 1 host。
    - `sequential-pool` 保留 `pool + (linkIndex*2+1/2)` 行为作为 legacy 路径。
  - [x] 接入 planner/reconcile/apply：
    - `NewTransportLinkSpecForGroup` 默认走 `DeriveTunnelAddresses`；legacy sequential mode 走旧顺序逻辑。
    - StrongSwan `BuildLoadConnMessage` 仍只根据 tunnel address family 选择宽泛 selector（IPv4 `0.0.0.0/0`、IPv6 `::/0`）。
    - XFRM interface 在 up 前设置 `addrgenmode none`，避免内核自动派生随机 link-local；`AssignAddress` 对 IPv6 link-local 使用 `/64`，peer route/selector 仍按对端 `/128` 精确匹配。
    - `photon debug links` 展示 scoped local/remote tunnel address。
  - 验证：
    - [x] config 单测：新结构化配置、旧 `tunnel_address_pool` 兼容、同时配置冲突、非法 mode/family/prefix、IPv4 默认 disabled 都有断言。
    - [x] planner 单测：A/B 镜像、不同 overlay/provider/link index 地址不同、IPv6 link-local 落在 `fe80::/64`、IPv4 derived-pool 落在 pool 且避开不可用 host。
    - [x] dry-run 测试：`ApplyPlan` / `debug links` 显示 scoped link-local address；sequential pool 仍输出旧式地址。
    - [x] root smoke：link-local 模式 XFRM interface 分配 scoped tunnel address，`ping6`/`route` 显式带 interface；新增 `TestDaemonStrongSwanReconcileBringupDerivedPoolSmoke` 覆盖 IPv4 derived-pool。

- [x] **4.3.2 host-born XFRM interface / 内嵌 VICI event 生命周期**
  - 目标：借鉴 `swan-updown` 的关键原理，但不依赖外部 updown script；由 Photon daemon 内嵌管理 StrongSwan CHILD_SA 与 XFRM interface 生命周期。设计稿已落地并并入 `docs/new/transport-ipsec.md` 的 XFRM interface 生命周期章节；原 `docs/strongswan-xfrm-netns-lifecycle-design.md` 已删除。
  - 修正 namespace 模型：单 host charon 负责 IKE/NAT-T、VICI、XFRM state/policy；XFRM interface 必须先在 charon/state/policy 所在 host netns 创建，再 move 到 `TransportLinkSpec.NetNS` / overlay netns，地址和 BIRD/Babel 继续在 overlay netns 内配置。
  - 更新 `SystemXFRMDriver.EnsureInterface`：named netns 目标下改为 host `ip link add <iface> type xfrm if_id <id>` -> `ip link set <iface> netns <target>` -> target netns `ip link set dev <iface> up`；已有目标 netns interface 直接 adopt/up，已有 host 残留则 move 后 adopt。
  - 保持 `ApplyTransportLink` 高层顺序不变：ensure namespace -> load key -> load connection -> ensure interface -> assign address；变化只在真实 XFRM driver 的 interface 出生点和 move 语义。
  - 第一版仍由 reconcile 驱动；daemon 已订阅 VICI `child-updown` / `ike-updown` 事件缩短收敛延迟。event handler 只把 IPsec 标记为 dirty 并进入同一套幂等 reconcile，不能绕过 desired spec、`LinkInstance` owner guard、revocation 和 restart recovery。
  - 删除/恢复语义：teardown 优先从目标 overlay netns 删除 owner-managed interface，找不到时清 host 残留；daemon restart 后从 desired spec + `ListSAs` + link inspection adopt/move 既有 interface；revocation/policy deny/transport key mismatch 仍强制 terminate/unload/delete，且不能被 retry 拉起。
  - staged rotate 语义：base/staged generation 都使用独立 host-born XFRM interface/`if_id`，move 到同一 overlay netns 后交给 Babel metric/cutover gate；rollback 只清 staged，revocation 同时清 base/staged。
  - 验证：
    - [x] 单元测试锁住 `SystemXFRMDriver` 命令顺序和 adopt/move 分支。
    - [x] preflight 增加 host-born XFRM interface move 到 named netns 能力检查。
    - [x] root/container smoke 覆盖 host XFRM state/policy + moved XFRM interface in overlay netns + tunnel ping。
    - [x] daemon StrongSwan smoke 失败诊断输出 host `ip xfrm state/policy`、host XFRM links、overlay netns link/address/route。
    - [x] VICI event 阶段补 fake event 单测和 daemon event-loop coalesce 测试，确认 event 只触发幂等 reconcile，不形成第二 writer。

- [x] **4.4 有界短断端口轮换 / 低频 rotate（生产必需基座）**
  - 目标：把 `ipsec/ports` 的 current/previous grace 从“公告和 planner fallback”推进到系统可执行、可观测、可回滚的低频 rotate，支持运营商 QoS、端口迁移、NAT 映射变化和维护窗口中的受控重建；高频/对抗性 port hopping 仍留到 Phase 7。
  - 明确当前边界：现在 `PlanPortRecord` 会发布 current + previous grace，peer planner 会在 current 失败/backoff 时回退 previous；StrongSwan/XFRM 系统路径选择的是 **bounded break-before-make**，`prepare_rotate` 会先 terminate/unload 旧 SA/connection，再加载并发起 staged connection，因此切换窗口内会出现短暂数据面中断。即使上层有 BIRD 兜底，这也只能算“有界短断/可控重建”，不能称为真正平滑过渡。
  - [x] 先做方案裁剪：
    - [x] Phase 4.4 首选实现 **staged reestablish over VICI**：对远端 current/previous ContactPoint 分别生成可审计 staged connection/action，先让新端口建立 SA，确认 `ListSAs` 后再清理旧 connection。理由：不引入 nftables/iptables ownership 和部署依赖，先把 StrongSwan/VICI 边界做完整。
    - [x] 外层 DNAT/redirect grace 延后为 Phase 6/7 防火墙集成：charon 保持稳定监听端口，nftables/iptables 把新旧 advertised 端口转发到当前 charon 端口；适合生产部署，但需要独立 owner token、规则恢复和 root 权限设计。
    - [x] 多 charon/socket 实例暂不实现，只保留为极端部署选项；除非 staged reestablish 无法满足，否则不要把 namespace/secret/VICI 管理复杂度提前引入。
  - [x] 扩展状态模型：
    - [x] `LinkInstance` 增加 selected contact、remote port generation、rotation phase（`idle`、`preparing`、`testing_new`、`cutover`、`rollback`、`cleanup`）、staged ike/child name、rollback deadline、last rotate error。本地 port generation 通过持久化 `IPsecPortRecord` 跟踪。
    - [x] staged connection 通过 `rotateSpec` 从 desired spec 派生，使用独立 transport id；`TransportLinkSpecHash` 继续表示期望状态，旋转由 generation 变化触发而不是被误识别为普通 update。
    - [x] `photon debug links` 显示 rotate phase、remote/staged generation、staged ike name、rotate deadline、last error。
  - [x] 扩展 planner/reconcile：
    - [x] 当远端 `ipsec/ports` generation 变化时，reconcile 进入 rotation 状态机而不是直接 update/tear down 旧 SA。
    - [x] reconcile 在 `idle -> preparing` 阶段加载新 connection/child，但保留旧 connection/SA；`testing_new` 阶段观察新 SA 是否 established；成功后进入 `cutover`（卸载旧 connection），失败则进入 `rollback` 并继续使用 previous。
    - [x] 如果 staged SA 在 deadline 前未建立，回滚并进入 backoff，避免无限重试。
    - [x] daemon 重启时从持久化 `LinkInstance` + 当前 `ipsec/ports` + `ListSAs` 恢复 rotate phase；staged SA 已存在则直接 commit，stale staged generation 则 cleanup。
  - [x] 明确命名和 owner 规则：
    - [x] staged connection/child 名称稳定可推导：`RotateConnectionName(transportID, generation)` / `RotateChildSAName(transportID, generation)`。
    - [x] teardown 对 Photon owner 匹配的实例执行；旋转清理只终止/卸载 staged connection，不删除共享的 XFRM interface/address。
    - [x] revocation/policy deny/transport key mismatch 仍走强制 teardown，不进入 rotate 状态机。
  - [x] 失败与回滚边界：
    - [x] staged SA 未在 deadline 内建立则 rollback，记录错误并进入 backoff。
    - [x] prepare rotate 复用已加载的本地 private key，不重复 load-key，避免 rollback 后遗留 staged key。
    - [x] commit rotate 只卸载旧 connection，保留新 SA 和共享 interface。
  - 验证：
    - [x] dry-run：`ApplyReconcileAction` 对 `prepare_rotate` 不加载 private key；`commit_rotate` 只 terminate/unload 旧 connection、不删 interface。
    - [x] reconcile 单测：prepare、commit、rollback、stale cleanup、restart recovery 路径覆盖。
    - [x] app 单测：`publishIPsecRecords` 按 `port_rotate_interval` 自动推进 generation，并保留 previous grace。
    - [x] 配置单测：`ipsec.port_mode` / `port_range` / `port_rotate_interval` / `port_previous_grace` 解析与校验。
    - [x] daemon 级单测：`notifyStateChanged` 触发 reconcile 后生成 `prepare_rotate`，`LinkInstance` 正确记录 staged generation/ike name。
    - [x] root smoke：已选择 B) bounded break-before-make 作为 Phase 4.4 可执行系统路径：`prepare_rotate` 先终止旧 SA，再加载/发起 staged connection，下一轮 observe 到新 SA 后 commit 清理旧 connection，并通过 tunnel ping 验证恢复；`TestDaemonStrongSwanPortRotationSmoke` 已接入 `make ipsec-xfrm-smoke` / `make ipsec-xfrm-container-smoke`，并在 privileged container 中完成复验。该验证证明的是 deadline/backoff/rollback 管理下的短断恢复，不是 zero-downtime rotate。
    - [x] container smoke 全量回归：`TestDaemonStrongSwanPortRotationSmoke` 通过；`TestSystemXFRMDriverPeerTunnelPingSmoke` 因容器/LXC 内 IPv6/xfrm 邻居解析限制失败，判定为与 4.4 无关的既有环境问题，已在容器 smoke 中通过 `PHOTON_IPSEC_XFRM_SMOKE_CONTAINER=1` 跳过该用例，其余 XFRM/StrongSwan/daemon smoke 继续运行。
      - 2026-06-12 container root 实验确认：共享 XFRM interface/同一 if_id/同一 traffic selector 下，“先建 staged CHILD_SA 再清旧 SA”会被 StrongSwan/内核策略拒绝，VICI `initiate` 返回 `establishing CHILD_SA ... failed`；真正无中断平滑切换后续只能走 A) staged generation 使用独立 XFRM interface/if_id，commit 时切换 route，或 C) Phase 6/7 DNAT/redirect grace，由防火墙 owner 管理新旧端口转发。

- [x] **4.4.x 真正平滑 rotate / staged transition（已归档）**
  - 目标：在不先打断当前可用 SA 的前提下，把 current/previous grace 变成系统层可执行的 staged transition；用户可见语义应是 zero-downtime 或接近 zero-downtime 的切换，而不是 bounded break-before-make。
  - 方案 A：为 staged generation 使用独立 XFRM interface/`if_id` 与独立 CHILD_SA，待新 SA established 且 tunnel/health check 通过后交给 Babel 层完成切换：新 link 以正常/更优 metric 加入，旧 link 在 grace 窗口内保留但调高 metric，等 Babel 邻居与路由收敛后再清理旧 generation。需要明确 route/interface ownership、BIRD interface pattern 自动发现语义、双 interface 期间的 metric/邻居收敛、daemon restart recovery 和 stale generation cleanup。
    - [x] IPsec staged generation 必须派生独立 `TransportID`、XFRM `if_id` 和 interface name；`prepare_rotate` 不再 terminate 旧 SA，旧 generation 在 staged 建立期间保持可用。
    - [x] `LinkInstance` 持久化 staged interface/`if_id`，用于 debug、daemon restart recovery、rollback、stale cleanup 和 revocation teardown。
    - [x] staged SA established 后进入 `dual_running`/cutover 语义：IPsec 层确认新旧 generation 并行承载；旧 generation 默认继续保留 1h，可通过 `overlays[].reconcile.rotate_retention` 配置；Babel/route manager 的 metric 纳入/调高/收敛回调仍由下一条接入。
    - [x] 旧 generation cleanup 由 retention 到期后的下一轮 reconcile 执行；daemon 重启后从落盘 `LinkInstance.rotate_deadline`、staged interface/`if_id` 和 `ListSAs` 恢复，若旧 SA 已不存在但 staged SA 已 established，则立即 promote staged generation 并清旧残留。
    - [x] 失败路径必须保持旧 generation：staged 建立超时、apply 失败或健康检查失败时只清 staged connection/interface，旧 SA/interface/route 继续保留并进入 backoff。
    - [x] 明确 role-only initiator 规则：当前 primary 或 secondary-takeover owner 负责主动建立 staged generation；`role=in` / `secondary-standby` 只准备 responder/trap staged config，不主动拨号，避免 rotate 触发双向同时拨号。
      - 2026-06-13 已在 `ReconcileLinkInstances` 中接入：secondary-standby/converged 观测到远端 port generation 变化时仍会生成 `prepare_rotate`，但 staged spec 被改写为无 ContactPoint 的 responder/trap，只加载 responder/trap；primary 和 secondary-takeover owner 保留主动 staged 建立语义。
    - [x] inbound 端 rotate advertised/listen port 时，真正平滑依赖 responder 侧能在 retention/grace 窗口同时接收 old/current port；若 StrongSwan 单实例无法双 listen，则 A 只能保持旧 SA/XFRM link，不能单独保证新旧端口监听无断，需 DNAT/redirect grace 或多实例 listener 作为 Phase 6/7 能力。
      - 2026-07-03 已接入 host firewall redirect grace：daemon 从本机 signed `ipsec/ports` 记录提取 current/previous advertised IKE/NAT-T ports，managed host firewall 将这些端口 redirect 到当前 charon 监听端口；已有 planner/unit/root smoke 覆盖 current/previous redirect 规则。
    - [x] bidirectional 双端同时 rotate 时沿用 4.5 的 primary/secondary-takeover：primary 或 takeover owner 负责 staged initiate，standby 只加载 responder；takeover 不应在 `dual_running` 保留窗口内抢拨，除非当前 owner 超时且无 established staged SA。rotate 不再依赖本地 `direction`。
      - 2026-06-13 已补 reconcile 守卫：secondary-standby 在 staged/`dual_running` rotate deadline 未到期时返回 `rotate_staged_active` / `rotate_retention_active` noop，不触发 takeover；新增单测覆盖超过 takeover delay 但仍处于 retention 窗口时保持 standby。
    - [x] 后续 Phase 5 接 Babel 时增加 route manager 回调/状态输入，避免 IPsec reconcile 在 Babel 尚未收敛前过早清理旧 generation。
      - 2026-06-13 已在 `ReconcileInputs` 增加 `RotateCutoverReady` per-instance 门闩：默认未接 route manager 时沿用 retention 到期 commit；Phase 5 route/Babel manager 可显式置为 false，让 `dual_running` 即使 retention 到期也继续保留旧 generation，直到 Babel metric/邻居/路由收敛后再允许 `commit_rotate`。
      - 2026-07-03 已把 health manager 的 `RotateCutoverReadiness()` 接入 daemon IPsec reconcile。
      - 2026-07-05 已把 BIRD staged interface 的 Babel neighbor / selected route 观测接入 health readiness，数据面 rotate 的 BIRD gate 基座完成；跨数据面 rotate smoke 降级为 Phase 7 之后远期增强。
  - 配置边界必须明确，避免把两类 rotate 混在一起：
    - `ipsec.port_mode` / `ipsec.port_range` / `ipsec.port_rotate_interval` / `ipsec.port_previous_grace` 是本节点公开的 IKE/NAT-T **入口端口 generation 策略**，决定本节点何时选择/公告 current port、previous port grace 多久；它主要影响 responder/inbound 入口和远端 planner 如何选择 ContactPoint。
    - `overlays[].reconcile.rotate_retention` 是本地 overlay link 的 **数据面旧 generation 保留窗口**，决定 staged CHILD_SA/XFRM link 已建立后，本机旧 SA/interface 继续保留多久给 Babel metric 收敛和回滚使用；默认 1h。它不负责让 charon 同时监听 old/current port。
    - 两者应满足：`port_previous_grace` 覆盖“远端还能尝试旧入口端口”的窗口；`rotate_retention` 覆盖“新旧 XFRM/Babel 数据面并行”的窗口。默认采用 `port_previous_grace=2h`、`rotate_retention=1h`；配置校验至少要求 `port_previous_grace >= rotate_retention`，生产推荐 previous grace 保持为 retention 的 2 倍或与 DNAT owner 规则生命周期绑定。
  - DNAT/redirect grace 已作为 inbound 端口平滑 rotate 的主线能力落地：charon 可以继续保持单实例/单当前监听端口，nftables/iptables owner 规则在 `port_previous_grace` 窗口把 previous/current advertised port 转发到当前 charon 监听端口，从而让 responder 在入口层同时接收 old/current port；规则 owner token、preflight、规则恢复、撤销清理、daemon restart adoption 和端口冲突检测由 firewall reconcile 能力覆盖。
  - 多 charon/socket/listener 暂不作为主线：只保留为极端部署 fallback。当前优先保持单 VICI socket、单 swanctl 配置树和 host firewall redirect grace，避免提前引入多 charon 生命周期和 XFRM/policy 互扰问题。
  - 决策点：优先走 A + DNAT grace + health/Babel gate 三层组合。IPsec staged generation 负责并行承载新旧 CHILD_SA/XFRM link；DNAT/redirect grace 负责 inbound 入口端口平滑；health/Babel gate 负责健康判断、metric 提升与流量迁移。
  - 验证要求：root/container smoke 必须覆盖旧 SA 保持可用、新 SA 并行建立、切换期间连续 tunnel ping 或允许的最大丢包窗口、失败回滚仍保持旧路径、daemon 重启恢复、revocation/policy deny 仍强制 teardown。
  - 归档边界：IPsec staged generation、host redirect grace、health cutover gate 和 BIRD staged route readiness 已形成当前平滑 rotate 基座；跨数据面 rotate smoke 作为 Phase 7 之后远期增强保留。

- [x] **4.5 Bidirectional 首拨失败接管（生产健壮性）**
  - 目标：双方 `role=both` 时，先使用稳定 tie-break 选出 primary initiator，避免正常情况下双向同时拨号；但当 primary 长时间无法建立 IKE_SA/CHILD_SA 时，secondary 可以有边界地接管主动拨号，避免稳定排序把链路永久卡死在单侧不可达/单侧防火墙或单侧 NAT 映射异常上。
  - 明确当前边界：当前 `InitiatorRoleForPeer` 在双方 `role=both` 时只用 zone 字典序决定首拨方；失败后 primary 进入本地 `LinkInstance` backoff/repair，secondary 初始 standby / 不主动拨。也就是说“稳定首拨 + 本地重试”已实现，“对端接管”尚未实现。
  - [x] 先做纯本地 runtime takeover：
    - 4.5 不新增 signed health record；secondary 只依据本机 `ListSAs`、本地 `LinkInstance` 超时、最近失败和 active state 计算接管。
    - Phase 6/7 再考虑低频 signed/runtime health hint；如果以后发布 health hint，必须防止瞬时网络抖动造成 gossip 风暴，也不能让第三方伪造失败诱导错误接管。
  - [x] 扩展 planner 角色模型：
    - `ShouldInitiate` 保持稳定 tie-break，但 planner 需要输出 initiator role：`primary`、`secondary-standby`、`secondary-takeover`、`converged`、`cooldown`。
    - `TransportLinkSpec` 增加 `InitiatorRole`（hash 中排除）；`LinkInstance` 记录 `InitiatorRole`、`TakeoverPhase`、`TakeoverStartedAt`、`TakeoverUntil`、`LastTakeoverError`、`ObservedInitiator`。
    - 初始状态：双方都 `role=both` 时，字典序小的一侧为 `primary` 并生成 create/repair；另一侧为 `secondary-standby`，产生 desired spec 但 reconcile 初始 noop，reason `bidirectional_standby`。
  - [x] 接管触发条件需要保守：
    - 必须双方 profile 都是 `role=both`；其他 role 组合不参与 takeover。
    - primary 连续失败次数、`connecting` 超时或长期未观测到匹配 SA 达到阈值后，secondary 才可接管；`takeoverDelay` 从 `LinkGroupSpec.Reconcile.Backoff` 派生（至少 2-3 个 backoff 周期），最小 60s。
    - secondary 接管前复用 planner 已过滤的 ContactPoint；缺少 ContactPoint 时返回 `takeover_no_contact_point`。
    - revocation、record 过期、transport key/profile mismatch、policy deny 时禁止 takeover；这些属于信任/授权失败，不是连通性失败。
  - [x] reconcile/adopt 规则：
    - `ReconcileLinkInstances` 看到已有匹配 SA 时优先 adopt，无论当前角色都进入 `up` 并标记 `converged`。
    - takeover 有 lease（默认 5min）与 cooldown（默认 2min）：secondary 接管成功后维持稳定窗口；takeover 超时或失败后进入 cooldown，期间不反复 apply；cooldown 过期后可 retry。
    - primary 后续恢复时若已有 SA 则 adopt，不会立刻抢回主动权导致重连风暴。
  - [x] debug / operator 输出：
    - `photon debug links` 显示 `initiator_role`、`takeover_phase`、`takeover_until`、`observed_initiator`、`takeover_error`。
    - reconcile noop reason 区分 `bidirectional_standby`、`takeover_delay_active`、`takeover_no_contact_point`、`takeover_cooldown_active`、`secondary_takeover_pending`。
  - 验证：
    - [x] dry-run：A/B 都 `role=both` 时初始只由稳定排序胜出的一侧 create；另一侧进入 standby/noop，并在 debug 中说明原因。
    - [x] dry-run：primary 连续失败并超过 takeover delay 后，secondary 生成 takeover create/repair action；成功观测 SA 后 adopt 为 `up/converged`。
    - [x] dry-run：takeover 失败进入 cooldown；cooldown 内不反复 apply。
    - [x] dry-run：revocation 不触发 takeover。
    - [x] root/system smoke：模拟 primary 侧 outbound 不可主动拨号但 responder 仍可达，验证 secondary 在 delay 后接管并建立 IKE_SA/CHILD_SA，tunnel ping 恢复；primary 恢复后 adopt 现有 SA，不抢回导致重连。
      - 2026-06-12 已加入 `TestStrongSwanBidirectionalTakeoverSmoke` 并接入 `make ipsec-xfrm-container-smoke`：container 内真实 netns/charon/VICI/XFRM 跑通 secondary takeover、`list-sas` adopt 和 tunnel ping；同时修正 planner 中 `DirectionInbound` 必须生成 responder/trap desired spec 的边界，避免真实 StrongSwan primary 没有对端 responder 配置。

## Phase 5: BIRD Babel 路由 + Route Authorization Filter（预计 3-4 周）

**目标：** 在 Photon 管理的 XFRM/TransportLink 接口上跑 Babel 协议，发现邻居、学习路由，并且只导入、导出经过 Zone/IPAM 授权的前缀；策略路由、路由表 ownership、debug 观测和 Phase 4 staged rotate cutover 形成闭环。

**核心决策：**
- 默认由 `photon daemon` 拉起并监管 BIRD Babel daemon 子进程，和 IPsec/XFRM reconcile 处于同一个单 writer 事件循环。这样 state/apply 顺序、重启恢复、撤销清理、rotate cutover gate 都由 Photon 统一控制。
- **后端实现：BIRD**
  - 项目已决定 Phase 5 默认采用 `bird` 跑 Babel protocol。详见 `docs/bird-babel-alternative-findings.md`。
  - BIRD 支持 `interface "phx*"` 自动发现 XFRM 接口、多 routing table、IPv4/IPv6 双栈、更平滑的 `birdc configure` filter 重载和更丰富的 filter 语言。
  - 代价是体积更大、需要维护 `bird.conf` 生成器和 `birdc` CLI client。
- 支持 `mode=external`：管理员用 systemd 启动 BIRD daemon，Photon 只连接已存在的 birdc control socket 并校验 router-id、netns、routing table、interface ownership。该模式用于发行版集成/生产托管，但第一版 smoke 以 Photon-owned 模式为主。
- 每个 `LinkGroupSpec.NetNS` / overlay data-plane 启动一个 Babel daemon 实例；不同 netns 不共享 control socket。daemon 必须和对应 XFRM interface 处于同一 netns。
  - BIRD 自身不能切换 netns，必须由 Photon Process Manager 在目标 netns 内启动（如 `ip netns exec <ns> bird ...` 或 systemd `NetworkNamespacePath`）。
- Babel router-id 是本地持久运行态，不进入 gossip：优先读取本地 state 中保存的 overlay router-id；不存在时从 `local zone + trusted root + overlay id` 确定性派生 64-bit id 并落盘。router-id 不等于 peer id，也不随接口/IP/端口变化而变化。
  - 正常场景禁止管理员手工配置 router-id；配置中的 `router_id` 只保留为迁移/恢复覆盖，且加载时必须校验与派生值一致或给出明确警告。
- Phase 5 route source 分三层：`ipam/assignments/*` 表示谁拥有/可使用某地址或前缀；`routes/announcements/*` 表示节点想发布哪些业务前缀；本地 config 可有 `route.export_static` 作为临时/恢复 override。只有 assignment 与 announcement 同时通过授权校验的前缀才能导出或被远端导入。
- 默认 overlay 业务前缀池应通过 root/父 Zone 的 `policy/default-ip-pool` 或 `ipam/pools/*` 统一声明，而不是硬编码在代码里。默认建议使用私有/ULA 空间（如 `fd00::/48`）并配合独立 route table/netns 使用，避免污染 host main table；若使用公网可路由前缀（如 `2001:da8::/48`），必须通过 IPAM assignment 显式授权，并在 import/export filter 中校验，防止误泄漏到公网。
- 默认不接受 default route、underlay/transport endpoint 前缀、loopback/link-local/multicast、Photon 保留 tunnel-address pool、未授权更宽聚合前缀；是否允许 `0.0.0.0/0` / `::/0` 必须以后续显式 policy record 开启。
- Babel learned routes 不直接污染 host main table。当 overlay 使用独立 netns 时，BIRD 直接把路由写入该 netns 的 main table 即可，netns 本身就是隔离边界，**不需要额外配置独立 route table / `ip rule`**。
- per-overlay route table / `ip rule` 只作为可选能力保留：当多个 overlay 共享同一个 netns、或管理员显式需要策略路由、或 `mode=external` 接入手动部署的 BIRD 时才启用。默认 `table: main`（即该 netns 的 table 254），`priority` 仅在该 overlay 使用非 main table 时生效。

- [x] **5.0 Babel 运行模式与配置模型**
  - [x] 增加 `overlays[].routing` 配置：`enabled`、`protocol=bird`、`mode=managed|external|disabled`、`netns` 继承 LinkGroup、`control_socket`、`pid_file`、`router_id` override、`table`（可选，默认 main）、`priority`（可选，仅非 main table 时生效）、`metric_base`、`metric_staged`、`metric_draining`、`export_static`。
  - [x] managed 模式骨架：daemon 在目标 netns 内启动 BIRD daemon，传入固定 router-id、control socket、pid/log 路径、routing table（默认该 netns 的 main table）；daemon 退出时按 ownership 清理子进程和 socket。
    - [x] 启动流程：确保 netns 存在 → 生成 `bird.conf` → `ip netns exec <ns> bird -c ... -s ... -P <pidfile>` → 等待 control socket 出现。
    - [x] 配置热重载：filter/接口参数变化时重写 `bird.conf`，执行 `birdc configure`（当前先使用普通 configure；后续可优化为 soft + reload in/out）。
    - [x] 优雅退出：Stop 先发 `birdc down`，再 SIGTERM，再删 Photon-owned pid/socket/config。
      - 2026-07-03 已把 daemon shutdown 接到 managed BIRD teardown：退出时只对本 daemon 已持有的 managed process manager 调用 Stop，`mode=external` 不触碰。
    - [x] 崩溃恢复/backoff：`ExecProcessManager` 通过 `waitpid`/`Wait` 记录 managed process exit，daemon reconcile 按指数 backoff 标记 degraded，到期后自动重拉起并清理 crash 状态。
  - [x] external 模式骨架：daemon 只校验配置并连接现有 socket，不杀进程。
  - [x] preflight：`bird.BirdPreflight` 检测 bird/birdc/ip/ip netns 可用性；`photon debug preflight` 后续统一接入。
  - [x] owner token 细化到 control socket/pid/config/route table/rule：`BirdResourceOwner` 持久化 per-resource token，Stop 只清理 owner 校验通过的 runtime 文件；route table/rule token 先进入 spec/state，为后续策略路由清理复用同一归属边界。

- [x] **5.1 Babel daemon control client 与 adapter**
  - [x] 在 `pkg/routing/bird/` 实现 BIRD adapter：config generator、birdc client、process manager、observed state parser。
  - [x] birdc client 能力：连接 control socket、执行 `configure`、`configure soft`、`reload in/out`、解析 `show status`/`show protocols`/`show route`/`show interfaces`/`show babel neighbors` 输出、超时与错误码检测。
  - [x] 定义纯函数 desired model：`BirdInstanceSpec`、`BirdConfig`、`KernelProtocolBlock`、`BabelProtocolBlock`、`FilterBlock`、`BirdObservedState` 等。
  - [x] daemon reconcile 顺序：IPsec desired/up snapshot -> BIRD desired config -> route authorization -> BIRD config apply (`birdc configure`) -> observe routes/neighbors -> 写入 debug snapshot。策略路由 table/rule 步骤随 5.4 后续补齐。
  - [x] **BIRD 后端**：依赖 interface pattern `"phx*"` 自动发现 XFRM 接口；teardown/revocation 时由 BIRD 自动 retract。
  - [x] **tunnel 模式选路**：`type tunnel` + `rxcost` + `ecmp on limit 16` 已生成到 bird.conf。
  - [x] staged generation 接入 `RotateCutoverReady=true`：IPsec reconcile 已消费 health-manager readiness；routing reconcile 会把 BIRD staged interface 的 Babel neighbor 与 selected route 观测写入 health manager，缺少收敛时继续阻断 cutover。
    - 2026-07-03 已接线：`BabelObservation` 按 `instance#staged` probe target 参与 readiness；BIRD 观测只在对应 staged interface 同时有 neighbor 和 selected Babel route 时放行。

- [x] **5.2 Route Authorization / IPAM 输入模型**
  - [x] 明确记录语义并实现解析：`ipam/pools/*`、`ipam/assignments/*`、`routes/announcements/*`。
  - [x] Phase 5 静态 assignment 解析：`BuildAuthorizedRouteSet` 从 verified active state 构建授权路由集合。
  - [x] `AuthorizedRouteSet`：输出 `zone -> announced prefixes`、`Assignments`、`Pools`、`Errors`。
  - [x] 校验规则：announcement 由宣告 Zone 签名；前缀必须在同 Zone 或祖先 Zone 的 assignment 覆盖内；父 Zone 可聚合宣告分配给子 Zone 的前缀；禁止无授权关系的 Zone 宣告重叠前缀。
  - [x] 撤销 Zone 后其 announcement 不进入 authorized set。

- [x] **5.3 Import / Export Filter（第一版）**
  - [x] BIRD import filter 接受所有已分配 IPAM 空间内的前缀（使用 `+` 包含更具体路由），拒绝 default route、bogon、未授权聚合。
  - [x] BIRD export filter 只发布本节点 `local export set`（本地 Zone 的 authorized announcements）。
  - [x] filter 变化时重写 bird.conf 并 `birdc configure`；后续可优化为 soft + reload in/out。
  - [ ] ~~per-peer/interface import whitelist~~ 已废弃：Babel 多跳传播与 per-interface filter 冲突，见 `docs/new/routing.md` 5.5 节。替代方案为控制面交叉审计（Phase 7 后续）。
  - [ ] route-table auditor 作为可选兜底留到后续。

- [x] **5.4 策略路由与路由表 ownership（第一版）**
  - [x] BIRD config 支持 `kernel table <id>` 和非 main internal table；默认仍使用 main table（独立 netns 隔离）。
  - [x] ECMP：`ecmp on limit 16` 已写入 bird.conf。
  - [ ] `ip rule` / fwmark / iif-oif 策略路由和 `/run/photon/rt_tables.d` 诊断输出已降级为 Phase 7.12 远期增强。
  - [ ] 多 overlay 共享同一 netns 时的 table/rule 隔离留到后续。
  - [ ] teardown/revocation 对 table routes/rules 的 owner-guarded 清理随策略路由一起补齐。

- [x] **5.5 Operator / Debug 命令（第一版）**
  - [x] `photon debug babel`：显示 overlay BIRD mode、pid/socket、router-id、table、state、last error。
  - [x] `photon debug routes`：显示 local export set、authorized route set、authorization errors。
  - [x] `photon debug route <prefix>`：解释前缀的授权状态、宣告来源、assignment 依据。
  - [x] `photon debug links` 扩展 `routing:` 列：bird_state、bird_neighbors、bird_best_routes。
  - [x] control method `bird_status` / `routes_dump` 已加入；daemon status 已包含 routing reconcile last error。
  - [x] `routing_reload` control method 和 `bird_dump`（完整 birdc 原始输出）已补齐。
  - [x] Photon 侧 authorized route set 与 BIRD 侧 learned/installed routes 的交叉视图已补齐：`routes_dump` / `debug routes` / `debug route <prefix>` 接入 BIRD live route cross-view，按 prefix 标注 selected、authorized exact match、assignment/import 范围命中和来源 zone。

- [x] **5.6 闭环验证（第一版）**
  - [x] 单元测试：`StableRouterID`、`AuthorizedRouteSet`（assignment/announcement/撤销/重叠/default route）、BIRD config/filter、birdc client、process manager、daemon routing reconcile。
  - [x] dry-run smoke：`make routing-dry-run-smoke` 验证两节点 route authorization + BIRD config 生成。
  - [x] container root smoke（3 节点 + StrongSwan/XFRM + managed BIRD + 跨节点业务 ping）：已增加 `make bird-babel-smoke` / `make bird-babel-container-smoke` 基础设施和 Go root smoke 测试骨架（`PHOTON_BIRD_SMOKE=1`），覆盖 managed BIRD lifecycle、两节点 Babel 邻居+路由学习、daemon routing reconcile、veth upstream。完整 3 节点 + StrongSwan/XFRM + managed BIRD 联合 smoke 仍待后续接入。
  - [x] managed BIRD 默认随 Photon daemon 退出保持运行，重启后 adopt；如需实验室 teardown 可显式配置 `shutdown_policy: stop`。
  - [x] restart/adopt smoke 随真实 BIRD 数据面补齐：daemon 默认退出不停止 managed BIRD，新 daemon/process manager 通过 pidfile/control socket adopt 原进程，避免 Babel 会话被控制面重启打断。
  - [x] negative smoke 随真实 BIRD 数据面补齐：用真实 BIRD 验证未授权 prefix 不被 import/selected/安装。
  - [ ] 跨数据面 rotate smoke 已降级为 Phase 7 之后远期增强：结合端口/IPsec rotate 与真实 BIRD route/metric 观测验证数据面切换窗口。

- [x] **5.7 BIRD 从 per-overlay 改为 per-netns（配置模型重构）**
  - 设计文档：`docs/new/routing.md`（完整 routing / IPAM / per-netns BIRD 规范）、`docs/design.md` Phase 5 netns 章节。
  - **核心决策：** 一个 netns 内只运行一个 BIRD 实例，同一 netns 下的所有 overlay 共享该实例；routing 配置从 `overlays[].routing` 上提到 `routing.instances[]` / `netns` 层级。
  - **Router-ID 派生：** `StableRouterID(localZone, rootTrust, netnsName)`，第三个参数从 overlayID 改为 netns 标识；同一节点不同 netns 的 BIRD 必须有不同 Router-ID，不同节点因 zone 不同也自然不同。netns name 通过 `routing/netns` record  announce，供对端审计时反推 Router-ID。
  - **安全设计结论（见设计文档 6.x 节）：**
    - per-peer/interface import filter 因 Babel 多跳传播冲突而废弃（6.3 节）。
    - BIRD filter 基于 `babel_router_id` 来源验证不可行：BIRD 2.x 源码未注册该 filter 动态属性（6.5 节）。
    - 恶意前缀宣告防护的唯一可行方案为控制面交叉审计（Phase 7 后续），Phase 5.7 保持全局 import filter。
  - [x] 新增顶层 `netns:` 配置段，定义默认 netns 列表（如 `netns.default.kind/name/create`）。
  - [x] 推荐使用 `netns.default` / `overlays[].netns: <name>` 引用模型；`overlay.default_netns`、`ipsec.default_netns` 和旧式内联 `overlays[].netns` 仅作为兼容读取。
  - [x] 新增顶层 `routing.instances[]`：每个实例绑定一个 netns，包含 enabled/protocol/mode/control_socket/pid_file/config_file/table/metrics/interface_pattern 等。
  - [x] `pkg/transport/ipsec/link.go`：从 `LinkGroupSpec` 中移除 `Routing` 字段；`TransportLinkSpec` 保留 `NetNS`。
  - [x] `pkg/routing/bird/routerid.go`：`StableRouterID` 改为 `(localZone, rootTrust, netnsName)` 三个参数；`netnsName` 使用 `NetNSSpec.Target()`，path netns 要求配置 `router_id_label`。
  - [x] `pkg/routing/records.go`：新增 `routing.netns.v1` record 类型、key `routing/netns`、解析函数；schema 包含 `version` 和 `netns` 列表。
  - [x] `app/photon/ipsec_publish.go`（或独立文件）：daemon 在发布 IPsec records 时同步发布本节点 `routing/netns` record；记录值从 `routing.instances[].netns` 推导。
  - [x] `app/photon/config.go`：解析新 `netns` / `routing.instances` 配置，校验每个 overlay 引用的 netns 存在；path netns 用于 routing 时必须设置 `router_id_label`。
  - [x] `app/photon/state.go`：`BirdInstances` key 从 overlay ID 改为 netns name；`BirdInstanceState.OverlayID` 改为 `NetNSName`。
  - [x] `pkg/routing/bird/types.go`：`BirdInstanceSpec.OverlayID` 改为 `NetNSName`；增加 `InterfacePatterns []string` 支持多 overlay 接口合并。
  - [x] `pkg/routing/bird/generator.go`：config 内部 table/protocol/filter 命名改用 netns name；支持多 interface pattern。
  - [x] `app/photon/routing_reconcile.go`：按 netns 分组 overlays，每个 netns 生成一个 BIRD 实例；合并该 netns 下所有 overlay 的接口 pattern。
  - [x] `app/photon/daemon.go` / `control.go` / `diagnostics.go` / `debug_routing.go`：`bird_status`、`debug babel`、`debug links` 输出按 netns 展示实例，并列出该 netns 下的 overlays。
  - [x] `pkg/routing/bird/preflight.go`：增加 BIRD 版本检查，断言 >= 2.0（项目依赖 BIRD 2.x 语法）。
  - [x] 测试改造：`routing_reconcile_test.go`、`pkg/routing/bird/generator_test.go`、`debug_routing_test.go` 中 BIRD 实例查找、filter/table 名称断言改为 netns 维度。
  - [x] smoke：`make routing-dry-run-smoke` 覆盖多 overlay 共享同一 netns 场景。

## Phase 6: IPAM / 准入 / 防火墙 / 链路健康（已完成主线归档）

**归档状态：** Phase 6 主线、增强 smoke 和 6.7.7 `app/photon` 模块化重构均已从主 `todo.md` 移出；主 TODO 只保留当前 Phase 7 可执行队列、远期后续和摘要链接。完整实现细节可回看对应设计文档：`docs/new/routing.md`、`docs/new/daemon.md`（原 `docs/phase6-event-driven-design.md` 已并入并删除）、`docs/new/firewall.md`（原 `docs/phase6-firewall-design.md` 已并入并删除）、`docs/web-status-dashboard-design.md`、`docs/app-photon-modularization-design.md`。

- [x] **6.0 事件驱动控制面重构**
  - [x] 默认启用 event loop + `SyncSession` FSM；packet demux、timer manager、异步 object pull、UDP chunk fallback、relay fanout 均接入事件循环。
  - [x] daemon 主 goroutine 成为 single writer；`ReplayWindow`、`PeerQuotas`、`stateFile` race 修复完成，`go test -race` 基线通过。
  - [x] endpoint 地址优先级与可达性探测修复：`Transport.Send()` 记录 per-address success/failure/backoff，`updateDiscoveredPeers()` 支持 source order，loopback smoke 自动抑制公网 endpoint 发布。
  - [x] 文档同步到 `docs/phase6-event-driven-design.md`（后并入 `docs/new/daemon.md` 并删除）、`docs/design.md` 和 `docs/protocol.md`（后并入 `docs/new/` 系列文档并删除）。

- [x] **6.0.x Gossip SyncSession 读写分离 / hint 语义重构**
  - 设计文档：`docs/new/gossip.md#15-当前结构读写分离与-hint-语义`。
  - [x] 把 active pull FSM、只读 responder 和 hint ingress 拆开，避免一个 per-peer `SyncSession.State` 同时表达“我正在读对方”和“对方正在读我”。
  - [x] Active pull FSM 收敛为 `PING/PONG Summary -> FETCH_CATALOG_PAGE/CATALOG_PAGE -> TCP object pull -> UDP chunk fallback -> apply`。
  - [x] Responder 只响应 `FETCH_CATALOG_PAGE`、TCP object pull 和必要的 UDP chunk fallback；读取本地 verified state，不改变 active pull FSM 状态。
  - [x] Hint ingress 只处理 `ANNOUNCE` / relay hint：记录 digest/source/time，按需唤醒 active pull；不依赖 UDP announce payload 完成同步。
  - [x] 回归测试覆盖：`SummarySent`/等待 `PONG` 时收到 `FETCH_CATALOG_PAGE` 或普通读取请求，active session 不会被 read-only responder 污染，后续 `PONG` 继续处理。
  - [x] 把 `FetchCatalogPageReceivedEvent` 从 `SyncSession.OnEvent` 中迁出，改为 daemon 只读 responder action/handler；保留 catalog page budget、诊断和发送错误记录。
  - [x] 把普通 `FETCH_ZONE` 兼容响应从主 FSM 迁出；现代路径优先走 TCP object pull，UDP `FETCH_ZONE{chunk_fallback:true}` 仅作为 TCP 不可达后的 chunk fallback 请求。
  - [x] 将 `ANNOUNCE` 处理收敛为 hint：不再把 UDP announce payload 作为正确性主路径；收到 hint 后创建或唤醒 active pull session，由 catalog diff/object pull 决定实际拉取内容。
  - [x] 删除旧兼容字段路径：现代 event-loop 不再使用旧 Ping/Pong digest/fetch 字段、反向 fetch 动作、服务中状态和 eager object pull；wire codec 与旧 `sync.go` receive 路径已随 6.0 事件循环收尾删除。
  - [x] 更新观测面：`sync status --verbose` / `debug peer` 可区分 active pull、read-only responder、hint suppressed/accepted、object pull/chunk fallback 结果；per-peer `sync_flow` / debug 展开字段包含 `active_pull_state`、`active_pull_last_event`、hint accepted/suppressed、read-only responder kind/zone/last。
  - [x] 验证：`go test ./app/photon -run 'TestSyncStatusVerboseOutput|TestDebugPeerOutput|TestDaemonEventLoopAnnounceIsHint|TestDaemonEventLoopResponderDoesNotStealActiveSession'`、`go test ./app/photon ./pkg/core/gossip`、`make check`。

- [x] **6.1 IPAM 闭环**
  - [x] 实现 pool/assignment 分离、pool enforcement、assignment 重叠检测和 `PermAllocateIP` 权限模型。
  - [x] 增加 `photon route ipam` CLI：pool create、assign、revoke assignment/pool、assigned 查询。
  - [x] 支持 `ipam.auto_announce_assigned_ips` 自动宣告本节点合法 assignment，并随撤销收敛。
  - [x] 支持 routing upstream / veth pair / BIRD static route 集成，`TestBIRDUpstreamBabelRootSmoke` 覆盖 overlay netns 与 host ns BIRD Babel 互通。
  - [x] anycast/shared assignment 第一版落地：`IPAMAssignmentRecord.Shared`、授权/重叠例外、CLI `--shared`、单测覆盖 shared route announcement。

- [x] **6.1.x IPAM pool 严格所有权 / 隐式继承修复**
  - 目标：把 `ipam/pools/*` 的 `delegated_to` 从“该 zone 及其所有子孙隐式可用”收紧为“精确 owner”；只有精确拥有覆盖 pool 的 zone 才能继续切子池或发布 assignment，避免 root/self pool 被全树绕过使用。
  - [x] 调整 `pkg/routing.AuthorizedRouteSet` pool read model：保留兼容用 `Pools map[netip.Prefix]*PoolEntry`，新增 `AllPools []*PoolEntry`，后续 assignment 校验遍历 valid `AllPools`，避免同 prefix/重叠 pool 被 map 覆盖丢失。
  - [x] 在 `BuildAuthorizedRouteSet` 中新增 pool validation 阶段，顺序为 active pool 收集 -> pool ownership/overlap 校验 -> assignment pool 校验 -> assignment overlap -> route authorization -> route overlap。
  - [x] 实现 pool ownership 校验：允许 `. DT=.` root bootstrap pool；其他 pool 必须由 source 精确拥有的 covering pool 支撑，即存在 valid `cover.DelegatedTo == pool.Source` 且 `containsPrefix(cover.Prefix, pool.Prefix)`。
  - [x] 实现 pool overlap 校验：允许 owner 从自己拥有的覆盖 pool 切子 pool；拒绝 sibling/unrelated owner 的相同、包含或部分重叠 prefix；非法 pool 输出 `ipam_pool_owner_mismatch` 或 `ipam_pool_overlap`，且不得进入 `AllPools`。
  - [x] 将 `isAssignmentPoolValid` 改为精确 owner 检查：assignment source 必须存在 `pool.DelegatedTo == assignment.Source` 且覆盖 assignment prefix 的 valid pool；`AssignedTo` 只表示使用者，不参与 pool ownership 校验。
  - [x] 保留现有 assignment overlap / anycast 语义，避免把 pool ownership 修复误扩展成禁止跨层 assign 或禁止 `Shared=true` anycast。
  - [x] 在 `app/photon/ipam.go` 写入路径增加 dry-run 早失败：`createIPAMPoolWithRuntime` 拒绝 owner mismatch / pool overlap；`assignIPAMWithRuntime` 拒绝 `ipam_assignment_pool_mismatch` / `ipam_assignment_overlap`；最终正确性仍以 `BuildAuthorizedRouteSet` 为准。
  - [x] 调整 `photon route ipam mine`：删除 `usable_by_managed_zone`，只保留 `published_by_managed_zone` 和 `delegated_to_managed_zone`，让输出匹配严格 owner 语义。
  - [x] 新增 `photon route ipam get <addr-or-prefix>` 只读诊断命令：归一化地址/前缀，基于 valid `AllPools` / `AllAssignments` / authorized routes 输出 pool chain、best pool、assignment、assigned_to、route 和 diagnostics；默认输出 human-readable 文本，`--json` 输出结构化 view；无 pool 输出 `ipam_no_pool`，有 pool 无 assignment 输出 `ipam_unassigned`。
  - [x] 补 `pkg/routing` 单测：root bootstrap pool、无 covering owner 的 delegated pool 拒绝、root 切 child pool 合法、child 再切 grandchild pool 合法、sibling/unrelated pool overlap 拒绝、ancestor self pool 不再授权 descendant assignment、显式 delegated pool 授权 assignment。
  - [x] 补 `app/photon` CLI/runtime 单测：root bootstrap pool 可创建、无 owner covering pool 的子池创建失败、隐式继承 assignment 失败、显式 delegation assignment 成功、`ipam mine` 不再显示 `usable_by_managed_zone`，`ipam get` 默认文本和 `--json` 覆盖地址查询、prefix 查询、anycast/shared assignment、`ipam_no_pool` 和 `ipam_unassigned`。
  - [x] 更新操作文档和示例：`README.md`、`docs/new/config.md`、`docs/new/operations.md` 中明确 root/self pool 只是精确 owner 声明，子 zone 需要显式 pool delegation；offline root 仍通过 `recovery export-zone/import-zone` 迁移 root-owned IPAM records。
  - [x] 验证：先跑 focused `GOCACHE=/tmp/photon-gocache GOMODCACHE=/tmp/photon-gomodcache go test ./pkg/routing ./app/photon -run 'Test(IPAM|Pool|Assignment|Recovery|Authority)'`，再跑 `make check`；若 broad `app/photon` 受 sandbox UDP 限制影响，记录具体失败并保留 focused 结果。

- [x] **6.2 Auto-join 准入基线与诊断**
  - [x] 空 DB + config 首启可创建 pending bootstrap state，普通 gossip 同步到 parent delegation 后自动 materialize 本地 Zone。
  - [x] pending 节点不发布 endpoint/IPsec/route 本机记录；`photon gossip join request --from-config` 可生成等价 join request。
  - [x] 增加 `admissionState` 持久化、`diagnoseAutoJoinAdmission()`、`photon debug admission` 和 `admission_status` control API。
  - [x] 增加 `photon recovery pull-zone` / `pull-chain`，用于管理节点 DB 丢失后按 trust chain 拉取恢复。

- [x] **6.3 防火墙规则同步**
  - [x] 新增 `firewall.instances[]` 配置、owner token/table-chain 命名、dry-run diff、hook、managed/external/disabled 模式。
  - [x] overlay netns 生成 input/forward/output policy；host netns 只管理 IKE/NAT-T ingress 与 port rotate redirect grace。
  - [x] forwarding policy 与 BIRD export/import 共享，revocation deny-first 从 allow set 中剔除 revoked prefix。
  - [x] nftables backend 优先、iptables fallback、per-instance netns 执行、owned stale cleanup 和 `photon debug firewall` 操作面已完成。

- [x] **6.4 动态 Peer 管理**
  - [x] 本地派生 peer 状态：eligible、discovered、connecting、active、stale、offline、policy_denied、config_error、revoked。
  - [x] 支持 stale/offline/cleanup 阈值、endpoint/profile/key/port 变化 dirty fanout、revocation 高优先级路径。
  - [x] 增加 `photon debug peers` 和 `peers_status` control API，展示 reason、severity、last sync/reconcile、cleanup timer。

- [x] **6.5 撤销后的传输与路由清理**
  - [x] 计算 `RevocationImpact`，覆盖 IPsec/XFRM、BIRD/routing、防火墙、gossip peer cache 和 configured bootstrap 诊断。
  - [x] deny-first 顺序落地：revocation cleanup -> firewall -> routing -> IPsec -> peer cache cleanup，单层失败不回滚安全删除。
  - [x] 增加 `photon debug revoke-impact`、`revoke_status` control API、debug links/routes/firewall 的 revoked reason 展示。

- [x] **6.6 链路健康检测**
  - [x] 新增 `pkg/health`：rolling window、状态机、ICMP/UDP prober、manager、OpenMetrics 渲染和 rotate cutover gate。
  - [x] daemon 接入 `health.*` 配置、`health_status` control API、`photon debug health`、health probe tick 与 `RotateCutoverReady` 门闩。
  - [x] 本地 metrics/spool schema 与低基数标签边界已定义；长期 TSDB 默认推荐 VictoriaMetrics single-node。

- [x] **6.7 Observer 只读状态控制台 MVP**
  - [x] 新增 `observer` 配置、daemon 内 HTTP server、localhost 默认监听、非 loopback 警告和优雅退出。
  - [x] REST API 覆盖 status、zones、peers、links、health、health series、本地 routes、BIRD；统一 `{ok,error,data}` 响应并过滤敏感字段。
  - [x] Go embed 静态 UI、SSE `/api/v1/events`、轮询 fallback、Health sparkline、本地 spool 查询、raw JSON view 已完成。
  - [x] `make observer-smoke` 纳入 `smoke-all`；README 和 `docs/web-status-dashboard-design.md` 已标注 MVP 已实现与只读安全边界。

- [x] **6.x 增强 smoke 收尾**
  - [x] 6.1.8 anycast smoke：多节点宣告同一 anycast 前缀，验证 Babel 多候选路由和故障切换；暂不声明 ECMP 多 nexthop。
  - [x] firewall root/container 增强 smoke：overlay netns + veth + BIRD 下验证 default drop、合法 prefix 放行、非法 prefix drop、revocation 断流、port rotate redirect grace。
  - [x] health root + metrics 增强 smoke：覆盖 probe state、OpenMetrics render、本地 spool/series、真实 BIRD selected route 进入 rotate cutover gate。
  - [x] health container / fault-injection 增强 smoke：在真实 XFRM+BIRD 链路上注入丢包/延迟，验证状态切换、BIRD metric/cutover gate 和数据面恢复。
  - [ ] state 文件外部协调补强已降级为 Phase 7 之后远期增强：在现有 bbolt 文件锁基础上增加显式 `flock` / fsnotify watcher，避免多进程或外部修改时状态漂移。
  - [ ] Observer 深度增强已降级为 Phase 7 之后远期增强：拓扑图、zone tree、VictoriaMetrics/Prometheus-compatible datasource/push 集成、BIRD protocols/routes/neighbors 深度解析。


## Phase 6.7.7: `app/photon` 模块化重构（Observer/debug 先行，已完成）

**设计文档：** `docs/app-photon-modularization-design.md`

**完成背景：** `app/photon` 曾同时承载 CLI wiring、daemon lifecycle、sync runtime、reconcile、observer、debug presenter 和 readmodel 推理。6.7.7 以 Observer/debug/inspect 为低风险第一刀，把可复用只读 view、reason、HTTP DTO 和 CLI presenter 从 executable 包中拆出，同时保留 `app/photon` 作为 runtime/source adapter。

**完成结果：**
- `internal/observer` 承接 HTTP routing、SSE、static web、API envelope、method/404/SSE/static/webapp 等通用 handler 测试；`app/photon` 只保留 daemon provider、observer 启停和 health spool/runtime adapter。
- `internal/inspect` 建立 links、zones/records、peers/endpoints、peer lifecycle、routes/BIRD、health、revocation、firewall、admission、rotate、ping、sync status 等共享 readmodel/builder/filter/reason。
- `internal/inspect/http` 承接 observer status/zones/peers/links/health/routes/BIRD DTO builder，稳定 HTTP schema，避免 observer 直接依赖 app 私有 state 或原始 runtime struct。
- `internal/inspect/text` 承接 debug/zone/record/peer/endpoints/links/routes/routing/health/revocation/firewall/admission/rotate/ping/sync status 文本 presenter 和 focused output 测试；`app/photon/debug_*.go` 保留命令注册、参数解析、control socket/live/offline source 选择。
- `internal/state` 承接跨 app/inspect/control/observer 共享的只读 snapshot 类型，例如 `PeerRuntimeState`、link runtime state、BIRD/firewall reconcile state；app 层通过 alias 表达 state ownership。
- `sync status` 与 `debug peer` 复用 `inspect.BuildPeerDebugFromRuntime`，peer status/backoff/next retry/observed path/datagram/object pull 诊断不再在 app 和 inspect 重复推理。
- manual rotate-port 输出下沉为 `inspect.ManualPortRotateView` + `inspect/text.WriteManualPortRotateResult`；app 层只做结果投影。
- 明确不新增 `internal/debug` 包：debug 是 CLI 命令面，可复用诊断 readmodel 留在 `internal/inspect`，文本 presenter 留在 `internal/inspect/text`。

**延后事项：**
- `internal/inspect/source` 暂不创建；control socket、offline DB、live daemon source 仍与 app 私有 runtime adapter 贴近，等 metrics/source collector 接口稳定后再抽。
- admission 的 state/key/delegation 检查和 admission state 更新 adapter 仍留在 app 层；后续若下沉，必须先定义纯 input，不把 `stateFile`、join request 编码或 app 私有协议塞进 inspect。
- `DatagramStats`、`ObjectPullStats` 等纯诊断计数仍随 `PeerRuntimeState` 持久化；后续随 metrics store / observability readmodel 拆出，避免统计计数推动主 committed state revision。
- `sync.go`、`daemon.go`、`ipsec_reconcile.go`、`routing_reconcile.go`、`config.go` 仍是后续模块化主战场，但不属于 6.7.7 收尾阻塞。

**验收覆盖：**
- `go test ./app/photon ./internal/...` 通过。
- `internal/inspect`、`internal/inspect/http`、`internal/inspect/text`、`internal/observer` 已补 focused builder/schema/output/handler 测试。
- Observer/debug app 层测试保留 daemon provider、source fallback、config/wiring 和 committed snapshot 行为覆盖。


## Phase 7.10.1: Daemon state 读写分离 / committed snapshot 重构（已完成）

**完成背景：** daemon event handler 曾直接在 live `*stateFile` 上原地修改 map/slice/字段。为避免 reader 看到半写入状态，writer 持有 `stateFile.Lock()` 时 observer/debug/control 的只读路径都会等待；当写事务内同步执行 IPsec/VICI、BIRD、firewall、health probe 等外部 I/O 时，运维面会在最需要诊断时失明。

**完成结果：**
- 引入 `DaemonStateStore`：维护 committed snapshot、revision、snapshot clone、short update、dirty flags，并提供 `Snapshot()`、`Update(fn)`、`CommitIfRevision(rev, fn)`、`BeginUpdate()` workspace 语义。
- observer/control/debug 只读路径迁到 committed snapshot，输出 `state_revision`、`snapshot_time_unix`、dirty/reconcile flags，不再依赖 live `stateFile.RLock()`。
- gossip packet 快路径、object-pull TCP lookup、sync timer、read-only responder、hinted session、relay fanout、daemon zone digest 和 IPsec interval 判断均迁到 committed snapshot 输入。
- IPsec reconcile 基于 committed snapshot 做 plan/list/XFRM inspect/apply；`LinkInstances` 按 instance owner token / revision 条件提交，`IPsecReconcile` summary 标注 source revision / committed / stale。
- routing/BIRD reconcile 基于 committed snapshot workspace 生成 `BirdInstances` / `RoutingReconcile`；BIRD config/start/reload/status 锁外执行，revision stale 时按 netns owner token 合并或重新置 dirty。
- firewall reconcile 基于 committed snapshot 构造 desired/plan/apply；`FirewallReconcile` summary 通过短事务写回，stale summary 可合并并重新置 dirty。
- `record_put`、delegate issue/grant/revoke、recovery import/purge、IPsec port rotate/cleanup、endpoint timer、revocation cleanup、sync snapshot apply、object-pull attempt/result 等写路径迁到 StateStore 短事务提交 committed snapshot。
- 移除 `DaemonService.lockState()`、`hasStateLock()`、`stateLocked` / `lockedState` 这类 live pointer 锁追踪；`setState` 只做 current snapshot 指针切换并发布 committed snapshot，不再承担 live-lock 转移语义。
- peer state 分层结论：`SyncPeers` 中 observed path、backoff、rejected digest/record cache 暂留 runtime control state；datagram/object-pull counters、read-only responder、last catalog/page/reject 等纯诊断字段后续随 6.7.7 inspect/source 迁到 peer observability readmodel 或 metrics store，避免统计写入频繁推动主 committed revision。

**验收覆盖：**
- `TestLongIPsecReconcileDoesNotBlockCommittedReaders`
- `TestLongBirdReconcileDoesNotBlockCommittedReaders`
- `TestLongFirewallReconcileDoesNotBlockCommittedReaders`
- IPsec/firewall stale commit 测试覆盖旧 snapshot result 不覆盖新 revision，并在冲突时重新置 dirty。
- `make check` 通过，包含 `go fmt ./...`、`go vet ./...`、`go test ./...`、`go build ./app/photon`。


## Phase 7 已完成项归档

### 7.1 异构 TransportLink 并行共存（模型、实验与公共边界）

- 冻结 D1-D8：一个 LinkGroup 对应一个 provider；静态 Babel base cost 属于 LinkGroup；Link ID 包含 provider；WG device 按 LinkGroup 与 underlay family 共享；health 第一版不接管 BIRD；IPsec/WG 各自使用 ports record 与 overlay intent；provider 各自拥有 lifecycle/resource graph，daemon 只统一调度 Babel-facing 输出。
- `TestBabelDualInterfaceCostFailoverRootSmoke` 验证 BIRD 双接口 cost failover；`TestWireGuardGREThreeNodeRootSmoke` 验证共享 WG device、多 peer、独立 GRE/Babel interface 的三节点数据面；`TestWireGuardGREStagedRotateRootSmoke` 验证 old/staged device、GRE cutover、listener/firewall grace 与零引用清理。
- 收敛为长期维护 StrongSwan/XFRM 与 WG/GRE 两套独立 lifecycle，撤回未进入生产路径的通用 provider plan/action/resource graph 与 StrongSwan adapter。
- `internal/state.LinkOutput` 成为 provider-neutral、只读的 Babel-facing 契约；health、firewall、BIRD health observation 与 `links_status.outputs` 都消费该输出，且不能反推 provider 的 apply/teardown 内部状态。

### Zone 写权限语义收口

- 普通网络节点使用通用 `write` 维护本 Zone control-plane records；relay 不持有 Zone authority 或私钥，仅转发已验证 gossip。
- 移除 `write:route`、`write:service`、`write:wireguard` capability 及其 record type 映射，route/crypto 回归测试覆盖统一权限语义。

### 7.16 Firewall backend-native inline hooks

- `firewall.instances[]` 支持 `nft_hooks` 及按 `ipv4` / `ipv6` 分组的 `iptables_hooks`；两套配置可并存，`backend: auto` 会选择可用且匹配已配置 hook 的 backend，debug 明确标记 active/inactive。
- 覆盖 overlay 的 `pre/post_input`、`pre/post_forward`、`pre/post_output` 与 host 的 `host_pre/post_input`、`host_pre/post_prerouting`。hook 规则按 YAML 顺序编入 Photon managed chain/generation；invalid drop 等基础安全规则和 post hook 的相对位置由 planner 测试锁定。
- nft 规则作为单条 rule body 与 managed table 进入同一个原子 batch；iptables 按 argv 执行，拒绝 shell 元字符和 chain/table 管理参数，并在 IPv4/IPv6 inactive generation 均准备成功后才切换 builtin-chain jump，失败时保留/回滚旧 generation。
- 移除了旧 `hooks:` 管理员外部 chain 入口及其兼容逻辑；只保留 backend-native inline hooks。hook 点、backend、family、顺序和原始表达式都进入 desired-state hash。
- 增加 hook 配置/strict field、顺序、backend 选择、双栈 family、危险参数、staging/activation rollback、dry-run/debug 等单元测试，并完成 nft overlay/host root smoke。真实 iptables root smoke 仍需在同时具备 `iptables` 与 `ip6tables` 的环境复验。
- 随后补齐 `mode: external` 只读语义、完整 iptables/ip6tables availability 检查与明确 warning，以及 nft `priority.filter`、`priority.prerouting`、`priority.postrouting`（默认 `filter`、`dstnat`、`srcnat`）的受限偏移配置。

### 7.3 Gossip UDP object chunk repair

- UDP chunk fallback 保持为 TCP object pull 不可达时的兜底，不扩展成通用可靠传输。
- 每个发送使用随机 16-byte `transfer_id`；接收端在 150ms quiet 后发送 `object_chunk_nack`，只列出缺块索引，完整 hash 与签名链验证通过后才 apply。
- 发送端只从 30 秒 TTL 的已发送缓存 repair；单 transfer 最多 3 轮、单 NACK 最多 128 个索引、单 peer 最多 4 个 inflight transfer、全局发送缓存最多 32 MiB。NACK 与 repair chunk 继续受 datagram budget、replay 和 peer quota 约束。
- `sync status --verbose` / `debug peer` 增加 repair NACK、repair chunk 和 ignored request counters，区分首次 fallback 与 repair 流量。
- `make check` 和 `make chunk-fallback-smoke` 通过；smoke 先覆盖乱序丢块、重复 NACK、过期/错误 transfer，再验证真实 daemon 在 TCP pull 不可达时经 UDP fallback 收敛。

### 7.10 Daemon / 本地控制接口生产化

- daemon 统一承担 gossip、committed state 和各数据面 runtime apply；CLI 写入优先走 Unix control socket，显式 `--direct` 仅用于离线或恢复场景。
- control socket 固定为 root-only：默认 `/run/photon/photon.sock`，目录/socket 权限 `0700`/`0600`；拒绝覆盖活跃 socket 或同名普通文件，仅清理确认失效的 socket。
- fallback 只接受 socket 不存在或明确 `ECONNREFUSED`；超时、权限、连接重置和协议错误不回退到直接 DB 写入。
- `internal/controlapi` 承担 Unix JSON transport、deadline 和 unavailable 分类。公共业务 DTO/typed client 暂不迁移，等出现实际复用需求再评估。
- 不做多用户 owner/group、只读/管理方法分级或 TCP listener；远程管理有需求时再单独设计鉴权。
- control API surface、离线策略、daemon 生命周期、systemd 运行方式和 BIRD shutdown policy 已形成文档。

### 7.13-7.15 稳态冗余优化

- **7.13 XFRM maintenance：** 已匹配的接口利用 observed flags/address 短路，避免重复执行 interface/address 维护命令，同时保留必要的周期自愈。
- **7.14 endpoint timer：** `runStateStoreWriteIfChanged` 只在 endpoint/IPsec/routing 记录实际变化时提交状态并触发 sync/reconcile；稳态不再递增 revision 或 flush 数据面。
- **7.15 unsolicited ping：** 收到带 catalog summary 的 ping 时先比较本地 root；一致则更新 peer sync 状态并回复 pong，不创建冗余 `SyncSession`，不一致时仍正常拉取差异。

## Phase 8 已完成子项归档

### 8.1 最小 service record 与显式发布

- 定义 `services/socks5` / `service.socks5.v1` record，支持 endpoints 数组、多 endpoint、旧单 endpoint 字段与可选 `active`。
- `photon service publish/withdraw` 校验地址归属当前节点 active assignment（普通或 shared），撤销通过 `active:false` 新版本表达。
- service record 使用通用 `write`、严格 schema 与 route-authorization 归属验证；Photon 主配置不再包含 Docker/Compose/service instance 模型。

### 8.2 独立 Compose 生成与 host/overlay 网络接入

- 独立 `photon-services` 读取 `/etc/photon/service.yaml` 并通过 `photon route ipam mine` 生成覆盖全部双栈 external network 的 Compose；支持多 network、`auto`/`tag:` assignment、相对 base address 与 resolved lock。
- 固定 SOCKS5 输出 `socks`、`dns`、`h2` 三容器，只原子写 artifact，不执行 Docker 生命周期操作。
- 校验 Docker subnet、host connected route、host→Photon netns 聚合路由与 overlay→host static upstream；服务前缀的 Babel export 仍限于实际拥有/获授权前缀。

### 8.3 发布、防火墙与运行状态

- 通用 endpoint ACL 持久化 `{destination, protocol, port, selectors}`，动态解析授权 overlay 来源；host FORWARD 先 allow 后精确 drop，空匹配 fail-closed。
- `photon-services publish` 校验 resolved lock / assignment、TCP 健康与 ACL，再发布多 endpoint record；withdraw 按 record、shared route、ACL 的顺序清理。
- 增加 `services` / `proxy` 本机诊断，展示地址归属、路由、firewall、readiness 与当前 record。

### 8.6 IPAM shared Anycast 与多网络发布

- shared assignment 支持稳定 tag；同 tag/地址族对应同一 prefix，成员按 owner 独立存储，并支持精确 revoke。
- `ipam.announce` 支持 `non-shared` / `tag:<tag>` selector；服务生命周期控制 Anycast announcement。
- publish 可由 `network: region` 同时发布本地和多个 Anycast endpoint；shared endpoint 宣告 assignment prefix 而非 host route。
