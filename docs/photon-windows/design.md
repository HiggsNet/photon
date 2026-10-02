# Photon Windows 设计

> 状态：实现中  
> 首个目标：Windows 11 amd64 prototype  
> 对应任务：[todo.md B](../../todo.md#b-photon-windows-当前主线)

## 1. 产品边界

Photon Windows 是一个独立的 Windows 叶子客户端，程序入口为
`app/photon-windows`，发布产物为 `photon-windows.exe`。它不是现有 Linux
`photon daemon` 的 Windows 交叉编译版本，也不尝试在 Windows 上模拟 StrongSwan、
XFRM、BIRD 或 network namespace。

第一版固定以下边界：

- outbound-only IKEv2 initiator；
- 一个 active Photon gateway；
- 用户态 ESP tunnel mode；
- 内嵌 Babel leaf 和用户态 source-specific route table；
- Wintun 承接 Windows TCP/IP stack 的 L3 packet；
- split tunnel，只向 Windows 安装稳定 Photon aggregate route；
- 不做 transit、IKE responder、lite-to-lite、full tunnel、DNS/NRPT、GUI 或 auto-update。

### 1.1 v1 支持与验收矩阵

首版支持目标固定为 Windows 11 amd64。Windows 10、Windows Server、arm64 和模拟运行均不进入
首版支持承诺，须在第一个真实 vertical slice 后分别补齐 CI 与设备验收才能扩展。此处是产品范围，
不是已通过兼容测试的声明；当前 Linux 上的测试和 Windows 交叉编译只证明公共逻辑与编译边界。

| 环境 | 当前验证用途 | 发布前必须补齐 |
| --- | --- | --- |
| Linux 开发主机 | config、State、公共 gossip 与 memory convergence 测试；Windows amd64 交叉编译 | 不替代 Windows 运行验收 |
| Windows 11 amd64 VM | 首版运行验收目标 | 真实 UDP、Wintun、IP Helper、SCM、停止/重启/崩溃恢复 |
| Photon Linux gateway | 协议互通目标 | StrongSwan IKE/ESP、BIRD Babel、撤销后停止转发 |

多个 `gateway.allowed_zones` 表示候选集合，不表示多个同时转发的 gateway。切换时先停止旧 gateway
承载业务，再启用新 gateway；同一 gateway 的 rekey overlap 不视为第二个 active gateway。
`overlay.split_routes` 只限制本机接入隧道的地址范围，不授予 route origin 权限。
DNS/NRPT、默认路由和系统代理不由本产品修改。服务启动后配置保持不变，修改配置通过重启应用。

首版算法实现范围依据 Linux 现网与两个实际构建的隔离互通结果确定（§1.2），
不要求既有 Linux 节点先更换算法。B1 的范围定义已完成；Windows 实现与真实互通仍由 B3 验收。

Photon Android 是后续独立产品。两个产品可以复用 portable core，但 Windows Service、
Wintun、IP Helper、named pipe 和 Event Log 不进入 Android 依赖图。

### 1.2 Linux 算法兼容基线（2026-10-01 现场与隔离验证）

兼容目标是接入现有 Linux Photon 网络。必须分开记录：构建所带插件的能力、连接允许协商的
proposal 集合、某次 IKE/CHILD_SA 实际选中的算法。三者不能互相替代，也不能把 ESP 算法
直接当作 IKE 算法。此前提出的 IKE GCM-only、X25519-only、强制 CHILD PFS 方案已撤回。

**现场证据。** 2026-10-01 10:29:56 UTC，通过 SSH 只读检查 `10.16.255.7`（less）：

- Photon commit `28472ea`，dirty=false；StrongSwan daemon `6.0.7`，Linux `6.18.39`，x86_64。
- `swanctl --list-sas` 中 36 条 IKE SA 全部为
  `AES_CBC-128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/ECP_256`。
- 36 条 CHILD_SA 全部为 `TUNNEL-in-UDP`、`AES_GCM_16-128`：22 条还显示 `ECP_256`，
  14 条没有显示独立 KE；这里是两个瞬时 SA 状态，不据此推断每条连接的完整 rekey policy。
- `swanctl --list-certs --type pubkey` 列出 21 项 ED25519 公钥；本机和已加载 peer 使用 raw public key
  认证。没有读取私钥材料，没有重新建链或主动触发 rekey。
- `swanctl --list-algs` 同时列出 AES_CBC、AES_GCM_16、PRF_HMAC_SHA2_256、ECP_256 与
  CURVE_25519。支持 X25519 不代表当前协商用了 X25519，也不单独证明任意 proposal 能互通。

| 层次 | 当前观测 | Windows 兼容工作依据 |
| --- | --- | --- |
| IKE 加密 | AES-CBC，128 位密钥 | 首先覆盖该现网组合；不能只实现 IKE GCM |
| IKE 完整性 | HMAC-SHA2-256，128 位截断 | 与 IKE 加密和 PRF 分开实现 |
| IKE PRF | HMAC-SHA2-256 | 这是现网已有的密钥派生参数，不是新增线上要求 |
| IKE KE | ECP_256，即 NIST P-256 | 不能与 X25519 混为一谈；优先覆盖现网 P-256 |
| ESP 数据加密 | AES-GCM，128 位密钥，16 字节 tag | `16` 指 tag 字节数，`128` 指密钥位数 |
| CHILD KE | 同时观察到 ECP_256 和无独立 KE | 首个 CHILD、独立 CREATE_CHILD_SA、双方发起 rekey 分别验证 |
| 认证 | 已加载公钥为 Ed25519 | 与密钥交换的 P-256 是两个不同用途，不冲突 |

IKE 实测组合可用 StrongSwan 名称 `aes128-sha256-prfsha256-ecp256` 表达；这是对实测结果的
翻译，不是要求修改 Linux 配置。算法名称参见
[StrongSwan 算法表](https://docs.strongswan.org/docs/latest/config/proposals.html)。

**构建与配置边界。** Photon 的 `BuildStrongSwanConnection` / `routeBasedChildSA` 不设置
`proposals` / `esp_proposals`，由 StrongSwan 默认 proposal 与对端共同决定结果；当前使用
`version=2`、`auth=pubkey`、`encap=yes`、`mobike=no`、`mode=tunnel`。Go 构建产物本身不内嵌
StrongSwan：Docker 安装 Ubuntu 24.04 的发行版包，native/NixOS 使用宿主机包。
不能用 less 上的 6.0.7 代替 Docker/Ubuntu 构建的版本与插件验收。

StrongSwan 的默认 ESP proposal 存在版本差异：6.0.2 起加入可选 KE，而旧版本默认不要求
独立 CHILD KE。首个 IKE_AUTH CHILD 的密钥派生又不同于 CREATE_CHILD_SA；因此不能只验证
首次连通后就强制 X25519 PFS。参见
[默认 proposal 说明](https://docs.strongswan.org/docs/latest/config/proposals.html#_default_proposals) 和
[CHILD 配置说明](https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html)。

**隔离互通证据。** `TestStrongSwanAlgorithmInteropSmoke` 复用 Linux 连接生成器、真实双 charon、
Ed25519 密钥和 XFRM；比较双方默认配置与仅 A 限定候选 proposal 两种情况，B 始终保留默认配置。
每种情况分别测试 IPv4/IPv6 内层流量（外层为 IPv4），建链后由 A、B 分别发起 CHILD 和 IKE rekey，
检查双方 SA ID 更新、收发 SPI 对应，并在每次 rekey 后执行双向隧道 ping。测试已接入现有
`ipsec-xfrm-smoke`，没有修改生产连接生成器。

| 实际测试依赖 | 4 个场景 | 首个 CHILD | 后续 CHILD rekey |
| --- | --- | --- | --- |
| Ubuntu 24.04 StrongSwan `5.9.13-2ubuntu4.24.04.5`，与 Dockerfile 相同的 StrongSwan 包集合 | 全通过，2.84 秒 | AES-GCM-16-128，无独立 KE | AES-GCM-16-128，无独立 KE |
| 本机 Nix StrongSwan `6.0.7`，只读挂载到隔离容器 | 全通过，3.05 秒 | AES-GCM-16-128，无独立 KE | AES-GCM-16-128，P-256 |

两组 IKE 均为 AES-CBC-128/HMAC-SHA256-128/PRF-HMAC-SHA256/P-256。
每一行是同版本双端测试，不是 5.9 与 6.0 直接互连；候选端同样由 StrongSwan 执行，不能当作
Windows 已实现。原有 ECDSA bring-up smoke 在 Ubuntu 上也通过。构建期间的 `/sys` 挂载限制
使用项目现有容器 smoke 的 `nsenter` 适配解决，未修改宿主机网络或现网服务。

**首版实现集合。** 以已经通过上述测试的候选集合为基线：

- IKE：`aes128-sha256-prfsha256-ecp256`；认证使用 Ed25519 raw public key。
- ESP：`aes128gcm16-ecp256-none-noesn`；首个 CHILD 按 IKE_AUTH 规则派生密钥；
  CREATE_CHILD_SA/rekey 支持 P-256 或无独立 KE，优先 P-256，兼容旧版默认无独立 KE。
- 不增加未经验证的替代算法或 X25519-only 限制；集合之外明确报协商失败，不临时放宽身份或算法。
- IKEv1、PSK/EAP、证书 CA 信任回退、未验证公钥不进入首版。rekey 失败不能越过 SA 到期、
  授权失效或序号上限继续发送；断线按已有 backoff 重试。

B3 仍须以真正 Windows 实现验证相同集合、双方 rekey、外层 IPv4/IPv6、NAT 变化和错误
proposal/身份/公钥的拒绝；本轮没有执行这些 Windows 或负向验收。任何更窄或新增的 proposal
都须另有双向互通证据，不默认要求 Linux 改 profile。

认证继续依据 verified transport-key/profile 与 Zone 身份绑定，不能仅凭 CERT 接受陌生公钥；
Ed25519 签名与 raw public-key 编码依据 [RFC 8420](https://www.rfc-editor.org/rfc/rfc8420.html) 和
[RFC 7670](https://www.rfc-editor.org/rfc/rfc7670.html)。具体 ID wire 编码仍须在互通测试中确认。
本次证明一个现场样本与上述两个隔离构建的算法基线，不宣称 Windows 已兼容或覆盖全部 Linux 构建。

## 2. 数据流

```text
Windows applications / TCP-IP stack
                |
                v
             Wintun
                |
                v
       portable packet engine
                |
                v
   SADR lookup (source, destination)
                |
                v
       selected gateway / ESP SA
                |
                v
   shared UDP socket (IKE + ESP demux)
                |
                v
      Photon StrongSwan/BIRD gateway
```

Babel control packet 不通过 Wintun。portable core 为每个已建立 ESP peer 构造标准
IPv6 link-local UDP/6696 packet，直接交给该 peer 的 ESP send path；收到 ESP plaintext
时也先识别 Babel control packet，再决定是否写入 Wintun。

这样可以避免把 Babel multicast membership、link-local scope 和 UDP/6696 socket 暴露给
Windows 虚拟接口，同时保证业务 packet 仍使用 Windows 自带 TCP/IP stack。

## 3. 信任边界

Photon Windows 继续消费 Photon 的可信事实层：

- Zone authority 与 delegation chain；
- signed record、revocation 和有效期；
- IPAM pool/assignment；
- route announcement authorization；
- transport key、profile、address、port 和 overlay intent。

静态 gateway address 只能作为 bootstrap hint。IKE responder identity 必须匹配已验证的
transport record，Babel route 必须在写入 SADR table 前通过 `AuthorizedRouteSet`。

### 3.1 route-origin 安装契约

v1 的路由准入须同时满足以下条件，缺失任何一项都不得安装或继续使用：

1. 接收路由的 SA 属于当前 active gateway；gateway 的 identity、transport key、overlay 和撤销状态
   均由当前 verified records 确认，bootstrap hint 和配置 allowlist 不能替代验证。
2. Babel 64-bit Router ID 必须无歧义地绑定到 verified origin Zone。绑定缺失、冲突或失效时拒绝该路由；
   不能把 next-hop gateway 自动当作 origin，也不能因为某个 Zone 授权了同一 prefix 就放行。
3. 使用当前 verified snapshot 与当前时间构建 `routing.BuildAuthorizedRouteSet`，匹配
   `Announced[origin][prefix]` 的有效授权，并限制在配置 split aggregate 内。SADR 的 source prefix
   同样须通过明确授权规则；规则未实现时拒绝带 source constraint 的路由，不静默丢弃该约束。
4. 安装前检查规划所用 `VerifiedRevision` 仍为当前值；异步完成过期时丢弃并重新规划。
   record 到期也须触发重新校验，不能只等待 revision 变化。

撤销或授权收紧时先使 packet lookup 中的旧授权不可用，再异步清理路由和 SA；失败不能恢复旧授权。
Windows aggregate route 只把流量送入 Wintun，不能绕过用户态逐路由授权。

以上是安装与撤销的验收契约。Router ID 派生、碰撞处理及端到端 binding 的 wire 方案仍须在 B4 实现
并验证；仅从身份稳定派生 Router ID 不能证明收到的 origin 声明可信。在绑定完成前，prototype
只能作为显式选择单个可信 gateway 的 experimental 实验，不能作为 production security boundary 发布。

### 3.2 本机私钥模型

Photon Windows 沿用 Photon Linux 的管理员责任模型。root、Zone identity 和 transport 的
Ed25519/private key material 可以作为普通原始字节直接保存在同一个
`state.BoltStore` 中，不强制 DPAPI、CNG、NCrypt 或 non-exportable key。

本项目不宣称抵御已经取得本机 Administrators/SYSTEM 权限的攻击者；数据库文件、备份、磁盘和
主机访问控制由管理员负责。安装器可以设置合理 ACL，但 ACL/磁盘加密不是 Photon 协议正确性的
前置条件。程序仍必须避免把私钥写入日志、IPC、Observer、gossip、crash diagnostics 或导出的
Zone snapshot；这是防止意外远程泄漏，不是把进程内 Store 当作不可信边界。

公共 Store 直接根据当前 authority 从同一事务 candidate 选择授权私钥并调用公共 Ed25519
sign/verify。Windows 与 Linux 不维护两套 signer/key-store adapter，也不为硬件不可导出密钥改变
state transaction 语义。未来若需要平台加固，只能作为兼容相同持久化和签名语义的可选扩展。

### 3.3 Verified state 与 Gossip runtime 边界

`VerifiedState` 只保存会影响信任结论的事实：managed Zone、已验证 Network、完整 Ed25519
`trusted_root_public_key` pin 以及本机
raw private key。它不包含 peer session 或同步统计。

Gossip 状态分成两类：session phase、round/catalog cursor、timer generation、chunk assembly、repair
cache 和在途 object-pull 是协议正确性所需的活状态，只存在于 Engine/GossipDriver 内存，重启后重新同步；
backoff、最近 endpoint、observed grace、relay suppression 和 rejected digest TTL 是可丢失的
`GossipCheckpoint`，丢失最多带来额外重试或重新发现，不能改变验签、授权与最终收敛。attempt/error、
hint/responder、datagram/object-pull 等纯统计进入有界 observability/metrics，不进入公共持久状态。

公共状态只保留一个 `VerifiedRevision`，仅在已验证 Network 内容发生变化时推进。
`GossipCheckpoint` 没有独立 revision；checkpoint-only 保存不会让下游 controller 误以为可信事实变化。
平台 runtime checkpoint 也不反向修改 verified，只记录它所基于的 `SourceVerifiedRevision`。同一个
`state.BoltStore` 可在一次 bbolt transaction 中原子保存这些逻辑分区，但不会创建第二个 DB handle、
writer goroutine 或 event loop。

公共 bbolt schema 由 `pkg/core/state` 固定为 `photon:common-state` 根 bucket，其下分别保存 schema/revision、
verified payload 与 gossip checkpoint。codec 只接收唯一 `state.BoltStore` 已打开的 `*bolt.Tx`，不打开、
提交或关闭数据库；Linux/Windows 因而可以在同一个 `Update` 中组合自己的 runtime bucket。写入只检查
verified payload 变化是否恰好推进一次 `VerifiedRevision`，checkpoint 变化不参与版本竞争；最终
commit/rollback 仍由平台唯一 writer 决定。
schema、revision 或 verified payload 损坏时 fail closed；checkpoint JSON 损坏时加载空 checkpoint 并返回
discard report，重启后的重新发现与同步负责恢复效率提示。

`TrustedRootPublicKey` 是本机 trust-anchor pin，不是可由 gossip 更新的普通 verified 字段。当前协议没有定义
root-key rotation，因此在线 Store/codec 拒绝修改 pin，远端 root snapshot 也不得替换既有 root authority；
它只能在 authority 完全相同时更新由该 authority 验证的 root Zone 内容。未来若增加 root rotation，必须
先定义由旧 trust anchor 授权的新 pin 迁移协议，不能复用普通 snapshot apply。

Linux 旧 `_meta/cli_state` 与 `zone:*` 迁移也只接收唯一 `state.BoltStore` 提供的事务：同一事务写完公共
state bucket 和 `photon:linux-runtime` bucket 后删除旧表示，失败整体回滚，新旧表示同时存在则拒绝启动。
迁移已接入 Linux 启动和离线打开数据库的入口，是单向旧数据库升级，不提供新 bucket 到旧 aggregate
的反向 view、双写或字段别名。Windows 不接受 Linux 旧布局，也不复制 Linux 迁移入口。

公共 `state.BoltStore` 是唯一持久化 owner，统一持有 bbolt handle、事务顺序和关闭生命周期。Linux 只提供
自己的 bucket codec 与事务组合函数，不再定义平台专属的持久化 Store。首次加载在同一事务内
迁移并读取完整 aggregate，公共状态与 Linux runtime 写入均复用该 handle。字节完全相同的提交回滚为空操作；
公共状态校验或提交失败会连同同事务的平台 payload 一起
回滚。第二个进程/handle 必须在有界超时后因文件锁冲突失败，Close 错误必须返回给生命周期 owner。Linux loader/writer 已完成切换，不保留第二套在线写入路径。

Metadata-only 写入不产生新的版本域：Gossip checkpoint 仍通过同一 BoltStore 保存，但保持当前
`VerifiedRevision`；Linux controller completion 只更新平台 runtime bucket，提交时将其开始计算时读取的
`VerifiedRevision` 与当前公共状态对照。二者不一致表示 completion 已过期，整笔事务回滚并重新规划。该检查
只消费唯一 verified revision，不允许 controller 更新 verified payload，也不引入 runtime/checkpoint revision。

启动时 `BoltStore.LoadCommon` 返回 detached candidate 和磁盘中的唯一 `VerifiedRevision`，公共
`RestoreStore` 校验状态根并再次 detach 后恢复内存状态。后续可信 Network 提交从该 revision 继续递增，不能
因进程重启回到 0；Gossip checkpoint 仍随 candidate 恢复但不拥有自己的 revision。

## 4. 代码边界

```text
app/photon-windows
  CLI/version and the one Windows composition root

pkg/core/host.GossipDriver
  the one common gossip/event/scheduler runtime

pkg/core/state.Store + BoltStore
  the one verified/checkpoint state owner and database handle

internal/photonclient
  portable userspace client data plane only
  ike / esp / babel / sadr / packet pipeline

internal/photonwindows
  SCM service, Wintun, Windows socket/IP Helper, named pipe, Event Log

pkg/core + pkg/crypto + pkg/routing + pkg/transport/ipsec
  reusable Photon verified facts and transport record model
```

Gossip 不做 Windows 分支。`pkg/core/state` 统一拥有 verified snapshot、zone digest、catalog DTO/
root/diff/projection 和 `ApplySnapshot`；`pkg/core/gossip` 直接引用这些 DTO，统一拥有 wire message、
依赖实际 wire-size 的 catalog page 装箱、object-pull、chunk 与 quota。Linux daemon 与 Photon Windows
直接链接同一组公共包，Windows 只注入 datagram/network adapter；不得复制协议源码到
`internal/photonwindows`，也不得引入 Windows 专属 snapshot 或“精简 gossip”语义。
每 peer 无 I/O 的同步 FSM 也位于 `pkg/core/gossip`；Linux daemon 已直接引用公共事件、action 与状态机，
Photon Windows 后续复用同一入口，不在自己的 composition 中保留类型别名或转发函数。
有界 packet receive loop 位于 `pkg/core/host`，由唯一 `host.GossipDriver` 持有，只依赖
`DatagramReceiver` 的 `Receive/Close` capability。Linux `Transport` 与未来 Windows adapter
共用该 loop；packet 直接进入 GossipDriver 默认的 64 项 event queue，与协议 timer/completion 共用同一
backpressure 和顺序边界，不创建第二条 packet channel 或 per-packet goroutine。`GossipDriver.Stop` 取消接收、
关闭 receiver 以解除不感知 context 的阻塞读取，并等待 receive goroutine 退出。`gossip.Transport`
不再持有 `UDPConn` 或执行 bind/read/write，只通过 `DatagramIO` capability 使用注入的 packet socket；它继续
统一负责 wire codec、allowlist、replay/quota 和地址选择。Linux 的 bind、`SO_REUSEPORT`、read/write/deadline
实现位于 `internal/photonlinux`，未来 Windows 注入自己的 adapter，不复制 Transport 策略。
TCP object-pull 的 listener 生命周期同样由唯一 GossipDriver 持有：平台 composition 只创建并注入
`net.Listener`，GossipDriver 统一执行有界 accept、连接 deadline、过载关闭、context cancellation 和 shutdown drain。
`pkg/core/gossip` 继续唯一拥有 object-pull framing、codec 与 request/response 语义；Linux app 目前只保留
listener/client 的 composition 与 verified-state lookup，不另建 server worker/event queue。公共 host executor 统一
地址选择、peer 并发、quota、响应校验和 completion/diagnostics 结果；Linux TCP adapter 只执行 dial、deadline 和
一次 stream exchange，Windows 后续注入等价 adapter 即可。
active-session/unsolicited packet classifier 也位于同一 `pkg/core/gossip`；它只按已验证
message 的 `PeerID` 查询当前 `SyncSession` map，不解释 message type。当前 Linux composition 负责仍未收口的
responder、状态提交和日志接线；这些公共执行语义应继续进入 GossipDriver，不能在 Windows 再实现一份。
daemon 的 sync、endpoint publisher、IPsec、routing、firewall 和 health 周期 deadline 由 Daemon 自己的 Scheduler/queue
管理；GossipDriver Scheduler 只处理协议 timer。两条队列分别保持平台编排与 gossip action 的 single-writer 顺序，
Windows composition 不得把平台 completion 回投到 GossipDriver。
同步事件的稳定诊断名和 peer ID 提取也由公共包提供，executor 不重复维护 event type switch。
在 classifier 之后，共享 inbound planner 统一解释 message type，产出有序的 session-event、
Ping/fetch responder、announce、chunk 或 NACK action。它固定 active/unsolicited policy 和
nil payload 的 fail-closed 行为；平台 composition 只执行真正的平台副作用。
Read-only fetch 分类与 Ping response message planning 同样共享：公共逻辑固定 responder 标签、
catalog-root equality，以及 Pong 后按需请求 catalog page 的顺序；executor 负责读取本地 summary、
观测和实际发送。
`gossip.Engine` 是同步 FSM/session registry：拥有 per-peer session 与 pending announce hint，但不拥有
event queue、timer 资源、数据库或平台副作用。公共 `host.GossipDriver` 拥有 bounded event queue 和单
heap/wakeup Scheduler；timer policy/期限仍由 gossip session action 决定，Scheduler 只统一执行
replace/cancel、generation stale 防护、背压和 stop。Linux daemon 已把共享 receive loop 产出的 verified packet
注入 GossipDriver event queue；Photon Windows 后续必须走同一入口和 action 顺序。
send action 到 wire message 的映射由 gossip 唯一实现；GossipDriver 的公共 action plan 固定
apply -> outbound -> object-pull -> timer -> backoff/persistence 分相和 persistence scope 合并。
平台 controller 只执行各相，不得再次按具体 gossip action 类型建立 switch。

因此平台注入边界不只有 UDP：至少还包括 timer clock、verified state projection、snapshot
apply/object-pull completion，以及 send/persistence/log effect executor。公共 gossip 不 bind socket、
不打开数据库，也不创建平台资源；协议 timer/receive goroutine 只依赖注入的 capability，具体 UDP
adapter 不泄漏进状态机。
UDP object chunk assembly、quiet-period NACK 和 sent-chunk repair cache 也复用
`pkg/core/gossip` 的同一实现。共享策略固定 object/hash/metadata 校验、per-peer inflight、
repair rounds、NACK index、TTL 和内存 byte 上限；GossipDriver 负责公共 NACK/chunk 与完整对象处理，平台只提供
实际 I/O，不在 Linux/Windows 各保留一套 executor。
Datagram announce planning、wire-size/MTU budget 计算和 zone snapshot chunk packing 也位于
gossip。它直接使用 state 的 `ZoneRoot`，统一排序、oversized 分类、object/root hash 与 chunk metadata；平台 executor
只提供随机 transfer ID，并承担 sent cache、UDP send 和日志副作用。

portable core 不得：

- 创建 Wintun/TUN；
- bind 系统 UDP socket；
- 修改 OS address、route、metric 或 DNS；
- 安装/控制 Windows Service；
- 读取 Windows registry；
- 监听 Unix signal。

`app/photon-windows` 是唯一 Windows composition root：它创建顶层 Daemon、一个公共 GossipDriver（当前类型
`pkg/core/host.GossipDriver`）、一个拥有公共 `state.BoltStore` 与 `pkg/core/state.Store` 的 `photonwindows.State`、WindowsDriver/WindowsState，
以及未来真正出现的用户态 packet engine。不得再建立一个持有这些组件的通用 `photonclient.Runtime`，也不得让事件按
`photonclient -> host -> photonclient` 往返。完整命名和持久化边界见 `docs/runtime-state-ownership.md`。

平台接口只在真实 consumer 出现时按最小调用面提取。编译目标已经区分 Windows/Linux，初始化失败由对应
composition root 当场返回；不建立包含所有未来能力的 `Resources` bag，也不通过 nil 检查探测当前平台能力。
`internal/photonclient` 只承载 Windows/Android 未来可复用的 IKE/ESP/Babel/SADR/TUN packet pipeline，不拥有 gossip、
公共 Store 或产品生命周期。尚未实现的数据面不提前冻结接口。

本机 identity 私钥属于公共 `VerifiedState`，不通过独立 `StateSnapshot/StaticSource` 或平台 key capability 复制发布。
网络同步、CLI intent 和 controller planner 读取同一个 Store；bbolt handle 也只有 Windows composition 持有的一份。

## 5. 生命周期

Windows service/composition 只有在配置、State、GossipDriver 和当前实际启用的平台组件初始化完成后才进入
`running`。组件在自己的构造入口返回具体初始化错误，不先注入 nil 再做通用 capability 扫描。关键后台 loop
意外退出时 service 进入 `failed`，不能继续报告 ready。

正常停止顺序：

1. cancel service context，停止接收新的 Wintun packet；
2. 用户态 packet engine 撤销 route、停止 peer 并清理 SA；
3. 停止 GossipDriver 并关闭其 gossip transport；
4. 关闭 Wintun session/device；
5. 关闭 Windows network observer 和平台资源；
6. 最后关闭 Store/BoltStore，并报告最终状态。

Windows address/route 的 ownership 和回滚属于 `internal/photonwindows`，不由 GossipDriver 或 portable packet
engine 猜测。service crash 后下一次启动只能 adopt 带匹配 owner/generation 的资源。

### 5.1 v1 生命周期验收目标

以下时限是待实现和测量的 v1 验收目标，不是当前性能数据。测试使用本机单调时钟，记录触发事件、
停止旧流量、资源收口和最终状态；不把公网传播、DNS 响应或远端可达时间计入本机处理时限。

| 事件与计时起点 | 先执行的安全动作 | 本机完成目标 |
| --- | --- | --- |
| 撤销/授权收紧：本机接受新的 verified revision；到期：本机授权期限到达 | 从该授权失效点起，后续 packet lookup 不得继续选中旧路由；在途发送须在最终提交前重新检查 | 1 秒内完成用户态 route/SA 失效处理，5 秒内完成相关 owned OS 资源清理 |
| 网络变化：收到 Windows 网络通知 | 使旧 socket/路径 generation 失效，过期 completion 不得重新启用旧路径 | 1 秒内开始重新观察与 rebind；单次本机 I/O 取消和关闭 5 秒内结束 |
| service stop：SCM stop 或 console cancellation 到达 composition | 停止接收新业务 packet，按本节顺序关闭资源，不启动新的重连 | 10 秒内完成正常关闭；超时报告 failed，列出未释放的 owned 资源，不报告 stopped 成功 |
| crash recovery：下一次进程启动进入 composition | 在重新验证可信状态、ownership 和新 SA 前保持数据面关闭；不恢复旧 SA sequence/replay window | 30 秒内完成本机资源检查与 adopt/清理，进入可连接的 disconnected 状态或明确 failed；不以远端连通作为期限前提 |

网络持续不可达时按配置 backoff 重试，并维持 disconnected；上述期限不承诺 VPN 建立时间。
进程崩溃到下一次启动的延迟由 SCM/管理员控制，不计入 recovery 时限。无法证明归属的 OS 资源
不得删除；出现冲突则失败退出并报告具体对象。资源清理超时不能重新开放已失效的授权。

验收至少包括：可持续发包时注入撤销、无 revision 变化的 record 到期、断网/换网时保留过期 completion、
阻塞 I/O 时停止、部分初始化失败、强制结束后重启，以及同时存在外部同类资源。必须观察真实发包
与 OS 资源结果；fake clock 和 memory 测试仅验证顺序与超时分支。B2/B4/B5/B6 分别实现并验收这些条件。

## 6. 当前首个切口

早期实现建立了可交叉编译的产品和 capability 骨架。F0 实验验证了具体 State、公共 BoltStore、GossipDriver 与
gossip Transport 可以完成双节点收敛，也暴露出 `photonclient.Runtime`、通用 `Resources.Validate` 与 gossip
controller glue 重复了已有公共 gossip 执行闭环。该套层已经删除；Store 恢复入口现位于 `internal/photonwindows`，
双节点测试直接驱动两个 GossipDriver、两个 State 和真实 Transport。

F 阶段修正为以下顺序：

- 可交叉编译的 `photon-windows.exe` 命令骨架；
- 公共 `state.BoltStore.LoadCommon/RestoreStore` 恢复唯一 Store，校验 root pin/managed zone；
- 已撤回 `photonclient.Runtime`、通用 `Resources` capability bag 和 client gossip controller glue；
- memory 双节点验收已直接围绕 GossipDriver/State/Transport，不创建第二个 runtime；
- 让公共 GossipDriver 的协议执行边界足够完整，Windows composition 不复制 Linux gossip executor；
- Photon Windows schema v1 与离线 `config validate`；
- Linux unit tests 与 Windows amd64 compile guard。

完成上述边界纠偏后才接 Windows UDP；Wintun、IP Helper、SCM、IKE/ESP/Babel 实现分别在
后续窄切口加入。未实现的命令不得伪造
connected/ready 状态。

### B2 console 当前实现与验证边界

`photon-windows run --console --config <path>` 现在运行公共状态同步。
`state.path` 必须指向已有的 common-schema bbolt，managed zone 和 root pin 必须与配置匹配。
首次运行可先用 `state import --config <path> --bundle <file> --key <file>` 导入 Linux 签发的
join bundle 和 Photon Ed25519 JSON 密钥，见 [初始化步骤](native-testing.md#首次初始化)。
导入只创建新数据库，拒绝覆盖已有文件；配置 root pin、zone、签名、有效期和密钥授权由公共身份逻辑验证。
只接受 root-to-managed authorities/parent proofs，不将 bundle 中夹带的 records 或其他 zone 视为 verified。
运行中的数据库不可同时由另一进程打开。尚未提供 Windows 密钥生成、自动入网或已有身份刷新命令。
`gossip_listen` 默认为 `0.0.0.0:33434`，接受 IP:port（IPv6 如 `[::]:33434`）；
UDP Gossip 与 TCP object-pull 绑定同一个地址和端口。bootstrap DNS 选择与监听地址相同族的第一个地址；
启动时解析，运行中由有界 worker 定时和重绑后刷新。配置本身保持不可变，修改配置后重启。

`Daemon.Run` 只打开一个 State/BoltStore，创建一个公共 GossipDriver，直接消费其事件；
协议、对象校验、checkpoint、重试策略继续归公共实现。TCP exchange 使用 context cancellation 和
I/O deadline，UDP write 有 deadline，Ctrl+C 关闭 reader/worker/server 后才关闭数据库。
`gossip_started` 日志明确记录 `tunnel_ready=false`，此阶段不创建 Wintun、IKE、路由或 SCM 服务。

真实 socket 测试覆盖 IPv4/IPv6 两节点同步、TCP 对象读取、取消退出、同地址重启及磁盘恢复，
另覆盖 TCP bind 失败释放 UDP/数据库和阻塞 TCP read 的取消。Linux 开发机和 Windows 11 amd64 VM
（OS build 26200）已通过；2026-10-02 又完成跨主机 Linux/Windows 同步与恢复验收。
可重复执行步骤见 [Windows 原生测试](native-testing.md)。进程 Ctrl+C、物理网络故障/睡眠、
Wintun/IKE/路由和 SCM 仍由后续阶段验收。

`Daemon.Rebind` 以及原生 IP Helper interface/address/route 通知会替换同端口 UDP/TCP listener，
保留唯一 GossipDriver、receive/accept worker、State 和数据库。旧 socket 结果不会跨代重新发布；
重绑失败释放部分资源，后续重试。已接受 TCP object-pull 连接由公共 driver 原有 deadline 收尾。
注册失败不报告启动成功，停止时先取消规划和通知，再关闭协议资源及 State。
通知回调仅投递有界事件，注销在回调外执行，遵守
[CancelMibChangeNotify2 的线程约束](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-cancelmibchangenotify2)。

`photon-windows gateways --config <path>` 离线读取同一数据库，逐一诊断 `gateway.allowed_zones`。
每次按当前时间复核 root pin、授权链、撤销、五项传输记录的签名和 owner/key、profile identity、
Ed25519 key fingerprint/有效期、inbound role、overlay/path family 和有效地址/端口。
输出 revision、评估时间、签名记录中的 IP contacts 或拒绝原因。bootstrap hints 不进入候选；
离线命令不解析 DNS，且不能在 console 持有数据库时执行。
这些结果仅用于检查传输材料，不创建 SA、不证明可达，也不代表 route-origin 授权；
输出明确标记 `tunnel_ready=false` 和 `route_authorized=false`。后续运行时必须重新校验，不能缓存为授权凭据。

console 复用同一候选校验：启动时、Gossip 事件推进 verified revision 后，以及每 5 秒执行一次。
定时校验不依赖 revision 变化，以发现授权链、key、地址或端口的到期。
仅候选/拒绝原因变化时输出 `gateway_candidates_changed`，附本次 revision 和评估时间；
这仍是观察日志，不是 active gateway 选择或数据面撤销执行器。尚无 SA/路由可由该观察控制，
后续数据面接入不得把 5 秒观察周期当作路由授权有效期或安全撤销目标。

在线 `PlanGateway` 使用签名记录解析 DNS，并按 allowlist/contact 顺序选出一个待连接目标。
唯一 worker 每轮最多 3 秒（bootstrap 部分最多 1 秒），不阻塞 Gossip event loop；新 revision、
重绑或新一轮请求取消旧计划，完成时以 generation/revision 丢弃旧结果，再按当前时间复验。
`Daemon.GatewayPlan` 返回 detached 且重新校验的当前结果；计划内容相同也更新 revision，
不能把日志去重误当成状态不更新。DNS 失败保留最后可用 bootstrap hint 重试，它仍不授予信任。

路由规划先对当前网络的每个相关 zone chain/record 签名重验，再复用 `BuildAuthorizedRouteSet`，
保留真实 origin，限制在 split aggregate 内。Selected 是待连接目标，Routes 是授权事实；
没有 SA、Router ID/origin 绑定的结果不得安装路由。这些后续数据面条件仍归 B3/B4。

B3 的实现顺序、锁定上游来源、各模块移植/重写决策和许可证材料见
[ranet-lite port map](ranet-port-map.md)。原型 IKE 为 AEAD-only，CHILD rekey 不支持 KE，
identity 使用 ASN1_DN；因此不能原样移植后宣称兼容当前 Linux 基线，也不以改窄 Linux profile 规避实现。
