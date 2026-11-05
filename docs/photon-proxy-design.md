# Photon Proxy 设计方案

> 状态：设计草案，尚未实现。日期：2026-10-23。
>
> 本文提出应用层代理网络的产品边界、进程划分和接口。文中的命令、配置与新 record 均为拟议接口，不能当作现有功能使用。

## 1. 定位与命名

**推荐产品名：Photon Proxy；推荐程序名：`photon-proxy`。**

Photon Proxy 对用户提供 SOCKS5 入口，利用 Photon 已验证的 Zone 数据发现代理节点、取得选路配置，在本机约束内选择中转和出口，转发 TCP 连接与 UDP 数据报。

| 名称 | 定位 |
| --- | --- |
| `photon` | 现有主程序，运行 Gossip、签名验证、数据库及可选的 IPsec/Babel 等模块 |
| `photon-proxy` | 新的应用层代理程序，消费主程序提供的可信状态，执行代理选路和转发 |
| `photon-services` | 现有服务部署 artifact 生成与发布编排工具，保留现有名字和行为 |
| SOCKS5 | 用户接入协议，不作为整个产品的名字；节点间可以使用其他代理协议 |

不把现有 `photon-services` 改名或直接变成长驻代理。它目前负责生成 GOST/Compose 配置及发布服务；新产品负责持续消费状态和处理代理会话，两者职责不同。

## 2. 需要解决的问题

现有 [Services](new/services.md) 已支持签名发布 `service.socks5.v1`，公布 `region/address/port`，并按 Zone selector 管理内网 endpoint ACL。代理进程仍主要通过管理员启动，发现服务后如何选择、串接和使用代理尚未形成闭环。

目标使用方式：用户只配置一个 SOCKS5 地址，入口自动取得可信节点目录，再按规则使用指定出口，或经过一个指定中转到达出口。

```text
用户 -- SOCKS5 --> A（入口）
                    |-- A 本机出口 --------------------> 目标
                    |-- C（出口）----------------------> 目标
                    `-- B（中转）--> C（出口）---------> 目标

每个节点运行自己的接入和转发策略，可以拒绝请求。
```

这里的路径是应用层代理链。它规定哪些代理处理连接，不保证节点间 IP 包走哪家 ISP、哪条物理线路；每一段网络连接仍由操作系统路由。

首版范围：

- SOCKS5 TCP CONNECT、UDP ASSOCIATE，承载 IPv4/IPv6 目标和域名目标。
- 本机出口、指定远端出口、最多一个中转；入口能配置多条有序候选代理链。
- 节点能力自动发现、显式引用的共享策略、节点本地接入与转发约束。
- 节点间先使用 Relay over TLS/TCP，TCP 和 UDP 业务都可经其传输。
- 新连接按当前策略选链；已建立会话固定路径，授权撤销时主动终止。

首版不增加 L3 隧道、TUN、IPsec provider、Babel cost 控制或 SRv6；也不计算全网最优路径，不提供已建立 TCP 连接的出口迁移。原生 UDP/QUIC 承载属于后续独立选项，不能因“支持 UDP 业务”就宣称已支持 UDP 承载。

## 3. 两个独立的架构选择

### 3.1 Proxy 与 Photon 主程序：推荐分进程

| 选择 | 优点 | 代价 |
| --- | --- | --- |
| 同进程可选模块 | 直接读取快照、通知简单、少一个服务 | 代理依赖和故障进入现有 daemon；大量连接与网络控制面共享进程资源 |
| **独立 `photon-proxy`** | 应用层服务有自己的生命周期、依赖和资源限制；可以独立重启 | 需要本地状态接口，明确断连、重连和缓存失效规则 |

推荐两个进程，复用现有 Unix 控制通信的 framing、请求处理和 DTO 习惯。**只有 `photon daemon` 运行 Gossip 和持有数据库；Proxy 不运行第二套 Gossip，也不直接打开主程序的 bbolt 文件。**

进程分离本身不等于权限隔离。部署时 Proxy 应使用独立系统用户；两个程序若共用高权限 UID，就不能声称已隔离权限。

### 3.2 Proxy 与 GOST：推荐库集成

| 选择 | 适用点 | 本方案的取舍 |
| --- | --- | --- |
| 启动外部 GOST，生成配置或调用其 API | 静态代理、早期协议对照验证 | 实现起步快，但 Photon 的节点身份、会话授权及撤销容易变成另一套配置同步 |
| **引入 GOST 库的必要组件** | 在建连、认证、选链和关闭会话时接入 Photon 策略 | 推荐；需要验证可注入接口、资源关闭和全局 registry 的使用边界 |

分进程与库集成并不冲突：推荐结构是 **`photon daemon` + 内嵌必要 GOST 组件的 `photon-proxy`**。

不把 GOST CLI、完整配置解析器、全部协议注册、Web 管理 API 和后台调度整体搬进 Proxy。不先建设通用代理后端插件框架；Photon 直接拥有策略、TLS 身份、连接生命周期，按实际需要复用 SOCKS5 handler、Relay connector/handler 等组件。

## 4. 总体结构与唯一状态所有者

```text
远端 Photon
    | Gossip：签名 Zone、record、撤销
    v
photon daemon
    签名和委派验证 --> State.Common（唯一可信数据库 owner）
                           |
                    代理专用公开快照
                           | Unix socket
                           v
photon-proxy
    节点目录 + 选定共享策略 + 本机配置 + 本机健康观测
                           |
                  不可变的有效策略快照
                           |
            SOCKS5 / 节点监听器 --> 建链 --> 会话转发
```

各层所有权：

- daemon 负责可信状态、签名提交、Gossip 传播和代理 record 的公开投影。
- Proxy 负责监听端口、TLS 数据面密钥、策略编译、建链、DNS、会话、观测和关闭。
- GOST 组件负责被明确复用的协议操作；不能成为第二个节点目录或权限决策源。
- Proxy 的业务流量不经过 daemon 的 Unix socket、Gossip reader 或事件循环。
- Proxy 查询 DTO 不包含 `VerifiedState` 的私钥，不直接序列化整个 `State.Common.ReadView()`。

这个应用层服务可以使用 Photon 内网作为接入地址，也可以使用签名公布的公网 TLS/TCP 地址；是否启用 IPsec，不是代理协议正确性的前提。主程序已有 Gossip 引导仍需可用：本方案不承诺解决 Gossip 自身的 UDP control 可达性问题。

## 5. 与现有 Gossip 的集成

### 5.1 读取方向

当前 Gossip 在对象验证、状态提交后调用 `notifyStateChanged()`。实现时在这条既有通知链路上标记代理视图需要重建，合并同批变更，再从已提交状态构造公开投影。

```text
Gossip 收到对象
  -> 验证 authority / delegation / record / revocation
  -> 提交 State.Common
  -> notifyStateChanged
  -> 更新代理视图 generation，唤醒等待查询
  -> Proxy 接收完整视图，构造新的有效策略快照
```

目前 `notifyStateChanged()` 中的 Linux dirty flags 受 `linuxDriver != nil` 保护。代理视图通知必须放在这项平台判断之外；不应要求 IPsec/BIRD 存在才可消费 Gossip 的代理能力。

### 5.2 写入方向

Proxy 发布本节点能力时，只向 daemon 提交限定类型的本地 intent。daemon 校验发布者权限、owner、schema、版本和端点约束，经现有 single-writer 提交并签名，提交成功后再由 Gossip 通知远端。

不暴露 `gossip.Engine` 方法，不允许 Proxy 绕过验证注入远端 record，不新增任意签名 RPC，也不把每个代理请求写入数据库。

共享策略由有权管理该 Zone 的管理员通过主程序提交。Proxy 自身只具有发布/撤销本节点能力的权限。

## 6. Unix 接口建议

复用现有控制协议实现，增加一个权限收窄的本地入口，例如 `/run/photon/proxy.sock`。保留现有管理 socket 的授权边界，不把完整管理权限授予代理用户。

daemon 通过 socket 文件权限和对端系统凭据识别允许的 Proxy 用户；不能相信请求 JSON 自报的 UID、Zone 或角色。

| 拟议方法 | 内容 | 权限 |
| --- | --- | --- |
| `proxy_view` | 读取完整代理视图；支持等待 generation 变化 | 只读 |
| `proxy_publish` | 发布本机 `services/proxy` 能力，带 expected record version | 只限 daemon 当前 managed Zone 和固定 record 类型 |
| `proxy_withdraw` | 撤销本机能力，带 expected record version | 同上；旧进程不能撤销新进程刚发布的版本 |

`proxy_view` 返回：

- daemon instance ID、代理 view generation、底层 state revision、生成时间。
- managed Zone、trust root 标识、经过验证且仍有效的节点能力和策略。
- 视图内节点/策略的版本、有效期，以及下一次需要按时间重新评估的时间点。
- 已发现但不满足代理 schema 的条目及明确诊断；这些条目不能进入可用节点集。

首版采用 **完整快照 + 有界长轮询**，不新增增量事件日志。请求可以携带上次的 `(instance ID, generation)`，最长等待 10 秒；超时也返回完整的当前视图。一次响应是同一状态 revision 和时间点的投影；数据超过接口容量时明确失败，不能截断后宣称目录完整。

长轮询在控制连接的协程中等待已提交视图的变化，不占用 daemon 事件循环；daemon 关闭时取消等待。客户端请求 deadline 应大于等待上限，例如 15 秒，不能直接套用现有管理请求的 10 秒 deadline。

重新连接、daemon instance 变化或 cursor 失效时取完整快照。不同 daemon instance 的 generation 不比较大小。时间到期也要唤醒/刷新投影，不能只在数据库 version 变化时处理证书或 record 过期。

IPC 失联时，最后一次成功视图最多继续使用 30 秒，并受条目自身有效期约束。超过窗口后拒绝新建代理会话并关闭已有节点代理会话；恢复完整有效视图后再接受新连接。loopback SOCKS5 listener 可保留并返回失败，不能悄悄改成本机直连。

这个 30 秒只约束 Proxy 与本机 daemon 的失联，不是全网撤销传播时限。尚未通过 Gossip 到达本机的变更无法被本机预知。

## 7. 全网事实、本机策略与观测

| 数据 | 进入 Gossip | 说明 |
| --- | --- | --- |
| 节点代理身份、公钥绑定、接入点、角色、业务协议能力 | 是 | 节点发布自己的签名能力 |
| 管理员发布的命名代理链与匹配规则 | 是 | 必须由本机显式选择可信发布者和 policy ID |
| 本机允许连接哪些节点、接受哪些请求、允许哪些目标 | 默认否 | 本机策略具有最终拒绝权 |
| 用户密码、TLS 私钥 | 否 | 本机秘密 |
| RTT、失败退避、连接数、UDP 会话映射 | 否 | 本机实时观测 |
| 每次 CONNECT、逐包数据、探测结果 | 否 | 不把最终一致数据库用作转发总线 |

### 7.1 新节点能力 record

建议新增 `service.proxy.v1`，固定 key 为 `services/proxy`。owner 从签名 `zone.Record.Zone` 获取，值里不允许自报另一个 owner。

示意值，地址和指纹只作说明：

```json
{
  "type": "proxy",
  "active": true,
  "expires_at": "2026-10-24T00:00:00Z",
  "region": "jp",
  "tls_spki_sha256": ["<TLS public-key SPKI SHA-256 hex>"],
  "endpoints": [
    {
      "id": "exit-tcp",
      "role": "exit",
      "address": "203.0.113.20:8443",
      "transport": "relay+tls",
      "scope": "underlay",
      "networks": ["tcp", "udp"]
    }
  ]
}
```

语义：

- `active` 和 `expires_at` 对新类型均必填；过期或撤销后不能继续参与认证和选路。
- endpoint ID 在 owner 内唯一，路径引用 `(Zone, endpoint ID)`；精确指定节点时不使用 Anycast。
- endpoint `role` 为 `relay` 或 `exit`。同一节点可提供两种端点；本机入口不必对外发布。
- exit 的 `networks` 表示可转发的业务协议。relay 端点仅接受到后续代理端点的 TCP 连接，内部可以继续承载出口的 UDP 代理协议。
- 仅提供本地入口的节点仍需公布自己的 TLS 身份，`endpoints` 可为空；不能因此被当作远端出口。
- `scope: mesh` 的 IP 地址仍须属于 owner 当前有效的 IPAM assignment；`underlay` 是节点宣告的公网/外部接入地址，不能冒用 IPAM 授权结论。
- underlay 地址的签名只证明“谁宣告了它”，实际连接必须验证其 TLS 公钥绑定。地址、域名、region 均不替代身份和权限。
- 能力按低频 lease 续期，首版建议有效 24 小时、剩余 12 小时时续期；续期走现有 record version 机制。lease 不代表在线，运行时仍需实测可达性。
- 停止服务尽力提交撤销；崩溃由连接失败和 lease 到期共同处理，不依赖进程总能正常退出。

Proxy 私钥由 Proxy 的本地凭据目录持有，daemon 只签名其公钥绑定。每个 TLS 公钥在有效目录中必须唯一映射到一个 Zone；客户端与服务端均检查当前绑定、有效期和实际持钥证明。

### 7.2 共享选路配置

建议新增 `proxy.policy.v1`，key 为 `proxy/policies/<id>`，包含 `active`、`expires_at`、命名候选路径、匹配规则和默认动作。利用外层 record version，不再发明另一套 revision。

本机通过精确 `(发布者 Zone, policy ID)` 显式引用共享配置；默认不自动继承某个祖先策略，也不让“最新发现的策略”自动接管本机。路径可以引用具体节点/端点，或让出口按 region 和允许的 Zone 范围形成有序候选集；每条实际会话开始前必须解析成确定路径。

共享配置与本机限制取交集：允许节点、允许承载协议、最多中转数、目标范围等均不得突破本机上限。共享配置不能改写本机 listener 或密码，也不能替其他节点承诺接受请求。引用的策略缺失、过期、撤销或非法时，相关规则不可用；不能退回更宽松的直连模式。

旧 `service.socks5.v1` 的 schema、IPAM 校验和默认值不变。它不能通过新增字段直接变成新节点能力；当前解析器严格拒绝未知字段，必须按新 record 类型单独实现。

## 8. 源节点选路、身份与中转拒绝

### 8.1 首版选择入口构造的嵌套代理链

以 `A -> B -> C -> 目标` 为例：

1. A 选择一条完整、无重复节点的已授权路径。
2. A 与 B 建立带节点身份校验的 TLS，要求 B 连接 C 的确切 exit endpoint。
3. B 校验 A 的请求和下一端点，建立到 C 的 TCP 连接并转发字节。
4. A 通过 B 的字节通道与 C 建立内层 TLS，验证 C 身份，向 C 请求最终目标。
5. C 校验实际 TLS 请求者和目标，再建立对外 TCP 连接或 UDP 映射。

这与“B 解读完整路径后，用 B 的身份重新向 C 发起代理请求”不同。首版采用上面的嵌套方式，不另造携带剩余路径和身份委托的新协议。

**重要：在这套设计中，B 和 C 都应认证到入口节点 A 的 TLS 身份。**C 的网络连接来源可能是 B，但不能把来源 IP 当作 B 的代理身份。GOST 是否确实按此方式保留嵌套 TLS 与客户端证书，必须列入集成验证；不能仅凭配置里出现三台机器就认定身份语义正确。

普通 SOCKS5 用户不是 Photon Zone。A 对其本机用户认证，远端默认只认 A；首版不把 A 提供的用户名字当作端到端可信身份。

### 8.2 每个节点可执行的限制

| 节点 | 可验证并拒绝的内容 |
| --- | --- |
| A 入口 | 本机用户、目标、允许的代理节点/链、承载协议、是否允许本机出口 |
| B 中转 | TLS 请求者 A、被请求的下一代理端点 C、并发与资源上限 |
| C 出口 | TLS 请求者 A、最终目标域名/IP/端口、业务协议和本地出站配置 |

B 的 relay listener 只允许连接当前目录中已验证且由本机允许的下一 exit endpoint，不允许当成任意目标 CONNECT 出口；relay 与 exit 由不同 endpoint 区分。

B 无法读取内层 TLS 中的最终业务目标，不能承诺执行针对最终域名的过滤。C 也不能仅凭来源 IP 验证“必须经过 B”。需要出口验证完整中转轨迹，或限制所有节点都基于真实上一跳身份授权时，再单独设计委托/路径证明，不混入首版。

节点自主拒绝优先于源节点选路。拒绝后只可尝试预先允许的其他完整候选链，不能删掉必经中转、改成未授权出口。显式策略拒绝不记作网络故障；认证失败的 endpoint 不通过跳过验证来恢复。

目标约束在出口对实际拨号 IP 再检查，包含域名解析结果；不得通过域名指向被拒绝地址绕过限制。节点地址是建连候选，不是任意探测和拨号的授权。

## 9. 会话、DNS 与更新行为

### 9.1 选路过程

`本机用户/网络/目标 -> 首个匹配规则 -> 命名候选链 -> 本机约束过滤 -> 有序建链尝试`。

第一版使用确定的候选顺序和失败退避，不自动按全网 RTT 重排。匹配不成功的默认动作是拒绝；需要本机出口时必须显式配置。入口只探测本机允许且实际可能使用的端点，不根据全网所有记录自动建立连接。

路径在会话建立时固定，首版最多一个中转。重复节点、未知 endpoint、角色不匹配、业务协议不支持和本机不允许的 transport 都在建链前拒绝。中转节点的本地出站策略不再自动套用入口的另一条代理链，避免递归选路。

### 9.2 TCP 与 UDP

- TCP 仅在尚未向用户报告成功、尚未转发业务数据的建链失败阶段，才可换候选链重试。成功后断线返回错误，不重放已发送数据。
- UDP ASSOCIATE 绑定 SOCKS5 控制连接；控制连接关闭时清理数据报映射。
- UDP 按本机用户、association、源和目标区分会话，同一会话固定链和出口，有独立空闲超时及容量限制。
- UDP-over-TCP 保留数据报边界和目标地址，回包必须来自对应的出口映射，不能混入另一客户端或另一目标的会话。
- UDP 链断开即使本地 association 尚在，也先使受影响的流失效并丢弃待发数据，不自动换出口重发；新会话再按当前配置选链。
- 首版不使用一条全局复用 TCP 连接承载全部用户；避免让一条拥塞连接同时阻塞所有会话。后续复用必须单独验证公平性、关闭和撤销行为。

域名由用户通过 SOCKS5 提交时，可在入口做域名规则匹配，默认由最终出口解析并执行实际 IP 限制。只提交 IP 的请求不猜测原域名；首版不靠 TLS 解密或 SNI 嗅探补齐域名。

TCP 承载能提供与 UDP 不同的网络表现，但不能保证更快。业务 UDP 经 TCP 时仍有队头阻塞；TCP 业务在这里由代理终止和重新建立连接，不是把原始 TCP/IP 包整体装入 TCP 隧道。

### 9.3 配置更新和撤销

Proxy 将目录、引用策略和本地配置编译为不可变快照，以原子替换供新会话读取。现有会话保留建立时的确定路径和关联的身份/授权引用。

| 变化 | 新会话 | 已有会话 |
| --- | --- | --- |
| 偏好出口/候选顺序调整 | 使用新快照 | 保持路径至结束 |
| 无关节点新增 | 可进入允许的候选集 | 不迁移 |
| 节点/证书/所依赖策略撤销、到期，或本机授权收紧 | 立即禁止相关请求 | 按引用索引关闭受影响连接和 UDP 流 |
| endpoint 正常地址调整，原身份和权限仍有效 | 用新地址 | 保持已有连接 |
| IPC 超过失联窗口、trust root/本机身份变化 | 禁止旧身份下的新请求 | 关闭旧会话，重新取得和验证目录 |

撤销处理先更新认证/准入快照，再取消会话；已经排队但尚未交付的数据不得靠旧快照继续发送。拨号完成、即将向用户宣布成功时再确认授权仍有效，覆盖“拨号过程中撤销”的竞争。

无变更到达时，Proxy 也按有效期定时使条目失效。全网同步是最终一致的；文中的“立即”是指本机观察到变更或到期后，不表示所有节点同时撤销。

## 10. GOST 复用方案和实施前验证

GOST 提供独立的 `go-gost/core` 接口和 `go-gost/x` 实现，公开源码有 handler/router 注入以及 Relay connector，可作为复用基础。构造具体对象并注入 Photon 的选路/认证适配，不使用完整 GOST 全局运行器管理节点和策略。

版本研究起点可用现有 GOST 3.2.6 对应的 `core v0.3.3`、`x v0.8.1`。这只是与现有服务对照的起点，不是未经验证的生产选版。调研时上游 master 已要求 Go 1.26.3，而本仓库 `go.mod` 为 1.25.0；本设计不修改工具链或添加依赖。

需要先证明的集成点：

1. SOCKS5/Relay 的建连能进入 Photon 的路由和目标授权入口，且禁止的 CONNECT/BIND/UDP 请求不会绕过它。
2. TLS 公钥绑定和客户端身份可由 Photon 注入；嵌套代理链的真实认证身份符合第 8 节。
3. Proxy 能索引和关闭受影响的 TCP/UDP 会话；取消、停止、重新启动不泄漏连接或 goroutine。
4. 策略更新能原子生效，不依赖重启全局 GOST 进程，也不要求开放 GOST 管理 API。
5. 仅引入需要的组件；全局 registry 不保存多个运行实例的可变授权和会话状态。审计 transitive dependencies 与实际构建影响。

某组件不能满足上述边界时，先缩小复用范围，用 Photon 的薄协议适配补足；若需要广泛 fork GOST，则重新评估该组件选择，不把权限语义退化成仅生成配置文件。

注意 GOST 协议名中的 `mtls` 表示 multiplexed TLS，不能把该名字当作 mutual TLS 双向身份验证已实现的证据。

## 11. 拟议操作方式

```text
photon daemon                       # 既有网络与可信状态主程序
photon-proxy serve -config proxy.yaml
photon-proxy nodes                   # 查看可信目录及本机可用性
photon-proxy routes                  # 查看有效规则和候选链
photon-proxy explain --network tcp --target example.com:443
photon-proxy sessions                # 查看本机实际会话路径
```

上述 Proxy 命令尚不存在。运行态命令通过 Proxy 自己的本地控制入口读取其实际状态；daemon 的代理 API 只提供可信事实，不能被用来假装会话已经建立。`explain` 默认只解释策略，不主动建业务连接。

入口节点本机配置示意：

```yaml
photon_socket: /run/photon/proxy.sock

socks5:
  listen: 127.0.0.1:1080

allowed_nodes: ["*.catofes."]
allowed_transports: [relay+tls]
max_relays: 1

profiles:
  overseas:
    candidates:
      - hops:
          - {zone: b.catofes., endpoint: relay-tcp}
          - {zone: c.catofes., endpoint: exit-tcp}
      - hops:
          - {zone: c.catofes., endpoint: exit-tcp}

rules:
  - domains: [example.com]
    networks: [tcp, udp]
    profile: overseas

default: reject
```

此例显式允许直达 C 作为备用；若业务必须经过 B，就删除第二条候选链。`allowed_nodes` 复用现有 `pkg/service` Zone selector 语义，`*.catofes.` 包含该 Zone 及其子 Zone。

监听器默认只绑定 loopback，远端用户入口需显式配置监听地址和认证/访问限制；现有内网容器 SOCKS5 的 NO AUTH 默认值不能直接用于公网入口。节点 relay/exit listener 另行启用，配置允许的 TLS 请求者、下一节点或最终目标；无允许项时拒绝，不因发布了角色就自动开放。

共享策略是本地规则的可选来源；实际 YAML/JSON schema 在第一步实现前一起冻结，不能让示例先成为未校验的隐式兼容契约。

## 12. 生命周期、发布与兼容

- 每个 managed Zone 首版只运行一个能力发布 owner；Proxy 通过本机单实例锁避免同一配置重复监听/续期。
- 先取得完整可信视图并验证配置、加载数据面密钥、启动监听器，再通过限定 intent 发布实际已就绪能力；未成功监听不能宣告可用。
- 数据面密钥只在本机文件保存；发布失败时不接受外部节点代理请求，本机状态清楚报告未发布原因。
- 本机入口不对外公布 endpoint 也可以工作，但其客户端 TLS 身份必须已成功发布。
- 发布提交只证明本机持有该签名能力，不代表远端已同步到它。远端暂时不认识入口身份时应拒绝，等待目录收敛后再建立新会话，不临时放宽认证。
- 停止时先停止接收、关闭会话，再尽力撤销自己的 record；撤销使用预期版本，避免旧进程退出误撤销新进程。
- 不接管旧 GOST 容器，不占用其原端口，不自动改变现有 route announce、IPAM、endpoint ACL 或 Compose 生命周期。
- 旧 SOCKS5 服务可以继续作为普通代理使用；没有新身份绑定和能力验证的旧 endpoint 不自动升级成新代理链的可信中转/出口。
- 首版针对 Linux 验证。纯应用层设计便于以后复用，但不据此承诺 Windows/Android 已支持。

## 13. 实施顺序与验收

先完成一条真实端到端路径，再扩展策略。每一步都保留“能力声明、策略选择、实际转发”三层证据。

| 阶段 | 交付 | 核心验收 |
| --- | --- | --- |
| P0：库适配验证 | 固定节点、内嵌必要 GOST 组件 | 双栈 TCP/UDP；嵌套 TLS 的身份；取消与资源回收；依赖/工具链兼容 |
| P1：可信目录闭环 | 新能力 record、受限 Unix API、Proxy 消费快照 | 发布/撤销、daemon 重启、长轮询超时、目录到期、无第二数据库 writer |
| P2：入口与出口 | SOCKS5、指定远端出口、出口目标限制 | 实际出口 IP、UDP DNS 数据和源地址、域名远端解析、错公钥/撤销拒绝 |
| P3：中转和策略 | 一个中转、有序候选链、共享策略引用和本机限制 | A-B-C 的实际路径；B 拒绝 A/C；C 认证到 A；无越权直连回退 |
| P4：运行验收 | 观测、限额、故障和更新闭环 | 规则切换不迁移旧 TCP；撤销关闭旧流；IPC 失联/恢复；并发时 Gossip 仍可收敛 |

必须覆盖：

- 来源和目标均分离的真实服务，证明业务确实经指定出口，不只检查配置或端口监听。
- A-B-C 链内每一层的 TLS 对端身份，避免把网络前一跳误当认证者。
- 中转只能连接允许的代理端点，出口仅连接允许的目标；域名解析后的 IP 也受限制。
- 策略在拨号、握手、UDP 队列和已有连接期间被撤销，各阶段均有停止边界。
- 版本竞争、旧进程撤销、错误/过期/未知 schema、视图切换、daemon instance 变化。
- TCP 建立后断链不重放数据，UDP 超时和控制连接关闭不泄漏映射。
- 外部网络抓包或等效观测证明指定 underlay 段实际使用 TCP，不能把“TCP 代理跑在 UDP IPsec 内”当成 TCP 跨境承载验收。
- 分别测量 TCP/UDP 业务在现有部署和代理链中的吞吐、延迟与丢包；不以“连通”推断性能优于 IPsec。

本文只完成设计，不表示以上验证已经执行。代码实现前首先解决 P0 的库接口和身份语义，不提前创建空后端、通用资源图或多协议兼容层。

## 14. 依据与待确认点

当前仓库依据：

- [现有 Service 发布和 GOST 部署](new/services.md)。
- [Gossip 验证与状态传播](new/gossip.md)。
- [daemon 单 writer 与运行时边界](new/daemon.md)。
- `pkg/service/records.go` 的严格 schema 与 IPAM 授权，`pkg/core/state/service_intent.go` 的签名提交。
- `app/photon/daemon.go` 的 `notifyStateChanged()`，`app/photon/daemon_control.go` 的视图查询。

2026-10-23 查阅的上游一手资料：

- [GOST Chain](https://gost.run/en/concepts/chain/)：链和节点组模型；UDP 类 data channel 的链层级限制。
- [GOST Relay](https://gost.run/en/tutorials/protocols/relay/)：TCP/UDP 转发，Relay 本身不提供加密。
- [GOST TLS](https://gost.run/en/tutorials/protocols/tls/)：协议与 TLS 组合，以及 multiplexed TLS 命名。
- [GOST 3.2.6 go.mod](https://github.com/go-gost/gost/blob/v3.2.6/go.mod)：现有版本对应库的研究起点。
- [core Handler](https://github.com/go-gost/core/blob/master/handler/handler.go)、[handler Options](https://github.com/go-gost/core/blob/master/handler/option.go)、[Relay connector](https://github.com/go-gost/x/blob/master/connector/relay/connector.go)：可复用接口研究。
- [x registry](https://github.com/go-gost/x/blob/master/registry/registry.go)：全局对象的生命周期需审计。

上游 master 接口和文档不能替代所锁定版本的验证。推荐的进程和权限边界已写明；库版本、适配所需代码量及嵌套链身份需由 P0 实测确定。UDP/QUIC 原生承载、多个中转、可信原始用户传递、路径证明和自动质量选路均留待有实际需求时单独设计。
