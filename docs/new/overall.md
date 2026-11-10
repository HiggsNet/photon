# Photon 整体结构

Photon 是一个 mesh VPN 控制平面。它不把某个节点的本地配置当成全网真相，而是先维护一份可验证、最终一致的 Zone 状态数据库，再由每个节点的 daemon 把这份状态收敛成本机的网络配置。

换句话说，Photon 分成两层：

- **全网事实层**：哪些 Zone 存在、谁有权限写入、节点发布了哪些 endpoint、transport key、route、IPAM 等记录。
- **本机执行层**：本节点根据已验证状态和本地策略，去配置 IPsec/WireGuard、BIRD/Babel、firewall、health probe 和 observer。

这两个层次要分开理解。Gossip 只负责传播和验证状态；StrongSwan、WireGuard、BIRD、nftables/iptables 等系统动作只在本机 daemon reconcile 阶段发生。

## 文档整理方式

新的文档按模块拆分。`overall.md` 只说明整体关系，不展开协议字段、配置项和实现细节。后续模块文档应该围绕一个清晰问题来写：

- 这个模块解决什么问题。
- 输入来自哪里。
- 输出影响什么。
- 哪些状态会进入 gossip，哪些只是本机 runtime 状态。
- 出错时 operator 应该看哪些 debug/health/observer 信息。

建议的模块文档：

| 文档 | 内容 |
|------|------|
| `gossip.md` | Zone 数据库、签名验证、delegation、record、revocation、endpoint 同步和 object pull |
| `daemon.md` | daemon 单 writer、事件循环、control socket、reconcile 调度和本机状态文件 |
| `transport-ipsec.md` | StrongSwan/IKEv2、XFRM interface、LinkPlanner、LinkInstance、rotate 和 teardown |
| `transport-wireguard.md` | WireGuard 控制面模型、record 形状和后续轻量 transport driver |
| `routing.md` | BIRD/Babel、route announcement、route authorization、per-netns routing instance |
| `firewall.md` | nftables/iptables 规则生成、host ingress、redirect grace、owner 清理 |
| `health.md` | 链路探测、BIRD 观测、metric/cutover gate、metrics 输出 |
| `observer.md` | 只读 Web/API 控制台、SSE、inspect read model 和 CLI debug 复用 |
| `services.md` | `photon-services` 工具、service manifest、shared Anycast assignment、service record、动态 endpoint ACL 和发布/撤销编排 |
| `config.md` | 用户配置文件结构、默认值和常见部署形态 |
| `operations.md` | 常用运行命令、排障路径和恢复操作 |
| `testing.md` | `make check`、轻量 smoke 和真实数据面 smoke 的验证入口 |

## 模块总览

### 1. Zone / Gossip 状态层

Zone 是 Photon 的核心数据模型。每个 Zone 有自己的 authority、delegation 和 signed records。节点只接受能从本地 trusted root 验证到的状态。

Gossip 负责把这些 signed Zone state 在 peer 之间同步。它维护的是控制面数据库，不直接修改系统网络。它的主要职责是：

- 交换 Zone digest 和 record metadata。
- 通过 UDP 交换带目录摘要的 PING/PONG，通知邻居同步。
- 通过 object pull 拉取完整的 Zone snapshot。
- 维护 endpoint discovery、bootstrap peer、observed path 等可达性信息。
- 在验证通过后更新本地 active state。

### 2. Daemon 控制循环

`photon daemon` 是长期运行入口。它把 gossip、admin 写入、endpoint 发布、object pull、relay、transport reconcile、routing reconcile、firewall reconcile、health 和 observer 放在同一个本机控制边界内。

daemon 的关键职责是：

- 保持单 writer，避免多个命令同时写本地状态。
- 接收 CLI/control socket 请求。
- 根据事件触发不同模块的 reconcile。
- 把各模块的 runtime snapshot 写回本机状态，供 debug、observer 和下一轮 reconcile 使用。

daemon 不应该让 HTTP handler、CLI presenter 或系统 driver 各自重新推理状态。长期方向是把可读状态先收敛成 inspect/read model，再由 CLI 和 Observer 共同展示。

### 3. Transport 控制面

Transport 模块负责把“哪些节点应该互联”变成真实的数据面链路。它的输入来自两部分：

- Gossip 中已验证的节点能力记录，例如 endpoint、transport key、IPsec profile、overlay intent。
- 本机配置中的 overlay/link policy，例如连接哪些 peer、使用哪个 provider、放入哪个 netns。

当前主线 transport 是 **StrongSwan/IKEv2 + XFRM interface**。它通过 VICI 控制 StrongSwan，通过 XFRM interface 承载 route-based tunnel，并把接口放入目标 network namespace。

WireGuard 是后续可选轻量 transport。它应复用同一套高层 mesh policy 和 signed record 思路，但底层 driver、key 管理和端口 rotate 能力会独立说明。

### 4. Routing 控制面

Routing 模块负责把已经建立的 tunnel link 接入动态路由。当前主线是 **BIRD 跑 Babel protocol**。

Routing 的边界是 per-netns：同一个 network namespace 内的多个 overlay 共享一个 BIRD 实例。BIRD 负责发现 tunnel interface 上的 Babel 邻居，并根据 route authorization filter 决定哪些路由可以导入或导出。

Routing 不负责建立底层 VPN 链路；它消费 transport 暴露出来的 interface、peer、health 和 route intent。

### 5. Firewall 控制面

Firewall 模块负责把本机 overlay 安全策略收敛成系统规则。当前设计以 nftables 为主，iptables 作为 fallback。

它主要处理：

- overlay/netns 内的 filter 规则。
- host ingress 规则。
- IPsec 端口 redirect grace。
- Photon-owned 规则的 owner 标记、恢复和清理。

Firewall 规则是本机 runtime 状态，不进入 gossip。Gossip 中的 signed state 只提供 peer、route、transport intent 等事实来源。

### 6. Health 监控平面

Health 模块负责判断链路是否真的可用，而不仅仅是配置是否已经下发。它可以结合 ICMP/UDP probe、BIRD 邻居观测、RTT、丢包和 route metric 等信息。

Health 的结果主要用于：

- debug 和 observer 展示。
- 调整 routing metric。
- 控制 rotate/cutover 时机。
- 暴露 metrics 给外部监控系统。

第一版 health 是本机观测，不直接写入 gossip active state。后续如果需要 signed health hint，应单独设计 record 和信任边界。

### 7. Observer / Inspect 展示层

Observer 是只读 Web/API 控制台。它不应该直接操作 daemon 状态，也不应该重新实现一套诊断逻辑。

理想结构是：

- 各 runtime 模块产出结构化 snapshot。
- inspect 层把 active state、runtime snapshot 和配置整理成可读 read model。
- CLI debug 和 Observer API 都消费同一份 read model。

这样可以避免 `debug links`、`/api/v1/links`、route debug、health API 各自给出不同原因。

### 8. Service 发布

Service 发布把“可信网络状态”和“容器部署”拆开。Photon daemon 只负责网络原语：保存 shared Anycast assignment、校验并签名 `service.socks5.v1` record、显式宣告或撤销服务前缀、按 Zone selector 维护动态 endpoint ACL。它不理解镜像、容器或 Compose。

独立工具 `photon-services` 读取本机 `/etc/photon/service.yaml`，通过 `photon route ipam mine` 解析本地和 shared Anycast 地址，生成 Docker Compose artifact，并在管理员拉起容器后编排 TCP 就绪检查、endpoint ACL、整段 assignment 的 route announce 和签名 service record 的发布/撤销顺序。

发布出去的签名事实只有 service record 本身（region、address、port）；容器拓扑、`allow_zones` 等部署与安全策略都留在本机。跨节点共用的服务地址使用带 tag 的 shared assignment，路由随服务健康状态宣告和撤销，与节点普通前缀的生命周期分开。

## 一次典型收敛流程

一个节点运行时，大致会经历以下流程：

1. daemon 加载本机配置、identity key、本地数据库和 trusted root。
2. gossip 与 bootstrap peer 同步 signed Zone state。
3. 通过 trust chain 验证后，远端节点记录进入 active state。
4. transport planner 根据 active state 和本地 overlay policy 规划要建立的 link。
5. transport driver 配置 StrongSwan/XFRM 或后续 WireGuard 资源。
6. routing manager 在对应 netns 内启动或更新 BIRD/Babel。
7. firewall manager 更新 nftables/iptables 规则。
8. health manager 探测链路并反馈状态。
9. observer 和 CLI debug 从 inspect/read model 展示当前状态。

## 重要边界

- Gossip 传播的是 signed control-plane state，不执行系统配置。
- Overlay/link policy 是本机策略，不默认公开到 gossip。
- Endpoint、DNS、reflector、observed path 只影响可达性候选，不替代 Zone trust chain。
- StrongSwan、WireGuard、BIRD、nftables/iptables 都是本机 runtime driver；它们的失败不改变 signed state 的真实性。
- Debug/Observer 应展示“已验证事实 + 本机期望状态 + 实际 runtime 状态”的差异，而不是只展示某一层。
- 服务发布是 operator 驱动的独立流程：daemon 只提供 signed record、路由宣告和动态 ACL 原语，容器部署和生命周期由 `photon-services` 与管理员负责。

这个边界是后续拆文档的主线：每个模块都要讲清楚自己在哪一层，读什么，写什么，以及不负责什么。
