# StrongSwan / XFRM 交互测试方案

这份 runbook 用于 Phase 4 的系统集成验证。它刻意不放进
`make smoke-all`：该流程会接触宿主机网络、StrongSwan/charon、VICI、XFRM
interface，以及 root 或 `CAP_NET_ADMIN` 权限。

推荐在 disposable root VM 或一次性 privileged container 中运行，而不是直接在日常
宿主机上手工折腾网络资源。容器路径已经自动化，优先使用：

```sh
make ipsec-xfrm-container-smoke
```

该目标会调用 `docs/scripts/ipsec-xfrm-container-smoke.sh`，自动完成：

- 首次运行时基于 `ubuntu:24.04` 构建本地缓存镜像
  `photon-ipsec-xfrm-smoke:ubuntu-24.04`；后续运行复用该镜像，避免重复
  `apt-get update/install`。
- 使用 `docker` 启动一次性 privileged container。
- 挂载当前 repo 到 `/work`，工作目录设为 `/work`。
- 镜像内已包含 `make`、Go、`iproute2`、`iputils-ping`、
  `strongswan-swanctl`、`strongswan-charon` 和 nested netns wrapper。
- 使用 named volume 缓存 Go build cache 和 module cache，避免一次性容器每次重新
  下载 Go toolchain/module。
- 在容器内运行 `make ipsec-xfrm-smoke`。
- 退出时尽量把 `build/` ownership 还给宿主用户，避免 root-owned 构建产物。

可用环境变量覆盖默认值：

```sh
PHOTON_CONTAINER_RUNTIME=podman make ipsec-xfrm-container-smoke
PHOTON_IPSEC_XFRM_IMAGE=ubuntu:24.04 make ipsec-xfrm-container-smoke
PHOTON_IPSEC_XFRM_CACHE_IMAGE=my-photon-xfrm-smoke:latest make ipsec-xfrm-container-smoke
PHOTON_IPSEC_XFRM_REBUILD_IMAGE=1 make ipsec-xfrm-container-smoke
PHOTON_IPSEC_XFRM_GO_CACHE_VOLUME=my-photon-gocache make ipsec-xfrm-container-smoke
PHOTON_IPSEC_XFRM_GO_MOD_CACHE_VOLUME=my-photon-gomodcache make ipsec-xfrm-container-smoke
PHOTON_CONTAINER_USERNS= make ipsec-xfrm-container-smoke
```

Docker 默认额外使用 `--userns=host`。这不是扩大外层 LXC 权限的魔法开关；它只是
避免 Docker 在已经 unprivileged LXC 的环境里再加一层 user namespace remap，从而
减少 mount/sysfs/netns 行为被二次映射弄坏的概率。若要验证它是否影响当前机器，可
用 `PHOTON_CONTAINER_USERNS=` 临时关闭。

如果要手工复现容器步骤，等价形式是：

```sh
docker run --rm -it --privileged \
  -v "$PWD":/work \
  -w /work \
  ubuntu:24.04 bash
```

注意：`--privileged` 是测试便利手段，不是安全隔离边界。尤其当宿主本身已经是
NixOS over LXC、云厂商受限容器、CI runner container 等嵌套环境时，内层
Docker/LXC 的 `--privileged` 不一定等价于真实宿主 root。外层 LXC 仍可能拦截
`/run/netns` mount、named netns、XFRM interface/state/policy、内核模块、AppArmor
或 seccomp 行为。因此不要只看容器启动参数是否有 `--privileged`；必须以
`make ipsec-xfrm-preflight` 的实际能力检查为准。若 preflight 中 named netns
create/delete、XFRM interface 或 VICI socket 检查失败，应换 root VM/裸机测试机，
或调整外层 LXC 配置后再跑。

## 1. 前置检查

运行：

```sh
make ipsec-xfrm-preflight
```

真实 `ipsec-xfrm-smoke` 创建任何资源前，必须先通过 preflight。它检查：

- Linux 内核是否支持 XFRM。
- 当前进程是否是 root，或是否具备有效 `CAP_NET_ADMIN`。
- VICI socket 是否存在；默认是 `/run/charon.vici`，可用 `PHOTON_VICI_SOCKET` 覆盖。
- `ip`、`swanctl`、`charon` 是否可用。
- `ip link type xfrm` 是否可用。
- named netns 是否能真实 create/delete；这一步能提前发现 LXC/嵌套容器里常见的
  `/run/netns` 或 mount namespace 限制。
- 当 `PHOTON_IPSEC_CHECK_UDP=1` 时，额外检查 IKE/NAT-T UDP 端口是否可绑定。

如果 preflight 失败，先修宿主机环境。不要让半途失败的 smoke 留下 connection 或
interface。

## 2. 当前自动化 Smoke

显式系统 smoke 入口为：

```sh
make ipsec-xfrm-smoke
```

在日常宿主机没有 root/system 网络权限时，优先使用容器包装入口：

```sh
make ipsec-xfrm-container-smoke
```

该目标不会进入 `make smoke-all`。它会：

1. 构建 `build/photon`。
2. 运行 `docs/scripts/ipsec-xfrm-preflight.sh`；任何 root/CAP、VICI、charon、
   iproute2 或 XFRM 能力缺失都会在创建资源前失败。
3. 设置 `PHOTON_IPSEC_XFRM_SMOKE=1`，运行
   `TestSystemXFRMDriverIntegrationSmoke`、
   `TestSystemXFRMDriverPeerTunnelPingSmoke`、
   `TestStrongSwanDriverLoadsKeyAndConnection`、
   `TestStrongSwanDriverIKEBringupSmoke` 和
   `TestDaemonReconcileUsesSystemXFRMDriverSmoke`、
   `TestDaemonStrongSwanReconcileBringupSmoke`、
   `TestDaemonRunGossipStrongSwanBringupSmoke`、
   `TestDaemonStrongSwanReconcileBringupDerivedPoolSmoke`。
4. 创建一个一次性的 named netns、直接在该 namespace 内创建 XFRM interface、
   分配 tunnel address、验证 interface/address 可见，再删除 interface 和 namespace。
5. 创建两个一次性的 named netns、veth underlay、两端 XFRM interface、手工 XFRM
   state/policy 和 tunnel route，验证 A/B tunnel IP 能互相 `ping`。
6. 通过 VICI `load-key`/`load-conn` 在两个隔离 charon 实例之间建立真实 IKE_SA/CHILD_SA，
   创建 XFRM interface、分配 tunnel address，验证 A/B tunnel IP 能互相 `ping`；该测试位于
   `pkg/transport/ipsec` driver 层，不经过完整 daemon/gossip，但验证 StrongSwan/XFRM/VICI
   数据面闭环。
7. 通过 Photon daemon reconcile 路径创建一次性的 named netns 内 XFRM interface，
   分配 tunnel host prefix，并在 link group 删除后由 daemon teardown 清理 interface。
8. 在两个 named netns 中启动隔离 charon/VICI 实例，构造已验证的
   root -> `catofes.` -> `node-a`/`node-b` active state 与 signed `ipsec/*`
   records，让两个 daemon service 使用真实 `StrongSwanDriver` +
   `SystemXFRMDriver` 自动加载 key/connection、创建 XFRM interface、观测
   VICI `list-sas` 后把 `LinkInstance` 推进到 `up`，并验证 tunnel IP 双向
   `ping`；同一 smoke 还会在保留 charon/XFRM 运行态时重建 node-a daemon
   service，断言启动 reconcile 观测现有 SA、不会重复创建 SA，并继续通过
   tunnel ping。已有 `up` 状态可保持 noop；缺失或旧状态才需要 adopt/repair。
9. 启动两个 daemon service 的真实 `Run` 循环，让两端各自自动发布 signed
   `ipsec/profile`、`ipsec/addresses`、`ipsec/ports` 和 `ipsec/transport-key`，
   通过 UDP gossip 同步对端 Zone 后自动触发真实 StrongSwan/VICI + XFRM
   reconcile；测试断言双方 `LinkInstance=up`、VICI SA snapshot 可见，并验证
   tunnel IP 双向 `ping`。
10. 在 daemon reconcile 级真实 StrongSwan/XFRM smoke 中注入父 Zone 对 peer 的
    revocation，断言 planner 输出 revoked skip reason，daemon 执行
    terminate/unload/delete interface，VICI 不再观测到该 SA，`LinkInstance`
    被清空，tunnel ping 失败。
11. 新增 IPv4 `derived-pool` 覆盖：使用 `10.88.0.0/24` 的 deterministic host
    派生，验证两端 tunnel address 落在同一 pool 内，XFRM interface 分配 `/32`
    host prefix，添加 `remote/32 dev xfrm src local` 路由后双向 `ping` 成功。

失败时脚本会输出 `ip netns list`、host XFRM links、`ip xfrm state/policy` 和
`swanctl --list-sas`，方便区分 kernel/iproute2/StrongSwan 环境问题。

当前自动化 smoke 已验证真实 `SystemXFRMDriver` 的 namespace/interface/address
lifecycle，其中 XFRM interface 会在目标 named netns 内创建，避免依赖宿主创建后
move 到 netns 的额外权限路径；同时 smoke 验证了手工 XFRM state/policy 下的双
namespace tunnel ping，并验证 daemon reconcile 能驱动真实 XFRM provider 创建和
清理 interface/address。root-gated daemon reconcile smoke 进一步覆盖 verified
active state 进入 daemon reconcile 后的真实 StrongSwan/VICI + XFRM bring-up 和
tunnel ping；daemon run smoke 进一步覆盖自动发布 `ipsec/*` records、UDP gossip
同步和真实 VICI/XFRM apply 的同一闭环。

StrongSwan 控制面已有真实 govici 客户端边界：`GoviciClient` 连接 charon VICI
socket，并把 Photon 内部 `StrongSwanDriver` 生成的 `load-conn`、`terminate`、
`unload-conn` 和 streaming `list-sas` 调用转换为 govici `Message`。这条路径
避免在 daemon 核心控制面解析 `swanctl` 输出；`swanctl --list-sas` 仍保留为
失败诊断和人工对照。

真实 StrongSwan/VICI driver 层测试已落地：
`TestStrongSwanDriverLoadsKeyAndConnection` 验证 VICI `load-key` 加载本地私钥和
`load-conn` 消息构造；`TestStrongSwanDriverIKEBringupSmoke` 在单测中启动两个隔离
charon 实例、两个 named netns、veth underlay、XFRM interface、tunnel address，
通过 Ed25519/ECDSA raw-public-key 认证完成 IKE_SA/CHILD_SA bring-up，并断言 A/B
tunnel IP 双向 `ping` 成功。该测试证明 StrongSwan/XFRM/VICI 数据面闭环已打通，但它
位于 driver 层，不经过完整 daemon/gossip 路径。

daemon 默认使用 `ipsec.driver: strongswan`，但没有本地 `overlays:` link group 时
不会初始化 VICI/XFRM driver，也不会触碰 root namespace、charon 或 XFRM。系统 smoke
主机启用 StrongSwan link group 时可以在 `config.yaml` 中显式配置：

```yaml
ipsec:
  driver: strongswan
  vici_socket: /run/charon.vici
```

此时 daemon 启动会创建真实 `GoviciClient` 和 `SystemXFRMDriver`；
如果 VICI socket 不可连接，启动会直接失败，避免运行到一半才发现
StrongSwan 控制面不可用。

配置了 `overlays:` / link group 的 daemon 会自动发布本节点 signed `ipsec/*`
capability records：`ipsec/profile`、`ipsec/addresses`、`ipsec/ports` 和
`ipsec/transport-key`。transport key 独立于 Zone signing key，并持久化到本地
state meta，避免 daemon 重启后 fingerprint 抖动。

普通 Go 测试已经覆盖双 daemon dry-run 闭环：两端使用真实 root -> `catofes.` ->
`node-a`/`node-b` 信任链，各自发布 signed `ipsec/*` records，通过 UDP gossip 同步
对端 Zone，再由本地 `LinkGroupSpec` 推导 `TransportLinkSpec` 并执行 dry-run
provider apply。这证明 daemon publish/gossip/planner/reconcile 边界已接通。

root/container smoke 现在已经覆盖 daemon `Run` 循环下的对端 `ipsec/*` record
同步、真实 VICI IKE_SA/CHILD_SA bring-up 和 tunnel ping；daemon reconcile 级
smoke 还覆盖启动恢复观测现有 SA、唯一 SA 断言、revocation teardown、VICI SA
消失、XFRM interface 删除、tunnel ping 失败、bounded break-before-make 端口
轮换（4.4）和 bidirectional takeover（4.5）。它们仍是 Go 测试内的 daemon
service，不是外部 `build/photon daemon` OS 进程；后续如果需要继续收紧，可以把同一
断言扩展到 CLI 进程启动和双外部 daemon 进程的 gossip revocation 传播。外部
OS 进程级 smoke 不阻塞 Phase 4 闭环，属于后续 hardening/7.8 生产化阶段。

## 3. 最小手工 StrongSwan 健康检查

在接入 Photon daemon reconcile 前，先确认宿主机能跑最小 route-based IPsec 链路：

1. 启动或 reload StrongSwan，并确认 VICI 可用：

```sh
swanctl --stats
```

2. 确认 XFRM interface 支持：

```sh
ip link help xfrm >/dev/null
```

3. 在 Photon 之外创建一次性 namespace/interface 组合：

```sh
ip netns add photon-a
ip link add phx-test-a type xfrm if_id 4242
ip link set phx-test-a netns photon-a
ip netns exec photon-a ip addr replace fd00:1200::1/64 dev phx-test-a
ip netns exec photon-a ip link set dev phx-test-a up
ip netns exec photon-a ip link show phx-test-a
```

清理：

```sh
ip netns exec photon-a ip link delete phx-test-a || true
ip netns delete photon-a
```

这一步用于把 kernel/iproute2 问题和 Photon 控制面问题分开排查。

## 4. Photon Provider Apply 检查

第一个真正面向 Photon 的检查，是先不接 VICI，只验证 XFRM/netns apply：

- 从 verified `ipsec/*` records 和本地 `LinkGroupSpec` 构造 `TransportLinkSpec`。
- 使用带默认 `netns.default` 的 `SystemXFRMDriver`；`overlay.default_netns` / `ipsec.default_netns` 仅作为旧配置兼容别名。
- provider 预期按这个顺序执行：
  `EnsureNamespace -> LoadConnection -> EnsureInterface -> AssignAddress`.
- 真实 XFRM driver 只会在 `create=true` 时创建 named namespace；`host` 和 path
  namespace 必须已经存在。对于 path namespace，第一版 provider 建议先 bind 到
  `/var/run/netns` 下，再用 `kind=name` 管理。
- 对 named namespace，`SystemXFRMDriver` 直接通过
  `ip netns exec <name> ip link add ... type xfrm` 在目标 namespace 内创建
  interface，再执行 `ip netns exec <name> ip addr replace ...` 分配地址；这条路径
  更贴近 daemon 后续管理目标 netns 的实际行为，也避开部分 LXC/容器环境对
  host-side link move 的限制。

执行任何变更前必须先记录 apply plan。失败时 daemon 应把 link 标记为
`degraded` 或 `error`，记录失败 operation，并且不能继续执行后续步骤。

## 5. 完整双节点 Smoke 形态

完整双节点进程级版本的 `make ipsec-xfrm-smoke` 只应在 preflight 通过后扩展：

1. 创建两个 Photon 数据目录和两个 named namespace，例如 `photon-a` 和
   `photon-b`.
2. 完成 root -> `catofes.` -> `node-a.catofes.` / `node-b.catofes.` join。
3. 每个节点发布已签名的 `ipsec/profile`、`ipsec/addresses`、`ipsec/ports`
   和 `ipsec/transport-key` records。
4. 启动两端 `photon daemon` 进程，让 gossip 收敛。
5. link planner 从 verified active state 加本地 `LinkGroupSpec` 推导对称的
   `TransportLinkSpec`；不应需要为每个 peer 手写 link。
6. StrongSwan provider 通过 VICI 加载 connection 和 secret。`swanctl` 只作为人工
   debug / 交叉检查工具。
7. XFRM provider 在目标 named namespace 内创建 interface，并分配 tunnel host
   prefix；当前 daemon system smoke 已覆盖这条 apply/teardown 路径，并已在
   verified active state 下覆盖真实 VICI/XFRM bring-up 与 tunnel ping。
8. 断言 `LinkInstance` 进入 `up`。
9. 断言 VICI 和 `swanctl --list-sas` 能看到匹配的 IKE_SA/CHILD_SA identity、
   child name、reqid/if_id 和 endpoint。
10. 断言数据面能通过 tunnel IP 互相 `ping`。

失败输出应始终包含 daemon logs、VICI SA list、`swanctl --list-sas`、`ip link`、
`ip xfrm state`、`ip xfrm policy`、`ip route`，以及对应 namespace 内的
`ip addr`。

## 6. 恢复与撤销

root/container smoke 已覆盖当前 daemon service 级恢复与撤销：

- 重建任意一端 daemon service 时，daemon 必须观测已有 StrongSwan/XFRM state，
  不能重复创建资源；已有 `up` 状态可保持 noop，缺失或旧状态才需要 adopt/repair。
  当前测试断言 node-a 重建后通过 VICI 看到现有 SA、established SA 仍只有一组，
  并且 tunnel ping 继续成功。
- 从父 Zone 撤销其中一个 peer 后，本地 daemon 必须 terminate IKE_SA/CHILD_SA、
  unload connection、删除 XFRM interface 和 address，并阻止 reconnect/backoff
  再次把它拉起；当前测试断言 revoked skip reason、VICI SA 消失、XFRM interface
  删除、`LinkInstance` 清空和 tunnel ping 失败。

尚未覆盖的是两个外部 `build/photon daemon` OS 进程之间通过 gossip 传播 revocation
后的同一组断言；这属于更高保真的 hardening，不再阻塞 Phase 4.3 最小闭环。

Phase 4 只做到 peer-to-peer tunnel link 可用。Babel routing 和 prefix authorization
仍属于 Phase 5。

## 7. 近期 Provider 行为变更（排障时注意）

以下变更已落地，运行 `make ipsec-xfrm-smoke` 或手工调试时应留意：

1. **NAT-T server-port 对齐**：当对端 `ipsec/ports` 公告或 observed 端口为自定义 NAT-T 端口时，StrongSwan `load-conn` 的 `remote_port` 会使用该 NAT-T 端口，并设置 `local_port=4500`、`encap=yes`、`mobike=no`。这保证初始 IKE 包走 NAT-T socket/non-ESP marker 路径；固定 500/4500 场景仍兼容。

2. **VICI 操作超时**：所有 VICI call 默认带 10s 超时，避免 charon 无响应时 reconcile 挂起。`load-conn` 等调用会输出结构化 debug 日志，敏感 key material 会被脱敏。

3. **有界异步 CHILD_SA 发起**：`InitiateChild` 默认在后台通过独立 VICI client 异步执行，reconcile 主路径不等待 IKE 协商完成；后台任务不继承单次 reconcile 的取消信号，同一 CHILD_SA 的并发请求会合并。VICI `initiate` 请求显式携带 15s charon 端 timeout，本地调用使用稍长的 20s 兜底；每个 driver 默认最多同时向 charon 提交 4 个 initiate，其余请求先在本地排队且不打开 VICI socket。这样不可达 peer 不会通过残留的 blocking initiate callback 耗尽 charon worker。若需要同步发起可关闭 `InitiateAsync`。

4. **SA 建立宽限期**：`LinkInstance` 进入 `connecting` 后，如果已观测到部分 SA 状态或在 3 分钟宽限期内，reconcile 不会立即标记为 error/backoff；宽限期结束后仍未 established 才进入 repair。

5. **repair 主动重试 CHILD_SA**：`ReconcileActionRepair` 在重新 `load-conn` + ensure XFRM 后会显式调用 `InitiateTransportChild`，避免失败链路只反复更新 connection 而不重新发起。

6. **防火墙按 instance netns 执行**：如果配置了 `firewall.instances[]`，overlay instance 的 nft/iptables 命令会在对应 netns 内执行，host instance 仍在 host namespace；owner scope 使用 `host`/`<netns>` 而不是配置 id。nftables apply 会重建同名 Photon table 以清除 stale rules。
