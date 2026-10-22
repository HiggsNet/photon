# B4 Babel、授权与 Windows 数据通路验收

## 状态与范围

2026-10-06 在 `windows` 分支继续 B4。B3 的 IKE/ESP、双版本 StrongSwan 和 Windows
跨主机协议验收已完成，见 [IKE 验收](ike-testing.md)。本文按独立切片记录 B4，
不把公共逻辑、平台 API 或单段数据通路的通过当作完整产品隧道通过。

### 完整 Router ID 与当前授权

- 由 root pin、Zone 和 overlay 派生稳定的完整 64 位 Router ID，不增加独立持久状态。
- 使用公共 typed intent 发布签名 `routing/babel/identities`，检查租约、当前签名链和 root pin；
  跨 Zone 碰撞、撤回、到期及未来时间记录均拒绝。
- 路由匹配完整 ID 的 origin 与精确公告前缀；提交/使用时重新检查 revision、当前 gateway、
  SA generation、IKE/CHILD 硬过期和本机传输授权。
- `pkg/routing`、`pkg/core/state`、`internal/photonwindows` 的相关测试与 race 检查通过。

签名记录证明身份认领，不证明转发 Update 的端到端来源；仍以显式信任的单 gateway 为实验边界。
Linux BIRD 的随机完整运行时 ID 已由 Linux Daemon 自动发布，不能仅匹配 BIRD 的低 32 位放行。

source-specific 路由的 source prefix 仅收紧本机使用条件：规范、非零且与目的地址同族，
并须覆盖至少一个当前获授权且已公告的非共享本机 /32 或 /128。每次 lookup 仍验证实际
本机地址，入站反向 lookup 以原始本机目标地址匹配该条件。远端仍须拥有精确目的前缀授权；
source prefix 不授权额外本机地址，也不允许转发。双栈、fallback、反向匹配及排队期间
撤销的包测试和 race 通过；真实 IPv6 SADR 跨主机互通见下文。

### 单 gateway Babel leaf

`Neighbor` 管理 Hello/IHU、序号回绕、精确到期和有界 ACK；`Leaf` 管理本地公告、
周期更新、请求应答、路由刷新/撤回和当前授权。最多 256 个本地 origin、4096 条 learned route。
不导出 learned route，不做 transit。网关 attachment 变化时重建，普通 SA rekey 保留邻居状态。

包测试、race 和 vet 已通过，覆盖单向链路、过期、撤回、无授权、伪造本机 ID、上限和请求限频。

真实 BIRD 2.19.1 在 `--network none` 隔离容器的 veth/netns 中通过：Hello/IHU 收敛、
IPv4-via-IPv6 与 IPv6 学习、本地双栈公告及撤回、SIGSTOP 后无撤回报文的静默邻居超时。
随机 Router ID 场景约 19.59 秒；默认非随机场景也通过。测试检查实际发出的每个有限 Update
均属于本机，learned route 的请求只得到撤回，不得到重新分发。

`show babel entries <protocol>` 的本地注入前缀行提供完整运行时 ID，测试已与 wire ID 比对。
生产解析器仅接受指定 protocol 中与当前授权本地前缀精确匹配、metric 为 0、Routes/Sources
为 0 的本地注入证据；拒绝不完整或歧义 ID。Linux Daemon 启动、周期协调及路由协调后观察，
通过公共签名事务发布两分钟租约，在剩余一分钟时续租；证据缺失或禁用时撤回。
不能拿任意 learned entry 认作本机 ID，也不能假设没有本地公告时该表仍能提供 ID。
生产解析器已再次通过真实 BIRD 2.19.1 验收，日志为
`/tmp/photon-babel-identity-observer-interop.log`。

Windows 本机地址意图仅取当前非共享、授权精确匹配的 /32 或 /128；不从子网猜测主机地址。
自动公告保留手动撤回。Babel 链路地址复用 Linux 的 overlay/link/port generation 派生契约，
当前仅支持显式 `derived-link-local`，不猜测未配置地址。

StrongSwan 的 link-local 控制地址现允许同一 CHILD SA 的 IPv4/IPv6 业务 TS；全局地址的
既有单地址族行为保持。StrongSwan 5.9.13 与 6.0.7 均通过同一 CHILD/SPI 双栈内核 ESP
往返验收，日志为 `/tmp/photon-linklocal-dual-esp.log` 与 `-nix.log`。

本次复验命令如下，需要隔离容器所需权限；Nix 包路径和镜像可换为具备 `bird`、`birdc`、
`ip`、`bash` 的测试环境。脚本不修改宿主机路由，退出检查容器已清理。

```sh
GOCACHE=/tmp/photon-gocache GOMODCACHE=/home/herbertqiao/go/pkg/mod \
  PHOTON_BIRD_NIX_PACKAGE=/nix/store/pxqa13ld4l0ihvz123bwhaimkn1pfjxw-bird-2.19.1 \
  bash docs/scripts/windows-babel-interop-smoke.sh
```

本次日志：`/tmp/photon-windows-babel-interop-final.log`。这是 portable Windows leaf 与真实 BIRD
的协议验收，未经过 Windows OS、Wintun 或 ESP。

### 授权、ESP 与共享 UDP 的双向管线

`gatewayBabelPipeline` 使用同一个串行调用方传入的当前 view/time；Babel 控制包在 ESP 内传输，
不交付 packet device。业务出站源地址与入站目标均精确匹配本机地址，收到的路由只用于本机选路
和入站反向来源授权，不做 transit。普通 CHILD rekey 保留 Leaf，attachment 撤销或 generation
变化使其失效；提交和 crypto completion 交付均重新校验。

真实 ESP worker、共享 UDP socket 与内存 Read/Write 设备集成测试通过：双向载荷、控制分流、
源地址伪造与 transit 拒绝、双向 completion 撤销/到期、rekey overlap、队列背压及 80 个本地
origin 批包覆盖。控制 payload 最多 1200 字节，避免每条公告独占队列而遗漏尾部前缀。
相关包全量测试及 pipeline race 通过。

该 owner 已接入 console Daemon：认证完成后协调本机公告与身份租约，异步创建配置设备，
检查当前 revision/generation 后接收完成结果；真实 Read pump、ESP completion 和周期 Tick
由同一运行循环协调。撤销、重绑和停止先撤掉 pipeline，再关闭并 join 设备。
仅当前 SA、平台地址就绪、Babel 邻居有效且实际本机地址能选到授权路由时发布
`tunnel_ready_changed=true`，同时检查 source constraint；撤销、重绑、设备失败或停止时
立即撤回 ready。composition 全包及相关 race 测试通过；这不是完整 Windows
原生跨主机业务隧道验收。

### IP Helper 原生协调

仅操作本进程新建 Wintun adapter 的 LUID，不使用接口索引回退，不执行 shell 网络命令。
使用 `Observe -> Plan -> Apply -> Re-observe`，先撤销再添加；只接受配置中的精确 split aggregate，
拒绝默认路由和越界前缀。地址限定 /32 或 /128，保留 Windows 自动生成的 link-local。

Windows 11 amd64 VM 上 `TestIPHelperSockaddrABI`、`TestIPHelperPlanBoundaries`、
`TestIPHelperPlanDriftAndWithdrawal`、`TestIPHelperNativeLifecycle` 均通过。
原生生命周期约 3.52 秒：双栈地址实际进入 DAD Preferred，重复协调无变化，删除路由后重建，
撤销及带配置关闭 adapter 后无残留。使用临时 benchmark/ULA 前缀，未改 VM 管理网卡或默认路由。

`Reconcile` 返回配置已收敛的观察，不能据此宣称 DAD 已完成或隧道可用。平台组合入口已等待
实际地址达到 DAD Preferred 后才交付设备，取消或失败会回收配置和 adapter。

后续原生回归已覆盖创建、DAD、取消、重复关闭、重建、初始化期间取消；自建 Wintun 的
通知不触发 underlay 重绑，外部临时接口变化仍能触发。修正 `x/sys` IP interface row 的
原生布局差异（168 字节），增加 size/offset 断言，防止遍历接口表时读错后续行。
平台原生生命周期、双栈往返及 B2 通知回归通过，临时网卡和路由已清理；证据为
`/tmp/photon-b4-owned-device-native.log`。

### Wintun 与 Windows TCP/IP 双向收发

`TestWintunNativeUDPRoundTrip` 在同一 Windows 11 VM 通过：真实 `udp4` / `udp6` socket
发包，经系统路由进入 `Wintun.Read`；测试构造带正确校验和的应答，经 `Wintun.Write` 注入，
原 socket 收到 25 字节载荷。双栈用例合计约 3.50 秒，关闭后地址/路由表无该 LUID 残留。
同期重跑 IP Helper 与原 Wintun lifecycle 均通过，临时测试目录和网卡已清理。
这证明 Wintun、IP Helper 与 Windows TCP/IP 闭环，尚未穿过 ESP 或远端网关。

复验需 Windows 管理员权限和固定官方 Wintun DLL。在 Linux 仓库根目录生成 bundle：

```sh
GOMODCACHE=/home/herbertqiao/go/pkg/mod bash docs/scripts/windows-wintun-smoke-build.sh
```

将输出目录整体复制到 Windows，在该 VM 执行：

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <bundle>/run.ps1
```

脚本显式启用 Wintun/IP Helper 原生测试，使用临时 adapter 和测试前缀；不属于普通无特权单元测试。
本次本地证据为 `/tmp/photon-b4-iphelper-native.log` 与
`/tmp/photon-b4-wintun-roundtrip-native.log`，日志路径仅指开发机本次运行。

## 集成检查

本轮所有切片合并后，完整 Go 测试、fmt、vet、Linux 构建和 Windows amd64 交叉编译通过。
重复打包遇到既有只读许可证无法覆盖的问题，已使复制目标可重建；连续两次 Windows 构建通过，
第三方 notice 内容和源文件权限保持不变。检查日志为 `/tmp/photon-b4-check.log`，
打包修复的复验日志为 `/tmp/photon-b4-repeat-build-1.log` 和 `-2.log`。

上述 Daemon、平台生命周期、source-specific 授权和就绪撤回接线后，再次运行完整
`make check` 通过，覆盖 fmt、vet、全量 Go 测试、Linux 构建与 Windows amd64 交叉编译。
本轮日志为 `/tmp/photon-b4-runtime-check.log`。

完整原生验收入口、签名撤销/恢复、SADR 与双 gateway 切换合并后，最终 `make check`
和 Windows amd64 `go vet ./internal/photonwindows` 再次通过，日志为
`/tmp/photon-b4-native-final-check.log`。

## 完整业务链路验收

`docs/scripts/windows-b4-cross-host-smoke.sh` 构建实际 Windows Daemon 测试与一次性 Linux
StrongSwan/BIRD 网关。网关使用随机临时身份、签名公共数据库与实际 BIRD 完整 ID；Windows
通过真实 UDP socket 检查双栈往返、显式重绑后恢复和 adapter/地址/路由回收。BIRD 内核导出
仅接受 learned Babel 路由，Windows 回程路由必须由本机公告实际学习。

脚本需要明确授权测试 VM 上的临时数据库/密钥传输、Wintun 和测试路由变更。运行示例：

```sh
PHOTON_WINDOWS_SSH=photon-test@10.16.252.11 \
PHOTON_LINUX_IP=10.16.255.8 \
PHOTON_BIRD_NIX_PACKAGE=/nix/store/pxqa13ld4l0ihvz123bwhaimkn1pfjxw-bird-2.19.1 \
bash docs/scripts/windows-b4-cross-host-smoke.sh
```

Windows 11 amd64 与隔离 Ubuntu StrongSwan 5.9.13 / BIRD 2.19.1 的完整基线通过，
耗时 18.35 秒：IPv4/IPv6 实际业务往返、显式重绑后双栈恢复、稳定性探测、停止时
adapter/地址/路由清理。两次成功创建与两次完成关闭匹配；重绑观察到 ready 立即
false 后重新 true。Windows 可以合法复用 LUID，验收按实际设备生命周期检查重建。
本次日志为 `/tmp/photon-windows-b4.0KkZiD/windows.log`。

后续真实签名 gossip 撤销/恢复验收通过（22.44 秒）：隔离 authority 经公共签名事务
撤销本机双栈 assignment，Windows 运行中的 object-pull 返回新签名版本和值 hash，
证明 verified state 已收敛；随后 ready=false，保留的真实 UDP sockets 收不到回包，
设备、地址及路由全部回收。恢复签名 assignment 后，新的设备生命周期建立，双栈
业务与 ready 恢复；三次创建/关闭数量匹配。日志为
`/tmp/photon-windows-b4.VaOdAU/windows.log`。测试不并发打开运行中的 Bolt 或直接改其状态。

`PHOTON_WINDOWS_B4_SADR=1` 模式启用真实 IPv6 源特定路由，三个 BIRD IPv6 channel
使用 SADR 表；目的 `fd00:7068:b4::1/128` 只由 `from fd00:7068:b4::2/128` 路由公告。
启动检查实际 table/export 双视图，拒绝 destination-only 回退；完整 ID 继续以同实例
精确本地 IPv4 注入证据发布。StrongSwan 5.9.13 与 6.0.7 下完整双栈业务、重绑、
撤销/恢复和清理均通过，分别为 23.29 秒和 22.68 秒，日志为
`/tmp/photon-windows-b4.qENEHD/` 与 `/tmp/photon-windows-b4.zsTm4S/`。
此模式验证 IPv6 SADR，IPv4 保持普通路由；不宣称已验收原生第二源地址的拒绝场景。

### 不同 gateway 的真实切换

`docs/scripts/windows-b4-gateway-switch-smoke.sh` 启动两个独立容器，各自拥有 transport
私钥、完整随机 BIRD ID、XFRM 与 kernel 回程表；只交换公开 manifest，再生成统一根信任和
Windows 客户端状态，后端私钥不离开容器。

Windows 先与 gateway A 完成双栈业务，然后 authority 通过公共签名事务及真实 gossip
禁用 A 的 profile。测试验证运行中的新签名版本/hash，旧设备关闭、ready=false、B 认证、
新设备创建和 ready=true；B 双栈业务及稳定性恢复，A 双栈业务持续拒绝。
结束时检查两 backend 的进程、鲜活流量快照及既有双栈服务计数，证明 A 仍存活，
切换由授权变更触发。原生生命周期和 owned 地址/路由清理通过。

StrongSwan 5.9.13 与 6.0.7 均通过，分别为 15.31 秒和 14.61 秒，日志为
`/tmp/photon-windows-switch.RnSd9X/` 和 `/tmp/photon-windows-switch.IEdJpp/`。
VICI 状态是一秒采样，远端 SA 删除仍为 best-effort；该用例不替代旧 SA 密文重放和
generation 拒绝的既有 pipeline 测试。

全部脚本结束后另做只读复核：Windows 仅剩原管理网卡，上述四条测试 split aggregate
及本轮临时目录均不存在；本机单/双网关一次性容器也无残留。临时凭据已清理，公开日志保留。

首次试跑发现 fixture 漏启 XFRM multicast，已补齐与生产驱动相同的步骤；生产 Babel
本来支持认证 ESP 内的组播控制帧，并增加错误 peer、host 注入及排队撤销回归。
测试凭据提前十五秒签发，兼容测试机的轻微时钟偏差，生产 NotBefore 检查保持严格。
退出清理一次性容器和凭据，保留本次日志；测试进程硬超时或机器故障后仍须确认 VM 资源状态。

## 产品边界与下一阶段

- 端到端来源证明仍受上述可信单 gateway 边界限制，不由 Router ID 签名认领替代。

B4 当前设计范围内的接线与分层验收已完成。B5 服务/IPC 与 B6 完整产品矩阵仍待推进；
console 无当前授权 pipeline 时仍默认拒绝业务数据，运行时就绪事件不能替代完整产品验收。
