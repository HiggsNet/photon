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
  SA generation、IKE/CHILD 硬过期和本机传输授权。source-specific 路由当前明确拒绝。
- `pkg/routing`、`pkg/core/state`、`internal/photonwindows` 的相关测试与 race 检查通过。

签名记录证明身份认领，不证明转发 Update 的端到端来源；仍以显式信任的单 gateway 为实验边界。
Linux BIRD 的随机完整运行时 ID 尚未自动发布，不能仅匹配 BIRD 的低 32 位放行。

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
未来自动发布必须识别本地来源并绑定实例、续租和重启；不能拿任意 learned entry 认作本机 ID，
也不能假设没有本地公告时该表仍能提供 ID。

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

该 owner 尚未接入 console 的平台生命周期，测试不是 Windows 原生业务跨主机隧道验收。

### IP Helper 原生协调

仅操作本进程新建 Wintun adapter 的 LUID，不使用接口索引回退，不执行 shell 网络命令。
使用 `Observe -> Plan -> Apply -> Re-observe`，先撤销再添加；只接受配置中的精确 split aggregate，
拒绝默认路由和越界前缀。地址限定 /32 或 /128，保留 Windows 自动生成的 link-local。

Windows 11 amd64 VM 上 `TestIPHelperSockaddrABI`、`TestIPHelperPlanBoundaries`、
`TestIPHelperPlanDriftAndWithdrawal`、`TestIPHelperNativeLifecycle` 均通过。
原生生命周期约 3.52 秒：双栈地址实际进入 DAD Preferred，重复协调无变化，删除路由后重建，
撤销及带配置关闭 adapter 后无残留。使用临时 benchmark/ULA 前缀，未改 VM 管理网卡或默认路由。

`Reconcile` 返回配置已收敛的观察，不能据此宣称 DAD 已完成或隧道可用；未来组合入口仍须检查
实际地址状态后启用数据交付。

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

## 尚未完成的产品链路

- Linux BIRD 完整运行时 Router ID 的读取、签名发布、续租和重启更新。
- Windows 本机地址意图、IP Helper/DAD、Babel 与 packet device 的 Daemon 生命周期接线。
- 通过实际 Windows Wintun、ESP、Linux StrongSwan/BIRD 的同一条完整业务链路验证，
  包括双向 IPv4/IPv6、授权撤销、gateway 切换、重绑和清理。
- source-specific prefix 授权契约与端到端来源证明的剩余边界。

B4 未整体完成；B5 服务/IPC 与 B6 完整产品矩阵未纳入此次切片。console 的业务数据默认拒绝，
`tunnel_ready=false`，不得因单项测试通过提前改成完整隧道就绪。
