# Ranet Windows 数据通路性能对照

2026-10-12，在与 [Photon 吞吐测量](throughput-testing.md) 相同的 Windows VM、1200 字节 UDP echo 工具和 Linux kernel XFRM peer 上，固定参照 Ranet `24a24a2` 的研究数据通路测得单流 **464.24 / 483.24 Mbps**，当前快照 `9eaabcd` 为 **499.47 / 499.61 Mbps**，均零 echo 丢失。当前版四流每流窗口 64 为 **689.23 / 701.82 Mbps**，丢失 3 / 2 个回包。本轮尚未达到单方向 1 Gbps。

这些是**经过测试兼容修补、使用静态 SA 和路由的 Windows 数据通路结果**，不是原版 Ranet 完整产品实测。它省略 IKE 协商、rekey、Babel 周期任务和注册表加载，也没有 Photon 的签名撤销、权限期限和逐包授权门禁。因此能比较 Windows I/O 与 ESP 管线的实际成本，不能据此计算完整产品速度比值。

## 来源与原版 Windows 构建

固定参照来自此前研究锁定的官方提交 [`24a24a2ff380c9f8ceb0092d640daa32e86b5eb5`](https://github.com/NickCao/ranet-lite/commit/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5)，2026-08-19 的 `protocol: enforce supported profile invariants`。2026-10-12 检查到的官方 master 为 [`9eaabcd8e0c7599c81ffa434b34a6f36538c3e09`](https://github.com/NickCao/ranet-lite/commit/9eaabcd8e0c7599c81ffa434b34a6f36538c3e09)，2026-10-02 的 `Use Tailscale wireguard-go for native multiqueue TUN`。

在已读取的官方 README、benchmark 材料、advertised refs 和 [Releases API](https://api.github.com/repos/NickCao/ranet-lite/releases) 中，没有找到公开的 Windows 吞吐结果；该日 Releases API 返回空数组。这是本次检查范围内的结论，不表示其他位置一定没有资料。

固定版的 [CLI](https://github.com/NickCao/ranet-lite/blob/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5/cmd/ranet-lite/main.go) 直接引用 `syscall.SIGUSR1`。以 Go 1.26.5、锁定依赖、`GOOS=windows GOARCH=amd64 CGO_ENABLED=0` 实际交叉构建失败：`main.go:134:36: undefined: syscall.SIGUSR1`。研究兼容补丁只把该路由调试信号处理移到平台文件；Windows 不安装这个 Unix 信号监听，不改变 UDP、Wintun、ESP 或 IKE 代码。修补后的独立 CLI 构建及 Windows 原生 `-help` 通过，不能称为原版 CLI 原样通过。

## Windows 实际采用的 I/O

固定版 [transport.NewHub](https://github.com/NickCao/ranet-lite/blob/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5/internal/transport/mux.go) 明确调用 `conn.NewStdNetBind`。当前版的 [非 Linux socket](https://github.com/NickCao/ranet-lite/blob/9eaabcd8e0c7599c81ffa434b34a6f36538c3e09/internal/transport/socket_default.go) 也调用这个接口。它们没有走 WireGuard 的 `NewDefaultBind` / Windows Registered I/O（RIO）backend。

- 锁定的 WireGuard [`bind_std.go`](https://git.zx2c4.com/wireguard-go/tree/conn/bind_std.go?id=ecfc5a8d5446) 在 Windows 的 `BatchSize` 为 1，实际使用 `ReadMsgUDP` 和逐包 `WriteMsgUDP`，并尝试设置 7 MiB socket 缓冲。Linux/Android 的 batch 128 与 UDP GSO/GRO 不能算作 Windows 行为。
- WireGuard 确实另有 [`bind_windows.go`](https://git.zx2c4.com/wireguard-go/tree/conn/bind_windows.go?id=ecfc5a8d5446) RIO 实现，但上述 Ranet 入口没有采用它。该实现也返回 `BatchSize=1`；存在 RIO 源码不构成本轮使用 RIO 的证据。
- 锁定的 [`tun_windows.go`](https://git.zx2c4.com/wireguard-go/tree/tun/tun_windows.go?id=ecfc5a8d5446) 使用 Wintun 8 MiB rings，每次 API 读写一个包。其自适应等待源码阈值为合计 800 Mbps、spin 最长 12.5 µs；读和写都会累计 rate，不能仅用单方向 echo Mbps 判断本轮是否进入 spin。当前版 [非 Linux TUN](https://github.com/NickCao/ranet-lite/blob/9eaabcd8e0c7599c81ffa434b34a6f36538c3e09/internal/netstack/tun_other.go) 仍只有一个 queue。
- 固定版 [Mesh](https://github.com/NickCao/ranet-lite/blob/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5/internal/netstack/mesh.go) 有常驻出站 crypto workers、按读取顺序提交结果；入站按包启动受 semaphore 限制的 goroutine，再按接收顺序投递。出站 ESP 序号在 worker 内生成，结果顺序不等于序号预留顺序。当前版改用 [reserved Peer、receiveESP 和 ordered replay commit](https://github.com/NickCao/ranet-lite/blob/9eaabcd8e0c7599c81ffa434b34a6f36538c3e09/internal/client/peer.go)，需独立实测，不能从 Linux multiqueue 提交名推断 Windows 收益。

## 固定版实测范围与结果

Windows 11 专业版 VM，8 个逻辑 CPU，报告 CPU 为 i9-12900H；Go 1.26.5、Windows amd64/GOAMD64=v1、CGO 关闭。Ranet 原始 `go.mod` / `go.sum` 不变，WireGuard 为 `ecfc5a8d5446`，Wintun DLL 为官方 0.14.1 amd64。构建不加 profile 标签，测试 executable 包含显式 opt-in 的 `TestResearchStaticDataPlane`；原版 CLI、兼容 CLI 和研究 executable 是三个不同的材料。

夹具保留原 `netstack.Mesh`、`transport.Hub/Mux`、ESP、Wintun、Babel 入站识别，以及固定版 `connectPeer` 的有序接收流程和原错误日志。静态 AES-GCM-128、16 字节 ICV、4 字节 salt、非 ESN、双方 replay window 64、MTU 1280；静态精确双栈 host route 替代协商和动态选路。固定版默认 replay 为 32，本轮显式 64 用于匹配 Photon 对照，不把它当作上游默认值。

Linux 使用同一临时 Ubuntu 24 image，StrongSwan 6.0.7 仅提供 UDP 4500 kernel decapsulation socket，独立 network namespace 内安装静态 XFRM SA；不启动 IKE 协商或 Babel peer。静态 XFRM 双向设置 `af-unspec`，允许同一 IPv4 外层承载双栈内层。每轮测试 key 随机生成，仅存在 ignored、权限受限的研究目录；没有生产 key。

复用最终 credit 工具 `c1c8ea8aa1e8a5032966b947fa872d0005abe139`，每点预热 2 秒、发送 8 秒、deadline 1 秒、800 万包预算，按唯一完整 echo payload 除以包含排空的实际时间。每次 echo 穿越双向数据通路，**表中不把双方向相加**。CPU 是研究进程累计 CPU / 实际时间，单位为单个逻辑核百分比，Linux kernel 和生成器 CPU 不计入该列。

| 地址族 / 流数 / 每流窗口 | 唯一 echo Mbps | echo 丢失 | Ranet 研究进程 CPU / 单核 % |
| --- | ---: | ---: | ---: |
| IPv4 / 1 / 64 | 464.24 | 0% | 265.23 |
| IPv6 / 1 / 64 | 483.24 | 0% | 284.72 |
| IPv4 / 4 / 64 | 648.31 | 0.0181% | 270.11 |
| IPv6 / 4 / 64 | 637.54 | 0.0238% | 249.15 |
| IPv4 / 4 / 1024 | 579.00 | 4.3615% | 252.66 |
| IPv6 / 4 / 1024 | 632.51 | 4.0315% | 235.50 |

六点均 `Completed=true`，无损坏、未发送序号、重复、外来、迟到回包、发送错误或包预算耗尽；每点结束后的低压恢复 echo 均通过，同一 fixture PID / 创建时间保持一致。顶层 JSON `Completed=true`，协调脚本退出 0，独立确认研究进程、Wintun 网卡、远端目录和 Docker 容器全部清理。大窗口有明显丢包，不能把容量探索点称为无损吞吐。

固定版最后的 Linux `XfrmInStateSeqError=959`，Windows 原日志报告 227 个 `sequence ... too old`，其余 payload 验证失败为 0。这证明本轮存在 replay 丢弃；累计日志没有按每个点切分，不能据此归因全部 echo 丢失、判断丢弃起因或宣称当前版已解决。本轮每点仅一次短测，没有长期稳定性或统计显著性证明。

## 当前快照的独立实测

当前 `9eaabcd8e0c7599c81ffa434b34a6f36538c3e09` 使用 [Tailscale WireGuard 精确提交 `18e99eba5393b8c9ea513ab7a1db1a12625422ca`](https://github.com/tailscale/wireguard-go/commit/18e99eba5393b8c9ea513ab7a1db1a12625422ca)。官方精确源码的 [UDP bind](https://github.com/tailscale/wireguard-go/blob/18e99eba5393b8c9ea513ab7a1db1a12625422ca/conn/bind_std.go) 与 [Windows TUN](https://github.com/tailscale/wireguard-go/blob/18e99eba5393b8c9ea513ab7a1db1a12625422ca/tun/tun_windows.go) 已下载并与本轮锁定 Go module 逐字节比较一致，两者 Windows `BatchSize` 均为 1。实际 fixture ready 记录 `tunQueues=1`、入站 workers 为 8，因此没有把 Linux multiqueue/GRO 算成 Windows 优化。

当前原版 CLI 同样交叉构建失败于 `main.go:67:36: undefined: syscall.SIGUSR1`；采用相同最小调试信号补丁后构建及原生 `-help` 通过。研究 test 位于该版 `internal/client`，直接使用真实 [tunnel.install / reserve / decryptBatch](https://github.com/NickCao/ranet-lite/blob/9eaabcd8e0c7599c81ffa434b34a6f36538c3e09/internal/client/tunnel.go)、`NewPeerReserved`、[receiveESP](https://github.com/NickCao/ranet-lite/blob/9eaabcd8e0c7599c81ffa434b34a6f36538c3e09/internal/client/receive.go)、`CommitBatch` 和 `DeliverInboundBatch`，没有通过兼容旧 API 别名代替新生产流程。该版原默认 replay 为 4096，本轮仍显式设置双方 64；其原 `go.mod` / `go.sum` 与 fixture 文件校验完全一致。

先运行 ESP、transport、netstack、client 四个 Windows 原生测试包，全部 PASS；研究 test 未配置时明确 skip。独立一秒双栈 probe 的 echo、恢复、JSON 和清理均通过后，使用与固定版相同工具、套件、MTU、8 秒发送及窗口运行六点。两轮采样均无其他 host/VM 重型编译、测试或 benchmark 并行。

| 地址族 / 流数 / 每流窗口 | 唯一 echo Mbps | echo 丢失 | Ranet 研究进程 CPU / 单核 % |
| --- | ---: | ---: | ---: |
| IPv4 / 1 / 64 | 499.47 | 0% | 218.33 |
| IPv6 / 1 / 64 | 499.61 | 0% | 228.48 |
| IPv4 / 4 / 64 | 689.23 | 0.000522%（3 包） | 226.32 |
| IPv6 / 4 / 64 | 701.82 | 0.000342%（2 包） | 219.84 |
| IPv4 / 4 / 1024 | 639.90 | 4.0808% | 203.73 |
| IPv6 / 4 / 1024 | 641.39 | 4.0137% | 195.11 |

六点全部完成、逐点低压恢复通过；无损坏、未发送、重复、外来、迟到 echo、发送错误或预算耗尽，顶层 `Completed=true`，协调脚本退出 0。独立清理核验确认 fixture、Wintun 网卡、VM 目录和容器全部消失。Linux XFRM 全部错误计数为 0，Windows 原日志仍有 5 个 `sequence ... too old`；不能据此归因大窗口约 4% 的全部 echo 丢失。相比固定版，本次小窗口吞吐更高、进程 CPU 更低，但每点仅一次短测，不能断言单项改动的因果收益或长期稳定性。当前版同样省略上述控制平面和 Photon 动态授权语义，不作为完整产品性能比值。

## 本地可复查材料

完整材料位于本地 ignored `build/validation/performance-20261012/ranet/`，不加入 Photon 依赖、发布包或公共 API：

- [来源、原版编译失败、平台兼容补丁](../../build/validation/performance-20261012/ranet/source-audit.txt)、[精确错误](../../build/validation/performance-20261012/ranet/windows-original-build-with-deps.log)、[CLI patch](../../build/validation/performance-20261012/ranet/windows-cli.patch)。
- [冻结固定版研究 fixture](../../build/validation/performance-20261012/ranet/frozen-static-fixture.go)、[host 编排](../../build/validation/performance-20261012/ranet/run-native.sh)、[Windows 测量与清理](../../build/validation/performance-20261012/ranet/measure-windows.ps1)、[Linux 静态 XFRM](../../build/validation/performance-20261012/ranet/setup-linux.sh)。
- [artifact / 脚本 SHA256](../../build/validation/performance-20261012/ranet/research-sha256.txt)、[Go build info](../../build/validation/performance-20261012/ranet/fixture-build-info.txt)、[四个相关包 race](../../build/validation/performance-20261012/ranet/fixed-race.log)。研究 fixture executable SHA256 为 `e8453b6173c6795ce740cfc7f65467962e09485e21050436c8ea4a506f17771a`；Wintun DLL 为 `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`。Linux/Windows 工具 SHA 与 Photon 最终 credit 矩阵相同。
- [完整六点 JSON](../../build/validation/performance-20261012/ranet/ranet-research-20261012-210820-1817320/throughput.json)，同目录保存每点 warmup、measurement、recovery、进程资源样本、原始 ESP / XFRM 日志、二进制 SHA 和 cleanup；[独立清理证明](../../build/validation/performance-20261012/ranet/fixed-cleanup-independent.log)。
- 当前版 [原版编译失败](../../build/validation/performance-20261012/ranet/current-windows-original-build.log)、[精确构建命令](../../build/validation/performance-20261012/ranet/build-current.sh)、[CLI patch](../../build/validation/performance-20261012/ranet/current-windows-cli.patch)、[冻结真实生产流程 fixture](../../build/validation/performance-20261012/ranet/frozen-current-static-fixture.go)、[module 文件一致性](../../build/validation/performance-20261012/ranet/current-module-sha256.txt) 与 [实际依赖图](../../build/validation/performance-20261012/ranet/current-fixture-dependencies.txt)。研究 executable SHA256 为 `eac2953d8bc99e168e0b3d58f68a3df6ed25841b15c72b8d0bb0d2261cb29a4e`。
- 当前版 [四包原生测试及目录清理](../../build/validation/performance-20261012/ranet/ranet-current-unit-20261012-212451-1909830/native-tests.log)、[完整六点 JSON](../../build/validation/performance-20261012/ranet/ranet-research-20261012-213846-1974660/throughput.json)、[独立清理证明](../../build/validation/performance-20261012/ranet/current-cleanup-independent.log)；原始进程、ESP/XFRM、warmup/recovery 与 tool/DLL SHA 均随本轮保留。

先前失败轮全部保留，不能纳入有效六点矩阵：第一轮 Windows 默认 cmd shell 下的错误脚本引号导致入口未运行；后续地址尚未 Preferred 时绑定失败；再一轮静态 XFRM 缺少 `af-unspec` 导致 IPv6 未返回，PowerShell 将带扩展属性的 `Get-Content -Raw` 结果放入 JSON 又导致结果保存停滞。修正后先做 [一秒双栈 window 1 探针](../../build/validation/performance-20261012/ranet/ranet-research-20261012-210713-1811471/throughput.json)，双向 echo、JSON 和独立清理通过，才运行本节完整测量。失败轮的研究进程及 adapter 先清理，卡住的 serializer 仅在核实精确 command line / 创建时间后停止；失败证据不视为产品瓶颈。
