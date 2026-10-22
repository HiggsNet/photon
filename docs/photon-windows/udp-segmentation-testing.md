# Windows 外层 UDP 分段发送研究

2026-10-14 继续研究 [无加密 Wintun＋跨主机 UDP 对照](wintun-udp-timing-testing.md) 中约 10µs 的实际 UDP write。候选是一次同步发送多个完整、等长的外层 datagram，减少每包发送操作；不是更改 Wintun ring。本记录分开列出源码可行性、VM 配置、实际功能及容量证据，未完成项不代表产品支持或性能收益。

## 最小发送入口与边界

本机 Go 1.26.5 的 `WriteToUDPAddrPort` 在 Windows 经过同一 FD 的 writeLock、execIO 和 WSASendto；多个 goroutine 共用该 FD 仍会串行写。标准 `UDPConn.WriteMsgUDPAddrPort` 则经过同一 Go FD/execIO，调用 WSASendMsg，保留同步返回、deadline、Close 和 buffer 完成等待的生命周期。更换 API 本身没有证明更快。

[Microsoft MsQuic 官方实现](https://github.com/microsoft/msquic/blob/main/src/platform/datapath_winuser.c#L3756) 在每次消息附上 `IPPROTO_UDP / UDP_SEND_MSG_SIZE / DWORD SegmentSize` 控制信息，可作为逐消息分段的研究入口。该链接为当日读取的 main 源码，不冒充固定发行版本。[官方 socket 文档](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-udp-socket-options) 规定分段大小以字节计、默认 0；Windows cmsg 的 DWORD 数据和 native header 对齐不能照搬 Linux 的 GSO uint16 布局。

当前产品同一 socket 承担 Gossip、IKE 和不同长度的 ESP。全 socket 设置固定 1264 B 会切开大于它的其他完整协议消息，不能直接采用；优先验证仅作用于本次发送的 cmsg。多个 WSABUF 聚集一个消息，也不等于任意长度 datagram 的 sendmmsg。

## 实际 VM 的只读能力盘点

查询时间 `2026-10-14T06:18:45Z`，Windows guest `10.16.252.11`、OS `10.0.26200.0`、PowerShell `5.1.26100.9711`，远端实际退出码 0。没有修改配置、开启 Wintun 或运行性能负载。

| 项目 | 实际查询结果 |
| --- | --- |
| 物理适配器 | Red Hat VirtIO Ethernet Adapter；Up，宣告 LinkSpeed 10 Gbps |
| 网卡驱动 | 100.100.104.27100，日期 2025-01-13 |
| RSS | Enabled，Maximum Number of RSS Queues 16 |
| USO IPv4 / IPv6 | 两者 Enabled，RegistryValue 1 |
| UDP checksum offload IPv4 / IPv6 | 两者 Rx & Tx Enabled，RegistryValue 3 |
| UDP global | receive / send offload 均 enabled；netsh exit 0 |
| Wintun service / 磁盘文件 | Stopped；wintun.sys FileVersion/ProductVersion 0.14；签名 Valid |

这是宣告及配置，不是实际发送使用硬件 USO 的证据，也没有测量 PVE 宿主队列或链路极限。[Microsoft USO 条件](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/udp-segmentation-offload-uso-) 还涉及最小分段数、最大 offload 大小、路径 MTU 和末段支持。即使功能收到多个正确 datagram，也只能先证明分段行为。

磁盘 wintun.sys SHA256 `1a7bb3555c5419befb1a5f54267dcae9a7af16749ddf4eef9b431fcf0b863110`；此次 service 已停止，没有取得加载内存映像，也不能由版本号证明包含 [2026-02 Ring Head 并发修补](https://git.zx2c4.com/wintun/commit/?id=dd050927f42081dce7c2ae262be55ffd8210c11a)。官方 0.14.1 DLL 的固定 SHA 和此 driver 文件 SHA 属于不同制品，本轮不更新驱动。

[查询源码、原始输出及退出码](../../build/validation/performance-20261014/udp-capability-research/query-capabilities.ps1)、[归一化结果](../../build/validation/performance-20261014/udp-capability-research/capabilities.decoded.json) 和 [解码审计](../../build/validation/performance-20261014/udp-capability-research/capabilities.decode-audit.json) 保存在 ignored 目录。原始 stdout 混有 CP936 网卡名、UTF-8 netsh 字符串及已损坏的本地化标签，初次本地 UTF-8 JSON 解码失败；保留原字节，逐字段归一化，不重跑远端查询。驱动、属性及 enabled 值均为未损坏的 ASCII，该本地解析失败不计作远端失败。

## 功能证伪与进入产品前的要求

实际功能夹具使用一个 AF6 FD、同一个固定 Linux PWU1 peer，验证逐消息 cmsg 的 1/2/4 个 1264 B 完整 frame。每个成员独立 nonce/ordinal/content 验证，回包须恰好为独立完整 datagram；再发无 oob 的普通 1284 B frame，核对全 socket 默认值前后未变。错误必须保留，不能静默 fallback。实际结果见下节，尚无 USO 容量测量。

产品现有 ESP 输出借用单 owner workspace，下一包可覆盖；批发送不能保存多个指向同一 scratch 的旧 completion，也不能提交后立即复用。未来需要有界独占 aggregate buffer，各成员保持独立 ESP 序号、IV、tag，并按相同端点、bind/generation、当前 CHILD 和完整 wireLen 分组。提交前逐包重新核对当前授权、路由、TS、取消及 SA，不能在等待凑组时缓存这些结论；加密后丢弃的 sequence 不回收。

只处理已经 ready 的少量包，不延长等待或扩大队列；不同包长与控制消息分别发送。失败或发送状态不明时不能盲目重发同一 ESP wire。保留 shared writeMu 对重绑/关闭的同步边界及完成后的 buffer 释放。后续若测容量，应分别记录批调用时间、成员数、组装等待、copy、CPU 和损失，不能把一次批调用时间重复填成多个旧 schema 的单包样本。

## 实机分段行为与 API 返回计数，2026-10-14

独立清洁 snapshot 保留原 890 文件/736 Go，仅加 4 个研究 Go，共 740；原无 Wintun 矩阵的 source743 与 executable 未改变。probe source SHA `3539acd3…`、Windows executable `93895b5f…`，同原 Linux peer `2f0f381a…`；构建 actual exit 0。它直接使用标准 Go UDPConn，不声称经过产品 writeTunnel、ESP、授权或实际控制消息。

| 同一个 socket 的调用 | 期望写字节 | Go 返回 n / oobn | 独立回包数 | 内容/checksum |
| --- | ---: | --- | ---: | --- |
| cmsg 1264，1 frame | 1264 | 0 / 24 | 1 | 全部通过 |
| cmsg 1264，2 frames | 2528 | 0 / 24 | 2 | 全部通过 |
| cmsg 1264，4 frames | 5056 | 0 / 24 | 4 | 全部通过 |
| 普通 WriteTo，无 oob，1284 B | 1284 | 1284 / 0 | 1 | 全部通过 |

三次 WriteMsg 都没有返回 send error，但 n 与期望不符；探针没有重发或静默 fallback，继续保存独立 wire 证据。8 个 ordinal 各唯一、完整长度/nonce/方向/full-wire equality 和独立 checksum 通过；Linux received/echoed 8/8，ignored/write errors 0。AF6 `[::]:52718`、handle448 前后相同，socket 全局 UDP_SEND_MSG_SIZE 前后均 **0**，普通较长包未被持续分段。

结果严格分开：**WireComplete=true，ApiCountsValid=false，Completed=false，Go child/PS actual exit 1**。外层采集器 exit 0 表示完整取回失败材料并完成独立清理，不表示严格功能全 PASS。原 child `3324/134364362102451712`、UDP endpoint、自有容器及唯一目录均独立确认不存在，cleanup actual exit 0。

这些数据证明在本 VM 的 AF6 bind／IPv4 peer 路径，逐消息 2/4 分段可输出独立完整 datagram；未证明硬件实际执行、外层 IPv6、真实 ESP/控制混包或吞吐收益。四个 SendCallWallNS 原值全部 **0**，不能解释为零成本，也不能给出微秒调用耗时；后续容量必须用匹配分辨率的 QPC 和独立批调用单位。

[原始分段与计数报告](../../build/validation/performance-20261014/uso-research/execution/native-functional/downloaded/done.json)、[退出/完整采集与清理汇总](../../build/validation/performance-20261014/uso-research/execution/native-functional/summary.json) 和 [源码制品 manifest](../../build/validation/performance-20261014/uso-research/execution/source-artifact-manifest.json) 保存在 ignored 目录。原始 n=0 和 strict exit1 不因随后控制实验而覆盖。

本机 Go 1.26.5 的 WriteMsgInet6 submit 将 WSASendMsg 的 bytesSent 传 nil、局部 qty 初值为 0；execIO 仅在 pending 或要求同步完成通知的分支读取 overlapped result。[Go 1.26.5 官方源码](https://github.com/golang/go/blob/go1.26.5/src/internal/poll/fd_windows.go#L1513) 提供相应路径线索。这是源码推断，尚未抓取本次 provider completion 的内部状态；另以无 cmsg 的普通 WriteMsg 对照区分是否为 USO 特有的计数异常，不改 Go 标准库或生产代码。

### 无 cmsg 的两帧普通 API 对照

保留上述全部原件，在新独立 source/build/输出目录 fork 最小 [显式差异](../../build/validation/performance-20261014/uso-research/execution-bytecount-control/source-fork.patch)：移除 cmsg/unsafe，仅普通 1264 B WriteMsg(nil oob) 与普通 1284 B WriteTo 两次调用。新 source `ad466090…`、Windows executable `c7005dac…`，构建 actual exit 0；其余 PWU1 helpers、原 Linux executable 和原生产字节不变，没有重跑原 1/2/4 实验或容量矩阵。

| 新控制实例内的调用 | 返回 n / oobn | 完整独立回包 |
| --- | --- | --- |
| 普通 WriteMsg，nil oob，1264 B | 0 / 0，无 send error | ordinal1，全部字节/checksum 通过 |
| 普通 WriteTo，无 oob，1284 B | 1284 / 0 | ordinal2，全部字节/checksum 通过 |

新 AF6 `[::]:62341`、handle436 在两次调用间相同，默认分段选项前后 0；它是 fresh FD，不把原 handle448 描述为一直存活。**WireComplete=true、ApiCountsValid=false、Completed=false，Go/PS actual exit 1** 仍保留。Linux received/echoed 2/2、ignored/errors 0，取消/Close/reader 完成；原 `5624/134364369540989587`、UDP endpoint、image、容器及目录独立清理 actual exit 0，采集器 outer0 不改写 probe1。

普通无 cmsg WriteMsg 也重现 n=0，因此 USO 不是这次计数异常的必要触发条件，问题已收窄到本 Go 1.26.5 Windows WriteMsg 路径。尚未运行时捕获具体同步完成分支，也不声称已经修复标准库或可以不经验证进入产品。两个 SendCallWallNS 同样为 0，仍没有调用摊销或吞吐结论。

[两帧原始报告](../../build/validation/performance-20261014/uso-research/execution-bytecount-control/native-functional/downloaded/done.json)、[独立 source/16 raw/8 冻结/实际退出与清理证书](../../build/validation/performance-20261014/uso-research/execution-bytecount-control/final-source-raw-certificate.json) 和 [Root 两实验最终复核](../../build/validation/performance-20261014/uso-research/root-final-evidence-audit.json) 完成；原 8 帧实验的 5 冻结/16 raw 与无 Wintun 矩阵的 20 冻结/743 Go 均未改变。

当日公开资料进一步核到改变计数取得方式的固定 Go 提交、Linux GSO/GRO 的原作者研究，以及 RSS/系统 trace 的适用边界，见 [公开研究与下一项对照](udp-performance-research.md)。源码候选仍待实际 completion 分支验证，严格失败与未测容量状态不变。
