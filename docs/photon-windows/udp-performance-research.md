# Windows UDP 性能的公开研究与下一项对照

2026-10-14，按用户要求检索原作者研究、操作系统/API 文档和固定版本源码。两个 subagent 分别核对 Linux 分流/批处理及 Go Windows WriteMsg，Root 核对 Wintun、Tailscale、QUIC 论文和 Microsoft 诊断资料。本节只总结证据与待执行实验，没有新增产品优化、编译器升级或宿主配置修改。

本地最新 [同 Linux peer、无 Wintun 对照](shared-peer-udp-testing.md) 的单流/四流中位为 **722/659Mbps**，四流同边界 UDP write 为 **7.34–8.04µs**；相同 Linux peer 的整组 CPU 为 **0.78–0.90 核当量**，其中 kernel 约 **88%**。它没有 AES，也没有达到 1Gbps。Windows 发送、共享 owner/队列及 Linux 串行回包都有调查价值，尚不能指定某一端为唯一瓶颈；整组 CPU 不能代替逐正式点或宿主 CPU。

## 批 syscall 与减少协议栈逐包处理应分别验证

Tailscale 原作者的 [Surpassing 10Gb/s（2023）](https://tailscale.com/blog/more-throughput) 展示 Go 实现的加密 WireGuard 在 Linux 上通过 UDP GSO/GRO 和 checksum 优化超过 10Gbps。作者明确区分：sendmmsg/recvmmsg 摊薄 syscall，而普通 mmsg 的内核实现仍逐包经过协议栈；GSO/GRO 进一步摊薄协议栈处理。其实验是 Ubuntu 22.04、两台 i5-12400＋25G Mellanox，以及另组 AWS c6i.8xlarge，负载为 10s 单流 TCP，不是本站 1264B UDP echo。

后续 [Increasing QUIC and UDP throughput（2023）](https://tailscale.com/blog/quic-udp-throughput) 延伸到 Linux TUN 的 UDP GSO/GRO；QUIC 加密关闭，但 WireGuard 隧道仍加密。这给出可参考的方法，不证明 Wintun 支持 Linux TUN 的 offload 元数据，或本站升级到同样吞吐。批处理与 zero-copy 也是不同改动：暂时保留有界 copy 可能更容易验证减少调用的收益。

[Wintun API 源码](https://git.zx2c4.com/wintun/tree/api/session.c) 中 AllocateSendPacket/SendPacket 使用共享 ring、锁及有条件的 SetEvent，不能直接说“每调用这两个函数一次就必有一次系统调用”。这是当日 upstream 源码参考，不是本 VM 已加载 driver 的证明。本站此前组合路径的 Wintun write 约 0.62–0.77µs，而 UDP write 约 10µs；源码与本地计时都不支持先把这 10µs 全归给 Wintun。

Windows 的对应候选是逐消息 USO，而非将整个 Gossip/IKE/ESP 共享 socket 设置固定分段大小。[固定 MsQuic 提交的发送实现](https://github.com/microsoft/msquic/blob/900ef64e86227e88936f578b9a3bb6ca6acb65a6/src/platform/datapath_winuser.c#L4019-L4054) 使用 IPPROTO_UDP/UDP_SEND_MSG_SIZE/DWORD 的 cmsg；[Microsoft USO 条件](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/udp-segmentation-offload-uso-) 还涉及最小分段数、MTU、最大 offload 大小等。本站 [1/2/4 分段功能实验](udp-segmentation-testing.md) 的独立回包正确，但 Go 返回 n=0，严格功能结果仍失败；尚无批发送容量数据或硬件实际执行证明。

## 四个内层流为什么没有形成四核数据面

[Linux RSS/RPS 官方文档](https://docs.kernel.org/networking/scaling.html) 描述按网络/传输头 flow hash 分配队列/CPU。当前四个 inner flow 仍封装在一个外层 UDP tuple，不能据此期待变成四个 RSS flow。应用侧也仍是一个 Windows owner、同 FD 同方向串行发送，以及一个 Linux peer goroutine 顺序读/修改/回写。这个外层分流解释属于由源码与拓扑推断，尚未测到本站物理 IRQ/virtqueue 的实际分布。

一个 socket 不等于整个程序只能用一核；Go 的读、写是不同方向，取得数据后的处理也可以并行。增大 GOMAXPROCS 或宣告 16 RSS queues 同样不等于已有多个数据面 worker。[QEMU virtio RSS 文档](https://www.qemu.org/docs/master/devel/ebpf_rss.html) 说明 vhost/eBPF/guest 协商也影响实际队列路径；这里的 live 文档不代表本站 PVE 版本或配置。未来按多个真实 remote peer 分配 owner 值得研究，但仍需核对外层 tuple、SA/replay 顺序与共享 Wintun/FD 边界。

Windows KVM 在 PVE `.200`，road LXC 在另一节点 `.202`；不能把两个 guest 当同宿主 CPU 竞争。后续只读观测应覆盖祖先 cgroup 的 [cpu.max/cpu.stat/effective cpuset](https://docs.kernel.org/admin-guide/cgroup-v2.html#cpu) 及宿主网络计数；guest 的 NumCPU/GOMAXPROCS 不证明可持续 CPU 配额。

## 加密与 copy 的研究不能替代本站分段计时

[A Quantum of QUIC（Kempf 等，2024）](https://arxiv.org/html/2405.09264v1) 用 Linux 裸机 EPYC 7543、10G NIC、8GiB HTTP 下载和每项 25 次测量，对比三个 QUIC 实现。移除 packet protection 的 NOOP cipher 使吞吐提高约 10–20%；MsQuic 的 NOENC 比 NOOP 又提高 13.6%，作者指出 NOOP 仍调用 OpenSSL 并执行 memcpy 等工作。

可借用的是分开测“算法本体”“加密函数及 copy”“包 I/O”的方法。这些比例不能移植到 Windows ESP，也不证明 Go bytes.Clone 占同样成本。本站无 AES 路径仍低于目标；最新三个四流 CPU profile 的可见 WSA 发送栈约占样本 39–40%，checksum flat 约 2–3%。它们支持优先调查 I/O，但 pprof 采样和 QPC elapsed 都不能直接给出内核/DPC/等待的分账。

## Go Windows WriteMsg 的具体源码线索

subagent 核对的 [CL 685436，固定提交 9b6bd64e](https://github.com/golang/go/commit/9b6bd64e46bd882fb8849d4476fc91a22b67cc96) 将 WSASendMsg 的 bytesSent 参数从旧 qty 地址改为 nil。本机 Go1.26.5 文件与 [官方 tag 源码](https://github.com/golang/go/blob/go1.26.5/src/internal/poll/fd_windows.go#L1513) 逐字相同；若发送立即成功且 skipSyncNotif=true，execIO 可直接返回初值 0。本站普通 nil-oob WriteMsg 也返回 n=0，而独立回包完整，因此 USO 不是必要触发条件。

这是匹配现象的静态候选：没有捕获本次 provider 返回、通知模式和实际 completion 分支，也没有旧版原生对照证明回归。读取 Go1.26.9/1.27.2 源码仍见 nil 参数，不能据此宣称升级即可修复。公开官方 issue 检索未找到完全匹配项，不等于不存在；已修的 [#77875](https://github.com/golang/go/issues/77875) 是非 nil 空 OOB 的 WSAEFAULT，条件不同。

[Microsoft WSASendMsg 合同](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasendmsg) 本身建议 overlapped 调用传 NULL；要核的是省去同步成功通知时怎样取得实际计数。下一项应隔离捕获真实 completion 分支和返回数量，保留 pending/取消/Close/buffer 生命周期；不能直接把 n=0 改成输入长度，也不能将严格失败探针记为已通过。

## 下一项实验的顺序与判据

| 方向 | 最小变量与判据 | 仍未完成的边界 |
| --- | --- | --- |
| Windows WriteMsg → USO | 先验证实际完成计数；再用匹配 QPC 的独立批调用单位对照 1/2/4 ready 成员，记录组装/copy/等待/CPU、唯一完整回包与损失。 | 不等待凑满、不放大队列；每个 ESP 成员独立序号/tag/current gate，独占 buffer 完成前不复用。尚无产品批发送或容量结论。 |
| Linux RX syscall | 只 fork 研究 peer 的收包为有界最多 8 个已 ready datagram 的 ReadBatch；立即逐包沿用原 reply/deadline/WriteTo。Windows 及原采样口径不变，先低压完整 oracle，再 3 组单流配对 A/B。 | 记录实际 batch size/syscalls 和同正式点 Linux U/K；新 peer source/binary 单列，不能冒称原冻结 peer。先不同时改 TX、GSO/GRO 或 RSS。 |
| 实际核/等待分账 | 按 [MsQuic 官方诊断方法](https://github.com/microsoft/msquic/blob/main/docs/TroubleshootingGuide.md) 用 ETW/WPR 核对发送栈、调度/等待、CPU 分布和实际 URO coalescing 事件。 | 配置 enabled 不等于工作；当前 ReadFrom 假设一个 frame，接收合并需要先正确拆帧。未采新的系统 trace，也未修改网卡/安全软件。 |

Linux 的 [Go 官方 ReadBatch 文档](https://pkg.go.dev/golang.org/x/net/ipv4#PacketConn.ReadBatch) 明确 Linux 可批处理、其他平台当前只处理一个 message；不能将它当成 Windows 的等效 batching API。本站尚未引入依赖或执行上述新对照。

两个 subagent 的 [Go 原始资料核对](../../build/validation/performance-20261014/online-research/go-windows-write-msg.md) 和 [Linux 原始资料核对](../../build/validation/performance-20261014/online-research/linux-udp-scaling.md) 在 ignored 本地目录；公开 primary 链接与本地现有实验分别列出。本项关闭的是资料调查，1Gbps、批发送产品验收及长期性能门槛继续开放。
