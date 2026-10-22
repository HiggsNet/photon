# Windows 真实 Wintun 的无加密容量对照

2026-10-13，完成六组、24 个正式点及 24 个预热点。1200 B UDP payload、每流窗口64下，单流三轮中位数约1.73–1.83 Gbps，四流约1.98–2.10 Gbps。每个请求和回复都经过实际 Wintun；这是隔离 echo 路径的验证结果，不是完整 Photon 加密隧道的容量，也不能把两者差额全部算作 AES 开销。

## 路径与范围

研究夹具复用生产 `openWintun`、接收循环和 IP Helper 配置形状，保持1 MiB ring与 raw ingress64。客户端与 echo 夹具是同一 Windows VM 上的独立进程，均实际 Go P8、affinity `0xff`，没有外部 echo peer。客户端 OS UDP发送 → Wintun Receive → 原有独占 heap copy及 ring release → raw64 → echo owner → Wintun Write → 客户端 OS UDP接收；每次完整 echo 包含两次 Wintun 穿越。

| 模式 | raw64 后的交接 |
| --- | --- |
| `raw-only` | echo owner直接调用实际 `wintunDevice.Read`；仍有原后台接收循环和 raw64，没有直接借用 ring |
| `relay64` | 独立 reader调用同一 Read，再经容量64的 `leafDevicePacket` 非阻塞队列交给 echo owner；只模拟现有第二次交接 |

两模式均使用 bare Wintun device，没有 `configuredPacketDevice` 的读前/读后门禁、真实 leaf attachment、Daemon主 select/owner、Gossip/IKE/ESP外层共享 UDP、AES、动态授权、SA/replay或物理链路。测试没有改动生产代码、公开接口或队列容量。它也不构成新的 Windows 多网关模式。

Read返回的包已独占且脱离 ring。echo原地交换完整 IP地址和 UDP端口，保持每字节 payload、nonce和 sequence；地址与端口交换不改变 one's-complement和，回复不增加 clone或逐包重算 checksum。完整 checksum和现有安全重算 oracle的逐字节对照、实际双栈 OS UDP验证均是前置检查，不假定 checksum offload。

## 冻结来源与前置验证

研究源为 clean archive `e009e9810274947bcf22ee13347f343418dca8a9`，724 个原生产 Go文件逐字不变，只加入两个 ignored研究 test文件。`internal/photonwindows` 与 [CPU A/B冻结来源](cpu-control-testing.md) `5a009981` 无差异；不是把当前 checkout未经冻结编译后与旧产品比较。Go1.26.5、Windows amd64、CGO_ENABLED=0、`photon_profile` 测试 executable在正式测量前已冻结，此轮没有重编译。

| 制品 | SHA256 |
| --- | --- |
| 研究 executable | `9cfe0ff182a28ecbeabff175898573fdfe2c7e005c201524a5322aa6546762e8` |
| 生成器，clean `5a009981` | `b7cc610eafbcbf6a61e19a8c13430064d6b92a4a1bdf109240e1b15d9fb80b1a` |
| 固定官方 `wintun.dll` | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |
| 已验证 echo runner | `8b02e4d59068b108390f1d13ef2ed828ac72171432ecb244dfaaec53a8fa47c9` |

便携 checksum/ownership检查通过；实际 Windows 的 `TestWintunControlReplyIntegrity`、`TestWintunControlNativeChecksum`、原有 `TestWintunNativeLifecycle` 全部通过，包括双栈实际 checksum、完整 payload回包、调用方 Read超时、parent取消、重复 Close和关闭后拒绝。随后两种模式各用双栈单流/window4/一秒低压 probe验证完整 ledger、实际 P/mask、退出和清理；这些功能 probe不进入容量统计。[原生功能证据](../../build/validation/performance-20261013/wintun-control/native-functional.log) 与 [生产源相等证明](../../build/validation/performance-20261013/wintun-control/product-go-equality.json) 保留在本地 ignored目录。

## 正式方法与单位

三轮模式顺序为 `raw-only→relay64`、`relay64→raw-only`、`raw-only→relay64`。每组新建独立进程/adapter，组内依次测 IPv4单流、IPv4四流、IPv6单流、IPv6四流；每点2秒预热、8秒发送、1秒 echo期限、每流窗口64、1200 B payload、8M包上限。生成器保持实际 Go P8/`0xff`，250 ms采样目标 echo进程的 CPU和线程；fixture角色不是 SCM服务，JSON的 `ServiceCPUCorePercent` 在此表示 echo研究进程。

Mbps为完整 nonce/sequence/content校验后的唯一 echo UDP payload字节数，按实际总时长计算，单位是每方向 payload goodput，不含 IP/UDP头，不把往返两次相加。总时长包含 pending-credit排空；四流每流各有64个待回复额度，不是总共64。生成器 CPU与 echo进程 CPU分别记录，部分 OS线程观察不等于完整 CPU拆分，也不命名某 TID为 Go owner。

两模式每组均有新的 OS UDP sockets、nonce、process creation identity和 adapter；即使 LUID被重用，也不是同一实例或五元组。这里没有做统计显著性检验，不以短测中位数宣称驱动极限。

## 全部三轮正式点

Expired是期限到期的请求，LateEchoed是到期后仍完整验证的回复。全部24正式点 LateEchoed=0，损失、实际排空时长和两进程 CPU均保留。

| 轮 | 模式 | IP | 流 | Mbps | 总秒数 | Expired | EchoLoss% | echo CPU%core | 生成器 CPU%core |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | raw-only | IPv4 | 1 | 1772.204 | 8.0109082 | 0 | 0.00000 | 105.715 | 172.226 |
| 1 | raw-only | IPv4 | 4 | 1976.160 | 8.7743924 | 1291 | 0.07142 | 102.393 | 335.315 |
| 1 | raw-only | IPv6 | 1 | 1749.503 | 8.0093967 | 0 | 0.00000 | 112.758 | 170.893 |
| 1 | raw-only | IPv6 | 4 | 1979.420 | 8.5430860 | 885 | 0.05022 | 101.325 | 344.577 |
| 1 | relay64 | IPv4 | 1 | 1727.242 | 8.0079621 | 0 | 0.00000 | 116.681 | 172.680 |
| 1 | relay64 | IPv4 | 4 | 2048.179 | 8.4187094 | 585 | 0.03256 | 115.071 | 351.152 |
| 1 | relay64 | IPv6 | 1 | 1698.278 | 8.0076797 | 0 | 0.00000 | 111.416 | 173.857 |
| 1 | relay64 | IPv6 | 4 | 1927.370 | 8.9137003 | 642 | 0.03586 | 105.350 | 330.776 |
| 2 | relay64 | IPv4 | 1 | 1778.212 | 8.0084951 | 0 | 0.00000 | 119.014 | 173.839 |
| 2 | relay64 | IPv4 | 4 | 1974.832 | 8.9744577 | 526 | 0.02848 | 105.682 | 328.362 |
| 2 | relay64 | IPv6 | 1 | 1777.343 | 8.0075120 | 0 | 0.00000 | 114.151 | 170.153 |
| 2 | relay64 | IPv6 | 4 | 2104.932 | 8.3545404 | 775 | 0.04229 | 119.695 | 346.743 |
| 2 | raw-only | IPv4 | 1 | 1813.944 | 8.0075486 | 0 | 0.00000 | 112.394 | 167.420 |
| 2 | raw-only | IPv4 | 4 | 2001.488 | 8.8389510 | 1028 | 0.05575 | 91.923 | 330.391 |
| 2 | raw-only | IPv6 | 1 | 1829.417 | 8.0073825 | 0 | 0.00000 | 106.933 | 177.766 |
| 2 | raw-only | IPv6 | 4 | 1984.031 | 8.8868443 | 719 | 0.03913 | 99.867 | 336.347 |
| 3 | raw-only | IPv4 | 1 | 1813.556 | 8.0087593 | 0 | 0.00000 | 109.060 | 169.346 |
| 3 | raw-only | IPv4 | 4 | 2058.316 | 8.7741160 | 596 | 0.03167 | 106.848 | 333.367 |
| 3 | raw-only | IPv6 | 1 | 1835.029 | 8.0077850 | 0 | 0.00000 | 109.464 | 171.708 |
| 3 | raw-only | IPv6 | 4 | 2209.121 | 8.0074393 | 611 | 0.03315 | 107.712 | 373.091 |
| 3 | relay64 | IPv4 | 1 | 1788.261 | 8.0075286 | 0 | 0.00000 | 114.346 | 173.860 |
| 3 | relay64 | IPv4 | 4 | 2004.865 | 8.7813735 | 941 | 0.05129 | 101.600 | 332.380 |
| 3 | relay64 | IPv6 | 1 | 1728.832 | 8.0073228 | 0 | 0.00000 | 113.958 | 168.010 |
| 3 | relay64 | IPv6 | 4 | 2180.781 | 8.0785735 | 659 | 0.03590 | 120.109 | 369.612 |

## 中位数与范围

| 模式 | IP | 流 | Mbps中位数（范围） | EchoLoss%范围 | echo CPU%core中位数 | 生成器 CPU%core中位数 |
| --- | --- | ---: | --- | --- | ---: | ---: |
| raw-only | IPv4 | 1 | 1813.556 (1772.204–1813.944) | 0.00000–0.00000 | 109.060 | 169.346 |
| raw-only | IPv4 | 4 | 2001.488 (1976.160–2058.316) | 0.03167–0.07142 | 102.393 | 333.367 |
| raw-only | IPv6 | 1 | 1829.417 (1749.503–1835.029) | 0.00000–0.00000 | 109.464 | 171.708 |
| raw-only | IPv6 | 4 | 1984.031 (1979.420–2209.121) | 0.03315–0.05022 | 101.325 | 344.577 |
| relay64 | IPv4 | 1 | 1778.212 (1727.242–1788.261) | 0.00000–0.00000 | 116.681 | 173.839 |
| relay64 | IPv4 | 4 | 2004.865 (1974.832–2048.179) | 0.02848–0.05129 | 105.682 | 332.380 |
| relay64 | IPv6 | 1 | 1728.832 (1698.278–1777.343) | 0.00000–0.00000 | 113.958 | 170.153 |
| relay64 | IPv6 | 4 | 2104.932 (1927.370–2180.781) | 0.03586–0.04229 | 119.695 | 346.743 |

全部单流正式点无损失。第二次交接的单流中位数低约1.95%/5.50%，其 echo进程 CPU中位数略高；四流中位数则 IPv4近似持平、IPv6较高，范围重叠。这个短研究不证明第二次交接是完整产品当前约450 Mbps的瓶颈，也不证明交接没有成本；不能据此承诺删除队列即可达到1 Gbps。明确成立的是：本负载与隔离范围内，真实 Wintun、原有1 MiB ring/raw64及额外 relay64都能超过1 Gbps。

## 完整性与清理证据

正式运行前，实际 Windows PowerShell parser通过两个固定脚本。六组真实子进程 ExitCode均为0，fixture在结束时 cancel、Close并join readers，exact LUID的自有地址/路由均不存在；原PID为4912、1388、6212、5860、3084、3548。每组 LUID均为14918723521478656，但前一代关闭及资源不存在已在下一组创建前确认，完整100 ns OS创建时间/token与adapter名分别记录，未把复用LUID当作永久身份。

`capacity.exit=0`，完整24正式/24预热 ledger均通过。总计与每流 Sent/OnTime/Expired/LateEchoed/unique echo/RTT相符，每字节 nonce/sequence/content校验保留；两阶段的 corrupt、foreign、duplicate、unsent、send errors及budget exhaustion均为0。实际 P/mask、线程枚举、同进程创建身份、线程缺口和真实进程 CPU时长核对通过；正式点无 partial thread query error。预热原值不进入正式中位数。

server的 raw/relay drop累计包含整组的预热、测量与其他控制帧，不是逐sequence去重账本，不能与 client loss简单相加。六组 `(RawDrops,RelayDrops)` 按运行顺序为 `(2793,0)`、`(1296,496)`、`(1365,338)`、`(2236,0)`、`(1700,0)`、`(1630,436)`，全部保留；回复失败计数均为0。

[完整验证及全部24正式点](../../build/validation/performance-20261013/wintun-control/capacity-validation.json)、[冻结制品和脚本SHA](../../build/validation/performance-20261013/wintun-control/capacity-frozen.sha256)、[48份原始JSON及六组ready/done/coordinator](../../build/validation/performance-20261013/wintun-control/capacity-downloaded/photon-wintun-capacity-20261013-064820-114901/matrix/) 保存在本地 ignored证据目录。单独的 [独立清理记录](../../build/validation/performance-20261013/wintun-control/capacity-independent-cleanup.log) 确认六个原PID、adapter名、disposable地址/路由和唯一远端目录全部不存在；VM与host容量窗口已明确交回主测量协调者。研究没有重测替换低点、修改生产授权门禁、发布或部署产品。

下一步独立测真实 ESP/AEAD处理与共享 UDP路径；它需要自己的完整性、sequence/replay及 CPU证据，不能用本对照减去产品吞吐推算 AES成本。完整 Photon稳定1 Gbps、长期soak及多核数据面优化门槛仍未关闭。
