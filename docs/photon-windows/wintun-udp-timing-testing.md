# Wintun 与跨主机 UDP 的无加密组合对照

本轮研究补齐 `Windows 应用 → Wintun → 外层 UDP → Linux 回包 → 外层 UDP → Wintun → 应用`，以相同的业务载荷、外层包长和 UDP 写计时边界，与 [完整产品分段计时](packet-timing-testing.md) 对照。它不是新的 Photon 模式，不修改生产代码或公开接口，也不构成完整产品的 1 Gbps 验收。

## 路径与匹配条件

从清洁 `5bf076cc` 归档构建研究程序，仅增加独列的研究文件。Windows 复用真实 `openWintun`、1 MiB ring、raw64 和实际共享 `packetSockets`；独立设备 reader 经 leaf64 交给唯一 owner，同一 owner 串行消费 leaf64 和实际 esp64，再同步写 UDP 或 Wintun。保留生产 UDP reader 的端点分流、独占 UDP datagram 副本及有界队列；不借用尚未归还的 Wintun ring，也不异步发送 owner 的临时缓冲区。

主矩阵使用内层 IPv4、1200 B UDP 业务载荷，即 1228 B 完整 IP 包；36 B 研究封装使外层 UDP payload 为 **1264 B**，与本次产品 ESP 对照相同。封装包含固定格式、长度、实例 nonce、序号和方向；首四字节非零，经过原有 NAT-T 分流进入 esp64，但它没有 ESP 密文、认证标签、SA 或重放保护，不能称作合法 ESP。

Linux 单 socket peer 校验研究格式，交换内层 IP 地址及 UDP 端口后回包，保持业务 payload 逐字不变。地址/端口交换的 checksum 必须通过独立重算及实际 Windows UDP 接收验证；不会把原始出站 IP 请求直接反射回 Wintun。Windows 只接受当前固定 peer、实例、回包方向及业务包格式，然后写真实 Wintun。

夹具沿用 `ipHelperTestIntent` 配置 MTU 1400；正式 IPv4 内层包 1228 B、低压 IPv6 包 1248 B 均小于该值。它匹配业务及外层包长，没有声称全部接口参数与完整产品一致。

Linux 位于 road 的 Docker 测试容器，Windows 位于既有 Windows 11 VM。按用户提供的拓扑，road 和 Windows 分别位于 PVE `10.16.255.202` 与 `10.16.255.200`；本轮不修改或测量宿主配置。研究 peer 在用户态修改并回包，省略完整 Linux Photon、StrongSwan/XFRM 和业务 echo 内核路径，因此与产品的差额不能只归给 Windows 或 AES。

## 分段计时口径

直接复用 schema 2、QPC、固定 1/256 admission-attempt 采样、窗口 epoch 和原 `writeTunnel` 四个 UDP 标记。直方图与结果保存精确 Sum/Count，失败只记录实际执行过的阶段，队列拒收和未完成另列。所有值都是经过时间，包括探针、调度及等待；不机械扣除探针常数，不把 owner 段当 CPU 时间。

| 原报告字段 | 本研究实际含义 |
| --- | --- |
| `queue_wait` | device.Read 返回后的 leaf64 入队尝试处到 owner 消费；反向为生产 UDP detach/admission attempt 到 esp64 消费。不代表 Read 返回瞬间，均不含 raw64 及之前的等待 |
| `precheck` | owner 开始至研究包格式、方向和端点的前置检查完成 |
| `aes` | 研究封装或拆封，没有 AES；保留字段只为复用原标记与读取器 |
| `fresh_gate` | 夹具当前取消、generation 和 peer 检查，没有签名授权、路由、CHILD/SA 或 replay 检查 |
| 出站 `delivery` | 实际同步 `writeTunnel` 调用，包括返回尾部 |
| 入站 `delivery` | 实际同步 Wintun Write 调用，返回不等于应用已消费 |
| `owner_total` | Dequeue 至 Finish 时间戳，包含上述处理段，不含 queue_wait 或时间戳之后的直方图合并 |

出站 UDP 子段的边界与产品完全复用：取得写锁、状态验证、一秒写期限设置、`WriteToUDPAddrPort` 返回。`udp_write` 包含 Go FD 锁、I/O 准备、系统调用以及可能的完成等待。四个子段嵌套在父 delivery 内，不能相加到父段上；只对同为四流、1264 B、实际共享 socket 的产品 **8.5–9.3µs** 记录作同边界比较。raw64、Linux、物理网络及 PVE 的独立时间仍未被这些 QPC 段覆盖。

## 正式方法

三轮顺序为 off→on、on→off、off→on，共六个 fresh Windows fixture，每个依次测单流和四流、每流窗口 64。固定实际 Go P8、affinity `0xff`，1200 B payload、2 秒独立预热、8 秒正式发送、1 秒请求 deadline，单次包预算 8M。单流和四流均各自独立开启/冻结计时窗口，预热不计入正式统计；f4 的两模式使用相同 CPU profile 条件，线程观测为 250ms。

共 12 个正式点、12 个预热点，全部低点、超期和实际排空时长保留。速率是完整 nonce/sequence/content 验证后的唯一回包有效载荷，按包含排空的总时间计算，不把往返两个方向相加。off/on 使用同一个 tagged executable；这只量采样开关的增量，不等于普通构建与诊断构建完全相同。

准备阶段先验证研究封装、checksum、buffer 所有权、取消和关闭，再运行实际跨主机低压回包及新夹具钩子的必要校准。源码、制品和运行参数在容量测量前冻结；正式运行期间不进行其他重型编译或基准。每次结束独立确认原 PID/创建身份、网卡与 LUID、自有地址路由、UDP/TCP endpoint、容器和唯一目录已回收。

## 夹具验证与原生校准，2026-10-14

便携封装普通/race、Windows 编译及 Linux peer 编译均 actual exit 0；双栈四个业务端口的独立 checksum oracle、畸形格式拒绝、借用 slice、workspace 及有效路径零分配通过。Linux peer 请求与旧 echo 相同的 4 MiB 读写缓冲区，另外记录系统实际 clamp，不修改 sysctl。最终研究源码经过独立审阅，Windows 使用当前 socket 状态的代次/peer 检查，marker 独占创建，异常结束仍关闭 profile 并 join readers。

清洁归档的 736 个原 Go 文件逐字不变，4 个研究 Go 文件与 1 个只读 runtime helper 独列，共 741 个；初版只完成构建、0 native 的准备制品另存，新增首次实际驱动包 checksum 证据后统一重新构建。该证据只检查每个实例、每个方向/地址族的首个有效包，正常位于预热中，不在正式热路径逐包扫描。

首次 `native-probe/` 在 SSH 创建阶段连接超时，actual exit 255：**0 上传、0 native、0 校准、0 正式点**，不是功能失败或性能低点，也不能因未连通而声称远端资源核验成功。Root 随后只读确认 Windows/road 可达；新 `native-probe-attempt-2/` 固定先前验证过的 SSH 配置，使用同一冻结 executable，没有覆盖旧目录或重编译。首轮本来也使用了获准的网络执行环境，因此不将超时归因为 sandbox，原因未确定。

第二次原生 6 个顶层功能检查全部 RUN/PASS、无 skip（含 1 个只读 runtime helper），另外 6 个新夹具 framing/copy＋钩子校准通过；共 7 个 fresh child 的真实退出码均为 0，实际 Go P8、8 logical CPU、process/system affinity `0xff`、QPF 10MHz 与 100ns 创建身份逐一核验。独立清理 actual exit 0，7 个原 PID/创建身份和唯一目录均不存在。

| 新夹具隔离循环 | R1 / R2 / R3，ns/op | 中位，ns/op |
| --- | ---: | ---: |
| off | 67.91 / 63.30 / 65.31 | 65.31 |
| on，实际 1/256 | 74.74 / 73.75 / 72.03 | 73.75 |

六点均 **0 B/op、0 allocs/op**。这是研究封装/copy 和计时钩子的隔离循环，没有实际 UDP/Wintun I/O，不是单包业务耗时，也不从正式阶段机械扣除这些数值。已有采样原语、旧 Wintun 功能或产品大套回归不重复运行。

[原生与校准完整汇总](../../build/validation/performance-20261014/wintun-udp-control/native-probe-attempt-2/complete-validation-summary.json)、冻结 manifest、全部失败/成功 stdout/runtime 与独立清理材料保存在本地 ignored 研究目录。组合路径的实际低压回包和容量结果见下节，原生钩子校准不能替代整条路径的测量。

## 组合路径结果

### 低压完整性与保留的准备失败

`functional-measurement/` 完成实际双栈 single-flow/window4，两个地址族各 1 秒预热及 1 秒正式低压回包，四段唯一 echo 为 19782/20289/19929/19592，合计 **79592**。超期、迟到、损坏、外来、重复、未发送序号和发送错误均 0；Linux received/echoed 均 79592、ignored/write errors 均 0。首次实际驱动包的出/入站×IPv4/IPv6 checksum 证据均 true，Windows/peer/独立资源清理 actual exit 0。它验证真实 Wintun 与网络路径，不进入容量统计。

正式启动包装的独立审阅另修正了 partial-start 清理：先成功确认唯一容器名不存在，再于 Docker run 之前登记该自有名称，覆盖创建成功但启动失败。原低压和初冻结材料保持原样，执行包装的变更单独冻结，不改 Go、PS 测量逻辑、制品或负载。

首个 `capacity-execution/` 正式矩阵在 r1-off 预热之后终止：**1 个已完成预热点、0 正式点**，warm Echoed 133896、Expired 16；Windows child actual exit 1、matrix 1。owner 报 generic invalid phase marker，回取最终 `.start` 内容为正确 `off\n`，原始读取错误没有记录，无法区分读到暂时空内容与 FileShare.None 的共享拒绝。旧 marker 先公开最终文件名、再写入关闭，确实存在这个发布窗口；没有将该准备失败当作吞吐低点或删去预热失包。

其原 PID/100ns 创建身份、网卡/LUID、自有地址路由、UDP/TCP pair、容器、远端目录及 host coordinator 均独立确认不存在。新 `capacity-attempt-2/` 仅将私有 PS marker 改为同目录唯一临时文件独占创建、写完关闭，再 Move 到最终名，保留拒绝覆盖语义。实际 PS 5.1 parser 与从最终源码 AST 抽取的 64 次并发 producer/consumer、拒绝覆盖和自有临时文件回收检查 actual exit 0；Go/executable/采样器/负载不变，不重复 native 或校准。新目录从头运行完整六实例，不择点补跑。

### 六实例、十二正式点

三轮 off→on、on→off、off→on，12 正式及 12 预热均完成。每实例真实 P8/8CPU/`0xff`、AF6 `[::]` 共用 UDP/TCP pair、固定 IPv4 peer、1 MiB Wintun/raw64/leaf64/esp64、1264 B 外层 payload。六个 Windows child/runner、Linux peer、严格读取器与独立清理均 actual exit 0；host 原 PID/启动 tick `3357223/195726553` 已确认不存在，matrix actual exit 0，性能窗口已释放。

| 实际顺序 | 单流 Mbps | 四流 Mbps | 夹具 CPU，单流/四流 %core | Expired，单流/四流 | 总秒数，单流/四流 |
| --- | ---: | ---: | --- | --- | --- |
| R1 off | 683.315 | 567.440 | 148.681 / 138.858 | 0 / 1406 | 8.007903 / 8.821940 |
| R1 on | 661.997 | 634.067 | 148.871 / 150.073 | 0 / 1442 | 8.008178 / 8.724920 |
| R2 on | 548.251 | 530.884 | 129.737 / 133.187 | 0 / 1360 | 8.008969 / 8.740089 |
| R2 off | 626.323 | 588.219 | 131.711 / 135.849 | 7 / 1449 | 8.007599 / 9.005896 |
| R3 off | 679.002 | 594.438 | 133.416 / 138.651 | 0 / 1403 | 8.010686 / 8.981644 |
| R3 on | 608.253 | 546.907 | 142.441 / 130.970 | 11 / 1430 | 8.007709 / 8.947656 |

单流 off/on 中位 **679.002/608.253Mbps**，四流 **588.219/546.907Mbps**；每条件仅三重复、范围重叠且实例间波动明显，不能把差额判定为固定探针开销或单项因果收益。四流失包率 **0.249606–0.280591%**，每次 1360–1449 个 Expired 全部保留；LateEchoed、send errors 及所有完整性异常均 0。少数单流失包也保留，没有将发送及排空的分母强行截成 8 秒。

每流 64 credits 不等于每流拥有独立数据面线程或外层 socket：本轮四流仍进入同一 Windows owner 和同一 Linux 单 socket 回包循环。失包请求等待一秒 deadline 才归还额度，也会降低 closed-loop 发送率；这些点没有证明开放式发包容量或稳定 1Gbps。

### 同口径计时

六份 on 报告均 QPC 10MHz、1/256、clock/invalid errors 0、unfinished 0，四个出站 UDP 子段与父 delivery 的 Count 相同，子 Sum 不超父 Sum；off 的直方图全部为空。下面使用每段自己的 Sum/Count，单位 **µs**；`N 出/入` 为两方向 business owner 的样本数，不推算精确失包。完整前置、封装/fresh 及四个 UDP 子段另保留在原始与派生 JSON 中。

| 轮/流 | N 出/入 | 出站队列 | 入站队列 | UDP write | 父 UDP delivery | 入站 Wintun delivery | owner 出/入 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| R1 f1 | 2158 / 2158 | 110.597 | 97.330 | 9.823494 | 10.838044 | 0.686932 | 12.137396 / 1.688091 |
| R1 f4 | 2255 / 2248 | 206.094 | 179.927 | 10.390599 | 11.419379 | 0.709698 | 12.902528 / 1.979226 |
| R2 f1 | 1787 / 1787 | 84.469 | 72.090 | 9.674818 | 10.551203 | 0.683268 | 11.742306 / 1.583380 |
| R2 f4 | 1893 / 1889 | 113.155 | 104.758 | 9.941363 | 10.924934 | 0.617628 | 12.174538 / 1.619111 |
| R3 f1 | 1982 / 1982 | 93.855 | 77.536 | 9.470585 | 10.418971 | 0.667962 | 11.650959 / 1.674420 |
| R3 f4 | 1995 / 1991 | 152.583 | 144.439 | 10.211579 | 11.145113 | 0.766549 | 12.478195 / 1.880663 |

四流出站写锁/状态/期限三个前置子段各约 0.17–0.40µs，实际 write 占同 Count 父 delivery 的 elapsed Sum **90.991%/90.997%/91.624%**。封装（`aes` 别名）均值约 0.339–0.387µs，研究 fresh 检查约 0.385–0.429µs；均非真实 AES 或签名授权。这次同边界、同 1264 B 写调用为 **9.94–10.39µs**，与产品 **8.5–9.3µs** 在同一量级，去掉 AES 后没有消失。二者来自不同实例、五元组和两端处理路径，不把约 1µs 的差额归因于某个锁、驱动或加密行为。

四流 UDP write 的 p50 桶依次 `[8193,16384]ns`、`[4097,8192]ns`、`[4097,8192]ns`，p99 均 `[32769,65536]ns`；两方向 queue p99 均 `[524289,1048576]ns`。这些是整数最近秩的所在桶区间，不是精确分位值。队列等待远大于 owner 处理段，但不计 CPU；同步发送期间 owner 无法同时消费入站，也不能仅凭这些均值指定某个丢包位置。

### Linux 与归因边界

Linux peer 实际 Go P8、12 logical CPU，两个 socket buffer 请求 4 MiB，系统报告各 8 MiB。其整组 ready→close 的进程 CPU 为 **81.51–90.90%core**，包含单流/四流、预热、正式、间隙及收尾；进程自身的 kernel CPU 占其累计 CPU **88.19–89.71%**。这是组级进程计数，不是某个正式点、宿主或逐函数的 CPU 分账。它使用一个串行收包/回包循环，因此 Linux peer 自身或其内核路径仍可能限制本组合对照；未测两台 PVE 的 CPU、软中断和 NIC 队列，不能排除外部路径，也不能把全部上限归给 Windows。

明确成立的是：无 AES/授权的组合路径仍未达到 1Gbps，实际同步 UDP write 仍是最大的已测出站 owner 子段，Wintun Write 均值小于 0.8µs，四流没有绕过串行 owner/外层 FD 的约束。接下来应分别研究同 peer 的外层 I/O 对照、Linux 单 socket 回包成本，以及在保留同步 buffer/代次/取消语义下拆分双向消费；不是继续把总差额算作 AES 成本，也不直接在产品中异步借用现有 scratch。

### 证据

[完整十二点与 Linux 分组数值](../../build/validation/performance-20261014/wintun-udp-control/capacity-attempt-2/complete-results.json)、[六份采样的完整分段与桶界](../../build/validation/performance-20261014/wintun-udp-control/capacity-attempt-2/timing-compact.txt)、[源码/186 份原始材料/退出与资源证书](../../build/validation/performance-20261014/wintun-udp-control/capacity-attempt-2/final-source-raw-certificate.json)、[独立十二点数学与最终材料复核](../../build/validation/performance-20261014/wintun-udp-control/audit/complete-attempt-2/independent-matrix-audit-final.json) 和 [Root 源码/原生/host 复核](../../build/validation/performance-20261014/wintun-udp-control/capacity-attempt-2/root-source-native-host-audit.json) 在本地 ignored 路径。最终 18 项冻结、890 个原归档文件（其中 736 Go）和独列 5 个研究/runtime Go 文件逐字核验；冻结分析器 SHA `3792185d…` 未修改。源与原始失败目录、低点、预热/正式逐流账目、profile 及各阶段实际退出码全部保留，未发布或部署产品。

## 外部优化建议的 API 核对

2026-10-14 按用户提供的 Google 建议核对官方来源。首先区分两条路径：这里约 10µs 是外层 Winsock UDP write，约 0.62–0.77µs 才是四流 Wintun Write（Allocate/Copy/Send）提交段；后者返回也不表示后续协议栈或应用处理完成。

- [官方 session 实现](https://git.zx2c4.com/wintun/tree/api/session.c) 的 Allocate/Send 主要操作共享 ring 与同步状态，Send 在需要唤醒时调用 SetEvent；DLL API 调用不能等同于每包必有一次内核系统调用。公开 API 也没有让调用者直接控制“多包后统一通知”的独立 flush 函数。
- [官方 API](https://git.zx2c4.com/wintun/about/#reference) 的 GetReadWaitEvent 等待可读包，不是发送 ring 空位；AllocateSendPacket 的 ring-full 返回 ERROR_BUFFER_OVERFLOW。容量由 StartSession(Adapter, Capacity) 配置，OpenAdapter(Name) 没有 PoolCapacity 参数。现有实现已经使用 read event、一个同步数据面 writer 和 1 MiB ring，不能凭通用描述诊断多 writer 竞争或 ring 必然太小。
- 用户给出的 [Ring->Head 驱动修补](https://git.zx2c4.com/wintun/commit/?id=dd050927f42081dce7c2ae262be55ffd8210c11a) 确为 2026-02 的并发竞态修复，涉及内核 NDIS 路径；它是应独立核对的线索，不能用应用只设单 writer 替代驱动分析。本轮固定官方 0.14.1 DLL，尚未核对当前实际加载驱动是否包含该修补；成功组合点没有 Wintun 错误或内容损坏，未据此归因其吞吐/失包。
- [Microsoft USO 文档](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/udp-segmentation-offload-uso-) 要求应用指定 UDP_SEND_MSG_SIZE 并满足网络设备的分段能力条件。它针对 UDP socket 分段，不是 Wintun ring 配置。外层独立 ESP datagram 的大小、认证、序号及分组边界仍须保留；当前共享 socket 同时承担不同长度的控制/业务包，不能直接全局改变分段大小。本轮未实现 USO、批发送、驱动更新或 ring 扩容。

后续 [逐消息 UDP 分段研究](udp-segmentation-testing.md) 已补充实际 VM 的只读 offload 配置和磁盘 driver 版本证据；功能与容量结果分别列出，不回写成上述组合矩阵已启用 USO。

[相同 Linux peer 的无 Wintun 对照](shared-peer-udp-testing.md) 已完成六个正式点，单流/四流中位 722/659Mbps、同边界四流 UDP write 7.34–8.04µs；整体供给、checksum、CPU 及 RTT 范围另列，不能把差额全部算作 Wintun 成本。
