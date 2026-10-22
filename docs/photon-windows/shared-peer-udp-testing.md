# 相同 Linux peer 的无 Wintun UDP 对照

2026-10-14 继续核对 [Wintun＋跨主机 UDP 无加密矩阵](wintun-udp-timing-testing.md) 中约 10µs 的 UDP write，以及 Linux 单 socket peer 的约束。新夹具保留同一个 Linux peer、完整 PWU1 格式、1264 B 外层 payload 和实际 Windows 共享 UDP 发送/分流，但省去 Wintun。本研究不修改生产实现，不代表完整 Photon 性能验收。

## 路径与不能直接相减的差异

清洁 `5bf076cc` 的生产 Go 文件逐字保留，研究文件单列；原 `5a009981` 工具的 payload/credit/完整内容校验和 CPU/线程观测通过独列桥接文件嵌入同一 Windows child。Windows 单 AF6 socket、实际 packetSockets reader、esp64 和 sole owner 保持；固定同一个 Linux peer source SHA `43fc4722…` 与 executable SHA `2f0f381a…`，读写缓冲区各请求 4 MiB，另外核验实际值。不改变 peer 为更快的回包程序。

Windows 路径为 `embedded flow engine → detached 1200 B payload → leaf64 → sole owner → 实际 writeTunnel → Linux peer → 实际 reader/demux/esp64 → owner → callback replies64 → flow engine`。每流仍使用独立 nonce/sequence、每流窗口 64 和一秒 deadline；四个 inner flow 共用一个外层 FD 和 owner，不等于四个并行数据面 worker。

整体吞吐与旧矩阵只能描述性对照，不能当作“只删除 Wintun”的精确差额：

- 新 producer 在进入 leaf64 前复制 payload，owner 新建 IPv4/UDP 头、完整 checksum 和 PWU1 frame；旧 Wintun 出站已经有完整 inner IP 包。
- leaf64 full 仍消费逻辑 Sent credit，等待实际 deadline 后归还；另记 admission drop。逻辑 Write 成功不等于实际 UDP 已发送。删除 raw64/Wintun ring 同时改变总缓冲与输入 backpressure，尤其影响四流同时供给。
- 回包再经过 bounded callback replies64；callback handoff 与完整内容校验分别执行，不能称为 Wintun Write。
- RTT 取 owner 消费 esp64 时刻，包含该队列等待、排除随后 decode/callback/content 校验；不是直接 UDP Read 返回时刻，也不与旧应用收包 RTT 相同。
- 进程 CPU 包含 embedded generator、完整校验、owner、reader 及观测；Generator/Service 相同 PID 的计数不能相加，也不能直接减去旧独立服务 CPU。

## 计时与正式方法

直接复用原 schema 2、QPC、1/256 admission-attempt 采样与 writeTunnel 四个标记。出站 UDP 的写锁/状态/期限/write 边界可以与旧组合及产品核对，均为 elapsed wall time，不是纯内核 CPU。新的 `aes` 槽是构建 IP/UDP/checksum/PWU1 或拆封，仍没有 AES；`fresh_gate` 是 current ctx/generation/peer，没有产品授权/路由/SA。入站 delivery 仅为 callback handoff，完整 payload 验证在 flow engine。

先执行低压完整 oracle，审阅并冻结源码/制品/执行器，再用三个 fresh Windows child，每个依次 f1/f4：实际 Go P8/affinity `0xff`、1200 B business、1264 B outer、window64、warm2s/send8s/deadline1s，共六正式与六预热点，全部开启采样，f4 同条件 CPU profile。速率按唯一完整验证 echo 的业务字节及包含排空的时间计算，保留全部超期和低点。没有增加新 off/on 矩阵或重复旧原生/校准套件。

## 准备验证与保留的失败

新 Windows executable SHA `faadff10…` 构建 actual exit 0。三个新增原生测试实际 RUN/PASS、无 skip：完整 inner checksum/workspace、输入复制与 callback 所有权/有界拒收、真实 AF6 loopback 发送与 deadline/关闭。原 child `6132/134364337694248087` actual exit 0、Go 1.26.5、P8/8CPU/affinity `0xff`；没有重复旧 Wintun 功能或计时校准。

首轮 PS wrapper actual exit 1：空 stderr 文件的 Get-Content -Raw 返回 null，随后 Trim 失败；原 child-proof.Completed=false 保留。只修两个私有 PS 的 string cast，不改 Go/executable。首次独立 cleanup 因内联路径 Replace 的反斜杠被转义为零长度而 exit 1，改用 char92/char47 后独立核验与清理 actual exit 0；不把首次失败写成已回收。首次 post-validation 因会话执行策略拒绝加载 helper 而 exit 1；新 post-2 仅指定进程级 Bypass，实际 PS 对原三项 RUN/PASS、创建身份/运行参数和 schema 2 严格复核 exit 0，没有再次运行 native 或修改机器执行策略。

执行器另移除无效的 failure stop-file 假设：新 Go 不读取该文件。异常时先读自有 launched-child，只有原 PID＋100ns 创建身份＋完整 image path 相符才终止/等待，缺失身份或路径不符明确失败并保留现场；取回材料并确认 exact owned image 不存在后才删除唯一目录。peer-ready 使用已验证的同目录临时文件写完关闭再 Move，保留拒绝覆盖。

准备冻结 `bc977e28…`，17 项逐一重算通过；[Root 源码/归档独立核对](../../build/validation/performance-20261014/shared-peer-udp-control/root-source-audit.json) 确认原 890 个文件（736 Go）逐字保留，独列 7 个研究 Go，共 743。正式前只增加三个 host launcher，另存 [20 项最终冻结核对](../../build/validation/performance-20261014/shared-peer-udp-control/root-final-freeze-audit.json)，SHA `bcf04efc…`，原 17 项字节不变；两个 manifest 不混用。初版构建、首次 PS/cleanup/post 验证失败、新 post-2 及清理输出均在 [准备原始目录](../../build/validation/performance-20261014/shared-peer-udp-control/native-functional/) 保留。

真实同 peer [低压结果](../../build/validation/performance-20261014/shared-peer-udp-control/functional-measurement/summary.json) 已完成：window4、各 warm1s/send1s，f1/f4 正式唯一 echo **23515/57795**，Expired 0；相应 exact outbound/inbound 完全相同，格式/nonce/content/账目/两方向 checksum 通过。Ignored、write errors、callback full/stale 均 0，两个方向计时分别 92/92 与 226/226 样本，QPF 10MHz、schema 2 守恒。整个 peer（含预热）received/echoed **161322**；两端、包装及独立 PID/token/socket/container/目录清理 actual exit 0。它是完整性检查，不进入容量统计。

## 三实例、六正式点

三组 fresh child 的六正式和六预热点全部完成，Windows/PS/peer/严格读取与独立清理 actual exit 0；每组原 PID＋创建身份、UDP/TCP pair、容器及唯一远端目录均不存在。host `3481018/196192202` 的 [最终身份核验](../../build/validation/performance-20261014/shared-peer-udp-control/final-host-proof.json) 确认原进程不存在、没有 PID reuse、matrix exit 0 与完整 summary。

| 轮次 | 单流 Mbps | 四流 Mbps | child CPU，单流/四流 %core | Expired，单流/四流 | 总秒数，单流/四流 |
| --- | ---: | ---: | --- | --- | --- |
| R1 on | 777.475 | 681.647 | 135.817 / 122.036 | 0 / 1418 | 8.007081 / 8.808896 |
| R2 on | 626.031 | 565.150 | 103.822 / 105.873 | 0 / 1379 | 8.006489 / 8.973024 |
| R3 on | 722.306 | 659.337 | 123.741 / 130.450 | 7 / 1451 | 8.005631 / 8.887503 |

这里列 sampled process CPU，包含 engine＋owner；另一个 whole-child CPU 字段观察同 PID，部分点因采样边界略有差异，不能相加。单流/四流中位 **722.306/659.337Mbps**，四流 loss **0.226195–0.260376%**，全部低点与单流 7 个 Expired 保留。LateEchoed、内容/来源/序号异常、send/write errors、callback full/stale 均 0。

四流三点 leaf64 full 分别 **423/502/577**，esp64 full 为 **995/877/874**；各点逻辑 Sent→实际 Outbound→callback Inbound→客户端 Echoed 的计数差值分别与这两个队列的 full 计数相符。它们与 Expired 是不同层的记录，不能再次累加成损失。单流 R3 的 7 个超期在这些 queue/callback full 计数均为 0，位置未定位；Linux 仍只有 whole-group datagram 计数，不能把数值相符当作端到端逐序号证明。四流输入更快填队列、失包 credit 等一秒才恢复，仍没有增加外层 owner 或 FD 并行度。

## 同边界阶段与 Linux 约束

六份 QPC 报告的 clock/invalid/unfinished 均 0，四个 UDP 子段与父 delivery 样本 Count 一致、嵌套 Sum 守恒；所有均值均用自己的 Sum/Count，单位 **µs**。

| 轮/流 | N 出/入 | 出站队列 | 入站队列 | UDP write | 父 UDP delivery | 入站 callback handoff | owner 出/入 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| R1 f1 | 2534 / 2534 | 132.202 | 119.514 | 7.269771 | 8.063418 | 1.607853 | 9.857340 / 2.615233 |
| R1 f4 | 2447 / 2446 | 125.353 | 138.974 | 7.339273 | 8.183694 | 1.412592 | 9.851492 / 2.375020 |
| R2 f1 | 2040 / 2040 | 63.255 | 57.606 | 7.557157 | 8.325735 | 1.104020 | 9.951324 / 2.004069 |
| R2 f4 | 2067 / 2063 | 82.251 | 83.699 | 7.659265 | 8.508563 | 1.143674 | 10.125399 / 2.065681 |
| R3 f1 | 2353 / 2353 | 94.207 | 76.869 | 7.749894 | 8.538292 | 1.150404 | 10.321079 / 2.115130 |
| R3 f4 | 2388 / 2385 | 139.974 | 131.099 | 8.041750 | 8.882161 | 1.301216 | 10.648786 / 2.388218 |

四流 write **7.34–8.04µs**，比旧组合同边界 **9.94–10.39µs** 低，但仍是最大的已测出站 owner 子段；writeLock/状态/期限各约 0.17–0.29µs。新出站 checksum＋framing（`aes` 别名）**0.905–1.003µs**，与旧组合仅封装的 0.339–0.387µs 含义不同。输入供给、总缓冲、callback、CPU 及实例运行条件变化，不能把 write 或吞吐差额全算为 Wintun 成本，也不能由 wall span 得出具体内核函数成本。

相同 Linux peer 的三个 whole-group 结果如下，含预热、两个正式点、间隙和关闭；不是逐正式点 CPU。每组 P8/12CPU，buffers 请求 4 MiB、实际各 8 MiB，received/echoed 相同、peer ignored/write errors 0。

| 轮次 | received / echoed | 进程 CPU 秒 | user / kernel 秒 | 观察秒数 | %core | kernel 占进程 CPU |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| R1 | 1589081 | 21.708606 | 2.527987 / 19.180619 | 27.750751 | 78.227 | 88.355% |
| R2 | 1320692 | 25.150948 | 2.999791 / 22.151157 | 28.051106 | 89.661 | 88.073% |
| R3 | 1527109 | 24.422889 | 3.046811 / 21.376078 | 28.151131 | 86.756 | 87.525% |

绕过 Wintun 后仍未达到 1Gbps；Windows 同步发送、双向单 owner 消费和 Linux 串行回包/内核路径都值得继续研究。Linux 组级 kernel CPU 仍约占 88%，未测两台 PVE/软中断/真实网卡队列，不能指定 Windows 单端瓶颈。下一步 [逐消息 USO 功能证伪](udp-segmentation-testing.md) 先验证批发送保持完整 datagram，再决定如何量调用摊销和组装成本；不把功能通过当作容量收益。

[原始完整矩阵与独立清理](../../build/validation/performance-20261014/shared-peer-udp-control/capacity-measurement/summary.json)、[完整六点原值](../../build/validation/performance-20261014/shared-peer-udp-control/complete-results.json)、[最终独立数学/直方图/逐流账目及 Linux CPU 核对](../../build/validation/performance-20261014/shared-peer-udp-control/audit/complete/independent-matrix-audit-final.json)、[源码/66 份原始材料/退出资源证书](../../build/validation/performance-20261014/shared-peer-udp-control/final-source-raw-certificate.json) 与 [Root 最终字节/证据复核](../../build/validation/performance-20261014/shared-peer-udp-control/root-final-evidence-audit.json) 在 ignored 本地目录；沿用 SHA `3792185d…` 的 schema 2 分析器和 `03618a6e…` 旧有界数学 helper，没有重复测量。源码/冻结核验与实际退出/资源证明分别保留，不以派生均值代替原始证据。

## 已捕获 CPU profile 的离线核对

没有重测或另开采样：只解析上述三个 f4 profile，逐一绑定 `faadff10…` binary 和原 66 份材料的 SHA，保留 raw flat/cum top10、完整表及独列的 cgocall-filter 子集。以下比例属于完整 pprof 样本权重，cum 与 flat 有嵌套，不能相加。

| 轮次 | profile 时长 / 样本权重秒 | 实际进程 CPU 秒 | cgocall flat | writeTunnel cum |
| --- | --- | ---: | ---: | ---: |
| R1 | 8.81 / 10.18 | 10.750000 | 51.08% | 44.70% |
| R2 | 8.97 / 8.13 | 9.500000 | 51.91% | 44.03% |
| R3 | 8.89 / 10.14 | 11.593750 | 50.30% | 44.67% |

可见栈主要落在 Windows DLL/syscall 的 runtime 入口、FD WriteToInet6/execIO 发送链，以及 semaphore/netpoll/select/lock 的唤醒调度。这里的 cgocall 名称不表示构建开启 Cgo，也不等于具体内核函数、DPC 或逐线程 CPU 分账。新 checksum flat **2.21–3.06%**，完整 payload 验证 flat **0.49–1.38%**，确有成本，未主导这三份可见样本。

[离线 profile 分析](../../build/validation/performance-20261014/shared-peer-udp-control/audit/profile-analysis/profile-analysis.json) 另列实际进程 CPU counters、profile duration 和 sample weight；过滤后的子集不重新冒充完整 CPU，不能用 Windows 用户可见栈替代 ETW/内核或 PVE 证据。
