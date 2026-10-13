# Windows 业务包分段计时

本片沿用真实 SCM 服务、Wintun、IKE/ESP、Babel 及 Linux 网关，定位完整业务往返的额外成本。控制面生成授权和路由，数据面执行当前规则；业务包不会重新运行 Gossip 同步或 IKE 握手。稳态签名授权投影已有缓存，实际数据路径仍检查当前连接、地址、路由、期限和撤销，并在加解密后重新确认。

## 范围与单位

仅 `photon_profile` 验证构建提供采样原语与导出入口。普通发行构建不启用采样；不增加产品 CLI、配置、IPC 方法或监听端口。队列容量、明文和密文所有权、序号、防重放及交付前当前授权继续使用原路径。

同一 Windows VM 内的时长采用 [QueryPerformanceCounter](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps)，频率随结果记录。QPC 是经过时间，不是线程 CPU 时间；调用内的阻塞和调度也会计入。微秒分布不能用来直接拆解先前统计的全部服务 user/kernel CPU。

目标区间为 leaf64/esp64 的入队尝试至消费、消费后的准备与前置检查、真实 ESP、加解密后的当前规则检查，以及同步 UDP/Wintun 交付调用。发送返回不代表网卡已在线路上发完，Wintun 写返回也不代表应用已消费。raw64 尚无时间 metadata/归还契约，本片不把它计入队列等待。

两个入队来源各自按固定周期选取 1/256 尝试；这是系统采样，不是随机采样，也没有逐流性能分解。样本只携本次采样窗口编号和时间等标量。开启与关闭窗口都返回固定 schema；关闭探针时不读取逐包时钟，也不累计逐包样本。结束窗口先撤下采样状态，再冻结结果，旧队列和处理中样本不能写入下一窗。

各方向记录 selected/finished/unfinished，按 unknown/business/control 分类保留 delivered、rejected、crypto_error、delivery_error、queue_rejected、canceled。窗口结束时尚在排队或处理的选中样本计入 unfinished，不能当作实际丢包。六段各有 Count/SumNS/MinNS/MaxNS 及固定 64 个纳秒直方图区间，末项容纳溢出范围；均值和分位区间需要使用该段自己的样本数。

control 的 delivered 表示本次 owner turn 成功处理 Babel，并可能排入既有控制作业，不表示已经同步发送 UDP；对应 delivery 直方图可以为空。业务样本的 delivered 则要求原同步 UDP/设备写调用成功返回，两种含义不合并为业务交付数。

ESP 段只包围真实 `SealInto`/`OpenOwned` 调用，fresh 段从其结束延续至实际交付前，包含后续分类、返回、最新视图、时间、SA 与地址/路由检查。owner 总段从消费延续至最终记录前，包含各段和其间的处理；不能再与各段相加。失败样本可能缺少后续阶段，不同阶段均值也不能直接相加。采样的时钟调用及同步等待会进入所测区间，应同时看时钟/探针校准和完整服务 off/on 结果，不机械减去一个校准常数。

owner 总段结束于 `Finish` 的 QPC 读数，后面的直方图合并、解锁、错误日志与可能的设备停止不在这个 span 内，因此也不等于整个 owner turn 的总经过时间或 CPU 时间。

入队时间戳取在发送尝试之前，因此区间可能包含入队前复制及线程被抢占的时间，并不是严格从 channel 成功入队之后开始。拒收不能生成成功入队的等待样本。入站 ESP 队列在认证前接收数据，解密失败、控制包和成功业务包需要分开解释。

## 固定验证入口

在原完整吞吐、CPU profile 模式下设置 `PHOTON_WINDOWS_PACKET_TIMING=off` 或 `on`。`PHOTON_WINDOWS_PACKET_TIMING_LABEL` 只接受 `f1-w64-IPv4`、`f4-w64-IPv4`，缺省为单流。两模式使用同一个带标签的二进制、相同 profile 位置、负载及运行时设置，用来观察探针自身开销。未设置开关时保留既有采集方式。

带标签的 off 仍保留诊断专用的标量 trace 布局及采样状态读取。off/on 对照量的是同一诊断构建中开启采样的增量，不能据此声称带标签的 off 与普通产品成本完全相同。普通构建另验证三个真实队列/completion 结构保持原大小、空探针可内联和无新增诊断分配。

fixture 只接受本次隔离目录中的固定 marker，内容为 `off:<label>\n` 或 `on:<label>\n`；与大窗口 packet-drop 诊断分开运行。导出的 `profile-<PID>.packet-timing.json` 随公共测量结果保存在本地，不包含包内容、地址、身份或密钥，不自动发布。

窗口在 CPU profile 成功启动后、发布 `.started` 前开启，在观察到 stop/硬期限后、停止 CPU profile 前关闭。它含开始确认及停止轮询边界，不精确等于生成器的发送窗口。JSON 必须独占创建并在 `.done` 前写完关闭；读取方验证时钟、采样率、直方图及选中/完成守恒，拒绝时钟错误或无效样本。

## 验证与后续解释

实现的启停、边界、原生功能、时钟开销和完整服务 off/on 对照需要分别验证。结果应保留所有低点、失包、实际进程身份、源码及制品 SHA、退出码和资源清理证明；在实际测量完成前不提供规则、ESP 或收发调用的微秒分账。

便携普通/诊断回归、完整 `make check`、诊断包全量 race 和 Windows 交叉构建通过。回归覆盖真实 UDP admission、业务/控制分类、签名撤回、selector 改变、加解密后取消、认证与设备写失败；窗口冻结、旧样本、计数溢出和不虚构未消费的等待时间另有原语验证。普通编译记录确认新增空 hook 内联、`Sampled` 常 false 后取消额外诊断分类；没有声称新旧二进制逐字相同。

实际 Windows PowerShell 5.1 parser 及 40 个 marker/报告检查通过，包括 JSON 中 `UInt64.MaxValue` 经 Decimal 读取后精确转换、整数类型、非法 schema 和计数守恒。首次私有 runner 被默认 ExecutionPolicy 拒绝，零测试，原 exit 1 留存；仅在新进程使用既有 fixture 的 `-ExecutionPolicy Bypass` 后完成，没有修改系统策略。

便携/编译材料位于 `build/validation/performance-20261013/packet-timing-{primitives,wiring,checks}/`；PowerShell 与系统工具能力证明位于 `packet-timing-rig/`。Windows QPC 的原 `LazyProc.Call` 变参逃逸证据与改用缓存地址直接调用后的非逃逸证据均保留；编译证据不代替下面的原生分配检查及开销校准。

首次原生 child 的 39 个顶层场景中 38 个通过，包括所有新原语/consumer、实际探针零分配及真实 Wintun 双栈往返；旧 `TestWintunNativeLifecycle` 第二代因“新网卡应无包”的单次读假设失败，actual exit 1，后续 app/ordinary/benchmark 均未执行，资源独立清理通过。测试改为在原 20ms 调用方期限内消费 Windows 自发包，直到观察到 DeadlineExceeded，保留两代、写入、取消 join 及关闭后拒绝断言，不改生产驱动。失败日志与首冻结版本留存在 `packet-timing-rig/native-validation/`，新一轮独立冻结并完整验证，不选择替代容量点。

第二次 tagged internal 的 39 个顶层场景全部 PASS、actual child exit 0、无 skip，两个真实 Wintun 场景均完成；私有 wrapper 却用大小写不敏感的 `FAIL|SKIP` 搜索误匹配正常测试名称 `FailureCoverage`，wrapper exit 1，后续仍未开始。原状态及清理 exit 0 保留在 `native-validation-attempt-2/`。读取器改为匹配真实 Go FAIL/SKIP 状态行；相同已冻结 executable/源码的这 39 项结果复用，继续剩余 app/ordinary/benchmark，不重复已过测试或覆盖原始状态。

续行在 `native-validation-attempt-3/` 完成：app 7 项、ordinary internal 4 项及 12 个校准点共 14 个 fresh child，actual exit 全 0，无 skip；先用原 stdout 和 FAIL/SKIP 状态反例验证读取器。加上复用的 39 项，三个功能 executable 共 50 个顶层场景（含 3 个只读运行时 metadata helper）。735 个原 Go 文件、15 个 owner 文件、两个 package 中单独列出的 metadata helper、3 个 executable SHA、100ns 进程创建身份及实际运行时全部核验。开发冻结源为 `130feeb3` 加逐文件明确标记的 dirty/new 修改，不冒称清洁提交或发行 binary。

QPC 频率为 10MHz；所有 native child 实际 Go P8、8 个可见 logical CPU、process/system mask 均 `0xff`。三轮独占、每点 1 秒的校准如下，全部 **0 B/op、0 allocs/op**：

| 隔离循环 | R1 / R2 / R3，ns/op | 中位，ns/op |
| --- | --- | ---: |
| QPC read，含 clock mutex | 77.92 / 71.47 / 71.61 | 71.61 |
| tagged off 的空钩子循环 | 21.94 / 20.95 / 20.39 | 20.95 |
| 每次强制选中的完整钩子循环，含重设选择计数 | 589.3 / 571.9 / 569.8 | 571.9 |
| 实际 1/256 的空业务钩子循环 | 22.86 / 22.95 / 22.42 | 22.86 |

这些是没有真实业务处理/I/O 的独立循环平均时间，不是实际各阶段或纯 DLL 延迟，也不能将中位差额当作完整服务的精确百分比。QPC 的 100ns tick 与循环平均 ns/op 是不同概念；实际阶段仍要通过服务 on/off 对照观察，不从每段机械扣除 71.61ns。

14 个续行 PID/创建身份、精确网卡、测试地址/路由和唯一远端目录均独立确认不存在。初次内联清理命令超过远端 cmd 长度而未执行 absence 查询，原 exit 1 保留；仅改为文件执行相同所有权检查后 exit 0，没有重测。原生执行与外层清理状态分别报告。

[严格原生汇总](../../build/validation/performance-20261013/packet-timing-rig/native-validation-attempt-3/complete-validation-summary.json)、[Root 校准复算](../../build/validation/performance-20261013/packet-timing-rig/native-validation-attempt-3/root-native-audit.json)、[复用 39 项的 Root 核验](../../build/validation/performance-20261013/packet-timing-rig/native-validation-attempt-2/root-functional-audit.json) 与全部原始失败/成功材料保留在本地 ignored 目录。

## 完整产品 off/on 对照，2026-10-13

四个 fresh SCM 实例按 R1 off→on、R2 on→off 执行，保留全部 8 个正式点及 8 个预热点。每实例固定 IPv4 单流/四流、每流 64 credits、1200B 应用载荷、2 秒预热、8 秒发送和 1 秒回包期限。生成器与服务均实际 Go P8、8 个可见 logical CPU、affinity `0xff`；线程 CPU 每 250ms 观测。CPU profile 和分段窗口固定在四流点，单流点未开启分段窗口。吞吐按经过发送及排空的完整时间计算，不剔除尾部排空。

Windows 使用清洁 `2fa12c9b8c5c06a60ce95ff10ef39944a0a44418` archive 的同一个 `photon_profile` executable，SHA-256 为 `192edce5993af1f5d7bc85d85e14f2bdfc1ccf1b4bebe21d80ea731113f7c0b0`。Linux/echo/生成器沿用固定制品；735 个原 Go 文件与原生验证源码逐字核对，两份私有 metadata 测试 helper 未进入产品。35 个执行/制品文件单独冻结，私有 PowerShell 改动只将执行点选择为这两个 IPv4 点，保留原参数数组、profile 和资源恢复契约，没有修改跟踪脚本。执行目录的 HEAD/dirty 文档状态另记录，不据其冒称制品来源。

road 是 PVE `10.16.255.202` 上的 LXC，Linux 网关/echo 仍在 road 的 Docker bridge 中；Windows 11 是另一 PVE `10.16.255.200` 上的 KVM。没有改变或测量两台 PVE 的宿主 CPU/配额/NIC 队列，也没有追加 ETW 或 Linux 采样进程。

| 实例 | 单流 Mbps | 四流 Mbps | 单流/四流服务 CPU，%core | 四流过期 / 已回包 | 四流失包率 |
| --- | ---: | ---: | --- | --- | ---: |
| R1 off | 506.865 | 471.750 | 140.816 / 151.269 | 1500 / 429420 | 0.34809% |
| R1 on | 467.401 | 458.666 | 143.001 / 143.875 | 1489 / 425474 | 0.34874% |
| R2 on | 488.265 | 476.472 | 145.927 / 153.026 | 1479 / 439380 | 0.33548% |
| R2 off | 493.945 | 497.771 | 147.302 / 154.820 | 1491 / 448991 | 0.33098% |

单流均无失包；8 个正式点及其预热、两阶段间隙均没有记录到 ready 变化，恢复均通过。`%core` 的 100% 表示一个 CPU 核，不是整个 VM 使用率。关闭模式单流/四流中位分别 500.405/484.760Mbps，开启模式 477.833/467.569Mbps。每模式仅两次重复，不能将约 4.51%/3.55% 的中位差额归因为探针开销；特别是单流根本未开启窗口，其差额反映了实例间波动。四流未比单流增长、过期约 1500 的现象继续存在，不能因服务 CPU 超过一核就推断串行数据路径已并行化。

两份 on 报告均 QPC 10MHz、时钟错误/无效样本为 0、unfinished 为 0。business 样本均 delivered，各段 Count 相同：R1 出/入站 1664/1662，R2 1718/1715。下面每格为 **R1 / R2 的均值，µs**，按该段精确 SumNS/Count 计算，不以均值拆分 CPU。

| 阶段 | 出站 | 入站 |
| --- | ---: | ---: |
| 入队尝试到 owner 消费 | 406.000 / 411.030 | 465.429 / 435.937 |
| 前置准备和检查 | 1.538 / 1.558 | 0.989 / 0.984 |
| 真实 ESP SealInto/OpenOwned | 0.772 / 0.648 | 0.629 / 0.670 |
| ESP 后至交付前的最新检查 | 1.581 / 1.694 | 1.651 / 1.750 |
| 同步 UDP/Wintun 交付调用 | 9.668 / 9.343 | 0.666 / 0.655 |
| owner 总段，包含上述处理段 | 13.747 / 13.426 | 4.073 / 4.201 |

两轮/两方向 queue p50 都落在 `(262.144, 524.288]µs`，p99 在 `(1048.576, 2097.152]µs`；出站 delivery p50 在 `(4.096, 8.192]µs`、p99 在 `(32.768, 65.536]µs`，出站 owner p99 也在后一桶，入站 owner p99 在 `(16.384, 32.768]µs`。这是固定直方图桶的分位区间，不是精确分位值。独立分析器检查固定 schema、整数边界、计数守恒、桶/min/max/sum 可行性及 owner 包含关系，采用整数 nearest-rank，不用桶中点制造精确值。

在所观测的四流窗口中，加密和 Wintun 写都小于出站同步发送调用；两侧入队尝试至消费的等待明显大于 owner 总段。这支持优先拆解 `WriteTunnel` 的写锁等待、状态校验、`SetWriteDeadline` 与实际 UDP write；尚不能区分这 9.3–9.7µs 中的锁、调度、runtime 与内核，也不能把 400µs 等待算作 CPU 成本或单凭均值指定全链路瓶颈。raw64、Linux、宿主虚拟化及外部链路仍有未覆盖部分，未证明 AES 是全产品主要损失，更未证明已达到 1Gbps。

| profile 实例 | raw64 drop | leaf64 drop | esp64 drop | 抽样 queue_rejected 出/入 |
| --- | ---: | ---: | ---: | --- |
| R1 off | 15 | 891 | 574 | 0 / 0，采样关闭 |
| R1 on | 10 | 969 | 505 | 4 / 2 |
| R2 on | 34 | 938 | 502 | 4 / 4 |
| R2 off | 4 | 1174 | 313 | 0 / 0，采样关闭 |

drop 是各位置在 profile 窗口的精确计数差额，没有逐序号关联，不相加结算端到端失包；抽样 queue_rejected 属于 unknown 类，也不乘 256 估算精确丢包。profile 窗口含开始确认/停止轮询，不等于生成器窗口。

四个实例的完整 SCM fixture、严格读取器和独立 Docker/service/NIC/目录/私有输入清理均 actual exit 0。matrix actual exit 0 之后，同一宿主独立确认原 coordinator PID/创建身份已不存在。原始数值、全部低点及 source/runtime/profile/计数/退出/清理证据保留在 [完整矩阵汇总](../../build/validation/performance-20261013/packet-timing-rig/product-off-on/complete-summary.json) 和 [源文件/原始制品证书](../../build/validation/performance-20261013/packet-timing-rig/product-off-on/final-source-raw-certificate.json)；[R1 分段复算](../../build/validation/performance-20261013/packet-timing-analysis/r1-on.json)、[R2 分段复算](../../build/validation/performance-20261013/packet-timing-analysis/r2-on.json) 保留精确均值分数、分位桶及源报告 SHA。

内核具体函数仍需独立的 Windows 调用栈观测。当前 VM 有系统 WPR 和 CPU/Network profile，尚未安装 WPA/xperf，也尚未开始 ETW 录制。本片的分段经过时间不能替代该项证据。
