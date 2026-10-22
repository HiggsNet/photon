# Windows 业务包分段计时

无加密的真实 Wintun＋跨主机 UDP 组合补测已完成，见 [组合路径计时对照](wintun-udp-timing-testing.md)：同边界四流 UDP write 为 9.94–10.39µs，原产品的 8.5–9.3µs 量级没有随 AES 省略而消失；Linux peer 的单 socket 路径仍可能构成约束，不据此将全部成本归给 Windows 内核。

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

## 出站 UDP 调用内部，schema 2

2026-10-14 继续细分出站业务包的同步发送。报告的 `schema_version` 升为 2，保留原六个 `stages`，在每个 class 下增加固定的 `udp_delivery` 四个直方图；入站、控制包和 unknown 的这四项保持空。历史 schema 1 原始报告及分析器副本保留，不向旧报告补字段；当前 fixture 严格读取 schema 2。

| 子段 | 起点和终点 |
| --- | --- |
| `writer_lock_wait` | 复用主 delivery 开始时刻，至取得 `writeMu` 后的时钟读数；包含调用和 defer 的少量前置工作 |
| `validation_state` | 前一时刻至完成当前 socket/generation/peer 校验；字段由已持有的 `writeMu` 保护，历史版本额外取得 `mu` |
| `deadline` | 校验结束至原 `time.Now()+1s` 和 `SetWriteDeadline` 返回 |
| `udp_write` | 期限设置结束至原 `WriteToUDPAddrPort` 返回；包含 Go FD 锁、I/O 准备、系统调用和可能的完成等待 |

四个子段包含相应采样时钟及调度成本，均为经过时间。解锁及函数返回尾部只落入主 delivery；不能将子段再加到主 delivery，或把 `udp_write` 全称作内核 CPU。失败只记录实际已执行的子段，每段使用自己的 Count。原锁顺序、共享连接、逐包一秒写期限、当前 generation 校验及同步写入语义保持不变；新增 trace 仍只含标量，结束时一次检查全部主/子段转换与溢出后统一记账。

普通构建的四个新增标记仍为空方法。公共 `WriteTunnel` 契约保留，只有真实同步业务 completion 向同一私有实现借用它的 trace；控制路径不参与业务计时。诊断构建新增标量布局与四个标记的成本需单独校准，不能把 schema 1 和 2 的不同循环直接当作性能优化对照。

本片便携专项验证通过正常交付、stale generation、关闭 UDP 在 deadline 处失败、真实过大 datagram 写失败、迟到 epoch、子段转换/累加溢出与非法分类。普通构建真实结构大小及空探针 0 alloc 验证通过，新增四标记可内联且 writer 的 trace 参数不逃逸；历史六段校准保留，另命名 `BenchmarkFixturePacketTimingUDPHooks` 以覆盖四个新标记。全量 `make check`（含普通 Windows 构建）及诊断包全量 race actual exit 0，材料在 `packet-timing-udp-{wiring,checks}/`。

实际 PowerShell 5.1 的 schema 2 原始 71 个读取/marker/旧制品场景及 5 份脚本 parser 通过；独立审阅后收紧顶层字段大小写及 capture epoch 正值，增加两个反例，新 73 场景再次 actual exit 0、独立资源清理 exit 0。四个子段均覆盖 UInt64 超限、非法字段、错误方向、缺/多字段、Count 前缀、合法部分失败和 Sum 包络；临近 UInt64.MaxValue 仅差 100 的错误和能精确拒绝，不经 Double 舍入。两轮原始证明分别在 `packet-timing-v2-rig/ps-preflight-attempt-{1,2}/`，未覆盖旧结果。独立分析器显式兼容 schema 1/2，10 个数学/失败边界场景通过；四份 schema 1 原报告的分数均值与分位桶复算保持相同。

独立源码复核另补父/子段包络及最后 owner end 不早于最后主 mark：在转换后、任何 histogram/outcome 写入前用减法预算检查子段和；异常计时整条拒绝，保持 selected/unfinished 账目，不部分合并。固定标量反例覆盖父时钟相对子段回退、子和超预算、缺父段、owner 结束回退及相等预算接受。两次补强后的所有采样/consumer 专项 race 分别 actual exit 0（1.279s、1.275s）；原完整检查结果及两次源 SHA 单独保留，没有冒称原完整检查是在最后补强源上重新运行。

schema 2 原生 `native-validation-attempt-2/` 的 tagged internal 18、tagged app 7、ordinary internal 5 个顶层功能场景全部 PASS（共 30，含 3 个只读 runtime metadata helper），无 skip；另 12 个校准点，合计 15 个 fresh child 的实际退出码均为 0。固定实际 P8、8 logical CPU、process/system mask `0xff`、QPF 10MHz。沿用单独命名的新 UDP 空钩子循环、每点 1 秒、三轮交错顺序：

| schema 2 隔离循环 | R1 / R2 / R3，ns/op | 中位，ns/op |
| --- | --- | ---: |
| QPC read，含 clock mutex | 71.60 / 69.61 / 69.45 | 69.61 |
| UDP tagged off 的空钩子循环 | 36.92 / 35.01 / 35.61 | 35.61 |
| 每次强制选中的完整 UDP 钩子循环 | 886.2 / 872.6 / 880.6 | 880.6 |
| 实际 1/256 的空 UDP 钩子循环 | 38.89 / 39.09 / 40.21 | 39.09 |

所有 12 点均 **0 B/op、0 allocs/op**。本表循环含四个新增标记，没有业务处理或 I/O；不是业务延迟、CPU 分账或纯探针比例，也不能机械扣除 QPC 常数。原 schema 1 循环和本表的代码/布局不同，分开解释。

同一次开发冻结的 736 个原 Go 文件、9 个明确修改/新增 Go 文件（其中 internal owner 8 个）、2 个独列的原生 metadata helper、3 executable 和 47 个原始输出 SHA 均核验；源为 `b04180d` 加逐文件 dirty/new 声明。准备版本 `native-validation-attempt-1/` 在最后 clock 补强前仅完成 crossbuild，**0 native**，没有覆盖；第二版统一新 archive 重建三个 executable 后执行上述 15 child。原生/独立文件清理均 actual exit 0，15 个原 PID/100ns 创建身份和唯一远端目录均确认不存在。

复用读取器的原派生摘要误留 Go 数量常数 735；原摘要及其 SHA 保留，实际 736 个源文件逐个核验通过。只按 manifest 长度另出 [数量修正摘要](../../build/validation/performance-20261013/packet-timing-v2-rig/native-validation-attempt-2/count-corrected-summary.json)，没有修改任何原始测量、源码制品或重测；[Root 原始结果复核](../../build/validation/performance-20261013/packet-timing-v2-rig/native-validation-attempt-2/root-native-audit.json) 独立验证全部 736 源/47 输出、30 个功能场景、15 个实际 runtime 及 12 点原始值，保留原派生数量差异。

## 发送状态快照的锁减法，2026-10-14

两轮 UDP 子段之后，两个独立源码审计确认：`udp`、`closed`、`tunnelGeneration`、`ikePeer`、`nattPeer` 的全部生产修改只在 Rebind、Close、invalidate、SelectTunnel 内，均持 `writeMu→mu`；构造时先 Rebind 再返回，尚未发布。收包/Accept 失败先释放 `mu` 后进入同一 invalidate。`SetReadDeadline` 只修改另属 reader 的字段并调用 UDPConn 自有期限 API，不修改上述五项。

`WriteDatagram` / 私有 `writeTunnel` 已持 `writeMu` 跨快照、期限和实际写入，因此删除其快照的额外 `mu.Lock/Unlock`。setter 仍保留双锁，让原 reader/demux 的 `mu` 读取同步；其余 reader metadata 继续由 `mu` 保护。外层写锁、关闭/代次/端点校验、逐包一秒期限、同步交付和 scratch 所有权保持原样。仅一个 Go 文件变化，不增加第二状态 owner、访问器或新字段；收益最多是状态段中的部分锁成本，不先宣称吞吐提升。

全量 `make check` 与普通 Windows 构建 actual exit 0；普通/诊断 internal 全包 race 分别 22.142s / 22.341s，actual exit 0。Windows 原生 ordinary 5、profile 7 个顶层场景全部 RUN/PASS（含两个只读 runtime helper），额外明确核验 select/rebind/invalidate/close 四个代次隔离子场景及 profile 的实际 stale-generation writer 拒绝。两个 native child、native wrapper、独立文件清理均 actual exit 0，原 PID/100ns 创建身份及唯一临时目录均确认不存在；实际 P8/8 logical CPU/`0xff`，无 skip。

原生候选源为 `d67fd52` 加唯一 Go 文件 SHA `2946fde151590b0ceab1b4ca5926fa3b4d9e4b5cc767f55b9cfea5355a2e3b3e`；736 个原 Go 文件只有该处变化，单个 metadata helper 独列，未重跑未改的 Wintun、app 捕获、73 个报告检查或 12 点校准。便携材料在 `build/validation/performance-20261014/packet-socket-send-lock-checks/`；[原生汇总](../../build/validation/performance-20261014/packet-socket-snapshot-lock/complete-validation-summary.json) 与 [Root 复核](../../build/validation/performance-20261014/packet-socket-snapshot-lock/root-native-audit.json) 保留实际源码/制品/运行时/退出/子场景证据。完整业务使用旧/新清洁版本交错对照，尚不能以功能验证推断性能收益。

### 旧/新清洁版本完整业务交错对照

旧 A 为清洁 `9a6031e3b3adf9f3f4a39f4155223b065e8c57e8`、Windows SHA `4230b7ba…`，新 B 为清洁 `d660a79069560cbee1c58b3892b89609437b3aac`、SHA `d539334532bc672e0dd7d5501aeec3d46338b59843459aed70fdd95ed907651e`。新 archive 的 736 个原 Go 文件与上述原生候选逐字一致，不带 metadata helper；两版 Go 仅发送快照锁/注释不同，schema 2、Linux/echo/生成器、四个原脚本和 profile 位置保持一致。四次 fresh SCM 按 R1 old→new、R2 new→old，全部 on，仅四流 IPv4/每流 64/1200B/2 秒预热/8 秒发送/1 秒回包期限、实际 P8/`0xff`、线程 250ms。

首次 `product-paired/` 在 Linux fixture 启动阶段报 `/smoke/b4.test: Permission denied`：复制 Common 时误将三个原 0755 的 Linux executable 变成 0644，字节/SHA 一致；**0 预热、0 正式点**，rig/matrix actual exit 1。失败清理确认独有容器/目录/私有输入不存在，服务尚未产生所有权证明，因此未声称全部服务 absence；同宿主另确认原 coordinator 身份不存在。该点是夹具 setup 失败，不计作性能低点，原目录/冻结/退出与失败范围原样保留。

新 `product-paired-attempt-2/` 只保留三个 Linux 文件的 0755，六份 source/dest 字节一致、X_OK 通过；只读确认宿主 mount 无 noexec，既有 Docker 只读 bind 没加 noexec。Go、Windows exe、脚本及负载不变，没有重编译或重跑原生验证；43 项冻结新增权限证明，原失败目录不改。该轮四次完整 fixture、严格读取器、逐点恢复、独立 Docker/service/NIC/目录/私有输入清理均 actual exit 0，4 正式 + 4 预热共 32 个逐流 phase 账目完整保留，均无 logged ready 变化。matrix actual exit 0 后同宿主确认原 PID/创建身份已不存在。

| 顺序/版本 | Mbps | 服务 CPU，%core | 状态段均值，µs | UDP write，µs | 父 delivery，µs | 过期 / 已回包 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| R1 old | 459.154 | 155.091 | 0.326595 | 9.233214 | 10.283959 | 1498 / 428372 |
| R1 new | 525.047 | 165.735 | 0.155899 | 9.045645 | 9.940298 | 1491 / 463030 |
| R2 new | 496.983 | 152.220 | 0.147245 | 8.530718 | 9.351196 | 1479 / 458594 |
| R2 old | 505.178 | 153.794 | 0.356240 | 8.516964 | 9.566397 | 1481 / 473147 |

四行出站 business 的 Count 依次 1677/1814/1797/1851；均 delivered，四个 UDP 子段与父 delivery 同 Count，子和均不超父段，clock/invalid errors 与 unfinished 均 0，其他方向/类的 UDP 子段均空。状态段两轮从 0.326595→0.155899µs、0.356240→0.147245µs，包含 probe/prologue/调度，不能把差额全称作纯 mutex 成本。两轮 new 的状态 p50 桶 `[65,128]ns`、p99 `[257,512]ns`，old 的 p50 `[129,256]ns`、p99 `[2049,4096]ns`；保留 old 长尾、没有按容量选择替代点。

旧/新吞吐中位分别 482.166/511.015Mbps，约 +5.983% **只作这四点的描述**。每版仅两重复，range 重叠，第二轮 new 496.983 还低于 old 505.178，不能称为稳定吞吐提升、统计显著或单项因果收益。计算保留发送及排空（四点 8.956408/8.4660768/8.858458/8.9913154 秒），没有剔除短尾或挑第一轮较高点。echo 失包率依次 0.348477/0.320976/0.321471/0.312034%，无 late echo 或 send errors，所有 expired 留存。

同 profile 窗口的 raw/leaf/ESP 精确 drop 依次 `1/997/492`、`65/856/547`、`2/755/710`、`72/704/703`，仍不是可相加的端到端丢包账本。当前小改动确实减少了采样状态段，但 UDP 写入仍约 8.5–9.2µs、owner 单次消费仍同步交付，性能尚在约 0.5Gbps，未达到 1Gbps。下一重点继续是发送调用/完成路径与双向消费的串行阻塞，不以这约 0.2µs 的减法代替多核设计或内核归因。

[完整交错矩阵](../../build/validation/performance-20261014/packet-socket-snapshot-lock/product-paired-attempt-2/complete-summary.json)、[原始制品/权限/资源证书](../../build/validation/performance-20261014/packet-socket-snapshot-lock/product-paired-attempt-2/final-source-raw-certificate.json)、[独立四点复核](../../build/validation/performance-20261013/packet-timing-analysis/lock-paired-independent-matrix-audit.json) 和四份 `packet-timing-analysis/lock-paired-r{1,2}-{old,new}.json` 保留精确 Sum/Count、直方图分位与原报告 SHA。独审核对全部方向/类别/结果、主段与 UDP 子段、4 正式及 4 预热的逐流账目和单位公式，并绑定源码、运行时、48 份原始材料 SHA 与清理证书，actual exit 0。首次失败及新目录完整材料均在本地 ignored 研究路径。

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

## 完整产品 off/on 对照，schema 1，2026-10-13

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

四个实例的完整 SCM fixture、严格读取器和独立 Docker/service/NIC/目录/私有输入清理均 actual exit 0。matrix actual exit 0 之后，同一宿主独立确认原 coordinator PID/创建身份已不存在。原始数值、全部低点及 source/runtime/profile/计数/退出/清理证据保留在 [完整矩阵汇总](../../build/validation/performance-20261013/packet-timing-rig/product-off-on/complete-summary.json) 和 [源文件/原始制品证书](../../build/validation/performance-20261013/packet-timing-rig/product-off-on/final-source-raw-certificate.json)，[独立矩阵复核](../../build/validation/performance-20261013/packet-timing-analysis/independent-matrix-audit.json) 另核源文件 SHA、实际运行时及 16 个 phase 的原始账目和数值；[R1 分段复算](../../build/validation/performance-20261013/packet-timing-analysis/r1-on.json)、[R2 分段复算](../../build/validation/performance-20261013/packet-timing-analysis/r2-on.json) 保留精确均值分数、分位桶及源报告 SHA。

## 完整产品 UDP 子段，schema 2，2026-10-14

清洁 `9a6031e3b3adf9f3f4a39f4155223b065e8c57e8` archive 的 736 个原 Go 文件与最后原生版本逐字一致，两个 metadata helper 未进入产品。两次 fresh SCM 使用同一 Windows tagged executable `4230b7ba771c5ee47525ccc2d898317a7e49dccabd79a0dd486dacc86fb789e7`、固定 Linux/echo/生成器和 32 个冻结制品/脚本。只运行四流 IPv4、每流 64 credits、1200B、2 秒预热和 8 秒发送/1 秒期限，P8/affinity `0xff`、线程 250ms，profile 固定在正式四流点。两次均为 on，**没有同版本 off 对照**，不将与 schema 1 的差异称作提速或探针开销。

| 实例 | Mbps | 服务 CPU，%core | 已回包 / 过期 | echo 失包率 | 发送及排空，秒 |
| --- | ---: | ---: | --- | ---: | ---: |
| R1 on | 458.543 | 147.058 | 426303 / 1497 | 0.34993% | 8.9250342 |
| R2 on | 468.514 | 148.147 | 438035 / 1485 | 0.33787% | 8.9754757 |

两点与预热、阶段间隙均无 logged ready 变化，恢复/完整 SCM fixture/严格 schema 2 检查及独立 Docker/service/NIC/目录清理均 actual exit 0。全部正式/预热、逐流账目和低点保留；coordinator actual exit 0 后在同一宿主确认原 PID/创建身份已不存在。

出站业务样本 R1 为 1670、R2 为 1714，四个子段及父 delivery 使用同一 Count，均 delivered；无 clock/invalid errors、unfinished 为 0。下表为 **按各自精确 SumNS/Count 计算的均值，µs**。

| 出站 UDP 子段 | R1 | R2 |
| --- | ---: | ---: |
| 写锁等待，含开始调用及探针 | 0.175269 | 0.169078 |
| 连接状态校验，含状态锁 | 0.375210 | 0.353267 |
| 当前时间及写期限设置 | 0.287305 | 0.279055 |
| 实际 UDP 写入调用至返回 | 9.348263 | 9.074796 |
| 父 delivery，包含上述四段 | 10.345389 | 10.098541 |

同 Count 的 UDP write Sum 占父 delivery Sum 的 90.36164% / 89.86244%，这是包围关系下的**采样经过时间占比，不是 CPU 或内核比例**。写调用包含 Go FD 写锁、准备/pinning、系统调用、可能的 IOCP 完成等待、调度及探针。写锁、状态校验和写期限各不足 0.4µs；至少在这两窗内，`writeMu` 竞争与逐包 `SetWriteDeadline` 不是同步交付的主要耗时。两轮 UDP write p50 都在 `(4.096, 8.192]µs`，R1/R2 p99 分别在 `(32.768, 65.536]µs` / `(16.384, 32.768]µs`，保留桶区间，不插值成精确分位。R2 出站 owner 均值为 14.354µs。

R1 主段另有出/入 queue 410.508/443.972µs、ESP 0.781/0.652µs、owner 14.716/4.161µs，入站设备交付 0.649µs。入站四个 UDP 子段均为零。R1/R2 exact drop 分别 raw/leaf/ESP=`8/934/555`、`92/803/584`，不合并归因端到端 echo 失包；R1 抽样 queue_rejected 出/入为 2/4，仍独立于精确计数。

下一优先级是发送调用/完成路径及单 owner 同步交付对双向消费的阻塞。普通 Go 同 FD 多 writer 仍受 FD 写锁约束，不能直接启动更多 writer 就宣称多核利用；密文还借用单 owner scratch，排队发送必须先有明确所有权及撤销、CHILD 切换、序号、关闭/join 的证明。保持现同步语义的更小候选是审计已有 `writeMu` 对连接字段的保护，只有确认全部字段写入也持该锁后，才移除冗余的内部状态读锁。它最多减少状态段的一部分，不能承诺大幅吞吐提升。

[完整两点汇总](../../build/validation/performance-20261013/packet-timing-v2-rig/product-udp-on/complete-summary.json)、[源码/原始制品与资源证书](../../build/validation/performance-20261013/packet-timing-v2-rig/product-udp-on/final-source-raw-certificate.json)、[独立矩阵复核](../../build/validation/performance-20261013/packet-timing-analysis/v2-independent-matrix-audit.json)、[R1 精确分段复算](../../build/validation/performance-20261013/packet-timing-analysis/v2-r1-on.json)、[R2 精确分段复算](../../build/validation/performance-20261013/packet-timing-analysis/v2-r2-on.json) 保存在本地 ignored 目录，不发布密钥/包内容或新的产品入口。

内核具体函数仍需独立的 Windows 调用栈观测。当前 VM 有系统 WPR 和 CPU/Network profile，尚未安装 WPA/xperf，也尚未开始 ETW 录制。本片的分段经过时间不能替代该项证据。
