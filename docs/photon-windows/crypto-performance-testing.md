# Windows AES-GCM 与完整 ESP 的独立对照

2026-10-13，完成36个 Windows 原生测量点。单 CPU、单 SA 的完整 ESP Seal+Open循环约10.6–11.2 Gbps application-equivalent；八 CPU、单 SA 约9.1–9.3 Gbps，八个独立 SA合计约15 Gbps。这些结果不支持将完整产品当前约450 Mbps的表现主要解释为 AES算力不足，但也不是网络吞吐或产品1 Gbps证明。

## 冻结来源与完整性

生产源为 clean archive `5a0099810bf70f456ce8ccb7554ea19484e84531`，875个原文件、其中725个 Go文件逐字相等，只加入两个 ignored研究 test文件。此基线未包含后续 nonce scratch候选改动。研究 executable SHA256为 `76849c327bcc2fccb554152ea5609ab4582718d3e609c4d2fc8286177a54a74a`，冻结 manifest为 `b6507e7cc32931c5073d7162cce3568ad72fd01a637b53fa08eb1b147c88ae49`。

使用 Go1.26.5、Windows amd64、GOAMD64=v1、CGO_ENABLED=0、GOEXPERIMENT为空、GOFIPS140=off、`-buildvcs=false`，没有 purego或 `cpu.*=off` 对照混入主结果。每点真实检测 AES/PCLMULQDQ/SSE41/SSSE3均为true，GODEBUG为空、FIPS未启用；这些 flags是支持条件，不把 flags或仅有汇编符号当作本循环的执行 profile证明。标准库相关 Go/汇编源指纹也随 manifest保留。

本机13个顶层 focused测试及 race、Windows交叉构建通过；实际 Windows 的14项功能前置全部 PASS、无skip，包括 OpenSSL独立向量、caller/key所有权、真实 replay、认证失败不推进 replay、边界/序号耗尽、并发 Sender和重复 Receiver，以及研究 framing/预热序列/实际 runtime。随后36个点均真实子进程 ExitCode=0、JSON与`.done`匹配。源码/制品SHA、实际 P与affinity、同 PID、精确100 ns OS创建时间及十进制 creation token、全部 worker计数和公式均核对通过；独立审计从全部原始 JSON重算12组三轮统计。

[完整验证](../../build/validation/performance-20261013/crypto-control/validation.json)、[源码及制品冻结清单](../../build/validation/performance-20261013/crypto-control/freeze.json)、[14项原生功能日志](../../build/validation/performance-20261013/crypto-control/downloaded/photon-crypto-control-20261013-071931-302994/functional.stdout.log) 和 [全部36份原始JSON及实际子进程证明](../../build/validation/performance-20261013/crypto-control/downloaded/photon-crypto-control-20261013-071931-302994/) 保存在本地 ignored证据目录，没有用重测替换低点。`native.exit=0`；[独立清理记录](../../build/validation/performance-20261013/crypto-control/independent-cleanup.log) 确认功能及测量的37个原PID、精确自有 executable路径下的进程与唯一远端目录均已不存在。此测试没有创建网卡/路由或更改其他进程的 CPU配置。

## 方法与口径

三种条件为 Go P1/affinity1/单 worker单 SA、Go P8/affinity8/单 worker单 SA、Go P8/affinity8/八 worker各自独立 SA；affinity数指本进程可用逻辑处理器，实际掩码分别为`0x1/0xff`。每轮均测两种 IP长度和两条路径，三轮交替配置与 core/ESP顺序，共36点；没有同 SA八 worker或多远端产品对照。每点新子进程、新随机 keySalt，每 worker拥有独立 mutable buffers和 SA，只有合成 input只读共享；密钥不序列化。

- `core`：复用生产 `newSA` 的标准 AES-128-GCM-16实现，预分配 nonce/AAD/密文及独立明文输出，逐pair Seal+Open并完整校验 padded plaintext。没有 ESP mutex/framing/replay；构造的 wire先由实际 Receiver验证互操作和 replay。
- `esp`：实际长期保留的 Sender.Seal→Receiver.Open，逐pair完整校验 detached inner packet。1024次预热后只清计数，nonce/sequence及 Receiver replay lifetime继续；测后重复 Open必须返回 ErrReplay，没有用重复密文或重置 Receiver获得假 Open速率。

合成 UDP application payload为1200 B；IPv4/IPv6 inner为1228/1248 B，padded plaintext为1232/1252 B，真实 ESP wire为1264/1284 B。一次完整 Seal+Open pair只计一次1200 B application-equivalent；此值没有 network、Wintun、outer UDP、selector、fresh authorization、routing或实际包到达调度。输入会重复使用，core输出 buffer也复用，因此不能当作完整流量的内存路径。

测前 setup、新 key、预热及显式 GC排除，worker通过同一 barrier开始约一秒的循环，每128个已校验pair检查一次 monotonic deadline，末批和join纳入实际总秒数。表中的 ns/pair是总时长/全部完成pair数；多 worker时是聚合吞吐的倒数，不是某包或某worker的调用延迟。进程 user+kernel累计 CPU在窗口前后采集，查询与 monotonic边界存在小量开销，不能据此精确拆分各线程或命名 crypto owner。

分配量来自整个测量进程的 TotalAlloc/Mallocs增量，包含循环、同步及窗口内 runtime/GC活动。core表中接近零的数值是少量固定分配被摊薄，并非声称全进程绝对零分配。完整 ESP单 worker点只有一个调用者，Sender与Receiver使用各自独立 mutex，没有并发锁竞争；多 SA点各 worker也有独立锁，不能将 core/ESP差额全部称为锁竞争。

## 全部三轮中位数

Gbps为1200 B application-equivalent，括号为全部三轮范围；CPU和B/alloc均为独立重算的中位数，完整三轮值保留在原始证据中。

| Go P / affinity / SA数 | IP | 路径 | ns/pair | 等效Gbps（范围） | 进程 CPU%core | B/pair / allocs/pair |
| --- | --- | --- | ---: | --- | ---: | --- |
| 1 / 1 / 1 | IPv4 | core | 511.379 | 18.773 (18.054–20.276) | 98.433 | 0.000025 / 0.000001 |
| 1 / 1 / 1 | IPv4 | esp | 853.433 | 11.249 (11.224–11.928) | 98.335 | 2592.000041 / 4.000002 |
| 1 / 1 / 1 | IPv6 | core | 509.542 | 18.840 (18.401–18.912) | 98.370 | 0.000024 / 0.000001 |
| 1 / 1 / 1 | IPv6 | esp | 904.983 | 10.608 (10.368–11.303) | 98.435 | 2720.000043 / 4.000002 |
| 8 / 8 / 1 | IPv4 | core | 474.211 | 20.244 (19.999–20.534) | 99.823 | 0.000076 / 0.000001 |
| 8 / 8 / 1 | IPv4 | esp | 1029.438 | 9.325 (9.311–9.751) | 123.429 | 2592.036465 / 4.000171 |
| 8 / 8 / 1 | IPv6 | core | 547.718 | 17.527 (17.002–17.952) | 98.358 | 0.000088 / 0.000002 |
| 8 / 8 / 1 | IPv6 | esp | 1059.134 | 9.064 (8.890–9.174) | 131.083 | 2720.038720 / 4.000189 |
| 8 / 8 / 8 | IPv4 | core | 89.907 | 106.777 (106.542–108.813) | 790.570 | 0.001390 / 0.000002 |
| 8 / 8 / 8 | IPv4 | esp | 639.126 | 15.021 (14.314–15.048) | 401.407 | 2592.057142 / 4.000438 |
| 8 / 8 / 8 | IPv6 | core | 97.419 | 98.543 (98.348–99.228) | 792.964 | 0.002001 / 0.000003 |
| 8 / 8 / 8 | IPv6 | esp | 637.910 | 15.049 (15.013–15.446) | 426.337 | 2720.066814 / 4.000510 |

完整 ESP约4 allocs/pair，不能仅因源码显式创建两个输出 buffer就写成2。旧源码的两个局部 nonce在 AEAD interface调用处逃逸到 heap，[编译证据](../../build/validation/performance-20261013/esp-nonce/escape-before.log) 对应原 `esp.go:97/144`；实际分配还必须以上表的 whole-loop窗口为准。core/ESP差额同时包含 copy、allocation、nonce/header/trailer、inner validation、replay、mutex、GC和校验差异，不能单独归给锁或某条 AES指令。

## 后续候选与边界

[真实 Wintun C对照](wintun-capacity-testing.md) 在其隔离范围内约1.73–2.10 Gbps；[完整产品 CPU矩阵](cpu-control-testing.md) 与 [共享外层 UDP对照](outer-socket-io-testing.md) 测的是另一些路径。不能将不同夹具的速率相减算组件耗时，更不能把完整产品与core等效速率的差额全部归给 AES。

- 减少 nonce分配：在现有每SA mutex下复用私有 scratch，保留 fresh-key/sequence耗尽、认证成功才推进 replay、输入/输出所有权和并发契约。前述36点基线未包含该变更；后续验证见下文，不能将分配收益换算成产品吞吐收益。
- 收窄外层 IO与owner交接：继续依据完整产品 profile和队列观察测量共享 socket/deadline/调度开销，维持同owner序号发出顺序、rebind generation、取消与每包当前授权/SA/TS检查，不扩队列掩盖损失。
- 多远端归属：八独立 SA说明可并行的 crypto条件，不改变 Windows v1单活动网关。未来需要按独立 transport/SA明确owner与有界输入，保留每SA nonce/replay、提交顺序和交付时当前门禁；它是另一个设计任务，不是本轮已经实现的多核数据面。

这份文档记录已完成的基线，不关闭完整产品稳定1 Gbps、长期soak、发布或部署门槛。

## 已验证小片：复用锁内 nonce 工作区

依据上述逃逸证据，Sender与Receiver各自持有私有12字节工作区，每次仍在原mutex内完整填入salt与当前wire IV，再同步调用原AES-GCM。没有复用序号、缩短锁范围、修改认证/replay提交顺序或借用调用方/返回包的存储；Receiver仍读取peer实际IV。新增真实Seal+Open benchmark在每次调用开始时生成新随机密钥并建立一次SA，整个循环保留同一Sender/Receiver的序号/replay状态，逐pair核对完整plaintext。编译器检查确认两处生产局部nonce的逐调用heap逃逸消失。

这里benchmark的1200 B是完整inner IP，区别于前述36点的1200 B UDP application payload，不直接比较两组绝对耗时。旧、新冻结归档的876个文件仅生产`esp.go`不同；344个生产Go文件（不含`*_test.go`）除该文件外逐字相等，共同benchmark和ignored Windows TestMain字节一致。旧生产源固定`5a009981`，新生产源是审阅过的nonce补丁；[冻结清单](../../build/validation/performance-20261013/esp-nonce/freeze.json) SHA256为`dd6503f2e29e0284b546736dd12338b5ffe611448bb890a95db64b3a19a1bfbd`，[完整来源差异](../../build/validation/performance-20261013/esp-nonce/source-proof.json)保留，没有将新程序称作未修改的旧commit。

2026-10-13，ESP完整普通/race、相关Windows数据面/序号耗尽/Babel-ESP门禁普通/race通过；完整`make check`的格式、vet、全Go测试、Linux与普通Windows构建通过。受限环境的netlink拒绝与原selector在允许本机测试环境中的成功重跑都保留。Windows旧、新两版各11项原生加密功能测试全部PASS、无skip，然后按旧→新、新→旧、旧→新运行三轮。各点实际Go P8、affinity `0xff`、NumCPU8，OS创建身份精确100 ns与实际子进程匹配；全部8个子进程真实ExitCode=0。

| Windows轮次 | 旧ns/pair | 新ns/pair | 旧B/pair / allocs/pair | 新B/pair / allocs/pair |
| --- | ---: | ---: | --- | --- |
| 1 | 1107 | 1082 | 2592 / 4 | 2560 / 2 |
| 2 | 1063 | 1019 | 2592 / 4 | 2560 / 2 |
| 3 | 1017 | 1025 | 2592 / 4 | 2560 / 2 |

Windows中位耗时1063→1025 ns（约低3.6%），但范围1017–1107与1019–1082重叠，第三轮新版稍慢；没有统计显著性或完整隧道提速证明。明确可重复的收益是每pair减少两次分配、32 B，独立packet buffer仍保留。Linux本机三轮为旧1130/1142/1033、新1005/984.5/1001 ns，中位约低11.4%，仅作为[本机对照](../../build/validation/performance-20261013/esp-nonce/host-comparison.json)，不替代Windows结果。

[原生完整验证与全部三轮](../../build/validation/performance-20261013/esp-nonce/native-validation.json)、[运行与独立清理](../../build/validation/performance-20261013/esp-nonce/independent-cleanup.log)、[全量检查](../../build/validation/performance-20261013/esp-nonce/full-check-permitted.log)保留在ignored目录。`native.exit=0`，完整本地validator通过，8个原PID、两条精确executable路径的进程和唯一远端目录均独立确认不存在。TestMain的CPU累计涵盖整个`m.Run`及测试框架/SA setup，未归为benchmark逐pair CPU。本片不包含完整SCM隧道的前后吞吐重测，也不表示已实现多远端并行或稳定1 Gbps。
