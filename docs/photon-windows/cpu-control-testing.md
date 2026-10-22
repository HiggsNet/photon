# Windows 调度上限、可用 CPU 与线程测量

本页记录测试构建的测量方法和已完成的 Go 并行度对照；目标服务进程的可用 CPU 数也已完成独立对照，不表示已经完成多核数据面优化。Windows 现有产品仍是单活动网关；多远端结构的后续研究另行记录。

## 服务运行配置

仅 `windows && photon_profile` 构建在实际 SCM 的 `run --service` 启动前缀下读取 executable 相邻目录的两个可选文件：

| 文件 | 严格内容 | 设置范围 |
| --- | --- | --- |
| `fixture-gomaxprocs` | `1\n`、`2\n`、`4\n` 或 `8\n`，恰好两字节 | 仅本服务的 Go 并行执行上限 |
| `fixture-cpu-affinity` | 同上 | 仅本服务进程；从原 CPU 掩码中选择前 N 个可用位，不扩大原范围 |

未提供文件时不调用对应 setter。两份请求及 API、原可用 CPU 数均先校验；以 `O_EXCL` 保留结果文件后才应用配置。无效请求、可用 CPU 不足或旧结果文件会失败，不能静默回退并继续把采样标成请求值。失败启动明确输出 stderr 并退出 1，同时尝试独占写 `runtime-PID.error`；不修改机器级配置、普通 CLI 或控制协议。

成功记录为 `runtime-PID.json`：真实 PID、OS 进程创建时间、Go 版本、`NumCPU`、GOMAXPROCS Before/Requested/Actual/Explicit，以及 CPU 掩码 Before/Actual/System、请求 CPU 数和实际可用位数。`NumCPU` 是 Go 的启动缓存值，不能替代修改后的掩码计数；Requested 为 0 表示没有请求，不表示实际只能使用零个 CPU。当前夹具保守限定一个 processor group，不把它当作超过 64 个逻辑处理器的通用验收。

[GOMAXPROCS](https://pkg.go.dev/runtime@go1.26.5#GOMAXPROCS) 限制同时执行 Go 代码的线程数，系统调用中的线程另有运行行为；它不能当作操作系统可用处理器数。进程 affinity 则限制本进程线程可运行的逻辑处理器，见 [SetProcessAffinityMask](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setprocessaffinitymask)。本页“CPU 数”均指逻辑处理器，不从 VM 的编号推断宿主物理核或超线程拓扑。

## 分开比较两个变量

生成器保持同 executable、GOMAXPROCS 和实际 affinity。服务用同一冻结源码及构建标志，分别比较：

1. Go 上限：GOMAXPROCS 为 1/2/4/8，可用 CPU 掩码保持 8 个逻辑处理器。
2. 系统可用 CPU：进程 affinity 为 1/2/4/8 个逻辑处理器，GOMAXPROCS 保持 8。

每点先验证实际值及同 PID/OS 创建身份，再使用统一 1200 B、预热 2 秒、发送 8 秒、每请求期限 1 秒的完整 credit 工具。重复轮次交替配置顺序，保留四流每流窗口 64 和单流；压力点另列，不能以最高点代替对照。首点 CPU profile 的位置、线程采样和构建条件必须一致。若共用 8/8 基线样本，在两份 matrix 中明确说明，不能伪称两次独立采样。

实际统计时长包含超期排空，四流与单流的分母可能不同。保留完整唯一回包、Expired/Late、payload 校验、测后低压恢复，以及测量内 readiness/rekey 变化；测后恢复不证明测量期间连续就绪。

## 线程 CPU 的解释边界

线程测量使用 Windows 的累计 user/kernel 时间，见 [GetThreadTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadtimes)。线程编号可以重用，必须同时核对所属进程和线程创建标识。消失的采样不是 CPU 为零，也不自动证明线程已退出；新出现或退出的线程可能缺少完整计数边界。

进程总 CPU 与可匹配线程区间的 CPU 分别记录，不把线程采样相加充当完整进程账目。100% 对应一个逻辑核。Go goroutine 会迁移，最忙的 OS 线程不能直接命名为 daemon owner；Go profile 中的 Windows 等待 syscall 栈也不能全部解释为实际 CPU 运算。

之前四 socket 直连 control 约 2 Gbps，不经过 Wintun；双栈共享外层 socket 对照约 820–824 Mbps 的 1200 B 等效量，也不经过 Wintun、AES 或当前授权。这些不能替代包含真实 Wintun 的无加密数据路径实测，详见 [I/O 对照](outer-socket-io-testing.md) 和 [现有四流解释](throughput-testing.md#多流cpu-与串行处理边界)。

## 运行入口功能验证

2026-10-13，Go 1.26.5 普通 app 测试、普通及 `photon_profile` Windows 交叉构建通过。冻结 tagged 测试 executable SHA256 为 `22f1bd615e4f2ca76a2a59f4e0933955cc4132b5ef3761ed9a5d1ee3061578b9`，Windows 原生 7 个顶层测试全部 PASS、无 skip；GOMAXPROCS 与 affinity 的 1/2/4/8 取值分别在短子进程验证，测试父进程的配置不变。

覆盖缺省值不改变继承设置、设置值真实生效、无效/过大请求在应用前拒绝、旧文件不覆盖，以及真实 SCM 命令前缀的 init 失败写出 error 并退出 1。原生测试子进程退出码实际捕获为 0，测试 PID3888、所有自有子进程及远端目录独立确认已清理。源码指纹、构建、原生日志及清理材料保存在本地 `build/validation/performance-20261013/runtime-fixture/`。

这验证配置入口和结果归属，不是吞吐核数对照。

## 外部采样器与脚本验证

测量工具的 `-thread-cpu` 仅用于 Windows client mode 且需要明确的服务 PID。采样周期 250 ms，单次最多枚举 1024 个目标线程；记录 TID、十进制字符串的线程创建标识、user/kernel/总 CPU 累计值、该线程实际观察时刻、FirstSeen/Exited/Missing 和 API 错误。打开线程后再次核对所属 PID，退出状态通过 handle 等待查询，不能读取活动线程未定义的 exit FILETIME 来判断退出。

生成器的实际 GOMAXPROCS/affinity 与服务分别记录。服务采样同时核验原进程仍存活；不同进程创建标识的末尾样本不进入 CPU 差分。多 processor-group 的掩码标为不完整；当前 8 CPU VM 的有效样本要求单 group、精确掩码一致。脚本对预热和正式测量都拒绝不完整、损坏、外来、未发送、重复、发送错误或预算耗尽，并拒绝枚举失败、全线程查询失败、拒绝访问和无法观察到真实线程 CPU 增量的结果。

2026-10-13，完整工具普通测试和 host race（3.034 秒）通过，Windows 交叉构建通过。冻结 native test executable SHA256 为 `233e5cfa7d18f7754a65863b95b745d4776475ea52a640295c126bd818e200ba`，实际 Windows 原生 5 项全部 PASS、无 skip，捕获子进程退出码 0；忙线程 TID5488 的线程与进程 CPU 都实际增加 0.015625 秒。保留旧 thread handle 后验证真实退出、原创建标识及累计计数，另验证退出子进程被拒绝、TID 重用和缺失样本不合并。

原生 PID4316 和自有目录独立确认清理。材料位于本地 `build/validation/performance-20261012/thread-cpu/`，实际执行日期为 2026-10-13。最后脚本 SHA256 `132d919cb97a915d9660d71f4bb828ab95cd2ccf1dcab39d0946ddd251086c52` 通过真实 Windows parser 和从当前 AST 抽取的 10 个校验探针，覆盖不完整预热、预算、相同 CPU 数但不同掩码、线程访问失败及重用等；这些是脚本校验，不是性能或实际产品结果，旧版本 parse 证据保留。

新增观测代码的全量检查、Linux/普通 Windows 构建通过；受限环境中的本地 socket 拒绝日志和允许本地测试网络后的成功重跑均保留在 `build/validation/performance-20261013/check-after-cpu-observation*.log`。冻结来源、完整核数矩阵与下一步优化的结果将在各独立阶段完成后追加；短测不关闭 1 Gbps、72h 或发布门槛。

## Go 并行度 A：三轮完整 SCM 对照

2026-10-13，在同一 8 逻辑 CPU Windows VM 上完成 12 个配置组、72 个正式点及 72 个预热点，服务 affinity 始终为 `0xff`，生成器始终为实际 Go P8/`0xff`。三轮服务 Go P 顺序依次为 `1,2,4,8`、`8,4,2,1`、`2,8,1,4`；每组均独立运行完整 SCM 夹具，六点顺序、1200 B、2 秒预热/8 秒发送/1 秒请求期限与 8M 包上限一致。仅首个单流 IPv4 点 profile，所有点同样启用 250 ms 线程采样，没有 drop diagnostic marker。

Windows 与新生成器均来自 clean archive `5a0099810bf70f456ce8ccb7554ea19484e84531`，Go 1.26.5/CGO=0，服务构建为 `photon_profile`。Windows executable SHA256 `5906cd3d8b0ffd18e1cf2178fc846b613e06603da49a47359de644fe6a74707d`，生成器 SHA256 `b7cc610eafbcbf6a61e19a8c13430064d6b92a4a1bdf109240e1b15d9fb80b1a`。Linux daemon/fixture 仍固定 `2c06877`，Linux echo 固定最终 `c1c8ea8`，没有重编译或改动其容量；完整分别来源和五份二进制 SHA 见本地 [冻结 manifest](../../build/validation/performance-20261012/runtime-cpu-bundle/performance-sources.json)。48 个内部生产文件仍与 Owned `84001ce` 同字节，这一轮没有产品数据通路优化。

同一新生成器先完成三轮 IPv4 LAN 直连四流/w64 control：2220.444 / 2299.949 / 1971.172 Mbps，中位数 2220.444 Mbps，实际生成器 P8/掩码 `0xff`，全部预热与正式点无超期、迟到或完整性异常。它使用独立 UDP socket，不经过 Wintun、ESP、AES 或授权，也不枚举服务线程，不能当作产品容量。6,740,117 个客户端发送/唯一回包与 peer 聚合计数相等；peer 未逐序号去重，不能据此精确归属前向丢包。六个真实子进程 exit0、PID/自有目录/Docker/端口已清理，完整资料见本地 `runtime-generator-control/`。

下表保留三轮全部值计算的中位数和最小–最大范围，不剔除低点。CPU 是进程累计 user+kernel 时间，100% 对应一个逻辑核；末列仅统计预热和正式测量开始前最后日志为 ready=true、两个阶段及其间隙无就绪变化的观察数，不证明持续就绪或稳态。

| Go P | 点 | Mbps 中位数（范围） | 服务 CPU%core 中位数 | 无日志中断观察 |
| --- | --- | --- | --- | --- |
| 1 | f1-w64-IPv4 | 172.745 (163.941–177.165) | 33.147 | 3/3 |
| 1 | f1-w64-IPv6 | 177.769 (167.722–179.700) | 31.208 | 3/3 |
| 1 | f4-w64-IPv4 | 187.931 (174.527–191.675) | 30.048 | 3/3 |
| 1 | f4-w64-IPv6 | 184.765 (183.219–188.933) | 34.791 | 3/3 |
| 2 | f1-w64-IPv4 | 376.419 (361.896–421.624) | 85.073 | 3/3 |
| 2 | f1-w64-IPv6 | 405.780 (350.379–415.956) | 88.779 | 3/3 |
| 2 | f4-w64-IPv4 | 458.511 (418.401–477.679) | 93.145 | 3/3 |
| 2 | f4-w64-IPv6 | 429.055 (65.077–436.024) | 93.060 | 2/3 |
| 4 | f1-w64-IPv4 | 497.370 (367.756–507.301) | 152.896 | 3/3 |
| 4 | f1-w64-IPv6 | 478.370 (384.342–494.816) | 143.198 | 3/3 |
| 4 | f4-w64-IPv4 | 452.803 (441.986–474.091) | 146.443 | 3/3 |
| 4 | f4-w64-IPv6 | 450.284 (442.028–469.005) | 142.041 | 3/3 |
| 8 | f1-w64-IPv4 | 443.322 (413.780–489.863) | 154.695 | 3/3 |
| 8 | f1-w64-IPv6 | 375.861 (367.992–484.072) | 141.216 | 3/3 |
| 8 | f4-w64-IPv4 | 459.600 (450.856–470.440) | 148.133 | 3/3 |
| 8 | f4-w64-IPv6 | 458.709 (449.907–468.666) | 149.609 | 3/3 |

压力点的三轮原值如下；受就绪变化影响的点原样计入范围与中位数，不作为稳态或 CPU 因果比较。

| Go P | 点 | Mbps r1 / r2 / r3 | 中位数（范围） | EchoLoss% r1 / r2 / r3 | 无日志中断观察 |
| --- | --- | --- | --- | --- | --- |
| 1 | f4-w1024-IPv4 | 169.849 / 85.257 / 23.235 | 85.257 (23.235–169.849) | 18.112 / 29.007 / 62.483 | 0/3 |
| 1 | f4-w1024-IPv6 | 174.171 / 185.164 / 175.229 | 175.229 (174.171–185.164) | 16.751 / 16.430 / 17.284 | 3/3 |
| 2 | f4-w1024-IPv4 | 40.948 / 12.534 / 447.512 | 40.948 (12.534–447.512) | 46.387 / 75.325 / 7.218 | 1/3 |
| 2 | f4-w1024-IPv6 | 411.974 / 425.513 / 447.103 | 425.513 (411.974–447.103) | 7.966 / 7.496 / 7.265 | 3/3 |
| 4 | f4-w1024-IPv4 | 148.971 / 188.560 / 206.352 | 188.560 (148.971–206.352) | 19.450 / 16.041 / 14.375 | 0/3 |
| 4 | f4-w1024-IPv6 | 464.622 / 452.798 / 431.056 | 452.798 (431.056–464.622) | 6.879 / 7.162 / 7.414 | 3/3 |
| 8 | f4-w1024-IPv4 | 0.000 / 144.308 / 129.638 | 129.638 (0.000–144.308) | 100.000 / 20.015 / 22.611 | 0/3 |
| 8 | f4-w1024-IPv6 | 422.293 / 431.363 / 449.669 | 431.363 (422.293–449.669) | 7.697 / 7.396 / 7.249 | 3/3 |

完整 [72 点三轮原始表及逐点就绪边界](../../build/validation/performance-20261012/runtime-gomaxprocs-A/complete-results.md) 和 [完整计数、线程及统计汇总](../../build/validation/performance-20261012/runtime-gomaxprocs-A/complete-summary.json) 保存在本地 ignored 证据目录，没有选择最高点或重测替换。12 组均真实核对请求/实际 P、精确掩码、OS 创建身份、同服务 PID、两阶段完整性、每流和总计账目、实际排空时长，以及固定 profile PID/`.done`；`matrix.exit=0`、12 组 rig/checker 通过，测后逐点低压恢复及各组独立 SCM/NIC/地址路由/Event Log/自有目录/Docker/私有测试输入清理通过。72 正式点 LateEchoed 全为 0，Expired/损失原值全部保留。

60/72 点符合上述“无日志中断观察”，另 12 点是混合状态：11 个大窗 IPv4 点，以及 r3/P2 的四流/w64 IPv6。r1/P8 大窗 IPv4 在预热阶段（含排空） t+2.437721 秒变为 false，正式开始前已 false，正式值为 0 Mbps/100% EchoLoss；不能因正式窗口内没有新事件就视为稳定。r3/P2 四流/w64 IPv6 为 65.077 Mbps，正式 t+0.176759 秒 false、t+7.024759 秒 true。所有测后 RecoveryPassed=true 只证明随后恢复，不证明测量期间连续就绪；完整 warmup/开始前 prior/gap/测量日志均保留，不据时间相关性归因 Owned、CPU、续租或队列。

Go P4 的单流 IPv4 中位数较高，但三轮 507.301/497.370/367.756 Mbps 的范围与 P8 重叠，第三轮 IPv6 单流也降到 384.342 Mbps；不能据中位数直接改默认值。P2/4/8 四流小窗 IPv4 中位数均约 453–460 Mbps，没有随 P 倍增；P1/affinity8 更不是“只可用一个 CPU”的实测。下一片独立固定 Go P8、改变真实 affinity 1/2/4/8，对照不能与本轮混为一组。

首 r1/P1 IPv4 服务实际累计 CPU 为 2.6875 秒/8.4742361 秒 = 31.714%core；同点 Go profile 的 8.60 秒中却记录 19.93 秒样本（231.74%），主要含 `runtime.cgocall` 的 Windows pipe/Wintun 等待。这不是实际运算 CPU。匹配的前三个线程区间约 0.703125/0.6875/0.609375 CPU 秒，仍只是部分相邻身份区间；不归一化过滤后的栈为完整 CPU，也不命名某 TID 为 daemon owner。解析材料位于本地 `performance-20261013/single-multicore-audit/`。这一轮尚未达到稳定 1 Gbps，也不关闭 72h 或发布门槛。

## 可用 CPU B2：固定 Go P8 的三轮对照

2026-10-13，完成三轮、12 组及 24 正式/24 预热点，仅比较 IPv4 单流/w64 与四流/w64，CPU 数顺序与 A 相同。服务 Go P 始终为实际 8，可用掩码分别为 `0x1/0x3/0xf/0xff`；生成器 Go P8/`0xff`、首点 profile、250 ms 线程采样、1200 B、2 秒预热/8 秒发送/1 秒期限和预算均保持一致。每轮的 8/8 也是新独立采样，没有复用 A。这里限制的是目标服务进程可运行的逻辑 CPU；VM、生成器和其他系统工作仍在 8 CPU 环境中，不是整台 VM 仅剩一个 CPU 的测试。

产品/生成器与 A 为同一冻结 `5906cd…`/`b7cc61…` executable，实际源码仍是 archive `5a009981`，Linux daemon/fixture `2c06877` 和 echo `c1c8ea8` 不变。各 case 的 `source-commit.txt` 为运行工作区 HEAD `93563e64ef544099c48470ecc81361dc91839414`，即 A 结果文档提交后的 checkout；它不是二进制编译来源，准确分别来源以冻结 manifest 和 SHA 为准。

原 B attempt1 的 singleton family 数组在 PowerShell 被展开为三个字符串，首个错误参数为 label `f1-w64-I`、local `P`、remote `v`；工具拒绝显式 IP，rig exit1，没有任何预热或正式 JSON，不能记作 affinity1 性能。原脚本 SHA `a3bdbcd…`、原实际字节、退出与失败材料均保留，PID5768（含创建身份）、自有 SCM/NIC/地址路由/Event Log/目录/Docker 独立确认清理。新 B2 使用独立 ignored 副本，只改两处 foreach 选择器，单个 family 用 unary comma 保持 tuple；helper SHA `d029109962b51bbfdac02464bed1aefbaa35d51d53cc95f69b3a7102ca58dee2`，coordinator SHA `700eeb462393a063afbf117e4515e5a8296834789676e20a39035ea00e6cf5e0`，不是 clean5a 脚本原字节。

真实 Windows parser 与从实际 AST 提取的嵌套 foreach 条件通过纯语义探针，逐字段确认两条完整 typed tuple 的 flow/window/family/label/local/remote，并以保存的旧脚本复现六条错误 scalar；native exit0、自有探针目录已删除。[完整 probe](../../build/validation/performance-20261012/runtime-affinity-B2-parser/parse-proof.json) 和 B2-scripts 下 `subset.patch`/全部 SHA 保留。没有重编译产品、生成器或改统计，B2 全部三轮从新目录开始，不覆盖失败尝试。

下表中位数、范围和 CPU 都来自全部三轮；完整 [24 点原值、loss/Expired/Late、线程和逐点就绪审计](../../build/validation/performance-20261012/runtime-affinity-B2/complete-summary.json) 保留在本地 ignored 目录。

| 服务可用 CPU | 点 | Mbps 中位数（范围） | EchoLoss% 范围 | 服务 CPU%core 中位数（范围） |
| --- | --- | --- | --- | --- |
| 1 | f1-w64-IPv4 | 323.528 (299.523–342.969) | 0.02077–0.02869 | 61.211 (60.752–75.942) |
| 1 | f4-w64-IPv4 | 325.320 (309.918–348.369) | 0.50246–0.55415 | 66.966 (63.023–72.338) |
| 2 | f1-w64-IPv4 | 451.516 (412.904–463.175) | 0.00518–0.00531 | 120.378 (111.178–123.260) |
| 2 | f4-w64-IPv4 | 421.499 (413.924–444.897) | 0.36585–0.39883 | 108.552 (104.376–109.594) |
| 4 | f1-w64-IPv4 | 473.777 (418.357–504.824) | 0.00000–0.00000 | 146.341 (143.982–147.301) |
| 4 | f4-w64-IPv4 | 442.552 (440.053–460.236) | 0.34899–0.37779 | 133.392 (127.144–139.502) |
| 8 | f1-w64-IPv4 | 404.581 (385.421–494.683) | 0.00000–0.00291 | 143.004 (140.256–167.742) |
| 8 | f4-w64-IPv4 | 453.501 (447.168–457.987) | 0.35077–0.36385 | 152.008 (144.659–152.180) |

`matrix.exit=0`，12 组 rig/严格 checker 与独立 gather/SCM/NIC/地址路由/Event Log/自有目录/Docker/私有夹具输入清理均通过，48 份 phase 完整保留。请求/实际 P 和掩码、Go 版本、OS 创建身份、同服务 PID、生成器 P8/`0xff`、完整唯一账目与真实时长均匹配。24/24 点预热、正式开始前 prior、阶段间隙及窗口内无记录就绪变化，LateEchoed 全 0；这仍不是连续 uptime 或长期稳态证明，全部损失和测后恢复记录保留。

Go P8/服务 affinity1 的单流中位数 323.528 Mbps 与 A 的 Go P1/affinity8 的 172.745 Mbps 是两种设置，不能都叫“单核容量”。四流中位数在服务可用 CPU1/2/4/8 时约 325/421/443/454 Mbps，未随 CPU 数线性扩展。单流 affinity8 三轮 494.683/404.581/385.421 Mbps 与 affinity4 的范围重叠，不据最高点或中位数直接改变默认设置，也不据部分线程或等待栈断言 AES、单 owner 或某种唤醒是瓶颈。1 Gbps 和多核数据面优化仍需后续独立证据。
