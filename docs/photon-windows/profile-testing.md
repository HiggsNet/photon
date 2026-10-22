# Windows SCM CPU profile 与优化对照

## 测试入口

沿用 [性能基线](baseline-testing.md) 或 [多流吞吐](throughput-testing.md) 的完整 daemon 命令，加 `PHOTON_WINDOWS_CPU_PROFILE=1`；必须同时开启其中一种独立性能模式，不能混入重协商或断网模式。

该选项仅为本次 Windows executable 增加 `photon_profile` 构建标签。`app/photon-windows/profile_fixture_windows.go` 使用 `windows && photon_profile` 条件，默认构建的 GoFiles 不包含它。没有产品 CLI/config 字段、公开 HTTP/pprof listener 或 IPC method。

带标签的 `run --service` 进程在 executable 所在的本次隔离目录检查自身 PID 对应的 `profile-<PID>.request`；其他命令不启用。检查异步进行，不阻塞 SCM，等待请求最多 5 分钟，每进程仅采一次。请求限定为当前进程启动后创建的 6 字节 `start\n`；profile 和确认文件使用 exclusive create，拒绝覆盖旧文件。输出路径固定，调用者不能指定任意路径或采样时长。

PowerShell helper 复用现有 SCM PID/创建时刻所有权检查，在首个 IPv4、窗口 8 的 15 秒负载前请求开始，收到 `.started` 后执行原负载。负载结束即写 `.stop`，必须等待 `StopCPUProfile` 和文件关闭完成后产生 `.done`。正常 start/stop 握手各有 5 秒期限；Go 侧独立设置 30 秒采样硬上限，触发上限的结果不冒充正常完成。

原生测试验证 hard limit、主动停止、确认之后 gzip 完整可读以及拒绝覆盖既有 profile；默认编译排除入口、带标签 Windows cross-build/vet 均单独核验。测试构建不用于发行。

产物包含原始 `.pprof`、`.done`、`baseline.json`、源码 commit/status 和 binary SHA256。CPU profile 是函数/栈/采样数据，不采集 heap、请求内容、私钥或 Bolt 文件；其中仍含源码路径和 executable 路径，仅保存在本地验收目录，不自动上传或发布。

## 匿名队列丢包诊断

新增 `photon_profile` 构建使用测试专属 `ReadFixturePacketDrops()` 读取进程累计的三个独立原子计数，不做 reset 或 enable。普通构建不提供该类型、接口或计数全局变量，三个私有 hook 可内联为空；不增加产品 CLI/config、IPC 或监听端口。具体位置及不包含的丢包见 [队列诊断边界](queue-drop-testing.md)。

CPU profile 启动成功后、发布 `.started` 前读取 baseline；收到 stop 或到达 30 秒硬限制后、停止 CPU profile 前读取 end。`profile-PID.packet-drops.json` 独占创建为 0600，输出 `schema_version: 1` 及三个 `uint64` 增量 `raw_ingress_drops`、`leaf_ingress_drops`、`esp_ingress_drops`；不包含包内容、身份或地址。任何计数逆向都令采集失败，不发布 `.done`；正常结束必须将 pprof 和 JSON 都关闭后才确认完成。这个区间包含启动确认、停止请求至最多约 50 毫秒轮询的窄边界，并非精确等于工具发送的 8 秒。

仅隔离 shell fixture 的 `PHOTON_WINDOWS_PACKET_DROP_DIAGNOSTIC=1` 开启诊断轮，要求同时为 `PHOTON_WINDOWS_THROUGHPUT=1` 和 `PHOTON_WINDOWS_CPU_PROFILE=1`。fixture 写入固定 marker `fixture-packet-drop-profile`，内容只能为 `f4-w1024-IPv4\n`；它将同一六点顺序中的唯一 CPU profile 延后到这个大窗口点。诊断轮 `throughput.json` 明确记录 `PacketDropDiagnostic=true` 和 `CPUProfileLabel=f4-w1024-IPv4`；缺 marker 的标准吞吐轮继续仅在首个 `f1-w64-IPv4` 点采集，历史 baseline 选择不变。marker 随自有 fixture 目录清理，shell collector 仅收固定 `profile-*.packet-drops.json` 公共结果。

原生 Windows 测试验证 gzip/JSON 在完成确认后完整可读、pprof 和 JSON 拒绝覆盖、单字段计数逆向失败。PowerShell fixture 另检查 helper 语法、完整有效 schema，以及负数、小数、错误版本、缺字段、额外字段和 stale JSON 的拒绝；它验证非负整数表示，实际 Go producer 的字段类型固定为 `uint64`。带计数的同一 native executable 还验证并发累计、真实 ESP/leaf 队列满及取消/错误不误计，实际 Wintun 两代生命周期和 IPv4/IPv6 OS UDP roundtrip 全部通过，测试目录及自有网卡已独立确认消失。证据在 `build/validation/performance-20261012/native-packet-drops/`，ordinary/tagged 构建与内联证据见同级 `queue-drops/`。

这三项不是完整端到端丢包账本：Raw 包含 OS 设备包，ESP 计数在认证前发生，其他网络栈、ring、远端和完整性/重放拒绝不在其中。不能相加后当作已认证业务 loss，也不能用零值证明无端到端损失。诊断轮单独保存源码、构建标签、实际 binary SHA 和数据，不把开启计数及改变 profile 位置的 CPU 差值当作旧标准矩阵的精确增益。

## 业务包分段采样

2026-10-13 新增测试专属的 [业务包分段计时](packet-timing-testing.md)：固定 1/256 采样，按两个方向及业务/控制/未知类别记录队列、前置检查、ESP、当前交付门禁和同步 I/O。同一个 tagged binary 支持 off/on 独立对照，并与首单流或四流小窗口的固定 CPU profile 对齐。经过时间包含调度与等待，不代替内核调用栈或线程 CPU 计数；普通发行构建仍使用空探针。

## 优化前真实证据

2026-10-09，源码 `83d697e0f064` 加测试专用 profile 工具，Windows 11 VM 对固定 BIRD 2.19.1 / StrongSwan 6.0.7。构建后立即固定二进制，再允许其他 agent 编辑产品代码，运行期间不重新构建。before executable SHA256：

```text
87b8f8a664c526b1eb20ee9e8e57a6c48170fb29be33c1ea5351186b83117f36
```

原始证据与文本报告位于 `build/validation/b6-profile-20261009/before/`。对应隔离运行目录为 `/tmp/photon-windows-full-daemon.Wc3vXi`。

采样覆盖首个 IPv4 窗口 8 负载，持续 15.35 秒；该轮应用 echo goodput 0.194 Mbps，1 秒内无丢失，Windows 服务 CPU 为 100.30% 单逻辑核。主要累计样本：

| 调用路径 | 累计秒数 |
| --- | --- |
| `crypto/ed25519.Verify` | 13.03 |
| `currentAuthorizedRouteSet` | 9.41 |
| `authorizedGatewayRoutes` | 6.60 |
| `gatewayBabelPipeline.authorize` | 6.30 |
| `planGateway` | 4.97 |

这些累计路径互有包含，不能相加。它们支持优先检查逐包重复执行的签名验证、当前授权投影和网关规划；不支持删除当前时间、revision、撤销或 packet verdict 检查。

### Windows 样本解释限制

原始 profile 总计 38.76 秒样本（252.49%），其中 `runtime.cgocall` 的 23.88 秒包含 `WaitForMultipleObjects` 和控制管道 `WaitForSingleObject` 等等待栈；同一时间进程累计 CPU 观测约为一个逻辑核。不能把原始 `cgocall` 61.61% 直接解读成真实 CPU 热点，也不能把该总量与进程 CPU 百分比混为一谈。

报告同时保留未经筛选的 `cpu-top.txt` / `cpu-cumulative.txt`，以及显式使用 `-ignore=runtime.cgocall` 的 `cpu-go-cumulative.txt`。筛选报告只辅助看 Go 栈，不是新的整体 CPU 测量，百分比分母仍由 pprof 保留；其 `Daemon.Run` 累计 14.26 秒，Ed25519 Verify 累计 13.03 秒，与进程 CPU 单核饱和观察一致。

复现分析使用嵌入 profile 的符号，不读取已被后续优化修改的源码逐行归因：

```sh
go tool pprof -top -nodecount=30 <profile.pprof>
go tool pprof -top -cum -nodecount=40 <profile.pprof>
go tool pprof -top -cum -nodecount=40 -ignore=runtime.cgocall <profile.pprof>
```

同负载 after 结果在产品优化独立提交且安全回归通过后补测；本切片不修改产品算法，也不把开启 profiler 的吞吐与无 profiler 的历史最好值直接比较。

优化前整轮 `baseline.json` 为 `Completed=true`，八个负载点均 `RecoveryPassed=true`；随后完整 SCM 正常重启、崩溃恢复、网络地址增删及外部 alias 冲突恢复均通过，入口 exit 0。原有清理流程移除了本次容器、服务、远端 fixture 目录及私密材料。首个测量点之外的基线仍未启用 profiler，可在同一组结果中观察采样开销，但不能据单轮差异精确量化该开销。

## 第一轮优化后的同配置实测

产品 revision `0ca5d703d66925fe6ed5c13ebe9d9085dd7bfb9d`，包含 event facts 复用及将 readiness 重算移出逐包路径。2026-10-09 固定该源码后编译，同一 VM、BIRD/StrongSwan、地址族、payload、窗口、预热、时长和首轮 profile 位置均保持一致。after executable SHA256：

```text
3e86c8febbe52ff1cb0dbfe116c94578ae023844993f173efabc288277215b5a
```

证据为 `build/validation/b6-profile-20261009/after/`，对应临时运行 `/tmp/photon-windows-full-daemon.asn9Iy`。下表 before 使用本页带相同 profile 入口的那轮结果，未混用历史无 profiler 的最好值。

| 配置 | before 有效载荷 Mbps | after 有效载荷 Mbps | 期限内回包与恢复 |
| --- | --- | --- | --- |
| 窗口 8 / IPv4，三轮中位数 | 0.206 | 1.497 | 两组均无丢失/超期，提升约 7.26 倍 |
| 窗口 8 / IPv6，三轮中位数 | 0.200 | 1.486 | 两组均无丢失/超期，提升约 7.42 倍 |
| 窗口 64 / IPv4，单轮 | 0.100（全部迟到） | 1.585 | before 期限 goodput 0；after 无丢失/超期 |
| 窗口 64 / IPv6，单轮 | 0.104（全部迟到） | 1.605 | before 期限 goodput 0；after 无丢失/超期 |

after 的八个负载点均 `RecoveryPassed=true`，`Completed=true`。服务 CPU 仍为约 99–101% 单逻辑核；生成器最高 1.56%。这是固定在途窗口的闭环压力配置，处理加快后实际发送请求数增加，不能将其表述为固定请求速率下的 CPU 百分比对照。首个采样点吞吐为 0.194→1.477 Mbps，服务 CPU 100.30→101.20%，按每单位成功应用载荷计算的 CPU 时间明显下降。

before/after 样本 private bytes 峰值为 57.13/57.60 MiB，working set 为 65.04/65.19 MiB；这一小幅变化不足以作内存改善或泄漏结论。after idle 前后服务 CPU 为 7.48%/6.55%。

### 剩余热点

after 同一采样点持续 15.15 秒，原始样本总计 29.35 秒；仍保留上述 Windows 等待栈限制。使用同样的 Go 栈筛选后，`Daemon.Run` 累计 14.13 秒，Ed25519 Verify 12.79 秒，`gatewayBabelPipeline.prepare` 10.43 秒、`currentAuthorizedRouteSet` 5.77 秒、`localTransportAuthorization` 3.04 秒。累计路径互相包含，不相加。

这表明第一轮已减少每包重复工作、提高吞吐，但 event 准备阶段的签名验证仍是下一步有依据的检查方向。本结果只归属于 `0ca5d70`，后续签名结果缓存或其他改动必须另行安全回归、重新固定二进制并追加独立对照，不能覆盖本轮证据。

### 验证与资源边界

after 完整 SCM 基线及后续正常重启、强制结束后恢复、真实地址变更通知、外部 alias 冲突恢复以 exit 0 完成。随后冻结同 revision 的六包 Windows 原生 executable，结束性能采样后才执行；`photonwindows`（含新增 packet authorization/撤销/到期边界）、Windows CLI、IKE、ESP、Babel、SADR 全部通过。原生 bundle source/status、二进制 SHA256 与完整日志另存同一 after 目录，产品继续编辑不改变这些已固定产物。

最后额外只读复核本轮服务、adapter、Event Log source、远端 fixture 目录及 Docker 容器均已移除，本地 fixture 私密材料不存在；独立原生测试目录也已清理。结果保留于 `after/cleanup.log`，VM 随后释放。

## 第二轮优化：有界签名验证结果复用

产品改动截止 `11b74bed4dcb5e75ed555911ba33c6f9479ed20d`；完整 rig 构建时 HEAD 为仅追加文档的 `32abd07a44f1510fc1da2832581b95d2dfc65106`，真实 source/status 均已保留。七包原生测试在此之前从 `11b74be` 固定，产品源码一致。Windows executable SHA256：

```text
b479f467aa82c4a47ddd787e1026b282c3c5767c600cea14558067c6e09794a0
```

仍使用相同 VM、BIRD 2.19.1、StrongSwan 6.0.7、1200 字节载荷、窗口、预热、时长和首个测量点的 profile；没有为得到更高数字调整工具参数。证据保留在 `build/validation/b6-profile-20261009/after-signature-memo/`，对应隔离目录 `/tmp/photon-windows-full-daemon.3yiZUK`。

| 配置 | 初始 before Mbps | event facts Mbps | 签名结果复用 Mbps |
| --- | --- | --- | --- |
| 窗口 8 / IPv4，三轮中位数 | 0.206 | 1.497 | 17.141 |
| 窗口 8 / IPv6，三轮中位数 | 0.200 | 1.486 | 17.424 |
| 窗口 64 / IPv4，单轮 | 0.100（全部迟到） | 1.585 | 17.701 |
| 窗口 64 / IPv6，单轮 | 0.104（全部迟到） | 1.605 | 17.488 |

第三组八个负载点全部 `Sent = Echoed`，`Expired`、`LateEchoed`、`Unmatched`、`Duplicates` 和 `SendBackpressure` 均为 0；各轮后的同进程恢复全部通过，最终 `Completed=true`。这些结论仅来自本 VM、当前完整 rig 的短时观察，不是所有部署环境的吞吐保证或长时间无损证明。

负载阶段服务 CPU 为 **124.56–133.19% 单逻辑核**，生成器为 **2.19–3.85%**。CPU 百分比没有下降：闭环发送实际完成了更多数据，且工作可分布到多个线程。按同一个首轮 profile 测量点及既定单方向应用 goodput 口径计算，服务 CPU 秒/Mbit 依次为 **5.173 → 0.685 → 0.08365**；这比混用 CPU 百分比更能说明每单位完成载荷的成本。三组计算值另存 `build/validation/b6-profile-20261009/comparison.json`。

本轮 private bytes 峰值 **58.23 MiB**、working set 峰值 **65.74 MiB**；idle 前后服务 CPU 为 6.86%/7.49%。短时内存样本和有界缓存单测仍不能替代 72h soak 或无泄漏验收。

### 最终 profile 与工具边界

首个 profile 点完成 15.923 Mbps，服务 CPU 133.19%；profile 持续 15.10 秒。Ed25519 Verify 累计样本由 **13.03 → 12.79 → 0.59 秒**，已不再主导 Go 计算样本。剩余累计路径包括 `gatewayBabelPipeline.prepare` 8.22 秒、`currentAuthorizedRouteSetWithVerifier` 4.64 秒、`json.Unmarshal` 3.92 秒、`planGatewaySelection` 3.73 秒、`mallocgc` 2.59 秒及 `gcDrain` 2.44 秒。它们重叠，不能相加；下一步可研究准备、解析和分配，但本切片没有继续修改算法。

本轮原始 profile 仍有 Windows 等待栈：47.30 秒总样本中 `runtime.cgocall` 累计 28.83 秒。继续保留原始和显式筛选报告，不将 profile 百分比误报为实际 CPU 占用。为保留低于默认截断阈值的 Ed25519 条目，另生成 `cpu-all-cumulative.txt`，命令增加 `-nodefraction=0 -nodecount=0`。

工具审查发现 C# 单线程逐包 Send/Poll/Receive、完整载荷检查和小数组分配可能限制更高吞吐；其固定 8192 项去重环也存在观测边界：回包序号落后最新已发送序号至少 8192 时记 `Unmatched`，即使当时尚在 pending。超过 8192 pps（1200 字节约 78.64 Mbps）后，接近 1 秒才返回的合法回包可能触及此边界，不能把这类计数都归因于网络丢包。

本轮最高约 **1844 pps**，生成器未接近满核，且全部 `Unmatched=0`，未观察到这些工具边界影响结果。保留工具和参数以维持本轮对照；更高速测试需要另行验证生成器与追踪范围，不能把当前工具测得的最大值称为产品容量上限。

第三轮完整 SCM rig exit 0，包含所有负载点后的同进程恢复及后续正常/异常重启、地址变化和冲突恢复。冻结的 **七包 Windows 原生回归全部通过**：原六包加 `pkg/crypto`，覆盖热签名命中后的撤销、到期、未来密钥、签名门限和字段变化仍须拒绝等边界；`native-tests.log`、实际 source/status、七个 executable SHA256 保存于本轮目录。

最后额外只读核查本轮服务、adapter、Event Log source、fixture 目录和容器均不存在，本地测试私密材料已删除；独立七包原生测试目录也已删除。公开 `cleanup.log` 保留核验结果，VM 随后释放。此轮不包含 72h soak 或正式发布。
