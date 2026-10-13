# Windows SCM CPU profile 与优化对照

## 测试入口

沿用 [性能基线](baseline-testing.md) 的完整 daemon 命令，加 `PHOTON_WINDOWS_CPU_PROFILE=1`；必须同时开启 `PHOTON_WINDOWS_BASELINE=1`，不能混入重协商或断网模式。

该选项仅为本次 Windows executable 增加 `photon_profile` 构建标签。`app/photon-windows/profile_fixture_windows.go` 使用 `windows && photon_profile` 条件，默认构建的 GoFiles 不包含它。没有产品 CLI/config 字段、公开 HTTP/pprof listener 或 IPC method。

带标签的 `run --service` 进程在 executable 所在的本次隔离目录检查自身 PID 对应的 `profile-<PID>.request`；其他命令不启用。检查异步进行，不阻塞 SCM，等待请求最多 5 分钟，每进程仅采一次。请求限定为当前进程启动后创建的 6 字节 `start\n`；profile 和确认文件使用 exclusive create，拒绝覆盖旧文件。输出路径固定，调用者不能指定任意路径或采样时长。

PowerShell helper 复用现有 SCM PID/创建时刻所有权检查，在首个 IPv4、窗口 8 的 15 秒负载前请求开始，收到 `.started` 后执行原负载。负载结束即写 `.stop`，必须等待 `StopCPUProfile` 和文件关闭完成后产生 `.done`。正常 start/stop 握手各有 5 秒期限；Go 侧独立设置 30 秒采样硬上限，触发上限的结果不冒充正常完成。

原生测试验证 hard limit、主动停止、确认之后 gzip 完整可读以及拒绝覆盖既有 profile；默认编译排除入口、带标签 Windows cross-build/vet 均单独核验。测试构建不用于发行。

产物包含原始 `.pprof`、`.done`、`baseline.json`、源码 commit/status 和 binary SHA256。CPU profile 是函数/栈/采样数据，不采集 heap、请求内容、私钥或 Bolt 文件；其中仍含源码路径和 executable 路径，仅保存在本地验收目录，不自动上传或发布。

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
