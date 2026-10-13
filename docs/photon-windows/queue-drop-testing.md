# Windows 有界队列丢包诊断

仅 `photon_profile` 测试构建提供三项进程累计计数。普通构建只有可内联消除的空入口，没有计数全局变量、导出接口、配置或日志。三个队列的容量、包所有权、取消及当前授权检查保持原行为。

| 计数 | 唯一计数位置 | 不包含 |
| --- | --- | --- |
| `RawIngress` | Wintun 成功接收并复制、释放 ring 包后，raw 64 包通道满而丢弃 | ring 读取错误、等待和取消 |
| `LeafIngress` | leaf 成功读取设备包后，leaf 64 包通道满而丢弃 | 设备读错误的有界交付、取消和旧 generation 清理 |
| `ESPIngress` | 共享 UDP 将选定 NAT-T 端点的 ESP 分到已满的 64 包队列 | IKE、Gossip、keepalive、无效 NAT-T framing 和非选定来源 |

ESP 计数发生在认证之前，表示密文队列的拒收次数，不能称为已经认证的业务包丢失。计数也不涵盖 Windows 网络栈、Wintun ring 自身、远端、完整性或重放检查造成的丢失；某项为零不能证明端到端没有丢包。三项涉及不同层与方向，不能直接相加当作端到端丢包总数。高负载下原子增量本身可能影响诊断吞吐，该轮吞吐不作为普通产品性能结果。

测试专用接口为 `ReadFixturePacketDrops() FixturePacketDrops`，返回 `RawIngress`、`LeafIngress`、`ESPIngress` 三个 `uint64`。三个累计值独立原子读取，不做 reset 或 enable。采集者在 CPU profile 成功启动后、发布 `.started` 前记录 baseline；收到 stop 或达到限制后、停止 CPU profile 前读取 end。输出各项 `end - baseline`，若 end 小于 baseline 则报错。快照的三个读取点可能有很小的时间差，仅用于定位队列拥塞。

诊断文件 `profile-PID.packet-drops.json` 只写 `schema_version: 1` 和 `raw_ingress_drops`、`leaf_ingress_drops`、`esp_ingress_drops` 三项增量，不写包、身份、地址或密钥。由 fixture 独占创建，CPU profile 与 JSON 都关闭后才发布完成标记。高负载诊断轮与标准吞吐轮分开保存证据；标准轮保持原有首点 CPU profile，专用 fixture marker 将唯一 profile 延后到固定的 `f4-w1024-IPv4` 点，没有新增产品参数或扩大队列。

回归测试覆盖并发累计与不重置快照、实际 ESP demux 满队列后恢复、其他 UDP 类别不误计，以及真实 leaf reader 满队列、读错误和取消的区分。原生 Windows 验证复用 Wintun 生命周期和双栈 OS UDP roundtrip；计数不会改变 ring 包释放和设备关闭顺序。源码、构建选择、编译器内联证据和测试日志保存在 `build/validation/performance-20261012/queue-drops/`；具体高负载计数由独立诊断轮记录，不能从单元测试推断产品吞吐。

## 2026-10-12 完整 daemon 大窗口诊断

Windows 测试 executable 从 `4665b4146748a6c84514be97cf93d3d7d21ff418` 的 clean git archive 构建，Go 1.26.5、`CGO_ENABLED=0`、`-buildvcs=false -tags photon_profile`，实际 SHA256 为 `12c64b76c8e7c0f6713333986b43935b11d71501c01674a426f91b5eb705863e`。Linux product/fixture 保持 `2c06877`，SHA256 分别为 `90a521aaca21a094244e7cef29df0a644a5482f3a52315550784875fc2fd1eff` / `faf4c23cdf699e609cd4757820848c14c223193e19a71b952193683e978a1760`；最终 `c1c8ea8` 工具仍为 Windows `7d2c37ababf2c47f27006e11ddbc6449f3284a93905e166289a8cb9e4b4ef478` / Linux `6c428a06cc3c66d127d8bb3e3970e38f6e9f74bd86e1ac9c8f833e0e8867e724`。来源及源归档 hash 保存在 `queue-drop-diagnostic-bundle/`，结果在 `queue-drop-diagnostic/`。

每点 1200 字节 payload、2 秒预热、8 秒发送、1 秒 deadline，保持既有六点顺序。仅 shell fixture 的 `PHOTON_WINDOWS_PACKET_DROP_DIAGNOSTIC=1` 写入 `fixture-packet-drop-profile`，内容固定为 `f4-w1024-IPv4\n`；实际 `throughput.json` 记录 `PacketDropDiagnostic=true`、`CPUProfileLabel=f4-w1024-IPv4`。这是独立诊断轮，profile 位置及计数构建与标准吞吐矩阵不同，不能把两轮 CPU/吞吐差值视为精确产品增益。

| 点 | 唯一 echo payload Mbps / 单方向 | echo 丢失 |
| --- | ---: | ---: |
| IPv4 / 1 flow / window 64 | 383.15 | 0.000626% |
| IPv6 / 1 flow / window 64 | 360.43 | 0% |
| IPv4 / 4 flows / window 64 | 422.77 | 0.386% |
| IPv6 / 4 flows / window 64 | 437.89 | 0.394% |
| IPv4 / 4 flows / window 1024 | 400.06 | 8.000% |
| IPv6 / 4 flows / window 1024 | 395.92 | 8.031% |

固定 profile 点发送 **402684** 个请求、完整唯一回包 **370470**、到期未完成 **32214**，实际 echo loss 为 **7.99982119974968%**，包含排空的测量时间为 **8.8900534 秒**。服务 CPU 为 **153.4369%**、生成器为 **88.7579%** 单逻辑核。`profile-5676.packet-drops.json` 实际为：

```json
{"schema_version":1,"raw_ingress_drops":2738,"leaf_ingress_drops":28571,"esp_ingress_drops":890}
```

本窗口最大的观察项为 leaf 成功读取设备包后向串行 owner 交付时的队列拒收，下一步可检查该处调度和 owner 工作量。这是定位证据，不把三项相加当作完整业务 loss；Raw 可能包含 OS 包，ESP 在认证前计数，计数与工具发送区间也有窄边界差异。profile baseline 在 `.started` 之前、end 在收到 stop 后最多约 50 毫秒轮询处，覆盖工具启动/排空边界；每点仅一轮短测，仍未证明长期稳定性或达到 1 Gbps。

`profile-5676.pprof` 持续 **8.95 秒**，原始样本总量 **27.99 秒**，其中 `runtime.cgocall` 累计 **19.90 秒** 包含 Windows 等待栈，不能解读为真实 CPU 百分比。保留原始 `profile-top.txt` 和显式过滤 `runtime.cgocall` 的 `profile-ignore-cum.txt`；过滤后累计 `acceptPrepared` 1.00 秒、`processOutbound` 0.74 秒、`authorize` 0.68 秒、`prepareSnapshotInto` 0.63 秒，运行时 schedule/select/lock 也有可见样本。这些累计栈重叠，不能相加，也不能将过滤比例当作操作系统 CPU 计量。

完整六点全部 `Completed=true`、`RecoveryPassed=true`、同服务 PID/创建身份，无迟到、外来、损坏、未发送序号、重复、发送错误或预算耗尽。完整 SCM rig `rig.exit=0`，独立 gather/cleanup 也退出 0；`cleanup.log` 确认自有服务、网卡、远端目录、Event Log 来源及容器已消失，私钥/数据库已删除。tagged 整包 race、默认 `make check` 均通过；`native-packet-drops/` 另保留同冻结 internal executable 的计数/Dataplane/CallerFacts/真实双栈 Wintun 原生验证、四类 app profile 测试及 PowerShell 完整/非法 JSON、stale artifact 拒绝证据，自有 native PID964 网卡和目录也已独立确认消失。
