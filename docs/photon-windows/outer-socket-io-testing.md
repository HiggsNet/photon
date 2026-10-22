# Windows 外层 UDP socket 的 I/O 对照

这是一份独立研究夹具，用于判断现有单 socket 的系统调用和发送包装是否还有底层余量。匹配产品 `[::]` 双栈 socket 的组中，真实发送包装的中位 raw UDP payload 为 **864–882 Mbps**，换算 1200 B equivalent 为 **820–824 Mbps**。首轮显式绑定 AF4 的 `10.16.252.11`，相应中位数为 **825–859 raw / 783–803 equivalent Mbps**；两组使用相同 executable 与 peer，保留全部原始结果并分别统计。AF4 结果不能直接代表产品的 socket family，组间差值也不能归因为 family 改善。

夹具不运行 Photon 的设备、授权或控制平面，不是完整产品吞吐，也不能据此证明 RIO 必要、达到 1 Gbps 的可行性，或所有接收 I/O 已不再是瓶颈。表中的 inner IPv4/IPv6 只标识 1264/1284 B 参考长度，两组 peer 都是 IPv4 endpoint；双栈 socket 补测也不表示外层 IPv6 网络吞吐。

## 冻结来源

生产源码来自本地 `git archive 84001ce795e254357b6ec4444a2761e389a18109`。归档中既有 722 个 Go 文件逐字保留；研究夹具只在归档内的 `internal/photonwindows` 增加六个测试文件，没有修改真实产品、API 或依赖。

测量器复制最终 `c1c8ea8aa1e8a5032966b947fa872d0005abe139` 的 `docs/tools/udp-perf/main.go`、平台进程统计和原测试。包名及 main 名改为归档测试包可用的名称，仅将 `runFlow` 的 socket 创建、发送、读取与结束处理接入夹具；原 pending-credit tracker、完整 nonce、序号、每字节校验、读时刻 RTT 与统计公式保留。

构建使用 Go 1.26.5、Windows amd64、`CGO_ENABLED=0`、`go test -c -buildvcs=false`。归档、原工具、注入脚本、精确补丁、源码指纹和 executable 均保存于本地 `build/validation/performance-20261012/outer-socket-io/`。

## 两条路径

整个 suite 在测量循环之外只调用一次真实 `openPacketSockets` 和 `SelectTunnel`，创建一个未连接的 UDP socket 及同端口 TCP listener。全部点保留同一实际 UDP handle、源端口、远端端口和 generation；初始化 TCP 的工作不进入逐包发送循环，最终同时关闭 socket pair。

- `direct` 每包设置一秒写期限，调用同一 `net.UDPConn.WriteToUDPAddrPort`。
- `wrapper` 调用实际 `packetSockets.WriteTunnel`，包含现有发送锁、当前 generation/peer 检查和同一秒期限。

两个 Windows 路径都保留 OS 默认 socket buffer，删除原 client 测量器的 4 MiB 覆盖。远端 echo 使用固定的同一 c1c 实现和配置；其原 buffer 设置另行记录，不能把 Windows 两路径默认值误读为两端均未调 buffer。

读取在两个路径中完全相同：直接 `ReadFromUDPAddrPort`，成功读取后立即记录单调时间，以归一化后的精确来源 endpoint 校验，foreign 包不释放请求 credit。这里绕过真实 reader 的状态快照锁和 demux，也绕过 Wintun、AES、签名/当前授权、daemon select 和各 ingress 队列。因此对照只涉及单 UDP 系统调用与发送包装，不能覆盖这些被省略的成本。

每点结束通过读期限立即唤醒并等待唯一读线程终止，再开始下一点；借用的 socket 不关闭，下一点重设读期限并生成独立随机 nonce。若唤醒失败，记录错误并强制关闭，整点不能报告完成。suite 的最终关闭及自有 PID、UDP/TCP endpoint 和临时材料由外部编排独立核验。

## 负载与单位

真实 `esp.Sender.Seal` 加 `Receiver.Open` 仅用作长度 oracle：1200 B 业务 UDP payload 在 IPv4/IPv6 内层分别形成 1228/1248 B IP 包，ESP payload 为 1264/1284 B。测量中的数据采用原工具的 nonce、序号和固定内容，是这个长度的 opaque UDP payload，没有合法 ESP 验证或真实 SA 生命周期。

primary 每个长度运行三轮，顺序为 direct→wrapper、wrapper→direct、direct→wrapper；每点一个发送 owner、一个 reader，窗口 64，预热 2 秒、发送 8 秒、每请求期限 1 秒，最多 800 万请求。可选窗口 1024 另列一轮压力点，不与 primary 中位数合并。预热与测量分别输出完整 JSON，旧证据不能覆盖。

JSON 中 raw UDP payload Mbps 按唯一回包数 × 1264/1284 B × 8 ÷ 实际统计时长计算，不含外层 IP/UDP header；每个 echo 两次穿越，但不把两个方向相加。1200 B equivalent application Mbps 只是将同一回包数换算为 1200 B，并不表示夹具实际传输了授权的 Photon 业务包。

原 `Sent = OnTime + Expired` 和 `Echoed = OnTime + LateEchoed` 判据保留。每点拒绝损坏、foreign、未发送序号、重复、发送错误或预算耗尽，并核对共享 endpoint/generation 不变；真实 Expired/Late 和丢失比例单独保留，不为获得零丢失修改统计。

## 已完成验证

原 tracker、payload/输出及两个 loopback 回归，加真实 ESP 长度和借用 socket 停止/复用回归，ordinary **4.009 秒**、race **5.042 秒**均通过。新增复用回归用同一 handle 连续运行两个一秒发送点，确认旧 reader 已结束、下一点期限重置与随机 nonce 独立；关闭后原 UDP 拒绝发送，UDP/TCP 原端口可以重新绑定。

Windows crossbuild 通过，研究 executable SHA256 为 `898562e3f1da10c752af68a814fdc8bce505025172470e005cc94857f55e1d65`，注入补丁 SHA256 为 `3535423e1207ea510180b220e36734e3c1d1e86a5682dfe4b2b9f49370857d1f`。同一 executable 的 Windows 原生 11 个顶层场景全部 PASS、无 skip，包括原进程统计、tracker/故障回包与新增 shared-FD 回归；实际 PID 与自有目录已独立确认清理，材料位于 `native-outer-socket-io/`。

## 产品 socket family 核验

完整产品在 `after-owned-outbound-standard/windows.db.log:1` 的 `gossip_started` 记录实际 endpoint 为 `[::]:53758`；`after-owned-outbound-diagnostic/windows.db.log:1` 为 `[::]:63037`。两份日志位于本地 `build/validation/performance-20261012/`，对应配置虽为 `0.0.0.0`，实际 Go UDP listener 使用 AF6 双栈 socket。首轮夹具显式绑定 `10.16.252.11` 使用 AF4，存在这个形状差异，不能把该组结果泛化为产品实际 socket 的容量。

新增 `Local=::` 的独立三轮 primary 使用相同冻结 executable、peer 和统计规则。每组内部共享真实 FD；两组之间的 source port/五元组不同，因此分别报告，不合并中位数，也不据其差值断言 socket family 的因果影响。原 AF4 全矩阵及低点保持不变。

## Windows 实测：AF4 显式绑定

2026-10-12 的独占窗口中，Windows VM 报告 8 个 logical CPU。整轮始终是 PID6040、UDP handle412、`10.16.252.11:49715` 到 `10.16.255.8:19341`、generation2；同端口 TCP listener 的 PID/endpoint 也在运行期间独立记录。两种内层参考长度均经过这同一外层 IPv4 路径，不是外层 IPv6 测量。

Linux peer 为 Docker `photon-ike-init-smoke:ubuntu24`，image ID `sha256:a0774c794599aa4ada5b618d568126d714eb074b5f06c6c82550b9f6735b8b9d`，固定 c1c echo executable SHA256 为 `6c428a06cc3c66d127d8bb3e3970e38f6e9f74bd86e1ac9c8f833e0e8867e724`。容器将宿主 `10.16.255.8:19341/udp` 发布到同端口，echo 仅一个 socket，保留原 4 MiB buffer 设置；没有 strongSwan、XFRM 或 Photon Linux daemon。

下面列出窗口 64 的全部三轮 raw UDP payload Mbps，以及两种单位的中位数；所有速率均为单方向唯一 echo 回包。Echo loss 与 deadline miss 相同，本轮没有 late 回包。

| 内层参考 / opaque UDP 大小 | 写路径 | raw R1 / R2 / R3（Mbps） | raw 中位（Mbps） | 1200 B equivalent 中位（Mbps） | loss R1 / R2 / R3（%） |
| --- | --- | --- | --- | --- | --- |
| IPv4 / 1264 B | direct | 819.022 / 840.421 / 807.650 | 819.022 | 777.553 | 0.001697 / 0.001654 / 0 |
| IPv4 / 1264 B | wrapper | 807.865 / 856.587 / 825.176 | 825.176 | 783.395 | 0 / 0 / 0 |
| IPv6 / 1284 B | direct | 815.321 / 850.773 / 736.981 | 815.321 | 761.982 | 0 / 0 / 0 |
| IPv6 / 1284 B | wrapper | 873.719 / 858.794 / 804.590 | 858.794 | 802.611 | 0.001616 / 0.004105 / 0 |

R3 的 1284 B direct 低点 **736.981 raw / 688.768 equivalent Mbps** 完整保留，没有补跑挑选替代值。primary 生成器 CPU 为 **82.02–90.42% 单核**，不是 VM 总 CPU。两个写路径的三轮数据没有显示包装导致明显吞吐下降；wrapper 的较高中位数也不能解释为包装加速，样本波动与被省略的 reader/产品成本仍存在。

窗口 1024 的一次压力轮单独列出，不混入上述中位数：

| 内层参考 / opaque UDP 大小 | 写路径 | raw Mbps | 1200 B equivalent Mbps | loss / deadline miss（%） | Expired |
| --- | --- | --- | --- | --- | --- |
| IPv4 / 1264 B | wrapper | 872.876 | 828.680 | 0.004916 | 34 |
| IPv4 / 1264 B | direct | 842.519 | 799.860 | 0.013631 | 91 |
| IPv6 / 1284 B | wrapper | 845.243 | 789.946 | 0.086621 | 582 |
| IPv6 / 1284 B | direct | 813.983 | 760.731 | 0.081825 | 520 |

包含预热在内的 32 个 phase 中，client 共发送 **13,100,428** 包，Linux peer 的 received/echoed 都恰为 **13,100,428**，peer 长度异常/send error 均为 0。client 收到 **13,098,381** 个唯一回包、Expired **2047**、Late 0。按聚合计数，peer 发出的 echo 比 client 观测多 2047；peer 没有逐序号去重账本，不能严格排除转发丢失与重复相互抵消，也不能进一步归因到具体 OS/网络层。这份夹具账目不能与 Photon ingress 计数或产品业务 loss 相加。

suite 日志报告 **PASS，162.28 秒**，全部 16 个测量点与 16 个预热点 `Completed=true`。只读 validator 核验 32 JSON 的来源、完整 matrix、同 handle/端口/generation、交替顺序、完整序号/RTT 账目、无异常字段及两种单位公式通过。原始材料位于 `outer-socket-io-measurement/`：`downloaded/results/`、`validation.json`、`peer-accounting-and-medians.json`、源/构建/echo 指纹和编排脚本全部保留。

结束后独立确认原 PID6040、UDP/TCP49715、自有 Windows 目录和 Linux 容器都已清理。外层 SSH/coordinator 退出 0，Go suite stdout 有最终 PASS，32 JSON 全部校验通过；PowerShell 子进程 `ExitCode` 读取为空，`post-suite-cleanup.json` 的 `TestExitCode=null` 已原样保留，不能把它描述为捕获到了 native 子进程退出码 0。后续收集器保留进程 handle 并拒绝空 ExitCode，独立小探针实际捕获预设的 7 和 0；补丁及清理证据位于 `exit-code-capture-fix.patch`、`exit-code-probe/`，没有重采矩阵或改写本轮缺口。

## Windows 实测：匹配产品 AF6 双栈绑定

独立补测设置 `Local=::`，外部 OS endpoint 观测确认实际 UDP 和 TCP 都是 PID6280 的 `[::]:63710`；全部 24 个 phase 保持 UDP handle440、该 local endpoint、IPv4 peer `10.16.255.8:19341` 和 generation2。冻结 executable、c1c echo、socket buffer、负载、统计公式和交替顺序均不变；没有修改 Go 夹具、运行 profile 或追加窗口 1024 压力点。补测在 2026-10-12 至 13 日的独占窗口执行，每点仍为预热 2 秒、发送 8 秒、窗口 64。

这组匹配的是产品 AF6 双栈 listener 的 family。远端仍是 IPv4，接收校验归一化 IPv4-mapped endpoint；这里也没有测量外层 IPv6 网络。该组使用新的 source port，与前组的五元组不同，结果独立列出。

| 内层参考 / opaque UDP 大小 | 写路径 | raw R1 / R2 / R3（Mbps） | raw 中位（Mbps） | 1200 B equivalent 中位（Mbps） | loss R1 / R2 / R3（%） |
| --- | --- | --- | --- | --- | --- |
| IPv4 / 1264 B | direct | 860.991 / 847.317 / 816.284 | 847.317 | 804.415 | 0.000434 / 0.003431 / 0.001028 |
| IPv4 / 1264 B | wrapper | 855.265 / 863.924 / 864.465 | 863.924 | 820.181 | 0 / 0 / 0.001608 |
| IPv6 / 1284 B | direct | 884.282 / 862.603 / 830.737 | 862.603 | 806.171 | 0.001162 / 0 / 0.001025 |
| IPv6 / 1284 B | wrapper | 881.635 / 860.918 / 886.152 | 881.635 | 823.958 | 0.000874 / 0 / 0 |

完整三轮 loss / deadline miss 为 **0–0.003431%**，Late 均为 0；生成器 CPU 为 **80.34–90.22% 单核**。同组 direct 与 wrapper 没有显示发送包装带来明显吞吐下降。wrapper 的较高中位数和 AF4/AF6 组间差值均不能证明加速或 socket family 的因果效果；样本波动、不同五元组及被省略的产品成本仍限制解释。

包含预热在内的 24 个 phase 共 client Sent **10,201,335**、Echoed **10,201,223**、Expired **112**、Late 0；Linux peer 的 received/echoed 都为 **10,201,335**，长度异常/send error 为 0。client 损坏、foreign、未发送序号、重复、发送错误及预算耗尽全部为 0。聚合 echo/client 观测差为 112；peer 没有逐序号校验/去重账本，仍不能严格推导精确 forward/return loss 或归因到 OS 层。

suite 报告 **PASS，121.90 秒**，12 个预热点及 12 个测量点 `Completed=true`；只读 validator 对全部 24 JSON 的来源、matrix、同 FD/endpoint/generation、交替顺序、计数与两种单位公式校验通过。修正后的收集器实际捕获子进程 **ExitCode=0**，外层 coordinator/gather/cleanup 也退出 0。独立确认原 PID6280、UDP/TCP63710、自有 Windows 目录、Linux 容器及宿主发布端口 19341 全部消失，事后源码/补丁/归档指纹核验通过。

完整补测材料位于 `build/validation/performance-20261012/outer-socket-io-dualstack-measurement/`：`downloaded/results/` 保留全部 24 JSON；`validation.json`、`peer-accounting-and-medians.json`、`family-matching-manifest.json` 记录统计及产品日志来源；`downloaded/actual-open-endpoints.json` 与 `downloaded/post-suite-cleanup.json`、独立清理日志分别记录实际 endpoint、捕获退出码和资源回收。两组结果仅确认该单 FD、默认 Windows buffer、opaque UDP 负载的系统调用及发送包装容量；真实 reader 锁/demux、Wintun、owner 调度和每包当前授权仍需另行定位。

后续最窄测量可对照同长度 opaque Wintun echo 的单消费者与现有 raw64→leaf reader→leaf64 的第二次 goroutine 交接，隔离交接成本，并保留实际取消/关闭边界。这是研究方向，没有实施产品优化或扩大队列，也不能把 I/O 对照与完整 Photon 的吞吐差额全部归因于 channel。
