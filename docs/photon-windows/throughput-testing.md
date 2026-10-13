# Windows 多流 UDP 吞吐测量

`PHOTON_WINDOWS_THROUGHPUT=1` 在既有完整 daemon/SCM 隔离 rig 中运行独立的 Go 负载工具。它保留历史 `PHOTON_WINDOWS_BASELINE=1` 对照，两个模式互斥。1200 字节 payload、窗口和生成器均有明确来源，不能把不同工具或窗口的结果称为同配置提升。

工具位于 `docs/tools/udp-perf/`，可原生交叉编译 Windows/Linux；没有产品 CLI、服务调参或公开 profile listener。每流一对发送/接收 goroutine 和独立 UDP socket，目的端口为 `19100 + flow`。Linux 业务 echo 在容器内双栈地址上各监听四个独立 socket，原来的 `19096` 业务恢复检查继续运行。

## 复现与证据

```sh
PHOTON_WINDOWS_THROUGHPUT=1 \
PHOTON_WINDOWS_SSH=photon-test@10.16.252.11 \
PHOTON_LINUX_IP=10.16.255.8 \
PHOTON_BIRD_NIX_PACKAGE=/nix/store/<bird-package> \
PHOTON_IKE_AUTH_NIX_PACKAGE=/nix/store/<strongswan-package> \
bash docs/scripts/windows-full-daemon-smoke.sh
```

每个地址族分别测 `1 flow / 每流窗口 64`、`4 flows / 每流窗口 64`、`4 flows / 每流窗口 1024`；各点预热 2 秒、发送 15 秒，每包 deadline 为 1 秒。所有流经过同一 Windows Photon 服务、Wintun 和当前 CHILD SA。窗口 1024 是容量探索点，丢包和积压需要一并报告。每点结束后验证同一服务创建时间/PID、双栈业务 echo 和 IKE/CHILD readiness，再继续后续完整 SCM 恢复验收。

`PHOTON_WINDOWS_THROUGHPUT_SECONDS=8` 可用于统一短测，范围 1..30 秒，默认仍为 15。参数经过 shell、PowerShell 和原生工具分别验证，结果记录实际 `SendSeconds`。需要同配置源码对照时所有组保持工具 SHA、窗口、deadline、预热、发送秒数和 profile 位置一致，短测不能替代长时间容量/稳定性验收。

结果为 `throughput.json` 和每点 `throughput-*.json`，包含工具、服务 executable SHA256，机器、时间、参数、逐流统计，服务 CPU/private bytes/working set 约 250 毫秒采样以及恢复结果。CPU 单位为一个逻辑核的百分比，可以超过 100%。工具生成器 CPU 单独记录；Linux kernel/gateway 的 CPU 未计入服务数字。失败时保存已完成点，只有顶层 `Completed=true` 才代表完整测量完成。`PHOTON_WINDOWS_CPU_PROFILE=1` 可在首个 `1 flow / IPv4` 点采样；其测试构建标签、采集边界和 Windows 等待栈限制沿用 [profile 说明](profile-testing.md)。

`PHOTON_WINDOWS_PERFORMANCE_BUNDLE=/absolute/path` 仅可用于显式 baseline/throughput 模式，要求事先冻结的普通文件：`photon`、`b4.test`、`photon-windows.exe`、`udp-perf`、`udp-perf.exe`、`performance-sources.json`。rig 复制后记录实际二进制 SHA256；调用者的 manifest 必须分别记录 Windows、Linux/fixture、工具的源码 commit、构建标志和 SHA256，不能用 rig 当前的 `source-commit.txt` 冒充冻结产品源码。两轮复用同一 Linux/fixture/tool，替换 Windows executable 及对应 manifest，避免其他 agent 编辑或构建时改变采样程序。执行期间不并行运行 host/VM 重 benchmark、原生测试或故障注入。

## 统计语义

- 每轮、每流使用随机 128-bit nonce、独立单调序号、流号和固定 payload 模式，校验所有非序号字节。外来 nonce、损坏、未发送序号、重复均单列，不增加 goodput。
- 每流窗口限定尚未完成请求的总数，收到唯一回包或到期就立即释放一个 credit，新序号可继续使用它。一个旧序号丢包只占一个 credit，不强制新序号等待同一 `seq % window` 槽位。发送和交付分别运行，避免旧生成器逐包 Send/Poll/Receive 限制；不重发原包。
- 全轮去重 bitset 和发送时间戳默认限制总计 800 万个序号，可明确设置最多 1600 万；默认时间戳数组约 64 MB、bitset 约 1 MB，另有固定回包 channel，内存有明确上界。递增 expiry cursor 按发送顺序处理到期，每个序号只越过一次，无逐包 map 或额外窗口槽位表。最大窗口为每流 16384、最多 16 流、发送最长 30 秒、deadline 最长 3 秒，排空最长为发送结束后 deadline 加 100 毫秒。超出包预算标记 `PacketLimitReached` 并令 `Completed=false`。旧唯一回包仍可用完整序号和发送时间匹配，不因落后 8192 个序号而丢失追踪。
- `Sent = OnTime + Expired`，`Echoed = OnTime + LateEchoed`。`Expired` 包含超时及最后未完成请求；迟到回包不会抹去 deadline miss。接收完的唯一完整 echo 分子除以包含排空的实际测量时间，得到一个方向的应用 payload Mbps。每个 echo 经两个方向各一次；不能以乘 2 后的合计速率宣称单方向达到 1 Gbps。RTT buckets 依赖来宾 monotonic clock 精度，只用于本次测量观察。
- deadline 使用接收 goroutine 实际读取回包的 monotonic 时间。发送 goroutine 因调度晚消费通知，即使请求已被 expiry cursor 先判为到期，仍按该包全轮保存的发送/读取时间判定；真实迟到不会因后续收到回包而消除期限失败。每流 `Expired` 在运行中是暂定计数，最终统计校正已读及时但通知延后的包。
- 工具限制使内存和等待时间有上界，不将产品队列或权限缓存放宽。临时端口、服务、网卡、容器及私钥/数据库沿既有 rig 的所有失败/成功路径清理。

Go 单元/race 测试覆盖重排、deadline 临界点、窗口复用、超过旧 8192 序号范围的合法迟到、重复、完整 payload 验证以及结果文件拒绝覆盖；真实 loopback 再注入一次丢包、重复、110 毫秒迟到验证统计。Windows 原生测试额外核验 CPU、进程创建身份与 private/working-set 采样。

## 2026-10-12 直连 control

Windows VM 为 8 个逻辑 CPU、约 8 GiB 内存，VirtIO Ethernet 报告 10 Gbps。Linux 源地址 `10.16.255.8` 与 VM `10.16.252.11` 同 LAN。control 仅经临时 Docker 发布的测试端口，绕过 Photon/Wintun/ESP；不能将其吞吐称为产品性能。

TCP 粗上界采用 256 KiB block，发送 5 秒；Windows 发送与 Linux 接收均为 5,182,849,024 字节，对应 **8292 / 8288 Mbps**。该控制只验证字节总量与链路容量，不逐包检查内容。第一次宿主直接监听 `19106` 未经 Docker 发布，被现有防火墙阻断；失败证据保留，没有修改宿主防火墙。

初版工具 `693d573` 的 1200 字节 UDP control 各发送 5 秒，完整 payload 校验，使用独立 Go echo：

| 流数 / 每流窗口 | 唯一 echo Mbps / 单方向 | 发送 / 回包 | echo 丢失 | 生成器 CPU / 单核 % |
| --- | ---: | ---: | ---: | ---: |
| 1 / 64 | 701.88 | 365680 / 365680 | 0% | 71.85 |
| 4 / 1024 | 2389.54 | 1248938 / 1248938 | 0% | 302.99 |
| 8 / 1024 | 2420.75 | 1393220 / 1390531 | 0.193% | 297.80 |

三点均无损坏、未发送序号、重复或迟到回包。初版四流 control 超过 1 Gbps；八流没有进一步可靠改善，并出现丢包。后续工具修正必须独立重测，不能把初版 capacity 数字视为其他工具 SHA 的验证。

最终 credit 工具 `c1c8ea8` 的同环境 5 秒 control 重新验证如下。Windows 工具 SHA256 为 `7d2c37ababf2c47f27006e11ddbc6449f3284a93905e166289a8cb9e4b4ef478`，Linux echo 为 `6c428a06cc3c66d127d8bb3e3970e38f6e9f74bd86e1ac9c8f833e0e8867e724`。

| 流数 / 每流窗口 | 唯一 echo Mbps / 单方向 | 发送 / 回包 | echo 丢失 | 生成器 CPU / 单核 % |
| --- | ---: | ---: | ---: | ---: |
| 4 / 64 | 2006.97 | 1045445 / 1045445 | 0% | 265.90 |
| 4 / 1024 | 2143.02 | 1120354 / 1120354 | 0% | 265.87 |

两点全部请求均在 deadline 内回包，无重复、损坏、外来或未发送序号，也没有发送错误或包预算耗尽，`Completed=true`。这组 control 证明用于最终产品对照的实际工具可以测量超过 1 Gbps；echo 结束后正常输出统计，自有容器和 Windows 临时工具均已移除。公开证据为 `control/udp-credit-f4-w64.json`、`udp-credit-f4-w1024.json`、`udp-server-credit.json` 及 cleanup 日志。

第五组产品实测清理完成后，使用完全相同的 `c1c8ea8` 二进制补测 IPv4 直连单流：1200 字节 payload、`1 flow / window 64`、预热 2 秒、发送 **8 秒**、deadline 1 秒。唯一 echo 为 **705.16 Mbps**，发送、回包及期限内回包均为 **587670**，生成器 CPU 为 **72.85%** 单核；丢失、期限失败、迟到、重复、外来、损坏、未发送序号、发送错误和预算耗尽均为零，`Completed=true`。echo 累计 720055 包与预热及正式测量的发送总数相等，正常结束后自有容器和 Windows 临时 executable 已删除。证据为 `control/udp-credit-f1-w64-8s.json`、`udp-credit-f1-w64-2s.json`、`udp-server-credit-single.json` 和 `udp-server-credit-single-cleanup.log`。这次同工具结果排除了测量端约 450 Mbps 的 IPv4 单流硬上限；它仍是绕过隧道的控制，不能当作 Photon 吞吐，也没有验证 IPv6 直连容量。

公开本地证据保存于 `build/validation/performance-20261012/control/`，工具验证为同级 `tool-race.log`、`tool-native-tests.log`。首版原生 loopback 测试预算 10 万包在快 VM 上触顶，正确标记未完成；改为 100 万包测试预算后原生验证通过，最初失败日志 `tool-native-tests-initial-budget.log` 保留。性能默认 800 万包预算不变。这些短时 control 不代替长期稳定性或物理网络验收。

## 2026-10-12 统一 credit 工具产品对照

四组均使用上述 `c1c8ea8` 工具，1200 字节 payload、每点预热 2 秒、发送 **8 秒**、deadline 1 秒、800 万包预算。Windows product 从指定 commit 的 clean git archive 构建，均使用 Go 1.26.5、`CGO_ENABLED=0`、`-buildvcs=false -tags photon_profile`，每组只在首个 IPv4 单流点采集 profile。Linux product 和 fixture 均固定为 `2c06877`，实际 SHA256 分别为 `90a521aaca21a094244e7cef29df0a644a5482f3a52315550784875fc2fd1eff` 和 `faf4c23cdf699e609cd4757820848c14c223193e19a71b952193683e978a1760`；两个工具 SHA 也在四组实际日志中一致。

| Windows product 检查点 | 固定源码 | Windows executable SHA256 | 证据目录 |
| --- | --- | --- | --- |
| 优化前 | `2c06877d5ff51b10cd20d1ac05f516255accb984` | `f070c9599d21453ac854389deefe3c4b014d50c4d9f5a8f0f208e8642d8045c9` | `before-credit/` |
| 缓存检查点 | `3e6f4624cd56ebbe015172b0898990133d0fb602` | `a495f41af263be1675dc77d63bbb044f2edc9e998e92a62ad1918e6bbec61d86` | `after-cache-credit/` |
| 串行 AES | `33a9313b5dccdc00ae31e905f5db3c6f700cec4c` | `ed18b00d9baf0fc8cd983e92680c78d50000bfd7fe373684f51ff977f543efd7` | `after-direct-credit/` |
| 就绪检查 | `0fa3fa509e2074d1e03d4a4c1c9d6fdfb498fb32` | `e369dd4b05ac7fc1ccd1c89cd0e42ebfa186221a747883a8ab0017825e1d234f` | `after-ready-credit/` |

缓存检查点同时包含 canonical/只读状态、ESP 收发和策略快照等已验证优化，不能将其整组增益只归因于某一个函数。后续 `5d9684f` UDP 地址分配修补不在上述四组二进制中。每组 `performance-sources.json` 保存完整独立来源；`source-commit.txt` 是执行 rig 的版本，不能替代产品来源。

下表每格为 **唯一 echo payload Mbps / echo 丢失百分比**，包含实际排空时间；不是双方向速率相加。

| 地址族 / 流数 / 每流窗口 | 优化前 | 缓存检查点 | 串行 AES | 就绪检查 |
| --- | ---: | ---: | ---: | ---: |
| IPv4 / 1 / 64 | 16.02 / 0% | 363.58 / 0% | 361.33 / 0% | **419.85 / 0%** |
| IPv6 / 1 / 64 | 16.11 / 0% | 369.49 / 0.000325% | 355.60 / 0% | **407.26 / 0%** |
| IPv4 / 4 / 64 | 13.83 / 8.324% | 310.36 / 0.401% | 350.79 / 0.460% | 381.81 / 0.419% |
| IPv6 / 4 / 64 | 12.78 / 8.747% | 80.11 / 2.565% | 344.74 / 0.462% | 386.31 / 0.420% |
| IPv4 / 4 / 1024 | 8.35 / 80.528% | 317.07 / 9.708% | 160.87 / 17.764% | 252.77 / 12.626% |
| IPv6 / 4 / 1024 | 14.62 / 69.940% | 320.34 / 9.787% | 367.52 / 8.624% | 385.40 / 8.264% |

单流点的 **服务 CPU / 生成器 CPU，单位单核百分比**：

| 地址族 | 优化前 | 缓存检查点 | 串行 AES | 就绪检查 |
| --- | ---: | ---: | ---: | ---: |
| IPv4 | 135.02 / 7.99 | 195.48 / 60.34 | 168.93 / 61.71 | 176.35 / 67.77 |
| IPv6 | 129.23 / 7.99 | 196.46 / 60.54 | 148.39 / 66.58 | 174.20 / 69.13 |

本轮单流零丢包点从约 16 Mbps 达到 407–420 Mbps，约 25–26 倍；**尚未达到 1 Gbps**。串行 AES 的本轮服务 CPU 降低但吞吐未继续提高，不能用便携微基准的时间差声称相同比例的 VM 增益。大窗口依然有大量丢包，四流较小窗口也存在波动；没有扩大产品队列来隐藏问题。每包超时前占用一个 credit，因此真实丢包会限制 closed-loop 发送速率，这是明确的测量语义，不能把它与无等待的开放式发包容量混为一谈。每点仅一轮短测，数据用于下一步定位，不证明长期稳定性、统计显著性或物理网络容量。

全部 24 个点均 `Completed=true`、同服务 PID/创建时间、`RecoveryPassed=true`；无损坏、外来、未发送序号、重复、发送错误、迟到回包或预算耗尽。四组完整 SCM rig 均 `rig.exit=0`，包含后续正常/异常重启、地址变化与冲突恢复；各目录 `cleanup.log` 独立确认自有服务/网卡/目录/Event Log 来源/容器已消失，私钥和数据库已删除。首点 profile 分别为 `profile-5068.pprof`、`profile-1356.pprof`、`profile-6648.pprof`、`profile-4744.pprof`；Windows 等待 syscall 栈的限制见 profile 说明，不能把全部样本直接当作 CPU 热点比例。

另以产品 `5d9684f` clean archive 构建并运行七包 Windows 原生回归（composition、CLI、IKE、ESP、Babel、SADR、crypto），全部 PASS、退出 0。`native-final-5d9684f/` 保存完整 source/status、七个 executable SHA256、测试和清理日志；它覆盖新增 UDP 地址契约修补的功能回归，不将其性能推算进四组矩阵。原生测试与吞吐采样串行执行，结束后自有远端测试目录已删除。

## 2026-10-12 第五组 IO 与周期数学复用检查点

第五组 Windows product 固定为 `9c48297a439bfc79309681d6190a00dbd07e9c7b` 的 clean git archive，executable SHA256 为 `84af727543be7dc6b48d5daeb013b26cfd65a5fb431d93d7c5d9a6484d5fbac8`。构建标志、Linux/fixture、最终 `c1c8ea8` 工具二进制、1200 字节 payload、2 秒预热、8 秒发送、1 秒 deadline 及首点 profile 位置均与上面四组相同。独立来源保存在 `after-io-leaf-credit/performance-sources.json`；rig 运行时其他未提交源码不参与该产品构建。

这一检查点同时增加 `5d9684f` UDP 地址分配修补、`ecd4d5f` 周期 attachment 的纯数学 Verifier 复用和 `9c48297` socket 写锁调整，不能将整组变化归因于其中一片。数学复用仍现场检查授权、当前 SA/generation、到期时间和 overlay 地址；写锁调整允许读取与发送并行，同时串行写入和 socket 更换。

| 地址族 / 流数 / 每流窗口 | 唯一 echo Mbps / 单方向 | echo 丢失 | 服务 CPU / 单核 % | 生成器 CPU / 单核 % |
| --- | ---: | ---: | ---: | ---: |
| IPv4 / 1 / 64 | **449.83** | 0% | 165.00 | 76.55 |
| IPv6 / 1 / 64 | **430.97** | 0.001949% | 165.81 | 75.58 |
| IPv4 / 4 / 64 | 414.50 | 0.391% | 147.50 | 83.28 |
| IPv6 / 4 / 64 | 398.64 | 0.405% | 153.34 | 90.25 |
| IPv4 / 4 / 1024 | 104.26 | 25.497% | 41.64 | 22.60 |
| IPv6 / 4 / 1024 | 351.90 | 8.908% | 130.71 | 73.35 |

IPv4 单流相对优化前约 16.02 Mbps 达到约 28 倍，但仍未达到 1 Gbps；IPv6 单流有 7 个未回包请求，不能称为零丢包。四流大窗口继续出现明显丢包及吞吐退化，不能只取单流最高点表示所有负载已经解决。各配置仅一轮短测，单流相对上一检查点的差值不证明统计显著性。

六点均 `Completed=true`、`RecoveryPassed=true`，服务保持同一 PID/创建身份；无迟到、损坏、外来、未发送序号、重复、发送错误或包预算耗尽。完整 SCM rig `rig.exit=0`，`cleanup.log` 独立确认自有服务、网卡、目录、Event Log 来源和 Linux 容器已消失，私钥及数据库已删除。首点 profile 为 `after-io-leaf-credit/profile-2948.pprof`。该检查点通过完整 Windows race 与 `make check`；新 socket/leaf 场景另以记录源码文件 SHA 的临时 Windows 原生测试 executable 验证通过，证据在 `native-dirty-socket-leaf/`，包括 Windows RawWrite 阻塞发送期间接收、socket 更换等待发送和双栈并行收发。这个临时功能验证不冒充该 clean 产品的七包原生回归，也不参与吞吐采样。

较早的 `before-original-tool/`、`before/`、`after-cache/` 15 秒原始样本全部保留：初版/时间戳工具使用固定序号槽位，丢包后存在 head-of-line 等待，其多流数据不作为最终容量矩阵。早期 `before/` 性能点完成但宿主协调器退出 143，后续资源由人工清理，不能将它说成完整 rig exit 0；统一工具五组使用独立协调器保存最终退出码并验证清理。
