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
- deadline 使用接收 goroutine 实际读取回包的 monotonic 时间。发送 goroutine 因调度晚消费通知，即使窗口已先到期或覆盖，仍按该包全轮保存的发送/读取时间判定；真实迟到不会因后续收到回包而消除期限失败。每流 `Expired` 在运行中是暂定计数，最终统计校正已读及时但通知延后的包。
- 工具限制使内存和等待时间有上界，不将产品队列或权限缓存放宽。临时端口、服务、网卡、容器及私钥/数据库沿既有 rig 的所有失败/成功路径清理。

Go 单元/race 测试覆盖重排、deadline 临界点、窗口复用、超过旧 8192 序号范围的合法迟到、重复、完整 payload 验证以及结果文件拒绝覆盖；真实 loopback 再注入一次丢包、重复、110 毫秒迟到验证统计。Windows 原生测试额外核验 CPU、进程创建身份与 private/working-set 采样。

## 2026-10-12 直连 control

Windows VM 为 8 个逻辑 CPU、约 8 GiB 内存，VirtIO Ethernet 报告 10 Gbps。Linux 源地址 `10.16.255.8` 与 VM `10.16.252.11` 同 LAN。control 仅经临时 Docker 发布的测试端口，绕过 Photon/Wintun/ESP；不能将其吞吐称为产品性能。

TCP 粗上界采用 256 KiB block，发送 5 秒；Windows 发送与 Linux 接收均为 5,182,849,024 字节，对应 **8292 / 8288 Mbps**。该控制只验证字节总量与链路容量，不逐包检查内容。第一次宿主直接监听 `19106` 未经 Docker 发布，被现有防火墙阻断；失败证据保留，没有修改宿主防火墙。

1200 字节 UDP control 各发送 5 秒，完整 payload 校验，使用独立 Go echo：

| 流数 / 每流窗口 | 唯一 echo Mbps / 单方向 | 发送 / 回包 | echo 丢失 | 生成器 CPU / 单核 % |
| --- | ---: | ---: | ---: | ---: |
| 1 / 64 | 701.88 | 365680 / 365680 | 0% | 71.85 |
| 4 / 1024 | 2389.54 | 1248938 / 1248938 | 0% | 302.99 |
| 8 / 1024 | 2420.75 | 1393220 / 1390531 | 0.193% | 297.80 |

三点均无损坏、未发送序号、重复或迟到回包。四流 control 已证明本工具在当前环境可以测量超过 1 Gbps 的完整回包速率；八流没有进一步可靠改善，并出现丢包。实际隧道从一流和四流开始，仍需分别验证产品瓶颈与达标结果。

公开本地证据保存于 `build/validation/performance-20261012/control/`，工具验证为同级 `tool-race.log`、`tool-native-tests.log`。首版原生 loopback 测试预算 10 万包在快 VM 上触顶，正确标记未完成；改为 100 万包测试预算后原生验证通过，最初失败日志 `tool-native-tests-initial-budget.log` 保留。性能默认 800 万包预算不变。这些短时 control 不代替长期稳定性或物理网络验收。
