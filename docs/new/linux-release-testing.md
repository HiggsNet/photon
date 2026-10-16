# Linux 重构版测试

本轮旧版固定为 `v0.5.6`（master 提交 `28472ea74615`），新版为
`v0.6.0-rc.10`（在 rc.9 基础上拆分 Gossip 输入与可靠结果交付，保留单消费者更新状态）。新版只供测试，Windows 完整隧道尚未交付。
master 保留旧版；候选版从独立 release 分支发布，不更新 Docker `latest`。

## rc.10：可靠交付内部结果，分批推进事件

- Gossip 状态仍由一个消费循环更新。保留原有 4 个 TCP 对象拉取 worker、64 个待执行任务及每 peer 最多 2 个并发；worker 只做网络拉取与响应解析，返回结果后由消费循环验证、持久化并发布状态。
- 可恢复输入默认容量 64，UDP 溢出时丢包并累计、限流记录。计时器与 worker 结果走独立容量 4 的可靠通道，满时生产 goroutine 等待交付，停止时可以取消；取消后的旧 timer generation 仍被拒绝。
- 已接收 PONG、目录页、分片组装结果、快照应用确认及提交失败结果通过返回值交回 dispatcher，不再与新收包争抢输入槽位。整批快照持久化失败也会交付失败结果，让会话明确收尾。
- 每轮最多执行 16 个就绪步骤，剩余结果保留并合并唤醒下一轮。有就绪内部工作时暂停取新输入，可靠结果与平台事件仍可处理；仅有异步 I/O 在途时不暂停输入。不增加结果转发 goroutine，也不并发提交状态事务。
- Linux daemon、sync serve/once 与 Windows 公共消费入口同步接入。批次聚合会话完成时的 NetworkChanged，避免后续内部事件覆盖已完成的变化；本地输入拥塞不再标记为远端 invalid_message。

已通过 make check、make smoke-all、公共 host/Linux/Windows 逻辑 race 检查及队列专项 race 连续 100 轮。回归包含单核满队列 PONG、快照成功/对象拒绝/整批提交失败、worker 满通道交付与停止、计时器取消、16 步预算续处理及等待 I/O 时继续响应其他输入。日志位于本地 build/validation/rc9-queue-fix-20261016/。

schema 2、Gossip wire、签名授权与默认 quota 保持原样。路由、IPsec 和部分持久化仍可能同步占用消费循环；本次保证结果交付和步骤预算，不代表已消除所有 I/O 等待或证明实机 CPU 降幅。实体机部署与观察需单独记录。

## rc.9：修复 quota 补额与分片续发，细分协调慢日志

- 每个 peer 的字节/对象限额保留原值。补额保留纳秒分母下的整数余数，密集检查和拒绝请求不再丢失小数额度；时钟回退不会重复产生额度，满桶不积攒额外额度。
- UDP 分片初发与修补复用原有有界发送缓存。统一 Host 调度器按小批续发，限流时保留未发送索引，等待额度后继续；事件循环不 sleep，不增加独立发送 worker。仍受原缓存容量和 30 秒 TTL 限制，过期不继续发送。
- 续发保留请求的回复地址，每次发送仍走 transport 的 peer 检查。重叠修补合并尚未发送的索引；停机清除待发游标与缓存。NACK 按一次有界请求计费，实际重传数据片各自计费。
- 调度器使用全局 generation 保持取消/替换后的过期事件拒绝，不再永久保留每个完成 transfer ID 的 generation 项。
- quota 的普通 warn 包含消息类型、收发方向和 requested/available bytes/objects 及限额，无需全量开启 debug。
- 协调日志增加固定子阶段：routing state read、授权路由、veth、upstream、BIRD write/start/configure/observe，以及 firewall state read、授权路由、preflight、apply；沿用 100ms 阈值与每阶段 30 秒限频，快速路径不输出日志。

确定性回归包含每 1/5/10ms 检查后的完整补额、拒绝请求、时钟回退、满桶与大数溢出；128KiB 合成对象超过 128 个分片时，在刻意收紧的真实 transport quota 下完成初发、重新组装和 128 片修补，其他 peer 仍可发包。另覆盖请求回复地址、peer 移除、缓存过期/停机、重叠修补、stale timer 和不启用 debug 的 quota 诊断。

已通过完整 make check、make smoke-all、make install-script-check，以及 state/host/gossip/photonlinux/app 的 race 检查。验证日志位于本地 build/validation/rc9-20261015/。

此版本不改变 schema 2、Gossip wire、验签或授权逻辑；旧 peer 保持其原有配额行为。两条历史 quota 警告的精确报文仍不可追溯；2.07 秒 routing 和 2.4 秒 firewall 长尾尚未复现，新增子阶段日志用于定位，不能宣称其根因已修复。

## rc.7：Gossip 窄读取与 CPU 基准

2026-10-13 在 `/tmp/rc6` 的 `perf/rc6-gossip-projections` 分支收窄 Gossip
读取。对照源码固定为已发布 rc.6 的 `f7d99cf7fdda`；下表比较原 rc.6 与 rc.7 的 CPU
改动，不是与 v0.5.6 的整机性能对照，也不代表线上 CPU 已下降。

- 入站 observed checkpoint 与路径恢复只读取该 peer、当前记录和祖先授权链。
  每次使用仍执行签名、授权、撤销及时间检查；检查点持久化完成后才发布地址。
- 全局 discovery 保留全部当前记录和 peer 检查点，省去 record history 与本地私钥。
  目录摘要仍由同一份当前记录计算，授权和端点 TTL 仍在每次使用时判断。
- TCP zone/record 只复制所请求对象；UDP zone 回应只读取目标快照和 parent proof。
  返回值保持可独立修改，历史 record 的版本选择顺序和 zone 撤销策略保留。
- `BuildObjectPullResponse` 的 Go 读取依赖改为 `ObjectPullSource`，请求类型处理仍
  由 Gossip 协议层统一负责。该 CPU 改动不改变 wire、数据库 schema 和检查点提交语义；rc.7 的存储改动见下一节。

使用同一个 `BenchmarkGossipReadPaths`，28 个 zone（26 个 leaf），每 leaf
10 条当前记录、每 key 8 份 history。入站 peer 使用真实签名授权链及 endpoint。
持久化回调为空，测量内存路径；transport 使用内存 datagram 和同一固定 clock，
并在计时前检查目标对象及 observed 地址实际产生。两版在同一 Ryzen 5700G 主机
依次运行，`-cpu=1 -benchtime=1s -count=3`，下表取三次中位数：

| 操作 | 原 rc.6 耗时 | CPU 优化耗时 | 原 rc.6 分配 | CPU 优化分配 |
| --- | ---: | ---: | ---: | ---: |
| 全局 discovery 输入 | 678.122 us | 128.702 us | 1,486,344 B | 184,960 B |
| 入站来源校验、checkpoint 与地址恢复 | 1,615.246 us | 219.885 us | 2,981,440 B | 33,024 B |
| TCP zone 响应 | 841.599 us | 5.911 us | 1,495,609 B | 9,104 B |
| TCP 历史 record 响应 | 730.277 us | 0.4763 us | 1,487,248 B | 744 B |
| UDP zone 回应规划 | 789.876 us | 31.376 us | 1,516,088 B | 38,065 B |

入站路径分配下降约 98.9%，耗时下降约 86.4%。全局 discovery 的当前记录复制
仍有开销；入站路径也仍有两次授权链验证。本轮没有用跨事件缓存替代这些检查。

另外各采集一次入站基准 CPU profile：原版 `ReadView` / 全网复制调用链占 CPU
样本约 84%，修改后 `VerifyChain` 调用链占约 87.6%。这确认主要复制热点已移除，
剩余耗时主要来自授权验签。两份 profile 的总操作次数不同，只用于定位热点；
累计调用链有重叠，不能相加。CPU/alloc profile 与文本报告也保存在下述日志目录。

已通过 `make check`（完整 Go 测试、vet、Linux 构建和 Windows 交叉构建）、
`make smoke-all` 及 `go test -race -count=1 ./pkg/core/state ./pkg/core/host ./pkg/core/gossip`。
回归覆盖当前摘要等价、父链 proof fallback、授权到期、签名撤销及未来撤销、历史
record 版本顺序、返回值深层隔离、并发提交和 wire 响应等价。网络检查在允许本机
socket 的环境中执行。基准输出和检查日志保存在本地
`build/validation/gossip-projections/`。

这些是合成内存基准。下一阶段需在相同主机、配置和流量下采集实际 daemon
CPU/alloc profile、写盘延迟和队列样本，才能判断 GC 与线上整体 CPU 的收益。
rc.7 包含上述 CPU 改动；实际部署结果需单独确认。

## rc.7：按 zone 存储与 schema 2 升级

2026-10-14 在 CPU 优化提交 `bab28786eb3d` 基础上建立
`perf/rc6-storage` 分支。Common schema 从 1 升到 2：身份、全局 root 和 zone
路径清单保留在小型 `verified/payload`，当前记录、历史、授权及撤销数据按 zone
保存到 `verified/zones`。提交仍比较全部候选编码，只有变化的 zone 执行 Put，
删除的 zone 执行 Delete；本轮没有引入缓存或依赖不完整的 ChangedZones 提示。

唯一 BoltStore、原子事务、不可变 root pin、verified revision 校验，以及持久化
成功后发布内存的顺序保持不变。路径清单用于拒绝缺失、重复、路径不符或多余的
zone 数据。schema 1 可以只读查询；Linux/Windows 启动在既有事务内一次性升级，
单纯布局变化不推进 verified revision。迁移失败回滚旧格式，二次启动不重写。
旧 rc.6 程序拒绝 schema 2，回退必须恢复升级前数据库；不要用新版数据库直接
启动旧程序。checkpoint 仍是按 peer 的同步提交，没有改变重启提示的发布时机。

同一主机依次运行相同 `BenchmarkVerifiedZoneCommit`，28-zone fixture 沿用前文
checkpoint 基准（26 个 leaf、每 leaf 10 条当前记录、每 key 8 份历史），每轮只改
一个 zone 的一条记录。`-cpu=1 -benchtime=1s -count=3`，表中为三次中位数。
NoSync 仅用于基准排除 fsync 等待；`db-page-B/op` 是分配的脏数据库页字节，
不能当作真实磁盘延迟或进程总写入量：

| 指标 | CPU 优化提交 | 存储优化 |
| --- | ---: | ---: |
| 单 zone 提交耗时 | 15.886 ms | 1.907 ms |
| 每次分配 | 5,277,164 B | 1,828,179 B |
| 每次分配次数 | 22,372 | 1,233 |
| 数据库脏页 | 1,695,744 B | 86,016 B |

另用正常 fsync 的隔离临时数据库实测 `/proc/self/io`：35 个 zone，每 zone
10 个 key、每 key 8 份历史、Value 256B，只改变一个 zone 的一个记录，提交 20 次，
初始化写入排除。verified 每次写入从 2,285,568 B（约 2.18 MiB）降至 155,648 B
（152 KiB），约减少 93.2%；单 peer checkpoint 前后均为 20 KiB。该实验只比较
存储布局，没有真实签名验证或同步流量；GlobalRoot 在该 fixture 中保持不变，
真实网络摘要更新还会重写小型 metadata。序列化仍遍历所有 zone，Bolt 的共享页、
父节点和空闲页列表仍有开销，不宣称单条记录只产生一条记录大小的物理写入。

已通过 `make check`、`make smoke-all` 和 state/host/gossip/app 的 race 检查。
新增回归覆盖 schema-1 升级的身份密钥、记录历史、checkpoint 和 revision 保留，
Linux 启动及二次启动、zone 删除和未变化数据保留、写入后失败的事务回滚，以及
新格式损坏时拒绝加载。基准、落盘实验及验证日志保存在
`/home/herbertqiao/Work/photon/build/validation/rc6-storage-20261014/`。
rc.7 包含上述存储改动；线上总写入量和 CPU 的收益仍需同机、同负载采样确认。

## rc.8：周期 reconcile 错峰

2026-10-14 在 `/tmp/rc6` 的 `perf/rc6-gossip-projections` 研究分支，以 rc.7
发布提交 `df8ec528` 为基线，将周期巡检按启动恢复完成时间分相位：路由默认在
10、40、70 秒执行，防火墙在 20、50、80 秒执行，IPsec 在 15、75、135 秒
执行。rc.7 的调度仍是路由和防火墙每 30 秒同时巡检，并与每 60 秒的 IPsec
和默认同步周期重合。新调度保持原周期；IPsec 自定义周期按其 1/4 设置相位。

状态变化、撤销和 VICI 事件仍立即进入原有单写者处理，保留撤销清理与
firewall → routing → IPsec 的处理顺序。事件驱动 reconcile 完成后，周期
巡检仍回到各自相位，下一次等待不超过该层周期；耗时工作结束后按当前时间
跳过已错过的槽位。禁用的层仍取消定时器。

已在 rc.7 基线上通过调度回归（相位保持、禁用、自定义周期、错过槽位与时钟
回退）和 `make check`（完整 Go 测试、vet、Linux 构建及 Windows 交叉构建）。
验证日志在 `build/validation/reconcile-phases/check-rc7.log`。

此改动只分散多层周期工作叠加的负载，不减少每轮工作量，也不拆分单次 IPsec
巡检。默认周期下三层不再定时重合；自定义周期、耗时巡检和外部状态变化仍
可能造成重叠。实际 CPU 峰值变化需同机上线采样确认，本地调度测试不能代替
线上性能验收。事件驱动的巡检不再推迟固定周期槽位，因此可能在刚处理完状态
变化后较快再巡检一次；这换取相位稳定，不能承诺平均 CPU 消耗下降。

## 2026-10-15：RC CPU 现场调研

研究源码为 `/tmp/rc6` 的 `perf/rc6-gossip-projections`，提交 `fb78d514`。
只读检查实际运行二进制：Table 与 less 均为 rc.7 `df8ec52`，suki.moe 仍为
v0.5.6 `28472ea`。错峰提交尚未部署。三台均有 38 条 up 链路；硬件、流量及
状态变更不同，以下是当时负载的观察，不能用来比较版本性能。

按一秒间隔读取 `/proc/<pid>/stat` 和服务 cgroup 的 `cpu.stat`，各采样 181 点，
实际覆盖约 182–185 秒。百分比以一个核心为 100%；回收子进程的 CPU 来自
主进程 `cutime/cstime`，服务 cgroup 另含常驻 BIRD 等进程。

| 节点 | CPU | 主进程平均 | 回收子进程平均 | 整个服务平均 | 主进程最高一秒区间 |
| --- | --- | ---: | ---: | ---: | ---: |
| Table / rc.7 | 1 vCPU EPYC Milan | 1.37% | 0.48% | 2.24% | 13.35% |
| less / rc.7 | 2 vCPU Ryzen 5700G | 1.15% | 0.18% | 1.79% | 46.37% |
| suki / v0.5.6 | 1 vCPU Xeon 8163 | 1.83% | 0.62% | 2.80% | 30.16% |

在 less 使用已有 perf 对现有进程补采 120 秒 `cpu-clock:u`，499 Hz、frame
pointer 展栈。678 个样本中 645 个属于 photon，33 个属于其新建的 ip/nft
子进程，以下比例仅以 645 个 photon 用户态样本为分母。粗分互斥类别：后台
GC 约 25.3%，目录摘要 `ZoneDigests` 调用链约 19.1%，授权链验证约 11.6%，
`ReadView` 调用链约 3.1%。前一轮 DWARF 采样有大量缺失调用栈，未用来判断
这些调用链的比例。两个 profile 窗口不同，不能直接相加或比较总 CPU 收益。

优先候选：

1. **减少未变 zone 的目录 root 重算。** `ReadCatalog` 虽然已避免整网复制，
   每次仍通过 `ZoneDigests` 对全部 zone 的 authority、delegation、revocation
   和当前 record 重新哈希。现有 28-zone 合成 fixture 的
   `BenchmarkReadProjection/catalog/narrow` 三次耗时中位数约 0.380 ms，
   每次分配 454,296 B、3,272 次。可在唯一 Store 内复用同一已提交版本的原始
   `ZoneRoot`，读取时再按当前时间筛掉撤销的 zone，返回独立副本。不能只按
   verified revision 缓存最终目录：未来撤销生效时可能没有新提交；也不能借此
   跳过 `VerifyChain`、密钥到期或其他时间检查。实际实现与收益尚未验证。
2. **批量执行上游路由命令。** Table 在另一个 70 秒 exec/wait 跟踪窗口内
   启动 211 个不同 PID，其中 130 个为 `ip route replace`，对应五轮处理，
   每轮 26 条；另有 5 个 `ip addr replace`。该窗口含事件驱动 reconcile，
   不能解释为纯周期频率。`execUpstreamRouteManager.EnsureRoutes` 目前逐条
   fork，适合先验证同一 netns 内用 `ip -batch` 合并执行，保留顺序和失败即停。
   不需要引入长期缓存，也不应只凭上次期望配置相同就跳过真实系统修复。
   strace 会扰动耗时，其 wait CPU 只能帮助定位，不能当作无跟踪的基线。
3. **减少防火墙重复探测与无变化时的重建。** 同一 Table 跟踪窗口有 10 个
   `iptables -V`、20 个 nft 读取进程和 10 个 `nft -f`。源码每次实例解析均
   探测后端，NFT apply 会原子重建受管表。仅比较上次 `PolicyHash` 不足以
   发现外部漂移；完整规则比较涉及安全和修复语义，复杂度高于前两项，暂列后续。

Table 首轮 any 抓包混入大量 Higgs 流量并在约 43 秒触及 20,000 包上限，未用
其包率代表 Photon。随后在 eth0 单独采集同步端口 90 秒：过滤掉两条无关 TCP
后为 276 个 UDP、12 个 TCP 包，UDP payload 合计约 99 KB，最高一秒 87 包，
抓包的内核丢弃计数为 0。该窗口支持先研究每事件计算和周期外部命令的判断，但抓包本身不能
定位 CPU，也不能排除其他时段的重传或高流量问题。

三台调研前后 daemon PID 未变，未重启或切换服务；没有改动网络配置和授权。
上述现场采样阶段只补充调研记录；后续本地实现见下一节。原始计数、包头文本、perf
数据、子进程跟踪、分析脚本和基准输出保存在本地
`/home/herbertqiao/Work/photon/build/validation/cpu-20261015/`。

## rc.8：目录 root 复用与上游路由批处理

在周期错峰提交 `fb78d514` 基础上，以 `1cbc784` 实现目录与路由优化，一并纳入 rc.8。唯一 Common Store 按
已提交的 verified revision 懒加载一份原始 zone root 快照，`ReadCatalog` 与
`Store.ZoneDigests` 共用。任意 verified revision 变化后下一次读取重算整份
原始快照，不依赖 ChangedZones；checkpoint-only 提交继续复用。每次读取仍按
当前时间判断撤销，返回独立的 slice 和 hash；未来撤销生效、时间回退、purge、
持久化失败和并发提交不会复用错误的可见目录。没有缓存授权链验证结果，wire
摘要算法、数据库 schema、持久化成功后发布内存的顺序保持不变。

`execUpstreamRouteManager` 将相邻且地址族相同的命令通过 stdin 交给一个
`ip -4/-6 -batch -`，保留先地址后路由、排序及失败即停的顺序，不使用 `-force`。
混合双栈按原顺序最多分四批；同一 IPv6 源地址加 26 条路由由 27 次调用变成
1 次。命名空间作用域保持原样。对含批处理注释、引号、换行或 NUL 等特殊字符
的接口名保留逐条 argv 执行，不让批处理解析器改变原参数含义。没有用上次期望
配置相同作为跳过实际系统修复的依据。

同一 Ryzen 5700G 本机依次运行，各 `-cpu=1 -benchtime=1s -count=3`，以下为
三次中位数。目录使用既有 28-zone 合成 fixture，并在同一 binary 保留原重算
路径作对照；路由在隔离 user/network namespace 内通过真实 iproute2 执行
同样的源地址及 26 条路由，父/子 CPU 通过 `getrusage` 分别计量：

| 项目 | 原路径 | 本地实现 |
| --- | ---: | ---: |
| 稳定版本目录读取 | 455.252 us | 9.611 us |
| 目录每次分配 | 454,296 B / 3,272 次 | 5,120 B / 192 次 |
| 单轮上游配置墙钟耗时 | 37.402 ms | 1.788 ms |
| 单轮上游配置父子进程合计 CPU | 39.786 ms | 1.881 ms |
| 单轮上游配置进程调用 | 27 | 1 |

稳定目录分配下降约 98.9%；路由这条路径的父子进程 CPU 时间下降约 95.3%。
目录首次未命中仍需重算，基准约 405.505 us、456,376 B；不能把稳定版本收益
用于每次都有 verified 提交的负载。父子进程可在多核上重叠，合计 CPU 时间可能
高于墙钟时间。这些均为局部基准，不是线上总 CPU 降幅。

回归覆盖撤销时间跨越与回退、返回值隔离、持久化前/失败时的目录可见性、
checkpoint-only 更新、身份安装、remote/recovery 提交、purge 及并发读写。
路由测试覆盖双栈与命名空间参数、特殊接口名兼容、后续批次失败即停；隔离内核
验收检查真实双栈路由与源地址、重复执行，以及批次中间错误后不执行后续行。
批处理的地址族选项、失败即停和注释/引号规则还核对了
[iproute2 的批处理入口](https://github.com/iproute2/iproute2/blob/v7.0.0/ip/ip.c)
与[行解析实现](https://github.com/iproute2/iproute2/blob/v7.0.0/lib/utils.c)。
已通过 `make check`、`make smoke-all`、state/host/gossip/photonlinux/app 的
`go test -race -count=1`，以及显式开启的隔离内核验收。
基准和验证日志保存在本地
`/home/herbertqiao/Work/photon/build/validation/cpu-optimizations-20261015/`。
rc.8 不改变 rc.7 的 schema 2；发布与 Table 同机对照结果需另外记录，以上为本地验证。

## rc.6 相对 rc.5 的变化：目录刷新与拒绝记录

- 目录和快照分两次读取，期间 endpoint 等 record 更新可能造成 `root_mismatch`。每轮首次摘要不一致会等待已有拉取和校验结果结束，刷新目录一次；不应用摘要不符的快照，不延长原有整轮超时。
- 刷新后仍不一致时保留拒绝与退避；签名、授权和版本校验继续执行。既有 gossip wire 格式保持不变，对端无需同步升级。
- peer API 的 `rejected_digests` 只显示有效拒绝；校验成功后清除来源 peer 的拒绝，也清除其他 peer 对同一已验证摘要的拒绝。过期后再次失败会续期，过期本身不代表恢复。
- 本地验证包括完整 Go 测试、vet、Linux 构建、Windows 交叉构建、全部 smoke 和核心包竞态检测；线上混版本长时间验收仍按下文执行。

## rc.5 相对 rc.4 的变化：被动接收方端口轮换

- 修复角色映射中明确的空值被当成缺省值、回退为主动拨号方的问题。空值表示仅被动接收连接，轮换时应继续加载被动配置，等待对端发起协商。
- 对端为 `role=out`、本机为 `role=both` 时，修复前可能在端口轮换期间持续报 `load connection: at least one contact point is required`，对端收到 `AUTHENTICATION_FAILED` 或 `NO_PROPOSAL_CHOSEN`；旧隧道仍可能正常传输，但新隧道无法建立。
- 同一配置加载用例在 v0.5.6 和 `cae426da` 的父提交通过，在 `cae426da`（2026-09-08，统一 IPsec 单代运行资源推导）失败。空角色判断的隐患在旧版已存在，该次重构开始覆盖轮换配置的角色，触发本次故障。
- 回归测试覆盖 IPv4/IPv6 被动轮换配置加载、不主动拨号、保留旧运行资源及等待对端协商；同时覆盖按 link/runtime 查找角色和旧调用缺省行为。

此修复不需要修改对端的 `role=out` 配置。发布包和本地测试不替代部署后的双向数据面与轮换验收。

## rc.4 相对 rc.3 的变化：Checkpoint 与读取性能

- 纳入性能提交 `de2b6859`：纯 GossipCheckpoint 更新走独立提交回调，不再复制、编码或写入 VerifiedState；verified revision 不变。
- 内存应用指定字段的 patch，只复制受影响的 peer；磁盘按 peer 保存小型 JSON，未变化的 peer 不重写。持久化成功后才发布内存状态。
- 同步会话只读取相关 peer；撤销清理只查询当前撤销结果和受影响的 checkpoint，不再复制整个网络和记录历史。
- 旧整块 checkpoint 在首次写入时原子迁移。直接回退 RC.2/RC.3 会丢弃可恢复的同步提示，但保留 verified 数据；重新升级时优先采用旧版新写入的 payload。此说明不代表承诺可以无损回退 v0.5.6。
- 没有修改事件队列容量、背压/丢弃策略和协议调度架构；短时采样不能证明队列拥塞已经消失。

2026-10-06 在 less 上分别采集相邻 180 秒 Go CPU profile（均含启动）：优化版 07:58:57–08:01:57 CST，原 RC.3 对照 08:02:01–08:05:01 CST。两轮在线流量不完全一致，以下是现场观察而非同负载基准。

| CPU 样本 | 原 RC.3 | 优化版 |
| --- | ---: | ---: |
| 进程合计 | 13.04 s | 2.90 s |
| Checkpoint 更新调用链 | 5.41 s | 0.07 s |
| 撤销清理调用链 | 2.06 s | 0.13 s |
| ReadView 调用链 | 2.97 s | 0.76 s |

调用链累计时间存在重叠，不能相加；Go profile 不包含子进程 CPU 或等待时间。采样后 less 已恢复原 NixOS RC.2，本分支未部署。

剩余 ReadView 复制主要来自 discovery（0.31 s）、生命周期 suppression（0.24 s）和 catalog/state view（0.18 s）。后续优先收窄查询，避免为了取摘要、活动时间、端点而复制 records/history；不要用未经证明的跨轮缓存替代验证，也不要仅按 verified revision 缓存受时间和 checkpoint 影响的结果。

进一步按 CPU 样本栈作互斥粗分（先归入 ReadView，再归后台 GC 等；不是把累计调用链相加）：

| 优化版样本类别 | CPU 时间 | 后续判断 |
| --- | ---: | --- |
| ReadView 内同步工作 | 0.76 s | 收窄查询 |
| 后台 GC 标记、清扫与回收 | 0.76 s | 先减少临时对象；归因到具体分配点仍需 alloc profile，不直接调 GC 参数 |
| ZoneDigests/ZoneRoot 摘要计算 | 0.28 s | 检查同一事件内复用和按变更 zone 重算 |
| ICMP 探测 | 0.16 s | 使用非阻塞 socket 与 Poll 等待，未发现明显忙循环 |
| 授权链验签 | 0.14 s | 保留验证；只有相同输入、相同有效期内的重复计算可考虑复用 |
| 其他及未归类 | 0.80 s | 包含撤销清理、调度、写盘、启动和零散平台/协议工作 |

其中 checkpoint 更新整个调用链只有 0.07 s，当前不是进一步拆分磁盘字段键的优先理由；JSON 解码累计 0.13 s、诊断对象复制 flat 0.03 s，也不是主导项。这些补充调用链已包含在上表，不能再次加总。样本总计只有约 290 个 10ms CPU tick，小于 0.1 s 的项目应通过更长采样或针对性基准确认后再改。

`ReadView` 之外约 2.14 s 并非全部业务计算，后台 GC 就占 0.76 s。继续减少复制可能同时降低 GC，但本次 CPU profile 不能精确断言每份垃圾来自哪条分配路径。现场出现的 111ms checkpoint 墙钟耗时也不能直接算作 CPU；若继续研究提交延迟，应另外统计事务/fsync 耗时。

本轮随后补充了窄读取和单段哈希分配优化，范围如下：

1. 已完成：`gossipStateView` 通过 `ReadCatalog` 在同一读锁内取得 managed zone 与 zone digests，不再构造完整 `ReadView`。catalog 的哈希计算另占 0.28 s，可先减少同一事件内的重复计算；若以后缓存单个 ZoneRoot，仅使变更 zone 失效，并按当前时间重新过滤撤销。
2. 已完成：`gossipSuppressions` 通过 `ReadPeerActivity(now)` 读取撤销结果及 peer 的 LastSync/ObservedLastSeen 时间。生命周期策略仍留在 daemon，每次重新判断未来撤销及 checkpoint 变化，不缓存超时结果。
3. 暂不扩大范围：单 peer 来源地址验证与全局 discovery 仍保持原路径，今后可考虑分开取数。保留父链、授权与撤销检查，避免每次收到包都构造整个网络和全部 checkpoint。跨事件缓存必须覆盖授权到期、未来撤销、端点 TTL 和 checkpoint 更新，不能只看 verified revision。

临时分配 profile 确认：旧目录查询主要分配在记录/字节切片深复制；移除复制后主要是哈希状态与编码 buffer。仅对 `Hash` 的单段输入使用库的 `blake2b.Sum256`，不引入缓存或对象池；测试覆盖空输入、块边界、单/多段等价和结果隔离，哈希及签名格式不变。

同一合成网络 fixture 的三次本地基准：

| 操作 | 改动前每次分配 | 本轮完成后每次分配 |
| --- | ---: | ---: |
| 目录读取和摘要计算 | 2,048,141 B | 454,298 B |
| 生命周期输入读取 | 1,485,906 B | 3,424 B |
| 单段哈希 | 416 B / 2 allocs | 32 B / 1 alloc |

目录窄查询约 0.39–0.42 ms；生命周期窄查询约 7–8 us。基准存在运行噪声，分配量比单次耗时稳定。上方 2.90 s 现场 CPU 结果来自前一阶段，不包含本轮补充；本轮没有再次部署 les，不能据此宣称新的线上 CPU 降幅。discovery 全量读取和多段摘要编码仍有开销，本轮到此收尾。

已验证完整 Go 测试、state/host/daemon 的 race 检查、go vet 和 Windows 公共依赖交叉编译；RC.4 准备分支的 `make smoke-all` 与 `make install-script-check` 也已通过；迁移、写盘失败回滚、未变 peer/verified 数据保留、未来撤销和查询隔离有测试覆盖。RC.4 的发布检查仍需按下文执行，长时间运行与特权数据面验证不由 CPU 采样替代。

## rc.3 相对 rc.2 的变化

- 增加 `component=sync event=slow_operation` 日志，覆盖 Gossip 事件处理、同步发起、来源地址和会话检查点、快照应用，以及路由、防火墙、IPsec 协调。
- 操作耗时达到 100ms 时记录；每个阶段最多每 30 秒输出一次，后续慢操作日志汇总期间被抑制次数及最大耗时。
- `queue_before` / `queue_after` 是操作边界的队列长度，`max_sampled_queue` 是慢操作边界采样的最大值，不代表连续测量的队列峰值。正常快速路径不构造日志字段或分配内存。
- 本版仅增加诊断，保持事件队列容量、丢弃策略和调度架构不变。日志不构成队列拥塞修复。
- 本版未合入 Windows 分支上的后续隧道开发。

## rc.2 相对 rc.1 的变化

- 兼容 iproute2 JSON 中十六进制字符串形式的 XFRM `if_id`，避免批量观察持续失败并回退逐接口读取。
- 默认 `photon gossip peer` 列表隐藏超过 cleanup_after、没有有效端点的历史节点；bootstrap 保留。按名称、`--filter`、`--verbose` 和 debug 仍可查询，最近活动或有效端点恢复后重新显示。此改动不删除数据库记录。
- 不包含现场 ln 数据库的手工恢复操作，也未新增 Rotate 状态日志或改变轮换策略。

## 下载和安装

使用一台专用 Linux 测试机，与仍运行旧版的节点互通。安装器支持 amd64/arm64，
会检查运行依赖并校验下载包的 SHA256。以下命令面向普通 systemd 安装；
NixOS、容器或自定义 unit 应沿用原部署方式，显式固定版本。

```sh
curl -fL --retry 3 -o /tmp/photon-install-rc.sh \
  https://raw.githubusercontent.com/HiggsNet/photon/v0.6.0-rc.9/contrib/install.sh
```

先在测试机安装旧版，完成入网并确认双向通信，作为基线：

```sh
sudo sh /tmp/photon-install-rc.sh --version v0.5.6
photon version
```

首次安装仍需按 [运维文档](operations.md) 配置身份、授权和网关，再启动
`photon.service`。安装包本身不会替你加入网络。

升级前停止 Photon，备份配置和数据库。默认 service 使用 `/etc/photon`；
先用 `systemctl cat photon` 检查实际配置、数据库和环境变量路径。
自定义路径必须一起备份，有其他 Photon 服务使用相同数据时也须先停止。

```sh
sudo systemctl stop photon
sudo install -d -m 0700 /var/backups/photon-before-rc9
sudo cp -a /etc/photon /var/backups/photon-before-rc9/etc-photon
sudo cp -a /usr/local/bin/photon /usr/local/bin/photon-services /var/backups/photon-before-rc9/
sudo sh /tmp/photon-install-rc.sh --version v0.6.0-rc.9 --no-service
sudo systemctl start photon
photon version
sudo systemctl status photon --no-pager
```

备份步骤只在首次升级前执行一次，保留原始旧版快照，勿用新版数据覆盖备份。
备份包含私钥，保持 root 私有。试用期间暂停该测试机的自动版本更新，避免切回正式版。

## 需要验证的行为

同一台机器先跑旧版、再跑新版，保持配置、对端、网络和负载相同：

| 场景 | 通过条件 |
| --- | --- |
| 基本联网 | 信息同步正常，IPv4/IPv6 双向实际流量可达 |
| 新旧混用 | 测试机运行新版，其他节点仍用旧版，正常同步和通信 |
| 重启及故障恢复 | 重启 Photon、strongSwan、BIRD，以及断网恢复后能自动恢复通信 |
| 授权更新 | 新授权生效，撤销后受影响的实际流量停止，其他节点不受影响 |
| 升级读取 | 旧版数据直接用于新版时，身份、授权和配置保留，无重复入网要求 |
| 持续运行 | 先跑 24 小时，定期传流量和重复故障恢复；发布前延长至 72 小时 |

记录每次故障发生、恢复连通的时间；记录丢包、CPU、内存和重启次数。
长时间运行应覆盖实际配置的密钥轮换周期，并检查轮换期间通信。
不能只根据进程 active 或 links 显示已连接判定成功；同时检查两端
`photon links`、`swanctl --list-sas`、实际路由和双向流量。
一台测试机只能验证新版与旧网的混合运行，不能替代全新版多节点组网验收。

故障注入放在专用测试节点；让节点断网或重启网络组件前，准备控制台或带外访问。
原始日志可用 `sudo journalctl -u photon --since '24 hours ago'` 导出，分享前去除敏感信息。

## 回退

本次未承诺新版写过的数据库可由旧版直接读取。回退应恢复旧程序及升级前数据，
会丢弃测试期间的本地变更；恢复后的节点仍需重新同步当前网络授权。
默认路径示例（先停止所有使用该数据库的服务）：

```sh
sudo systemctl stop photon
sudo mv /etc/photon /etc/photon-rc9-saved
sudo cp -a /var/backups/photon-before-rc9/etc-photon /etc/photon
sudo cp -a /var/backups/photon-before-rc9/photon /var/backups/photon-before-rc9/photon-services /usr/local/bin/
sudo systemctl start photon
photon version
```

`/etc/photon-rc9-saved` 必须尚不存在，保留新版数据供诊断。回退后再次确认真实通信，
必要时重启测试机清理运行中的网络状态，不只检查程序版本。

## 发布者检查

发布前执行 `make check`、`make smoke-all`、`make install-script-check`；
记录特权数据面测试、真实升级和长时间测试是否实际执行，不以基础检查替代它们。
GitHub Actions 必须提供两种 Linux 架构的归档和校验文件，Release 标记为
Pre-release，RC.9 Docker 镜像使用显式 `v0.6.0-rc.9` 标签，正式 `latest` 保持不变。
