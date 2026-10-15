# Windows B6 分层验收

B6 按可重复的独立场景推进，不以一次完整脚本通过代替睡眠、断网、长期稳定性和发布验收。
Windows 保持 leaf 接入节点、一个 active gateway、split tunnel，不增加转发功能。

## 当前 rig 的边界

`docs/scripts/windows-service-smoke.sh` 运行生产 Windows CLI/SCM 入口，Linux 容器运行真实
StrongSwan、BIRD，以及 Photon 的生产 StrongSwanDriver、GossipDriver 和 object-pull 服务。
Linux 端仍是隔离 fixture，没有启动完整 `app/photon` gateway daemon。
这一入口保留为组件分层对照；完整产品入口另见下节。

入口沿用 [服务验收](service-testing.md) 的 SSH、Linux LAN 地址、BIRD 和可选 StrongSwan 参数。
默认开启远程 Gossip，额外发布 `PHOTON_WINDOWS_GOSSIP_PORT`（默认 15201）的 UDP/TCP；
脚本要求端口空闲，不修改管理网卡或默认路由。`PHOTON_WINDOWS_B6_GOSSIP=0` 可仅运行静态快照场景。
临时数据库和私钥只用于本次隔离测试，结束后清理。公开日志、DTO 和事件记录保留。

### 完整 Linux gateway 入口

`docs/scripts/windows-full-daemon-smoke.sh` 使用同样的 SSH、Linux LAN、BIRD 与 StrongSwan 参数，
固定运行 Windows SCM/CLI 对真实 `app/photon daemon`。两端均从独立临时数据库启动；
准备程序在 daemon 启动前关闭数据库，没有共用文件的第二 writer，也没有额外文件锁。
bbolt 自带排他锁，在线观测通过 daemon 控制接口读取。

Linux daemon 负责真实 Gossip/object-pull、StrongSwan 连接、XFRM 创建、BIRD 生成/启动及签名
Babel 身份发布。辅助程序只生成临时初始材料、提供 UDP echo 和只读观测，不运行控制面 sidecar。
脚本仅向容器 `lo` 添加 gateway 自身获授权的业务地址，不安装 Windows 静态回程。

开始 Windows 业务前，必须确认 Linux 控制接口在线，实际 BIRD 的本地完整 Router ID 与 daemon
签名记录相符，并确认保留预设的容器端口映射。Windows 初始缺少该网关身份，需真实远程同步。
Windows 自己签发本地路由公告，Linux 再通过 Gossip 获取授权、Babel 学习并安装两个精确 host 回程；
验收要求两条内核路由均为 `proto bird` 且指向实际 XFRM 接口，BIRD 查询显式覆盖全部表。

容器使用独立 bridge、`NET_ADMIN` 和 `systempaths=unconfined`，后者允许生产 XFRM driver
写本容器网络 sysctl；不使用 host network、privileged 或宿主 `/proc` 挂载。
`/nix/store` 只读挂载用于固定 BIRD/StrongSwan。最终先停止本容器 daemon，再关闭 charon，
复制公开配置/日志/DTO 后移除容器和远端临时目录，不保留私钥和数据库。

2026-10-07，Windows 11 amd64 对 StrongSwan 5.9.13 和 6.0.7 的完整入口均通过。
两版均观察到 Windows verified revision `3 → 7`、gateway 成功 pull 2 次；Linux 的两个
精确 host 回程均为 `proto bird` 并指向实际 `phx...` XFRM 接口。初始、正常重启、强制结束后
同 Bolt/新 SA、地址新增/删除、外部占名失败及解除后恢复的双栈业务全部通过。
公开证据新增 `linux-status.txt`、`linux-identity.json`、`linux-ports.json`、`linux-routes.txt`、
`linux-xfrm.txt`、`bird-entries.txt`、`bird-routes.txt` 和 `daemon.log`。

| StrongSwan | 完整入口网络变化 generation | 新增后观察到业务恢复 | 删除后观察到业务恢复 |
| --- | --- | --- | --- |
| 5.9.13 | 3 → 7 → 11 | 6.71 秒 | 8.17 秒 |
| 6.0.7 | 3 → 7 → 11 | 7.19 秒 | 7.97 秒 |

以上仍是单次全链路观察总耗时，不作为本机期限或性能基线。
完整联测同时修复了两个生产问题：顶层默认 namespace 未传给 XFRM driver，导致 host 配置
误落入默认 named namespace；双栈静态路由混用一个 BIRD static protocol，导致真实解析失败。
默认 namespace 现在由已解析配置传给 driver；静态协议分别生成稳定的 `_v4`、`_v6` 名称，
保留各自路由与过滤语义。配置到实际 driver 命令链、BIRD 真实配置解析和上述双版本业务均通过。

## 已完成场景

2026-10-07，Windows 11 amd64 对 StrongSwan 5.9.13 和 6.0.7 的远程 Gossip 与强制结束后重启通过：

1. Linux gateway 持有完整签名状态，Windows 初始数据库故意缺少 gateway 的
   `routing/babel/identities`，业务 readiness 必须等待远程恢复该记录。
2. SCM 运行期间真实 UDP Gossip/TCP object-pull 完成；实测 verified revision `4 → 6`，
   gateway peer 的成功 pull 计数为 1，随后双栈业务通过。
3. 正常停止重开保持数据库；在已通过业务的第二次运行中，只强制结束经 SCM PID、
   创建时刻和 executable/config 验证的本次进程。
4. SCM 报告异常停止 1067，未产生正常关闭事件 103；此 VM 上崩溃后的临时 adapter 数为 0。
5. 同一个服务、配置和 Bolt 文件重新启动，重新协商 IKE/CHILD；新进程、两 SA lease 与双栈 echo
   共同证明恢复。进程内 generation 数值可重置，不作为跨进程递增计数。
6. 最终 IPC stop、初始化失败、Event Log source 冲突回滚及服务/source/adapter/address/route 清理通过。

公开证据包括 `gossip-evidence.json`、`gossip-convergence.json`、`crash-recovery.json`、
崩溃前后的 `*-owned-network.json`、各阶段 IPC DTO、Event Log 和文件日志。

### 真实网络通知与同进程重绑

仅向唯一 type-24 loopback 新增此前不存在的随机 `192.0.2.X/32` 地址，设置
`SkipAsSource=true`、`ActiveStore`，不修改管理网卡、默认路由或其他地址。
新增和删除分别触发真实 IP Helper 通知；两次都要求同一 SCM PID 的 generation 增加、
IKE/CHILD lease 更新并恢复双栈 echo。最终精确移除本次地址并检查对应 host route 消失。

| StrongSwan | 同一进程 generation | 新增后观察到业务恢复 | 删除后观察到业务恢复 |
| --- | --- | --- | --- |
| 5.9.13 | 3 → 7 → 11 | 21.98 秒 | 18.16 秒 |
| 6.0.7 | 3 → 7 → 11 | 21.94 秒 | 18.37 秒 |

随后包含外部占名场景的 6.0.7 整轮回归也通过，新增/删除分别为 25.94/21.05 秒；
这些单次观察值不作为性能基线。

这是包含 PowerShell 操作、远端协商及 Babel 收敛的观察总耗时，不是通知 API 时延，
不代替设计中的本机处理期限测量。公开记录在 `network-change.json`；网关日志记录了
初次启动、正常重启、崩溃恢复和两次网络变化后各自独立的 SA/SPI。
此项验证实际 OS 配置通知，仍不等同物理网卡断开、Wi-Fi 切换或睡眠恢复。

### 地址未变时的恢复通知

Windows composition 现在通过 `PowerRegisterSuspendResumeNotification` 订阅电源恢复。
仅自动恢复事件 `PBT_APMRESUMEAUTOMATIC` 投递到容量为 1 的队列，忽略随后代表用户交互的
`PBT_APMRESUMESUSPEND`，避免同次唤醒重复拆连接。回调不操作网络；composition 复用现有
停止 leaf/旧 SA、重绑 socket、重新规划并认证的串行流程，原地址/路由不变也会触发。
注册或注销错误传播为运行失败；注销失败保留已停用的回调上下文，避免释放 Windows 仍可能引用的内存。
参见 [注册 API](https://learn.microsoft.com/en-us/windows/win32/api/powerbase/nf-powerbase-powerregistersuspendresumenotification)
及 [恢复事件语义](https://learn.microsoft.com/en-us/windows/win32/power/pbt-apmresumeautomatic)。

2026-10-07，Windows 11 amd64 原生通过真实 API 注册/注销、模拟错误、并发回调/关闭和
真实注册到 synthetic resume callback、同地址 daemon 重绑及 object-pull 恢复的接线测试；
portable focused race、Windows vet/cross-build 和全仓 `make check` 也通过。
测试不改变机器电源状态，没有验证真实睡眠、休眠、Modern Standby 或醒来后的真实 ESP 业务。
这些场景仍是独立验收门槛。MOBIKE 保持关闭，也未改变端口 generation/rotate。
同日只读 `powercfg /a` 确认当前 VM 的 S1/S2/S3、休眠和 S0 低功耗待机均不可用；
真实恢复场景需另用支持对应电源状态、且具备独立唤醒手段的环境，不在此 VM 上强行模拟验收。

### 隔离网关传输中断与同进程恢复

完整 daemon 入口另设可选的 `PHOTON_WINDOWS_TRANSPORT_OUTAGE=1`，同时指定已有的
`PHOTON_NFT_NIX_PACKAGE`，指向 `/nix/store` 下包含 `bin/nft` 的包。仅在本次 bridge 容器
创建唯一 nft 表，丢弃 `eth0` 上的 IKE/NAT-T/ESP；Gossip 保持可达，避免身份租约过期混淆
DPD。不会改动宿主 firewall、Windows 管理网卡、默认路由或 SSH。

Windows helper 与 Linux coordinator 用本次临时目录中的有期限 request/ack 协调，按以下门槛验收：

1. 阻断后，旧 IKE/CHILD 仍 live、业务仍 ready 时，双栈新 nonce 均发送成功但接收超时；
   探测前后均检查 live，不能把 adapter 已销毁导致的 bind 失败当作传输黑洞证据。
2. nft 分别统计非零 ESP SPI 的 UDP/4500 密文，要求两个方向均实际丢包；IKE 的零 marker、
   NAT keepalive 和短包不计入 ESP counter。原生 ESP 规则保留，但此场景实际走 NAT-T。
3. 保持同一 SCM PID、创建时刻和运行状态，在 90 秒观察上限内看到 Windows 的旧 IKE/CHILD
   均不 live、readiness 关闭，并要求本阶段新增生产日志明确报告 IKE 重传预算耗尽。
   非 live 的 IPC generation 为 0，不能误要求它比旧 live generation 大。
4. 删除本次精确 nft 表后，90 秒内恢复 live IKE/CHILD、更大的 live generation、两条新 lease
   和双栈业务；Linux `swanctl --list-sas` 的新 IKE/CHILD 公共 ID 共同确认实际重新建 SA。
   不要求断网期间远端立即删除尚未超时的旧 SA，也不以静态端口恢复冒充 MOBIKE。

公开证据保留 `transport-outage.json`（含 live 探测、状态采样、进程和 lease）、
`outage-nft.txt`、before/after SA 公共 ID/SPI 与 coordinator 日志，不导出会话密钥。
失败和正常路径均删除本次 nft 表，结束后清理临时服务、私钥、数据库和容器。
这覆盖隔离网关传输黑洞与 DPD 自动重连，不等同物理 Wi-Fi 切换、多层 NAT 或真实睡眠。

2026-10-07，Windows 11 amd64 对两个 StrongSwan 版本的上述门槛与完整服务回归均通过：

| StrongSwan | 同进程 PID | live generation | 阻断至观察到旧 SA 退役 | 恢复至验收完成 | NAT-T ESP 丢弃入/出 |
| --- | --- | --- | --- | --- | --- |
| 5.9.13 | 1432 | 3 → 6 | 33.41 秒 | 7.82 秒 | 15 / 11 包 |
| 6.0.7 | 1636 | 3 → 6 | 39.21 秒 | 6.46 秒 | 17 / 13 包 |

两版的早期双栈探测均为成功发送后接收超时，Linux 均出现新的 IKE/CHILD 公共 ID `#2`。
表中时间包含 IPC/SSH 观测与恢复后的业务检查，阻断发生在既有 DPD 周期的不同位置；
这些单次结果不是本机处理期限或性能基线。相同程序中的正常重启、强制结束重开、真实地址
新增/删除、外部占名失败及解除后恢复也通过。公开日志分别位于
`/tmp/photon-windows-full-daemon.9qKiFU`（5.9.13）和
`/tmp/photon-windows-full-daemon.Pag9Jm`（6.0.7）。

### 同名外部网卡保护

固定 Wintun 0.14.1 的创建便利函数会在名称冲突时重命名已有网卡。
产品现在先以随机内部 alias 创建新 GUID，再验证实际 GUID 并仅重命名本次新对象；
冲突返回错误，释放新对象，不接管或改名已有网卡。
Windows 原生 `TestWintunNativeForeignNamePreserved` 已确认大小写同名冲突时，
外部网卡的名称、GUID、双栈地址和 split routes 保持不变；失败创建释放资源，
只有外部 owner 关闭后才可复用其名字。原 Wintun ring 生命周期回归也通过。

本次没有新增资源 journal 或 stale adopt。Windows 11 本次软件适配器随创建进程结束释放的证据
不代表其他资源类型也可免于 ownership 验证。

崩溃验收还发现：网卡消失后，Windows 可能暂时保留名称并返回 `ERROR_DUP_NAME`。
该错误本身不证明有外部 owner。产品只在目标 alias 对应不同 GUID、且仍有实际 IP 接口时
分类为不可恢复冲突；仅 PnP/名称残留或观察失败继续现有 5 秒退避，不猜测归属或修改残留。
当前且仍匹配 request/revision/授权/generation 的致命冲突使 composition 清理后退出；
过期 completion 只清理自身设备，普通临时错误可重试。这些分支有 portable race 和 Windows 分类测试。
未证实存活外部接口的 `ERROR_DUP_NAME` 从首次当前命名失败起设置 30 秒恢复预算，仍每 5 秒重试。
重复失败、普通 Gossip revision 和过期 completion 不延长期限；当前成功、明确停止或期望变化才结束
本次恢复。恰好到期的成功结果也要关闭，超时沿既有 composition 清理后报告失败，不删除未知对象。
该预算只约束本机命名恢复，不代表设计中从 composition 启动起 30 秒的整个 crash-recovery 目标
已经完成；长期真实 PnP 残留仍需原生验收。

SCM 层的外部占名验收也在 StrongSwan 6.0.7 整轮回归通过：测试进程持有独立 Wintun
adapter，服务尝试使用其 alias，最终以 Win32 1066/service-specific 1 停止，记录一次
runtime failure 事件 104，没有正常停止事件 103；外部 alias/GUID 保持不变。
仅关闭测试进程持有的外部 adapter 后，同一服务、配置和 Bolt 文件重新启动，双栈业务恢复，
证明失败路径已释放控制管道和数据库。结果保存于 `adapter-conflict.json` 及对应事件/业务 DTO。

### IPC fuzz

新增真实外部输入边界的两入口，2026-10-07 各运行 15 秒通过：

- `FuzzControlFrame`：206,463 次，覆盖长度、截断、超限和短读。
- `FuzzControlRequestDispatch`：278,537 次，覆盖严格 JSON、重复/转义重复字段、版本、类型、
  额外字段、尾随内容及五种合法 method；无效请求不能调用 Observe/Stop。

代表性 seeds 进入普通回归，focused race 和 Windows 编译通过。短时运行不算持续 fuzz 完成；
SKF/Babel 长序列状态机、持续调度与更长 fuzz 仍有后续工作。

## 本轮回归

`make check` 的格式、vet、全仓测试、Linux build 和 Windows cross-build 通过；
Windows `go vet`、冲突处理 focused race、Windows 原生分类与 Wintun 生命周期测试通过。
服务完整场景在上述 VM 和两个 StrongSwan 版本分层执行，最后一轮 6.0.7 增加了外部占名
失败退出与恢复；之后仅调整脚本的进程创建时间采样诊断，Windows PowerShell 解析通过。
后续完整 Linux daemon 入口两版本也均通过，名称恢复期限的 fake-time/race、默认 namespace
配置/driver 回归及 BIRD 静态协议真实解析/包 race 通过；这些产品修复后的全仓 `make check` 通过。
结束后再次只读核查最后一轮临时服务、事件源、adapter、测试地址及 host route 均为零，
远端临时目录和 Linux 容器已删除。
电源恢复入口完成后的 `make check` 通过；随后同一构建对两版 StrongSwan 的最终传输黑洞
矩阵与完整服务回归通过。全部三轮本次隔离运行的临时服务、事件源、adapter、目录及精确
测试地址/host route 再次核查均为零，本地测试密钥、数据库和程序已清理。

## 2026-10-09 RC.5 合并与后续切片

`windows` 已包含当日 `origin/master`，另合并 Linux RC.5 `9f7e764a`：保留显式为空的
passive responder 角色，使 Linux gateway 被动端口轮换不错误回退为主动发起方。
合并提交 `a96c0b1b`，同时同步该 RC 的 VERSION 与测试说明；没有发布 Windows 版本。
IPsec race、全仓 `make check`、Windows composition 与 portable 五包 race 均通过。

本轮回归暴露首次随机共享端口的 UDP/TCP 可用性差异：UDP 选出的端口，TCP 可能被
占用或被 Windows 排除。首次 `:0` 绑定现在最多尝试 16 次，每次失败释放 UDP；
已配置或已公布的端口不重选，重绑仍保持原 endpoint。focused 五轮 race、独立审阅和
Windows 原生回归通过。此处未确定性注入连续 16 次 TCP 冲突，不将现场通过等同全部错误分支验证。

原生入口新增此前遗漏的 Babel/SADR 两包，Windows 11 amd64 六包共 239 个顶层测试
通过（含 13 个 fuzz seed suites）。新 [SKF 长序列 fuzz](skf-fuzz-testing.md) 覆盖
有状态认证分片、PMTU 重启、到期与失败恢复；短时探索不计作持续 fuzz 门槛完成。
全仓检查及原生日志保留在 `build/windows-b6-*`，避免只依赖可清理的 `/tmp`。

双版本完整网关的[持续流量重协商](b6-rekey-testing.md)已通过明确的有界连续性门槛；
原始发送/接收计数暴露明显缺口，后续须定位，不能称为无损切换。

[性能基线](baseline-testing.md)另以独立原生 Socket 负载计数：Nix strongSwan 6.0.7
完整测量，Ubuntu 5.9.13 部分测量保留。窗口 8 双栈约 0.20–0.21 Mbps，Windows
服务接近占满一个逻辑 CPU；窗口 64 暴露迟到与积压，每组之后另验证同进程双栈恢复。
这只是固定 echo 负载下的基线，不是饱和容量或性能达标；实际热点仍须 profile 定位。

## 2026-10-14 RC.6/RC.7 合并与 Windows 状态回归

在性能历史整理后的 `a2a2bbd1` 上合并已发布 `v0.6.0-rc.7`（`df8ec528`），
包含 RC.5 之后的五个提交；当日 `origin/master` 仍是旧版 `28472ea7`，已在 Windows
祖先中。36 个 RC 目标文件与标签逐字相同，原有 Windows 性能实现保留；VERSION
同步为 `0.6.0-rc.7`，这不是 Windows 发布或部署。

- RC.6：目录/快照期间首次 root mismatch 排空已有工作后刷新目录一次，不延长
  原 round deadline；签名错误或再次漂移仍拒绝。拒绝记录显示按当前时间过滤，
  成功验证可清除其他 peer 对同一摘要的拒绝。
- RC.7：Gossip discovery、zone/record responder 改用独立窄投影，保留授权链、
  历史版本选择、撤销和时间检查；共同状态按 zone 持久化，事务失败不发布部分状态。

新增 Windows `TestOpenStateUpgradesRC6CommonLayoutPreservingRevision`：真实签名
common fixture 使用 RC.6 aggregate/schema1，经 OpenState 升级后 verified 内容和
revision7 保留；再次启动数据库字节不变。公共迁移/zone delta/损坏拒绝/回滚回归保留，
Windows 按 store/revision 的授权缓存契约不变。

本次 `make check`（全仓 fmt/vet/test、Linux 构建、Windows amd64 交叉构建）、
state/gossip/host/inspect/Windows/app 七包 race，以及 `photon_profile` 两包测试和
Windows 采样构建通过。真实 Windows 普通 test executable 的 OpenState/PacketState/
PacketPolicy **22 项全部 RUN/PASS、无 skip，Go actual exit0**；原 PS 包装及采集 exit1
是 required-tests JSON 数组额外嵌套的解析失败，原 Completed=false/失败日志保留。
独立精确集合复核 exit0，没有重跑测试；原 PID/创建身份、精确 exe 和唯一目录独立清理
exit0，见 [原生分层证据](../../build/validation/rc-merge-20261014/native-state/post-native-validation.json)。
所有测试 DB 使用自有临时目录；本次没有业务隧道或新的吞吐/长期验收。

Common schema1 可读，启动原子升级到 schema2，单纯布局变化不推进 verified revision。
后续回退 RC.6 或更早程序时必须同时恢复升级前数据库，见
[RC.7 升级与回退边界](../new/linux-release-testing.md#rc7按-zone-存储与-schema-2-升级)。

## 尚未完成的门槛

2026-10-14 用户确认当前 Windows 性能可接受，剩余优化不再阻塞其他 B6 事项。
链路故障继续按独立场景推进，网关出站密文故障见
[丢包、重复与乱序验收](b6-impairment-testing.md)。

实际睡眠/恢复、物理换网与多层 NAT、
完整丢包/重复/乱序产品矩阵（网关出站单向场景已通过）、长期真实 PnP 残留及完整生命周期期限仍待补齐。
吞吐/CPU/内存已有上述短时基线，但热点优化与目标验收、72h soak、Authenticode、SBOM
和正式安装升级验收仍未完成。
当前分层验收不构成 Windows 正式发布。
