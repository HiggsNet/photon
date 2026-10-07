# Windows B6 分层验收

B6 按可重复的独立场景推进，不以一次完整脚本通过代替睡眠、断网、长期稳定性和发布验收。
Windows 保持 leaf 接入节点、一个 active gateway、split tunnel，不增加转发功能。

## 当前 rig 的边界

`docs/scripts/windows-service-smoke.sh` 运行生产 Windows CLI/SCM 入口，Linux 容器运行真实
StrongSwan、BIRD，以及 Photon 的生产 StrongSwanDriver、GossipDriver 和 object-pull 服务。
Linux 端仍是隔离 fixture，没有启动完整 `app/photon` gateway daemon。
因此“完整 Linux Photon gateway 产品 rig”保持未完成，已有协议、资源和服务证据分别记录。

入口沿用 [服务验收](service-testing.md) 的 SSH、Linux LAN 地址、BIRD 和可选 StrongSwan 参数。
默认开启远程 Gossip，额外发布 `PHOTON_WINDOWS_GOSSIP_PORT`（默认 15201）的 UDP/TCP；
脚本要求端口空闲，不修改管理网卡或默认路由。`PHOTON_WINDOWS_B6_GOSSIP=0` 可仅运行静态快照场景。
临时数据库和私钥只用于本次隔离测试，结束后清理。公开日志、DTO 和事件记录保留。

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
长期无法确认归属的名称残留及失败期限仍需后续验收。

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
结束后再次只读核查最后一轮临时服务、事件源、adapter、测试地址及 host route 均为零，
远端临时目录和 Linux 容器已删除。

## 后续门槛

完整 Linux gateway daemon 的同 rig 验收、实际睡眠/恢复、物理换网与多层 NAT、
丢包/重复/乱序产品矩阵、长期 stale resource 残留及失败期限仍待补齐。
吞吐/CPU/内存基线、72h soak、Authenticode、SBOM 和正式安装升级验收也未完成。
当前分层验收不构成 Windows 正式发布。
