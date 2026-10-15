# Windows B5 服务与控制接口

服务与 console 使用同一个 Daemon、GossipDriver、State 和资源关闭顺序。
SCM 的 Running 表示初始化完成；业务是否可用以实时 `tunnel_ready` 为准。
Windows 继续作为接入节点，仅一个 active gateway，不转发其他节点的流量。

## 管理命令

在管理员管理的目录准备可执行文件、相邻的固定版本 `wintun.dll` 和配置。
已有数据库继续恢复；数据库不存在时，服务首次启动生成本机身份并进入 [自动入网](autojoin-testing.md)，等待上级授权。
服务安装要求配置及 `state.path` 使用绝对路径，启动账号为 LocalSystem，默认手动启动。

```powershell
.\photon-windows.exe service install --config C:\Photon\config.yaml
.\photon-windows.exe service start
.\photon-windows.exe status --config C:\Photon\config.yaml
.\photon-windows.exe peers --config C:\Photon\config.yaml
.\photon-windows.exe routes --config C:\Photon\config.yaml
.\photon-windows.exe diagnostics --config C:\Photon\config.yaml
.\photon-windows.exe service stop
.\photon-windows.exe service remove
```

默认服务名 `PhotonWindows`；隔离实例的所有管理操作都应传相同 `--name`。
顶层 `stop --config <path>` 通过 IPC 等待 Daemon 释放资源；SCM stop 使用相同关闭流程。
移除服务要求先停止，只接受当前可执行文件安装的命令行及属于本产品的 Event Log source。
配置修改后重启，不提供 reload。

本机窗口和托盘使用同一套服务与 IPC，见 [GUI 使用与桌面验收](gui-testing.md)。

console 用 `run --console --config <path>`，同时提供相同 IPC。
`status` 等运行态命令不打开数据库，也不创建身份；没有运行实例时返回失败。
离线检查使用 `config validate`、`gateways`，后者仅检查已签名网关材料。

## IPC、观察与日志边界

v1 named pipe 根据数据库绝对路径生成名称，默认只允许本机 SYSTEM 与管理员。
服务端拒绝远程连接及第二个同名 owner；客户端核对服务端进程权限，并使用
SECURITY_IDENTIFICATION 防止服务端模拟客户端。每次连接一个请求，限制帧长度和五秒超时。

观察来自 Daemon 串行 owner，重新检查当前授权、IKE/CHILD 生命周期、Babel 邻居和实际安装的
Wintun/路由。返回已分离的公开 DTO，不导出私钥、原始包或数据库对象。
peer/route 结果最多各 256 项，并显式报告截断；peer pull 计数器有界。
固定维度的 running、tunnel_ready、live、数量和截断标记可作为指标输入，不按 peer/IP 建立指标标签。

文件日志位于 `state.path + ".log"`，单文件 8 MiB，保留三个轮转文件。
console 同时输出到 stderr；服务同时写 Application Event Log。两种输出先经过同一脱敏层，
过滤私钥、原始字节和敏感字段。固定 event id：生命周期 101–104、gossip 201–207、
gateway 301–302、隧道 401–405、leaf 501–505，未知事件 999；保留实际 severity。
Event Log source 使用安装时生成的 ownership 标记，拒绝接管现有 source。
已有日志文件超过上限或不是普通文件时拒绝打开，不删除或截断原文件。

## 可重复原生验收

复用 B4 的隔离 StrongSwan/BIRD 网关与临时签名身份，运行生产 CLI，而非模拟服务。
目标 Windows 账号需要管理员权限，Linux 需要 Docker NET_ADMIN；不改变管理网卡。

```sh
PHOTON_WINDOWS_SSH=photon-test@10.16.252.11 \
PHOTON_LINUX_IP=10.16.255.8 \
PHOTON_BIRD_NIX_PACKAGE=/nix/store/<bird-package> \
bash docs/scripts/windows-service-smoke.sh
```

可通过 `PHOTON_IKE_AUTH_NIX_PACKAGE` 选择另一版本 StrongSwan。
脚本传输本次临时数据库和隧道私钥，创建唯一测试服务名、Event Log source、Wintun 和 split routes。
结束后删除本次服务/source、网络资源、两端凭证与测试文件；保留不含凭证的验收日志。
Event Log 中本次产生的历史事件保留，不清空系统 Application 日志。

原生管道测试 `^TestControlNative` 独立覆盖实际 ACL、受限 token、独占 owner、服务端身份验证、
stop 应答、OVERLAPPED 取消和慢请求。网络通知测试沿用 B2 的真实 IP Helper 回调验收。
以上不代替 B6 的物理断网、睡眠恢复、崩溃恢复、长时间压力与发布验收。

## 2026-10-07 实测

Windows 11 amd64 VM 对 StrongSwan 5.9.13 和 6.0.7 两轮完整服务验收通过：

- 安装为 LocalSystem/manual，初始 `running=true, tunnel_ready=false`；双栈业务通过后 readiness 为 true。
- 首次启动及停止后重启都通过 IPv4/IPv6 真实 UDP echo，状态和诊断显示实际 Wintun、SA、Babel 与两条授权路由。
- 首轮 SCM stop、第二轮 IPC stop 均等待关闭完成；停止后 runtime 查询返回失败。
- 每次启动/正常关闭产生 Information 101/103；缺失数据库启动产生 Error 102，SCM 返回非零失败。
- 已存在的 Event Log source 导致安装失败；本次 SCM 注册回滚，原 source 不变。
- 两轮结束均确认临时服务、source、适配器、地址、路由及凭证已移除。

第二轮同时保留公开 IPC DTO、Event Log 记录和脱敏文件日志供核对。
Windows 原生管道测试确认管理员/SYSTEM ACL、实际受限 token 拒绝、同名 owner 拒绝、
低权限进程抢占名称后的客户端拒绝、停止应答、取消与超时均通过。
IP Helper 三类通知测试及日志用例也在同一 VM 通过；通知进入 Daemon 后完成重绑。
本地 `make check`（fmt、vet、全仓测试、Linux build、Windows cross-build）和 Windows `go vet` 通过。
原生结果与交叉编译结果分别记录，不将 cross-build 当作原生服务验收。

随后 B6 扩展了同一入口：默认从 Linux gateway 真实同步初始缺失的签名记录，并强制结束本次
SCM 进程后重启；这些增量验收与后续边界见 [B6 分层验收](b6-testing.md)。
`docs/scripts/windows-full-daemon-smoke.sh` 则将 Linux 端换为完整 `app/photon daemon`，
沿用同样参数，在 StrongSwan 5.9.13/6.0.7 上通过签名同步、动态双栈回程及完整服务恢复场景。
