# B6 持续双栈业务中的重协商

完整 Linux daemon / Windows SCM rig 支持 `PHOTON_WINDOWS_REKEY_TRAFFIC=1`。
其余 SSH、LAN、BIRD、可选 StrongSwan 包参数沿用
[B6 完整入口](b6-testing.md)。测试不改变宿主防火墙、管理网卡或默认路由。
rekey、transport outage 与 baseline 模式互斥，各自独立运行，避免跨场景超时与采样干扰。

```sh
PHOTON_WINDOWS_SSH=photon-test@10.16.252.11 \
PHOTON_LINUX_IP=10.16.255.8 \
PHOTON_BIRD_NIX_PACKAGE=/nix/store/<bird-package> \
PHOTON_WINDOWS_REKEY_TRAFFIC=1 \
bash docs/scripts/windows-full-daemon-smoke.sh
```

## 门槛

首次双栈业务已通过后，两个独立 PowerShell job 各自保持一个绑定本机业务地址的
UDP socket，每轮发送独立随机 nonce 加递增序号，约每 50 毫秒一次。收包检查本轮 nonce、
序号范围和重复，每 500 毫秒保存累计发送/唯一接收计数。主进程持续采样 IPC，不能用
检查 IPC 时暂停发包的顺序探测替代持续流量。

Linux coordinator 仅通过本次容器的 VICI，先针对一个精确 CHILD ID、再针对一个精确
IKE ID 发起重协商。每次要求旧 ID 不再属于 `INSTALLED` / `ESTABLISHED` 集合、
出现唯一的新 ID，并确认另一层 SA 的公共 ID 保持不变。Windows 必须保持同一 SCM PID、
进程创建时刻、live generation、业务 readiness，且对应 lease 更新。
协商完成后保持原业务 socket 再运行两秒，最后另发新的双栈业务 nonce 验证。

当前连续性门槛是每族至少 20 个唯一回复、无应用层重复或错误 nonce、最大回复间隔
不超过 3 秒，结束时最后回复不超过 2 秒。该门槛不是无损或性能目标。
worker 有 150 秒总期限，coordinator 与每个协商等待也有明确期限；失败和正常路径均
停止本次 jobs，沿既有入口移除临时服务和容器，不保留密钥或数据库。

## 2026-10-09 实测

Windows 11 amd64、默认 Linux proposal、完整生产 gateway daemon 与 SCM：

| StrongSwan | 同进程 PID / generation | IPv4 发送 / 唯一回复 | IPv6 发送 / 唯一回复 | IPv4 / IPv6 最大回复间隔 |
| --- | --- | --- | --- | --- |
| 5.9.13 | 388 / 3 | 155 / 51 | 154 / 50 | 1360 / 1605 ms |
| 6.0.7 | 4252 / 3 | 137 / 46 | 136 / 46 | 1253 / 988 ms |

两版均完成 CHILD 与 IKE 更替、保持另一层 SA、同进程及原 live generation，且无重复
回复；两轮脚本退出码均为 0，后续既有正常重启、崩溃恢复、地址通知与占名保护回归均通过。
该结果只通过上述有界连续性门槛，**存在显著收包缺口，不能称为无损重协商**。

每 500 毫秒样本显示，5.9.13 IPv4 在 CHILD 请求前已是发送 18 / 收到 8；6.0.7
相应前置样本为 9 / 5。CHILD 交换附近还分别出现约 1.4 秒和 1.3 秒收包停顿。
IKE 交换和交换完成后的样本继续增长，但发送与接收计数仍有差距，因此不能将全部缺口
归因于 rekey，也不能据此定位为加密、队列或网络丢包。worker 停止时没有额外 drain，
在低时延情况下可解释约最后一包在途，无法解释大部分缺口；还需与独立原生 Socket
基线及分层观测结合定位。所有原始计数保留，不调整统计口径掩盖损失。

公开证据保存在 `build/validation/b6-rekey-20261009/{ubuntu,nix}/`，其中
`rekey-traffic.json` 含阶段时刻、IPC 状态和每族逐窗口计数；`rekey-*-sas.txt`、
`rekey-*-command.txt` 记录公共 SA ID/SPI 和 VICI 操作结果，不导出会话密钥。
同时保留构建 commit/status、两端日志和完整服务回归证据。原临时目录分别为
`/tmp/photon-windows-full-daemon.KjcPrJ`、`/tmp/photon-windows-full-daemon.D4jdRQ`。

本切片未注入 loss/dup/reorder，没有验证 Windows 主动定时 rekey 的长期流量，
也不代替真实睡眠、多层 NAT、吞吐基线或 72h soak；B6 总里程碑保持未完成。

## 自动五分钟定时点验证（2026-10-23）

Windows 当前在建立或激活 CHILD 后 5 分钟主动换钥，CHILD 硬到期为 10 分钟；IKE
主动换钥为 30 分钟，硬到期为 1 小时。正常 CHILD 换钥应保留 IKE SA、传输 generation
和本机网卡；需要更换 ESP SPI 与密钥，并回收旧 CHILD。初次 IKE_AUTH 中的 CHILD
与后续 CREATE_CHILD_SA 的 KE/PFS 协商不同，因此仅验证初次连接不覆盖这个时点。

新增可选长测保留上述生产定时器，实际连续运行约 5 分 20 秒：

```sh
PHOTON_WINDOWS_TIMED_REKEY_SMOKE=1 \
GOMODCACHE=/home/herbertqiao/go/pkg/mod \
bash docs/scripts/ike-auth-smoke.sh
```

隔离容器中同时维护两条独立 IKE/ESP 隧道，每条约 10 个 ICMP probe/s；使用序号匹配
唯一回复，检查最大回复间隔、自动 CHILD 更替、旧 CHILD 回收、原 IKE SPI 和 generation
保持，以及另一连接不中断。默认快速 smoke 不执行这项长测。StrongSwan 包选择方式
沿用原入口。

真实 Windows → Linux 的同一检查通过现有跨主机入口启用：

```sh
PHOTON_WINDOWS_SSH=photon-test@10.16.252.11 \
PHOTON_LINUX_IP=10.16.255.8 \
PHOTON_WINDOWS_TIMED_REKEY_SMOKE=1 \
bash docs/scripts/windows-tunnel-cross-host-smoke.sh
```

该入口只为一次性容器发布指定的测试 UDP 端口，使用临时随机测试凭据，不安装 Windows
网卡、路由或服务；结束后移除两端临时凭据、程序、目录和容器。Windows 直接调用测试
程序，无需修改 PowerShell 执行策略。完整 Wintun/SCM 的长期业务仍属于独立验收范围。

### 本次发现与修复

修复前，portable 双连接和真实 Windows 11 跨主机测试在 StrongSwan 5.9.13、6.0.7
上均于约 5 分 10 秒报 `ike: unknown or repeated local CHILD Delete SPI`。第一次自动
CHILD 换钥成功，五秒后删除旧 CHILD；处理删除确认时再次解析 successor，错误地又把
已删除的 predecessor 排进删除队列，再过五秒触发生命周期失败。正式 `v0.6.1` 中也有
这段逻辑，单连接即可触发，不依赖多节点改动。

修复使 `ResolveChildRekey` 只对仍存在的 predecessor 返回 Delete 决策；对已激活的同一
CHILD 重复解析时保持原有效期，不因旧 CHILD 的清理确认延长密钥寿命。新增确定性
回归通过真实加密请求/回复复现先换钥、再 Delete、再解析 survivor 的顺序；快速互通
矩阵也检查删除不会重新排队、不会重置当前密钥期限。

修复后的实际自动五分钟长测结果：

| 客户端场景 | StrongSwan | 发送 / 唯一回复 | 最大回复间隔 |
| --- | --- | --- | --- |
| 真实 Windows 11 → 隔离 Linux | 5.9.13 | 3189 / 3189 | 101.96 ms |
| 真实 Windows 11 → 隔离 Linux | 6.0.7 | 3189 / 3189 | 110.76 ms |
| portable 双隧道，各条 | 5.9.13 | 各 3189 / 3189 | 最大 104.11 ms |
| portable 双隧道，各条 | 6.0.7 | 各 3189 / 3189 | 最大 114.15 ms |

每轮真实运行约 320 秒，保留生产定时器；全部无过期 probe、无重复、结束无 outstanding，
原 generation 与 IKE SPI 保持，CHILD SPI 更换且旧 CHILD 回收。5.9.13 使用既有认证
no-PFS 回退，6.0.7 使用 P-256；两版默认 Linux proposal 均未改窄。Windows 长测后
又完成 CHILD rekey/Delete 与 IKE rekey、各阶段的 Linux 内核 echo。

当前工作目录完整 `make check`、IKE/Windows race 和打包回归通过。公开日志与源码指纹
保存在忽略目录 `build/validation/windows-rekey-20261023/`；新测试包位于
`build/windows-mesh-rekey-20261023/`，标记为 `v0.6.1-mesh-rekey-dev`。尚未发布新正式版。
本次未启用 Wintun、SCM 或真实网卡路由，不将上述结果称为完整 Windows 业务长稳验收，
也未等待 30 分钟 IKE 自然定时点或执行 72h soak。
