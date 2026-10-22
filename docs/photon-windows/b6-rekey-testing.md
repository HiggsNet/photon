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
