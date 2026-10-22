# 托盘崩溃与 PVE 虚拟网卡故障验收

本场景验证直接运行 Daemon 的 GUI/托盘，不用 SCM 的进程崩溃结果代替托盘验收。
网关、签名 authority、身份、数据库和 Photon 网卡均为每轮隔离夹具生成，不修改真实网络授权。
完整 Linux Photon gateway / StrongSwan 6.0.7 和 Windows Wintun、IKE/ESP、双栈 UDP 业务真实运行。

## 范围与恢复

PVE 操作刻意限定为 `root@10.16.255.200` 上的 `win11 / VMID 101 / net0`，
并核对 VirtIO MAC `BC:24:11:BE:0E:E0`。仅临时设置 `link_down=1`；不操作其他 VM、
宿主机桥接、存储、重启或电源，也不安装 Guest Agent。原 net0 完整字符串保存并原样恢复。
写入前拒绝 pending 配置、已有 link-down、错误身份或锁；恢复前拒绝外来 net0 改动。
恢复后核对 VM101 其他配置、其他 VM 配置以及宿主机网络和存储配置哈希。

断网前在 PVE 创建唯一的临时 systemd 恢复任务，45 秒后触发，不依赖 Windows 或本地协调进程。
正常协调器约 30 秒后恢复；异常退出也先恢复网卡，再收集与清理测试资源。
45 秒表示恢复任务的触发时间，并非恢复完成的硬期限。
正式断网前，`arm-only` 演练只保存快照、定时核对原值，不写 VM 配置。

Windows 桌面通过一次性 InteractiveToken/Highest 任务运行测试。
`-StartOnly` 注册并启动后立即结束 SSH；恢复后 `-CollectOnly` 验证同任务的用户 SID、
唯一名称、动作和完整参数，核对完成文件与实际任务退出码，再注销。
不以 SSH 重连或 PVE 配置已恢复代替 Photon 业务恢复。

## 运行

```sh
PHOTON_WINDOWS_SSH=photon-test@10.16.252.11 \
PHOTON_LINUX_IP=10.16.255.8 \
PHOTON_BIRD_NIX_PACKAGE=/nix/store/<bird-package> \
PHOTON_IKE_AUTH_NIX_PACKAGE=/nix/store/<strongswan-package> \
PHOTON_WINDOWS_TRAY_SMOKE=1 PHOTON_WINDOWS_AUTOJOIN_SMOKE=1 \
PHOTON_WINDOWS_GATEWAY_GLOB=1 PHOTON_WINDOWS_TRAY_FAULTS=1 \
PHOTON_PVE_SSH=root@10.16.255.200 PHOTON_PVE_VMID=101 \
bash docs/scripts/windows-full-daemon-smoke.sh
```

该选项默认关闭；普通托盘与 CLI 服务验收不触碰 PVE。
测试 hook 还需本次目录的 `fixture-tray-faults` 内容严格为 `1`，仅 helper 文件存在不启用。

## 验收断言

- 先验证完整托盘的首次配置、自动入网、授权错钥拒绝、启停、配置保存及换目录身份稳定。
- 对唯一自有 GUI 复核 PID、创建时间、exe/config、HWND 和保留的进程句柄，
  `TerminateProcess` 指定退出码 71，核实实际异常退出码，单独标为 `ExpectedForcedExit`。
  验证管道、原接口路由、网卡和数据库释放；同 exe/数据库新 GUI 显式启动后，
  身份与数据库文件 ID 不变、新 IKE/CHILD 生命周期及实际双栈业务恢复。
- 对按 MAC 唯一识别的物理网卡，记录 Up→非 Up→Up。
  断网期间两个地址族均尝试业务探测，必须无回包，且只接受明确的超时或原生网络错误；
  记录发送阶段、发送成功与否及原生错误码，其他测试异常不算业务中断证据。
- 恢复物理链路后，不点击启动或重新连接；要求原 GUI PID、创建时间、数据库和已入网身份稳定，
  自动恢复授权双栈路由与实际 UDP 回包。短断可能继续使用原 SA，不强制要求 SA 更换。
- 最终正常退出释放网络资源和数据库。强杀的异常退出不冒充正常退出码 0。
  `ObservedDownSeconds` 只统计 Windows 观察到的链路中断时间，不是完整业务恢复延迟。

## 未覆盖范围

本 VM 的 `powercfg /a` 报告 S1/S2/S3、休眠和 S0 低功耗待机均不可用。
本批不修改固件、电源或显卡配置来启用睡眠，也不把 PVE 暂停当作 Windows 睡眠。
本场景只覆盖同一虚拟网卡的链路中断，不代表物理 Wi-Fi 切换、多层 NAT、
真实笔记本睡眠、72h soak 或正式发布验收。

## 2026-10-15 实际结果

Windows 11 `photon-test` Session 2 / Explorer 556 对上述完整隔离网关验收通过，
整轮 rig、一次性任务及正常 GUI 实际退出码均为 0。产品代码没有因此修改。

- GUI 5736 被按保留句柄强制结束，实际退出码为预设的 71；管道、原接口路由及网卡消失，
  离线命令能打开原数据库。GUI 7296 使用同一 exe/config/数据库恢复，保持原文件 ID 和
  已入网身份，建立新 IKE/CHILD 生命周期并完成双栈业务。
- PVE 仅设置 VM101/net0 的 link-down，随后原样恢复。
  Windows 观察到相同 MAC 的 VirtIO 网卡 Up→Disconnected→Up，单调计时中断约 32.82 秒。
  两族断网探针实际在 Bind 阶段返回 `AddressNotAvailable / 10049`，未发送报文，
  表明该时刻原业务地址已不可用；不声称已发包超时或统计了断网期间的线上丢包率。
  GUI 7296 始终保持原创建时间，不点击重新连接，自动恢复真实 IPv4/IPv6 UDP 回包及授权路由。
- 保留观察：断网前 peer 的 `pull_state=completed`，恢复后的末次快照为 `failed`，
  日志包含 `round_timeout`，本轮未延长观察到下一次完整同步成功。
  强杀重开期间还有短暂适配器名称重复警告，随后自动恢复且业务通过。
  本批不声称 Gossip 全面健康或无警告；后续需单独验证恢复后的新一轮控制面同步。
- 最后 GUI 7296 正常退出，管道、原接口路由和网卡释放，数据库可离线读取。
  剪贴板恢复，两个原 Explorer 会话保留；旧停用服务登记保持原值，最后仅删除测试登记。
- 独立 `arm-only` 定时器演练确实自行触发，只核对配置而不写 VM 设置。
  最终 VM101 与其他 VM 运行状态/PID 保持，VM101/net0 恢复原字符串，其他 VM、宿主机
  网络和存储配置哈希一致；本轮临时定时器、宿主机目录、Windows 测试资源及网关容器无残留。

公开证据位于 `build/validation/windows-tray-faults-20261015/`：
`accepted-tray/tray-faults.json`、`tray-smoke.json`、`gui-session-result.json` 为实际业务与退出结果；
同目录 `pve-link-state.json`、`pve-link-events.jsonl`、`pve-link-coordinator.log` 为宿主机恢复证据。
`watchdog-accepted/` 保存最终脚本的独立定时器演练，`watchdog-before-arm-only-guard/` 保留先前演练原件。
Windows 与 PVE UTC 存在偏差，不跨机时间戳直接相减；链路中断时长取 Windows 单调计时。

`ast.log` 记录五个 PowerShell 5.1 文件解析及三个 C# helper 编译通过；`guard-check.log` 记录
Python 语法及 NIC 参数保留/拒绝检查，shell 语法与 diff 检查通过。
`accepted-sources.sha256`、`source-recheck.log` 对应真实验收的最终源码；
`cleanup.log`、`docker-cleanup.txt`、`pve-final.log` 是独立清理核对。
