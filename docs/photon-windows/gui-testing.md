# Windows 本机界面与托盘

同一个 `photon-windows.exe` 提供 CLI、原生窗口和托盘。界面复用现有 SCM 与本机
named pipe，不运行第二个 Daemon，也不打开服务数据库。

## 使用

在管理员管理的目录准备 `photon-windows.exe`、相邻的固定版本 `wintun.dll` 和实际配置。
示例配置见 [config.example.yaml](config.example.yaml)，其中的公钥、域名、地址都需要替换。
数据库不存在时，首次启动自动生成本机身份并等待上级授权，见 [自动入网](autojoin-testing.md)。

右键可执行文件，选择“以管理员身份运行”，无参数启动默认进入窗口，读取可执行文件
旁的 `config.yaml`。也可以在管理员 PowerShell 指定已有配置与服务名：

```powershell
.\photon-windows.exe gui --config C:\Photon\config.yaml --name PhotonWindows
```

默认服务名为 `PhotonWindows`，隔离实例必须使用对应的 `--name`。已有 CLI 命令仍可使用。
目录、配置、数据库及 driver 应由管理员管理；界面沿用现有管理员权限要求，不自动提权。

- 窗口显示服务状态、业务连接状态、活动网关和实时 Babel 路由。服务 Running 与业务
  隧道 ready 分开显示；服务停止或 IPC 读取失败时清除旧网关与路由。
- “安装服务”安装当前可执行文件和配置；“启动”“停止”“重启服务”管理这个实例。
  只接受与当前 executable、配置及 LocalSystem 服务账号匹配的服务。
- 首次启动显示入网进度与可复制的入网请求，授权同步后自动继续连接。已入网与业务已连接分别展示。
- 关闭窗口隐藏到托盘；托盘可以打开窗口、启动、停止和退出界面。退出界面保留后台服务。
  托盘不可用时关闭窗口会退出界面。
- 基础配置是 YAML 文本编辑框。保存前严格校验字段及绝对 `state.path`；无效配置不落盘。
  保存使用同目录临时文件及原子替换，并保留原 DACL。检查已发生的外部内容/文件身份变更，
  此时需“重新读取”后再编辑；这不是针对并发恶意写入的原子 compare-and-swap。
  保存后明确点击“重启服务”生效，不自动重启，不提供热重载。

缺失配置时可以在界面粘贴完整有效配置后保存，再安装和启动服务。
已有身份数据库继续沿用，首次离线导入也可使用现有 `state import` 命令。

## 可重复验收

portable 测试覆盖参数、配置校验、外部变更、状态解析及路由文本；Windows 原生测试额外覆盖
Win32 ABI、真实控件、DACL 保留、原子替换失败保护、服务 ownership 及管道进程身份绑定。
原生控件测试可以在 SSH 的非交互会话运行，不能据此认定托盘已在 Explorer 中出现。

完整桌面场景需要测试账号以控制台方式登录 Windows，保持解锁且 Explorer 运行。
SSH 使用同一账号。通过一次性 InteractiveToken/Highest 计划任务在该用户桌面运行夹具，
任务无持久触发器，结束后注销，只操作本次唯一命名的测试服务和本次 GUI。

```sh
PHOTON_WINDOWS_SSH=photon-test@10.16.252.11 \
PHOTON_LINUX_IP=10.16.255.8 \
PHOTON_BIRD_NIX_PACKAGE=/nix/store/<bird-package> \
PHOTON_IKE_AUTH_NIX_PACKAGE=/nix/store/<strongswan-package> \
PHOTON_WINDOWS_GUI_SMOKE=1 \
bash docs/scripts/windows-full-daemon-smoke.sh
```

沿用完整 Linux Photon gateway、临时签名身份和真实 Windows SCM/Wintun/双栈业务。
GUI 场景读取真实控件，发送 Win32 控件消息，核对 IPC DTO 与 SCM 进程，保存仅针对本次窗口的
PrintWindow 截图。覆盖停止清空状态、启动恢复、非法 YAML 拒绝、MTU 1400→1360 保存不重启、
重启应用 MTU、退出界面后双栈通信继续。托盘检查核对本次 HWND/ID 的 Explorer 图标矩形，
恢复检查只删除自己的图标并模拟 `TaskbarCreated`，不重启 Explorer。

结束后继续既有服务回归，并删除本次服务、Event Log source、适配器、地址、路由、凭证和
一次性计划任务。系统 Application 历史事件保留，不清空日志。

## 2026-10-15 验收记录

Windows 11 amd64 VM `10.16.252.11` 的 `photon-test` 已登录 Session 2，
同会话 Explorer PID 556。对完整 Linux Photon gateway / StrongSwan 6.0.7 验收通过。
身份与地址为本次隔离夹具生成，Windows SCM、Wintun、IKE/ESP、网关和双栈 UDP 通信均真实运行。
控件由程序发送消息操作，截图经独立查看，中文、路由和配置区域可读，无控件裁切。

- 连接窗口显示实际 `gateway.catofes.` 与两条双栈路由；停止后清空网关和路由，启动恢复。
- Explorer 中本次托盘图标存在，窗口关闭隐藏、托盘命令重新打开及自身图标重建通过。
  图标恢复仅模拟 `TaskbarCreated`，没有真实重启 Explorer。
- 非法 YAML 未改变原配置字节；合法保存不改变服务 PID。重启后 PID 更新，接口 24 的
  IPv4/IPv6 `NlMtu` 均为 1360，双栈业务通过。GUI 实际退出码为 0，后台 PID 保持不变，
  退出后的双栈业务再次通过；一次性计划任务实际退出码也为 0。
- 后续既有服务回归覆盖正常 SCM/IPC 停止、同 Bolt 崩溃恢复、地址通知重绑、缺失数据库失败、
  Event Log source 冲突和外部网卡占名保护及恢复。预期失败负例不计作运行故障。
- 最终源码 `make check`、两包 race、两包 Windows vet 通过；Windows 原生测试 25 项通过，
  一个仅供子进程调用的 helper 顶层跳过，其行为已由父测试实际执行。

本地公开证据保留在 `build/validation/windows-gui-20261015/`：
`accepted-desktop/` 为通过轮，`native-final-source.log`、`make-check-final.log`、
`race-final.log`、`windows-vet-final.log` 分别记录原生、全仓、并发与 Windows vet。
前两次桌面运行分别因夹具误用 PowerShell MTU 属性及未提前持有进程 handle 导致退出码为空而失败，
原件分别保存在 `failed-mtu-property/`、`failed-exit-observation/`；修正后完整重跑通过，
没有将部分成功当作整轮通过。原生测试准备时的输入模拟/相对资源路径、错误 runner 路径及
全仓 Windows vet 遇到既有 Linux-only BIRD 代码的日志也保留；Windows vet 通过范围是本次两包。

独立复核确认本次服务、source、适配器、地址、路由、进程、计划任务和远端夹具目录无残留。
本次 GUI 范围完成；B6 的物理睡眠/断网、72h soak 和发布门槛继续独立推进。
