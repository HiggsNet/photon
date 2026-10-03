# Windows 原生测试

在 Linux 开发机编译测试包，复制到 Windows 11 amd64，通过 PowerShell 执行。
Windows 不需要安装 Go。测试使用临时数据库和 loopback 临时端口，不配置路由、
防火墙、Wintun 或系统服务。

## 执行

在仓库根目录运行（模块缓存可通过 `GOMODCACHE` 指定）：

```sh
bash docs/scripts/windows-native-smoke-build.sh
```

脚本输出独立测试包路径，内含四个测试程序（composition、CLI、IKE、ESP）、第三方 notice、公开配置样例、PowerShell 入口、
源码 commit 和工作树状态。将整个目录复制到 Windows，例如：

```sh
scp -r /tmp/photon-windows-native.XXXXXX user@windows-host:C:/photon-test/
ssh user@windows-host 'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\photon-test\photon-windows-native.XXXXXX\run.ps1'
```

替换目录后缀及 SSH 地址；目标父目录需已存在。`ExecutionPolicy Bypass` 仅作用于该进程。
入口在任一测试包失败时返回非零，每包超时 120 秒；运行目录保留原仓库结构，
以便 CLI 测试读取配置样例。PowerShell 中 Go 测试参数加引号，避免带点的参数被拆开。

## 2026-10-01 验证结果

基于 `fcc2ba0` 的 Go 代码，在 Windows 11 amd64 VM、OS build `10.0.26200.0`、
Windows PowerShell 5.1 下执行，两个测试包全部通过：

- 配置校验、CLI 参数与版本输出。
- common State 恢复、root pin 不匹配拒绝、旧格式拒绝和 BoltStore 独占。
- 公共 GossipDriver 收敛与恢复。
- IPv4/IPv6 loopback 两节点真实 UDP Gossip/TCP object-pull、数据库落盘与原端口重启。
- TCP bind 失败后的 UDP/数据库释放，以及 context 取消解除阻塞 TCP read。

实际 socket 收敛与恢复测试合计约 0.16 秒。日志出现两次包级 `PASS`。
这是 Windows 原生功能测试，不是 Windows race 检查，也不覆盖进程级 Ctrl+C、
跨主机 Linux/Windows 互通、自动 rebind、网络切换、IKE/ESP、Wintun、路由或 SCM。
测试账号具有管理员权限，因此也未验证普通用户运行。

## 首次初始化

准备 Windows 配置，固定 `managed_zone` 和从可信管理渠道获得的 `trusted_root_public_key`。
`state.path` 应位于管理员管理的目录，且目标文件必须不存在。导入命令不覆盖或刷新已有数据库。

使用现有 Linux Photon CLI 创建该 Windows 节点的独立密钥及请求：

```sh
photon gossip keygen laptop.key.json
photon gossip join request laptop-a.catofes. laptop.key.json laptop.request.b64
```

将请求交给管理 `catofes.` 的授权节点，按已有 Linux 配置选择父节点身份后签发：

```sh
photon gossip delegate issue laptop.request.b64 laptop.bundle.b64
```

将 bundle 和该节点密钥放到 Windows 管理目录后运行：

```powershell
.\photon-windows.exe state import --config .\config.yaml --bundle .\laptop.bundle.b64 --key .\laptop.key.json
.\photon-windows.exe run --console --config .\config.yaml
```

bundle 文件支持 JSON 和 Base64 JSON，沿用 Linux 格式；私钥文件沿用
`photon.ed25519.private.v1` JSON 格式。私钥直接保存在 common bbolt，由管理员管理文件访问权限，
不增加本地加密层。不要复制仍在运行的 Linux 节点密钥来冒充新 Windows 节点。

导入先验证完整授权链，再创建数据库；root pin/zone 不符、签名损坏、过期授权、未授权密钥、
私钥 seed 不一致、额外 zone/record 和重复导入均被拒绝。正常错误会清理本次新建的数据库；
若进程在写入期间被强制结束，目标可能残留，重试仍拒绝覆盖，需管理员确认后处理。
首次导入完成不代表已建隧道；后续 Gossip 使用配置中的 bootstrap hints。

停止 console 后可检查网关传输材料：

```powershell
.\photon-windows.exe gateways --config .\config.yaml
```

结果包含每个 allowlist zone 的候选 IP contacts 或拒绝原因、verified revision 和评估时间。
仅有 bootstrap hint 或尚未同步网关记录时会显示拒绝，这不是导入失败。
该命令不解析 DNS、不测试连通性、不建立隧道或授予路由权限。

## B2 在线生命周期与跨主机验收

2026-10-02 原生测试增加在线 gateway DNS/授权事实规划、过期 completion 丢弃、取消、
IPv4/IPv6 同端口连续重绑、失败 bind 恢复、socket 故障恢复和 Windows IP Helper 通知。
通知测试请求真实 OS 初始回调，经 Daemon event loop 触发重绑，再读取同端口对象；
不修改 VM 管理地址。这不等于物理断网、睡眠恢复或数据面撤销验收。

跨主机 rig 需要 Linux 和 Windows 互相可达的空闲 UDP/TCP 端口。Linux 防火墙须已放行该端口；
脚本不修改 Linux 防火墙。Windows 测试账号需管理员权限，脚本创建只允许指定 Linux 来源
和测试端口的临时规则，结束时清理。Windows 只需 OpenSSH/PowerShell，不需 Go。

```sh
PHOTON_WINDOWS_SSH=photon-test@10.16.252.11 \
PHOTON_LINUX_IP=10.16.255.8 PHOTON_WINDOWS_IP=10.16.252.11 \
PHOTON_CROSS_PORT=5201 bash docs/scripts/windows-cross-host-smoke.sh
```

按实际设备替换地址/端口；脚本编译当前工作树、生成隔离测试身份和数据库、上传 helper。
Windows 初始数据库缺少 Linux 节点对象，真实 Gossip 同步后落盘，停止再同端口重启；
禁用 bootstrap 后由 Linux 反向 TCP 读取恢复对象，最后再次打开 Windows DB 检查 revision。
已验证 revision `11 → 12 → 12`。脚本输出日志目录，清理两端测试身份、Windows 临时规则和目录。
这些是同一公共控制面在两种 OS 上的互通证据，不是 StrongSwan/IKE/ESP 隧道验收。
