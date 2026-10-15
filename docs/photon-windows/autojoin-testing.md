# Windows 首次自动入网

新机器配置根公钥、节点域名、bootstrap 和网络范围后，可以直接安装并启动服务。
数据库不存在时，服务生成本机独立身份并保存为待授权状态，通过 Gossip 同步父域授权。
身份只保存在本机 common 数据库中，GUI 和控制命令通过运行中的服务读取公开入网状态。

## 安装与授权

将构建包解压到管理员管理的固定目录，保留相邻的 `wintun.dll`。
复制 `config.example.yaml` 为 `config.yaml`，替换实际 `trusted_root_public_key`、
`managed_zone`、`gateway.bootstrap_hints`、网关 allowlist 和 split routes。
`state.path` 使用绝对路径，指向这个节点专用的数据库。

以管理员身份运行 `photon-windows.exe`，点击“安装服务”及“启动”。
首次启动会创建身份，界面显示入网进度和完整请求；点击“复制入网请求”交给管理该父域的管理员。
命令行也可读取同一运行状态：

```powershell
.\photon-windows.exe status --config C:\Photon\config.yaml
```

返回 `result.admission`，待授权时的 `join_request_b64` 是可交给上级管理员的请求，
包含节点域名和公钥，不包含私钥。管理员核对域名、公钥及拟授予权限后，
按现有 Linux Photon 委派流程签发授权；客户端不会自行替上级签发或分配 IP 前缀。

例如将请求保存为 `laptop.request.b64`，在具备对应父域签发权限的 Linux 节点上执行：

```sh
photon gossip delegate issue --permissions write laptop.request.b64 laptop.bundle.b64
```

Windows 会通过 Gossip 获取已签发的授权，无需再传回 bundle 或私钥文件。

服务同步并验证授权后完成身份接纳，自动继续现有网关发现、隧道和路由流程，无需重新导入或重启。
界面的“已入网”与“已连接”分别表示身份授权完成和业务隧道就绪；连接仍依赖实际网络、
网关传输记录、IPAM 分配和路由授权。

## 状态与兼容性

待授权期间保持 Gossip 和本机控制接口可用，不配置 Wintun、业务路由或隧道。
停止服务或重启机器保留同一节点身份，再次启动使用同一公钥；无需重新申请。
已有通过 `state import` 导入的数据库继续沿用，`state import` 仍可作为离线初始化方式。

只有缺失数据库时才执行初始化，已有损坏文件、root pin/节点域名不匹配或锁冲突均报错，
不会删除或重建身份。首次初始化要求有效 bootstrap；离线只读命令不会创建数据库。
Windows 新身份数据库在写入私钥前限制为本机 SYSTEM 和管理员访问。

协议诊断与请求构造由 `pkg/core/gossip` 负责，运行中同步与授权接纳沿用
`pkg/core/host.GossipDriver` 和 common State。Windows 负责初始化及界面展示，
不增加第二套 admission 状态或签发服务。

## 验收

复用完整网关夹具，启用独立 autojoin 场景；与 GUI 组合时，需要同一测试账号保持登录且 Explorer 运行：

```sh
PHOTON_WINDOWS_SSH=photon-test@10.16.252.11 \
PHOTON_LINUX_IP=10.16.255.8 \
PHOTON_BIRD_NIX_PACKAGE=/nix/store/<bird-package> \
PHOTON_IKE_AUTH_NIX_PACKAGE=/nix/store/<strongswan-package> \
PHOTON_WINDOWS_AUTOJOIN_SMOKE=1 PHOTON_WINDOWS_GUI_SMOKE=1 \
bash docs/scripts/windows-full-daemon-smoke.sh
```

该场景不生成或传输 Windows 身份数据库、私钥或导入 bundle。
Linux 使用隔离容器内的临时 authority，经生产控制接口先签发错误公钥授权，
Windows 验证拒绝后撤销并重新签发正确公钥的 `write` 授权。
父域签名、root pin、epoch、请求公钥和叶节点后续签名记录分别核对；不操作真实网络的授权。
双栈 host assignment 由夹具预先签发，验证首次入网不代表客户端能够自行分配 IP。

2026-10-15：Windows 11 amd64 `10.16.252.11` 的 `photon-test` Session 2 / Explorer 556，
对完整 Linux Photon gateway / StrongSwan 6.0.7 验收通过：

- 起点确认没有数据库。本机生成公开请求，GUI 能显示完整请求并通过原生按钮复制；剪贴板往返一致，
  结束时恢复测试前数据。请求使用共享的无填充 URL-safe Base64 JSON，四种既有兼容编码均有回归。
- pending 与错误公钥阶段均无 SA/Wintun/业务就绪，原因以中文显示，请求保持不变。
  正确授权为 epoch 2、公钥精确匹配且签名链/root pin 通过，首次入网保持 SCM PID 3508 和同一 Bolt file ID。
- 授权同步完成后自动继续建立 IKE/CHILD、Babel 和双栈业务；GUI 显示已入网/已连接并清空、隐藏请求及复制按钮。
  重启后 PID 1284，数据库文件与原公钥授权保持一致，真实双栈业务恢复。
- 窗口控件由程序发送消息操作，截图只捕获本次 GUI。三阶段截图已独立查看，中文、请求复制区和路由可读。
  后续原有 GUI、托盘、MTU 保存/重启、退出后服务存活，以及崩溃恢复、网络通知和外部网卡保护全部通过。
- 最终 `make check`、六包 race、Windows 两包 vet 通过；两包 Windows 原生测试 214 项通过，
  另有 10 项独立 opt-in 集成入口或子进程 helper 顶层跳过，不将这些跳过算作原生通过。
  缺失 bootstrap、错误 root/zone、损坏/空文件不覆盖、并发初始化、公钥稳定和实际受限 token 拒读均有回归。

实测暴露并修复共享拒收缓存中的临时条件问题：未来生效的撤销、未到齐的父域授权此前会被同一 digest
拒收 10 分钟。现在仍严格返回验证失败，类型化的暂时条件由原调度重试；真正坏签名继续使用原拒收 TTL。
真实 Store 与目录过滤组合回归覆盖同 root 在时间推进/父域到齐后成功，以及坏签名仍被缓存。
本轮 VM 比 Linux 慢约 3.5 秒，保留双方 UTC 记录，未修改系统时间或放宽校验；
实际日志包含未来撤销拒绝，随后同进程 `auto_join_adopted`，证明重试实际生效。

公开证据位于 `build/validation/windows-autojoin-20261015/accepted-desktop/`，包含
`autojoin-smoke.json`、`autojoin-restart.json`、三阶段截图、公开请求及签名 bundle、时钟和生产 CLI 日志。
同级 `native-accepted.log`、`make-check-accepted.log`、`race-accepted.log`、
`windows-vet-accepted.log` 与 `cleanup.log` 分别记录最终原生、全仓、并发和独立清理。
前两次实际运行的请求格式失败与临时拒收缓存失败，分别完整保存在
`failed-request-format/` 和 `failed-corrected-delegation/`，修复后完整重跑通过。
结束后确认本次服务、source、适配器、地址、路由、进程、计划任务、两端凭证和远端临时目录无残留。
