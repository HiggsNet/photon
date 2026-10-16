# Windows 首次自动入网

新机器配置根公钥、节点域名、bootstrap 和网络范围后，可以直接从托盘启动连接。
数据库不存在时，Daemon 生成本机独立身份并保存为待授权状态，通过 Gossip 同步父域授权。
身份只保存在本机 common 数据库中，GUI 和控制命令通过运行实例读取公开入网状态。

## 安装与授权

将构建包解压到管理员管理的固定目录，保留相邻的 `wintun.dll`。
以管理员身份运行 `photon-windows.exe`，在“身份”页填写实际根公钥和节点域名；
在“网关与引导”页添加允许网关规则和引导节点，在“分流路由”页添加网段。
引导节点分开填写网关身份与 Gossip 地址。在“高级”页确认数据库绝对路径，
指向这个节点专用的数据库，点击“保存配置”。没有 `config.yaml` 时会自动进入首次配置。
具体字段含义见 [GUI 使用](gui-testing.md)。也可以继续复制 `config.example.yaml` 为
`config.yaml` 并编辑，已有配置会自动显示为表单。

点击“启动连接”，无需安装 Windows 服务。
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

Daemon 同步并验证授权后完成身份接纳，自动继续现有网关发现、隧道和路由流程，无需重新导入或重启。
界面的“已入网”与“已连接”分别表示身份授权完成和业务隧道就绪；连接仍依赖实际网络、
网关传输记录、IPAM 分配和路由授权。

## 状态与兼容性

待授权期间保持 Gossip 和本机控制接口可用，不配置 Wintun、业务路由或隧道。
停止连接或重启机器保留同一节点身份，再次启动使用同一公钥；无需重新申请。
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
PHOTON_WINDOWS_AUTOJOIN_SMOKE=1 PHOTON_WINDOWS_TRAY_SMOKE=1 \
bash docs/scripts/windows-full-daemon-smoke.sh
```

该场景不生成或传输 Windows 身份数据库、私钥或导入 bundle。
Linux 使用隔离容器内的临时 authority，经生产控制接口先签发错误公钥授权，
Windows 验证拒绝后撤销并重新签发正确公钥的 `write` 授权。
父域签名、root pin、epoch、请求公钥和叶节点后续签名记录分别核对；不操作真实网络的授权。
双栈 host assignment 由夹具预先签发，验证首次入网不代表客户端能够自行分配 IP。

以下为原 SCM GUI 的历史验收；当前托盘直接运行的验收见 [GUI 记录](gui-testing.md)。

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

## 2026-10-16 多域冷启动同步修复

用户日志显示跨页目录包含大量域时，多个子域先报 `parent zone authority is nil`，同时出现
`object pull per-peer inflight limit reached`；父域下载成功后没有对应应用记录，重启后才完成入网。
旧 FSM 每收到一页便同时启动该页所有拉取，超过共享执行器每 Peer 两个 stream 的限制；
子域在父域授权未应用时验证失败，会话提前结束，随后到达的父域结果可能失去当前会话槽位。

共享 FSM 现在先收齐目录，按域层级从浅到深调度。每会话最多两个 pull/apply/fallback 槽，
父域下载后仍占槽，直到收到验证应用 ACK 才放行更深层级。同层有稳定顺序并在完成后补位。
保留原有根 pin、签名、授权、目录漂移一次刷新、拒收缓存及 round 硬期限，不增加 wire 字段或第二个调度 owner。
这同时修复使用同一 FSM 的 Linux/Windows 冷同步；已入网节点继续沿用原身份。

真实签名、pending identity、Store 和 Driver 的确定性回归将 24 个子域放在第一页，根和父域放在后页，
使用真实四个 worker/每 Peer 两并发执行器；旧生产源码 overlay 重放稳定失败，修复后完成同进程接纳和全部域收敛。
另一个场景在父域提交后强制 round 超时，新一轮继续同步，已提交根/父域各只下载一次。
两个场景连续 20 次通过；FSM 回归覆盖分页收齐、同层补位、父域 ACK、UDP fallback 占槽、
queued digest reconciliation、坏父域终止及有限期限，既有目录漂移与真实坏签名回归保留。

最终全仓 `make check`、五包 race、Windows app/internal/Gossip vet 和两包 253 项交互原生测试通过。
完整隔离 Linux 网关与真实 Windows 桌面回归覆盖空数据库、错公钥拒绝、正确授权在同一 GUI 进程接纳、
双栈业务、启停重连、身份保持及日志/Peer/诊断显示；实际退出码为 0，独立 Windows/容器清理通过。
证据见 `build/validation/windows-diagnostics-20261016/` 的 `photon-cold-catalog-red.log`、
`photon-cold-catalog-core*.log`、`photon-cold-catalog-repeat.log`、`accepted-final-tray/`、
`full-tray-final.log`、`native-final-interactive.log`、`make-check-final.log`、`race-final.log` 和 `cleanup.log`。

多域确定性回归为隔离调度问题提高了 fixture 对象配额，不代表默认配额下的大目录吞吐或慢 WAN 单轮全量验收。
原 round 硬期限保持，大目录可能跨轮继续；未新增跨会话 worker generation，也未使用用户实际网络签发授权。
