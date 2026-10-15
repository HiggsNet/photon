# Windows 本机界面与托盘

同一个 `photon-windows.exe` 提供 CLI、原生窗口和托盘。默认 GUI 在自身进程内管理一个
Photon Daemon，复用 console 的运行链路与本机 named pipe，不需要安装 Windows 服务。
窗口通过 IPC 读取公开状态，数据库和网络资源始终由同一个 Daemon 管理。

## 使用

在管理员管理的目录准备 `photon-windows.exe` 和相邻的固定版本 `wintun.dll`。
可以直接在界面填写配置，也可以继续使用已有配置文件。
示例配置见 [config.example.yaml](config.example.yaml)，其中的公钥、域名、地址都需要替换。
数据库不存在时，首次启动自动生成本机身份并等待上级授权，见 [自动入网](autojoin-testing.md)。

右键可执行文件，选择“以管理员身份运行”，无参数启动默认进入窗口，读取可执行文件
旁的 `config.yaml`。也可以在管理员 PowerShell 指定已有配置：

```powershell
.\photon-windows.exe gui --config C:\Photon\config.yaml
```

GUI 不再接受 `--name`，每个实例使用独立的配置和数据库路径。已有 CLI 服务命令仍可使用。
目录、配置、数据库及 driver 应由管理员管理；界面沿用现有管理员权限要求，不自动提权。

- 窗口显示运行状态、业务连接状态、活动网关和实时 Babel 路由。Daemon 运行与业务
  隧道 ready 分开显示；停止或 IPC 读取失败时清除旧网关与路由。
- “启动连接”“停止连接”“重新连接”管理本次托盘进程拥有的 Daemon。
  打开 GUI 不自动连接；运行中的配置使用启动时的快照，保存设置不会自动重启。
- 首次启动显示入网进度与可复制的入网请求，授权同步后自动继续连接。已入网与业务已连接分别展示。
- 关闭窗口隐藏到托盘；托盘可以打开窗口、启动、停止及停止连接后退出。
  退出会等待 Daemon 释放网络资源和数据库，不留下常驻子进程。
  托盘不可用时关闭窗口也走停止连接后退出流程。
- 配置分为“身份”“网关与引导”“分流路由”“高级”四页。
  身份页填写根公钥和本机节点域名；网关规则与分流网段通过列表添加、修改和删除，
  无需在文本框中手工维护每行一项。引导节点分别填写 Photon 网关身份与 `主机:端口`。
  身份是网关实际的 Photon peer/zone，例如 `gateway-a.catofes.`；地址是 Gossip 的 UDP/TCP
  端点，例如 `gateway.example.net:33434`，不是 IKE 的 500/4500 端口。
  允许网关支持完整身份和与 Linux 相同的 glob：
  `*` 匹配全部候选，`*.catofes.` 匹配 `gateway.catofes.`、`a.b.catofes.` 等，
  不包含 `catofes.` 自身。`.*` 是以点开头的 glob，不是正则的全匹配。
  按配置顺序展开候选，每个通配符的匹配结果按节点身份排序，重叠结果去重；
  现有单活动网关规则及完整身份/签名/传输授权校验保持不变。
  引导节点的身份始终填写具体节点，须被至少一条允许网关规则匹配。
  手工编辑 YAML 时将通配符加引号，例如 `allowed_zones: ['*.catofes.']`；表单保存自动处理引号。
- 高级页包含数据库路径、overlay ID、Gossip 监听、适配器名称、MTU、日志级别及重连间隔。
  从主窗口点击“打开设置”进入，切换设置页或关闭设置窗口保留尚未保存的编辑。
  保存前复用现有配置校验及绝对 `state.path` 检查，无效配置不落盘。
  保存使用同目录临时文件及原子替换，并保留原 DACL。检查已发生的外部内容/文件身份变更，
  此时需“重新读取”后再编辑；这不是针对并发恶意写入的原子 compare-and-swap。
  保存后明确点击“重新连接”生效，不自动重启，不提供热重载。

缺失配置时自动打开身份页，提供可编辑的默认值；填写各页后直接“保存配置”，再“启动连接”。
切换页面会保留尚未加入列表的输入；保存时会提示先添加或更新对应条目，避免丢失输入。
不需要先创建空白 YAML 文件或手动点击“重新读取”。配置目录须已存在且可写。
默认数据库位于配置文件同目录，使用配置文件名加 `.db`（`config.yaml` 对应 `config.db`）。
已有身份数据库的节点域名和根公钥须与原身份一致；修改这两项不会改写已有身份。
底层仍使用同一个 YAML 文件，命令行与已有配置保持兼容；图形界面不维护另一份设置数据库。
表单保存会重新生成 YAML，保留配置值，不保留原有注释和排版。
无法解析的已有文件不会作为默认配置被覆盖，需先修正文件并重新读取。
已有身份数据库继续沿用，首次离线导入也可使用现有 `state import` 命令。

升级时先从托盘退出，再解压新程序并保留实际使用的配置和数据库；更换 exe 路径无需重新登记服务。
`state.path` 仍是数据库的绝对路径，移动程序目录不会自动移动身份数据。
旧版 Windows 服务已经停止时不影响托盘使用；如果仍在运行并占用同一数据库，
需要先在 Windows 服务管理器停止旧服务。托盘不会自动停止、修改或接管既有服务。

## 可重复验收

portable 测试覆盖参数、配置校验、外部变更、状态解析及路由文本；Windows 原生测试额外覆盖
Win32 ABI、真实控件、DACL 保留、原子替换失败保护、运行生命周期及管道进程身份绑定。
原生控件测试可以在 SSH 的非交互会话运行，不能据此认定托盘已在 Explorer 中出现。

完整桌面场景需要测试账号以控制台方式登录 Windows，保持解锁且 Explorer 运行。
SSH 使用同一账号。通过一次性 InteractiveToken/Highest 计划任务在该用户桌面运行夹具，
任务无持久触发器，结束后注销，只操作本次唯一目录和本次 GUI。

```sh
PHOTON_WINDOWS_SSH=photon-test@10.16.252.11 \
PHOTON_LINUX_IP=10.16.255.8 \
PHOTON_BIRD_NIX_PACKAGE=/nix/store/<bird-package> \
PHOTON_IKE_AUTH_NIX_PACKAGE=/nix/store/<strongswan-package> \
PHOTON_WINDOWS_TRAY_SMOKE=1 PHOTON_WINDOWS_AUTOJOIN_SMOKE=1 \
bash docs/scripts/windows-full-daemon-smoke.sh
```

沿用完整 Linux Photon gateway、临时签名身份和真实 Windows Wintun/双栈业务。
GUI 场景读取真实控件，发送 Win32 控件消息，核对 IPC DTO 与 GUI 进程，保存仅针对本次窗口的
PrintWindow 截图。覆盖停止清空状态、启动恢复、非法选项拒绝、MTU 1400→1360 保存不重启、
重新连接应用 MTU、退出界面后释放资源和换目录重开身份稳定。托盘检查核对本次 HWND/ID 的 Explorer 图标矩形，
恢复检查只删除自己的图标并模拟 `TaskbarCreated`，不重启 Explorer。

独立的 CLI 服务回归继续由原服务模式验证。托盘场景结束删除本次适配器、地址、路由、凭证和
一次性计划任务。系统 Application 历史事件保留，不清空日志。

以下是先前 SCM GUI 的历史验收记录，当前 GUI 的托盘运行语义以上述说明为准。

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

## 2026-10-15 配置表单验收

配置编辑已改为独立的基本/高级设置窗口，底层 YAML schema、文件和安全保存保持同一 owner。
`ConfigOptions` 是原文件 schema，解析和表单序列化使用相同校验；GUI 不访问身份数据库。
已有多网关、同一网关多个引导地址、双栈网段及全部高级选项均完整往返。
已有文件解析失败时禁止保存，不用空白默认值覆盖；外部修改仍须重新读取。

最终源码 `make check`、两包 race、Windows vet 通过；Windows 两包原生测试 221 项通过，
10 项需显式启用的集成测试或 helper 顶层跳过。原生控件测试实际从缺失配置开始，通过 worker 加载默认值、
填写选项、增删引导节点并保存新文件；重新读取后值一致，没有创建身份数据库。

Windows 11 amd64 `10.16.252.11` 的 `photon-test` Session 2 / Explorer 556，
对隔离完整 Photon gateway / StrongSwan 6.0.7 的最终桌面回归通过。
身份与签发 authority 为夹具临时生成；SCM、Wintun、Gossip、IKE/ESP 和双栈业务实际运行，
控件由程序发送 Win32 消息操作，截图仅捕获本次自有窗口：

- 基本/高级设置在 700×700 窗口可用，双栈分流网段同时可见。主窗口没有旧 YAML 控件。
- 同一网关增加第二个引导地址、修改、删除并恢复原列表通过。未添加/更新的输入拒绝保存，
  保留输入且原文件字节不变；无效 MTU 1279 同样不落盘。
- MTU 1400→1360、重连最大间隔 31s 保存并重新读取一致，其余选项与列表保持原值；
  日志下拉选项操作通过。保存保持同一服务进程，重启后自有接口双栈 `NlMtu` 均为 1360。
- 状态、托盘、启停、重启及退出后双栈业务通过；GUI 与一次性桌面任务的实际退出码均为 0。
- 空数据库自动入网、错误公钥拒绝、正确授权同进程接纳及重启身份稳定通过；后续服务崩溃恢复、
  地址通知重绑、损坏数据库保护、Event Log source 与外部适配器冲突保护均通过。

公开证据在 `build/validation/windows-settings-20261015/`：`accepted-desktop/`、
`full-rig.log`、`native.log`、`make-check.log`、`race.log`、`windows-vet.log` 及
`accepted-sources.sha256`。首轮功能已通过，列表加高及配置读写完成的绘制调整后完整重跑通过；
首轮日志和截图保留在 `full-rig-before-layout.log` 与 `pre-layout-fix/`。
独立清理确认服务、source、网卡、地址、路由、进程、计划任务、远端目录和两轮网关容器均无残留。

## 2026-10-15 网关通配符验收

`gateway.allowed_zones` 支持与 Linux 相同的 glob，匹配和语法校验统一归
`pkg/core/zone`，原 Linux mesh policy 复用该实现。精确身份的顺序、缺失身份诊断及
非根完整身份校验保留；通配符从每次当前 verified view 展开、排序、去重，不增加缓存。
匹配后仍逐项检查原有 root pin、签名链、记录、角色、overlay、密钥和地址有效期。
bootstrap 始终为具体身份，须匹配至少一条允许项；GUI 拒绝把通配符添加为引导节点身份。

全仓 `make check`、四包 race 与四包 Windows vet 通过。Windows app/internal 两包完整原生测试，
加共享 glob 与 Linux mesh policy 的定向兼容测试，共 239 项顶层通过、10 项 opt-in/helper 顶层跳过。
签名夹具覆盖重叠去重、确定顺序、新 view 增删候选、禁用/撤销/过期、错误 root、无签名记录、
仅有 bootstrap 不授信及多候选共用原 DNS 时间预算；GUI 表单完整保留通配符和具体引导节点。

已登录 Windows 11 `photon-test` Session 2 对隔离完整 Photon gateway / StrongSwan 6.0.7 验收通过：
起点仅配置 `*.catofes.`，从空数据库自动入网，错误公钥拒绝、正确授权同进程接纳后，
实际连接到 `gateway.catofes.` 并完成双栈业务。在 700×700 设置窗改为 `*`，验证 YAML 自动引号、
保存不重启、重新读取后仍为字面 `*`；重启后仍认证同一具体网关，双栈业务通过。
截图已独立目检。后续崩溃恢复、网络变化、损坏数据库和外部资源冲突保护回归通过，
GUI/一次性桌面任务实际退出码均为 0；独立清理确认测试资源无残留。
身份和授权使用本轮临时 authority，未操作真实网络的授权或 IPAM。

首次原生回归发现既有自动入网测试只给右端配置 object-pull worker，左端自动反向同步会回退
到 chunk，可能撞到原发送缓存限额；前批 binary 的 20 次重复也复现 2 次，本批修正前为 5 次。
仅将夹具的双端 worker 配齐并前移到首包前，保留原有断言、期限和生产限额；修正后 Linux
20 次及 Windows 40 次连续通过，再完整重跑原生与真实网关验收通过。

公开证据位于 `build/validation/windows-gateway-glob-20261015/`：
`accepted-desktop/gui-smoke.json` 的 `GatewayGlob` 记录初始/保存通配符、YAML 引号及重启前后
认证网关；`full-rig.log`、`native.log`、`make-check.log`、`race.log`、`windows-vet.log` 和
`accepted-sources.sha256` 对应最终检查。原生初轮失败与前后 binary 对比、修正后的重复记录分别保留在
`native-before-fixture-fix.log`、`native-autojoin-probe.log`、`native-autojoin-fixed-repeat.log`。

## 2026-10-15 首次配置与分组列表验收

缺文件作为成功的新建表单加载，界面自动打开身份页；安装或启动前提示先保存。
读取失败显示具体原因，保留重新读取入口，不把损坏或不可读文件当成新建配置覆盖。
新建状态由加载结果提供，不从空字段推断；失败重读会清除旧新建状态，保存成功后清除首次提示。
配置目录缺失时指出路径，不自动创建目录；目录补齐后可直接重试保存。

身份、网关与引导、路由、高级四页使用同一配置模型。网关规则和 CIDR 改为原生列表及
独立输入增改删；引导节点保留身份/地址两列。切页保留各组草稿，保存前提示应用或清除，
重新读取仍须确认丢弃编辑。含主机位或默认路由的 CIDR 在添加时明确拒绝，不静默扩大网段。

全仓 `make check`、两包 race、Windows vet 通过。Windows 两包完整原生测试 235 项通过，
10 项 opt-in/helper 顶层跳过；覆盖缺文件加载→状态刷新→首次保存、并发外部创建拒绝、
缺目录重试、真实 Win32 非缺失错误，以及首次加载后外部损坏文件的失败/恢复流程。
当前源码未复现用户原先的普通缺文件报错，未将其归因于目录或权限；本批明确首设流程并实际验收。

Windows 11 `photon-test` Session 2 / Explorer 556，对隔离完整 Photon gateway / StrongSwan 6.0.7
验收通过。身份和 authority 为本轮临时生成，SCM、Wintun、Gossip、IKE/ESP 和双栈业务真实运行：

- 同一 exe 复制到全新目录，从另一空工作目录启动且不传 `--config`。
  exe 旁 `config.yaml` 原不存在，填四页后首次保存成功，全程没有点击“重新读取”。
  实际落盘配置通过 CLI 校验，网关及引导地址逐项一致；没有数据库、服务或工作目录文件产生。
- 两组新列表及原引导列表增改删、通配符 `*.catofes.`→`*` 保存加引号/重读、无效 MTU 拒绝通过。
  保存保持原服务 PID，重启后双栈 `NlMtu=1360`，退出 GUI 后服务及双栈通信继续。
- 四页 700×700、首设默认 920×760 截图经独立目检；物理客户区和控件边界记录与图像一致。
  本次为 96 DPI，未验证高 DPI。GUI、首设 GUI 和一次性桌面任务实际退出码均为 0。
- 自动入网错误公钥拒绝/正确授权同进程接纳、崩溃恢复、地址通知重绑、损坏数据库、
  Event Log source 和外部适配器冲突保护及恢复通过；独立检查确认两轮资源和容器无残留。

公开证据在 `build/validation/windows-settings-ux-20261015/`：`accepted-desktop/`、`full-rig.log`、
`native.log`、`make-check.log`、`race.log`、`windows-vet.log`、`ast.log`、源码校验及清理记录。
首轮新增占用负例没有制造读取错误，已换为先核实真实 `ERROR_INVALID_NAME` 再验证加载/保存保护，
没有修改生产权限逻辑或跳过断言；原件保留在 `native-before-error-fixture-fix.log`。
首轮桌面在首设成功后因测试参数 `$Input` 与 PowerShell 自动变量冲突中断，改名后完整重跑通过。
截图夹具另补齐工作线程 DPI 上下文、同步重绘与物理几何记录，产品布局没有因此改动；
失败日志与原始裁切图保留在 `full-rig-before-ps-variable-fix.log` 和 `failed-ps-variable/`。

## 2026-10-15 托盘直接运行 Photon

默认 GUI 改为在自身进程内管理 Daemon，移除安装服务入口与 GUI `--name`，不启动后台子进程。
复用 console 的运行、控制管道和清理链路；窗口关闭隐藏，托盘退出取消并等待实际运行结束。
忙碌时退出会排队等待，结果消息发送失败仍由定时器收取；失败保留窗口及编辑供重试。
保存配置不改变当前运行快照，重新连接后应用。CLI SCM 的所有权校验和服务模式保留。

Windows 11 `photon-test` Session 2 / Explorer 556 的真实桌面，以临时 authority、
完整隔离 Linux Photon gateway / StrongSwan 6.0.7 验证，未修改真实网络授权或 IPAM：

- 从另一工作目录启动无配置的副本，四页首次保存成功，不创建数据库、服务或自动连接。
- GUI 内生成身份、等待授权、错误公钥拒绝及正确授权接纳，整个过程保持同一 GUI PID 和数据库身份。
  授权后实际 Wintun、IKE/ESP、IPv4/IPv6 UDP 业务及路由通过。
- 隐藏窗口、重建自身托盘图标后业务继续；停止释放管道、适配器及数据库，启动恢复同一身份。
  通配符和列表往返、非法 MTU 保留原文件、保存不重启、重新连接双栈 MTU 1360 生效通过。
- 同数据库竞争托盘被拒绝，其停止和退出不影响原实例的 SA 或双栈业务。
  原托盘退出后管道、路由、适配器消失，离线数据库可读；换 exe 目录重开沿用已入网身份。
  停用的旧服务登记始终保持原路径、账号及 PID 0，不影响以上操作。

独立 CLI SCM 回归覆盖启停、同数据库崩溃恢复、地址增删通知、损坏数据库保护、Event Log source
和外来适配器冲突保护及恢复，实际双栈业务通过。首轮托盘失败来自 Windows 返回
`ERROR_PIPE_BUSY` 而占用提示仅覆盖 `ERROR_ACCESS_DENIED`；补齐提示并保留原错误码后重跑通过。
未降低管道独占、进程绑定、文件权限或服务所有权要求。

全仓 `make check`、两包 race、Windows vet 通过；Windows 两包原生测试 240 项顶层通过、
10 项 opt-in/helper 顶层跳过。最小 700×620 主窗口覆盖正常及待入网两种布局，
配置摘要与三行提示区域不重叠。最后仅调整提示区高度，原生与完整托盘桌面场景再次验收。
CLI SCM 证据对应调整前源码，服务与运行链路在该布局调整中没有变化。
桌面截图为 96 DPI，未验证高 DPI；托盘重建仅模拟 `TaskbarCreated`，未实际重启 Explorer。
本批不替代 B6 的物理睡眠、长时间稳定性或发布验收。

公开证据在 `build/validation/windows-tray-20261015/`：`accepted-tray/` 为最终桌面轮，
`pre-note-layout/` 为功能通过后提示区调整前的原件，`accepted-scm/` 为独立服务回归。
`native.log`、`make-check-final.log`、`race.log`、`windows-vet.log`、`ast.log`、
`accepted-sources.sha256` 及 `sources-before-note-layout.sha256` 区分最终检查与服务回归源码。
占用提示修正前失败日志和原件保留在 `full-tray-before-pipe-busy-hint.log`、
`native-before-pipe-busy-hint.log`、`failed-pipe-busy-hint/`。

最终 GUI、竞争 GUI、换目录 GUI、首设 GUI 及一次性桌面任务实际退出码均为 0，剪贴板已恢复。
`cleanup.log`、`docker-cleanup.txt` 独立确认本轮服务、Event Log source、适配器、地址、路由、
任务、进程、远端临时目录及四轮容器无残留；两名用户原有 Explorer 会话均保留。

后续已补充直接托盘进程的真实强杀恢复，以及 PVE VM101/net0 断开后同进程自动双栈恢复，
含独立定时恢复和宿主机配置核对，见 [托盘故障验收](tray-fault-testing.md)。
