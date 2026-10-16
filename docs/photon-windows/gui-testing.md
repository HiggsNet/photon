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

GUI 不再接受 `--name`，同一登录会话只保留一个托盘实例。重复启动恢复已有窗口，
不会应用第二次指定的配置路径；先退出已有托盘后才可切换配置或解压目录。已有 CLI 服务命令仍可使用。
目录、配置、数据库及 driver 应由管理员管理；界面沿用现有管理员权限要求，不自动提权。

- 窗口显示运行状态、业务连接状态、活动网关和实时 Babel 路由。Daemon 运行与业务
  隧道 ready 分开显示；停止或 IPC 读取失败时清除旧网关与路由。
- “启动连接”“停止连接”“重新连接”管理本次托盘进程拥有的 Daemon。
  打开 GUI 不自动连接；运行中的配置使用启动时的快照，保存设置不会自动重启。
- 首次启动显示入网进度与可复制的入网请求，授权同步后自动继续连接。已入网与业务已连接分别展示。
- 已入网后优先显示 IKE、数据隧道、链路本地控制面及 Babel 邻居的真实等待状态。
  控制面已连通、尚无可用业务地址时，显示“等待业务IP分配”；收到有效分配及本机路由公告后自动继续，
  无需重新连接。地址须为当前分流范围内、本节点独占且有效的 `/32` 或 `/128`，子网及共享分配不作为接口地址。
  认证隧道和有效 overlay 的 `fe80::` 链路地址用于用户态 Babel 控制面，独立于业务 IPAM；
  链路 IPv6 与实际 Wintun 业务地址分别显示，Babel 邻居在线不代表业务就绪。
- “日志与诊断”默认打开概览，提供概览、网关与隧道、Gossip / Peer、日志及原始 JSON 五页，
  支持自动刷新、暂停、刷新一次及复制当前内容。概览先显示当前状态和实际连接事实，
  不将历史 TCP 失败计数当成当前业务故障。
  日志只读当前或最后一次连接的 `state.path + ".log"`，最多显示末尾 256 KiB / 1000 行；
  来源、采样时间及截断提示位于正文上方。保存数据库路径不会切换正在运行的连接及其日志来源。
  停止后仍可查看历史日志；Peer 和诊断详情在停止或实时读取失败后清除旧在线数据。
  Peer 页左侧为简短节点列表，选择一项后在右侧显示最新会话 `pull_state`、最后事件、失败原因和退避时间，并单列 TCP 累计计数、
  最后拉取对象与历史错误及 UDP 回退次数；这些累计值不等于当前会话结果。
  原始 JSON 页为当前公开状态，包含入网、Wintun、IKE 阶段、网关候选拒绝原因、Babel 和路由。
  网关规划保留其原采样时间与 revision；候选不代表已认证。暂停只冻结诊断窗口，“刷新一次”在暂停时仍有效。
  网关页将当前目标、握手尝试与认证/CHILD/Babel/Wintun 事实分组；失败和拒包分别保留时间、阶段、
  网关与端点，后续重试耗尽不覆盖先前具体认证拒因。旧尝试记录明确标记历史；单个拒包不代表隧道失败。
  日志默认筛选连接与网关，可切换警告错误、Gossip 或全部日志；筛选仅作用于原有有界 tail，
  全部日志保留原文。原生文本软换行便于查看长原因，复制不插入视觉换行。
  可读页面使用本地时间并标明时区偏移，原始 JSON 保留现有机器可读格式。
  关闭诊断窗口保留连接，退出托盘才停止 Daemon。
- 关闭窗口隐藏到托盘；托盘可以打开窗口、启动、停止及停止连接后退出。
  退出会等待 Daemon 释放网络资源和数据库，不留下常驻子进程。
  托盘不可用时关闭窗口也走停止连接后退出流程。
- 配置分为“身份”“网关与引导”“分流路由”“高级”四页。
  页面导航和主操作使用统一强调色；身份、地址与网段采用等宽字体，输入框提供示例。
  保存与重新读取位于设置页右下方，字段和列表按逻辑 DPI 单位排列。
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
新建配置的 Overlay ID 默认 `ipsec-main`，与 Linux 示例一致；必须填写网关实际发布的同名 overlay。
已有配置保留其 Overlay ID，不会自动修改；Gossip 同步成功不表示 overlay 已匹配或隧道已认证。
已有身份数据库的节点域名和根公钥须与原身份一致；修改这两项不会改写已有身份。
底层仍使用同一个 YAML 文件，命令行与已有配置保持兼容；图形界面不维护另一份设置数据库。
表单保存会重新生成 YAML，保留配置值，不保留原有注释和排版。
无法解析的已有文件不会作为默认配置被覆盖，需先修正文件并重新读取。
已有身份数据库继续沿用，首次离线导入也可使用现有 `state import` 命令。

升级时先从托盘退出，再解压新程序并保留实际使用的配置和数据库；更换 exe 路径无需重新登记服务。
`state.path` 仍是数据库的绝对路径，移动程序目录不会自动移动身份数据。
旧版 Windows 服务已经停止时不影响托盘使用；如果仍在运行并占用同一数据库，
需要先在 Windows 服务管理器停止旧服务。托盘不会自动停止、修改或接管既有服务。

Windows 已有 `status`、`peers`、`routes`、`diagnostics` 只读命令，例如：

```powershell
.\photon-windows.exe diagnostics --config C:\Photon\config.yaml
.\photon-windows.exe peers --config C:\Photon\config.yaml
```

这些命令读取正在运行实例的本机 IPC；Linux 的整套 `debug` 子命令尚未全部移植。
诊断窗口复用现有公开状态，没有执行任意命令或打开另一份身份数据库。

## 2026-10-16 诊断分组与握手观察

诊断默认进入概览；网关与隧道页区分尝试目标、已认证事实、最近失败与历史拒包。
Peer 页按节点选择，最新会话与累计传输计数分别展示；刷新保留选择，节点消失或连接停止时清除旧详情。
日志提供连接与网关、警告错误、Gossip、全部四种筛选，保留原始 JSON 和原文复制。
长文本自动换行，仍复用现有只读 observation、刷新 worker 和有界日志 tail。

全仓 `make check`、两包 race、Windows vet、PowerShell AST 与原生辅助类编译通过。
已登录 Windows 桌面两包原生测试共 290 项通过、10 项显式跳过，两个进程及一次性任务实际退出码均为 0。
完整隔离托盘测试通过，包含真实 Linux 网关、双栈业务、等待地址后恢复、重启、重复启动与换目录恢复；
五页正文、日志筛选、节点选择与刷新保留、最小窗口几何和复制均有运行记录。
已目检实际桌面的概览、网关与节点三页截图。测试后独立检查确认本轮服务、事件源、网卡、路由、任务、进程和测试目录均已清理，测试容器已删除。
证据位于 `build/validation/windows-debug-ui-20261016/`，真实连接记录为 `full-tray.log`，截图位于 `accepted-tray/`。
这批隔离测试不代替用户机器的认证故障验证；未操作 PVE 或修改生产配置、授权及 IPAM。

## 2026-10-16 日志与诊断窗口

新增独立原生窗口，三页共用只读、可选择和滚动的正文区。日志打开和更新时定位到最新记录；
暂停保留正文、选区和滚动位置，主窗口仍正常刷新。手动刷新在暂停或 worker 忙碌时不会丢失。
窗口使用既有主题、字体和逐窗口 DPI 布局，最小逻辑尺寸为 700 × 620。

日志读取只打开 regular file，不跟随最终 symlink/reparse point；不创建配置、日志、数据库或身份。
每次按打开文件当时的大小只读末尾 256 KiB，保留最多 1000 行并处理 UTF-8 边界；
共享删除权限、短时打开及关闭句柄允许既有 logger 轮转。日志路径以当前或最后一次 owned run 为准，
保存新的数据库路径不会改读其他运行实例。日志脱敏沿用既有生产 logger。

全仓 `make check`、五包 race 及 Windows app/internal/Gossip vet 通过；Windows app/internal
两包在已登录 Session 2 运行，253 项通过、10 项 opt-in/helper 跳过，两个测试进程和一次性任务实际退出码均为 0。
原生新增回归包括缺失日志无写入、无效配置及非 regular/link 拒绝、UTF-8/字节/行数边界、
运行路径保持、轮转、原有脱敏、真实 worker 读取、暂停及忙碌时手动刷新、离线 JSON 无旧 observation、
三页最小窗口几何及最新日志可见行。文件 ACL 拒读未单独注入验收。

公开证据位于 `build/validation/windows-diagnostics-20261016/`。`accepted-tray/` 保留首轮真实桌面验收，
之后根据截图修复日志初始滚动位置，最终原生测试见 `native-final-interactive.log`。
`accepted-final-tray/` 与 `full-tray-final.log` 为最终冻结源码的完整重跑，实际退出码为 0，
包含 `PORTABLE_TRAY_REAL_RUNTIME_PASS`。真实日志正文与文件、Peer 的 `pull_state` 与计数、
公开 JSON 的 IKE/Babel 双栈路由一致；暂停保持、手动刷新、完整复制及剪贴板恢复通过。
停止后 Peer/详情清除旧在线信息而日志仍可读，重连后的新 SA 与 status 一致；
诊断关闭不改变 SA，双栈通信持续。三阶段九张最小窗口截图及物理几何保留，最终三页截图已独立目检，
日志视口显示最新记录。完整组还回归首次配置、错误公钥拒绝、同进程正确入网、配置保存/MTU、
竞争实例保护、换目录保持身份和退出释放资源；本轮未操作 PVE。
Windows vet 曾扩大到包含 Linux-only BIRD 测试的 host 包，因 `syscall.Wait4` 不可用而失败，
原件 `windows-vet-linux-only-host.log` 保留；该包普通/race 测试在 Linux 通过，Windows vet 通过范围如上。

## 2026-10-16 业务 IP 等待与链路 IPv6

后续诊断批次修正了“缺业务 IP 掩盖网关未建立”的展示：主状态按 IKE、CHILD、链路本地
pipeline、实时 Babel 邻居分层，业务地址缺口仍作为独立事实保留。
公开状态新增网关规划 revision/时间、候选拒绝原因、当前重验选择与 IKE 原始阶段；
规划或原始阶段不代表已认证，`ike.live` / `child_live` 仍使用原授权和到期校验。
Peer 状态新增 checkpoint 失败及时间、最后事件、退避截止与最后 TCP 对象/错误，
明确最新会话与进程内累计计数的不同口径。候选和 Peer 同时受条数、文本及 JSON 编码预算限制。

该诊断批次全仓检查、两包 race、Windows vet 及 277 项已登录桌面原生测试通过，10 项显式跳过。
真实隔离托盘完整组通过：无业务 IP 时实际 SA/链路邻居在线，随后自动创建业务接口，
双栈业务、诊断窗口、重启、单实例唤醒和换目录恢复全部通过，实际任务退出码为 0。
证据位于 `build/validation/windows-diagnostics-stages-20261016/`，仅证明隔离夹具，
不代替用户机器和旧版 Venus 的实际连接验收；Venus 本轮只读检查，未修改生产配置或 IPAM。

主窗口现在分别显示业务 IP、用户态隧道链路 IPv6，并为已入网但未分配有效 host 地址的节点显示
“等待业务IP分配”。公开 `readiness.stage` 只解释两个已确认的地址门禁：`address_assignment`
和 `address_announcement`；原始原因有界保留，未配置网卡本身不用于推断缺 IPAM。
`babel.local` 只采样当前经过授权校验的实际 pipeline，`neighbor` 仍须当前邻居在线，
不显示由 GUI 自行推导的地址。`wintun.addresses` 继续只描述实际业务接口地址。

有效 SA、双方签名 overlay/path/epoch 和 Babel 身份到齐后，即使业务 host 还未分配，也可在
原 pipeline owner 中交换严格绑定两端链路地址的 Babel 报文。此时没有 OS packet device、
业务源地址或分流路由，业务包双向拒绝，`tunnel_ready` 保持 false。
首次分配或后续撤销沿用同一 reconcile：分配及公告生效后自动创建业务附件，撤销后释放附件并保留
有效控制面。代际变化、SA 过期或授权失效仍销毁控制面；没有增加 IPAM 写入口、额外 worker 或接口地址推断。

全仓 `make check`、两包 race、Windows 两包 vet 通过；已登录桌面的 263 项 Windows 原生测试通过，
10 项 opt-in/helper 跳过，两个测试进程及一次性任务实际退出码均为 0。新增回归覆盖
有界原因、shared/subnet/范围外/无效分配、公告缺失与手工撤销、纯控制面邻居和真实 ESP、
业务双向拒绝及撤销前 crypto completion 的再次校验、同 SA 分配升级、过期/授权失效，
以及三行地址区最小窗口几何和离线清除旧地址。

公开证据位于 `build/validation/windows-address-wait-20261016/`。最初恢复测试的 root snapshot
夹具误用了小型 datagram 预算，失败原件保留；按生产 object-pull 的 8 MiB snapshot 预算修正后通过，
生产配额没有改变。相关记录为 `focused-address-runtime-object-pull.log`、`make-check.log`、
`race.log`、`native-interactive.log` 和 `ast.log`。

真实桌面完整组实际退出码为 0，包含 `PORTABLE_TRAY_REAL_RUNTIME_PASS`。
`accepted-tray/tray-address-waiting.json` 与截图证明：入网已接纳、IKE/CHILD 有效、两端 `fe80::`
和 Babel 邻居在线，业务地址/路由为空、没有 Wintun、`tunnel_ready=false`。
隔离网关通过其现有生产 control socket 分别签发测试 `/32`、`/128`，日志明确 `via daemon`；
Gossip 同步后 GUI PID 9924、数据库 file ID、IKE generation/到期时间以及两端链路地址均未变化，
业务接口和双栈路由自动出现，真实双栈 UDP 往返通过。独立对比见 `address-transition.json`。
缺地址阶段的 UDP 负探针实际在源地址 bind 处失败，`Sent=false`；业务包的加密后拒绝另由原生回归验证，
不将未发出的探针描述成经过 ESP 的负向验收。
原有启停、MTU/配置、日志诊断、竞争实例和换目录恢复全部通过，剪贴板恢复。
`cleanup.log`/`docker-cleanup.txt` 确认仅本次测试资源已清理，原桌面保留；本轮未操作 PVE 或用户实际 IPAM。

## 可重复验收

portable 测试覆盖参数、配置校验、外部变更、状态解析及路由文本；Windows 原生测试额外覆盖
Win32 ABI、真实控件、DACL 保留、原子替换失败保护、运行生命周期及管道进程身份绑定。
基础原生控件测试可在 SSH 非交互会话运行；启用 `PHOTON_WINDOWS_GUI_NATIVE=1` 的
完整组包含真实可见性与 Tab 导航断言，应在已登录桌面运行，不能用不可见窗口代替。
例如从管理员桌面终端先设置 `$env:PHOTON_WINDOWS_GUI_NATIVE='1'`，
再运行 `go test ./app/photon-windows ./internal/photonwindows`，
或由一次性 InteractiveToken/Highest 任务执行交叉编译的测试程序。

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

单实例脚本检查会先隐藏原窗口，再从另一解压目录传入另一个不存在的配置路径启动：
第二进程须快速以 0 退出，唤醒原 PID/创建时间对应窗口，不创建另一个配置或数据库，
原配置、数据库身份、SA 与双栈业务保持；原实例退出后仍验证换目录重开。
此处描述验收要求，实际通过状态以对应批次运行记录为准。

2026-10-16 单实例批次已在 Windows 11 已登录桌面通过：268 项原生测试通过，10 项显式跳过，
含 8 进程竞争、正常退出与强杀后重新获取、重复打开的句柄释放，以及隐藏窗口恢复。
完整隔离 Linux gateway / Windows 托盘场景也通过：跨目录重复进程退出码为 0，原窗口恢复，
配置与数据库身份不变、同一 SA 上 IPv4/IPv6 业务继续；退出后换目录重开通过。
证据位于 `build/validation/windows-single-instance-20261016/`。

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

## 2026-10-15 原生界面整理

主窗口区分连接标题、运行说明、网关/入网与路由，正常连接以绿色标题呈现。
路由使用等宽字体按列对齐，额外窗口高度分配给路由区；配置摘要和操作提示固定在底部。
完整错误进入可选择、可复制、可滚动的只读详情框，不再挤占单行状态标题。
同一状态轮询不重置文字选择，恢复健康状态也不抹去上一条操作失败提示。

四个设置页统一导航、标题、说明、间距与输入示例；网关规则、引导节点及路由按组排列，
高级字段分两列，保存按钮固定在右下。cue 仅提示示例，不写入配置或草稿。
沿用原配置 schema、校验、原子保存、外部变更保护、托盘生命周期及管理员权限要求。

exe 内嵌 common-controls v6 / PerMonitorV2 / asInvoker 清单，不增加前端运行时。
每个顶层窗口独立处理 DPI、字体和最小尺寸；高对比度配色沿用系统颜色，禁用按钮单独绘制。
字体、画刷在所有子控件关闭后统一释放。清单源为 `photon-windows.manifest`，
1.4 KiB 的 `rsrc_windows_amd64.syso` 由固定版本 `rsrc v0.10.2` 生成并入库，
普通构建无需安装资源编译器；`go generate ./app/photon-windows` 可重新生成，确定性比较通过。

全仓 `make check`、两包 Windows vet 通过。完整原生组在 Windows 11 `photon-test`
Session 2 的一次性任务内运行：243 项顶层通过、10 项 opt-in/helper 顶层跳过，
两包实际退出码及任务实际退出码均为 0。新增检查覆盖 DRAWITEMSTRUCT ABI、
96/144/192 DPI 通知、字体角色保持、最小窗口四页边界/不重叠、真实 Tab 遍历、
长错误详情及轮询保留选择。144/192 为本次窗口注入的通知，未更改显示器缩放；
实际桌面截图均为 96 DPI，不替代高 DPI 多显示器实机目检或系统高对比度模式验收。

完整隔离 Photon gateway / StrongSwan 6.0.7 桌面验收通过：四页最小 700×700 截图、
主窗口、待授权及占用失败提示均经独立目检，真实控件边界与字体记录一致。
首次配置、自动入网、列表操作、通配符保存/重读、非法 MTU 保护、保存不重启、
重新连接后双栈 MTU1360 与实际业务、双实例保护、换目录身份稳定及退出释放继续通过。
本轮没有 PVE 操作或物理断网；先前故障验收与 Gossip 待观察项继续独立。

公开证据在 `build/validation/windows-ui-20261015/`：`accepted-tray/` 为完整桌面原件，
`native-interactive.log`、`make-check-final.log`、`windows-vet.log`、`ast.log`、
`accepted-sources.sha256` 和 `source-recheck.log` 对应最终验证。
首轮 SSH 原生组在控件可见性断言失败，诊断确认 SSH 窗口不可见，原断言未放宽；
移至已登录桌面后通过。首次交互包装将正常 stderr 日志当成 PowerShell 错误提前结束，
改为保留 stderr 并核实际原生退出码后完整重跑通过。
原件保留在 `native-before-tab-diagnostic.log`、`native-tab-diagnostic.log`、
`native-dpi-focused.log` 和 `native-interactive-before-stderr-fix.log`。

`cleanup.log`、`docker-cleanup.txt` 独立确认本轮服务/source、适配器、地址、路由、
GUI/原生测试任务、进程、远端目录和容器均无残留；两个原 Explorer 会话保留。
