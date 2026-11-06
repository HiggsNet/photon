# Photon 的 FlClash Windows 客户端

锁定 FlClash v0.9.3，复用其代理组、连接、日志、设置和托盘。Photon 后台独立运行；仓库维护版本锁、上游接入补丁及 `overlay/`，不复制一整份上游源码。原生 GUI 保留为另一个独立客户端。

## 使用

1. 打开 FlClash，进入侧栏 **Photon**。首次使用点 **Photon 设置**，填写管理员提供的节点名、可信根公钥和至少一条内网路由。首次自动入网还需要引导地址。保存后应用会在用户数据目录下管理 `photon/photon.yaml`。已有身份可用 **选用已有 Photon YAML** 继续使用原配置。
2. 在 **概览、隧道、Gossip 节点、路由、代理服务、诊断** 中查看实时状态。每个网关选择一个外层地址（IPv4 或 IPv6）建立连接；同一连接可以承载内层双栈。隧道表中的 IPv4 和 IPv6 分别表示内层是否已有可用路由，「外层」表示连网关使用的地址族。点击一行可查看完整远端地址、ESP 到期时间和最近一次失败或重连原因。Gossip 节点表显示同步状态，代理服务表按发布节点汇总地区和端点数。数据采样被截断时会显示提示。
3. Photon 自动将当前有效、已授权的 SOCKS5 端点加入代理组。在代理服务中点击 **切换到 Photon 配置**，FlClash 会生成并选用独立的 Photon 配置；无需先导入其他配置。前往 **代理** 页使用 `Photon` 手选组、`Photon Auto` 自动择优或 `Photon Balance` 负载均衡，再按需要开启 FlClash 的代理接管。已有配置和订阅不会被覆盖，可以在 **配置** 页随时切回。
4. Photon 连接、代理接管、系统代理和 TUN 通过各自的入口控制。仅连接 Photon 可以访问内网。关闭 Photon 后，普通代理配置继续运行。使用 Photon 配置时，接管保持开启，无法经 Photon 转发的代理流量会被拒绝，节点在隧道重连后自动恢复。

首次连接后可在概览复制待授权的入网请求。如果管理员已提供离线授权包和与之匹配的现有密钥，可以在连接前用 **导入授权** 安装，目标配置须指向尚无数据库的状态目录。已有身份直接使用原配置即可。

停止 Photon 后可打开 **Photon 设置**，修改引导节点、路由或允许的网关，网卡、MTU 和日志级别等选项位于 **高级配置**。保存后的参数在下次连接时生效。配置路径自动保存。客户端可用普通权限打开，连接 Photon 时会由 Windows 请求批准本次后台启动。Mihomo 的 TUN 授权仍由 FlClash helper 处理。离线导入身份需要能创建受保护状态库的管理员权限。安全模式禁止启动 Photon。

## 自定义代理规则

在 Photon 配置旁放一个同名的 `.proxy.yaml` 文件，例如 `photon.yaml` 对应 `photon.proxy.yaml`。可从已有 Mihomo 配置复制代理组和规则。Photon 读取其中的 `proxies`、`proxy-providers`、`proxy-groups`、`rules`、`rule-providers` 和 `sub-rules`，把防回环所需规则放在用户规则之前。DNS 和 TUN 继续由 FlClash 与 Photon 管理。模板需要至少一条规则，最多 4 MiB。移除模板会恢复内置的 Photon 规则。

```yaml
proxy-groups:
  - name: Nodes
    type: select
    proxies: [Photon, DIRECT]
rules:
  - DOMAIN-SUFFIX,google.com,Nodes
  - MATCH,DIRECT
```

`Photon`、`Photon Auto`、`Photon Balance` 和 `photon-services` 由 Photon 提供。自定义组也可以用 `use: [photon-services]` 引入所有节点，再用 Mihomo 的 `filter` 筛选地区。建议为这类组设置 `empty-fallback: REJECT`，让筛选后为空的组拒绝连接。模板由用户编辑，生成的配置由 FlClash 管理。模板启用后，Photon 断开时只停用 Photon 出口，用户规则和其他出口继续可用。

## 数据与网络边界

- 应用级 controller 持有唯一后台进程，经 v1 私有帧协议核对 PID、配置 SHA256 和状态路径。关闭页面/隐藏窗口不会释放网络；退出应用等待后台回收。退出未确认时保留归属并拒绝重启。
- `services` 每两秒读取签名状态，再次验证当前 root、授权链、撤销、地址分配及服务签名。快照最多有效五秒；已授权不等于已测通。界面只消费公开 DTO，不打开 Photon 数据库。
- 节点随授权目录更新，经 Mihomo 校验后原子替换生成的配置。只更新 Photon 所属配置，保留用户模板、其他订阅和代理配置。内容无变化时不重新应用网络配置。
- SOCKS5 节点绑定 Photon 网卡。Photon 内网、服务地址、引导地址和当前网关公网地址进入 TUN 路由排除，同时提供直连规则。配置中的直连规则不替代操作系统路由排除。
- 服务失效、主动停止或 Photon 意外退出时，正在使用的 Photon 配置切换到拒绝 Photon 代理流量的状态并关闭旧连接。独立的代理开关维持用户选择。完整崩溃和睡眠恢复由 D7 跟踪。

## 准备与构建

在 Windows 上用带 GNU Make、Bash 和 `zip` 的终端运行，或在启用了 Windows 互操作的 WSL 中从 Windows 磁盘上的检出运行，例如 `/mnt/c/photon`。

```sh
make photon-flclash-build
```

目标会编译 Photon 后台、准备锁定的 FlClash 源码并调用 Windows Flutter 打包。ZIP 默认位于 `build/photon-flclash/dist/photon-flclash-windows-amd64.zip`，内含 `SHA256SUMS`。Windows 的 `PATH` 需要包含锁定版本的 Flutter、Go 和 Rust，并安装 Visual Studio C++ 构建工具及 Windows SDK。Photon 后台要求 Go 1.25 或更新版本，WSL 中用 Linux Go 编译。独立 Linux 主机可以用 `make photon-windows-build` 交叉编译 Photon 原生便携包。Flutter 的 Windows 界面编译需要 Windows 主机。

如果只准备源码和运行检查，可以单独执行以下命令。

```sh
bash app/photon-flclash/prepare.sh
cd build/photon-flclash/upstream
flutter pub get
dart run intl_utils:generate
flutter analyze
flutter test test/photon test/providers/action_test.dart test/providers/system_action_test.dart test/l10n test/lint
```

`prepare.sh` 只操作它创建并标记的锁定检出，升级补丁时先校验、撤回旧补丁；发生冲突则保留原内容。请修改 `overlay/` 或补丁后重新准备，不在生成的检出中维护修改。

版本要求见 `upstream.env`：Flutter 3.47.6、FlClash Go 1.27.1、Rust 1.99.0；Photon 后台使用 Go 1.25。Windows 还需要 Visual Studio C++ 构建工具和 Windows SDK。

在具备工具链的 Windows 上执行：

```powershell
.\app\photon-flclash\build-windows.ps1 `
  -Checkout .\build\photon-flclash\upstream `
  -BackendDirectory .\build\windows-amd64 `
  -OutputDirectory .\build\photon-flclash\windows-amd64
```

打包先用 `make photon-windows-build` 生成含驱动及第三方声明的后台目录。脚本验证锁定提交、子模块、接入文件摘要及编译器版本，启用真实原生构建，附带 Photon 后台、Wintun、上游许可证和 SHA256SUMS，不携带用户配置或身份。FlClash 和依赖的许可证及声明保留在源码与产物中。

对外分发时，在打包用户的 Windows「当前用户 → 个人」证书库中配置公开受信的代码签名证书及其私钥，并将 Windows SDK 的 `signtool.exe` 加入 Windows 的 `PATH`。运行 `make photon-flclash-build` 前设置 `PHOTON_FLCLASH_SIGNING_THUMBPRINT`，值为证书指纹。直接调用 PowerShell 脚本时也可传入 `-SigningCertificateThumbprint`。

签名模式会在生成校验和前为未签名的 EXE 和 DLL 加上 SHA-256 Authenticode 签名及时间戳，验证包内每个 EXE 和 DLL，并保留 Wintun 等已有有效签名的文件。签名或验签失败会中止打包。未指定证书时会生成预览包并显示提示。即使发布者已签名，新版本仍可能需要积累 SmartScreen 信誉。详见 [Microsoft 的 SmartScreen 说明](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)。

仅测试 Dart 界面时，可在临时检出关闭两个 `build_assets` hook，并指定从锁定源码构建的 `FRB_DART_LOAD_EXTERNAL_LIBRARY_NATIVE_LIB_DIR`。生产构建拒绝这些关闭 hook 的检出。

## Windows 实机验收

`overlay/integration_test/photon_windows_test.dart` 在已登录桌面执行真实控件操作，通过以下两个参数使用明确授权的测试身份和证据目录：

```powershell
flutter test integration_test/photon_windows_test.dart -d windows `
  --dart-define=PHOTON_TEST_CONFIG=C:\Photon\config.yaml `
  --dart-define=PHOTON_TEST_EVIDENCE=C:\Photon\acceptance
```

构建目录须先附带匹配的 `photon-windows.exe` 与 `wintun.dll`。测试涉及真实系统代理和虚拟网卡，应在隔离 Windows VM 中执行；首次免责声明使用上游的 `FLCLASH_ACCEPT_DISCLAIMER=1` 无人值守入口。测试结束恢复原开关并核对配置文件字节。

2026-11-06：Go 后台测试及 101 项前端/退出/本地化/界面规则测试通过，静态检查无问题；此前完整回归 1051 项通过。Windows 已完成完整 release 构建和真实窗口六页切换、多选操作，原有 test 身份的 11 个发布节点/33 个端点可见。经 FlClash 的洛杉矶、新加坡、东京三个 HTTPS 出口均验证成功。

双 TUN 的最小真实数据面已通过：普通应用不显式设置代理时走洛杉矶出口，显式 HTTP 代理仍正常，More 内网 IPv6 1232 字节 ping 3/3；Photon 公网出口仍走物理网卡，SOCKS 地址走 Photon。洛杉矶和新加坡还通过本地 Mihomo 的 UDP ASSOCIATE 完成 IPv4 DNS 查询；东京的同一 UDP 查询持续超时，TCP 正常，不能据此宣称该端点 UDP 可用。

已修复网关域名被 Fake-IP 替换导致的回环，并按实际外层路径变化触发重连。自动择优/负载均衡、清空选择后的阻断、重新选择及停止后重连恢复已在真实桌面验证。物理换网/睡眠、其他 VPN、性能与长时间运行等完整矩阵仍未完成；IPv4 内网、普通用户权限拆分、安装升级与正式发布分别由根目录 `todo.md` D1–D8 跟踪。公开验收日志在 `build/validation/photon-flclash-full-20261105/`，不包含身份私钥。

完整范围、已知限制和便携包实测见 [验收记录](../../docs/photon-windows/flclash-testing.md)。
