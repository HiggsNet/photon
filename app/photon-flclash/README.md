# Photon 的 FlClash Windows 客户端

锁定 FlClash v0.9.3，复用其代理组、连接、日志、设置和托盘。Photon 后台独立运行；仓库维护版本锁、上游接入补丁及 `overlay/`，不复制一整份上游源码。原生 GUI 保留为另一个独立客户端。

## 使用

### 路径

从侧栏进入 **路径**。连接 Photon 后可以新建路径，选择出口和中继，指定每一跳的地址族或传输方式，也可以手工输入未公开的出口。已保存的路径显示它的本地 SOCKS5 地址，并可进行连通性、UDP DNS、下载速度或自定义目标探测。编辑同名路径会保留端口，已有连接可以继续使用原路径。

勾选 **加入 Photon 配置**，再到 **模板** 页点击 **应用 Photon 配置**，会把路径追加到模板生成的配置中。代理页的 `Photon Paths` 可手选路径，模板规则也可以使用 `MATCH,Photon Paths` 或把它放进其他选择组。默认客户端由 FlClash 随 Photon 后台启动，路径保存在 Photon 身份数据库旁的 `.proxy-v2` 状态目录。手工配置了 `proxy_v2_config` 时，界面使用其中已有的客户端。

### Photon

1. 打开 FlClash，进入侧栏 **Photon**。首次使用进入 **设置** 标签，点 **新建 Photon 配置**，填写管理员提供的节点名、可信根公钥和至少一条内网路由。首次自动入网还需要引导地址。保存后应用会在数据目录下管理 `photon/photon.yaml`。已有配置可用 **导入 Photon YAML** 复制配置、规则模板及已有身份；要继续直接读取原文件，选择 **引用外部 Photon YAML**。
2. 顶部显示隧道数量，使用 **连接**、**断开** 控制 Photon。在 **概览、隧道、Gossip 节点、路由、诊断** 中查看实时状态。网关同时提供已授权的 IPv4、IPv6 地址且本地支持双栈时，Photon 分别尝试建立两条隧道，单条也能承载内层双栈。隧道表按外层连接显示，每行的 IPv4 和 IPv6 分别表示内层是否已有可用路由，「外层」表示连网关使用的地址族。点击一行可查看完整远端地址、ESP 到期时间和最近一次失败或重连原因。Gossip 节点表显示同步状态。数据采样被截断时会显示提示。
3. Photon 将当前有效、已授权且符合出口选择的端点加入代理组，支持 SOCKS5、HTTP 和 TrustTunnel。在侧栏 **模板** 中点击 **应用 Photon 配置**，FlClash 会生成并选用独立的 Photon 配置；无需先导入其他配置。前往 **代理** 页使用 `Photon` 手选组、`Photon Auto` 自动择优或 `Photon Balance` 负载均衡，再按需要开启 FlClash 的代理接管。已有配置和订阅不会被覆盖，可以在 **配置** 页随时切回。
4. Photon 连接、代理接管、系统代理和 TUN 通过各自的入口控制。仅连接 Photon 可以访问内网。关闭 Photon 后，普通代理配置继续运行。使用 Photon 配置时，接管保持开启，无法经 Photon 转发的代理流量会被拒绝，节点在隧道重连后自动恢复。

首次连接后可在概览复制待授权的入网请求。如果管理员已提供离线授权包和与之匹配的现有密钥，可以在连接前用 **导入授权** 安装，目标配置须指向尚无数据库的状态目录。已有身份直接使用原配置即可。

断开 Photon 后可进入 **设置** 标签编辑当前配置，修改引导节点、路由或允许的网关，网卡、MTU 和日志级别等选项位于 **高级配置**。保存后的参数在下次连接时生效。配置路径自动保存。客户端可用普通权限打开，连接 Photon 时会由 Windows 请求批准本次后台启动。Mihomo 的 TUN 授权仍由 FlClash helper 处理。离线导入身份需要能创建受保护状态库的管理员权限。安全模式禁止启动 Photon。

## 配置与数据目录

全新 Windows 便携版使用 EXE 所在目录下的 `data`，安装版使用 AppData。便携目录必须可写；路径始终以 EXE 位置为准，不随快捷方式的工作目录变化。已有 AppData 中的应用设置会继续读取，避免升级后丢失原配置；已初始化的便携 `data` 优先于旧 AppData。

**设置** 标签集中展示当前配置、配置管理和数据目录，提供 **打开目录**。断开 Photon 后可用 **迁移数据目录**，选一个空目录，把 YAML、同名 `.proxy.yaml` 和已有身份数据库复制过去并切换使用。原文件保留；数据库正在使用、身份验证失败或目标目录非空时拒绝迁移。复制受保护身份时会请求 Windows 管理员授权。这个入口迁移当前 Photon 配置，不迁移 FlClash 的其他订阅和设置。

新建及导入后的 `state.path` 默认相对 YAML 所在目录解析，内部配置选择也保存为相对应用数据目录的路径。因此全新便携版可以整体移动程序和 `data`。外部引用及手工设置的绝对路径继续按原位置读取；修改数据库路径只改变引用，不会自动搬迁身份。导入的配置分别放入 `photon/import-时间戳/`，不会覆盖当前配置。

## 代理出口选择

侧栏的 **服务** 按发布节点汇总出口地区。在这里分别勾选 SOCKS5、HTTP 和 TrustTunnel，再按实际发布的地区及固定节点筛选，点击 **保存出口选择**。首次使用默认只开启 SOCKS5，其他协议需要自行勾选。页面显示当前选择的出口数量；选择保存在本应用中，重启后继续使用，也适用于切换后的 Photon 配置。

地区选择控制该地区的全部协议入口；固定节点选择只控制该节点的 `local` 出口。Global 和地区任播入口按协议、目的地址和端口合并，不受某个发布节点的固定出口勾选影响。新发现的地区和节点默认纳入已开启的协议，取消勾选的地区、节点在撤回或重新发布后仍保持排除。

保存路径选择、服务出口或规则模板后，在 **模板** 页点击 **应用 Photon 配置**，一次应用这些变更。筛选同时作用于内置代理组及规则模板引用的 `photon-services`。没有选中出口时，Photon 出口进入拒绝状态。HTTP 不承载 UDP，需要认证且尚未提供凭据的 HTTP 入口不加入候选；TrustTunnel 保留服务发布的证书指纹验证。

## 自定义代理规则

打开侧栏 **模板**。当前 Photon 配置的路径和服务共用这份模板，断开时也可以编辑。用 **导入 YAML 模板** 选择已有的 Mihomo YAML，或用 **编辑 YAML 模板** 打开 FlClash 自带的编辑器。验证通过后，模板保存为 Photon 配置旁的同名 `.proxy.yaml`，例如 `photon.yaml` 对应 `photon.proxy.yaml`。也可直接编辑这个文件。Photon 读取其中的 `proxies`、`proxy-providers`、`proxy-groups`、`rules`、`rule-providers`、`sub-rules`、`dns` 和 `tun`。DNS、TUN 缺少的字段使用内置默认值，再应用 FlClash 选定的覆写项；TUN 开关、设备和协议栈等仍由 FlClash 界面控制。最后合并 Photon 必需的内网及端点路由排除，并把防回环直连规则放在其他规则之前，避免被覆写移除。模板需要至少一条规则，最多 4 MiB。点击 **使用内置规则** 可以移除模板。

在 **模板** 页点击 **复制 AI 提示词**，把提示词和已隐去凭据及私人订阅链接的现有 Clash/Mihomo YAML 一起交给 AI。将生成的 YAML 保存为文件，补回需要的值后用 **导入 YAML 模板** 验证。

```yaml
proxy-groups:
  - name: Photon
  - name: Photon Paths
  - name: Nodes
    type: select
    proxies: [Photon, Photon Paths, DIRECT]
rules:
  - DOMAIN-SUFFIX,google.com,Nodes
  - DOMAIN-SUFFIX,example.org,Photon Paths
  - MATCH,DIRECT
```

在 `proxy-groups` 中用只含 `name` 的条目给内置组指定在**代理**页的位置。上例把 `Photon` 和 `Photon Paths` 放在 `Nodes` 前。`Photon Auto` 和 `Photon Balance` 也可以这样排序，未指定位置的内置组追加在末尾。分流仍按 `rules` 的顺序匹配。

`Photon`、`Photon Auto`、`Photon Balance`、`Photon Paths` 和 `photon-services` 由 Photon 提供。`Photon Paths` 包含勾选 **加入 Photon 配置** 的路径，组为空时会拒绝流量。自定义组也可以用 `use: [photon-services]` 引入所有节点，再用 Mihomo 的 `filter` 筛选地区。建议为这类组设置 `empty-fallback: REJECT`，让筛选后为空的组拒绝连接。模板由用户编辑，生成的配置由 FlClash 管理。模板启用后，Photon 断开时只停用 Photon 出口，用户规则和其他出口继续可用。

注入代理时，相同地址和端口的 Global、地区任播入口会合并为一个，名称为 `Anycast / global / 地址:端口` 或 `Anycast / jp / 地址:端口`，不随发布节点变化。`local` 入口保留节点名，便于选择固定出口；原始服务发布记录仍按节点保留供诊断。完整示例和界面内示例均包含 `OpenAI` 选择组，通过 MetaCubeX 的 OpenAI 域名规则集单独分流，可在代理页为该组选择出口。

完整示例见 [examples/photon.proxy.yaml](examples/photon.proxy.yaml)，包含按应用分组、规则集和 DNS 策略。支持底层选路的后台不修改模板的 Fake-IP 过滤及域名 DNS 策略；旧后台仍需为网关域名补充真实 IP 解析和直连 DNS。旧后台使用 Fake-IP 白名单时会转换为等价规则模式，为网关域名添加例外。Windows 的 `strict-route` 配合 `dns-mode: hijack` 可能由防火墙阻断 Photon 的底层 DNS，绑定接口无法绕过该限制；这类配置应验证 `dns-mode: native` 的兼容性。

## 数据与网络边界

- 应用级 controller 持有唯一后台进程，经 v1 私有帧协议核对 PID、配置 SHA256 和状态路径。关闭页面/隐藏窗口不会释放网络；退出应用等待后台回收。退出未确认时保留归属并拒绝重启。
- `services` 每两秒读取签名状态，再次验证当前 root、授权链、撤销、地址分配及服务签名。快照最多有效五秒；已授权不等于已测通。界面只消费公开 DTO，不打开 Photon 数据库。
- 节点列表随授权目录更新。显式应用时经 Mihomo 校验后原子替换生成的配置。隧道状态变化和新增目录节点保持已经应用的配置及连接。
- SOCKS5 节点绑定 Photon 网卡，内网和服务地址进入 TUN 路由排除。支持底层套接字选路的 Photon 后台自行处理外层 IKE、ESP、Gossip 发送和网关 DNS。公网网关换址不会改变生成的代理配置。连接旧后台时继续用地址和域名排除。Mihomo 的 `strict-route` 可以拦截底层接口的明文 DNS（53 端口），该模式下应先验证 Photon 网关域名能正常解析。
- 已应用出口从有效目录撤回时，运行配置拒绝该出口并关闭使用它的连接。目录过期、主动停止或 Photon 意外退出时，运行配置阻断 Photon 出口。重新取得有效目录后恢复已应用且仍获授权的出口。已保存的配置文件保持原样。

## 准备与构建

Windows amd64 同时提供 ZIP 便携版和 `photon-flclash-<版本>-windows-amd64-setup.exe` 安装版。安装版需要管理员权限，默认安装到 `Program Files\Photon-FlClash`，提供开始菜单、可选桌面快捷方式和系统卸载入口。安装与升级前先从托盘退出客户端；运行中的客户端或后台会阻止替换文件。卸载只清理本安装的程序、快捷方式及注册项，保留 AppData 中的订阅、设置、Photon 配置和身份。安装程序不会自动迁移便携版的 `data`；可在 Photon 页面导入或引用原配置。

安装版与便携版沿用相同的 AppData 兼容逻辑，不应同时打开。Photon 构建的更新入口指向 Photon Release 页面，更新时下载新的 Photon 安装程序覆盖安装；禁用上游 FlClash 的自动二进制替换，避免丢失 Photon 集成。

在 Windows 上用带 GNU Make、Bash 和 `zip` 的终端运行，或在启用了 Windows 互操作的 WSL 中从 Windows 磁盘上的检出运行，例如 `/mnt/c/photon`。

```sh
make photon-flclash-build
```

安装 [Inno Setup 6](https://jrsoftware.org/inno-setup/downloads) 后，可以同时构建 ZIP 和安装版：

```sh
make photon-flclash-installer
```

安装包默认位于 `build/photon-flclash/dist/photon-flclash-windows-amd64-setup.exe`，旁边生成 `.sha256`。已有经过校验的 ZIP 可直接打包，无需重新编译 Flutter：

```powershell
.\app\photon-flclash\build-installer.ps1 `
  -Archive .\build\photon-flclash\dist\photon-flclash-windows-amd64.zip `
  -Checksum .\build\photon-flclash\dist\photon-flclash-windows-amd64.zip.sha256 `
  -OutputPath .\build\photon-flclash\dist\photon-flclash-windows-amd64-setup.exe `
  -PackageVersion 0.7.5
```

编译器默认从 PATH 或 Inno Setup 6 的标准安装目录查找，也可用 `-Compiler` 指定。安装包复用 ZIP 中的完整目录、许可证和逐文件校验清单，不重新选择后台或驱动。`PHOTON_FLCLASH_SIGNING_THUMBPRINT` 也用于签名安装程序。

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

GitHub Actions 的 **Windows packages** 可以手动运行，构建并上传原生客户端 ZIP、Photon-FlClash ZIP 和 EXE 安装版及各自的 SHA256 校验文件。安装版还会执行静默安装、逐文件校验、运行中拒绝更新/卸载、覆盖安装、卸载及数据保留检查。手动构建名称包含提交短 SHA，不发布 Release 或 Docker 镜像。推送版本标签时，**Release** 复用同一流程，在两个客户端及相关测试通过后将 ZIP 和 EXE 一起发布到 GitHub Release。

`master` 和 `windows` 上的 FlClash 接入或 Windows 流水线变更也会运行 **Windows packages**。`master` 构建为发布预热默认分支缓存；`windows` 构建用于开发分支检查和同分支缓存复用。GitHub 的缓存按分支或标签隔离：不同版本标签不能互相读取缓存，但都能读取默认分支缓存；仅添加 `restore-keys` 无法解决标签间缓存未命中。工作流尚未合入默认分支时，可通过推送 `windows` 分支启动构建并重跑，以对比冷、热缓存。

缓存包括 Go 模块和编译缓存、Dart/Rust 下载依赖、锁定提交的 Flutter SDK 和引擎文件，以及 Rust helper/native-assets 的 Cargo 编译目录。Windows 的 Rust bridge 使用系统临时目录中的短路径，需与 `.dart_tool` 下的 Cargo 目录一起缓存。SDK 按系统、架构和 Flutter 提交隔离；Rust 产物还按上游工具链、Cargo 配置/锁文件和原生源码区分，源码变化时可回退复用相同工具链和依赖的编译缓存，由 Cargo 重新检查输入。最终 Windows 应用、安装包及 Photon 后台身份校验仍每次执行。

比较性能时，在同一分支、同一提交上手动运行两次 **Windows packages**，分别记录缓存恢复/保存与编译耗时；发布能否复用缓存则查看标签构建的命中日志。`build-windows.ps1` 输出每个构建命令的耗时和 Flutter 详细日志，可进一步区分 Go core、Rust helper、Rust bridge 与 Flutter/C++ 编译。v0.7.5 的冷缓存基线：便携包步骤 8 分 11 秒，其中 Windows 应用构建 416.4 秒，其余约 75 秒为工具链初始化、依赖、引擎下载和打包；整个 FlClash job（含安装包及测试）11 分 23 秒。该基线不能当作优化后的实测结果。

FlClash 使用原生客户端产物中的同一份 Photon 后台和 Wintun，并在打包后核对二者摘要。工具链与上游版本均取自 `upstream.env`；流水线执行 Windows 后台/原生 GUI 测试、Flutter 静态检查和 Photon 前端回归。目前流水线生成未签名包。

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
