# Photon 的 FlClash Windows 客户端

锁定 FlClash v0.9.3，复用其代理组、连接、日志、设置和托盘。Photon 后台独立运行；仓库维护版本锁、上游接入补丁及 `overlay/`，不复制一整份上游源码。原生 GUI 保留为另一个独立客户端。

## 使用

1. 打开 FlClash，进入侧栏 **Photon**。已有身份可直接选择原来的 Photon Windows YAML。首次使用可点 **新建 Photon 配置**，选择文件夹，在表单中填写可信 root、节点和至少一个用于自动入网的引导地址，然后保存该文件夹下的 `photon.yaml`。
2. 在 **概览、隧道、节点、路由、代理服务、诊断** 中查看实时状态。可以筛选节点/地址/路由、复制入网请求和诊断，检查 IKE/ESP、Babel、同步和失败原因。数据采样被截断时会显示提示。
3. 在代理服务中勾选多个端点，点击 **使用选中的代理**。生成独立的 Photon 配置并启用系统代理，在 FlClash 的代理页使用 `Photon` 手选组、`Photon Auto` 自动择优或 `Photon Balance` 负载均衡。
4. 系统代理和 TUN 开关沿用 FlClash 的仪表盘、设置及托盘。只连接 Photon 可以仅访问内网；暂停代理不会停止 Photon。主动停止 Photon 会先停用正在使用的 Photon 代理配置，再关闭内网连接。

首次连接后可在概览复制待授权的入网请求。如果管理员已提供离线授权包和与之匹配的现有密钥，可以在连接前用 **导入授权** 安装，目标配置须指向尚无数据库的状态目录。已有身份直接使用原配置即可。

停止 Photon 后可打开 **Photon 设置**，编辑当前配置。保存后的参数在下次连接时生效。配置路径自动保存；更换所选配置只会切换引用。当前客户端请求管理员权限，安全模式禁止启动 Photon。

## 数据与网络边界

- 应用级 controller 持有唯一后台进程，经 v1 私有帧协议核对 PID、配置 SHA256 和状态路径。关闭页面/隐藏窗口不会释放网络；退出应用等待后台回收。退出未确认时保留归属并拒绝重启。
- `services` 每两秒读取签名状态，再次验证当前 root、授权链、撤销、地址分配及服务签名。快照最多有效五秒；已授权不等于已测通。界面只消费公开 DTO，不打开 Photon 数据库。
- 勾选项按信任 root 和节点隔离保存；移除失效节点，确定性生成并用真实 Mihomo 校验后原子替换配置。只更新 Photon 所属配置，保留其他订阅和代理配置。内容无变化时不重新应用网络配置。
- SOCKS5 节点绑定 Photon 网卡。Photon 内网、选中服务地址、引导地址和当前网关公网地址进入 TUN 路由排除，同时提供直连规则。配置中的直连规则不替代操作系统路由排除。
- 服务失效或 Photon 意外退出时，正在使用的 Photon 配置关闭已有连接并切换到拒绝新公网流量的规则；用户主动停止则关闭代理接管。该应用级处理尚不等同于经过完整崩溃/睡眠矩阵验证的系统防泄漏保证。

## 准备与构建

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
