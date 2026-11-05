# Photon 的 FlClash 前端

锁定 FlClash v0.9.3，将 Photon 作为独立后台接入。上游代码下载到忽略的 `build/photon-flclash/upstream`；仓库只维护版本锁、三个上游文件的小补丁及 `overlay/` 中的接入代码。切换上游版本必须同时更新 Mihomo 和 prism_ui 的锁定提交。

当前切片在 Windows 的 **工具 → Photon** 提供选择已有 YAML 配置、启动/停止、连接状态、内网地址和连接数量。选择配置只记录文件路径，不导入、重写或复制身份数据库。窗口和页面不拥有网络资源；应用级 controller 持有唯一后台进程，退出 FlClash 时与 Mihomo 一起关闭。通信复用 Photon v1 私有流，核对 PID、配置 SHA256 和状态文件路径；超时或失联清除状态，未确认进程退出时保留归属并阻止新实例。

这是接入原型，还没有可分发的统一 Windows 客户端。授权导入、设置保存、服务目录、自动生成代理配置及双 TUN 防回环尚未接入。普通用户提权也尚未接入 FlClash Helper；这一切片需要以管理员身份运行整个客户端。安全模式禁止启动 Photon。原生 GUI 仍作为独立可用客户端保留。

## 准备源码

在安装 Git、Bash 的开发环境执行：

```sh
bash app/photon-flclash/prepare.sh
```

脚本不会覆盖不属于它的已有目录；再次执行会校验锁定版本并同步接入代码。不要在生成的目录维护修改，应修改 `overlay/` 或补丁后重新准备。FlClash 及其依赖的许可证和原有声明保留在检出目录中。

## 检查与构建

使用 `upstream.env` 中的 Flutter 3.47.6。FlClash 核心使用 Go 1.27.1，Photon 后台继续使用自己的 Go 1.25 工具链。完整构建还需要上游要求的 Rust、C/C++ 和 Windows Flutter 工具链。

```sh
cd build/photon-flclash/upstream
flutter pub get
flutter analyze --no-fatal-infos
flutter test test/photon test/providers/system_action_test.dart test/widgets test/lint
```

只验证 Dart 界面时，可在**临时检出**将 `hooks.user_defines.setup.build_assets` 设为 `false`，避免编译 Go 核心。完整 widget 回归仍需 Rust 编辑器库：保留 `rust_api.build_assets: true`，或按上游方式指定 `FRB_DART_LOAD_EXTERNAL_LIBRARY_NATIVE_LIB_DIR`。这些测试开关不能进入发布构建。

在具备工具链的 Windows 环境，从 Photon 仓库运行：

```powershell
.\app\photon-flclash\build-windows.ps1 `
  -Checkout .\build\photon-flclash\upstream `
  -BackendDirectory .\build\windows-amd64 `
  -OutputDirectory .\build\photon-flclash\windows-amd64
```

脚本验证锁定版本、启用真实原生构建，附带 Photon 后台、Wintun、上游许可证和校验和，不携带用户配置或身份。该 Windows 打包脚本尚未执行完整构建验收。

## 2026-11-05 验证

协议、进程、页面及上游退出流程/widget/lint 合计 1051 项回归通过，最后的局部调整后又通过 30 项相关测试。Rust 编辑器依赖由锁定源码独立构建，测试指定该库并在临时检出关闭两个原生构建 hook；生产 hook 保持开启。原始结果见 `build/validation/photon-flclash-20261105/`。Windows 打包脚本仅检查语法，未完成完整 GUI 构建或桌面验收。

同一 `backend.dart` 在 Windows 11 的原有 `windows-test.catofes.` 身份上运行成功：取得 `2a0d:2905:1:2f::1/128`，隧道进入就绪，向 More 的 IPv6 ping 2/3 回包，首包超时。停止后后台进程、Photon 网卡和分流路由均为零，原配置 SHA256 与数据库文件身份保持不变。这是 Dart 适配器的真实后台验收，不是完整 FlClash 窗口或双 TUN 验收；不据此声称网络无丢包。
