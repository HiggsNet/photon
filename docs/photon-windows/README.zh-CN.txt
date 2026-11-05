Photon Windows（Windows 11 amd64）

开始使用
1. 将整个 ZIP 解压到由本人/管理员管理的目录。保留相邻的两个 EXE、wintun.dll 和 third_party。
2. 右键 photon-windows-gui.exe，选择“以管理员身份运行”。无参数会打开本机窗口和托盘。
   photon-windows.exe 是独立后台/服务和命令行工具；窗口会自动启动并管理它。
3. 首次使用在界面填写实际根公钥、节点域名、网关/引导节点和分流路由，保存配置。
   默认配置文件为可执行文件旁的 config.yaml。示例 config.example.yaml 仅供参考，
   其中的公钥、域名和地址必须替换；不要直接将示例作为真实网络配置。
4. overlay.id 必须与网关签名发布的 overlay ID 一致（Linux 示例为 ipsec-main）。
5. 在 Dashboard 右上角点击“连接网络”。空数据库自动生成本机身份，复制入网请求交给所属网络管理员授权。
   入网授权与业务 IP 分配是两个步骤；缺少业务 IP 时控制面仍可连接，业务需等待有效分配。

窗口与连接
- 左侧导航为 Dashboard、Gossip、Tunnel、Babel、日志、诊断和设置，均在主窗口内切换。
- Dashboard 只显示入网状态与节点摘要；节点按名称倒序，双击节点查看详情。
- 节点列分别显示 Gossip 最近同步结果、Tunnel 的 IPv4/IPv6 可用状态和 Babel 邻居健康。
  双栈显示两个勾，单栈显示一个勾。未检测、连接中和异常有独立提示。
  协议可用依据当前授权路由与就绪状态，不代表主动 ping 或测速；Babel 在线不等于端到端探测通过。
- 连接/断开开关位于 Dashboard 右上角；设置入口固定在侧栏底部。
- Windows 同时连接全部已验证、可连接的节点，按目的地址和 Babel 路由选路。
- 新配置的节点范围默认为 *；已有显式范围仍生效，可在“节点与引导”页调整。
- Windows 完全不中转：只收发本机流量，不转发远端流量，也不发布远端路由。
- 关闭窗口只隐藏到托盘；“停止连接并退出 Photon”会停止并等待本窗口启动的后台释放连接。
- 同一登录会话只保留一个新版本托盘实例。重复启动恢复已有窗口，不切换配置。
- 修改并保存配置不会自动重启；点击“重新连接”后应用。
- 默认直接运行托盘，无需安装 Windows 服务。窗口和后台分别运行在独立进程；已有旧服务若占用同一数据库，先停止它。
- 需要排查时从侧栏打开 Gossip、Tunnel、Babel 或日志；“诊断”提供概览、节点地址和原始 JSON。

命令行（管理员 PowerShell）
  .\photon-windows.exe version
  .\photon-windows.exe help
  .\photon-windows-gui.exe --config C:\Photon\config.yaml
  .\photon-windows.exe status --config C:\Photon\config.yaml
  .\photon-windows.exe diagnostics --config C:\Photon\config.yaml

升级与校验
先从旧托盘退出，再将新包解压到另一个目录；保留并显式选择原配置及原数据库路径。
移动程序目录不会自动移动身份数据库。不要覆盖、删除或公开配置、数据库、密钥或日志。
本包故意不提供 config.yaml，也不包含数据库或私钥。
SHA256SUMS 列出包内固定文件的 SHA-256；发布包旁的 .sha256 校验文件校验整个 ZIP。
固定官方 Wintun 0.14.1 amd64 DLL 随包提供，程序在创建适配器前仍会检查其 SHA-256。
third_party 保存依赖来源及许可证。本包不自动提权，不安装或重启其它服务。
