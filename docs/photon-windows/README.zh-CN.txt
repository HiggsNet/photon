Photon Windows（Windows 11 amd64）

开始使用
1. 将整个 ZIP 解压到由本人/管理员管理的目录。保留相邻的 wintun.dll 和 third_party。
2. 右键 photon-windows.exe，选择“以管理员身份运行”。无参数会打开本机窗口和托盘。
3. 首次使用在界面填写实际根公钥、节点域名、网关/引导节点和分流路由，保存配置。
   默认配置文件为可执行文件旁的 config.yaml。示例 config.example.yaml 仅供参考，
   其中的公钥、域名和地址必须替换；不要直接将示例作为真实网络配置。
4. overlay.id 必须与网关签名发布的 overlay ID 一致（Linux 示例为 ipsec-main）。
5. 点击“启动连接”。空数据库自动生成本机身份，复制入网请求交给所属网络管理员授权。
   入网授权与业务 IP 分配是两个步骤；缺少业务 IP 时控制面仍可连接，业务需等待有效分配。

窗口与连接
- 关闭窗口只隐藏到托盘；“停止连接并退出 Photon”才会停止并释放本进程的连接。
- 同一登录会话只保留一个新版本托盘实例。重复启动恢复已有窗口，不切换配置。
- 修改并保存配置不会自动重启；点击“重新连接”后应用。
- 默认直接运行托盘，无需安装 Windows 服务。已有旧服务若占用同一数据库，先停止它。
- 需要排查时打开“日志与诊断”：概览、网关隧道、Gossip 节点、日志和原始 JSON。

命令行（管理员 PowerShell）
  .\photon-windows.exe version
  .\photon-windows.exe help
  .\photon-windows.exe gui --config C:\Photon\config.yaml
  .\photon-windows.exe status --config C:\Photon\config.yaml
  .\photon-windows.exe diagnostics --config C:\Photon\config.yaml

升级与校验
先从旧托盘退出，再将新包解压到另一个目录；保留并显式选择原配置及原数据库路径。
移动程序目录不会自动移动身份数据库。不要覆盖、删除或公开配置、数据库、密钥或日志。
本包故意不提供 config.yaml，也不包含数据库或私钥。
SHA256SUMS 列出包内固定文件的 SHA-256；发布包旁的 .sha256 校验文件校验整个 ZIP。
固定官方 Wintun 0.14.1 amd64 DLL 随包提供，程序在创建适配器前仍会检查其 SHA-256。
third_party 保存依赖来源及许可证。本包不自动提权，不安装或重启其它服务。
